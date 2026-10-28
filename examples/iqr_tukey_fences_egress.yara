// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect data exfiltration and staging by isolating extreme surges in daily outbound byte volume per host.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP / NETWORK_CONNECTION)
// Statistical Model: Non-Parametric Quantiles, Bowley Skewness & Hubert-Vandervieren Skewness-Adjusted Tukey Fence
// Mathematical Rationale:
//   - Why this model: Network transfer byte volumes follow an extreme power-law / heavy-tailed distribution where standard deviation
//     is distorted by bursts. Computing the 5-point quantile envelope (P10, Q1, Q2, Q3, P90) in a single stage enables both
//     Bowley's quartile skewness B = (Q3 + Q1 - 2*Q2) / IQR and the Hubert-Vandervieren skewness-adjusted upper fence
//     Q3 + 1.5 * exp(3 * max(0, B)) * IQR, preventing false positives on naturally right-skewed servers while keeping tight fences
//     on symmetric workstations.
//   - Noise protection: Enforces a daily volume floor of >= 50 MB, a baseline sample density floor (>= 7 active days),
//     and an IQR spread floor to prevent idle hosts transferring a few KB from triggering mathematical outlier conditions.
// Sensitivity Boundary: BALANCED (Surge Ratio >= 2.0, Daily MB >= 50, IQR >= 10 MB, Active Days >= 7)
// ============================================================================

// Stage 1: Daily outbound byte volume and intra-day flow payload quantiles per host
stage daily_egress {
    (metadata.event_type = "NETWORK_HTTP" or metadata.event_type = "NETWORK_CONNECTION")
    principal.asset.hostname = $host
    $host != ""
    target.ip = $dst_ip
    $dst_ip != ""
    // Exclude internal RFC 1918 traffic
    not net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
    not net.ip_in_range_cidr(target.ip, "172.16.0.0/12")
    not net.ip_in_range_cidr(target.ip, "192.168.0.0/16")
    $bytes = network.sent_bytes

  match:
    $host by 1d
  outcome:
    // Convert bytes to Megabytes and capture distinct external destinations
    $daily_mb = sum($bytes) / 1048576.0
    $distinct_targets = count_distinct($dst_ip)
    $flow_p50_bytes = window.percentile($bytes, 50)
    $flow_p90_bytes = window.percentile($bytes, 90)
}

// Stage 2: Calculate 5-point empirical quantile envelope (P10, Q1, Q2, Q3, P90) and active observation days in 1 stage
stage iqr_fences {
    $host = $daily_egress.host

  match:
    $host
  outcome:
    $active_days = count_distinct($daily_egress.window_start)
    $p10 = window.percentile($daily_egress.daily_mb, 10)
    $q1 = window.percentile($daily_egress.daily_mb, 25)
    $q2 = window.percentile($daily_egress.daily_mb, 50)
    $q3 = window.percentile($daily_egress.daily_mb, 75)
    $p90 = window.percentile($daily_egress.daily_mb, 90)
}

// Root Stage: Compare daily upload against Skewness-Adjusted Tukey Fence and emit 6 Evidence Pillars
$host = $daily_egress.host
$host = $iqr_fences.host
$window_start = $daily_egress.window_start

match:
  $host, $window_start by 1d
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_egress.daily_mb)
  $baseline_active_samples = max($iqr_fences.active_days)
  $baseline_mean = max($iqr_fences.q2)
  $q1_val = max($iqr_fences.q1)
  $q3_val = max($iqr_fences.q3)
  $p10_val = max($iqr_fences.p10)
  $p90_val = max($iqr_fences.p90)
  $baseline_dispersion = $q3_val - $q1_val
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_egress.distinct_targets)

  // Non-Parametric Bowley Skewness, Tail Heaviness & Skewness-Adjusted Tukey Upper Fence
  $safe_iqr = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)
  $bowley_num = $q3_val + $q1_val - (2.0 * $baseline_mean)
  $bowley_skew = $bowley_num / $safe_iqr
  $idr = $p90_val - $p10_val
  $tail_heaviness = $idr / $safe_iqr
  $pos_skew = if($bowley_skew > 0, $bowley_skew, 0.0)
  $skew_exp = math.pow(2.718281828, 3.0 * $pos_skew)
  $adj_upper_fence = $q3_val + (1.5 * $skew_exp * $safe_iqr)
  $safe_fence = if($adj_upper_fence > 0, $adj_upper_fence, 1.0)
  $surge_ratio = $observation_count / $safe_fence

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 50.0
  and $baseline_dispersion >= 10.0
  and $surge_ratio >= 2.0

order:
  $surge_ratio desc
