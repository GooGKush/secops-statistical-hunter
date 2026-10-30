// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect data exfiltration and staging by isolating extreme surges in daily outbound byte volume per host.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP / NETWORK_CONNECTION)
// Statistical Model: Recalibrated Bowley Skewness-Adjusted Tukey Fence Excess Z (IQR_TUKEY_SKEW_FENCES)
// Mathematical Rationale:
//   - Network transfer byte volumes follow heavy-tailed distributions. Computing the 5-point quantile envelope
//     (P10, Q1, Q2, Q3, P90) in Stage 2 frees Stage 3 for concurrent fleet prevalence and enables recalibrated
//     Bowley skewness adjustment Q3 + 1.5 * exp(1.35 * max(0, B)) * Safe_IQR with continuous floor max(0.01 * Q2, 1.0).
//   - Ranks excesses in scale-invariant standard-deviation units: $fence_z = (Observed - Adj_Fence) / (Safe_IQR / 1.349).
// Sensitivity Boundary: BALANCED (Fence Z >= 3.5σ, Daily MB >= 50.0, Active Days >= 7)
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
    $daily_mb = sum($bytes) / 1048576.0
    $distinct_targets = count_distinct($dst_ip)
    $flow_p50_bytes = window.percentile($bytes, 50)
    $flow_p90_bytes = window.percentile($bytes, 90)
}

// Stage 2: Calculate 5-point empirical quantile envelope (P10, Q1, Q2, Q3, P90) in a single stage
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

// Stage 3: Enterprise-wide fleet prevalence of high-egress hosts per day
stage fleet_breadth {
    $ws = $daily_egress.window_start

  match:
    $ws by 1d
  outcome:
    $fleet_hosts = sum(if($daily_egress.daily_mb >= 50.0, 1, 0))
}

// Root Stage: Compare daily upload against Skewness-Adjusted Tukey Fence and emit 6 Evidence Pillars
$host = $daily_egress.host
$host = $iqr_fences.host
$window_start = $daily_egress.window_start
$window_start = $fleet_breadth.ws

match:
  $host, $window_start by 1d
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_egress.daily_mb)
  $baseline_active_samples = max($iqr_fences.active_days)
  $baseline_mean = max($iqr_fences.q2)
  $q1_val = max($iqr_fences.q1)
  $q3_val = max($iqr_fences.q3)
  $baseline_dispersion = $q3_val - $q1_val
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $distinct_binaries = max($daily_egress.distinct_targets)

  // Continuous IQR Floor, Recalibrated Bowley Skewness (1.35) & Scale-Invariant Fence Z
  $rel_floor = 0.01 * $baseline_mean
  $iqr_floor = if($rel_floor > 1.0, $rel_floor, 1.0)
  $safe_iqr = if($baseline_dispersion > $iqr_floor, $baseline_dispersion, $iqr_floor)
  $bowley_skew = ($q3_val + $q1_val - (2.0 * $baseline_mean)) / $safe_iqr
  $tail_heaviness = (max($iqr_fences.p90) - max($iqr_fences.p10)) / $safe_iqr
  $pos_skew = if($bowley_skew > 0.0, $bowley_skew, 0.0)
  $skew_exp = math.pow(2.718281828, 1.35 * $pos_skew)
  $adj_upper_fence = $q3_val + (1.5 * $skew_exp * $safe_iqr)
  $safe_fence = if($adj_upper_fence > 1.0, $adj_upper_fence, 1.0)
  $surge_ratio = $observation_count / $safe_fence
  $fence_z = ($observation_count - $adj_upper_fence) / ($safe_iqr / 1.349)

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 50.0
  and $fence_z >= 3.5

order:
  $fence_z desc
