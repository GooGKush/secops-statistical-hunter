// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect data exfiltration and staging by isolating extreme surges in daily outbound byte volume per host.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP / NETWORK_CONNECTION)
// Statistical Model: Non-Parametric Interquartile Range (IQR) & Tukey's Upper Fence
// Mathematical Rationale:
//   - Why this model: Network transfer byte volumes follow an extreme power-law / heavy-tailed distribution where standard deviation
//     is meaningless. Tukey's fence (Q3 + 1.5 * IQR) establishes a non-parametric upper fence derived purely from the 25th (Q1)
//     and 75th (Q3) percentiles of the host's historical activity.
//   - Noise protection: Enforces a daily volume floor of >= 50 MB, a baseline sample density floor (>= 7 active days),
//     and an IQR spread of >= 10 MB to prevent idle hosts transferring a few KB from triggering mathematical outlier conditions.
// Sensitivity Boundary: BALANCED (Observed Bytes >= 2.0x Upper Fence, Daily MB >= 50, IQR >= 10 MB, Active Days >= 7)
// ============================================================================

// Stage 1: Daily outbound byte volume per host
stage daily_egress {
    (metadata.event_type = "NETWORK_HTTP" or metadata.event_type = "NETWORK_CONNECTION")
    principal.asset.hostname = $host
    // Exclude internal RFC 1918 traffic
    not net.ip_in_range_cidr(target.ip, "10.0.0.0/8")
    not net.ip_in_range_cidr(target.ip, "172.16.0.0/12")
    not net.ip_in_range_cidr(target.ip, "192.168.0.0/16")
    $bytes = network.sent_bytes

  match:
    $host by day
  outcome:
    // Convert bytes to Megabytes
    $daily_mb = sum($bytes) / 1048576.0
}

// Stage 2: Calculate Q1 (25th percentile), Q3 (75th percentile), Median, and active observation days
stage iqr_fences {
    $host = $daily_egress.host

  match:
    $host
  outcome:
    $q1 = window.percentile($daily_egress.daily_mb, 25)
    $q3 = window.percentile($daily_egress.daily_mb, 75)
    $median_mb = window.median($daily_egress.daily_mb, true)
    $active_days = count_distinct($daily_egress.window_start)
}

// Root Stage: Compare daily upload against Tukey's Upper Fence and emit 6 Evidence Pillars
$host = $daily_egress.host
$host = $iqr_fences.host
$window_start = $daily_egress.window_start

// Linear event-level Tukey Fence computation (eliminates intra-stage outcome race conditions)
$iqr_val = $iqr_fences.q3 - $iqr_fences.q1
$iqr_margin = 1.5 * $iqr_val
$fence_val = $iqr_fences.q3 + $iqr_margin
$surge = $daily_egress.daily_mb / $fence_val

match:
  $host, $window_start by day
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_egress.daily_mb)
  $baseline_active_samples = max($iqr_fences.active_days)
  $baseline_mean = max($iqr_fences.median_mb)
  $baseline_dispersion = max($iqr_val)
  $fleet_prevalence = 1
  $distinct_binaries = max($daily_egress.daily_mb)
  
  // Aggregate Surge Ratio
  $surge_ratio = max($surge)

condition:
  // Small-Sample Protection: Require at least 7 active daily observation windows
  $baseline_active_samples >= 7
  // Volume Floor: at least 50 MB transferred today
  and $observation_count >= 50.0
  // Noise Floor: IQR must be at least 10 MB (prevents triggering on idle hosts that send 1KB)
  and $baseline_dispersion >= 10.0
  // Exceeds upper fence by at least 2x
  and $surge_ratio >= 2.0

order:
  $surge_ratio desc

