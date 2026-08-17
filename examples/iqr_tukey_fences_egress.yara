// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect data exfiltration and staging by isolating extreme surges in daily outbound byte volume per host.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP / NETWORK_CONNECTION)
// Statistical Model: Non-Parametric Interquartile Range (IQR) & Tukey's Upper Fence
// Mathematical Rationale:
//   - Why this model: Network transfer byte volumes follow an extreme power-law / heavy-tailed distribution where standard deviation
//     is meaningless. Tukey's fence (Q3 + 1.5 * IQR) establishes a non-parametric upper fence derived purely from the 25th (Q1)
//     and 75th (Q3) percentiles of the host's historical activity.
//   - Noise protection: Enforces a daily volume floor of >= 50 MB and an IQR spread of >= 10 MB to prevent idle hosts transferring a few KB
//     from triggering mathematical outlier conditions.
// Sensitivity Boundary: BALANCED (Observed Bytes >= 2.0x Upper Fence, Daily MB >= 50, IQR >= 10 MB)
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

// Stage 2: Calculate Q1 (25th percentile), Q3 (75th percentile), and IQR
stage iqr_fences {
    $host = $daily_egress.host

  match:
    $host
  outcome:
    $q1 = window.percentile($daily_egress.daily_mb, 25)
    $q3 = window.percentile($daily_egress.daily_mb, 75)
    $median_mb = window.median($daily_egress.daily_mb, true)
}

// Root Stage: Compare daily upload against Tukey's Upper Fence
$host = $daily_egress.host
$host = $iqr_fences.host
$window_start = $daily_egress.window_start

match:
  $host, $window_start by day
outcome:
  $observed_mb = max($daily_egress.daily_mb)
  $q1_val = max($iqr_fences.q1)
  $q3_val = max($iqr_fences.q3)
  $median_val = max($iqr_fences.median_mb)
  $iqr = $q3_val - $q1_val
  // Tukey's Mild Outlier Upper Fence: Q3 + 1.5 * IQR
  $upper_fence = $q3_val + (1.5 * $iqr)
  // Anomaly severity ratio relative to upper fence
  $surge_ratio = $observed_mb / $upper_fence

condition:
  // Volume Floor: at least 50 MB transferred today
  $observed_mb >= 50.0
  // Noise Floor: IQR must be at least 10 MB (prevents triggering on idle hosts that send 1KB)
  and $iqr >= 10.0
  // Exceeds upper fence by at least 2x
  and $observed_mb > $upper_fence
  and $surge_ratio >= 2.0

order:
  $surge_ratio desc
