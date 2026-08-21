// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect DNS Tunneling and Domain Generation Algorithm (DGA) activity via abnormal unique subdomain query counts.
// Target Telemetry: UDM_EVENTS (NETWORK_DNS)
// Statistical Model: Modified Z-Score (M_Z) via Median Absolute Deviation (MAD)
// Mathematical Rationale:
//   - Why this model: Security telemetry distributions (like daily DNS lookups) are heavily right-skewed and zero-inflated.
//     Standard standard-deviation (Z-Score) breaks down because massive exfiltration spikes distort the mean and variance.
//     MAD is robust up to 50% outliers, ensuring an accurate baseline median for each host.
//   - Noise protection: Enforces a daily volume floor of >= 50 distinct queries and a minimum MAD threshold > 10.0 to prevent
//     zero-deviation division explosions on idle hosts.
// Sensitivity Boundary: BALANCED (M_Z > 2.5 represents top ~2% statistical tail, Daily Queries >= 50, MAD > 10.0)
// ============================================================================

// Stage 1: Daily distinct subdomain query count per host
stage daily_stats {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.ip = $host
    network.dns.questions.name = $dns_query
    $host != ""

  match:
    $host by day
  outcome:
    $distinct_subdomains = count_distinct($dns_query)
    $total_queries = count(metadata.id)
}

// Stage 2: Compute overall historical median distinct subdomains per host
stage median_stats {
    $host = $daily_stats.host

  match:
    $host
  outcome:
    // True enables exact median computation
    $host_median = window.median($daily_stats.distinct_subdomains, true)
}

// Stage 3: Compute Absolute Deviation |x - median| for each day
stage abs_dev {
    $host = $daily_stats.host
    $host = $median_stats.host

  match:
    $host by day
  outcome:
    $daily_val = max($daily_stats.distinct_subdomains)
    $median_val = max($median_stats.host_median)
    $raw_dev = $daily_val - $median_val
    $dev = math.abs($raw_dev)
}

// Stage 4: Compute Median Absolute Deviation (MAD) across all daily deviations
stage mad_stats {
    $host = $abs_dev.host

  match:
    $host
  outcome:
    $mad = window.median($abs_dev.dev, true)
}

// Root Stage: Calculate Modified Z-Score (0.6745 * deviation / MAD)
$host = $abs_dev.host
$host = $mad_stats.host
$window_start = $abs_dev.window_start

match:
  $host, $window_start by day
outcome:
  $daily_subdomains = max($abs_dev.daily_val)
  $host_median = max($abs_dev.median_val)
  $mad_val = max($mad_stats.mad)
  // Modified Z-score formula for robust outlier detection on skewed distributions
  $diff = $daily_subdomains - $host_median
  $abs_diff = math.abs($diff)
  $scaled_diff = 0.6745 * $abs_diff
  $m_z_score = $scaled_diff / $mad_val

condition:
  // Volume Floor: at least 50 distinct queries today
  $daily_subdomains >= 50
  // Noise Floor: MAD must be non-zero and > 10 to avoid division by zero on flat baselines
  and $mad_val > 10.0
  // Sensitivity Tier: BALANCED (M_Z > 2.5 identifies the top ~2% anomalies)
  and $m_z_score > 2.5

order:
  $m_z_score desc
