// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect DNS Tunneling and Domain Generation Algorithm (DGA) activity via abnormal unique subdomain query counts.
// Target Telemetry: UDM_EVENTS (NETWORK_DNS)
// Statistical Model: Modified Z-Score (M_Z) via Median Absolute Deviation (MAD)
// Mathematical Rationale:
//   - Why this model: Security telemetry distributions (like daily DNS lookups) are heavily right-skewed and zero-inflated.
//     Standard standard-deviation (Z-Score) breaks down because massive exfiltration spikes distort the mean and variance.
//     MAD is robust up to 50% outliers, ensuring an accurate baseline median for each host.
//   - Noise protection: Enforces a daily volume floor of >= 50 distinct queries, a baseline sample density floor (>= 7 active days),
//     and a minimum MAD threshold > 10.0 to prevent zero-deviation division explosions on idle hosts.
// Sensitivity Boundary: BALANCED (M_Z > 2.5 represents top ~2% statistical tail, Daily Queries >= 50, MAD > 10.0, Active Days >= 7)
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
    $host_median = window.median($daily_stats.distinct_subdomains, true)
}

// Stage 3: Compute Median Absolute Deviation (MAD) across all daily deviations
stage mad_stats {
    $host = $daily_stats.host
    $host = $median_stats.host

  match:
    $host
  outcome:
    $mad = window.median(math.abs($daily_stats.distinct_subdomains - $median_stats.host_median), true)
    $host_median_val = max($median_stats.host_median)
    $active_days = count_distinct($daily_stats.window_start)
}

// Root Stage: Calculate Modified Z-Score (0.6745 * deviation / MAD) and emit 6 Evidence Pillars
$host = $daily_stats.host
$host = $mad_stats.host
$window_start = $daily_stats.window_start

match:
  $host, $window_start by 1d
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($daily_stats.distinct_subdomains)
  $baseline_active_samples = max($mad_stats.active_days)
  $baseline_mean = max($mad_stats.host_median_val)
  $baseline_dispersion = max($mad_stats.mad)
  $fleet_prevalence = 1
  $distinct_binaries = max($daily_stats.distinct_subdomains)
  
  // Aggregate Modified Z-Score (0.6745 * |x - median| / MAD)
  $m_z_score = 0.6745 * math.abs(max($daily_stats.distinct_subdomains) - max($mad_stats.host_median_val)) / (max($mad_stats.mad) + 0.001)

condition:
  // Small-Sample Protection: Require at least 7 active daily observation windows
  $baseline_active_samples >= 7
  // Volume Floor: at least 50 distinct queries today
  and $observation_count >= 50
  // Noise Floor: MAD must be non-zero and > 10 to avoid division by zero on flat baselines
  and $baseline_dispersion > 10.0
  // Sensitivity Tier: BALANCED (M_Z > 2.5 identifies the top ~2% anomalies)
  and $m_z_score > 2.5

order:
  $m_z_score desc

