// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect DNS Tunneling and Domain Generation Algorithm (DGA) activity via abnormal unique subdomain query counts.
// Target Telemetry: UDM_EVENTS (NETWORK_DNS)
// Statistical Model: One-Sided Modified Z-Score (Iglewicz & Hoaglin, 1993) via Median Absolute Deviation (MAD)
// Mathematical Rationale:
//   - Why this model: Security telemetry distributions (like daily DNS lookups) are heavily right-skewed.
//     Median and MAD have a 50% breakdown point, preventing massive exfiltration spikes from distorting the baseline.
//   - Steady-host protection: Uses a signed numerator (observed - median) so downward drops never fire, and falls back
//     to scaled Mean Absolute Deviation (1.253314 * meanAD) when MAD = 0 rather than dropping steady endpoints.
// Sensitivity Boundary: BALANCED (M_Z > 3.5, Daily Distinct Subdomains >= 50, Active Days >= 7)
// ============================================================================

// Stage 1: Daily distinct subdomain query count per host
stage daily_stats {
    metadata.event_type = "NETWORK_DNS"
    principal.asset.ip = $host
    network.dns.questions.name = $dns_query
    $host != ""

  match:
    $host by 1d
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
    $host_median = window.median($daily_stats.distinct_subdomains, false)
}

// Stage 3: Compute MAD and Mean Absolute Deviation (Iglewicz-Hoaglin MAD=0 fallback)
stage mad_stats {
    $host = $daily_stats.host
    $host = $median_stats.host

  match:
    $host
  outcome:
    $mad = window.median(math.abs($daily_stats.distinct_subdomains - $median_stats.host_median), false)
    $mean_abs_dev = avg(math.abs($daily_stats.distinct_subdomains - $median_stats.host_median))
    $host_median_val = max($median_stats.host_median)
    $active_days = count_distinct($daily_stats.window_start)
}

// Root Stage: Calculate One-Sided Modified Z-Score and emit 6 Evidence Pillars
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
  $baseline_mean_abs_dev = max($mad_stats.mean_abs_dev)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_stats.distinct_subdomains)

  // Robust Scale with Iglewicz-Hoaglin MAD=0 Fallback (One-Sided Excess)
  $scale_from_mad = $baseline_dispersion / 0.6745
  $scale_from_meanad = $baseline_mean_abs_dev * 1.253314
  $robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)
  $safe_robust_scale = if($robust_scale > 1.0, $robust_scale, 1.0)
  $m_z_score = ($observation_count - $baseline_mean) / $safe_robust_scale

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 50
  and $m_z_score > 3.5

order:
  $m_z_score desc
