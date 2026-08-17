// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting extreme statistical surges in process launch volume (Z-Score > 3.0).
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Parametric Historical Z-Score per Host (Z = (x - μ) / σ)
// Mathematical Rationale:
//   - Why this model: Compares each host's hourly process execution volume against its own historical
//     baseline mean and standard deviation. Hourly surges exceeding 3 standard deviations (Z > 3.0, top ~0.13%)
//     reveal anomalous activity such as automated malware loops, batch lateral movement, or ransomware staging.
//   - Noise protection: Enforces an activity floor of >= 50 executions and a minimum standard deviation floor (σ >= 10.0)
//     to prevent zero-variance divisions and idle baseline noise.
// Sensitivity Boundary: CONSERVATIVE (Z-Score > 3.0, Min Hourly Executions >= 50, Min Stddev >= 10.0)
// ============================================================================

// Stage 1: Hourly process execution counts and distinct binaries per host
stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""

  match:
    $host by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
}

// Stage 2: Historical mean and standard deviation baseline per host
stage host_stats {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $host_mean = avg($host_hourly.hourly_count)
    $host_stddev = stddev($host_hourly.hourly_count)
}

// Root Stage: Explicitly bind both stages in events section and calculate Z-score
$host = $host_hourly.host
$host = $host_stats.host
$window_start = $host_hourly.window_start

match:
  $host, $window_start by 1h
outcome:
  $observed_count = max($host_hourly.hourly_count)
  $mean_val = max($host_stats.host_mean)
  $stddev_val = max($host_stats.host_stddev)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $z_score = ($observed_count - $mean_val) / $stddev_val

condition:
  // Activity Floor: at least 50 executions in this hour
  $observed_count >= 50
  // Variance Floor: standard deviation must be >= 10 to ensure meaningful spread
  and $stddev_val >= 10.0
  // Outlier Boundary: 3-Sigma threshold (Z > 3.0)
  and $z_score > 3.0

order:
  $z_score desc
