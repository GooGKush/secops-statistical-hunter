// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting extreme statistical surges in process launch volume (Z-Score > 3.0).
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Parametric Historical Z-Score per Host (Z = (x - μ) / σ) & Fleet Prevalence
// Mathematical Rationale:
//   - Why this model: Compares each host's hourly process execution volume against its own historical
//     baseline mean and standard deviation. Hourly surges exceeding 3 standard deviations (Z > 3.0, top ~0.13%)
//     reveal anomalous activity such as automated malware loops, batch lateral movement, or ransomware staging.
//   - Small-Sample & Multiple-Comparison Protection: Enforces an active baseline sample floor (>= 120 hourly samples),
//     an activity floor of >= 50 executions, and a minimum standard deviation floor (σ >= 10.0)
//     to prevent zero-variance divisions, idle baseline noise, and small-sample false anomalies.
// Sensitivity Boundary: CONSERVATIVE (Z-Score > 3.0, Min Hourly Executions >= 50, Min Stddev >= 10.0, Min Active Samples >= 120)
// ============================================================================

// Stage 1: Hourly process execution counts, distinct binaries, and sample commands per host
stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""

  match:
    $host by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Historical mean, standard deviation, and active sample density per host
stage host_stats {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $host_mean = avg($host_hourly.hourly_count)
    $host_stddev = stddev($host_hourly.hourly_count)
    $active_samples = count($host_hourly.window_start)
}

// Stage 3: Enterprise-wide fleet prevalence of process activity
stage fleet_prevalence {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $fleet_hosts = count_distinct($host_hourly.host)
}

// Root Stage: Join all stages, calculate Z-score in events body, and emit standardized 6 Evidence Pillars
$host = $host_hourly.host
$host = $host_stats.host
$host = $fleet_prevalence.host
$window_start = $host_hourly.window_start

// Linear event-level statistical transformation (prevents intra-stage outcome race conditions)
$diff = $host_hourly.hourly_count - $host_stats.host_mean
$z = $diff / $host_stats.host_stddev

match:
  $host, $window_start by 1h
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($host_stats.active_samples)
  $baseline_mean = max($host_stats.host_mean)
  $baseline_dispersion = max($host_stats.host_stddev)
  $fleet_prevalence = max($fleet_prevalence.fleet_hosts)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)
  
  // Aggregate computed Z-Score
  $z_score = max($z)

condition:
  // Small-Sample Protection: Require at least 120 hourly active baseline samples for 30-day search
  // Note: For a 2-day / 48-hour search, scale this floor down to: $baseline_active_samples >= 12
  $baseline_active_samples >= 120
  // Activity Floor: at least 50 executions in this hour
  and $observation_count >= 50
  // Variance Floor: standard deviation must be >= 10 to ensure meaningful spread
  and $baseline_dispersion >= 10.0
  // Outlier Boundary: 3-Sigma threshold (Z > 3.0)
  and $z_score > 3.0

order:
  $z_score desc


