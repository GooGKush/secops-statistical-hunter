// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting extreme statistical surges in process launch volume (Z-Score > 3.0).
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Parametric Fleet-Wide Standard Z-Score (Z = (x - μ) / σ)
// Mathematical Rationale:
//   - Why this model: Normal process execution volume across enterprise endpoints follows an established baseline.
//     Sudden spikes exceeding 3 standard deviations (Z > 3.0, representing the top ~0.13% tail) indicate automated script loops,
//     malware execution storms, batch lateral movement, or ransomware staging.
//   - Noise protection: Enforces an activity floor of >= 50 executions per host and a minimum fleet standard deviation (σ >= 10.0)
//     to prevent zero-variance divisions and idle baseline noise.
// Sensitivity Boundary: CONSERVATIVE (Z-Score > 3.0, Min Executions >= 50, Min Fleet Stddev >= 10.0)
// ============================================================================

// Stage 1: Hourly process execution counts and distinct binaries per host
stage host_execution_volume {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $hostname
    $hostname != ""

  match:
    $hostname by 1h
  outcome:
    $process_count = count(metadata.id)
    $distinct_processes = count_distinct(target.process.file.full_path)
    $sample_command = array_distinct(target.process.command_line)
}

// Stage 2: Aggregate fleet-wide baseline mean and standard deviation across all hosts
stage fleet_baseline {
    // Reference upstream stage outputs directly
    $observed_count = $host_execution_volume.process_count

  outcome:
    $fleet_mean = avg($observed_count)
    $fleet_stddev = stddev($observed_count)
}

// Root Stage: Compute Z-score and filter for 3-Sigma outliers (unwrapped at root level)
$hostname = $host_execution_volume.hostname

match:
  $hostname
outcome:
  $host_executions = max($host_execution_volume.process_count)
  $distinct_binaries = max($host_execution_volume.distinct_processes)
  $sample_activity = array_distinct($host_execution_volume.sample_command)
  $fleet_avg = max($fleet_baseline.fleet_mean)
  $fleet_sd = max($fleet_baseline.fleet_stddev)

  // Standard Z-Score formula: (x - μ) / σ
  $z_score = ($host_executions - $fleet_avg) / math.max($fleet_sd, 1.0)

condition:
  // Activity Floor: at least 50 executions on this host
  $host_executions >= 50
  // Variance Floor: fleet standard deviation must be >= 10 to ensure meaningful spread
  and $fleet_sd >= 10.0
  // Outlier Boundary: 3-Sigma threshold (Z > 3.0)
  and $z_score > 3.0

order:
  $z_score desc
