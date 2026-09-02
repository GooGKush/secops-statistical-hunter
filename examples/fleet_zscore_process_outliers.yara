// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting anomalous process launch volume relative to peer enterprise fleet behavior.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Cross-Fleet Peer Normalization Z-Score (Z_fleet = (x_host - μ_fleet) / σ_fleet)
// Mathematical Rationale:
//   - Why this model: Evaluates each host against the fleet-wide peer population across all endpoints.
//     Isolates singular hosts whose process volume explodes beyond organizational peer norms, identifying dedicated
//     compromised machines, command-and-control pivot nodes, or anomalous local scripts.
//   - Small-Sample & Peer Protection: Enforces a minimum peer fleet size floor (>= 15 active hosts),
//     an activity floor of >= 25 executions, and a fleet standard deviation floor (σ >= 5.0).
// Sensitivity Boundary: BALANCED (Fleet Z-Score >= 2.5σ, Min Hourly Executions >= 25, Min Fleet Stddev >= 5.0, Min Peer Hosts >= 15)
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
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Calculate fleet-wide peer baseline mean and standard deviation across all hosts
stage fleet_stats {
    $host = $host_hourly.host
    $dummy = 1

  match:
    $dummy
  outcome:
    $fleet_mean = avg($host_hourly.hourly_count)
    $fleet_stddev = stddev($host_hourly.hourly_count)
    $total_fleet_hosts = count_distinct($host_hourly.host)
}

// Stage 3: Measure peak hourly intensity and binary diversity per host
stage host_summary {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $peak_hourly = max($host_hourly.hourly_count)
    $distinct_binaries = max($host_hourly.distinct_procs)
    $sample_cmds = array_distinct($host_hourly.sample_cmd)
}

// Root Stage: Join host summary with fleet stats, calculate Fleet Z-Score, and emit 6 Evidence Pillars
$host = $host_summary.host
$dummy = 1
$dummy = $fleet_stats.dummy

match:
  $host
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_summary.peak_hourly)
  $baseline_active_samples = max($fleet_stats.total_fleet_hosts)
  $baseline_mean = max($fleet_stats.fleet_mean)
  $baseline_dispersion = max($fleet_stats.fleet_stddev)
  $fleet_prevalence = max($fleet_stats.total_fleet_hosts)
  $distinct_binaries = max($host_summary.distinct_binaries)
  $sample_commands = array_distinct($host_summary.sample_cmds)
  
  // Aggregate Fleet Z-Score
  $fleet_z = (max($host_summary.peak_hourly) - max($fleet_stats.fleet_mean)) / (max($fleet_stats.fleet_stddev) + 0.001)

condition:
  // Small-Sample Protection: Require at least 15 active peer endpoints in comparison population
  $baseline_active_samples >= 15
  // Activity Floor: at least 25 executions in peak hour
  and $observation_count >= 25
  // Variance Floor: fleet standard deviation must be >= 5.0 to ensure meaningful spread
  and $baseline_dispersion >= 5.0
  // Outlier Boundary: 2.5-Sigma threshold relative to fleet peers
  and $fleet_z >= 2.5

order:
  $fleet_z desc

