// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting anomalous process launch volume relative to peer enterprise fleet behavior.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Cross-Fleet Peer Normalization Z-Score (Z_fleet = (x_host - μ_fleet) / max(σ_fleet, sqrt(max(μ_fleet, 1.0))))
// Mathematical Rationale:
//   - Evaluates each host against the concurrent fleet-wide peer population across all endpoints in the same hour.
//   - Uses a continuous Poisson variance floor max(σ_fleet^2, max(μ_fleet, 1.0)) without additive denominator blunting
//     or arbitrary dispersion cliffs, while tracking concurrent surging host breadth in Stage 3.
// Sensitivity Boundary: BALANCED (Fleet Z-Score >= 2.5σ, Min Hourly Executions >= 25, Min Peer Hosts >= 15)
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

// Stage 2: Calculate fleet-wide peer baseline mean and standard deviation across all hosts for each window
stage fleet_stats {
    $host = $host_hourly.host
    $ws = $host_hourly.window_start

  match:
    $ws by 1h
  outcome:
    $fleet_mean = avg($host_hourly.hourly_count)
    $fleet_stddev = stddev($host_hourly.hourly_count)
    $total_fleet_hosts = count_distinct($host_hourly.host)
}

// Stage 3: Count concurrent hosts exceeding the hourly surge floor per window
stage fleet_surging {
    $ws = $host_hourly.window_start

  match:
    $ws by 1h
  outcome:
    $surging_hosts = sum(if($host_hourly.hourly_count >= 25, 1, 0))
}

// Root Stage: Join host hourly with fleet stats, calculate Fleet Z-Score, and emit 6 Evidence Pillars
$host = $host_hourly.host
$ws = $host_hourly.window_start
$ws = $fleet_stats.ws
$ws = $fleet_surging.ws

match:
  $host, $ws by 1h
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($fleet_stats.total_fleet_hosts)
  $baseline_mean = max($fleet_stats.fleet_mean)
  $raw_sd = max($fleet_stats.fleet_stddev)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $raw_var = $raw_sd * $raw_sd
  $safe_var = if($raw_var > $floor_var, $raw_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $fleet_prevalence = max($fleet_surging.surging_hosts)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)

  // Aggregate Fleet Z-Score
  $diff = $observation_count - $baseline_mean
  $fleet_z = $diff / $baseline_dispersion

condition:
  $baseline_active_samples >= 15
  and $observation_count >= 25
  and $fleet_z >= 2.5

order:
  $fleet_z desc
