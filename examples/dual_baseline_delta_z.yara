// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for targeted host volume surges isolated from company-wide shifts (Delta-Z)
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH / NETWORK_HTTP / NETWORK_CONNECTION)
// Statistical Model: 3-Stage Dual-Baseline Population Normalization (Delta-Z = Z_Personal - Z_Fleet)
// Operational Analogy: "The Patch Tuesday Immunity Shield"
// Mathematical Rationale:
//   If a corporate-wide software deployment (e.g. Patch Tuesday or agent rollout) occurs,
//   all endpoints experience massive concurrent surges. Standard Z-scores flag the entire fleet.
//   Dual-Baseline Delta-Z subtracts the concurrent fleet shift from the personal surge:
//   when the entire fleet spikes, Delta-Z remains near zero; when a single host spikes while
//   the fleet remains calm, Delta-Z explodes, isolating targeted attacks with zero false alarms.
// Sensitivity Boundary: Delta-Z >= 3.0σ, Min Events >= 25, Min Fleet Hosts >= 15
// ============================================================================

// Stage 1: Individual Host Activity Volume in tumbling hourly windows
stage host_hourly_extract {
  $e.metadata.event_type = "PROCESS_LAUNCH"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count($e.metadata.id)
    $distinct_procs = count_distinct($e.target.process.file.full_path)
}

// Stage 2: Individual Host Personal Historical Baseline (Temporal Baseline)
stage host_personal_baseline {
  $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Fleet-Wide Macro Baseline across all active endpoints in the same hour
stage fleet_concurrent_baseline {
  $host = $host_hourly_extract.host
  $ws = $host_hourly_extract.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hour_avg = avg($host_hourly_extract.hourly_count)
    $fleet_hour_stddev = stddev($host_hourly_extract.hourly_count)
    $active_fleet_hosts = count_distinct($host_hourly_extract.host)
}

// Root Stage: Dual-Baseline Delta-Z Evaluation
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

$obs = $host_hourly_extract.hourly_count
$p_mu = $host_personal_baseline.personal_avg
$p_sd = $host_personal_baseline.personal_stddev

$f_mu = $fleet_concurrent_baseline.fleet_hour_avg
$f_sd = $fleet_concurrent_baseline.fleet_hour_stddev

// 1. Personal Historical Z-Score
$p_diff = $obs - $p_mu
$personal_z = $p_diff / $p_sd

// 2. Concurrent Fleet Z-Score
$f_diff = $obs - $f_mu
$fleet_z = $f_diff / $f_sd

// 3. Delta-Z Targeted Isolation Score
$delta_z = $personal_z - $fleet_z

match:
  $host, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly_extract.hourly_count)
  $baseline_active_samples = max($host_personal_baseline.active_hours)
  $baseline_mean = max($host_personal_baseline.personal_avg)
  $baseline_dispersion = max($host_personal_baseline.personal_stddev)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_hosts)
  $distinct_binaries = max($host_hourly_extract.distinct_procs)

  // Dual-Baseline Metrics
  $personal_z_score = max($personal_z)
  $fleet_concurrent_z = max($fleet_z)
  $targeted_delta_z = max($delta_z)

condition:
  // Fleet Population Floor: At least 15 active hosts
  $fleet_prevalence >= 15
  and $baseline_active_samples >= 24
  and $observation_count >= 25
  and $baseline_dispersion >= 5.0
  and $targeted_delta_z >= 3.0
