// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for targeted host volume surges isolated from company-wide shifts (Delta-Z)
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Leave-One-Out Personal Z Minus Mature-Cohort Fleet Historical Shift Z (Delta-Z = Z_Personal - max(0, Z_Fleet))
// Operational Analogy: "The Patch Tuesday Immunity Shield"
// Mathematical Rationale:
//   Computes leave-one-out personal standardization ($personal_z) with a continuous Poisson dispersion floor
//   sqrt(max(loo_mean, 1.0)) and subtracts concurrent fleet shift ($fleet_z) evaluated strictly across mature
//   peer hosts (active_hours >= 30) relative to their own historical expected mean and spread.
// Sensitivity Boundary: BALANCED (Delta-Z >= 3.0σ, Min Events >= 25, Mature Fleet Hosts >= 5, Min Active Samples >= 30)
// ============================================================================

// Stage 1: Individual Host Activity Volume and Squared Moments in tumbling hourly windows
stage host_hourly_extract {
  $e.metadata.event_type = "PROCESS_LAUNCH"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count($e.metadata.id)
    $hourly_count_sq = 1.0 * count($e.metadata.id) * count($e.metadata.id)
    $distinct_procs = count_distinct($e.target.process.file.full_path)
}

// Stage 2: Individual Host Personal Historical Baseline
stage host_personal_baseline {
  $host = $host_hourly_extract.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly_extract.hourly_count)
    $sum_x2 = sum($host_hourly_extract.hourly_count_sq)
    $personal_avg = avg($host_hourly_extract.hourly_count)
    $personal_stddev = stddev($host_hourly_extract.hourly_count)
    $active_hours = count($host_hourly_extract.window_start)
}

// Stage 3: Concurrent Mature-Fleet Shift Baseline (excludes cold-start hosts < 30 active hours)
stage fleet_concurrent_baseline {
  $host = $host_hourly_extract.host
  $host = $host_personal_baseline.host
  $ws = $host_hourly_extract.window_start

  match:
    $ws by 1h

  outcome:
    $active_fleet_hosts = sum(if($host_personal_baseline.active_hours >= 30, 1, 0))
    $sum_fleet_obs = sum(if($host_personal_baseline.active_hours >= 30, $host_hourly_extract.hourly_count, 0))
    $sum_fleet_exp = sum(if($host_personal_baseline.active_hours >= 30, $host_personal_baseline.personal_avg, 0.0))
    $sum_fleet_sd = sum(if($host_personal_baseline.active_hours >= 30, $host_personal_baseline.personal_stddev, 0.0))
}

// Root Stage: Leave-One-Out Personal Z & Mature-Cohort Fleet Shift Subtraction
$host = $host_hourly_extract.host
$host = $host_personal_baseline.host
$ws = $host_hourly_extract.window_start
$ws = $fleet_concurrent_baseline.ws

match:
  $host, $ws by 1h

outcome:
  $observation_count = max($host_hourly_extract.hourly_count)
  $baseline_active_samples = max($host_personal_baseline.active_hours)
  $fleet_prevalence = max($fleet_concurrent_baseline.active_fleet_hosts)
  $distinct_binaries = max($host_hourly_extract.distinct_procs)

  // Leave-One-Out Personal Standardization
  $raw_n_prior = $baseline_active_samples - 1
  $n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)
  $baseline_mean = 1.0 * (max($host_personal_baseline.sum_x) - $observation_count) / $n_prior
  $raw_loo_var = ((max($host_personal_baseline.sum_x2) - (1.0 * $observation_count * $observation_count)) / $n_prior) - ($baseline_mean * $baseline_mean)
  $floor_var = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $safe_var = if($raw_loo_var > $floor_var, $raw_loo_var, $floor_var)
  $baseline_dispersion = math.sqrt($safe_var)
  $personal_z = ($observation_count - $baseline_mean) / $baseline_dispersion

  // Mature-Cohort Historical-Referenced Fleet Shift Z
  $safe_hosts = if($fleet_prevalence > 0, $fleet_prevalence, 1)
  $fleet_exp_mean = 1.0 * max($fleet_concurrent_baseline.sum_fleet_exp) / $safe_hosts
  $raw_fleet_var = (1.0 * max($fleet_concurrent_baseline.sum_fleet_sd) / $safe_hosts) * (1.0 * max($fleet_concurrent_baseline.sum_fleet_sd) / $safe_hosts)
  $fleet_floor_var = if($fleet_exp_mean > 1.0, $fleet_exp_mean, 1.0)
  $safe_fleet_var = if($raw_fleet_var > $fleet_floor_var, $raw_fleet_var, $fleet_floor_var)
  $fleet_z = ((1.0 * max($fleet_concurrent_baseline.sum_fleet_obs) / $safe_hosts) - $fleet_exp_mean) / math.sqrt($safe_fleet_var)
  $pos_fleet_z = if($fleet_z > 0.0, $fleet_z, 0.0)
  $delta_z = $personal_z - $pos_fleet_z

condition:
  $baseline_active_samples >= 30
  and $fleet_prevalence >= 5
  and $observation_count >= 25
  and $delta_z >= 3.0

order:
  $delta_z desc
