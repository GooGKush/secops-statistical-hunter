// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting extreme statistical surges in process launch volume (Z-Score > 3.0).
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Leave-One-Out Parametric Z-Score per Host (Z = (x - μ_{-t}) / max(s_{-t}, sqrt(max(μ_{-t}, 1.0)))) & Fleet Prevalence
// Mathematical Rationale:
//   - Leave-One-Out (n - 1) Baseline: Excludes the scored hour from its own baseline mean and sample SD
//     so single extreme surges cannot inflate σ and mask themselves via Samuelson's inequality.
//   - Continuous Poisson Dispersion Floor: Uses sqrt(max(μ_{-t}, 1.0)) without additive denominator blunting
//     or hard dispersion cliffs, while measuring surging peer prevalence in Stage 3.
// Sensitivity Boundary: BALANCED (Z-Score > 3.0, Min Hourly Executions >= 25, Min Prior Active Samples >= 30)
// ============================================================================

// Stage 1: Hourly process execution counts, squared counts, distinct binaries, and sample commands per host
stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $hourly_count_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Whole-window sufficient statistics (Σx, Σx², active bucket count) per host
stage host_stats {
    $entity = $host_hourly.entity

  match:
    $entity
  outcome:
    $sum_x = sum($host_hourly.hourly_count)
    $sum_x2 = sum($host_hourly.hourly_count_sq)
    $active_samples = count($host_hourly.window_start)
}

// Stage 3: Enterprise-wide fleet prevalence of surging hosts per window
stage fleet_breadth {
    $ws = $host_hourly.window_start

  match:
    $ws by 1h
  outcome:
    $fleet_hosts = sum(if($host_hourly.hourly_count >= 25, 1, 0))
}

// Root Stage: Compute leave-one-out Z-score with continuous Poisson floor and emit 6 Evidence Pillars
$entity = $host_hourly.entity
$entity = $host_stats.entity
$window_start = $host_hourly.window_start
$window_start = $fleet_breadth.ws

match:
  $entity, $window_start by 1h
outcome:
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($host_stats.active_samples) - 1
  $safe_n_prior = if($baseline_active_samples > 1, $baseline_active_samples, 1)
  $loo_sum = max($host_stats.sum_x) - $observation_count
  $baseline_mean = 1.0 * $loo_sum / $safe_n_prior
  $df = $baseline_active_samples - 1
  $safe_df = if($df > 1, $df, 1)
  $raw_ss = (max($host_stats.sum_x2) - (1.0 * $observation_count * $observation_count)) - ((1.0 * $loo_sum * $loo_sum) / $safe_n_prior)
  $pos_ss = if($raw_ss > 0.0, $raw_ss, 0.0)
  $loo_sd = math.sqrt($pos_ss / $safe_df)
  $floor_arg = if($baseline_mean > 1.0, $baseline_mean, 1.0)
  $poisson_floor = math.sqrt($floor_arg)
  $baseline_dispersion = if($loo_sd > $poisson_floor, $loo_sd, $poisson_floor)
  $z_score = ($observation_count - $baseline_mean) / $baseline_dispersion
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)

condition:
  $baseline_active_samples >= 30
  and $observation_count >= 25
  and $z_score > 3.0

order:
  $z_score desc
