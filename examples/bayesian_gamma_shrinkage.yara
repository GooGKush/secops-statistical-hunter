// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for high-confidence host activity surges using Poisson-Gamma Bayesian Shrinkage & Overdispersion Predictive Z-Score
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Leave-One-Out Conjugate Gamma-Poisson Predictive Standardization with Empirical Excess Overdispersion
// Operational Analogy: "The Seasoned SOC Detective"
// Mathematical Rationale:
//   Updates a conjugate Gamma(2.0, 2.0) prior with leave-one-out prior volume across 167 prior hourly buckets
//   and adds empirical excess overdispersion variance max(0, E[X^2]_prior - mu_prior^2 - mu_prior)
//   so steady bursty servers are shrunk while genuine surges on quiet predictable hosts produce high $bayesian_z.
// Sensitivity Boundary: BALANCED (Bayesian Predictive Z >= 3.0σ, Min Events >= 15, Active Hours >= 24)
// ============================================================================

// Stage 1: Extraction & Binning (Hourly activity volume and squared count per host)
stage host_hourly_activity {
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

// Stage 2: Historical Moment Accumulation per Host
stage host_prior_stats {
  $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $sum_x = sum($host_hourly_activity.hourly_count)
    $sum_x2 = sum($host_hourly_activity.hourly_count_sq)
    $active_hours = count($host_hourly_activity.window_start)
}

// Stage 3: Organizational Peer Prevalence Baseline
stage fleet_context {
  $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = sum(if($host_hourly_activity.hourly_count >= 15, 1, 0))
}

// Root Stage: Leave-One-Out Conjugate Gamma-Poisson Updating & Predictive Z-Score
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

match:
  $host, $ws by 1h

outcome:
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_procs)

  // Leave-One-Out Conjugate Gamma Prior & Predictive Dispersion
  $raw_prior_sum = max($host_prior_stats.sum_x) - $observation_count
  $prior_sum = if($raw_prior_sum > 0, $raw_prior_sum, 0)
  $raw_prior_sum_sq = max($host_prior_stats.sum_x2) - (1.0 * $observation_count * $observation_count)
  $prior_sum_sq = if($raw_prior_sum_sq > 0.0, $raw_prior_sum_sq, 0.0)
  $alpha_prior = 2.0 + $prior_sum
  $beta_prior = 2.0 + 167
  $baseline_mean = $alpha_prior / $beta_prior
  $posterior_arrival_rate = ($alpha_prior + $observation_count) / ($beta_prior + 1.0)
  $prior_emp_mean = 1.0 * $prior_sum / 167
  $raw_excess_var = (1.0 * $prior_sum_sq / 167) - ($prior_emp_mean * $prior_emp_mean) - $prior_emp_mean
  $excess_var = if($raw_excess_var > 0.0, $raw_excess_var, 0.0)
  $raw_pred_var = ($baseline_mean * ($beta_prior + 1.0) / $beta_prior) + $excess_var
  $safe_pred_var = if($raw_pred_var > 1.0, $raw_pred_var, 1.0)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $bayesian_z = ($observation_count - $baseline_mean) / $baseline_dispersion

condition:
  $baseline_active_samples >= 24
  and $observation_count >= 15
  and $bayesian_z >= 3.0

order:
  $bayesian_z desc
