// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for anomalous failure bursts (password spray, credential stuffing, or service errors) via Beta-Binomial Predictive Standardization
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Leave-One-Out Conjugate Beta-Binomial Updating & Predictive Failure Z-Score ($fail_z)
// Operational Analogy: "Entity-Adaptive Failure Rate Regularization"
// Mathematical Rationale:
//   Updates a Beta(1.0, 19.0) hyperprior (~5% baseline failure rate) with each entity's leave-one-out
//   historical failures and successes from Stage 2, then standardizes the scored hour's failure count against
//   the exact Beta-Binomial predictive variance n * p0 * (1 - p0) * (M + n) / (M + 1).
// Sensitivity Boundary: BALANCED (Predictive Failure Z >= 3.5σ, Min Attempts >= 15, Min Fails >= 10, Active Hours >= 12)
// ============================================================================

// Stage 1: Aggregate total and failed trials per entity in tumbling hourly windows
stage entity_hourly_trials {
  $e.metadata.event_type = "USER_LOGIN"
  $user = $e.target.user.userid
  $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count($e.metadata.id)
    $failed_trials = sum(if($e.security_result.action = "BLOCK" or $e.security_result.action = "FAIL", 1, 0))
    $distinct_sources = count_distinct($e.principal.ip)
}

// Stage 2: Historical Trial & Failure Accumulation per Entity
stage entity_historical_rates {
  $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

// Stage 3: Concurrent Fleet Failure Breadth
stage fleet_stats {
  $ws = $entity_hourly_trials.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_users = sum(if($entity_hourly_trials.failed_trials >= 10, 1, 0))
}

// Root Stage: Leave-One-Out Beta-Binomial Conjugate Updating & Predictive Failure Z
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$ws = $entity_hourly_trials.window_start
$ws = $fleet_stats.ws

match:
  $user, $ws by 1h

outcome:
  $observation_count = max($entity_hourly_trials.failed_trials)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)
  $safe_trials = if($hourly_trials_count > 0, $hourly_trials_count, 1)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Leave-One-Out Beta Prior & Beta-Binomial Predictive Standardization
  $raw_prior_fails = max($entity_historical_rates.total_historical_fails) - $observation_count
  $prior_fails = if($raw_prior_fails > 0, $raw_prior_fails, 0)
  $raw_prior_events = max($entity_historical_rates.total_historical_events) - $hourly_trials_count
  $prior_events = if($raw_prior_events > $prior_fails, $raw_prior_events, $prior_fails)
  $prior_succ = $prior_events - $prior_fails
  $alpha_prior = 1.0 + $prior_fails
  $beta_prior = 19.0 + $prior_succ
  $prior_total = $alpha_prior + $beta_prior
  $baseline_mean = $alpha_prior / $prior_total
  $posterior_fail_prob = ($alpha_prior + $observation_count) / ($prior_total + $safe_trials)
  $pred_var = $safe_trials * $baseline_mean * (1.0 - $baseline_mean) * (($prior_total + $safe_trials) / ($prior_total + 1.0))
  $safe_pred_var = if($pred_var > 0.25, $pred_var, 0.25)
  $baseline_dispersion = math.sqrt($safe_pred_var)
  $fail_z = ($observation_count - ($safe_trials * $baseline_mean)) / $baseline_dispersion

condition:
  $baseline_active_samples >= 12
  and $hourly_trials_count >= 15
  and $observation_count >= 10
  and $fail_z >= 3.5

order:
  $fail_z desc
