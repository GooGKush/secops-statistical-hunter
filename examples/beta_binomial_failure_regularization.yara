// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for anomalous failure ratios (e.g. password spray or HTTP 5xx errors) with Beta-Binomial Regularization
// Target Telemetry: UDM_EVENTS (USER_LOGIN / NETWORK_HTTP)
// Statistical Model: Beta-Binomial Bayesian Updating & Small-Sample Shrinkage
// Operational Analogy: "Small-Sample Ratio Regularization"
// Mathematical Rationale:
//   Raw failure percentages (fails / total) trigger massive false alarms on low sample counts
//   (e.g., 1 failed login out of 1 total attempt = 100% failure rate).
//   Beta-Binomial conjugate updating regularizes the failure probability toward the population
//   prior baseline, filtering out transient single-trial mistakes while catching true sustained attacks.
// Sensitivity Boundary: Regularized Posterior Failure Prob >= 0.70, Min Trials >= 10
// ============================================================================

// Stage 1: Aggregate successes and failures per entity in tumbling hourly windows
stage entity_hourly_trials {
  $e.metadata.event_type = "USER_LOGIN"
  $user = $e.target.user.userid
  $user != ""

  match:
    $user by 1h

  outcome:
    $total_trials = count($e.metadata.id)
    $failed_trials = sum(if($e.security_result.action = "BLOCK", 1, 0))
    $distinct_sources = count_distinct($e.principal.ip)
}

// Stage 2: Historical Parameter Estimation across all active baseline windows
stage entity_historical_rates {
  $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $total_historical_events = sum($entity_hourly_trials.total_trials)
    $total_historical_fails = sum($entity_hourly_trials.failed_trials)
    $active_hours = count($entity_hourly_trials.window_start)
}

// Stage 3: Fleet Context
stage fleet_stats {
  $user = $entity_hourly_trials.user

  match:
    $user

  outcome:
    $fleet_users = count_distinct($entity_hourly_trials.user)
}

// Root Stage: Beta-Binomial Conjugate Updating & Shrinkage
$user = $entity_hourly_trials.user
$user = $entity_historical_rates.user
$user = $fleet_stats.user
$ws = $entity_hourly_trials.window_start

$trials = $entity_hourly_trials.total_trials
$fails = $entity_hourly_trials.failed_trials
$successes = $trials - $fails

// Population Prior Estimation (Default informative prior: alpha_0 = 1.0, beta_0 = 9.0 ~ 10% normal corporate failure rate)
$alpha_prior = 1.0
$beta_prior = 9.0

// Conjugate Posterior Updating
$alpha_post = $alpha_prior + $fails
$beta_post = $beta_prior + $successes
$total_post = $alpha_post + $beta_post

// Regularized Posterior Failure Probability
$posterior_fail_prob = $alpha_post / $total_post
$raw_fail_rate = $fails / $trials

match:
  $user, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($entity_hourly_trials.failed_trials)
  $baseline_active_samples = max($entity_historical_rates.active_hours)
  $baseline_mean = max($entity_historical_rates.total_historical_fails)
  $baseline_dispersion = max($entity_historical_rates.total_historical_events)
  $fleet_prevalence = max($fleet_stats.fleet_users)
  $distinct_binaries = max($entity_hourly_trials.distinct_sources)

  // Regularized Posterior Probability
  $regularized_failure_prob = max($posterior_fail_prob)
  $unregularized_raw_rate = max($raw_fail_rate)
  $hourly_trials_count = max($entity_hourly_trials.total_trials)

condition:
  // Small-Sample Protection Floor
  $baseline_active_samples >= 12
  and $hourly_trials_count >= 10
  and $observation_count >= 5
  and $regularized_failure_prob >= 0.70
