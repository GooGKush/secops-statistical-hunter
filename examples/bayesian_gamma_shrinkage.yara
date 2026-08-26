// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for high-confidence host activity surges using Poisson-Gamma Bayesian Credibility Shrinkage
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH / NETWORK_HTTP / USER_LOGIN)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting
// Operational Analogy: "The Seasoned SOC Detective"
// Mathematical Rationale:
//   Traditional Z-scores can produce false alarms on noisy, erratic endpoints.
//   Bayesian shrinkage uses the Method of Moments to estimate Gamma prior hyperparameters
//   (alpha_0, beta_0) from the host's historical baseline, weighting prior stability against
//   current-day evidence. Small bursts on rock-solid predictable hosts trigger true anomaly shifts,
//   while erratic hosts require massive evidence.
// Sensitivity Boundary: Bayesian Belief Shift Ratio >= 3.0, Min Events >= 20, Active Units >= 24
// ============================================================================

// Stage 1: Extraction & Binning (Hourly activity volume per host)
stage host_hourly_activity {
  $e.metadata.event_type = "PROCESS_LAUNCH"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count($e.metadata.id)
    $distinct_procs = count_distinct($e.target.process.file.full_path)
}

// Stage 2: Historical Parameter Estimation (Method of Moments Gamma Prior)
stage host_prior_stats {
  $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $hist_mean = avg($host_hourly_activity.hourly_count)
    $hist_stddev = stddev($host_hourly_activity.hourly_count)
    $active_hours = count($host_hourly_activity.window_start)
}

// Stage 3: Organizational Peer Prevalence Baseline
stage fleet_context {
  $host = $host_hourly_activity.host

  match:
    $host

  outcome:
    $fleet_hosts = count_distinct($host_hourly_activity.host)
}

// Root Stage: Bayesian Conjugate Updating & Credibility Scoring
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$host = $fleet_context.host
$ws = $host_hourly_activity.window_start

$obs = $host_hourly_activity.hourly_count
$mu = $host_prior_stats.hist_mean
$sd = $host_prior_stats.hist_stddev

// Gamma Prior Hyperparameters (Method of Moments: variance = sd * sd; beta = mu / var; alpha = mu * beta)
$var = $sd * $sd
$beta_prior = $mu / $var
$alpha_prior = $mu * $beta_prior

// Conjugate Posterior Updating (k = obs, t = 1 hour window)
$alpha_post = $alpha_prior + $obs
$beta_post = $beta_prior + 1.0

// Posterior Expected Arrival Rate & Credibility Weights
$posterior_mean = $alpha_post / $beta_post
$prior_credibility_weight = $beta_prior / $beta_post
$evidence_weight = 1.0 / $beta_post

// Bayesian Belief Shift Ratio (Posterior Rate / Baseline Mean)
$bayes_shift_ratio = $posterior_mean / $mu

match:
  $host, $ws by 1h

outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly_activity.hourly_count)
  $baseline_active_samples = max($host_prior_stats.active_hours)
  $baseline_mean = max($host_prior_stats.hist_mean)
  $baseline_dispersion = max($host_prior_stats.hist_stddev)
  $fleet_prevalence = max($fleet_context.fleet_hosts)
  $distinct_binaries = max($host_hourly_activity.distinct_procs)

  // Bayesian Posterior Metrics
  $posterior_arrival_rate = max($posterior_mean)
  $prior_weight_pct = max($prior_credibility_weight)
  $evidence_weight_pct = max($evidence_weight)
  $anomaly_score = max($bayes_shift_ratio)

condition:
  // Small-Sample Protection Floor
  $baseline_active_samples >= 24
  and $observation_count >= 20
  and $baseline_dispersion >= 3.0
  and $anomaly_score >= 3.0
