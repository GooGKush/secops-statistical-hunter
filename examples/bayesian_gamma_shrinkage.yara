// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for high-confidence host activity surges using Poisson-Gamma Bayesian Credibility Shrinkage
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH / NETWORK_HTTP / USER_LOGIN)
// Statistical Model: Poisson-Gamma Bayesian Conjugate Updating & Credibility Weighting
// Operational Analogy: "The Seasoned SOC Detective"
// Mathematical Rationale:
//   Traditional Z-scores can produce false alarms on noisy, erratic endpoints.
//   Bayesian shrinkage uses the Method of Moments to estimate Gamma prior hyperparameters
//   (alpha_0, beta_0) from the host historical baseline, weighting prior stability against
//   current-day evidence. Small bursts on rock-solid predictable hosts trigger true anomaly shifts,
//   while erratic hosts require massive evidence.
// Sensitivity Boundary: BALANCED (Bayesian Belief Shift Ratio >= 3.0, Min Events >= 15, Active Units >= 30)
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
// Keyed on the window (NOT the host): grouping by $host and counting distinct
// hosts always yields 1. A $dummy = 1 Cartesian key is rejected by the compiler.
stage fleet_context {
  $ws = $host_hourly_activity.window_start

  match:
    $ws by 1h

  outcome:
    $fleet_hosts = count_distinct($host_hourly_activity.host)
}

// Root Stage: Bayesian Conjugate Updating & Credibility Scoring
$host = $host_hourly_activity.host
$host = $host_prior_stats.host
$ws = $host_hourly_activity.window_start
$ws = $fleet_context.ws

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
  $variance = max($host_prior_stats.hist_stddev) * max($host_prior_stats.hist_stddev)
  $safe_var = if($variance > 0, $variance, 1.0)
  $beta_prior = max($host_prior_stats.hist_mean) / $safe_var
  $alpha_prior = (max($host_prior_stats.hist_mean) * max($host_prior_stats.hist_mean)) / $safe_var
  $posterior_arrival_rate = ($alpha_prior + max($host_hourly_activity.hourly_count)) / ($beta_prior + 1.0)
  $prior_weight_pct = $beta_prior / ($beta_prior + 1.0)
  $evidence_weight_pct = 1.0 / ($beta_prior + 1.0)
  $safe_hist_mean = if(max($host_prior_stats.hist_mean) > 0, max($host_prior_stats.hist_mean), 1.0)
  $anomaly_score = $posterior_arrival_rate / $safe_hist_mean

condition:
  $baseline_active_samples >= 30
  and $observation_count >= 15
  and $anomaly_score >= 3.0

order:
  $anomaly_score desc
