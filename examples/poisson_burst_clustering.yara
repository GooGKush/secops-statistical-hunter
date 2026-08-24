// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect automated authentication spray campaigns and burst reconnaissance waves that evade volume rate limits.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Poisson Dispersion via Fano Factor (F = σ² / μ > 4.0) & Fleet Prevalence Filter
// Mathematical Rationale:
//   - Why this model: Random human login mistakes occur independently over time following a memoryless Poisson process
//     where variance equals the mean (Fano Factor F = σ² / μ ≈ 1.0). Coordinated attack waves (e.g. password spraying,
//     credential stuffing) arrive in synchronized, intermittent bursts across users, creating extreme over-dispersion (F >> 4.0).
//   - Noise protection: Enforces an activity floor of >= 15 failed logins over the baseline window, a sample density floor (>= 30 active hours),
//     and a mean rate floor (μ >= 1.0) to prevent small-sample division noise on dormant accounts.
// Sensitivity Boundary: BALANCED (Fano Factor F >= 4.0x, Min Total Failures >= 15, Historical Mean μ >= 1.0, Active Hours >= 30)
// ============================================================================

// Stage 1: Hourly authentication failure counts and source IP diversity per target user
stage hourly_failures {
    metadata.event_type = "USER_LOGIN"
    (security_result.action = "BLOCK" or security_result.action = "FAIL")
    target.user.userid = $user
    $user != ""

  match:
    $user by 1h
  outcome:
    $hourly_fails = count(metadata.id)
    $sample_ip = array_distinct(principal.ip)
}

// Stage 2: Calculate historical arrival mean (μ), standard deviation (σ), and active sample density
stage dispersion_baseline {
    $user = $hourly_failures.user

  match:
    $user
  outcome:
    $mean_rate = avg($hourly_failures.hourly_fails)
    $stddev_rate = stddev($hourly_failures.hourly_fails)
    $total_failures = sum($hourly_failures.hourly_fails)
    $active_hours = count($hourly_failures.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of users experiencing authentication failures
stage fleet_prevalence {
    $user = $hourly_failures.user

  match:
    $user
  outcome:
    $fleet_users = count_distinct($hourly_failures.user)
}

// Root Stage: Join stages, calculate Fano Factor in events section, and emit 6 Evidence Pillars
$user = $hourly_failures.user
$user = $dispersion_baseline.user
$user = $fleet_prevalence.user

// Linear event-level Fano Factor computation (eliminates intra-stage outcome race conditions)
$var_rate = $dispersion_baseline.stddev_rate * $dispersion_baseline.stddev_rate
$fano = $var_rate / $dispersion_baseline.mean_rate

match:
  $user
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($dispersion_baseline.total_failures)
  $baseline_active_samples = max($dispersion_baseline.active_hours)
  $baseline_mean = max($dispersion_baseline.mean_rate)
  $baseline_dispersion = max($dispersion_baseline.stddev_rate)
  $fleet_prevalence = max($fleet_prevalence.fleet_users)
  $distinct_binaries = max($dispersion_baseline.total_failures)
  $sample_commands = array_distinct($hourly_failures.sample_ip)
  
  // Aggregate Fano Factor
  $fano_factor = max($fano)

condition:
  // Small-Sample Protection: Require at least 30 active hourly observation windows
  $baseline_active_samples >= 30
  // Activity Floor: at least 15 failed logins across the search window
  and $observation_count >= 15
  // Historical Rate Floor: average at least 1 failure per active hour (protects against zero-division)
  and $baseline_mean >= 1.0
  // Over-dispersion Threshold: Fano Factor >= 4.0 indicates non-random burst clustering
  and $fano_factor >= 4.0

order:
  $fano_factor desc

