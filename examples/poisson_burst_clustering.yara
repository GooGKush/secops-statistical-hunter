// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect automated authentication spray campaigns and burst reconnaissance waves that evade volume rate limits.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Poisson Dispersion via Fano Factor (F = σ² / μ > 4.0)
// Mathematical Rationale:
//   - Why this model: Random human login mistakes occur independently over time following a memoryless Poisson process
//     where variance equals the mean (Fano Factor F = σ² / μ ≈ 1.0). Coordinated attack waves (e.g. password spraying,
//     credential stuffing) arrive in synchronized, intermittent bursts across users, creating extreme over-dispersion (F >> 4.0).
//   - Noise protection: Enforces an activity floor of >= 15 failed logins over the baseline window and a mean rate floor (μ >= 1.0)
//     to prevent small-sample division noise on dormant accounts.
// Sensitivity Boundary: BALANCED (Fano Factor F >= 4.0x, Min Total Failures >= 15, Historical Mean μ >= 1.0)
// ============================================================================

// Stage 1: Hourly authentication failure counts per target user
stage hourly_failures {
    metadata.event_type = "USER_LOGIN"
    (security_result.action = "BLOCK" or security_result.action = "FAIL")
    target.user.userid = $user
    $user != ""

  match:
    $user by 1h
  outcome:
    $hourly_fails = count(metadata.id)
}

// Stage 2: Calculate historical arrival mean (μ) and variance (σ²) across the search window
stage dispersion_baseline {
    $user = $hourly_failures.user

  match:
    $user
  outcome:
    $mean_rate = avg($hourly_failures.hourly_fails)
    $stddev_rate = stddev($hourly_failures.hourly_fails)
    $total_failures = sum($hourly_failures.hourly_fails)
}

// Root Stage: Join stages, calculate Fano Factor (σ² / μ), and filter for clustered bursts
$user = $hourly_failures.user
$user = $dispersion_baseline.user

match:
  $user
outcome:
  $mu = max($dispersion_baseline.mean_rate)
  $stddev_val = max($dispersion_baseline.stddev_rate)
  $total_fails = max($dispersion_baseline.total_failures)
  // Variance is standard deviation squared (σ²)
  $var_rate = $stddev_val * $stddev_val
  // Fano Factor: ratio of variance to mean (F = σ² / μ)
  $fano_factor = $var_rate / $mu

condition:
  // Activity Floor: at least 15 failed logins across the search window
  $total_fails >= 15
  // Historical Rate Floor: average at least 1 failure per active hour (protects against zero-division)
  and $mu >= 1.0
  // Over-dispersion Threshold: Fano Factor >= 4.0 indicates non-random burst clustering
  and $fano_factor >= 4.0

order:
  $fano_factor desc
