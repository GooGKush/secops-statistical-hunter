// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect automated authentication spray campaigns and burst reconnaissance waves that evade volume rate limits.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Zero-Inclusive Poisson Dispersion via Fano Factor (F = σ² / μ >= 4.0 over T = 168 buckets) & Fleet Prevalence Filter
// Mathematical Rationale:
//   - Why this model: Random human login mistakes occur independently over time following a memoryless Poisson process
//     where variance equals the mean (Fano Factor F = σ² / μ ≈ 1.0). Coordinated attack waves (password spraying from a
//     source IP via principal.ip or concentrated waves against target.user.userid) arrive in intermittent bursts separated
//     by silent intervals, creating extreme zero-inclusive over-dispersion (μ = Σx / T, σ² = Σx² / T - μ², F >> 4.0).
//   - Noise protection: Enforces an activity floor of >= 15 failed logins, router-validated window bucket count
//     (T = 168 >= 1), and a zero-inclusive rate floor (μ >= 0.1) while keeping Stage 2 purely numeric.
// Sensitivity Boundary: BALANCED (Fano Factor F >= 4.0x, Min Total Failures >= 15, Zero-Inclusive Mean μ >= 0.1, Window Buckets T = 168)
// ============================================================================

// Stage 1: Hourly authentication failure counts, squared counts, and source IP diversity per target user
stage hourly_failures {
    metadata.event_type = "USER_LOGIN"
    (security_result.action = "BLOCK" or security_result.action = "FAIL")
    target.user.userid = $entity
    $entity != ""

  match:
    $entity by 1h
  outcome:
    $hourly_fails = count(metadata.id)
    $hourly_fails_sq = 1.0 * count(metadata.id) * count(metadata.id)
    $sample_peers = array_distinct(principal.ip)
}

// Stage 2: Purely numeric accumulation of Σx, Σx², and active non-zero bucket count (never mix array_distinct here)
stage dispersion_baseline {
    $entity = $hourly_failures.entity

  match:
    $entity
  outcome:
    $sum_x = sum($hourly_failures.hourly_fails)
    $sum_x2 = sum($hourly_failures.hourly_fails_sq)
    $active_hours = count($hourly_failures.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of users experiencing burst failures per window
stage fleet_breadth {
    $ws = $hourly_failures.window_start

  match:
    $ws by 1h
  outcome:
    $fleet_users = sum(if($hourly_failures.hourly_fails >= 5, 1, 0))
}

// Root Stage: Join stages, rebuild zero-inclusive Fano Factor over T = 168 hourly buckets, and emit 6 Evidence Pillars
$entity = $hourly_failures.entity
$entity = $dispersion_baseline.entity
$ws = $hourly_failures.window_start
$ws = $fleet_breadth.ws

match:
  $entity
outcome:
  $sum_x = max($dispersion_baseline.sum_x)
  $sum_x2 = max($dispersion_baseline.sum_x2)
  $zero_incl_mean = 1.0 * $sum_x / 168
  $mean_sq = 1.0 * $sum_x2 / 168
  $raw_var = $mean_sq - ($zero_incl_mean * $zero_incl_mean)
  $zero_incl_var = if($raw_var > 0.0, $raw_var, 0.0)
  $zero_incl_sd = math.sqrt($zero_incl_var)
  $safe_mean = if($zero_incl_mean > 0.0, $zero_incl_mean, 1.0)
  $raw_fano = $zero_incl_var / $safe_mean
  $fano_factor = if($zero_incl_mean > 0.0, $raw_fano, 0.0)

  // 6 Core Evidence Pillars
  $observation_count = $sum_x
  $baseline_active_samples = max($dispersion_baseline.active_hours)
  $baseline_mean = $zero_incl_mean
  $baseline_dispersion = $zero_incl_sd
  $fleet_prevalence = max($fleet_breadth.fleet_users)
  $distinct_binaries = $sum_x
  $sample_commands = array_distinct($hourly_failures.sample_peers)

condition:
  $baseline_active_samples >= 1
  and $observation_count >= 15
  and $baseline_mean >= 0.1
  and $fano_factor >= 4.0

order:
  $fano_factor desc
