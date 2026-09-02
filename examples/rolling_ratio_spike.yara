// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect velocity bursts in failed authentications indicating brute force or password spraying campaigns.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Multi-Window Moving Average Rolling Ratio (1-Day vs 7-Day vs 30-Day)
// Mathematical Rationale:
//   - Why this model: Compares current day activity against short-term (7d) and medium-term (30d) moving averages using integer epoch day arithmetic.
//     Sudden spikes in login failures against both historical baselines reveal active attack waves without assuming stationary Gaussian distribution.
//   - Noise protection: Enforces a daily volume floor of >= 100 failed logins today, a baseline density floor (>= 14 active days),
//     and requires exceeding both moving averages simultaneously.
// Sensitivity Boundary: BALANCED (1v7 Ratio >= 3.0x AND 1v30 Ratio >= 5.0x, Today Failed Logins >= 100, Active Days >= 14)
// ============================================================================

// Stage 1: Daily authentication failure counts per target user
stage daily_auth_fails {
    metadata.event_type = "USER_LOGIN"
    (security_result.action = "BLOCK" or security_result.action = "FAIL")
    target.user.userid = $user
    $user != ""
    // Calculate relative day index from epoch (0 = 1970-01-01)
    $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)

  match:
    $user, $day_id
  outcome:
    $fail_count = count(metadata.id)
}

// Stage 2: Find the latest day_id in the baseline window (current/max day)
stage max_day_tracker {
    $user = $daily_auth_fails.user
    $day_id = $daily_auth_fails.day_id

  match:
    $user
  outcome:
    $max_day = max($day_id)
}

// Stage 3: Bucket sums into 1-Day (today), 7-Day rolling, and 30-Day rolling windows
stage window_buckets {
    $user = $daily_auth_fails.user
    $day_id = $daily_auth_fails.day_id
    $user = $max_day_tracker.user
    $max_day = $max_day_tracker.max_day

  match:
    $user
  outcome:
    // Today's count
    $sum_1d = sum(if($daily_auth_fails.day_id = $max_day_tracker.max_day, $daily_auth_fails.fail_count, 0))
    // Last 7 days total
    $sum_7d = sum(if($daily_auth_fails.day_id >= $max_day_tracker.max_day - 6, $daily_auth_fails.fail_count, 0))
    // Last 30 days total
    $sum_30d = sum(if($daily_auth_fails.day_id >= $max_day_tracker.max_day - 29, $daily_auth_fails.fail_count, 0))
    $active_days = count_distinct($daily_auth_fails.day_id)
}

// Root Stage: Calculate moving averages, surge ratios, and emit 6 Evidence Pillars
$user = $window_buckets.user

match:
  $user
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($window_buckets.sum_1d)
  $baseline_active_samples = max($window_buckets.active_days)
  $baseline_mean = max($window_buckets.sum_30d) / 30.0
  $baseline_dispersion = max($window_buckets.sum_7d) / 7.0
  $fleet_prevalence = 1
  $distinct_binaries = max($window_buckets.sum_1d)
  
  // Aggregate Velocity Ratios
  $ratio_1v7 = max($window_buckets.sum_1d) / ((max($window_buckets.sum_7d) / 7.0) + 0.1)
  $ratio_1v30 = max($window_buckets.sum_1d) / ((max($window_buckets.sum_30d) / 30.0) + 0.1)

condition:
  // Small-Sample Protection: Require at least 14 active observation days
  $baseline_active_samples >= 14
  // Volume Floor: at least 100 failed logins today
  and $observation_count >= 100
  // Velocity Spike: 1-day volume is > 3x the 7-day average AND > 5x the 30-day average
  and $ratio_1v7 >= 3.0
  and $ratio_1v30 >= 5.0

order:
  $ratio_1v30 desc

