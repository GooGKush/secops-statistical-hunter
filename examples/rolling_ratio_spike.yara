// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect velocity bursts in failed authentications indicating brute force or password spraying campaigns.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Multi-Window Moving Average Rolling Ratio (1-Day vs 7-Day vs 30-Day)
// Mathematical Rationale:
//   - Why this model: Compares current day activity against short-term (7d) and medium-term (30d) moving averages using integer epoch day arithmetic.
//     Sudden spikes in login failures against both historical baselines reveal active attack waves without assuming stationary Gaussian distribution.
//   - Noise protection: Enforces a daily volume floor of >= 100 failed logins today and requires exceeding both moving averages simultaneously.
// Sensitivity Boundary: BALANCED (1v7 Ratio >= 3.0x AND 1v30 Ratio >= 5.0x, Today Failed Logins >= 100)
// ============================================================================

// Stage 1: Daily authentication failure counts per target user
stage daily_auth_fails {
    metadata.event_type = "USER_LOGIN"
    security_result.action = "BLOCK" or security_result.action = "FAIL"
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
    // Today's count (offset = 0)
    $sum_1d = sum(if(($max_day - $day_id) = 0, $daily_auth_fails.fail_count, 0))
    // Last 7 days total
    $sum_7d = sum(if(($max_day - $day_id) <= 6, $daily_auth_fails.fail_count, 0))
    // Last 30 days total
    $sum_30d = sum(if(($max_day - $day_id) <= 29, $daily_auth_fails.fail_count, 0))
}

// Root Stage: Calculate moving averages and surge ratios
$user = $window_buckets.user

match:
  $user
outcome:
  $today_fails = max($window_buckets.sum_1d)
  $avg_7d = math.round(max($window_buckets.sum_7d) / 7.0, 2)
  $avg_30d = math.round(max($window_buckets.sum_30d) / 30.0, 2)
  // Velocity ratios
  $ratio_1v7 = math.round($today_fails / ($avg_7d + 0.1), 2)
  $ratio_1v30 = math.round($today_fails / ($avg_30d + 0.1), 2)

condition:
  // Volume Floor: at least 100 failed logins today
  $today_fails >= 100
  // Velocity Spike: 1-day volume is > 3x the 7-day average AND > 5x the 30-day average
  and $ratio_1v7 >= 3.0
  and $ratio_1v30 >= 5.0

order:
  $ratio_1v30 desc
