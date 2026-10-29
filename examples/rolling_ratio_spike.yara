// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect velocity bursts in failed authentications indicating brute force or password spraying campaigns.
// Target Telemetry: UDM_EVENTS (USER_LOGIN)
// Statistical Model: Multi-Window Moving Average Rolling Ratio (1-Day vs 7-Day vs 30-Day)
// Mathematical Rationale:
//   - Why this model: Compares the latest UTC calendar day's authentication failures against short-term (7d)
//     and medium-term (30d) moving averages using native 'by 1d' window_start epoch boundaries.
//   - Noise protection: Enforces a daily volume floor of >= 100 failed logins on the latest day, a baseline
//     density floor (>= 14 active days), and safe conditional denominators (no additive denominator blunting).
// Sensitivity Boundary: BALANCED (1v7 Ratio >= 3.0x AND 1v30 Ratio >= 5.0x, Latest Day Failed Logins >= 100, Active Days >= 14)
// ============================================================================

// Stage 1: Daily authentication failure counts per target user (UTC-aligned by 1d)
stage daily_auth_fails {
    metadata.event_type = "USER_LOGIN"
    $etype = metadata.event_type
    (security_result.action = "BLOCK" or security_result.action = "FAIL")
    target.user.userid = $user
    $user != ""

  match:
    $etype, $user by 1d
  outcome:
    $fail_count = count(metadata.id)
}

// Stage 2: Anchor the latest observed daily bucket across the search horizon
stage fleet_latest_day {
    $etype = $daily_auth_fails.etype

  match:
    $etype
  outcome:
    $max_ws = max($daily_auth_fails.window_start)
    $cutoff_7d = max($daily_auth_fails.window_start) - 518400
    $cutoff_30d = max($daily_auth_fails.window_start) - 2505600
}

// Stage 3: Bucket sums into 1-Day (latest day), 7-Day rolling, and 30-Day rolling windows
stage window_buckets {
    $etype = $daily_auth_fails.etype
    $etype = $fleet_latest_day.etype
    $user = $daily_auth_fails.user

  match:
    $user
  outcome:
    $sum_1d = sum(if($daily_auth_fails.window_start = $fleet_latest_day.max_ws, $daily_auth_fails.fail_count, 0))
    $sum_7d = sum(if($daily_auth_fails.window_start >= $fleet_latest_day.cutoff_7d, $daily_auth_fails.fail_count, 0))
    $sum_30d = sum(if($daily_auth_fails.window_start >= $fleet_latest_day.cutoff_30d, $daily_auth_fails.fail_count, 0))
    $active_days = count_distinct($daily_auth_fails.window_start)
}

// Root Stage: Calculate moving averages, surge ratios, and emit 6 Evidence Pillars
$user = $window_buckets.user

match:
  $user
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($window_buckets.sum_1d)
  $baseline_active_samples = max($window_buckets.active_days)
  $avg_30d = max($window_buckets.sum_30d) / 30.0
  $avg_7d = max($window_buckets.sum_7d) / 7.0
  $baseline_mean = $avg_30d
  $baseline_dispersion = $avg_7d
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($window_buckets.sum_1d)

  // Unbiased Conditional Denominators & Velocity Ratios
  $safe_7d = if($avg_7d > 0.2, $avg_7d, 0.2)
  $safe_30d = if($avg_30d > 0.2, $avg_30d, 0.2)
  $ratio_1v7 = $observation_count / $safe_7d
  $ratio_1v30 = $observation_count / $safe_30d

condition:
  $baseline_active_samples >= 14
  and $observation_count >= 100
  and $ratio_1v7 >= 3.0
  and $ratio_1v30 >= 5.0

order:
  $ratio_1v30 desc
