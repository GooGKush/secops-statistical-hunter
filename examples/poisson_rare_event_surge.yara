// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect statistically improbable surges in rare administrative / security tools on endpoints with established online history.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Leave-One-Out Discrete Poisson Arrival Score (Poisson Z^2 = (k - λ)^2 / λ >= 9.0)
// Required Window Mode: Mode B (Extended 14d-30d historical baseline window; daily 'by 1d' buckets).
// Mathematical Rationale:
//   - Computes leave-one-out Jeffreys-smoothed daily rate λ = (prior_runs + 0.5) / 29 across 29 prior calendar days
//     while measuring host online maturity via distinct UTC dates in Stage 3 (host_online_baseline), so a first-time
//     execution of vssadmin.exe or procdump.exe on a mature online host fires immediately on its latest active day.
// Sensitivity Boundary: BALANCED (Poisson Z >= 3.0σ [Z^2 >= 9.0], Today Executions k >= 2, Historical Rate λ <= 2.0/day, Host Online Days >= 7)
// ============================================================================

// Stage 1: Daily execution counts for sensitive utilities per entity and tool (UTC-aligned by 1d)
stage daily_tool_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""
    $tool = target.process.file.full_path
    $tool != ""
    (
      re.regex(target.process.file.full_path, `(?i)(vssadmin|certutil|dsquery|whoami|procdump|psexec|adfind)\.exe$`)
      or re.regex(target.process.command_line, `(?i)(vssadmin|certutil|dsquery|whoami|procdump|psexec|adfind)`)
    )

  match:
    $entity, $tool by 1d
  outcome:
    $daily_count = count(metadata.id)
    $distinct_cmds = count_distinct(target.process.command_line)
    $bucket_max_ts = max(metadata.event_timestamp.seconds)
}

// Stage 2: Historical tool run accumulation per entity and tool
stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool

  match:
    $entity, $tool
  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $tool_active_days = count($daily_tool_counts.window_start)
}

// Stage 3: Host online calendar-day maturity across all PROCESS_LAUNCH telemetry
stage host_online_baseline {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""
    $utc_date = timestamp.get_date(metadata.event_timestamp.seconds, "UTC")

  match:
    $entity
  outcome:
    $online_days = count_distinct($utc_date)
    $host_max_ts = max(metadata.event_timestamp.seconds)
}

// Root Stage: Calculate Leave-One-Out Discrete Poisson Score on Latest Active Day and emit 6 Evidence Pillars
$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool
$entity = $host_online_baseline.entity
$ws = $daily_tool_counts.window_start

match:
  $entity, $tool, $ws by 1d
outcome:
  // Leave-one-out prior runs & Jeffreys-smoothed daily arrival rate over 29 prior calendar days
  $today_k = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 29

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($host_online_baseline.online_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $lambda
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

  // Aggregate Poisson Squared Score & Latest-Day Gate
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0.01, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda
  $lag_seconds = max($host_online_baseline.host_max_ts) - max($daily_tool_counts.bucket_max_ts)
  $is_latest_day = if($lag_seconds < 86400, 1, 0)

condition:
  $baseline_active_samples >= 7
  and $is_latest_day = 1
  and $observation_count >= 2
  and $baseline_mean <= 2.0
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 9.0

order:
  $poisson_z_sq desc
