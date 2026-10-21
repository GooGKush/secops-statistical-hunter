// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect statistically improbable surges in rare administrative / security tools on endpoints with near-zero baseline history.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Discrete Poisson Arrival Score (Poisson Z^2 = (k - λ)^2 / λ >= 12.25)
// Required Window Mode: Mode B (Extended 14d-30d historical baseline window; daily 'by 1d' buckets require multi-day horizon).
// Mathematical Rationale:
//   - Why this model: High-impact administrative binaries (e.g., vssadmin.exe, certutil.exe, dsquery.exe, whoami.exe)
//     occur with very low historical daily frequency (λ <= 0.5 runs/day). Standard Z-score breaks down because the sample
//     standard deviation (s) across 30 days is nearly zero, causing false-positive divide-by-zero or mathematical distortion.
//     Under Poisson theory, the theoretical variance is λ. We compute leave-one-out historical λ = (prior_runs + 0.5) / 29.0
//     over the 29 prior calendar days (excluding today's count k so the surge does not inflate its own baseline) and score
//     squared deviance Z^2 = (k - λ)^2 / λ.
//   - Noise protection: Enforces a daily observed floor (k >= 3 executions), a baseline sample density floor (>= 7 active days),
//     and restricts baseline rate (λ <= 2.0) to isolate true discrete rare-event surges from standard routine operational tools.
// Sensitivity Boundary: BALANCED (Poisson Z >= 3.5σ [Z^2 >= 12.25], Today Executions k >= 3, Historical Rate λ <= 2.0/day, Active Days >= 7)
// ============================================================================

// Stage 1: Daily execution counts for sensitive utilities per entity and tool (UTC-aligned by 1d, no array fan-out)
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
}

// Stage 2: Historical accumulation across all active days per entity and tool
stage baseline_accumulation {
    $entity = $daily_tool_counts.entity
    $tool = $daily_tool_counts.tool
    $ws = $daily_tool_counts.window_start

  match:
    $entity, $tool
  outcome:
    $total_hist_runs = sum($daily_tool_counts.daily_count)
    $active_days = count($daily_tool_counts.window_start)
    $max_ws = max($daily_tool_counts.window_start)
}

// Root Stage: Calculate Leave-One-Out Discrete Poisson Score and emit 6 Evidence Pillars
$entity = $daily_tool_counts.entity
$tool = $daily_tool_counts.tool
$entity = $baseline_accumulation.entity
$tool = $baseline_accumulation.tool

match:
  $entity, $tool by 1d
outcome:
  // Leave-one-out prior runs & Jeffreys-smoothed daily arrival rate over 29 prior calendar days
  $today_k = max($daily_tool_counts.daily_count)
  $total_hist = max($baseline_accumulation.total_hist_runs)
  $raw_prior_runs = $total_hist - $today_k
  $prior_runs = if($raw_prior_runs > 0, $raw_prior_runs, 0)
  $lambda = ($prior_runs + 0.5) / 29.0

  // 6 Core Evidence Pillars
  $observation_count = $today_k
  $baseline_active_samples = max($baseline_accumulation.active_days)
  $baseline_mean = $lambda
  $baseline_dispersion = $lambda
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($daily_tool_counts.distinct_cmds)

  // Aggregate Poisson Squared Score (Z^2 = (k - λ)^2 / λ)
  $diff = $today_k - $lambda
  $diff_sq = $diff * $diff
  $safe_lambda = if($lambda > 0, $lambda, 0.01)
  $poisson_z_sq = $diff_sq / $safe_lambda

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 3
  and $baseline_mean > 0.0
  and $baseline_mean <= 2.0
  and $baseline_dispersion > 0.0
  and $observation_count > $baseline_mean
  and $poisson_z_sq >= 12.25

order:
  $poisson_z_sq desc

