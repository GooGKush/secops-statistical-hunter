// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect statistically improbable surges in rare administrative / security tools on endpoints with near-zero baseline history.
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Discrete Poisson Arrival Score (Poisson Z = (k - λ) / √λ > 3.5)
// Mathematical Rationale:
//   - Why this model: High-impact administrative binaries (e.g., vssadmin.exe, certutil.exe, dsquery.exe, whoami.exe)
//     occur with very low historical daily frequency (λ <= 0.5 runs/day). Standard Z-score breaks down because the sample
//     standard deviation (s) across 30 days is nearly zero, causing false-positive divide-by-zero or mathematical distortion.
//     Under Poisson theory, the theoretical standard deviation is inherently √λ, providing an exact, stable rarity metric.
//   - Noise protection: Enforces a daily observed floor (k >= 3 executions) and restricts baseline rate (λ <= 2.0)
//     to isolate true discrete rare-event surges from standard routine operational tools.
// Sensitivity Boundary: BALANCED (Poisson Z >= 3.5σ, Today Executions k >= 3, Historical Rate λ <= 2.0/day)
// ============================================================================

// Stage 1: Daily execution counts for sensitive utilities per host
stage daily_tool_activity {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""
    (
      re.regex(target.process.file.full_path, `(?i)(vssadmin|certutil|dsquery|whoami|procdump|psexec|adfind)\.exe$`)
      or re.regex(target.process.command_line, `(?i)(vssadmin|certutil|dsquery|whoami|procdump|psexec|adfind)`)
    )
    $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)

  match:
    $host, $day_id
  outcome:
    $daily_count = count(metadata.id)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Historical daily arrival rate (λ = mean daily executions) and max day tracking
stage tool_baseline {
    $host = $daily_tool_activity.host
    $day_id = $daily_tool_activity.day_id

  match:
    $host
  outcome:
    $lambda_rate = avg($daily_tool_activity.daily_count)
    $max_day = max($day_id)
    $total_historical_runs = sum($daily_tool_activity.daily_count)
}

// Stage 3: Today's execution count (day_id = max_day)
stage today_activity {
    $host = $daily_tool_activity.host
    $day_id = $daily_tool_activity.day_id
    $host = $tool_baseline.host
    $max_day = $tool_baseline.max_day

  match:
    $host
  outcome:
    $today_runs = sum(if($day_id = $max_day, $daily_tool_activity.daily_count, 0))
    $today_cmds = array_distinct(if($day_id = $max_day, $daily_tool_activity.sample_cmd, ""))
}

// Root Stage: Calculate Discrete Poisson Score ( (k - λ) / √λ )
$host = $tool_baseline.host
$host = $today_activity.host

match:
  $host
outcome:
  $observed_today = max($today_activity.today_runs)
  $historical_lambda = max($tool_baseline.lambda_rate)
  $historical_total = max($tool_baseline.total_historical_runs)
  // Poisson standard deviation is √λ
  $poisson_sd = math.sqrt($historical_lambda)
  // Linear AST Poisson Z-score
  $diff = $observed_today - $historical_lambda
  $poisson_z = $diff / $poisson_sd

condition:
  // Activity Floor: at least 3 executions observed on the target day
  $observed_today >= 3
  // Rare Event Filter: historical baseline rate must be positive and low (0 < λ <= 2.0 runs/day)
  and $historical_lambda > 0.0
  and $historical_lambda <= 2.0
  and $poisson_sd > 0.0
  // Poisson Score Floor: 3.5 Sigma threshold indicates extreme improbability
  and $poisson_z >= 3.5

order:
  $poisson_z desc
