// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect endpoints exhibiting extreme statistical surges in process launch volume (Z-Score > 2.0).
// Target Telemetry: UDM_EVENTS (PROCESS_LAUNCH)
// Statistical Model: Parametric Historical Z-Score per Host (Z = (x - μ) / σ) & Fleet Prevalence
// Mathematical Rationale:
//   - Why this model: Compares each host hourly process execution volume against its own historical
//     baseline mean and standard deviation. Hourly surges exceeding 3 standard deviations (Z > 3.0, top ~0.13%)
//     reveal anomalous activity such as automated malware loops, batch lateral movement, or ransomware staging.
//   - Small-Sample & Multiple-Comparison Protection: Enforces an active baseline sample floor (>= 60 hourly samples),
//     an activity floor of >= 25 executions, and a minimum standard deviation floor (σ >= 5.0)
//     to prevent zero-variance divisions, idle baseline noise, and small-sample false anomalies.
// Sensitivity Boundary: BALANCED (Z-Score > 2.0, Min Hourly Executions >= 25, Min Stddev >= 5.0, Min Active Samples >= 60)
// ============================================================================

// Stage 1: Hourly process execution counts, distinct binaries, and sample commands per host
stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $entity
    $entity != ""

  match:
    $entity by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Historical mean, standard deviation, and active sample density per host
stage host_stats {
    $entity = $host_hourly.entity

  match:
    $entity
  outcome:
    $host_mean = avg($host_hourly.hourly_count)
    $host_stddev = stddev($host_hourly.hourly_count)
    $active_samples = count($host_hourly.window_start)
}

// Stage 3: Enterprise-wide fleet prevalence of process activity per window.
// Keyed on the window (NOT the entity): grouping by $entity and counting distinct
// entities always yields 1. A $dummy = 1 Cartesian key is rejected by the compiler.
stage fleet_breadth {
    $ws = $host_hourly.window_start

  match:
    $ws by 1h
  outcome:
    $fleet_hosts = count_distinct($host_hourly.entity)
}

// Root Stage: Join all stages, calculate Z-score in outcome section, and emit standardized 6 Evidence Pillars
$entity = $host_hourly.entity
$entity = $host_stats.entity
$window_start = $host_hourly.window_start
$window_start = $fleet_breadth.ws

match:
  $entity, $window_start by 1h
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($host_stats.active_samples)
  $baseline_mean = max($host_stats.host_mean)
  $baseline_dispersion = max($host_stats.host_stddev)
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)
  
  // Aggregate computed Z-Score
  $diff = max($host_hourly.hourly_count) - max($host_stats.host_mean)
  $raw_stddev = max($host_stats.host_stddev)
  $safe_stddev = if($raw_stddev > 0, $raw_stddev, 1.0)
  $z_score = $diff / ($safe_stddev + 1.0)

condition:
  $baseline_active_samples >= 60
  and $observation_count >= 25
  and $baseline_dispersion >= 5.0
  and $z_score > 2.0

order:
  $z_score desc
