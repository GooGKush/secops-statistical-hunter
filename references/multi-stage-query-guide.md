# Multi-Stage YARA-L Query Architecture & Compiler Rules

This guide defines the syntax, structural limits, and compilation invariants for multi-stage statistical hunting queries in Google SecOps.

---

## 1. Multi-Stage Pipeline Topography

A valid Malachite multi-stage query consists of **1 to 4 named intermediate stages** followed by **1 unwrapped root stage**:

```yara
// --- INTERMEDIATE STAGE 1: Event-Plane Extraction & Binning ---
stage stage1_extract {
  $e.metadata.event_type = "PROCESS_LAUNCH"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $hourly_count = count($e.metadata.id)
    $distinct_procs = count_distinct($e.target.process.file.full_path)
}

// --- INTERMEDIATE STAGE 2: Historical Parameter Estimation ---
stage stage2_stats {
  $host = $stage1_extract.host

  match:
    $host

  outcome:
    $hist_mean = avg($stage1_extract.hourly_count)
    $hist_stddev = stddev($stage1_extract.hourly_count)
    $active_hours = count($stage1_extract.window_start)
}

// --- ROOT STAGE (UNWRAPPED): Root Arithmetic & Scoring ---
$host = $stage1_extract.host
$host = $stage2_stats.host
$ws = $stage1_extract.window_start

$obs = $stage1_extract.hourly_count
$mu = $stage2_stats.hist_mean
$sd = $stage2_stats.hist_stddev

$diff = $obs - $mu
$z = $diff / $sd

match:
  $host, $ws by 1h

outcome:
  $observation_count = max($stage1_extract.hourly_count)
  $baseline_active_samples = max($stage2_stats.active_hours)
  $baseline_mean = max($stage2_stats.hist_mean)
  $baseline_dispersion = max($stage2_stats.hist_stddev)
  $anomaly_score = max($z)

condition:
  $baseline_active_samples >= 24
  and $baseline_dispersion >= 3.0
  and $anomaly_score >= 3.0
```

---

## 2. Hard Compiler Invariants

1. **Clean Materialization Barrier Rule (Zero Intra-Stage Race Conditions)**:
   - Within an outcome block, **never** reference a variable defined on an earlier line in the same outcome block.
   - Linear arithmetic (`$a - $b`, `$diff / $sd`) must be declared in the root stage events section (above `match:`).
2. **Outcome Variable Limit (`OutcomeLimit = 20`)**:
   - No stage may declare more than 20 outcome variables.
3. **Unwrapped Final Stage**:
   - The final stage must **never** be wrapped in `stage <name> { ... }`.
4. **Mandatory Root Stage Key Bindings**:
   - Every upstream stage referenced in root outcome must be bound in root events (`$host = $stage1.host`).
5. **Scope Restrictions**:
   - Queries must execute raw UDM telemetry only (`UDM_EVENTS`). Forbidden scopes include `metrics.*`, `risk_score`, and detection rule syntax (`rule <name>`).
