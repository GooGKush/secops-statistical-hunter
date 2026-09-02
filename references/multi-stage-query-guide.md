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

// --- ROOT STAGE (UNWRAPPED): Root Aggregation & Outcome Math ---
$host = $stage1_extract.host
$host = $stage2_stats.host
$ws = $stage1_extract.window_start

match:
  $host, $ws by 1h

outcome:
  $observation_count = max($stage1_extract.hourly_count)
  $baseline_active_samples = max($stage2_stats.active_hours)
  $baseline_mean = max($stage2_stats.hist_mean)
  $baseline_dispersion = max($stage2_stats.hist_stddev)
  $diff = max($stage1_extract.hourly_count) - max($stage2_stats.hist_mean)
  $anomaly_score = (max($stage1_extract.hourly_count) - max($stage2_stats.hist_mean)) / max($stage2_stats.hist_stddev)

condition:
  $baseline_active_samples >= 24
  and $baseline_dispersion >= 3.0
  and $anomaly_score >= 3.0
```

---

## 2. Hard Compiler Invariants

1. **Common Compiler Grammar Invariant (Zero Event Arithmetic & Explicit Match Binding)**:
   - **Above `match:` (Event Sections)**: Binary arithmetic (`+`, `-`, `*`, `/`) between variables or literals is prohibited. Placeholders must bind directly to UDM fields, stage variables (`$host = $stage1.host`), or scalar functions (`timestamp.as_unix_seconds`). Performing binary arithmetic above `match:` causes Google SecOps Common Compiler to fail with `missing type info for placeholder`.
   - **Explicit Match Variable Binding**: Every placeholder appearing in `match:` must be explicitly assigned in that stage's event section (`$host = $e.principal.hostname` or `$host = $stage1.host`).
2. **Outcome Mathematical Expressions**:
   - Binary arithmetic, subtraction, ratios, parentheses, and scalar math (`math.abs`, `math.log`) are natively supported and fully legal in `outcome:`.
   - Avoid intra-stage race conditions: within an outcome block, do not reference an outcome variable defined on an earlier line in the same outcome block. Instead, compose aggregations directly (`(max($s1.obs) - max($s2.mean)) / max($s2.std)`) or compute intermediate values in an upstream stage.
3. **Outcome Variable Limit (`OutcomeLimit = 20`)**:
   - No stage may declare more than 20 outcome variables.
4. **Unwrapped Final Stage**:
   - The final stage must **never** be wrapped in `stage <name> { ... }`.
5. **Mandatory Root Stage Key Bindings**:
   - Every upstream stage referenced in root outcome must be bound in root events (`$host = $stage1.host`).
6. **Scope Restrictions**:
   - Queries must execute raw UDM telemetry only (`UDM_EVENTS`). Forbidden scopes include `metrics.*`, `risk_score`, and detection rule syntax (`rule <name>`).

