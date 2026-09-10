# Multi-Stage YARA-L Query Architecture & Compiler Rules

This guide defines the syntax, structural limits, and compilation invariants for multi-stage statistical hunting queries in Google SecOps.

---

## 1. Multi-Stage Pipeline Topography

A valid Malachite multi-stage query consists of **1 to 3 named intermediate stages** followed by **1 unwrapped root stage** (up to 4 stages total):

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
  // Safe divisor: additive dispersion floor (+ 1.0) prevents divide-by-zero on quiet hosts
  $safe_stddev = if(max($stage2_stats.hist_stddev) > 0, max($stage2_stats.hist_stddev), 1.0)
  $anomaly_score = $diff / ($safe_stddev + 1.0)

condition:
  $baseline_active_samples >= 24
  and $baseline_dispersion >= 3.0
  and $anomaly_score >= 3.0
```

---

## 2. Hard Compiler Invariants

1. **Common Compiler Grammar Invariant (Zero Event Arithmetic & Explicit Match Binding)**:
   - **Above `match:` (Event Sections)**: Binary arithmetic (`+`, `-`, `*`, `/`) between variables or literals is prohibited. Placeholders must bind directly to UDM fields, stage variables (`$host = $stage1.host`), or scalar functions (`timestamp.as_unix_seconds`). Performing binary arithmetic above `match:` causes Google SecOps Common Compiler to fail with `missing type info for placeholder`.
   - **Explicit Match Variable Binding (ZERO DOTS IN MATCH)**: Every placeholder appearing in `match:` must be explicitly assigned before `match:` (`$host = $e.principal.hostname` or `$host = $stage1.host`). Match blocks accept ONLY simple bare identifiers without dots (`$host by 1h`, `$src_ip, $dst_ip by 1h`, `$entity, $ws by 1h`), NEVER member dot-notation (`$e.target.ip`, `$stage1.host`, `$stage1.target_ip`, or `$stage.window_start` in `match:` is a fatal syntax violation). Always bind stage attributes to simple variables first: `$host = $stage1.host; $dst_ip = $stage1.target_ip; $ws = $stage1.window_start` then `match: $host, $dst_ip, $ws by 1h`.
2. **Outcome Mathematical Expressions & Safe Divisors**:
   - Binary arithmetic, subtraction, ratios, parentheses, and scalar math (`math.abs`, `math.log`) are natively supported in `outcome:`.
   - **Mandatory Additive Dispersion Floor (`+ 1.0`)**: Every outcome division must include a `+ 1.0` additive floor on the denominator (e.g. `($obs - $avg) / ($std + 1.0)`) or safe non-zero wrapper. Quiet accounts with zero historical variance will cause division-by-zero crashes without this floor.
   - Avoid intra-stage race conditions: within an outcome block, do not reference an outcome variable defined on an earlier line in the same outcome block. Instead, compose aggregations directly or compute intermediate values in an upstream stage.
3. **Outcome `if(condition, then_expr, else_expr)` Rules**:
   - The second argument (`then_expr`) of `if()` accepts ONLY placeholders, event fields, and constants. Compound arithmetic inside `then_expr` (e.g. `if($std > 0, ($obs - $mean) / $std, 0.0)`) is rejected by the Chronicle Malachite compiler.
   - Assign compound arithmetic to intermediate outcome variables first, then pass the placeholder into `if()`.
4. **Zero Non-Linear Functions (No `sqrt()`)**:
   - YARA-L 2.0 does NOT support `sqrt()`. For orthogonal distance, compute squared Euclidean distance (`$dist_sq = ($z1 * $z1) + ($z2 * $z2)`) and sort by `$dist_sq desc`.
5. **Outcome Variable Limit (`OutcomeLimit = 20`)**:
   - No stage may declare more than 20 outcome variables.
6. **Unwrapped Final Stage & Root Condition**:
   - The final stage must **never** be wrapped in `stage <name> { ... }`.
   - The Root stage natively supports a `condition:` section (e.g. `$z_score >= 3.0 and $baseline_active_samples >= 24`) before `order:`.
7. **Mandatory Root Stage Key Bindings**:
   - Every upstream stage referenced in root outcome must be bound in root events (`$host = $stage1.host`).
8. **Scope Restrictions**:
   - Queries must execute raw UDM telemetry only (`UDM_EVENTS`). Forbidden scopes include `metrics.*`, `risk_score`, and detection rule syntax (`rule <name>`).
9. **Template-First Formulation**:
   - Inspect `templates/pipelines/*.yl2` for complete, verified reference implementations:
     - `zscore_process_surge_2stage.yl2` (Z-Score)
     - `poisson_rare_surge_2stage.yl2` (Discrete Poisson Rarity)
     - `mad_exfiltration_2stage.yl2` (Median Absolute Deviation)
     - `c2_beaconing_jitter_2stage.yl2` (Coefficient of Variation)
     - `poisson_burst_clustering_2stage.yl2` (Fano Factor)
     - `two_part_hurdle_2stage.yl2` (Two-Part Hurdle)
     - `dual_baseline_delta_z_3stage.yl2` (Delta-Z)
     - `multi_sector_threat_fusion_4stage.yl2` (Multi-Sector Threat Fusion)

