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
2. **Outcome Mathematical Expressions, OIO & Safe Divisors**:
   - Binary arithmetic, subtraction, ratios, parentheses, and Function Factory math (`math.abs`, `math.log`, `math.exp`, `math.sqrt`, `math.pow`, `math.floor`, `math.ceil`, `math.round`, `math.min`, `math.max`) are natively supported in `outcome:`.
   - **Outcomes-in-Outcomes (OIO) In-Stage Dependency Inlining**: Chronicle Malachite natively evaluates in-stage outcome variable dependencies (`$diff = $obs - $avg`, `$z = $diff / $safe_sd`). Dependencies are inlined at compile time as long as definition precedes reference and the dependency graph is acyclic.
   - **Safe Non-Zero Dispersion Floors**: Every outcome division by standard deviation or dispersion must include a safe non-zero divisor guard (`$safe_sd = if($sd > 0, $sd, 1.0)`) or additive floor (`($obs - $avg) / ($sd + 1.0)`) to prevent division-by-zero crashes on zero-variance baselines.
3. **Outcome `if(condition, then_expr, else_expr)` Rules**:
   - The second argument (`then_expr`) of `if()` accepts ONLY placeholders, event fields, and constants. Compound arithmetic inside `then_expr` (e.g. `if($std > 0, ($obs - $mean) / $std, 0.0)`) is rejected by the Chronicle Malachite compiler.
   - Assign compound arithmetic to intermediate outcome variables first, then pass the placeholder into `if()`.
4. **Malachite Function Factory Non-Linear Functions (`math.sqrt()`, `math.log()`, `math.exp()`)**:
   - YARA-L 2.0 supports non-linear mathematical built-ins under the `math.` namespace:
     - `math.sqrt($val)`: Computes square roots for true Euclidean Threat Distance ($D$). Bare `sqrt()` without the `math.` prefix is strictly rejected.
     - `math.log($val)`: Computes natural logarithms for Log-Normal volumetric transforms.
     - `math.exp($val)`: Computes exponentials for continuous Calibrated Risk Index (CRI) sigmoids and burst decay.
     - `math.pow($base, $exp)`: Native power function (replaces `$x * $x`).
     - `math.min($a, $b)` and `math.max($a, $b)`: 2-argument scalar clamps.
   - See [`references/malachite-function-factory-matrix.md`](malachite-function-factory-matrix.md) for the complete signature matrix.
5. **Outcome Variable Limit (`OutcomeLimit = 20`)**:
   - No stage may declare more than 20 outcome variables.
6. **Unwrapped Final Stage & Root Condition**:
   - The final stage must **never** be wrapped in `stage <name> { ... }`.
   - The Root stage natively supports a `condition:` section (e.g. `$z_score >= 3.0 and $baseline_active_samples >= 24`) before `order:`.
7. **Mandatory Root Stage Key Bindings**:
   - Every upstream stage referenced in root outcome must be bound in root events (`$host = $stage1.host`).
8. **Scope Restrictions**:
   - Queries must execute raw UDM telemetry only (`UDM_EVENTS`). Forbidden scopes include `metrics.*`, `risk_score`, and detection rule syntax (`rule <name>`).
9. **Zero Artificial Cartesian Joins (`$dummy = 1` Prohibited)**:
   - Multi-stage YARA-L queries do NOT support artificial unwindowed Cartesian joins via `$dummy = 1` or `match: $dummy`.
   - Stages must align using real partition keys (e.g. `$token by 1d`, or `$ws by 1h` with `$ws = $stage.window_start`) across all stages.
10. **Dual Temporal Spines Architecture (`by 1d` vs `by 1h`)**:
    - **Daily Temporal Spine (`by 1d`)**: Used for multi-day horizons ($\ge 7\text{d}$) on macro-aligned models (`MULTI_SECTOR_FUSION`, `LOG_NORMAL_VOLUME`, `DATA_EXFILTRATION_SPIKE`). Provides 1:1 mathematical reconciliation with `secops-risk-metrics-multistage` and a 24× reduction in row cardinality.
    - **Micro Temporal Spine (`10m`, `15m`, `1h`)**: Used for short horizons (6h–72h) to uncover intra-day timing variance (C2 beaconing jitter, clustered brute force bursts).
11. **Categorical Outlier & Entity Rarity Architecture**:
   - When detecting rare or outlier categorical strings across endpoints (e.g. browser user-agent strings, rare domains, JA3 hashes, commands):
     - **High-Performance Single-Stage Rarity Hunt**: For direct rarity filtering without multi-stage joining, use a single-stage windowed query:
       ```yara
       metadata.event_type = "NETWORK_HTTP"
       network.http.user_agent = $user_agent
       $user_agent != ""
       principal.ip = $device_ip

       match:
         $user_agent by 1h

       outcome:
         $event_count = count(metadata.id)
         $device_count = count_distinct(principal.ip)
         $sample_devices = array_distinct(principal.ip)
         $sample_uris = array_distinct(target.url)

       condition:
         $device_count <= 2
         and $event_count >= 5

       order:
         $event_count desc
       ```
     - **2-Stage Token-Centric Fleet Adoption Pipeline**: If combining entity-level surges with enterprise adoption breadth, match across stages using the categorical token (`$user_agent by 1d`), as shown in `examples/rare_user_agent_prevalence.yara`.
11. **Template-First Formulation**:
   - Inspect `templates/pipelines/*.yl2` and `examples/*.yara` for complete, verified reference implementations:
     - `rare_user_agent_prevalence.yara` (Categorical Fleet Prevalence & Rarity)
     - `fleet_zscore_process_outliers.yara` (Peer Fleet Z-Score Normalization)
     - `zscore_process_surge_2stage.yl2` (Z-Score)
     - `poisson_rare_surge_2stage.yl2` (Discrete Poisson Rarity)
     - `mad_exfiltration_2stage.yl2` (Median Absolute Deviation)
     - `c2_beaconing_jitter_2stage.yl2` (Coefficient of Variation)
     - `poisson_burst_clustering_2stage.yl2` (Fano Factor)
     - `two_part_hurdle_2stage.yl2` (Two-Part Hurdle)
     - `dual_baseline_delta_z_3stage.yl2` (Delta-Z)
     - `multi_sector_threat_fusion_4stage.yl2` (Multi-Sector Threat Fusion)
12. **Verified Compiler Facts (live `udm_search` probes, 2026-09-24)**. Each row was established by submitting a minimal pair to the compiler; treat these as ground truth over folklore:
   | Construct | Verdict |
   | :--- | :--- |
   | Full multi-stage query (`stage … { }` + root) as the `udm_search` `query` argument | **Compiles**; returns aggregated `stats` rows. The Turn 2 execution path. |
   | Intermediate stage keyed on a real entity with no window (`match: $host`) | **Compiles**. Canonical per-entity baseline collapse. |
   | Constant key (`$dummy = 1` … `match: $dummy`) | **Rejected**. Use a window key (`$ws by 1h`) for fleet-wide stages. |
   | Referencing `$stage.window_start` without defining it | **Compiles**. It is an implicit column of every windowed stage. |
   | Defining `$window_start = min(metadata.event_timestamp.seconds)` in a stage outcome | **Rejected**. Collides with the implicit column. |
   | Root outcome variable named the same as a stage | **Rejected**. Rename the stage. |
   | Three independent raw stages joined at the root | **Rejected** (any two compile). Fold sectors into one raw stage with conditional sums. |
   | `match: … by 2d` / `by 7d` / `by 14d` / `by 24h` | **Rejected**. `by 5m`, `by 1h`, `by 2h`, `by 1d` verified to compile; any `by Nd` with N > 1 is rejected. Widen `startTime`/`endTime` for longer horizons. |
   | `if($x == 1.0, …)` | **Rejected**. Use `=`. |
   | Aggregator arithmetic inside a stage outcome (`(max($ts) - min($ts)) / (count(metadata.id) + 1.0)`, `avg(x) * avg(x)`) | **Compiles**. |
   | `array_distinct($stage.array_col)` in root (re-aggregating a stage array) | **Compiles**. |
   | Aggregator wrapping an outcome variable (`max($some_outcome_var)`) | **Rejected**: "aggregation cannot refer to outcome variables". |
   | `max()` / `min()` on a string field or string placeholder (`max(target.process.file.full_path)`, `max($host)`) | **Rejected**: `max()`/`min()` are numeric only (Int/Float). Project strings with `array_distinct(...)` or count them with `count_distinct(...)`; the same field under `array_distinct()` compiles. |
   | Reference list that does not exist in the tenant (`$x in %missing_list`) | **Rejected** as an invalid argument — tenant-dependent, not a grammar error. |

