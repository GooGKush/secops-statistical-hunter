---
name: secops-statistical-hunter
description: |
  Guides and executes multi-stage statistical anomaly detection and outlier hunting
  in Google Security Operations (SecOps). Uses inline non-parametric, time-series,
  kinematic, and information-theoretic operators (window.*, math.*, arrays.*) over
  raw UDM telemetry and Rule Detections across arbitrary ad-hoc time ranges.
  Triggers: "find beaconing with jitter", "hunt for statistical outliers",
  "multi-stage outlier search", "calculate MAD on DNS", "Tukey fence anomaly",
  "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "z-score process execution surge".
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

This skill empowers an LLM agent and SOC analyst to execute **ad-hoc multi-stage statistical outlier hunting** in Google SecOps without requiring pre-computed machine-learning pipelines or UEBA batch metrics.

---

## 📐 Canonical Multi-Stage YARA-L Grammar & Syntax (CRITICAL)

Multi-stage queries in Google SecOps use a specific DAG grammar parsed by the Search/Dashboard engine (`parser.MultiStageQuery`). **Do NOT confuse this with standard Detection Rule syntax.**

### 1. Structure of a Multi-Stage Query

A multi-stage query consists of **one or more named intermediate stages** followed by an **unwrapped root stage**:

```yara
// Stage 1: Named Intermediate Stage (Bucketed by time window)
stage host_hourly {
    // Direct telemetry filters (NO "events:" header)
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""

  match:
    $host by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
}

// Stage 2: Historical Baseline Stage (Across the full window)
stage host_stats {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $host_mean = avg($host_hourly.hourly_count)
    $host_stddev = stddev($host_hourly.hourly_count)
}

// Root Stage: Final Unwrapped Stage (NEVER wrap in "stage name { ... }")
// CRITICAL: Explicitly bind all upstream stages used in outcome above the match block!
$host = $host_hourly.host
$host = $host_stats.host
$window_start = $host_hourly.window_start

match:
  $host, $window_start by 1h
outcome:
  $observed_count = max($host_hourly.hourly_count)
  $mean_val = max($host_stats.host_mean)
  $stddev_val = max($host_stats.host_stddev)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $z_score = ($observed_count - $mean_val) / $stddev_val

condition:
  $observed_count >= 50
  and $stddev_val >= 10.0
  and $z_score > 3.0
```

### 2. Five Syntax Traps to Avoid (Anti-Pattern Guide)

| ❌ INCORRECT (Syntax Error) | ✓ CORRECT (Valid Multi-Stage) | Why it Fails |
| :--- | :--- | :--- |
| `stage s1 { events: $e.metadata... }` | `stage s1 { metadata.event_type = "..." }` | Stages **do not** have an `events:` header. Event filters are written directly. |
| `$s in stage_1` or `$s in $stage_1` | `$val = $stage_1.val` or `$stage_1.val` | There is no `in stage` keyword in YARA-L. Stage outputs are accessed via `$stage_name.field`. |
| Missing stage binding in root events section | `$host = $s1.host; $host = $s2.host` before `match:` | `outcome_validator.go` throws `events section does not declare event variable` if an outcome stage isn't bound. |
| `stage final_outliers { ... }` (last stage named) | Unwrapped root level (no `stage` wrapper) | The final evaluation stage must be at the root level of the query. |
| `math.max($a, $b)` or `math.min($a, $b)` | `$a / $b` with condition floor, or `if($b > 0, $b, 1)` | `math.max` does **not** exist in YARA-L. `max()` is only an aggregator. |

---

## 🚫 Critical Scope & Execution Guardrails (Mandatory Check)

### 1. SEARCH-ONLY EXECUTION: NEVER Convert to Detection Rules
* **Multi-Stage Queries (`stage ... { ... }`) are SEARCH & DASHBOARD ONLY.**
* The Google SecOps Detection Rules Engine (`RuleService` / `create_rule`) strictly rejects multi-stage syntax (`stage <name>`) and cannot execute multi-stage DAG pipelines.
* ❌ **PROHIBITED ACTION**: NEVER suggest, offer, or attempt to convert a multi-stage statistical search query into a continuous real-time YARA-L alert rule.
* ✓ **VALID OPERATIONAL NEXT STEPS TO OFFER**:
  1. Execute search directly via `udm_search` across the target environment.
  2. Adapt data sources, field pivots, or sensitivity boundaries.
  3. Export to a **Native SecOps Dashboard Widget** (Native Dashboards fully support multi-stage queries).
  4. Set up an **Automated Scheduled Hunting Search** (e.g., daily/weekly cron search reporting outliers).

### 2. Boundary with `secops-yara-l`
* If consulting the `secops-yara-l` skill, use it **only** for UDM field name lookups (`principal.asset.ip`, `network.dns.questions.name`) and basic scalar functions (`strings.*`, `re.*`).
* **Do NOT** adopt `secops-yara-l`'s rule-centric structural templates or alerting rule creation suggestions.

### 3. Exclusion of UEBA & Risk Analytics (`metrics.*`, `graph.risk_score`)
* ❌ **DO NOT USE**: `metrics.*` (e.g., `metrics.network_bytes_outbound`), `graph.risk_score`, or `source_dataset: UEBA_EVENTS`. These require fixed batch schedules and belong in **`secops-risk-analytics`**.
* ✓ **USE INSTEAD**: Raw telemetry (`UDM_EVENTS`) or alerts (`RULE_DETECTIONS`) with inline window/math functions (`window.median`, `window.percentile`, `stddev`, `math.abs`).

---

## 📝 Self-Documenting Query Header Requirement (Mandatory)

Every multi-stage query generated by this skill **MUST** start with a standardized, human-readable methodology comment block:

```yara
// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: [Clear threat hunting hypothesis]
// Target Telemetry: [e.g., UDM_EVENTS (PROCESS_LAUNCH)]
// Statistical Model: [e.g., Parametric Historical Z-Score per Host (Z = (x - μ) / σ)]
// Mathematical Rationale:
//   - Why this model: [Explain why this formula fits the anomaly behavior]
//   - Noise protection: [Explain volume floor and variance thresholds]
// Sensitivity Boundary: [e.g., CONSERVATIVE (Z > 3.0, Min Executions >= 50, Min Stddev >= 10.0)]
// ============================================================================
```

---

## 🧭 Workflow Execution Checklist

- [ ] **Step 1: Consultative Scoping & Archetype Selection.**
  * Interpret the analyst's high-level intent (e.g., *"find hosts with Z-score > 3 for process executions"*).
  * Map the intent using the **Threat-to-Statistical-Model Decision Matrix** (see Section 1).
- [ ] **Step 2: Pre-Flight Boundary Calibration Probe (Optional / Recommended).**
  * If the analyst is unsure of the threshold, run a fast 24-hour distribution probe (`approx_count_distinct` grouped by score deciles) to preview candidate volume and identify the tenant's **Noise Cliff**.
- [ ] **Step 3: Select Sensitivity Tier & Guardrails.**
  * Present semantic tiers (`CONSERVATIVE`, `BALANCED`, `AGGRESSIVE`) with explicit physical trade-off translations.
  * Bake in mandatory volume/activity floors (`$total_conns >= 25`, `$MAD > 100`, `$observed_count >= 50`) to prevent zero-variance or low-sample mathematical explosions.
- [ ] **Step 4: Generate Valid Multi-Stage YARA-L & Validate.**
  * Prepend the **Self-Documenting Query Header**.
  * Enforce canonical grammar: Direct filters in `stage` (no `events:`), explicit stage binding in root events block, stage references as `$stage_name.field` (no `in stage`), unwrapped root stage, and no `math.max`/`math.min`.
  * Run `scripts/multistage_query_builder.py` to verify syntax and assert zero `metrics.*` or `rule` wrapper leakage.
- [ ] **Step 5: Async Search Dispatch & Reactive Watchdog Polling.**
  * Dispatch via `udm_search` with async LRO enabled.
  * Use the **`schedule`** tool for non-blocking reactive wakeup checks (`get_operation`). **Never run a synchronous `while not done: sleep()` loop.**
  * Monitor progress deltas (`events_searched`) and enforce the 10-minute stall watchdog.
- [ ] **Step 6: Contextual Synthesis & Tactical Next Steps.**
  * Return ranked Top $N$ outliers with human-readable operational context (interval, jitter, fleet prevalence, median deviation).
  * Surface one-click follow-up investigation queries and dashboard export options. **Never offer conversion to alert rules.**

---

## 1. Threat-to-Statistical-Model Decision Matrix

| Threat Archetype | Primary Anomaly Signal | Secondary Filter | Statistical Model | Mathematical Primitive | Reference Template |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`ZSCORE_PROCESS_SURGE`** | Execution volume surge per host | Historical entity baseline | **Parametric Z-Score ($Z$)** | $Z = \frac{x - \mu}{\sigma} > 3.0$ | `examples/zscore_process_execution_surges.yara` |
| **`C2_BEACONING_JITTER`** | Low inter-arrival variance ($\Delta t$) | Fleet-wide low prevalence ($\le 2$ hosts) | **Inter-Arrival Jitter ($\text{CV}_{\Delta t}$)** | $\text{CV} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} < 0.25$ | `examples/c2_beaconing_jitter_cv.yara` |
| **`DATA_EXFILTRATION_SPIKE`** | Skewed, heavy-tailed byte volume | Outbound direction / external IP | **Modified Z-Score ($M_Z$) / MAD** | $M_Z = \frac{0.6745 \cdot (x - \tilde{x})}{\text{MAD}} > 3.0$ | `examples/mad_outlier_detection.yara` |
| **`HEAVY_TAIL_OUTLIERS`** | Non-parametric volume outlier | High payload / session count | **Interquartile Range (Tukey Fences)** | $Q_3 + (1.5 \cdot \text{IQR})$ via `percentile()` | `examples/iqr_tukey_fences_egress.yara` |
| **`VELOCITY_SURGE_RATIO`** | Sudden spike relative to moving avg | Short vs long window comparison | **Multi-Window Rolling Ratio** | $\text{Ratio}_{1v7} = \frac{S_{1\text{d}}}{\text{avg}_{7\text{d}}} > 3.0$ | `examples/rolling_ratio_spike.yara` |
| **`LATERAL_RECON_DISPERSION`** | Single host touching abnormal targets | Internal subnet targets | **Categorical Dispersion (HHI)** | $D = 1 - \sum(n_i/N)^2 \to 1.0$ | `references/statistical-models-taxonomy.md` |
| **`IMPOSSIBLE_TRAVEL_SPEED`** | Rapid physical distance change | Geo-coordinates & timestamp delta | **Haversine Kinematics** | $\text{Speed} = \frac{\text{geo\_distance}}{\Delta t} > 800\text{ km/h}$ | `references/statistical-models-taxonomy.md` |

---

## 2. Sensitivity & Boundary Guidance Engine

When configuring thresholds for non-practitioners, translate raw floats into **Semantic Tiers**:

### A. Parametric Z-Score ($Z = (x - \mu) / \sigma$) Tiers
* **`CONSERVATIVE` ($Z > 3.0$)**: 3-Sigma threshold (top $0.13\%$ distribution tail). High confidence.
* **`BALANCED` ($Z > 2.0$)**: 2-Sigma threshold (top $\approx 2.5\%$ distribution tail). Good baseline sweep.
* ❌ **`NOISE CLIFF` ($Z \le 1.0$)**: Within standard daily operational variance. **Refuse search.**

### B. Timing Jitter ($\text{CV} = \sigma_{\Delta t} / \mu_{\Delta t}$) Tiers
* **`CONSERVATIVE` ($\text{CV} \le 0.05$)**: Catches strict hardcoded timers ($\pm 3\%$ randomness).
* **`BALANCED` ($\text{CV} \le 0.20$)**: Catches modern C2 frameworks (Cobalt Strike, Sliver) with $15\%–20\%$ random jitter.
* **`AGGRESSIVE` ($\text{CV} \le 0.40$)**: Catches long-sleep or randomized implants (`prevalence <= 2`).
* ❌ **`NOISE CLIFF` ($\text{CV} > 0.50$)**: Approaching Poisson randomness (normal web browsing).

---

## 3. Directory Structure & References

* `README.md`: Architectural overview and comparison with `secops-risk-analytics`.
* `examples/`:
  * `zscore_process_execution_surges.yara`: 3-Sigma ($Z > 3.0$) process launch volume surge detector.
  * `c2_beaconing_jitter_cv.yara`: Inter-arrival timing CV & low-prevalence C2 detector.
  * `mad_outlier_detection.yara`: Modified Z-Score via Median Absolute Deviation (MAD).
  * `iqr_tukey_fences_egress.yara`: Non-parametric IQR / Tukey Fences for egress network bytes.
  * `rolling_ratio_spike.yara`: Multi-window moving average ratio ($1\text{d}$ vs $7\text{d}$ vs $30\text{d}$).
* `references/`:
  * `references/statistical-models-taxonomy.md`: Detailed math, physical translations, and boundary curves.
  * `references/watchdog-polling-architecture.md`: LRO watchdog mechanics and F1 optimization guide.
  * `references/scope-exclusions-guardrail.md`: Deep dive on UEBA `metrics.*` vs ad-hoc multi-stage telemetry and Rules Engine separation.
* `scripts/`:
  * `scripts/multistage_query_builder.py`: Linter and parameter injection script for validating canonical multi-stage grammar, stage bindings, and scope guardrails.
