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
// Stage 1: Named Intermediate Stage
stage stage_1 {
    // 1. Direct filters (NO "events:" keyword!)
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host

    // 2. Optional match block
  match:
    $host by 1h

    // 3. Mandatory outcome block
  outcome:
    $count = count(metadata.id)
}

// Stage 2: Downstream Intermediate Stage (references Stage 1)
stage stage_2 {
    // Direct reference to upstream variable (NO "$s1 in stage_1"!)
    $observed_count = $stage_1.count

  outcome:
    $fleet_avg = avg($observed_count)
    $fleet_stddev = stddev($observed_count)
}

// Root Stage: Final Unwrapped Stage (NEVER wrap this in "stage name { ... }")
$host = $stage_1.host

match:
  $host
outcome:
  $host_count = max($stage_1.count)
  $fleet_avg = max($stage_2.fleet_avg)
  $fleet_sd = max($stage_2.fleet_stddev)
  $z_score = ($host_count - $fleet_avg) / math.max($fleet_sd, 1.0)

condition:
  $z_score > 3.0
```

### 2. Four Syntax Traps to Avoid (Anti-Pattern Guide)

| ❌ INCORRECT (Syntax Error) | ✓ CORRECT (Valid Multi-Stage) | Why it Fails |
| :--- | :--- | :--- |
| `stage s1 { events: $e.metadata... }` | `stage s1 { metadata.event_type = "..." }` | Stages **do not** have an `events:` header. Event filters are written directly. |
| `$s in stage_1` or `$s in $stage_1` | `$val = $stage_1.val` or `$stage_1.val` | There is no `in stage` keyword in YARA-L. Stage outputs are accessed via `$stage_name.field`. |
| `stage final_outliers { ... }` (last stage named) | Unwrapped root level (no `stage` wrapper) | The final evaluation stage must be at the root level of the query. |
| `rule my_outlier_rule { stage s1 ... }` | Standalone query without `rule` header | Multi-stage queries are Search & Dashboard only; the Rules Engine rejects `stage` syntax. |

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
// Statistical Model: [e.g., Fleet-Wide Parametric Z-Score (Z = (x - μ) / σ)]
// Mathematical Rationale:
//   - Why this model: [Explain why this formula fits the anomaly behavior]
//   - Noise protection: [Explain volume floor and variance thresholds]
// Sensitivity Boundary: [e.g., CONSERVATIVE (Z > 3.0, Min Executions >= 50, Min SD >= 10)]
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
  * Bake in mandatory volume/activity floors (`$total_conns >= 25`, `$MAD > 100`, `$process_count >= 50`) to prevent zero-variance or low-sample mathematical explosions.
- [ ] **Step 4: Generate Valid Multi-Stage YARA-L & Validate.**
  * Prepend the **Self-Documenting Query Header**.
  * Enforce canonical grammar: Direct filters in `stage` (no `events:`), stage references as `$stage_name.field` (no `in stage`), and unwrapped root stage.
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
| **`FLEET_ZSCORE_OUTLIER`** | Execution volume surge across fleet | Multi-host baseline | **Parametric Z-Score ($Z$)** | $Z = \frac{x - \mu}{\sigma} > 3.0$ | `examples/fleet_zscore_process_outliers.yara` |
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
  * `fleet_zscore_process_outliers.yara`: 3-Sigma ($Z > 3.0$) process launch volume surge detector.
  * `c2_beaconing_jitter_cv.yara`: Inter-arrival timing CV & low-prevalence C2 detector.
  * `mad_outlier_detection.yara`: Modified Z-Score via Median Absolute Deviation (MAD).
  * `iqr_tukey_fences_egress.yara`: Non-parametric IQR / Tukey Fences for egress network bytes.
  * `rolling_ratio_spike.yara`: Multi-window moving average ratio ($1\text{d}$ vs $7\text{d}$ vs $30\text{d}$).
* `references/`:
  * `references/statistical-models-taxonomy.md`: Detailed math, physical translations, and boundary curves.
  * `references/watchdog-polling-architecture.md`: LRO watchdog mechanics and F1 optimization guide.
  * `references/scope-exclusions-guardrail.md`: Deep dive on UEBA `metrics.*` vs ad-hoc multi-stage telemetry and Rules Engine separation.
* `scripts/`:
  * `scripts/multistage_query_builder.py`: Linter and parameter injection script for validating canonical multi-stage grammar and scope guardrails.
