---
name: secops-statistical-hunter
description: |
  Guides and executes multi-stage statistical anomaly detection and outlier hunting
  in Google Security Operations (SecOps). Uses inline non-parametric, time-series,
  Poisson dispersion (Fano factor), discrete Poisson rarity scores, and kinematic operators
  (window.*, math.*, arrays.*) over raw UDM telemetry and Rule Detections across arbitrary
  ad-hoc time ranges. Formats results using an executive CommonMark Cyber-First 4-Tier Structured
  Triage Report (with Unicode visual bars, Threat Translation Callout Cards, SOC Severity Badges,
  Common False Positives, SOC Playbooks, and 1-click drill-down queries) and multi-dimensional
  graph-ready specifications (Dual-Y Axis Timelines, 4D Bubble Plots, Heatmaps, Tolerance Bands).
  Triggers: "find beaconing with jitter", "hunt for statistical outliers",
  "multi-stage outlier search", "calculate MAD on DNS", "Tukey fence anomaly",
  "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "z-score process execution surge", "poisson burst clustering", "fano factor password spray",
  "rare admin tool surge", "dual-y axis outlier timeline".
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

This skill empowers an LLM agent and SOC analyst to execute **ad-hoc multi-stage statistical outlier hunting** in Google SecOps without requiring pre-computed machine-learning pipelines or UEBA batch metrics.

---

## 🎯 Non-Statistician Intent & Trigger Question Catalog

When interacting with a cybersecurity analyst who does not have an advanced background in statistics, **match their operational hypothesis to the optimal statistical model** and explain the choice using plain-English physical analogies:

| What the Analyst Asks / Wants to Solve | Statistical Model | Plain-English Concept / Analogy |
| :--- | :--- | :--- |
| *"Find password sprays or brute force that pulse in intermittent waves to evade high-volume rate limits."* | **`POISSON_BURST_CLUSTERING`** (Fano Factor $F = \sigma^2 / \mu > 4.0$) | **Rainfall downpour vs. steady trickle**: Normal login mistakes trickle in steadily; automated attack waves arrive in synchronized, clumpy bursts. |
| *"Detect sensitive administrative commands (`vssadmin`, `certutil`, `whoami`) running more than usual on quiet servers without divide-by-zero errors."* | **`POISSON_RARE_SURGE`** (Poisson $Z = \frac{k - \lambda}{\sqrt{\lambda}} > 3.5$) | **Mathematical rarity on quiet baselines**: Evaluates the improbability of seeing $N$ runs today given a near-zero historical arrival rate. |
| *"Detect extreme surges in process launches or script executions compared to a host's normal behavior."* | **`ZSCORE_PROCESS_SURGE`** (Parametric $Z = \frac{x - \mu}{\sigma} > 3.0$) | **1-in-1,000,000 baseline anomaly**: Flags activity breaking 3 standard deviations above the host's 30-day baseline (top $0.13\%$ tail). |
| *"Hunt for C2 beaconing where the implant uses randomized sleep delays to avoid fixed-interval alerts."* | **`C2_BEACONING_JITTER`** ($\text{CV} \le 0.20$ + Low Prevalence $\le 2$) | **Robotic timing regularity**: Automated implants exhibit low timing variance ($\text{CV} \le 0.20$), while human browsing is chaotic ($\text{CV} > 0.50$). |
| *"Find abnormal outbound data transfers or DNS tunneling on heavily skewed network data."* | **`DATA_EXFILTRATION_SPIKE`** ($M_Z > 2.5$ via Median / MAD) | **Median-anchored surge**: Uses Median Absolute Deviation so a single massive upload doesn't distort baseline calculations. |

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
  // Linear AST: single-operation variable assignments (NO parentheses in outcome math)
  $diff = $observed_count - $mean_val
  $z_score = $diff / $stddev_val

condition:
  $observed_count >= 50
  and $stddev_val >= 10.0
  and $z_score > 3.0
```

### 2. Critical Compiler & Syntax Anti-Patterns (Malachite AST Rules)

| ❌ INCORRECT (Syntax Error) | ✓ CORRECT (Valid Multi-Stage) | Why it Fails |
| :--- | :--- | :--- |
| `$z = ($a - $b) / $c` (Parentheses in math) | `$diff = $a - $b`<br>`$z = $diff / $c` | **No Parentheses in Outcome Math**: Malachite AST rejects compound/parenthesized arithmetic. Use linear single-operation variable assignments. |
| `$val = if($b > 0, $a / $b, 0)` or `$a / if(...)` | `$val = $a / $b`<br>`condition: $b > 0 and $val > 3.0` | **No Bare `if()` in Arithmetic**: Outcome math does not support inline `if()` for zero-division. Handle divisor protection in `condition:`. |
| `count(if(status = "FAIL", 1, 0))` | `sum(if(status = "FAIL", 1, 0))` | **Conditional Counting Standard**: `count(if(...))` is invalid syntax. Use `sum(if(condition, 1, 0))` to aggregate conditional events. |
| `stage s1 { events: $e.metadata... }` | `stage s1 { metadata.event_type = "..." }` | Stages **do not** have an `events:` header. Event filters are written directly. |
| `$s in stage_1` or `$s in $stage_1` | `$val = $stage_1.val` or `$stage_1.val` | There is no `in stage` keyword in YARA-L. Stage outputs are accessed via `$stage_name.field`. |
| Missing stage binding in root events section | `$host = $s1.host; $host = $s2.host` before `match:` | `outcome_validator.go` throws `events section does not declare event variable` if an outcome stage isn't bound. |
| `stage final_outliers { ... }` (last stage named) | Unwrapped root level (no `stage` wrapper) | The final evaluation stage must be at the root level of the query. |
| `math.max($a, $b)` or `math.min($a, $b)` | `$diff = $a - $b`<br>Condition floor: `$a >= $b` | `math.max` and `math.min` do **not** exist in YARA-L. `max()` is only an aggregator. |
| `options: ...` in multi-stage search | Query ends after `condition:` or `order:` | `options:` is rule-engine only. Including it in ad-hoc searches causes parser `<EOF>` errors. |
| `match: $host by 1h hop 15m` or `by 1h over 15m` | `match: $host by 1h` (Tumbling)<br>or `match: $host over 15m` (Sliding) | **Window Syntax Rule**: YARA-L does not support compound `by X hop Y`. Use `by <duration>` for discrete tumbling buckets, `over <duration>` for sliding windows, or `match: $entity` for unwindowed baseline stages. |

---

## 📊 CommonMark Cyber-First 4-Tier Triage Report (Mandatory Standard)

When presenting search results, the agent **MUST** format output using clean **CommonMark / GFM Markdown** (using standard `###`/`####` headers, `---` horizontal rules, and `> [!NOTE]` callouts instead of terminal ASCII box-drawing characters `═══`/`───` which break in rich HTML renderers):

```markdown
### ⚡ Statistical Outlier Report: Process Execution Surges

* **Outliers Detected**: **4 entities** exceeded the configured anomaly threshold.
* **Baseline Envelope**: Mean ($\mu$) $\approx 659.9$ | StdDev ($\sigma$) $\approx 32.8$

---

#### 📊 Ranked Outlier Summary (Top Anomalies by Severity)

| Entity Identifier | Spike Window | Observed | Baseline Envelope | Severity Rating | Visual Magnitude |
| :---------------- | :----------- | :------- | :---------------- | :-------------- | :--------------- |
| `br-win10-14` | 2026-08-11T09:00 | **827** | 660 ± 33 | 🚨 **[CRITICAL OUTLIER]** (`+5.10σ`) | `██████████` |
| `dev-win10-4` | 2026-08-12T09:00 | **888** | 720 ± 33 | 🚨 **[CRITICAL OUTLIER]** (`+5.06σ`) | `█████████▉` |
| `acc-win11-15` | 2026-08-16T09:00 | **595** | 446 ± 30 | 🚨 **[CRITICAL OUTLIER]** (`+5.00σ`) | `█████████▊` |

---

#### 🔍 Top Outlier Spotlight: `br-win10-14` — 🚨 **[CRITICAL OUTLIER]** (`+5.10σ`)

* **Activity Surge**: **827 executions** (+25.3% above historical personal mean).
* **Binary Diversity**: **51 distinct full binary paths** executed.

> [!IMPORTANT]
> **Threat Translation: Parametric Z-Score (Standard Deviation Surge)**
> * **Threat Meaning**: Volume explosion exceeding personal 30-day host baseline. Indicates script loops, build storms, mass lateral movement, or ransomware staging.
> * **Common False Positives**: Software compiler builds (MSBuild/Ninja/GCC), SCCM/Ansible endpoint management jobs, local developer testing.
> * **SOC Triage Playbook**:
>   1. Inspect Parent Binary Lineage (e.g. `cmd.exe` vs `devenv.exe` / `CcmExec.exe`).
>   2. Verify executing User Account (Service Account vs Interactive End-User).
>   3. Check for executions from user-writable directories (`C:\Temp`, `AppData\Local\Temp`, `/tmp`).

---

#### 🎯 Immediate Drill-Down Investigation Query

```yara
principal.hostname = "br-win10-14" AND metadata.event_type = "PROCESS_LAUNCH"
AND metadata.event_timestamp.seconds >= 1786438800 AND metadata.event_timestamp.seconds <= 1786442400
```
```

---

## 📈 Multi-Dimensional Threat Visualizations & Strict Data Typing

For clients that support rich UI graphing, the skill provides **Strictly-Typed JSON Specifications (Vega-Lite & Chart.js)** with pure numeric coordinates:

1. **Dual-Y Axis Timeline Plot (`DUAL_Y_TIMESERIES`)**:
   * **Shared $X$-Axis**: `TIME_BUCKET` (Temporal timestamp).
   * **Left $Y$-Axis**: Observed Volume / Event Count (e.g. Bar / Area mark).
   * **Right $Y$-Axis**: Normalized Statistical Anomaly Score ($Z$-Score, Fano Factor, or Modified $Z$) (Line + Point mark).
   * **Vega-Lite Resolution**: Uses `resolve: { scale: { y: "independent" } }`.
2. **4D Threat Bubble Plot (`4D_BUBBLE`)**:
   * **$X$-Axis**: Timing Interval ($\Delta t$).
   * **$Y$-Axis**: Observed Intensity / Volume.
   * **Bubble Size**: Cardinality (Distinct destination IPs, unique binaries, or users).
   * **Bubble Color**: Statistical Anomaly Score ($Z$, $M_Z$, or $\text{CV}$).
3. **3D Temporal Density Heatmap (`HEATMAP`)**:
   * **$X$-Axis**: Hour of Day ($00–23$).
   * **$Y$-Axis**: Day of Week (Monday–Sunday) or Host Subnet.
   * **Color Density**: Anomaly Score or Event Concentration.

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

### 4. Search Window Ceilings: Single-Stage (90 Days) vs. Multi-Stage (30 Days)
* **Single-Stage Macro Stats Searches (`match: $entity outcome: ...`)**:
  * ✓ **Supported Window**: Up to **90 consecutive days** (7,776,000s / 2,160h).
  * **Use Case**: Macro historical sweeps, 90-day host average bytes, total failure counts, and entity profile baselines.
* **Multi-Stage DAG Outlier Queries (`stage s1 { ... } stage s2 { ... }`)**:
  * ✓ **Supported Window**: Up to **30 consecutive days** (2,592,000s / 720h).
  * ❌ **Hard Ceiling**: Requests $> 30\text{ days}$ for multi-stage queries fail with `INVALID_ARGUMENT` due to distributed intermediate join state buffer limits in F1.
* **Prescriptive Analyst Guidance for Requests $>30\text{ Days}$**:
  * If an analyst requests a multi-stage hunt spanning $>30\text{ days}$ (e.g., *"hunt for 3-sigma process surges across the last 90 days"*), advise:
    > *"Multi-stage anomaly queries (hourly Z-scores, MAD, Fano factor) have a 30-day maximum limit due to distributed join state buffers. We can run this multi-stage hunt over the maximum 30-day window (which provides 720 hourly samples—statistically optimal for 3-Sigma), or run a 90-day single-stage macro search for overall historical baselines."*

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

## 1. Threat-to-Statistical-Model Decision Matrix

| Threat Archetype | Primary Anomaly Signal | Secondary Filter | Statistical Model | Mathematical Primitive | Reference Template |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`ZSCORE_PROCESS_SURGE`** | Execution volume surge per host | Historical entity baseline | **Parametric Z-Score ($Z$)** | $Z = \frac{x - \mu}{\sigma} > 3.0$ | `examples/zscore_process_execution_surges.yara` |
| **`POISSON_BURST_CLUSTERING`** | Synchronized, clumpy auth bursts | Low/moderate total volume | **Fano Factor ($F$)** | $F = \frac{\sigma^2}{\mu} > 4.0$ | `examples/poisson_burst_clustering.yara` |
| **`POISSON_RARE_SURGE`** | Rare admin binary jump on quiet host | Low historical rate ($\lambda \le 2.0$) | **Discrete Poisson Score** | $\frac{k - \lambda}{\sqrt{\lambda}} > 3.5$ | `examples/poisson_rare_event_surge.yara` |
| **`C2_BEACONING_JITTER`** | Low inter-arrival variance ($\Delta t$) | Fleet-wide low prevalence ($\le 2$ hosts) | **Inter-Arrival Jitter ($\text{CV}_{\Delta t}$)** | $\text{CV} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} < 0.25$ | `examples/c2_beaconing_jitter_cv.yara` |
| **`DATA_EXFILTRATION_SPIKE`** | Skewed, heavy-tailed byte volume | Outbound direction / external IP | **Modified Z-Score ($M_Z$) / MAD** | $M_Z = \frac{0.6745 \cdot (x - \tilde{x})}{\text{MAD}} > 3.0$ | `examples/mad_outlier_detection.yara` |
| **`HEAVY_TAIL_OUTLIERS`** | Non-parametric volume outlier | High payload / session count | **Interquartile Range (Tukey Fences)** | $Q_3 + (1.5 \cdot \text{IQR})$ via `percentile()` | `examples/iqr_tukey_fences_egress.yara` |
| **`VELOCITY_SURGE_RATIO`** | Sudden spike relative to moving avg | Short vs long window comparison | **Multi-Window Rolling Ratio** | $\text{Ratio}_{1v7} = \frac{S_{1\text{d}}}{\text{avg}_{7\text{d}}} > 3.0$ | `examples/rolling_ratio_spike.yara` |
| **`LATERAL_RECON_DISPERSION`** | Single host touching abnormal targets | Internal subnet targets | **Categorical Dispersion (HHI)** | $D = 1 - \sum(n_i/N)^2 \to 1.0$ | `references/statistical-models-taxonomy.md` |
| **`IMPOSSIBLE_TRAVEL_SPEED`** | Rapid physical distance change | Geo-coordinates & timestamp delta | **Haversine Kinematics** | $\text{Speed} = \frac{\text{geo\_distance}}{\Delta t} > 800\text{ km/h}$ | `references/statistical-models-taxonomy.md` |

---

## 2. Directory Structure & References

* `README.md`: Overview, 4-tier triage report formatting, and comparison with `secops-risk-analytics`.
* `examples/`:
  * `zscore_process_execution_surges.yara`: 3-Sigma ($Z > 3.0$) process launch volume surge detector.
  * `poisson_burst_clustering.yara`: Fano Factor ($F = \sigma^2 / \mu > 4.0$) password spray cluster detector.
  * `poisson_rare_event_surge.yara`: Discrete Poisson score for sensitive administrative binaries.
  * `c2_beaconing_jitter_cv.yara`: Inter-arrival timing CV & low-prevalence C2 detector.
  * `mad_outlier_detection.yara`: Modified Z-Score via Median Absolute Deviation (MAD).
  * `iqr_tukey_fences_egress.yara`: Non-parametric IQR / Tukey Fences for egress network bytes.
  * `rolling_ratio_spike.yara`: Multi-window moving average ratio ($1\text{d}$ vs $7\text{d}$ vs $30\text{d}$).
* `references/`:
  * `references/cyber-practitioner-glossary.md`: Dedicated field manual translating statistics to SOC operations.
  * `references/statistical-models-taxonomy.md`: Detailed math, physical translations, Poisson dispersion, and Dual-Y/4D plots.
  * `references/watchdog-polling-architecture.md`: LRO watchdog mechanics and F1 optimization guide.
  * `references/scope-exclusions-guardrail.md`: Deep dive on UEBA `metrics.*` vs ad-hoc multi-stage telemetry and Rules Engine separation.
* `scripts/`:
  * `scripts/multistage_query_builder.py`: Linter, CommonMark 4-tier triage report formatter, and Dual-Y / 4D Vega-Lite spec generator.
