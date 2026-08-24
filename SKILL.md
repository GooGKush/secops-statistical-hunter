---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.0.0
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

### 1. The Four-Stage DAG Architecture

A multi-stage query consists of **up to 4 named intermediate stages** followed by an **unwrapped root stage (5 stages total)**:

```yara
// Stage 1: Extraction & Binning (by time window)
stage host_hourly {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""

  match:
    $host by 1h
  outcome:
    $hourly_count = count(metadata.id)
    $distinct_procs = count_distinct(target.process.file.full_path)
    $sample_cmd = array_distinct(target.process.command_line)
}

// Stage 2: Historical Baseline & Sample Density Tracking
stage host_stats {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $host_mean = avg($host_hourly.hourly_count)
    $host_stddev = stddev($host_hourly.hourly_count)
    $active_samples = count($host_hourly.window_start)
}

// Stage 3: Enterprise-Wide Peer Prevalence & Context
stage fleet_prevalence {
    $host = $host_hourly.host

  match:
    $host
  outcome:
    $fleet_hosts = count_distinct($host_hourly.host)
}

// Root Stage: Final Unwrapped Stage (NEVER wrap in "stage name { ... }")
$host = $host_hourly.host
$host = $host_stats.host
$host = $fleet_prevalence.host
$window_start = $host_hourly.window_start

// Linear event-level statistical transformation (prevents intra-stage outcome race conditions)
$diff = $host_hourly.hourly_count - $host_stats.host_mean
$z = $diff / $host_stats.host_stddev

match:
  $host, $window_start by 1h
outcome:
  // 6 Standardized Evidence Pillars
  $observation_count = max($host_hourly.hourly_count)
  $baseline_active_samples = max($host_stats.active_samples)
  $baseline_mean = max($host_stats.host_mean)
  $baseline_dispersion = max($host_stats.host_stddev)
  $fleet_prevalence = max($fleet_prevalence.fleet_hosts)
  $distinct_binaries = max($host_hourly.distinct_procs)
  $sample_commands = array_distinct($host_hourly.sample_cmd)
  
  // Aggregate Computed Score
  $z_score = max($z)

condition:
  // Small-Sample Protection Gate
  $baseline_active_samples >= 120
  and $observation_count >= 50
  and $baseline_dispersion >= 10.0
  and $z_score > 3.0
```

### 2. Critical Compiler & Syntax Anti-Patterns (Malachite AST Rules)

| ❌ INCORRECT (Syntax Error / Race Condition) | ✓ CORRECT (Valid Multi-Stage) | Why it Fails |
| :--- | :--- | :--- |
| **Intra-Stage Chaining**: `$diff = $a - $b`<br>`$z = $diff / $c` inside same `outcome:` | Linear transform in `events:` section:<br>`$diff = $a - $b`<br>`$z = $diff / $c`<br>`outcome: $z_score = max($z)` | **Clean Materialization Barrier Rule**: Outcome variables cannot reference other outcome variables defined within the same block. Decompose across stages or compute in the event body before `match:`. |
| `$z = ($a - $b) / $c` (Parentheses in math) | Linear transforms in event body or across stages | **No Parentheses in Outcome Math**: Malachite AST rejects compound/parenthesized arithmetic. |
| `$val = if($b > 0, $a / $b, 0)` or `$a / if(...)` | `$val = $a / $b`<br>`condition: $b > 0 and $val > 3.0` | **No Bare `if()` in Arithmetic**: Outcome math does not support inline `if()` for zero-division. Handle divisor protection in `condition:`. |
| `count(if(status = "FAIL", 1, 0))` | `sum(if(status = "FAIL", 1, 0))` | **Conditional Counting Standard**: `count(if(...))` is invalid syntax. Use `sum(if(condition, 1, 0))` to aggregate conditional events. |
| `stage s1 { events: $e.metadata... }` | `stage s1 { metadata.event_type = "..." }` | Stages **do not** have an `events:` header. Event filters are written directly. |
| `$s in stage_1` or `$s in $stage_1` | `$val = $stage_1.val` or `$stage_1.val` | There is no `in stage` keyword in YARA-L. Stage outputs are accessed via `$stage_name.field`. |
| Missing stage binding in root events section | `$host = $s1.host; $host = $s2.host` before `match:` | `outcome_validator.go` throws `events section does not declare event variable` if an outcome stage isn't bound. |
| `stage final_outliers { ... }` (last stage named) | Unwrapped root level (no `stage` wrapper) | The final evaluation stage must be at the root level of the query. |
| `math.max($a, $b)` or `math.min($a, $b)` | `$diff = $a - $b`<br>Condition floor: `$a >= $b` | `math.max` and `math.min` do **not** exist in YARA-L. `max()` is only an aggregator. |
| `options: ...` in multi-stage search | Query ends after `condition:` or `order:` | `options:` is rule-engine only. Including it in ad-hoc searches causes parser `<EOF>` errors. |
| `match: $host by 1h hop 15m` or `by 1h over 15m` | `match: $host by 1h` (Tumbling)<br>or `match: $host over 15m` (Sliding) | **Window Syntax Rule**: YARA-L does not support compound `by X hop Y`. Use `by <duration>` for discrete tumbling buckets, `over <duration>` for sliding windows, or `match: $entity` for unwindowed baseline stages. |
| Exceeding 20 outcome variables per section | Group variables or keep $\le 20$ | `outcome_validator.go` strictly enforces `OutcomeLimit = 20` per block. |


---

## 📊 CommonMark Cyber-First 4-Tier Triage Report (Mandatory Standard)

When presenting search results, the agent **MUST** format output using clean **CommonMark / GFM Markdown** (using standard `###`/`####` headers, `---` horizontal rules, and `> [!NOTE]` callouts instead of terminal ASCII box-drawing characters `═══`/`───` which break in rich HTML renderers):

```markdown
### ⚡ Statistical Outlier Report: Process Execution Surges

* **Outliers Detected**: **1 entities** exceeded the configured anomaly threshold.
* **Fleet Scaling / Multiple-Comparison Adjustment**: Fleet Size $N = 5000$ | Bonferroni Threshold $Z_{\text{adj}} \ge 4.13\sigma$
* **Normal Baseline Envelope**: Typical Average ($\mu$) $\approx 250.0$ | Typical Variation ($\sigma$) $\approx \pm35.0$

---

#### 📊 Ranked Outlier Summary (Top Anomalies by Severity)

| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Visual Magnitude |
| :------------------- | :----------- | :---------------- | :------------------------- | :-------------- | :-------------- | :--------------- |
| `host-alpha-prod` | 2026-08-24T08:00 | **850** | 250 ± 35 | 🟢 **HIGH CONFIDENCE** | 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | `██████████` |

---

#### 🔍 Top Outlier Spotlight: `host-alpha-prod` — 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`)

* **Data Confidence Level**: 🟢 **HIGH CONFIDENCE** — Robust historical baseline (>= 120 active samples, verified dispersion, low fleet prevalence).

##### 🗣️ What Happened & Why It Matters (In Plain English)
> **The Finding**: During this window, `host-alpha-prod` performed **850 events**, representing **3.4x higher than normal** (+240% above baseline) (normal average is **250.0**).
> 
> **Why It Matters**: This sudden burst produced an anomaly rating of **+17.14σ**, indicating behavior so statistically rare that it almost certainly represents **automated software execution, script loops, or active threat tooling** rather than normal human employee activity.
> 
> **Organization Context**: This behavior was observed on only **1 endpoint(s)** across the entire company, ruling out a routine corporate-wide software rollout.

##### 🏛️ Forensic Evidence Breakdown

| Evidence Pillar | Observed Value | What this Means for Your Investigation |
| :--- | :--- | :--- |
| **1. Activity Spike** | `850` | What this computer actually did during the spike window |
| **2. Baseline History** | `168 units` | How much history was analyzed to ensure this isn't a new or unobserved machine |
| **3. Typical Normal Level** | `250.0` | The normal expected volume when things are operating routinely |
| **4. Normal Daily Spread** | `±35.0` | Typical fluctuation range; this surge blew far past this envelope |
| **5. Company-Wide Breadth** | `1 host(s)` | 1 host = isolated/targeted; 100 hosts = company-wide software push |
| **6. Variety of Programs** | `42` | Unique programs/commands involved (high variety = batch recon/staging) |

> [!IMPORTANT]
> **Threat Explanation: Process Execution Volume Surge (Parametric Z-Score)**
> * **The Core Concept**: Massive sudden burst in program launches compared to this computer's normal daily routine.
> * **Security Significance**: When an endpoint suddenly launches hundreds or thousands of processes in a short window, it almost always indicates automated software execution (such as a script loop, malware installer, or rapid reconnaissance sweep) rather than a human user clicking applications.
> 
> **🔴 Potential Attack Scenarios (What to look for)**:
> * Ransomware traversing folders and launching execution helpers to encrypt files.
> * Attacker running automated batch discovery scripts (ping sweeps, user queries, network shares).
> * Malware dropper unpacking and executing secondary payloads in rapid succession.
> 
> **🟢 Legitimate Business Explanations (False positives to rule out)**:
> * Software engineer compiling code locally using build tools (Ninja, MSBuild, GCC, Rust/Cargo).
> * IT systems management software (SCCM, BigFix, Ansible) deploying a large software suite.
> * Local antivirus or security sensor running an aggressive background definitions update.
> 
> **🎯 Step-by-Step SOC Action Plan (No Math Required)**:
> 1. Run the drill-down query below to see the exact process paths (.exe/.sh) and command-line arguments that executed.
> 2. Check the User Account: Is it an interactive employee user or a system background account (SYSTEM, root, svc-)?
> 3. Look for suspicious execution folders: Are binaries launching from temporary folders (C:\Temp, AppData\Local\Temp, /tmp)?
> 4. Check if the host established sudden outbound network connections immediately following the process spike.

---

#### 🎯 Immediate Drill-Down Investigation Query

```yara
principal.hostname = "host-alpha-prod" AND metadata.event_type = "PROCESS_LAUNCH"
AND metadata.event_timestamp.seconds >= 1786438800 AND metadata.event_timestamp.seconds <= 1786442400
```

---

<details>
<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>

##### 📐 Mathematical Model & Formulaic Derivations
* **Model**: Parametric Gaussian Standardization (Historical $Z$-Score)
  $$Z = \frac{x - \mu}{\sigma} = \frac{850 - 250.0}{35.0} = +17.14\sigma$$
* **Degrees of Freedom ($N$)**: `168` active baseline observation intervals.
* **Dispersion Metric**: Sample Standard Deviation $s = \sqrt{\frac{1}{N-1} \sum (x_i - \bar{x})^2} = 35.0$.

##### 🌐 Multiple-Comparison Fleet Correction (Bonferroni / Gumbel Tail)
* **Fleet Population ($N$)**: `5000` independent endpoints evaluated simultaneously.
* **Adjusted Critical Threshold**: $Z_{\text{adj}} \approx \sqrt{2 \ln N} = 4.13\sigma$.
* **Family-Wise Error Rate (FWER)**: Controls fleet-wide false discovery probability at $\alpha = 0.01$.

##### 🛡️ Statistical Validity & Safeguard Verification
* **Sample Density Floor**: `168` active units (Threshold $\ge 30$ $\to$ **PASSED**).
* **Dispersion Non-Zero Floor**: Spread `35.0` (Threshold $\ge 5.0$ $\to$ **PASSED**).
* **Fleet Prevalence Isolation**: `1` host(s) (Threshold $\le 3$ $\to$ **PASSED**).
</details>
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

### 4. Dynamic Time-Window Protocol & Adaptive Granularity (CRITICAL)

The skill is **inherently flexible on time** and adapts seamlessly to any user-requested search window—whether "today" (last 24 hours), "past 2 days", "the past week", "days this week so far", "days this month so far", or "the past 30 days".

#### A. Up-Front Time Window Clarification
* If the user specifies a time window (e.g. *"hunt for process surges over the last 2 days"* or *"analyze failed logins for today"*), adopt and lock that window immediately.
* If the user's request lacks a time window (e.g. *"hunt for C2 beaconing"*), proactively propose or confirm a standard default (e.g. 7-day or 30-day baseline) and state the window explicitly in the methodology header.

#### B. Dynamic Granularity & Proportional Sample Density Matrix
**NEVER hardcode fixed 30-day sample floors (like `$baseline_active_samples >= 120` or `$active_days >= 30`) on short windows.** Doing so creates an **automatic query failure** (zero results) because the total intervals in the search window cannot meet the condition.

Instead, scale the bucket granularity and sample density floor dynamically based on the window duration ($\Delta T$):

| Target Search Window ($\Delta T$) | Example Analyst Requests | Recommended Tumbling Bucket | Total Window Capacity | Proportional Sample Density Floor | Optimal Statistical Models |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Intra-Day / Ultra-Short** ($\le 24\text{h}$) | *"today"*, *"past 12 hours"*, *"last 24 hours"* | `by 10m` or `by 15m` | $96–144$ intervals | `$baseline_active_samples >= 12` to `24` | `POISSON_BURST_CLUSTERING`, `C2_BEACONING_JITTER`, `FLEET_PEER_ZSCORE` |
| **Short Window** ($24\text{h}–7\text{d}$) | *"past 2 days"*, *"the past week"*, *"days this week so far"* | `by 1h` | $48–168$ hourly intervals | `$baseline_active_samples >= 12` (2d) to `48` (7d) | `ZSCORE_PROCESS_SURGE`, `POISSON_BURST_CLUSTERING`, `C2_BEACONING_JITTER`, `FLEET_PEER_ZSCORE` |
| **Extended Window** ($7\text{d}–30\text{d}$) | *"days this month so far"*, *"past 30 days"* | `by 1h` or `by 1d` | $168–720$ hourly / $7–30$ daily | `$baseline_active_samples >= 60` (hourly) or `7` (daily) | `ZSCORE_PROCESS_SURGE`, `DATA_EXFILTRATION_SPIKE` (MAD), `HEAVY_TAIL_OUTLIERS` (IQR), `VELOCITY_SURGE_RATIO` |
| **Macro Historical** ($30\text{d}–90\text{d}$) | *"past 90 days macro baseline"* | Single-Stage `match: $entity` | Full Macro Window | Single-stage macro aggregations | Single-Stage Macro Search |

#### C. Proportional Sample Density Floor Rule
$$\text{Proportional Sample Floor} = \max(3, \min(\text{Default Floor}, \lfloor 0.25 \times N_{\text{total\_intervals}} \rfloor))$$
* Example for a **2-day hunt (48 hours with 1h buckets)**: Total capacity is 48. Enforce `$baseline_active_samples >= 12` (NOT 120!).
* Example for a **24-hour hunt (96 15-minute buckets)**: Total capacity is 96. Enforce `$baseline_active_samples >= 24`.

#### D. Model Selection by Window Duration
* If an analyst asks for an anomaly search over $\le 48\text{ hours}$ using a model that normally relies on multi-day baselines (e.g. 30-day moving average ratios or daily MAD lookups), **shift bucket granularity down from days to hours (`by 1h` / `by 15m`)** or **shift the comparison axis from longitudinal time-series to cross-sectional peer fleet normalization (`FLEET_PEER_ZSCORE`)**.

---

### 5. Search Window Ceilings: Single-Stage (90 Days) vs. Multi-Stage (30 Days)
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

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*

