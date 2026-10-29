---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.9.0
description: |
  Multi-stage statistical outlier hunting, Bayesian updating, and Entity Context Graph (GLOBAL_CONTEXT, DERIVED_CONTEXT) enrichment in Google SecOps over raw UDM telemetry. Supports Z-Score, Fano, Poisson, standalone Median Absolute Deviation (MAD) over raw fields or custom windows (30d MAD: secops-risk-metrics-multistage), Quantile/Bowley-Skewness Tukey Fences, CV, Gamma, Beta-Binomial, Delta-Z, Multi-Sector, Markov, Shannon, Zipf, EWMA, and Hybrid Models with 5-Section Triage Reporting (6 pillars, CRI [0-100]). Triggers: beaconing with jitter, MAD on DNS, Tukey fence, Bowley skewness, quantile fence, ingestion lag, impossible travel, poisson burst, fano factor, bayesian gamma, beta-binomial, dual-baseline delta-z, multi-sector threat fusion, service account out of normal behavioral scope, diversity deficit, elephant flow, two-part hurdle, global threat intel, derived context, markov process transition, shannon character entropy, zipfian process rarity, ewma burst velocity.
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

Executes **ad-hoc multi-stage statistical outlier hunting** in Google SecOps over raw UDM telemetry without pre-computed ML or UEBA batch metrics. *(Both raw UDM multi-stage hunting and `metrics.*` UEBA are native to Google SecOps; never mention BigQuery unprompted, and if asked, state BigQuery contributes nothing to SecOps UEBA.)*

> [!IMPORTANT]
> ### 🚨 Telemetry Scope & Mandatory Pre-Flight Delegation Gate
> Executes **ad-hoc multi-stage statistical anomaly detection strictly over raw in-flight event telemetry** (`UDM_EVENTS`).
> If an analyst prompt references `"UEBA"`, `"30-day baseline"`, `"30d baseline"`, `"risk metric"`, `"risk score"`, `"peer cohort"`, asks for a 30-day behavioral risk review, or asks to baseline/compare HTTP request volume across browser user-agent strings, hosts, or users (`metrics.http_queries_total`), **emit the Skill Delegation Card below and yield the turn (0 tool calls — NEVER run a compiler probe when delegating)**:
>
> ### 🔄 Skill Handoff Card — Skill Delegation: Route to `secops-risk-metrics-multistage`
> > [!NOTE]
> > **Architectural Boundary Demarcation: Ad-Hoc Raw Telemetry ──► Pre-Computed Behavioral Metrics**
> > • **Routing Rationale**: Rolling 30-day behavioral baselines and UEBA `metrics.*` functions are maintained in `secops-risk-metrics-multistage`.
> > • **Target Skill**: `secops-risk-metrics-multistage` | **Recommended Metric / Function**: `metrics.*` | **Target Dimension**: `[target user, host, or metric]`
> >
> > **Delegation Action**: Handing off to `secops-risk-metrics-multistage` to construct the 30-day behavioral baseline query.

---

## 🎯 Non-Statistician Intent & Trigger Catalog

Match the analyst's hypothesis to the optimal statistical model and explain using plain-English analogies:

| Analyst Operational Question | Statistical Model | Plain-English Concept & Analogy |
| :--- | :--- | :--- |
| *"Password sprays pulsing in intermittent waves."* | **`POISSON_BURST_CLUSTERING`** ($F = \sigma^2 / \mu > 4.0$) | **Rainfall downpour vs. trickle**: Normal errors trickle in; sprays arrive in synchronized bursts. |
| *"Sensitive admin commands (`vssadmin`, `whoami`) surging on quiet servers."* | **`POISSON_RARE_SURGE`** (Poisson $Z > 3.5$) | **Rarity on quiet baselines**: Improbability of $N$ events today given a near-zero arrival rate ($\lambda$). |
| *"C2 beaconing with randomized sleep jitter."* | **`C2_BEACONING_JITTER`** ($\text{CV} \le 0.20$) | **Robotic timing regularity**: Implants exhibit low timing variance ($\text{CV} \le 0.20$); human browsing is chaotic ($\text{CV} > 0.50$). |
| *"Sudden surges on volatile hosts while ignoring noisy machines."* | **`BAYESIAN_GAMMA_SHRINKAGE`** ($\text{Shift} \ge 3.0$) | **The Seasoned SOC Detective**: Gamma prior weights host stability against current evidence; stable hosts alert on small shifts. |
| *"Password spray failure ratios without single-trial (1/1) false alarms."* | **`BETA_BINOMIAL_REGULARIZATION`** ($P_{\text{fail}} \ge 0.70$) | **Small-Sample Ratio Regularizer**: Beta-Binomial updating shrinks single-trial mistakes toward population error baselines. |
| *"Isolate endpoint spikes from company-wide Patch Tuesday rollouts."* | **`DUAL_BASELINE_DELTA_Z`** ($\Delta Z \ge 3.0\sigma$) | **The Patch Tuesday Immunity Shield**: Subtracts fleet shift from personal surge ($\Delta Z = Z_p - Z_f$), ignoring fleet updates. |
| *"Coordinated low-and-slow kill chains across Auth, Endpoint, and Network."* | **`MULTI_SECTOR_FUSION`** ($D = \sqrt{\sum Z_i^2} \ge 3.0\sigma$) | **The Combined Arms Radar**: Orthogonal Euclidean distance across domains catches multi-vector attacks where point rules miss. |
| *"Service accounts accessing repositories from unexpected origins or service account out of normal behavioral scope."* | **`POISSON_ORIGIN_RARITY`** (Poisson $Z > 3.5$) | **The Train on a New Track**: Service accounts run on fixed rails; repository access from an unseen host has $\lambda \to 0$ over `USER_RESOURCE_ACCESS`. |
| *"Scripted exfiltration with low vocabulary entropy or elephant flows."* | **`DIVERSITY_DEFICIT`** ($k/(N+1) \le 0.20$) & **`ELEPHANT_FLOW_CONCENTRATION`** ($\text{Peak}/\text{Sum} \ge 0.70$) | **The High-Speed Conveyor**: Scripted exfiltration generates repetitive, low-entropy transfers with high single-flow concentration. |
| *"Privileged accounts logging into unseen endpoints or expanding machine radius."* | **`PRIVILEGED_LATERAL_EXPANSION`** ($Z_{\text{breadth}} \ge 2.0\sigma$) | **The Explorer off the Beaten Path**: Admins touch a bounded machine cluster; a surge in unique target hosts reveals lateral traversal. |
| *"Dormant or service accounts suddenly awakening with unusual activity."* | **`TWO_PART_HURDLE`** ($H \ge 2.5$) | **The Sleeper Awakening**: Dormant accounts incur a discrete activation penalty; active accounts score on continuous deviation. |
| *"Egress to newly registered domains (WHOIS) or GCTI threat indicators."* | **`GLOBAL_THREAT_INTEL`** ($Z_{\text{threat}} \ge 3.0$) | **The Flash in the Dark**: Combines raw network burst velocity with `GLOBAL_CONTEXT` (WHOIS NRD age $< 30$d or GCTI matches). |
| *"Anomalous logins targeting brand-new or recently commissioned assets."* | **`DERIVED_CONTEXT_PREVALENCE`** ($Z_{\text{auth}} \ge 2.5$) | **The Unfamiliar Machine**: Uses `DERIVED_CONTEXT` asset `first_seen_time` to separate routine logins from unestablished endpoints. |
| *"Execution bursts of rare or enterprise-unseen binaries."* | **`DERIVED_CONTEXT_FILE_PREVALENCE`** ($Z_{\text{threat}} \ge 2.5$) | **The Unprecedented Binary**: Uses `DERIVED_CONTEXT` file prevalence (`day_count = 10`, `rolling_max <= 3` and `> 0`) for a 2.5x multiplier. |
| *"Outbound egress bursts to enterprise-unseen or rare domains."* | **`DERIVED_CONTEXT_DOMAIN_PREVALENCE`** ($Z_{\text{threat}} \ge 2.5$) | **The First-Contact Flow**: Cross-references `DERIVED_CONTEXT` domain prevalence (`day_count = 10`, `rolling_max <= 3` and `> 0`). |
| *"Anomalous process lineages or rare parent-child executions (Word -> cmd)."* | **`MARKOV_2GRAM_TRANSITION_RARITY`** (Surprisal $I \ge 3.0$) | **The Broken Lineage Chain**: Parent-child transitions follow $P(B \mid A)$; rare adversary chains trigger high information surprisal. |
| *"Obfuscated command lines, base64 payloads, or algorithmic DGA domains."* | **`SHANNON_ENTROPY_CHARACTER`** (Entropy $\ge 5.5$) | **The Scrambled Script**: Encoded payloads and DGA tokens exhibit elevated character-class entropy proxy scores. |
| *"Rare admin utilities executing in the asymptotic fleet tail (<= 2 hosts)."* | **`ZIPFIAN_PROCESS_RARITY`** (Zipf Rarity $\ge 2.5$) | **The Long-Tail Tool**: Process execution follows a power law ($f(k) \propto 1/k^s$); stealthy utilities sit in the fleet tail. |
| *"Acute intraday rate acceleration without lagging trailing baselines."* | **`EWMA_BURST_VELOCITY`** (Velocity $V \ge 2.0\sigma$) | **The Sudden Kinetic Thrust**: Exponentially weighted moving average ($\alpha = 0.30$) captures instantaneous intraday velocity shifts. |
| *"Consecutive user logins faster than physical flight speed (> 900 km/h)."* | **`IMPOSSIBLE_TRAVEL_GEO_VELOCITY`** ($V \ge 900\text{ km/h}$) | **The Supersonic Commuter**: Haversine geodesic distance (`math.geo_distance`) across logins isolates cross-continent credential theft. |
| *"Workstations inverting directional byte ratio to become net producers."* | **`PRODUCER_CONSUMER_RATIO_INVERSION`** ($\rho \ge 0.70$, $Z \ge 2.5\sigma$) | **The Role Reversal**: Workstations consume data ($\rho < 0.20$); exfiltration flips $\rho = \text{sent}/(\text{sent}+\text{received}) \ge 0.70$. |

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Interactive Verification Gate)

0. **Pre-Flight Routing Interceptor (Risk Metrics Delegation Gate - Strict Precedence)**:
   Evaluate first; when any pre-computed baseline or UEBA indicator below matches, emit the **Skill Delegation Card** above and yield (**0 tool calls**):
   - **Explicit UEBA / 30d Baselines / Risk Metrics**: Prompts containing `"UEBA"`, `"30-day baseline"`, `"30d baseline"`, `"risk metric"`, `"risk score"`, or 30-day behavioral reviews.
   - **30d / `metrics.*` MAD**: MAD/modified-Z on a 30d metric-catalog vector routes to `secops-risk-metrics-multistage`; standalone raw-field or custom-window (1h–14d) MAD stays here.
   - **Web / HTTP & Domain Catalog Baselines**: HTTP volume across user-agents/hosts/users (`metrics.http_queries_*`), or 30d baselines over logins (`metrics.auth_attempts_*`), network (`metrics.network_*`), DNS (`metrics.dns_*`), process (`metrics.file_executions_*`), or Workspace (`metrics.workspace_*`).
   - **Peer Cohorts & Risk Scores**: Peer-group comparisons, `graph.risk_score`, or 360° health checks.
   - **Bilateral UEBA Harness Co-Execution**: When co-loaded with `secops-risk-metrics-multistage` on open-ended exploit/CTI inquiries (`references/statistical-hunting-cooperative-framework.md` §8), supply bounded-window raw pipelines (`by 5m`, `by 1h`, Markov 2-gram, Shannon, Poisson Fano, EWMA, CV jitter, Zipfian) paired with 30d `metrics.*` and `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` loopback; never run 30d raw scans over VPC/DNS/HTTP/Auth.
1. **Universal Pre-Flight Gate & Interactive Scoping Protocol**:
   Turn 1 emits approach overview, analogy, pre-flight card, candidate query preview (` ```yara `), and clearance question. Turn 1 never executes multi-stage `stage ... { ... }` pipelines (`ZERO_UNSOLICITED_EXECUTION`); multi-stage execution occurs strictly on Turn 2 after clearance.
2. **Consultative Support & Expert Bypass Rule**:
   * *Consultative Discovery*: For open-ended raw telemetry requests, inspect `references/consultative-worksheet.md` (14 Raw Behavioral Telemetry Deformations across 6 Domains) and offer 2–3 Summary View options.
   * *Enterprise-Grounded Hunt Consultative Pattern*: Offer **Tier A (Pure Local Baseline)** vs **Tier B (Enterprise-Grounded Hunt)** joining `DERIVED_CONTEXT` prevalence (`day_count = 10`, `rolling_max <= 3` and `> 0`) for a 2.5x rarity multiplier.
   * *Expert Bypass Rule*: If target telemetry and statistical model are specified, emit the Pre-Flight Card directly.
3. **Plain-English Operational Analogy**: Explain detection mechanics in 1–2 intuitive sentences.
4. **Structured Pre-Flight Hunting Specification Card & Candidate Query Preview**:
   * *Template-First Formulation Directive*: Inspect `~/.gemini/config/skills/secops-statistical-hunter/templates/pipelines/<model>.yl2` (or `references/multi-stage-query-guide.md`):
     - **Parametric/Robust**: `zscore_process_surge_2stage.yl2`, `mad_modified_z_4stage.yl2` (`MAD_EXFILTRATION`), `iqr_tukey_skew_fences_3stage.yl2` (`IQR_TUKEY_SKEW_FENCES`), `log_normal_volume_surge_2stage.yl2`, `ewma_burst_velocity_2stage.yl2`
     - **Poisson/Timing**: `poisson_burst_clustering_2stage.yl2`, `poisson_rare_surge_2stage.yl2` (`POISSON_ORIGIN_RARITY`), `c2_beaconing_jitter_2stage.yl2`
     - **Bayesian/Fleet**: `bayesian_gamma_shrinkage_4stage.yl2`, `beta_binomial_failure_4stage.yl2`, `dual_baseline_delta_z_3stage.yl2`
     - **Multi-Sector/Hybrid**: `multi_sector_threat_fusion_4stage.yl2`, `privileged_lateral_expansion_2stage.yl2`, `two_part_hurdle_2stage.yl2`, `hybrid_entropy_concentration_2stage.yl2`, `impossible_travel_geo_velocity_2stage.yl2`, `producer_consumer_ratio_inversion_2stage.yl2`
     - **Info-Theoretic & ECG**: `zipfian_process_rarity_2stage.yl2`, `markov_2gram_transition_rarity_2stage.yl2`, `shannon_entropy_character_2stage.yl2`, `global_threat_intel_enrichment_3stage.yl2`, `derived_context_prevalence_3stage.yl2`, `derived_context_file_prevalence_3stage.yl2`, `derived_context_domain_prevalence_3stage.yl2`
   * *Canonical Pre-Flight Specification Card Structure*:
     ```markdown
     PRE-FLIGHT HUNTING SPECIFICATION:
     • Target Entity / Scope:  `[Entity]` ([Entity Type])
     • Threat Hypothesis:      [1-sentence specific threat hypothesis]
     • Baseline Horizon Spine: Raw UDM Telemetry (`[EVENT_TYPE]`, 14-day horizon via `startTime`/`endTime`, canonical `by 1h`/`by 1d` buckets)
     • Statistical Model:      [Canonical Mathematical Model Name]
     • Significance Threshold: [Model-specific statistical threshold] | CRI >= 50
     • Compiler Probe:         1-shot `udm_search(maxEvents=1)` over a 10-minute ISO 8601 window — schema verified.

     ### Candidate Multi-Stage YARA-L Query Preview
     ```
   * *6 Mandatory Root Outcome Variables Protocol*:
     Every multi-stage query emits all 6 root outcome variables: `$observation_count`, `$baseline_active_samples`, `$baseline_mean`, `$baseline_dispersion`, `$fleet_prevalence`, and `$distinct_binaries` (max 20 outcome vars per block). When fleet breadth is not computed, emit `$fleet_prevalence = 0 - 1` (bare `-1` fails compilation; never emit literal `1` as a placeholder).
   * *Affirmative Compiler Grammar Protocols*:
     - **Entity Scoping & Stage Bindings**: Filter target entities in Stage 1 (`principal.hostname = "dev-ub22-1"`, `principal.hostname = $entity`, `$entity != ""`), bind `match:` with bare identifiers (`$entity by 1h`, `$entity, $ws by 1h`, `$host by 1d`), and place cross-stage bindings before `match:` in root (max 3 named + 1 root = 4 stages).
     - **Outcome `if()`, OIO & Safe Dispersion**: `if()` `then` clauses require simple placeholders/constants (bind compound math to an intermediate variable first). In-stage OIO derivations (`$diff = $obs - $avg`, `$z = $diff / $safe_sd`) are supported. Guard division with `$safe_sd = if($sd > 0, $sd, 1.0)` and divide directly (`/ $safe_sd`).
     - **Function Factory Math & Window Built-Ins**: Supports `math.sqrt()`, `math.log()`, `math.pow(base, exp)` (`math.pow(2.718281828, x)` for $e^x$; `math.exp()` does NOT exist), `math.abs()`, `math.round()`, `math.floor()`, `math.ceil()`, `math.geo_distance()`, `window.percentile(expr, P)` ($P \in [0, 100]$, 1-stage quantiles, Bowley skewness, lag auditing), and `window.median(expr, false)`. `math.min()`/`math.max()` do NOT exist; use `if($a > $b, $a, $b)`.
     - **Stage Keying, Windows & Aggregations**: Unwindowed stages (`match: $host`) collapse entity baselines; windowed breadth stages key on `$ws = $stage1.window_start` (`match: $ws by 1h`). Join at most 2 raw stages at root (`sum(if(metadata.event_type = "...", 1, 0))` for 3+ sectors) and canonical windows (`by 5m`, `by 1h`, `by 2h`, `by 1d`). Use single `=` in `if($flag = 1.0, ...)`, `re.regex(<field>, `(?i)...`)`, `max()`/`min()` on numbers, `array_distinct()`/`count_distinct()` on strings, `$max_day = max($day_id)` for daily isolation, and plain Unicode in table headers (`Mean (μ)`, `StdDev (σ)`).
     - **ECG Freshness, Join Filter & Day-0 Companion (`WS1-08`)**: Anchor `DERIVED_CONTEXT` hunts at `D-2` (`compute_ecg_search_window`), disclose that Stage 2 is an **inner-join filter** (unindexed artifacts drop out; pair with `build_day0_companion_query` for **Day-0** artifacts), and when `first_seen_time = 0`, disable `<7d` ECG novelty and defer to `metrics.*` `first_seen`.
5. **Compile-Time Verification Protocol & Identifier Coverage Probe (`D4`)**:
   Run at most ONE 10-minute flat single-event probe (+ max 1 retry) on Turn 1 (`udm_search(query="metadata.event_type = \"...\" AND ...", maxEvents=1)` — never run multi-stage `stage` pipelines on Turn 1). For network/DNS/HTTP hunts where tenant identifier coverage varies (`principal.ip` ~99.9% vs `principal.asset.hostname` < 1%), use `build_identifier_coverage_probe(event_type)` (1h read-only stats screen) and `select_identifier_from_coverage(payload)` (`identifier_coverage_payload` in `build_query`) to select `principal.asset.hostname` when $\ge 20\%$ (or $\ge$ IP coverage) else `principal.ip`; join hostnames to IPs **only** via a `DERIVED_CONTEXT` `ASSET` stage, never direct equality.
6. **Explicit Clearance Question & Turn 1 Yield Invariant**:
   Conclude Turn 1 with:
   *"Would you like me to proceed with executing this search in **Mode A (Rolling 24-Hour Raw-Event Window)** or **Mode B (14-Day Raw-Event Timeline)**?"*
   *(Recommend **Mode B (7-to-14-Day Raw-Event Timeline)** by default for `by 1d` models; hourly models support Mode A or B.)* Yield the turn immediately.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 5-Section Triage Report (After Clearance)

1. **Immediate Execution Turn (Single Multi-Stage Dispatch & Zero Follow-Up Raw Dumps)**:
   Dispatch the approved multi-stage query via `udm_search` once (Mode B 14d default for `by 1d`; Mode A 24h for `by 1h`/`by 5m`). If `{}` or `{"stats": []}` returns, stop calling tools and render the 5-Section Triage Report as a nominal baseline (`0 Outliers Detected`). Never run follow-up raw dumps or Python scripts.
2. **Mandatory 5-Section Triage Report Delivery (All Models & Zero-Outlier Runs)**:
   Even when a hunt returns 0 outlier rows (`{}` / `{"stats": []}`) or runs an info-theoretic model (`SHANNON_ENTROPY_CHARACTER`, `MARKOV_2GRAM_TRANSITION_RARITY`, `ZIPFIAN_PROCESS_RARITY`), Turn 2 MUST ALWAYS emit all 5 canonical sections in exact order:

```markdown
### ⚡ Statistical Outlier Report: [Hunt Topic]
* **Outliers Detected**: [N entities] exceeded the anomaly threshold.
* **Normal Baseline Envelope**: Typical Average ($\mu$) $\approx X$ | Typical Variation ($\sigma$) $\approx \pm Y$
* **Fleet Scaling**: Threshold adjusted to $Z_{\text{adj}} \approx Z\sigma$ for fleet size $N$.

---
#### 📊 Ranked Outlier Summary
| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `host-alpha` | 2026-08-24T08:00 | **850** | 250 ± 35 | 🟢 **HIGH CONFIDENCE** | 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | 🚨 `[CRI: 100]` | `██████████` |

---
#### 🔍 Top Outlier Spotlight: `host-alpha` — 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | 🚨 `[CRI: 100]`
* **Data Confidence Level**: 🟢 **HIGH CONFIDENCE** — Strong sample density ($N \ge 30$).
##### 🗣️ What Happened & Why It Matters (In Plain English)
[Plain-English executive explanation including CRI operational tier]
##### 🏛️ Forensic Evidence Breakdown (6 Mandatory Evidence Pillars)
| Evidence Pillar | Observed Value | What this Means for Your Investigation |
| :--- | :--- | :--- |
| **1. Activity Spike** | `850` | Exact event count or score observed during spike window (`$observation_count`) |
| **2. Baseline History** | `168 hours` | Depth of historical data evaluated (`$baseline_active_samples`) |
| **3. Typical Normal Level** | `250.0` | Expected baseline average volume (`$baseline_mean`) |
| **4. Normal Daily Spread** | `±35.0` | Normal deviation range (`$baseline_dispersion`) |
| **5. Company-Wide Breadth**| `1 host` | Isolated vs fleet-wide prevalence (`$fleet_prevalence`; `Unknown / N/A` if `-1`) |
| **6. Variety of Programs** | `42 unique` | Distinct binaries, tokens, or targets involved (`$distinct_binaries`) |

[Potential Attack Scenarios | Legitimate Business Explanations | Step-by-Step SOC Action Plan]

> [!NOTE]
> **Zero Outliers (Nominal Baseline)**: When $N=0$ outliers breach the threshold, all 5 sections remain mandatory. Format Section 3 as `#### 🔍 Top Outlier Spotlight: Nominal Baseline (0 Outliers Detected)` and populate all 6 Forensic Evidence Pillars with nominal baseline values.

---
#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)
*(Passive UDM filter for manual triage in Chronicle SIEM console. Use a ```text fence — NEVER ```yara.)*
```text
principal.hostname = "host-alpha" AND metadata.event_type = "PROCESS_LAUNCH"
```

---
<details>
<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>

##### 📐 Mathematical Model & Formulaic Derivations
* **Model**: $Z = \frac{x - \mu}{\sigma} = \frac{850 - 250.0}{35.0} = +17.14\sigma$
##### 🎚️ Calibrated Risk Index (CRI) Sigmoid Normalization
$$\text{CRI} = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right) = \mathbf{100}$$
##### 🌐 Multiple-Comparison Fleet Correction ($Z_{\text{adj}} \approx \sqrt{2 \ln N}$)
##### 🛡️ Statistical Validity & Safeguard Verification
##### 📜 Verbatim Executed Multi-Stage YARA-L Query
*(This is the ONLY ```yara code block permitted in the Turn 2 post-execution report.)*
```yara
stage host_hourly { ... }
```
</details>
```

---

### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock)

* **Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)**: When the analyst asks to *"run same for user X"*, *"what about admin?"*, or shifts entities, RETAIN SESSION AFFINITY and re-enter State 1 for the new entity (operational analogy ──► compiler probe ──► spec card ──► clearance question).
* **Federated Bridge to Macro Analysis**: When the analyst requests 30-day pre-computed baselines, peer cohort comparisons, longitudinal CUSUM drift, or 360° health checks, emit the Skill Handoff Card steering to `secops-risk-metrics-multistage` (enforcing Zero-Code Handoff Invariant).
* **Bilateral Cooperative Framework**: Consult `references/statistical-hunting-cooperative-framework.md` for macro vs. micro division of labor.

---

## 🎨 Strict Visual Axis-Type Isolation & Post-Query Verification

* **Visual Axis-Type Isolation (Vega-Lite / Chart.js)**: Map numeric volume (`quantitative`) to the **Left Y-Axis**, anomaly scores ($Z, \sigma, Fano$) to the **Right Y-Axis ($y_1$)**, timestamps (`temporal`) or categories (`nominal`) to the **X-Axis**, and categorical IDs (`host`, `user`, `extension_id`) exclusively to X-axis, color, or facet encodings.
* **Post-Query Intent & Concordance Verification**: Validate natively in chat that the executed query runs as a true multi-stage DAG matching the pre-flight specification card.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 0. THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)
* **Invariant 1: Empirical Data Grounding (Zero Data Simulation)**: Derive all metrics ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) from `udm_search` responses. When `udm_search` returns `{}` or zero matches, report nominal baseline (`0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`). Truth Over Completion.
* **Invariant 2: Verified Compiler Grammar (Zero Schema/Syntax Fantasy)**: Construct queries from validated UDM schemas and compilable YARA-L 2.0 grammar (ISO 8601 timestamps, safe denominators). Validate via a 10-minute 1-shot probe.

### 1. Native Execution & Truth in Reporting
* **Empirical Metric Derivation Contract**: Derive all summary numbers ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) directly from `udm_search` outputs.
* **Transparent Error Surfacing**: When an API query returns an error, surface the exact error response and diagnostics directly to the analyst.
* **Tool Orchestration Protocol**: Use chat Markdown and SecOps MCP tools (`udm_search`, `import_logs`, `create_case_comment`) and `read_file` on `~/.gemini/config/skills/secops-statistical-hunter/templates/pipelines/*.yl2`. There is no blanket approval for `run_command`, only explicit exemptions.
* **Native SIEM Engine Execution Guarantee**: Execute all multi-stage baseline aggregations, standard deviations, and thresholds natively within Google SecOps Chronicle SIEM via `udm_search`.
* **Pre/Post Execution Query Integrity Gate (`QueryIntegrityGate`)**: Verify zero unresolved `{{placeholders}}`, AST compliance, and aggregated `stats` buckets. Section 5 (`Statistical & Mathematical Appendix`) carries the verbatim executed multi-stage query as the ONLY ```` ```yara ```` block in Turn 2.
* **Search Query Nomenclature**: Structure all threat hunting artifacts as ad-hoc Multi-Stage Queries (`stage ... { ... }` + Root stage); `rule ... { ... }` is reserved for detection engineering.

### 2. Calibrated Risk Index (CRI [0–100]) Standard
* **CRI Normalization & Zero-Floor Clamp**: Maps raw deviations ($Z$-scores, $\text{MAD } Z$, Poisson deviance, $\text{CV}$) onto a [0–100] S-Curve with a zero floor ($\text{CRI}(Z) = 0$ for $Z \le 0$) and $Z = 3.0\sigma$ anchored at $\text{CRI} = 50$:
  $$\text{CRI}(Z) = \begin{cases} 0 & \text{if } Z \le 0 \\ \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right) & \text{if } Z > 0 \end{cases}$$
* **In-Query Derivation**: Inside YARA-L `outcome:` blocks (where `math.exp()` does not exist), compute CRI via piecewise step-function tiers (`if($z >= 6.5, 95, ...)`) or `math.pow(2.718281828, ...)`.

### 3. Clean Hand-Off (CH) Protocol (Synthetic UDM Event Ingestion vs. Active Case Wall)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill escalation requests (*"create a UDM alert"*, *"alert on this"*, *"escalate"*, *"open a case"*, *"handoff"*) via Clean Hand-Off (`references/clean-handoff-udm-schema.md`):
* **Path A (Standard Escalation Default — Synthetic Event Ingestion)**: Map outliers to synthetic UDM events (`product_name: "SecOps Statistical Hunter"`, `resource_type: "RESOURCE_TYPE_UNSPECIFIED"`, shared `Hunt Campaign ID`). Preview the Pre-Ingestion Clearance Card (yield turn, 0 tools), then ingest via `import_logs` (`log_type: "UDM"` with `forwarderId` wrapping `{"events": [{"event": ...}]}`).
* **Path B (Explicit Active Case Attachment)**: Only when explicitly instructed for an active case (*"Attach to Case 11075"*), call `create_case_comment(case_id="<ID>", comment=...)`.
* **Conceptual Handoff Contract (Cross-Skill Steering Protocol)**: Maintain Skill Handoff Cards to peer skills as purely architectural envelopes. Zero-Code Handoff Invariant: Skill steering never emits candidate queries or code blocks.

---

## 📚 Specialized Deep-Dive Reference Guides

* [statistical-models-taxonomy.md](references/statistical-models-taxonomy.md) | [calibrated-risk-index-guide.md](references/calibrated-risk-index-guide.md) | [clean-handoff-udm-schema.md](references/clean-handoff-udm-schema.md)
* [multi-stage-query-guide.md](references/multi-stage-query-guide.md) | [malachite-function-factory-matrix.md](references/malachite-function-factory-matrix.md) | [entity-context-graph-guide.md](references/entity-context-graph-guide.md)
* [scope-exclusions-guardrail.md](references/scope-exclusions-guardrail.md) | [consultative-worksheet.md](references/consultative-worksheet.md) | [dynamic-windowing-matrix.md](references/dynamic-windowing-matrix.md)
* [chart-specifications-guide.md](references/chart-specifications-guide.md) | [query-auditing-guide.md](references/query-auditing-guide.md) | [cyber-practitioner-glossary.md](references/cyber-practitioner-glossary.md)
* [statistical-hunting-cooperative-framework.md](references/statistical-hunting-cooperative-framework.md)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
