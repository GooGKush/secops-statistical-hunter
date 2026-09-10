---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.4.1
description: |
  Guides and executes multi-stage statistical anomaly detection, Bayesian credibility updating,
  and outlier hunting in Google Security Operations (SecOps) over raw UDM telemetry across custom time slices.
  Supports Z-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Median Absolute Deviation (MAD),
  Coefficient of Variation (CV), Poisson-Gamma Bayesian Shrinkage, Beta-Binomial Ratio Regularization,
  Dual-Baseline Delta-Z (Patch Tuesday Shield), Multi-Sector Threat Fusion, and 6 Hybrid Mathematical Models
  (Diversity Deficit, Elephant Flow Concentration, Orthogonal Threat Space, Bayesian Joint Odds, Two-Part Hurdle,
  and Fleet Prevalence Normalization). Supports dynamic root-stage condition filtering and noise level steering.
  Enforces strict 5-Section CommonMark Triage Reporting (with 6 standardized forensic evidence pillars,
  Calibrated Risk Index [0-100] normalization, Unicode visual bars, and 1-click drilldowns),
  strict visual axis-type isolation, and post-query intent and stage degradation auditing.
  Triggers: "hunt for beaconing with jitter", "inline C2 timing regularity", "calculate MAD on DNS",
  "Tukey fence anomaly", "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "poisson burst clustering", "fano factor password spray", "rare admin tool surge",
  "bayesian gamma prior updating", "beta-binomial failure rate shrinkage", "dual-baseline delta-z",
  "patch tuesday immunity", "multi-sector threat fusion", "4-stage killchain hunter",
  "service account out of normal behavioral scope", "unexpected host origin or abnormal access patterns",
  "unusual data repository access", "service account origin rarity", "source code repository anomaly",
  "diversity deficit", "elephant flow concentration", "orthogonal threat space", "two-part hurdle", "privileged lateral expansion", "unseen endpoint login", "admin destination breadth".
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

This skill empowers an LLM agent and SOC analyst to execute **ad-hoc multi-stage statistical outlier hunting** in Google SecOps over raw UDM telemetry without requiring pre-computed machine-learning pipelines or UEBA batch metrics.

> [!NOTE]
> ### 🎯 Telemetry Scope & Skill Delegation
> This skill executes **ad-hoc multi-stage statistical anomaly detection over raw in-flight event telemetry** (`UDM_EVENTS`).
> **Skill Delegation Boundary:**
> 1. 30-Day pre-computed behavioral baselines (`window: 30d`)
> 2. Team, cohort, or peer-group comparisons from Risk Analytics
> 3. 360° entity health checks or omnibus risk scoring (`graph.risk_score`)
> 4. UEBA or Risk Analytics pre-computed metrics (`metrics.*`)
> 5. Cloud-native data repository baselines (GCS, BigQuery, S3) with pre-computed origin IP baselines (`metrics.resource_read_*`, `principal.ip`).
> 👉 **Delegate all 30-day baseline, peer, and UEBA requests to `secops-risk-metrics-multistage` (enforcing the conceptual Skill Handoff Card protocol).**

---

## 🎯 Non-Statistician Intent & Trigger Catalog

When interacting with a cybersecurity analyst, **match their operational hypothesis to the optimal statistical model** and explain the choice using plain-English physical analogies:

| Analyst Operational Question | Statistical Model | Plain-English Concept & Analogy |
| :--- | :--- | :--- |
| *"Find password sprays or brute force pulsing in intermittent waves to evade rate limits."* | **`POISSON_BURST_CLUSTERING`** ($F = \sigma^2 / \mu > 4.0$) | **Rainfall downpour vs. steady trickle**: Normal login mistakes trickle in steadily; automated attack waves arrive in synchronized, clumpy bursts. |
| *"Detect sensitive admin commands (`vssadmin`, `whoami`) surging on quiet servers without division-by-zero."* | **`POISSON_RARE_SURGE`** (Poisson $Z > 3.5$) | **Mathematical rarity on quiet baselines**: Evaluates the improbability of seeing $N$ events today given a near-zero historical arrival rate. |
| *"Hunt for C2 beaconing where the implant uses randomized sleep delays to avoid fixed-interval alerts."* | **`C2_BEACONING_JITTER`** ($\text{CV} \le 0.20$) | **Robotic timing regularity**: Automated implants exhibit low timing variance ($\text{CV} \le 0.20$), while human browsing is chaotic ($\text{CV} > 0.50$). |
| *"Find sudden surges on volatile hosts while ignoring false alarms on erratic machines."* | **`BAYESIAN_GAMMA_SHRINKAGE`** ($\text{Shift} \ge 3.0$) | **The Seasoned SOC Detective**: Gamma prior weights host stability against current evidence; stable machines alert on small shifts. |
| *"Hunt for password spray / error ratios without false alarms from single-trial mistakes (1 fail / 1 try)."* | **`BETA_BINOMIAL_REGULARIZATION`** ($P_{\text{fail}} \ge 0.70$) | **Small-Sample Ratio Regularizer**: Beta-Binomial conjugate updating regularizes single-trial mistakes toward population error baselines. |
| *"Isolate targeted endpoint spikes from company-wide software deployments or Patch Tuesday."* | **`DUAL_BASELINE_DELTA_Z`** ($\Delta Z \ge 3.0\sigma$) | **The Patch Tuesday Immunity Shield**: Subtracts concurrent fleet shift from personal surge ($\Delta Z = Z_p - Z_f$), ignoring company-wide updates. |
| *"Detect coordinated low-and-slow kill chains across Auth, Endpoint, and Network silos."* | **`MULTI_SECTOR_FUSION`** ($D = \sqrt{\sum Z_i^2} \ge 3.0\sigma$) | **The Combined Arms Radar**: Computes orthogonal Euclidean distance across domains, catching multi-vector attacks where point detectors miss. |
| *"Find service accounts accessing source code or data repositories (GitHub, GitLab, internal shares) from unexpected host origins or out of normal scope."* | **`POISSON_ORIGIN_RARITY`** (Poisson $Z > 3.5$) | **The Train on a New Track**: Service accounts operate like trains on fixed rails (fixed CI runners, deterministic IPs). Accessing a repository from an unseen host has a near-zero historical arrival rate ($\lambda \to 0$), triggering an acute statistical rarity alert over raw `USER_RESOURCE_ACCESS`. |
| *"Find automated scripted exfiltration where an entity touches many destinations with minimal vocabulary entropy or elephant flows."* | **`DIVERSITY_DEFICIT`** ($k/(N+1) \le 0.20$) & **`ELEPHANT_FLOW_CONCENTRATION`** ($\text{Peak}/\text{Sum} \ge 0.70$) | **The High-Speed Conveyor**: Attackers scripting data exfiltration generate repetitive, low-entropy transfers with high volume concentration. |
| *"Detect privileged or administrative accounts logging into unseen endpoints or expanding their machine radius."* | **`PRIVILEGED_LATERAL_EXPANSION`** ($Z_{\text{breadth}} \ge 2.0\sigma$) | **The Explorer off the Beaten Path**: Admins routinely touch a small, bounded cluster of machines; a sudden surge in unique target workstations/servers reveals lateral traversal. |
| *"Detect dormant accounts or service accounts suddenly awakening with unusual activity."* | **`TWO_PART_HURDLE`** ($H \ge 2.5$) | **The Sleeper Awakening**: Historically dormant accounts incur a discrete activation penalty; active accounts are evaluated on continuous baseline deviation with exact conditional zero-dispersion protection. |

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Interactive Verification Gate)

When an analyst initiates a threat hunt or selects an archetype, proceed through the interactive pre-flight gate:
1. **Interactive Scoping Protocol**: Reserve Turn 1 for configuration, scoping, and confirmation. Full historical search execution begins after analyst clearance.
2. **Consultative Support & Expert Bypass Rule**:
   * *Consultative Discovery*: If the analyst's request is open-ended, inspect `references/consultative-worksheet.md` to classify the objective across the 5 Raw Behavioral Telemetry Deformations and present 2–3 targeted Summary View options.
   * *Expert Bypass Rule*: If the analyst specifies both the target telemetry (e.g. `PROCESS_LAUNCH`) and statistical model (e.g. `MAD` or `Z-score`), proceed directly to emitting the Pre-Flight Card.
3. **Plain-English Operational Analogy**: Explain the detection mechanics in 1-2 intuitive sentences.
4. **Structured Pre-Flight Hunting Specification Card**: Present hunting objective, telemetry scope, search horizon, model, and threshold.
   * *Noise Level & Significance Threshold Steering*: Analysts may adjust sensitivity thresholds or define sensitivity bands (e.g. `$z_score >= 2.0 and $z_score < 3.0` for investigative anomalies, or `$z_score >= 3.0` for critical outliers), enforced via root-stage `condition:`.
5. **Compile-Time Verification Protocol**: Verify query grammar via a background 1-shot probe with ISO 8601 timestamps against a 10-minute horizon: `secops-gus:udm_search(query="<query>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Present the candidate YARA-L query in markdown once validated (200 OK).
6. **Explicit Clearance Question & Turn Termination**: Solicit analyst confirmation to execute across the full historical horizon, conclude the turn, and await approval.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 5-Section Triage Report (After Clearance)

When formatting hunting results for ANY client (CLI, Chat UI, or Web UI), the agent **MUST ALWAYS OUTPUT ALL 5 SECTIONS** in exact order:

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
| **1. Activity Spike** | `850` | Exact event count observed during spike window |
| **2. Baseline History** | `168 hours` | Depth of historical data evaluated |
| **3. Typical Normal Level** | `250.0` | Expected baseline average volume |
| **4. Normal Daily Spread** | `±35.0` | Normal deviation range |
| **5. Company-Wide Breadth**| `1 host` | Isolated vs fleet-wide prevalence |
| **6. Variety of Programs** | `42 unique` | Distinct binaries or IPs involved |

[Potential Attack Scenarios | Legitimate Business Explanations | Step-by-Step SOC Action Plan]

---
#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)
*(Passive UDM filter provided strictly as an analyst copy-paste reference for manual triage within the Chronicle SIEM console. Automated multi-turn agent execution is reserved for multi-stage statistical pipelines.)*
```yara
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
</details>
```

---



### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock)

* **Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)**: When analyst asks to *"run same for user X"*, *"what about admin?"*, or shifts entities, RETAIN SESSION AFFINITY and re-enter State 1 for the new entity (operational analogy ──► compiler probe ──► spec card ──► clearance question). Maintain execution exclusively within the structured statistical hunting framework rather than unconstrained raw searches.
* **Federated Bridge to Macro Analysis**: When analyst requests 30-day pre-computed baselines, peer cohort comparisons, longitudinal CUSUM drift, or 360° health checks, emit Skill Handoff Card steering to `secops-risk-metrics-multistage` (enforcing Zero-Code Handoff Invariant).
* **Bilateral Cooperative Framework**: Consult `references/statistical-hunting-cooperative-framework.md` for macro vs. micro division of labor and mutual delegation protocols.

---

## 🎨 Strict Visual Axis-Type Isolation Rules

When generating Vega-Lite or Chart.js charts:
* **Left Y-Axis**: Map numeric event volume (`quantitative` / `linear`).
* **Right Y-Axis ($y_1$)**: Map statistical anomaly scores ($Z, \sigma, Fano$).
* **X-Axis**: Map timestamps (`temporal`) or categories (`nominal`).
* **Categorical Mapping**: Assign categorical string identifiers (`host`, `user`, `extension_id`) exclusively to the X-axis, color encodings, or facet dimensions.

---

## 🔍 Post-Query Intent & Architecture Verification

Before finalizing execution, verify that the executed query matches the promised architecture and narrative:
```bash
python3 scripts/multistage_query_builder.py \
  --query_file hunt_query.yara \
  --audit_intent DUAL_BASELINE_3STAGE \
  --audit_model DELTA_Z
```
* **Concordance & Anti-Degradation**: `PostFlightExecutionAuditor` validates that when a multi-stage pipeline is explained to the analyst, the executed query actually runs as a multi-stage DAG with named stages, preventing silent degradation into single-stage stats searches.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 0. THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)
* **Invariant 1: Empirical Data Grounding (Zero Data Simulation)**: Extract all reporting metrics ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) directly from verified Chronicle SIEM API responses (`secops-gus:udm_search`). When an API response is empty (`{}`) or returns zero matches, report normal operational baseline (`0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`). Truth Over Completion — reporting zero anomalies confirms that the target entity is behaving within normal historical parameters, which constitutes a successful, complete threat hunt.
* **Invariant 2: Verified Compiler Grammar (Zero Schema/Syntax Fantasy)**: Construct queries strictly from validated UDM schemas and compilable YARA-L 2.0 grammar (e.g. ISO 8601 timestamps, safe intermediate denominators in root outcome, valid linear derivations). Validate every query against the live Chronicle compiler via a 10-minute background probe before presenting it in the specification card.


### 1. Native Execution & Truth in Reporting
* **Empirical Metric Derivation Contract**: Derive all summary numbers ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) directly from `secops-gus:udm_search` query outputs. When a search yields no outliers, report the normal baseline status accurately.
* **Transparent Error Surfacing**: When an API query returns an error, surface the exact error response and diagnostic details directly to the analyst with proposed template adjustments.
* **Native SIEM Engine Execution Guarantee**: Execute all multi-stage baseline aggregations, standard deviation calculations, and threshold evaluations natively within Google SecOps Chronicle SIEM via `secops-gus:udm_search`.
* **Verbatim Query Provenance**: Display the exact literal multi-stage YARA-L query string submitted to `secops-gus:udm_search(query=...)` in Section 2 of the triage report.
* **Statistical Aggregation Integrity**: Format the 5-Section Triage Report exclusively from aggregated `stats` buckets. If `udm_search` returns unaggregated raw events, present the auto-corrected multi-stage query (via `MultiStageTemplateRouter`) and solicit analyst clearance to execute the aggregated pipeline.
* **Search Query Nomenclature**: Identify and structure all threat hunting artifacts as ad-hoc Multi-Stage Queries (`stage ... { ... }` + Root stage). Continuous detection rules (`rule ... { ... }`) are reserved for detection engineering workflows.

### 2. Calibrated Risk Index (CRI [0–100]) Standard
* **CRI Normalization**: The Calibrated Risk Index maps raw statistical deviations ($Z$-scores, $\text{MAD } Z$, Poisson deviance, $\text{CV}$) onto a standardized [0–100] S-Curve:
  $$\text{CRI}(Z) = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right)$$
* **Anchoring Invariant**: Strictly anchors the 3-Sigma alertable boundary ($Z = 3.0\sigma$) at exactly $\text{CRI} = 50$.
* **CRI Derivation Standard**: Derive the CRI either via the standardized sigmoid formula in post-processing presentation scripts (`scripts/multistage_query_builder.py`) or via piecewise outcome tiers in the query root stage.

### 3. Clean Hand-Off (CH) Protocol (Synthetic UDM Event Ingestion vs. Active Case Wall)
* **Path A (Standard Escalation Default — Synthetic Event Ingestion)**: When an analyst requests escalation (*"Escalate to SecOps"*, *"Log in Chronicle"*), generate a synthetic UDM event (`product_name: "SecOps Statistical Hunter"`) encapsulating the 6 Evidence Pillars and ingest via `import_logs` for automated case promotion.
* **Path B (Explicit Active Case Attachment)**: When the analyst is actively reviewing a specific case and explicitly instructs findings to be attached (e.g. *"Attach to Case 11075"*), execute `create_case_comment(case_id="...", comment=...)`.
* **Case Attachment Targeting**: Call `create_case_comment` exclusively when provided with an explicit, analyst-confirmed `case_id`.
* **Conceptual Handoff Contract (Cross-Skill Steering Protocol)**: Maintain Skill Handoff Cards as purely architectural and conceptual envelopes (specifying protocol, intent, target entity, and parameters). Query formulation and code emission belong exclusively to the destination skill once invoked.

---

## 📚 Specialized Deep-Dive Reference Guides

* **Mathematical Models & Formulations**: See [references/statistical-models-taxonomy.md](references/statistical-models-taxonomy.md)
* **Calibrated Risk Index (CRI) Guide**: See [references/calibrated-risk-index-guide.md](references/calibrated-risk-index-guide.md)
* **Clean Hand-Off & Synthetic Ingestion**: See [references/clean-handoff-udm-schema.md](references/clean-handoff-udm-schema.md)
* **Multi-Stage Query Grammar & Compiler Invariants**: See [references/multi-stage-query-guide.md](references/multi-stage-query-guide.md)
* **Dynamic Time-Window Adaptation Matrix**: See [references/dynamic-windowing-matrix.md](references/dynamic-windowing-matrix.md)
* **Chart Specs (Vega-Lite & Chart.js)**: See [references/chart-specifications-guide.md](references/chart-specifications-guide.md)
* **Query Auditing & Intent Verification**: See [references/query-auditing-guide.md](references/query-auditing-guide.md)
* **Cyber Glossary & SOC Playbooks**: See [references/cyber-practitioner-glossary.md](references/cyber-practitioner-glossary.md)
* **Bilateral Cooperative Framework**: See [references/statistical-hunting-cooperative-framework.md](references/statistical-hunting-cooperative-framework.md)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
