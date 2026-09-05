---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.3.0
description: |
  Guides and executes multi-stage statistical anomaly detection, Bayesian credibility updating,
  and outlier hunting in Google Security Operations (SecOps) over raw UDM telemetry across custom time slices.
  Supports Z-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Median Absolute Deviation (MAD),
  Coefficient of Variation (CV), Poisson-Gamma Bayesian Shrinkage, Beta-Binomial Ratio Regularization,
  Dual-Baseline Delta-Z (Patch Tuesday Shield), and Multi-Sector Threat Fusion.
  Enforces strict 5-Section CommonMark Triage Reporting (with 6 standardized forensic evidence pillars,
  Calibrated Risk Index [0-100] normalization, Unicode visual bars, and 1-click drilldowns),
  strict visual axis-type isolation, and post-query intent auditing.
  Triggers: "hunt for beaconing with jitter", "inline C2 timing regularity", "calculate MAD on DNS",
  "Tukey fence anomaly", "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "poisson burst clustering", "fano factor password spray", "rare admin tool surge",
  "bayesian gamma prior updating", "beta-binomial failure rate shrinkage", "dual-baseline delta-z",
  "patch tuesday immunity", "multi-sector threat fusion", "4-stage killchain hunter",
  "service account out of normal behavioral scope", "unexpected host origin or abnormal access patterns",
  "unusual data repository access", "service account origin rarity", "source code repository anomaly".
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

This skill empowers an LLM agent and SOC analyst to execute **ad-hoc multi-stage statistical outlier hunting** in Google SecOps over raw UDM telemetry without requiring pre-computed machine-learning pipelines or UEBA batch metrics.

> [!CAUTION]
> ### 🛑 STRICT UEBA EXCLUSION
> This skill is **STRICTLY for ad-hoc math over raw UDM telemetry** (`UDM_EVENTS`).
> **NEVER USE THIS SKILL IF THE ANALYST ASKS FOR:**
> 1. 30-Day pre-computed behavioral baselines (`window: 30d`)
> 2. Team, cohort, or peer-group comparisons from Risk Analytics
> 3. 360° entity health checks or omnibus risk scoring (`graph.risk_score`)
> 4. UEBA or Risk Analytics pre-computed metrics (`metrics.*`)
> 5. Cloud-native data repository baselines (GCS, BigQuery, S3) with pre-computed origin IP baselines (`metrics.resource_read_*`, `principal.ip`).
> 👉 **Route ALL baseline, peer, and UEBA requests to `secops-risk-metrics-multistage` (enforcing Zero-Code Handoff Invariant).**

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

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Zero Execution on Turn 1) (MANDATORY STEP 1: PRE-FLIGHT CLEARANCE)

Whenever the analyst initiates a threat hunt or selects an archetype, **THE AGENT MUST NEVER CALL SEARCH TOOLS ON THAT TURN**.
1. **ZERO Tool Calls**: Execute 0 tool calls to `udm_search`.
2. **Plain-English Operational Analogy**: Explain the detection mechanics in 1-2 down-to-earth sentences.
3. **Structured Pre-Flight Hunting Specification Card**: Present hunting objective, telemetry scope, search horizon, model, and threshold.
4. **Mandatory Upfront Query Preview Protocol**: Execute 1-shot pre-preview compiler probe with ISO 8601 timestamps: `secops-gus:udm_search(query="<query>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. Display query in markdown ONLY if probe compiles cleanly (200 OK). Emitting ```yara without an immediate preceding successful probe is STRICTLY PROHIBITED.
5. **Explicit Clearance Question & Turn Termination**: Ask for analyst approval to proceed, and **STOP calling tools immediately and yield the turn**.

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
*(Passive UDM filter for manual copy-paste into Chronicle SIEM search bar. NOT for automated tool execution; multi-turn follow-ups must remain within the statistical hunting framework.)*
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

* **Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)**: When analyst asks to *"run same for user X"*, *"what about admin?"*, or shifts entities, RETAIN SESSION AFFINITY and re-enter State 1 for the new entity (operational analogy ──► compiler probe ──► spec card ──► clearance question). NEVER fall through to unconstrained search skills (`secops-siem-search`) or execute Pillar 5 string.
* **Federated Bridge to Macro Analysis**: When analyst requests 30-day pre-computed baselines, peer cohort comparisons, longitudinal CUSUM drift, or 360° health checks, emit Skill Handoff Card steering to `secops-risk-metrics-multistage` (enforcing Zero-Code Handoff Invariant).
* **Bilateral Cooperative Framework**: Consult `references/statistical-hunting-cooperative-framework.md` for macro vs. micro division of labor and mutual delegation protocols.

---

## 🎨 Strict Visual Axis-Type Isolation Rules

When generating Vega-Lite or Chart.js charts:
* **Left Y-Axis**: Strictly numeric event volume (`quantitative` / `linear`).
* **Right Y-Axis ($y_1$)**: Strictly statistical anomaly score ($Z, \sigma, Fano$).
* **X-Axis**: Strictly timestamps (`temporal`) or categories (`nominal`).
* **Rule**: NEVER place string identifiers (`host`, `user`, `extension_id`) on a Y-axis.

---

## 🔍 Post-Query Intent & Architecture Verification

Before finalizing execution, verify that the executed query matches the promised architecture:
```bash
python3 scripts/multistage_query_builder.py \
  --query_file hunt_query.yara \
  --audit_intent DUAL_BASELINE_3STAGE \
  --audit_model DELTA_Z
```

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 0. THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)
* **Invariant 1: Zero Data Simulation (NEVER Fabricate Data)**: All numbers, baselines, event counts, and entity names MUST come from executed Chronicle SIEM API responses (`secops-gus:udm_search`). If `{}` or empty, report `0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`. Truth Over Completion — reporting 0 matches is a 100% successful hunt. Fabricating data is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Invariant 2: Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)**: All queries MUST use valid UDM schemas and compilable YARA-L grammar (e.g. ISO 8601 timestamps, no bare scalar if in stage outcomes, valid outcome arithmetic). Inventing fake UDM fields or uncompilable syntax is **STRICTLY PROHIBITED**. Emitting ```yara without an immediate preceding successful compiler probe is strictly forbidden.


### 1. Native Execution & Truth in Reporting
* **Zero Generative Simulation & Strict Data Grounding Contract**: Numbers ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) MUST be extracted from `secops-gus:udm_search`. If `{}` or empty, report `0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`. Fabricating numbers is a **CRITICAL TRUTH-IN-REPORTING FAILURE**.
* **Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)**: If an API query fails, STOP IMMEDIATELY and report the error to the analyst. Writing local scratch Python scripts to simulate baselines or query results is **STRICTLY PROHIBITED**.
* **Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)**: Statistical anomaly detection MUST run natively inside Google SecOps Chronicle SIEM via `secops-gus:udm_search`. Simulating baselines locally in Python is a **CRITICAL COMPLIANCE VIOLATION**.
* **Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)**: Section 2 of the triage report MUST contain the exact literal multi-stage YARA-L query string passed into `secops-gus:udm_search(query=...)`.
* **Post-Flight Audit & RAW_LOG_DUMP_DETECTED Rule**: If `udm_search` returns `"events"` without `"stats"`, or unaggregated raw logs, abort 5-Section triage formatting immediately. Disguising raw log dumps as baselines is **STRICTLY PROHIBITED**. Present the auto-corrected query (via `MultiStageTemplateRouter`) or trigger consultative pivot and ask for clearance to re-run.
* **Strict Nomenclature Mandate (Query vs. Rule)**: Ad-hoc hunt logic is a Query (`stage ... { ... }` + Root stage), never a Rule. Outputting streaming detection rule syntax (`rule ... { ... }`) or calling a search query a 'Rule' is a **CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION**.

### 2. Calibrated Risk Index (CRI [0–100]) Standard
* **CRI Normalization**: The Calibrated Risk Index maps raw statistical deviations ($Z$-scores, $\text{MAD } Z$, Poisson deviance, $\text{CV}$) onto a standardized [0–100] S-Curve:
  $$\text{CRI}(Z) = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right)$$
* **Anchoring Invariant**: Strictly anchors the 3-Sigma alertable boundary ($Z = 3.0\sigma$) at exactly $\text{CRI} = 50$.
* **Zero In-Query CRI Calculation**: CRI is calculated exclusively in post-processing presentation scripts (`scripts/multistage_query_builder.py`), NEVER inside YARA-L database queries.

### 3. Clean Hand-Off (CH) Protocol (Synthetic UDM Event Ingestion vs. Active Case Wall)
* **Path A (Mandatory Default — Synthetic Event Ingestion)**: When an analyst requests escalation (*"Escalate to SecOps"*, *"Log in Chronicle"*), generate a synthetic UDM event (`product_name: "SecOps Statistical Hunter"`) encapsulating the 6 Evidence Pillars and ingest via `import_logs` for catch-all rule case promotion.
* **Path B (Carved-Out Active Case Exception)**: ONLY when the analyst is actively reviewing a specific case and explicitly instructs the agent to attach findings to that case (e.g. *"Attach to Case 11075"*), call `create_case_comment(case_id="...", comment=...)`.
* **Anti-Case-Comment Pollution Prohibition**: Calling `create_case_comment` or `list_cases` to attach hunt summaries to arbitrary open cases without an explicit `case_id` is **STRICTLY PROHIBITED**.
* **Zero-Code Handoff Invariant (Cross-Skill Steering Protocol)**: Under NO circumstances may an agent emit candidate ````yara query blocks inside or alongside a Skill Handoff Card or when steering between skills (e.g. to `secops-risk-metrics-multistage`). Handoff cards are strictly conceptual/architectural; code emission belongs exclusively to the destination skill once invoked. Emitting unvalidated code during handoff violates the Tool-Precondition Code Block Embargo.

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
