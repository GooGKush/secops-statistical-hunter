---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.1.0
description: |
  Guides and executes multi-stage statistical anomaly detection, Bayesian credibility updating,
  and outlier hunting in Google Security Operations (SecOps) over raw UDM telemetry across custom time slices.
  Supports Z-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Median Absolute Deviation (MAD),
  Coefficient of Variation (CV), Poisson-Gamma Bayesian Shrinkage, Beta-Binomial Ratio Regularization,
  Dual-Baseline Delta-Z (Patch Tuesday Shield), and Multi-Sector Threat Fusion.
  Enforces strict 5-Section CommonMark Triage Reporting (with 6 standardized forensic evidence pillars,
  Unicode visual bars, and 1-click drilldowns), strict visual axis-type isolation, and post-query intent auditing.
  Triggers: "hunt for beaconing with jitter", "inline C2 timing regularity", "calculate MAD on DNS",
  "Tukey fence anomaly", "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "poisson burst clustering", "fano factor password spray", "rare admin tool surge",
  "bayesian gamma prior updating", "beta-binomial failure rate shrinkage", "dual-baseline delta-z",
  "patch tuesday immunity", "multi-sector threat fusion", "4-stage killchain hunter".
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
> 👉 **Route ALL baseline, peer, and UEBA requests to `secops-risk-metrics-multistage`.**

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

---

## 🚦 MANDATORY STEP 1: PRE-FLIGHT CLEARANCE & HARD TURN BOUNDARY

Whenever the analyst initiates a threat hunt or selects an archetype, **THE AGENT MUST NEVER CALL SEARCH TOOLS ON THAT TURN**.
1. **ZERO Tool Calls**: Execute 0 tool calls to `udm_search`.
2. **Plain-English Operational Analogy**: Explain the detection mechanics in 1-2 down-to-earth sentences.
3. **Structured Pre-Flight Hunting Specification Card**: Present hunting objective, telemetry scope, search horizon, model, and threshold.
4. **Explicit Clearance Question & Turn Termination**: Ask for analyst approval to proceed, and **STOP calling tools**.

---

## 📋 MANDATORY OUTPUT CONTRACT: 5-SECTION TRIAGE REPORTING SCHEMA

When formatting hunting results for ANY client (CLI, Chat UI, or Web UI), the agent **MUST ALWAYS OUTPUT ALL 5 SECTIONS** in exact order:

```markdown
### ⚡ Statistical Outlier Report: [Hunt Topic]
* **Outliers Detected**: [N entities] exceeded the anomaly threshold.
* **Normal Baseline Envelope**: Typical Average ($\mu$) $\approx X$ | Typical Variation ($\sigma$) $\approx \pm Y$
* **Fleet Scaling**: Threshold adjusted to $Z_{\text{adj}} \approx Z\sigma$ for fleet size $N$.

---
#### 📊 Ranked Outlier Summary
| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Visual Magnitude |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `host-alpha` | 2026-08-24T08:00 | **850** | 250 ± 35 | 🟢 **HIGH CONFIDENCE** | 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | `██████████` |

---
#### 🔍 Top Outlier Spotlight: `host-alpha` — 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`)
* **Data Confidence Level**: 🟢 **HIGH CONFIDENCE** — Strong sample density ($N \ge 30$).
##### 🗣️ What Happened & Why It Matters (In Plain English)
[Plain-English executive explanation]
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
#### 🎯 Immediate Drill-Down Investigation Query
```yara
principal.hostname = "host-alpha" AND metadata.event_type = "PROCESS_LAUNCH"
```

---
<details>
<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>

##### 📐 Mathematical Model & Formulaic Derivations
* **Model**: $Z = \frac{x - \mu}{\sigma} = \frac{850 - 250.0}{35.0} = +17.14\sigma$
##### 🌐 Multiple-Comparison Fleet Correction ($Z_{\text{adj}} \approx \sqrt{2 \ln N}$)
##### 🛡️ Statistical Validity & Safeguard Verification
</details>
```

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

## 📚 Specialized Deep-Dive Reference Guides

* **Mathematical Models & Formulations**: See [references/statistical-models-taxonomy.md](references/statistical-models-taxonomy.md)
* **Multi-Stage Query Grammar & Compiler Invariants**: See [references/multi-stage-query-guide.md](references/multi-stage-query-guide.md)
* **Dynamic Time-Window Adaptation Matrix**: See [references/dynamic-windowing-matrix.md](references/dynamic-windowing-matrix.md)
* **Chart Specs (Vega-Lite & Chart.js)**: See [references/chart-specifications-guide.md](references/chart-specifications-guide.md)
* **Query Auditing & Intent Verification**: See [references/query-auditing-guide.md](references/query-auditing-guide.md)
* **Cyber Glossary & SOC Playbooks**: See [references/cyber-practitioner-glossary.md](references/cyber-practitioner-glossary.md)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
