# Google SecOps Statistical Outlier Hunter (`secops-statistical-hunter`)

A specialized agentic skill for Google Security Operations (SecOps / Chronicle SIEM) that provides **Consultative Threat Hunting, Mathematical Modeling, and Multi-Stage YARA-L Query Execution** over raw telemetry and alert detections.

---

## What is this Skill?

Unlike traditional detection engineering rules or scheduled UEBA batch metrics, `secops-statistical-hunter` leverages Chronicle's inline analytical engine (`window.*`, `math.*`, `arrays.*`, `strings.*`, `timestamp.*`) to run **ad-hoc time-window statistical searches**.

It translates high-level analyst hunting hypotheses (e.g., *"find low-prevalence C2 beaconing with random timing jitter"*, *"find password sprays that pulse in waves"*, or *"find rare admin tools running on quiet servers"*) into pre-validated, multi-stage YARA-L search pipelines.

---

## Core Capabilities

1. **Non-Statistician Consultative Routing & Intent Catalog**:
   * Translates operational security questions into optimal statistical models (`POISSON_BURST_CLUSTERING`, `POISSON_RARE_SURGE`, `ZSCORE_PROCESS_SURGE`, `C2_BEACONING_JITTER`, `DATA_EXFILTRATION_SPIKE`, `HEAVY_TAIL_OUTLIERS`, `VELOCITY_SURGE_RATIO`, `LATERAL_RECON_DISPERSION`, `IMPOSSIBLE_TRAVEL_SPEED`).
2. **Cyber-First 4-Tier Structured Triage Reports**:
   * Renders executive anomaly verdicts, ranked outlier tables with Unicode visual magnitude bars (`█████`), and standard SOC severity badges (🚨 `[CRITICAL OUTLIER]`, ⚠️ `[HIGH SUSPICION]`, 🟡 `[ELEVATED WATCH]`).
   * Appends **Threat Translation Cards**, **Common False Positive Reality Checks** (e.g. MSBuild, SCCM, NTP), and **3-step SOC Triage Playbooks** directly beneath hunt results.
3. **Multi-Dimensional Threat Visualizations**:
   * Generates client-agnostic Vega-Lite and Chart.js JSON specifications for **4D Threat Bubble Plots** (Volume $\times$ Timing $\times$ Cardinality $\times$ Severity), **3D Temporal Density Heatmaps**, and **Control Chart Tolerance Bands**.
4. **Strict Scope Exclusions Guardrail**:
   * Actively rejects and strips **UEBA Metric Functions (`metrics.*`)** and **Entity Risk Scores (`graph.risk_score`)**, ensuring ad-hoc time slices (`start_time` / `end_time`) execute cleanly without compilation errors.
5. **Asynchronous LRO Polling Watchdog (`schedule` Wakeup Pattern)**:
   * Uses non-blocking background timers via Jetski's `schedule` tool (`get_operation`).
   * Diagnoses frozen progress (`events_searched`) and quota starvation, offering prescriptive query refactoring tips.

---

## Directory Organization

```
secops-statistical-hunter/
├── SKILL.md                              # Main skill specification & decision matrix
├── README.md                             # Overview & architecture reference
├── llms.txt                              # AI agent summary file
├── examples/                             # Working multi-stage YARA-L search templates
│   ├── zscore_process_execution_surges.yara # Historical 3-Sigma Z-Score process surges per host
│   ├── poisson_burst_clustering.yara     # Fano Factor (σ² / μ > 4.0) password spray cluster detector
│   ├── poisson_rare_event_surge.yara     # Discrete Poisson score for sensitive administrative binaries
│   ├── c2_beaconing_jitter_cv.yara       # Inter-arrival CV + low-prevalence filter
│   ├── mad_outlier_detection.yara        # Median Absolute Deviation (MAD / Modified Z-Score)
│   ├── iqr_tukey_fences_egress.yara      # Non-parametric IQR / Tukey Fences for egress bytes
│   └── rolling_ratio_spike.yara          # 1-day vs 7-day vs 30-day moving ratio
├── references/                           # Deep-dive engineering guides
│   ├── cyber-practitioner-glossary.md    # Field manual translating statistics to SOC operations
│   ├── statistical-models-taxonomy.md    # Mathematical curves, Poisson dispersion, & 4D plots
│   ├── watchdog-polling-architecture.md  # LRO watchdog mechanics & F1 optimization
│   └── scope-exclusions-guardrail.md     # Why UEBA metrics.* are excluded from ad-hoc searches
└── scripts/
    └── multistage_query_builder.py       # Python linter, 4-tier triage report formatter, & 4D chart generator
```

---

## Release Notes

### v2.1.0 (Minor Point Revision)
* **Strict UEBA Exclusion Guardrail**: Added prominent top-level routing guardrails (`🛑 STRICT UEBA EXCLUSION`) directing all 30-day pre-computed behavioral baselines, peer group comparisons, 360° health checks, and longitudinal CUSUM drift to `secops-risk-metrics-multistage`.
* **Trigger Specialization & De-Duplication**: Refined skill triggers to explicitly anchor on raw telemetry ad-hoc inline statistical models (C2 beaconing jitter CV, Poisson burst clustering, Tukey fences, MAD on raw egress, Haversine impossible travel) to prevent skill collisions with UEBA.
* **Separation of Concerns**: Clarified that `secops-statistical-hunter` is strictly for ad-hoc inline math over raw UDM telemetry across custom time slices and does not stand in for 30-day UEBA baselines.

### v2.0.1
* Clarified reporting constraints and chart axis isolation for non-CLI clients.

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*

