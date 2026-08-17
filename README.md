# Google SecOps Statistical Outlier Hunter (`secops-statistical-hunter`)

A specialized agentic skill for Google Security Operations (SecOps / Chronicle SIEM) that provides **Consultative Threat Hunting, Mathematical Modeling, and Multi-Stage YARA-L Query Execution** over raw telemetry and alert detections.

---

## What is this Skill?

Unlike traditional detection engineering rules or scheduled UEBA batch metrics, `secops-statistical-hunter` leverages Chronicle's inline analytical engine (`window.*`, `math.*`, `arrays.*`, `strings.*`, `timestamp.*`) to run **ad-hoc time-window statistical searches**.

It translates high-level analyst hunting hypotheses (e.g., *"find low-prevalence C2 beaconing with random timing jitter"*, or *"find anomalous outbound byte surges above personal median"*) into pre-validated, multi-stage YARA-L search pipelines.

---

## Core Capabilities

1. **Consultative Threat-to-Math Routing**:
   * Interprets analyst goals into explicit statistical archetypes (`C2_BEACONING_JITTER`, `DATA_EXFILTRATION_SPIKE`, `HEAVY_TAIL_OUTLIERS`, `VELOCITY_SURGE_RATIO`, `LATERAL_RECON_DISPERSION`, `IMPOSSIBLE_TRAVEL_SPEED`).
2. **Human-Readable Sensitivity Tiers & Boundary Guidance**:
   * Translates abstract math floats ($\text{CV} \le 0.15$, $M_Z > 2.5$) into operational tiers (`CONSERVATIVE`, `BALANCED`, `AGGRESSIVE`, `NOISE CLIFF`).
   * Includes a **Pre-Flight 24-Hour Decile Probe** mode to show analysts empirical score distributions on their actual telemetry before running 30-day queries.
3. **Strict Scope Exclusions Guardrail**:
   * Actively rejects and strips **UEBA Metric Functions (`metrics.*`)** and **Entity Risk Scores (`graph.risk_score`)**, ensuring ad-hoc time slices (`start_time` / `end_time`) execute cleanly without compilation errors.
4. **Asynchronous LRO Polling Watchdog (`schedule` Wakeup Pattern)**:
   * Uses non-blocking background timers via Jetski's `schedule` tool (`get_operation`).
   * Diagnoses frozen progress (`events_searched`) and quota starvation, offering prescriptive query refactoring tips (window splitting, regex indexing).

---

## Directory Organization

```
secops-statistical-hunter/
├── SKILL.md                          # Main skill specification & decision matrix
├── README.md                         # Overview & architecture reference
├── llms.txt                          # AI agent summary file
├── examples/                         # Working multi-stage YARA-L search templates
│   ├── c2_beaconing_jitter_cv.yara   # Inter-arrival CV + low-prevalence filter
│   ├── mad_outlier_detection.yara    # Median Absolute Deviation (MAD / Modified Z-Score)
│   ├── iqr_tukey_fences_egress.yara  # Non-parametric IQR / Tukey Fences for egress bytes
│   └── rolling_ratio_spike.yara      # 1-day vs 7-day vs 30-day moving ratio
├── references/                       # Deep-dive engineering guides
│   ├── statistical-models-taxonomy.md# Mathematical curves & physical translations
│   ├── watchdog-polling-architecture.md # LRO watchdog mechanics & F1 optimization
│   └── scope-exclusions-guardrail.md # Why UEBA metrics.* are excluded from ad-hoc searches
└── scripts/
    └── multistage_query_builder.py   # Python linter, parameter injector, & boundary validator
```

---

## Comparison with Sibling Skills

| Feature / Domain | `secops-statistical-hunter` (This Skill) | `secops-risk-analytics` |
| :--- | :--- | :--- |
| **Primary Data Source** | `UDM_EVENTS` (Raw telemetry), `RULE_DETECTIONS` | `UEBA_EVENTS`, Entity Risk Graph |
| **Execution Window** | **Arbitrary ad-hoc time slices** (e.g. 14 days, exact start/end) | **Fixed batch windows** (Pre-computed 24h/1h scheduled profiles) |
| **Functions Used** | Inline dynamic math (`window.median`, `percentile`, `CV`, `Fano`) | Curated machine-learning anomaly baselines (`metrics.*`) |
| **Analyst Persona** | Active Threat Hunter building custom hypothesis queries | Alert Responder reviewing pre-scored user/asset risk posture |
