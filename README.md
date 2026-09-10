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
├── SKILL.md                                 # Main skill specification, routing & execution contracts
├── README.md                                # Overview & architecture reference
├── RELEASE_NOTES.md                         # Detailed version changelog & feature notes
├── LICENSE                                  # Apache 2.0 open-source license
├── llms.txt                                 # Token-efficient AI agent summary file
├── templates/pipelines/                     # Golden YARA-L 2.0 multi-stage DAG templates (11)
│   ├── privileged_lateral_expansion_2stage.yl2 # Privileged lateral movement & destination expansion
│   ├── hybrid_entropy_concentration_2stage.yl2 # Diversity Deficit & Elephant Flow Concentration
│   ├── c2_beaconing_jitter_2stage.yl2       # C2 beaconing timing jitter & interval regularity (CV)
│   ├── poisson_burst_clustering_2stage.yl2  # Poisson Burst Clustering & Fano Factor (password spray)
│   ├── poisson_rare_surge_2stage.yl2        # Discrete Poisson Rarity & Two-Part Hurdle
│   ├── multi_sector_threat_fusion_4stage.yl2 # Orthogonal Threat Space & Euclidean Distance
│   ├── bayesian_gamma_shrinkage_4stage.yl2  # Poisson-Gamma Bayesian Credibility Shrinkage
│   ├── beta_binomial_failure_4stage.yl2     # Beta-Binomial Failure Rate Shrinkage
│   ├── dual_baseline_delta_z_3stage.yl2     # Dual-Baseline Delta-Z & Fleet Prevalence Normalization
│   ├── mad_exfiltration_2stage.yl2          # Median Absolute Deviation (MAD) & Non-Parametric IQR
│   └── zscore_process_surge_2stage.yl2      # Parametric Z-Score process surges per host
├── examples/                                # Working standalone YARA-L search templates (12)
│   ├── bayesian_gamma_shrinkage.yara        # Poisson-Gamma Bayesian Credibility Shrinkage
│   ├── beta_binomial_failure_regularization.yara # Beta-Binomial failure rate regularization
│   ├── c2_beaconing_jitter_cv.yara          # Inter-arrival CV + low-prevalence filter
│   ├── dual_baseline_delta_z.yara           # Dual-Baseline Delta-Z (Patch Tuesday Shield)
│   ├── fleet_zscore_process_outliers.yara   # Fleet-wide peer Z-Score process surges
│   ├── iqr_tukey_fences_egress.yara         # Non-parametric IQR / Tukey Fences for egress bytes
│   ├── mad_outlier_detection.yara           # Median Absolute Deviation (MAD / Modified Z-Score)
│   ├── multi_sector_threat_fusion.yara      # 4-Stage Multi-Sector Fusion (Auth + Endpoint + Net)
│   ├── poisson_burst_clustering.yara        # Fano Factor (σ² / μ > 4.0) password spray cluster detector
│   ├── poisson_rare_event_surge.yara        # Discrete Poisson score for sensitive administrative binaries
│   ├── rolling_ratio_spike.yara             # 1-day vs 7-day vs 30-day moving ratio
│   └── zscore_process_execution_surges.yara # Historical 3-Sigma Z-Score process surges per host
├── references/                              # Deep-dive engineering guides (8)
│   ├── chart-specifications-guide.md        # Vega-Lite and Chart.js dual-Y visualization schemas
│   ├── cyber-practitioner-glossary.md       # Field manual translating statistics to SOC operations
│   ├── dynamic-windowing-matrix.md          # Adaptive window bucketing & sample floor matrix
│   ├── multi-stage-query-guide.md           # 4-Stage DAG grammar rules & compiler invariants
│   ├── query-auditing-guide.md              # Pre-flight and post-flight payload intent auditing
│   ├── scope-exclusions-guardrail.md        # Why UEBA metrics.* are excluded from ad-hoc searches
│   ├── statistical-models-taxonomy.md       # Mathematical curves, Poisson dispersion, & 4D plots
│   └── watchdog-polling-architecture.md     # LRO watchdog mechanics & F1 optimization
├── scripts/
│   └── multistage_query_builder.py          # Python linter, AST validator, & report/chart generator
└── tests/                                   # Automated test suite (85 tests, 100% pass rate)
    ├── __init__.py
    ├── test_compiler_grammar.py             # AST grammar, 1-3 stage limit, 20-var limit, and syntax trap tests
    ├── test_global_context_syntax.py        # Entity Context Graph (GLOBAL_CONTEXT/DERIVED_CONTEXT) syntax tests
    ├── test_guardrail_contracts.py          # Golden pipeline validation, session lock, and guardrail contracts
    ├── test_handoff_endpoint.py             # Federated handoff ingestion and protocol ACK tests
    ├── test_math_models.py                  # Bayesian, Beta-Binomial, Fano, and norm unit tests
    ├── test_query_auditor.py                # Post-flight intent and raw log dump detection tests
    ├── test_triage_reporting.py             # CommonMark 5-section triage schema tests
    └── test_window_adaptation.py            # Dynamic windowing and sample floor adaptation tests
```

---

## Release Notes

### v2.4.2 (September 9, 2026)
* **Entity Context Graph (GLOBAL_CONTEXT & DERIVED_CONTEXT)**: Added `references/entity-context-graph-guide.md` and two 3-stage golden templates (`global_threat_intel_enrichment_3stage.yl2` for GCTI/WHOIS NRD network correlation, and `derived_context_prevalence_3stage.yl2` for new asset authentication anomalies).
* **Stage Allowance Limit Enforcement**: Strictly codified and enforced 1 to 3 named intermediate stages plus 1 root stage ceiling in `references/multi-stage-query-guide.md` and `scripts/multistage_query_builder.py`.
* **Consultative Intent Catalog**: Added *"The Flash in the Dark"* and *"The Unfamiliar Machine"* operational analogies and intent routing in `SKILL.md`.
* **Portfolio & Regression Suite Expansion**: Expanded golden pipeline templates to 14 and regression test suite to 85 tests (100% pass rate).

### v2.4.1 (September 9, 2026)
* **Privileged Account Lateral Movement & Destination Expansion**: Added `templates/pipelines/privileged_lateral_expansion_2stage.yl2` measuring daily unique destination host footprint across a bounded lookback window (e.g. 90d) on raw `USER_LOGIN` events with AD privilege filtering.
* **Safe Zero-Divisor Hardening**: Hardened arithmetic divisions across all golden templates with positive divisor gating (`if($sd > 0, $sd, 1.0)`).
* **Two-Part Hurdle Model Pipeline**: Added `templates/pipelines/two_part_hurdle_2stage.yl2`.
* **Federated Protocol & Intent Routing**: Registered `PRIVILEGED_LATERAL_EXPANSION` in `HandoffEndpoint` and `MultiStageTemplateRouter` for seamless bilateral delegation from `secops-risk-metrics-multistage`.
* **Portfolio Expansion**: Expanded golden pipeline templates to 12 (77/77 unit tests passing).

### v2.4.0 (September 7, 2026)
* **Dynamic Root-Stage Condition Filtering**: Enabled root-stage condition filtering and noise level steering in `MultiStageTemplateRouter`.
* **Anti-Degradation Auditing**: Upgraded `PostFlightExecutionAuditor` to detect stage degradation and enforce user narrative concordance.
* **6 Hybrid Mathematical Models**: Diversity Deficit, Elephant Flow Concentration, Orthogonal Threat Space, Bayesian Joint Odds, Two-Part Hurdle, and Fleet Prevalence Normalization.

### v2.3.3 (September 5, 2026)
* **Dual-Plane & Telemetry Enrichment Routing**: Added bilateral federated routing for `RAW_TELEMETRY_ENRICHMENT` and `DUAL_PLANE_CORRELATION` to micro telemetry spike models.
* **Framework Synchronization**: Synchronized Section 7 (Two-Phase Federated Funnel) with `secops-risk-metrics-multistage`.

### v2.3.2 (September 5, 2026)
* **Federated Threat Hunt Ingestion Endpoint**: Implemented `--ingest_handoff` supporting `secops-threat-hunt-handoff-v1` protocol.
* **Dynamic Intent Routing Engine**: Added `INTENT_ROUTING_MAP` across 6 core statistical threat archetypes.
* **Mutual ACK & Step-Out Contract**: Standardized `HANDOFF_ACK_ACCEPTED` and `STEP_OUT_CONFIRMED` contracts.

### v2.3.1 (September 5, 2026)
* **Bilateral Cooperative Threat Hunting Architecture**: Codified micro-analysis (raw telemetry) vs macro-analysis (30-day UEBA) boundary.
* **Dual Grounding Invariants**: Enforced Zero Data Simulation ("Truth Over Completion") and Zero Schema/Syntax Fantasy.
* **Intermediate AST Hardening**: Prohibited bare scalar `if()` in intermediate stage outcomes; regularized C2 jitter division floor.

### v2.3.0 (September 3, 2026)
* **Common Compiler AST Invariants**: Codified syntax traps (`$stage.var`, no outcome `sqrt()`, no `rule` wrapper, no event arithmetic).
* **Calibrated Risk Index (CRI [0–100])**: Standardized logistic sigmoid normalization anchoring $3.0\sigma$ at CRI 50.
* **Data Reduction Engine & Auto-Remediation**: Truncates large payloads to top $N$ anomalies; auto-detects `RAW_LOG_DUMP_DETECTED`.

### v2.2.1 (September 1, 2026)
* **Dual Multi-Stage Taxonomy Disambiguation**: Formalized operational boundary between ad-hoc raw DAGs (`UDM_EVENTS`) and pre-computed 30-day metric tables.

### v2.2.0 (September 1, 2026)
* **AST Pre-Flight Guards & Post-Flight Auditing**: Added pre-flight traps for `^`, `in ("A", "B")`, `by 1d`, and multi-vector cramming.

### v2.1.0 (August 26, 2026)
* **Progressive Disclosure Architecture**: Streamlined `SKILL.md` to core routing and modularized references.
* **Post-Query Intent & Architecture Auditor**: Added automated AST verification against stage degradation.
* **Advanced Raw Telemetry Hunting Models**: Added Bayesian Gamma Shrinkage, Beta-Binomial Regularizer, and Delta-Z.

### v2.0.1 (August 24, 2026)
* **Clarified Reporting & Chart Axis Isolation**: Enforced strict axis type isolation and 5-section reporting for non-CLI clients.

### v2.0.0 (August 24, 2026)
* **Four-Stage DAG Pipeline Architecture**: Formalized support for up to 4 intermediate stages plus root stage with 20-variable limit.
* **6 Standardized Forensic Evidence Pillars**: Guaranteed observation count, active density, central tendency, dispersion, prevalence, and cardinality.
* **Dynamic Time-Window Protocol**: Adaptive granularity matrix (`by 10m`, `by 1h`, `by 1d`) with proportional sample floor.

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*

