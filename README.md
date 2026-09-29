# Google SecOps Statistical Outlier Hunter (`secops-statistical-hunter`)

[![Version](https://img.shields.io/badge/version-v2.7.2-blue.svg)](RELEASE_NOTES.md) [![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE) [![Unit Tests](https://img.shields.io/badge/unit%20tests-136%2F136%20passing%20(100%25)-brightgreen.svg)](tests/) [![Dual Platform Regression](https://img.shields.io/badge/dual--engine%20regression-20%2F21%20passing%20(95.2%25)-brightgreen.svg)](RELEASE_NOTES.md)

A specialized agentic skill package for **Google Security Operations (SecOps / Chronicle SIEM & SOAR)** that provides **Consultative Threat Hunting, Mathematical Modeling, and Multi-Stage YARA-L 2.0 Query Execution** over raw in-flight UDM event telemetry.

---

## 🧭 What is this Skill?

Unlike traditional detection engineering rules or scheduled UEBA batch metrics, `secops-statistical-hunter` leverages Chronicle's inline analytical engine (`window.*`, `math.*`, `arrays.*`, `strings.*`, `timestamp.*`) to run **ad-hoc time-window statistical searches over raw in-flight event telemetry** (`UDM_EVENTS`).

It translates high-level analyst hunting hypotheses (e.g., *"find low-prevalence C2 beaconing with random timing jitter"*, *"find password sprays that pulse in waves"*, or *"find rare admin tools running on quiet servers"*) into pre-validated, multi-stage YARA-L search pipelines with zero reliance on external batch computation.

---

## 🌟 Core Capabilities

1. **Option A Affirmative Native-Chat Runtime**:
   * Operates hermetically inside conversational chat sessions using native Google SecOps MCP tools (`udm_search`, `import_logs`, `create_case_comment`) and Markdown exclusively.
   * Python helper scripts (`scripts/`) are reserved strictly for offline CI and developer unit testing (`pytest tests/`).
2. **The 3-State Active Threat Hunt Lifecycle**:
   * **State 1 (Pre-Flight Clearance & Specification)**: Universal entry gate for all inquiries. Verifies schema via a 1-shot compiler probe (`maxEvents=1`, 10-minute window), renders the structured Pre-Flight Specification Card, displays the candidate multi-stage YARA-L query preview with 6 mandatory root outcome variables, and solicits analyst clearance (Mode A vs Mode B).
   * **State 2 (Deterministic Multi-Stage Execution & 5-Section Triage)**: Immediately executes the full multi-stage query via `udm_search(query=...)` upon receiving user clearance, and synthesizes aggregated `stats` evidence into the mandatory 5-Section CommonMark Triage Report.
   * **State 3 (Dynamic Follow-Up & SOC Action Execution)**: Executes authorized post-hunt workflows including Clean Hand-Off synthetic UDM alert generation (`import_logs`), case wall attachment (`create_case_comment`), or client-agnostic visualization schemas.
3. **Turn 2 Execution Mandate & Nominal Baseline Reporting**:
   * Receiving analyst clearance unconditionally authorizes immediate execution of the full multi-stage query via `udm_search`, eliminating secondary clarification stalls.
   * Quiet entities or zero-observation sweeps evaluate natively in Chronicle SIEM and are reported affirmatively as nominal baselines ($Z = 0.00\sigma, \text{CRI} = 0$) under the **Zero-Telemetry Clean Hunt Exemption**.
4. **6 Mandatory Root Outcome Variables & Forensic Evidence Pillars**:
   * Guarantees 6 standardized root outcome columns across all multi-stage pipelines: `$observation_count`, `$baseline_active_samples`, `$baseline_mean`, `$baseline_dispersion`, `$fleet_prevalence`, and `$distinct_binaries` (aliasing distinct programs, IPs, or targets).
   * Maps directly to the 6 Forensic Evidence Pillars in Section 3 of the triage report: `1. Activity Spike`, `2. Baseline History`, `3. Typical Normal Level`, `4. Normal Daily Spread`, `5. Company-Wide Breadth`, and `6. Variety of Programs`.
5. **Chronicle SIEM Compiler Grammar & Bare Identifier Match Binding**:
   * Formats all `match:` expressions with bare identifiers bound in stage event predicates (e.g. `$entity by 1h`, `$entity, $window_start by 1h`, `$entity by 1d`), completely eliminating match dot-notation syntax errors (`ZERO DOTS IN MATCH`).
   * Enforces Target Entity Scoping directly in primary stage predicates (`principal.hostname = "dev-ub22-1"`) to anchor baselines cleanly to the requested entity.
6. **Chronicle Malachite Function Factory Modernization & OIO Inlining**:
   * Leverages Chronicle Function Factory mathematical built-ins (`math.sqrt`, `math.log`, `math.exp`, `math.min`, `math.max`, `math.round`) for true Euclidean Threat Distance ($D = \sqrt{\sum Z_i^2}$) and Log-Normal volumetric transforms ($Z_{\log} = (\ln(B+1) - \mu_{\ln}) / \sigma_{\ln}$).
   * Employs **Outcomes-in-Outcomes (OIO)** in-stage inlining, allowing intermediate outcome variables to directly feed subsequent formulas within the same stage (e.g., `$diff = $obs - $avg`, `$z = $diff / $safe_sd`).
7. **Purged Dispersion Denominators & Safe Zero-Divisor Floor Guards**:
   * Replaced artificial `+ 1.0` additive dispersion denominators across all 14 golden templates with exact conditional guards (`$safe_sd = if($sd > 0, $sd, 1.0)` or `$safe_dispersion = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)`).
   * Eliminates statistical distortion in Fano factor, standard score, and Poisson dispersion ratios on quiet baselines without artificial variance blunting, while preserving legitimate Bayesian conjugate updates ($\beta_{\text{post}} = \beta_0 + 1.0$, $\ln(B+1)$).
8. **Timeline Optimization: The Daily Temporal Spine (`by 1d`)**:
   * Features adaptive window granularity that dynamically selects `by 1d` bucket sizes for macro-aligned models on horizons $\ge 7$ days, reducing intermediate row cardinality by $24\times$ ($336 \rightarrow 14$ rows per entity over 14 days) and providing 1:1 metric reconciliation with `secops-risk-metrics-multistage`.
   * Preserves high-frequency bins (`10m`, `15m`, `1h`) for intraday and jitter-sensitive models (`C2_BEACONING_JITTER`, `POISSON_BURST_CLUSTERING`).
9. **Strict Pre-Flight Routing Interceptor & Delegation Gate**:
   * Evaluates incoming requests against pre-computed baseline indicators (UEBA keywords, 30-day rolling baselines, `metrics.*`, peer cohorts, and omnibus risk scores), immediately emitting the Markdown Skill Delegation Card routing to `secops-risk-metrics-multistage` (0 tools called). Sub-second timing, rarity, and raw UDM outlier hunts remain inline under the Expert Bypass Rule.
   * Strictly adheres to the **Zero-Code Handoff Invariant**: handoff cards provide conceptual architectural guidance and parameters, leaving YARA-L code generation strictly to the destination skill.
10. **Entity Context Graph (ECG) & Enterprise-Grounded Novelty Enrichment**:
    * Correlates raw telemetry bursts with Chronicle's persistent Entity Context Graph: `GLOBAL_CONTEXT` (GCTI threat intelligence, WHOIS Newly Registered Domains) and `DERIVED_CONTEXT` (enterprise binary prevalence `FILE`, domain prevalence `DOMAIN_NAME`, entity prevalence `USER`, and asset first-seen/last-seen age `ASSET`).
    * Supports the Enterprise-Grounded Hunt consultative pattern: offers analysts Tier A (Pure Local Baseline) vs. Tier B (Enterprise-Grounded Hunt) with 2.5x threat score boost for rare/novel binaries or domains (`day_count <= 3`).
11. **6 Hybrid Mathematical Models**:
    * Implements Diversity Deficit, Elephant Flow Concentration, Orthogonal Threat Space, Bayesian Joint Odds, Two-Part Hurdle, and Fleet Prevalence Normalization directly over raw event streams.
12. **Calibrated Risk Index (CRI [0–100])**:
    * Standardizes multi-dimensional statistics onto a unified, logistic sigmoid 0–100 scale anchoring $3.0\sigma$ at CRI 50 across 4 operational severity tiers: 🟢 Nominal (0–29), 🟡 Elevated (30–49), 🟠 High (50–84), and 🔴 Critical (85–100).
13. **Standardized 5-Section CommonMark Triage Reporting**:
    * Generates structured forensic reports: 1. Executive Summary, 2. Calibrated Risk Index, 3. Forensic Evidence Pillars with visual ASCII bars (`████░░░░░░`), 4. Baseline Distribution Context, and 5. Actionable Next Steps & 1-Click Drill-Down Queries.
14. **Automated Clean Hand-Off Protocol**:
    * Generates schema-compliant synthetic UDM security analytics events (`CUSTOM_SECURITY_DATA_ANALYTICS`) under a unique `Hunt Campaign ID`, caught by tenant rule `secops_statistical_hunter_alert_catchall` for seamless alert escalation without case wall pollution.
15. **Advanced Information-Theoretic & Long-Tail Models**:
    * Expands analytical reach with Markov 2-Gram Transition Rarity (evaluating $- \ln P(B \mid A)$ conditional process surprisal), Shannon Character-Class Entropy (obfuscated scripts & DGA detection), Power-Law / Zipfian Long-Tail Process Rarity ($f(k) \propto 1/k^s$ asymptotic tail isolation), and Intraday EWMA Burst Velocity ($\alpha = 0.30$ kinetic rate acceleration), bringing the golden pipeline suite to 21 models.

---

## 🗺️ Directory Organization

```
secops-statistical-hunter/
├── SKILL.md                                 # Canonical skill specification, routing & execution lifecycle
├── README.md                                # Overview & architectural reference
├── RELEASE_NOTES.md                         # Detailed version changelog & release history
├── LICENSE                                  # Apache 2.0 open-source license
├── llms.txt                                 # Token-efficient AI agent summary file
├── templates/pipelines/                     # Golden YARA-L 2.0 multi-stage DAG templates (21)
│   ├── bayesian_gamma_shrinkage_4stage.yl2  # Poisson-Gamma Bayesian Credibility Shrinkage
│   ├── beta_binomial_failure_4stage.yl2     # Beta-Binomial Failure Rate Shrinkage
│   ├── c2_beaconing_jitter_2stage.yl2       # C2 beaconing timing jitter & interval regularity (CV)
│   ├── derived_context_domain_prevalence_3stage.yl2 # Derived Context domain egress enterprise prevalence
│   ├── derived_context_file_prevalence_3stage.yl2 # Derived Context binary SHA-256 enterprise prevalence
│   ├── derived_context_prevalence_3stage.yl2 # Derived Context enterprise user prevalence & asset age
│   ├── dual_baseline_delta_z_3stage.yl2     # Dual-Baseline Delta-Z & Fleet Prevalence Normalization
│   ├── ewma_burst_velocity_2stage.yl2       # Intraday EWMA burst rate velocity & kinetic acceleration
│   ├── global_threat_intel_enrichment_3stage.yl2 # GCTI Threat Intel & WHOIS NRD egress correlation
│   ├── hybrid_entropy_concentration_2stage.yl2 # Diversity Deficit & Elephant Flow Concentration
│   ├── log_normal_volume_surge_2stage.yl2   # Parametric Log-Normal Volumetric Standardization & Sigmoid CRI
│   ├── mad_exfiltration_2stage.yl2          # Median Absolute Deviation (MAD) & Non-Parametric IQR
│   ├── markov_2gram_transition_rarity_2stage.yl2 # Markov 2-Gram transition probability & information surprisal
│   ├── multi_sector_threat_fusion_4stage.yl2 # Orthogonal Threat Space & Euclidean Distance
│   ├── poisson_burst_clustering_2stage.yl2  # Poisson Burst Clustering & Fano Factor (password spray)
│   ├── poisson_rare_surge_2stage.yl2        # Discrete Poisson Rarity & Low-Volume Spikes
│   ├── privileged_lateral_expansion_2stage.yl2 # Privileged lateral movement & destination expansion
│   ├── shannon_entropy_character_2stage.yl2 # Shannon character-class entropy & obfuscated script density
│   ├── two_part_hurdle_2stage.yl2           # Two-Part Hurdle model for zero-inflated dormant entities
│   ├── zipfian_process_rarity_2stage.yl2    # Power-Law / Zipfian long-tail administrative utility rarity
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
├── references/                              # Deep-dive engineering guides (14)
│   ├── calibrated-risk-index-guide.md       # Sigmoid normalization (CRI 0–100) formulas
│   ├── chart-specifications-guide.md        # Vega-Lite and Chart.js dual-Y visualization schemas
│   ├── clean-handoff-udm-schema.md          # Synthetic UDM schemas & Chronicle API forwarder contracts
│   ├── consultative-worksheet.md            # Mapping security intent to 5 behavioral deformations
│   ├── cyber-practitioner-glossary.md       # Field manual translating statistics to SOC operations
│   ├── dynamic-windowing-matrix.md          # Adaptive window bucketing & sample floor matrix
│   ├── entity-context-graph-guide.md        # GLOBAL_CONTEXT & DERIVED_CONTEXT YARA-L architecture
│   ├── malachite-function-factory-matrix.md # Chronicle Malachite math.* and built-in function matrix
│   ├── multi-stage-query-guide.md           # 4-Stage DAG grammar rules & compiler invariants
│   ├── query-auditing-guide.md              # Pre-flight and post-flight payload intent auditing
│   ├── scope-exclusions-guardrail.md        # Why UEBA metrics.* are excluded from ad-hoc searches
│   ├── statistical-hunting-cooperative-framework.md # Bilateral micro/macro hunting boundary
│   ├── statistical-models-taxonomy.md       # Mathematical curves, Poisson dispersion, & 4D plots
│   └── watchdog-polling-architecture.md     # LRO watchdog mechanics & F1 optimization
├── scripts/                                 # Offline CI/testing helper scripts (Option A developer tooling)
│   ├── clean_handoff.py                     # Synthetic UDM builder, multi-event batching & schema validator
│   ├── generate_references.py               # Generates taxonomy and windowing reference markdown
│   └── multistage_query_builder.py          # Python linter, AST validator, & report/chart generator
└── tests/                                   # Automated unit test suite (127 tests, 100% pass rate)
    ├── test_chart_specifications.py         # Dual-axis visualization spec tests
    ├── test_clean_handoff.py                # Clean Hand-Off UDM schema validation & batching tests
    ├── test_compiler_grammar.py             # AST grammar, 1-3 stage limit, bare match identifiers
    ├── test_cri_and_math.py                 # Sigmoid CRI normalization and mathematical derivations
    ├── test_global_context_syntax.py        # Entity Context Graph (GLOBAL_CONTEXT/DERIVED_CONTEXT) syntax tests
    ├── test_guardrail_contracts.py          # Golden pipeline validation, session lock, and guardrail contracts
    ├── test_handoff_endpoint.py             # Federated handoff ingestion and protocol ACK tests
    ├── test_math_models.py                  # Bayesian, Beta-Binomial, Fano, and norm unit tests
    ├── test_query_auditor.py                # Post-flight intent and raw log dump detection tests
    ├── test_routing_interceptor.py          # Pre-flight routing interceptor and delegation tests
    ├── test_triage_reporting.py             # CommonMark 5-section triage schema & pillar tests
    ├── test_verified_compiler_facts.py      # Chronicle Malachite compiler grammar facts
    └── test_window_adaptation.py            # Dynamic windowing and sample floor adaptation tests
```

---

## 🚀 How to Install & Use in AI Coding Assistants

### 1. Installation
Clone or copy this directory into your assistant's skills search path (e.g., `~/.gemini/skills/` or `.agents/skills/`):
```bash
git clone https://github.com/GooGKush/secops-statistical-hunter.git ~/.gemini/skills/secops-statistical-hunter
```

---

## 🧭 Triggering Threat Hunts & Consultative Guidance

### 1. Mapping Operational Intent to Statistical Models
When interacting with an analyst, the skill translates operational hunting hypotheses into mathematical models using plain-English concepts:

| Analyst Operational Question | Statistical Model | Plain-English Concept & Physical Analogy |
| :--- | :--- | :--- |
| *"Find low-and-slow C2 beaconing with jitter"* | Coefficient of Variation ($CV$) | **The Metronome with Jitter**: Measures rhythmic timing regularity in outbound connections. |
| *"Find password sprays pulsing in waves"* | Poisson Dispersion (Fano Factor) | **The Clustered Surge**: Detects bursty, non-random variance spikes across target accounts. |
| *"Find rare admin tools running on quiet hosts"* | Discrete Poisson Rarity | **The Flash in the Dark**: Scores extreme rarity for sensitive administrative execution. |
| *"Find abnormal data exfiltration ignoring past spikes"* | Median Absolute Deviation (MAD) | **The Shock Absorber**: Outlier detection resistant to extreme historical skew. |
| *"Detect low-and-slow trickles over 14 days"* | Longitudinal CUSUM Drift | **The Slow Creep**: Cumulative baseline drift tracking sub-threshold data movement. |
| *"Find dormant accounts waking up today"* | Two-Part Hurdle Model | **The Sleeping Giant**: Evaluates binary transition from zero history to positive activity. |
| *"Correlate spikes with threat intel & newly registered domains"* | Global Threat Intel Correlation | **The Outside Threat**: Cross-references outbound spikes with GCTI intel and WHOIS domain age. |
| *"Find unusual binaries executed on this machine"* | Enterprise Prevalence Normalization | **The Unfamiliar Machine**: Blends host execution bursts with enterprise-wide novelty (`day_count <= 3`). |

### 2. The Two-Tier Scoping Choice
For asset and endpoint hunts, the skill proactively offers the analyst a structured consultative choice:
* **Tier A (Pure Local Baseline)**: Evaluates the target host solely against its own historical baseline. Best for isolated machines or bespoke developer servers.
* **Tier B (Enterprise-Grounded Hunt)**: Correlates local surges with enterprise-wide prevalence via Chronicle's Entity Context Graph (`DERIVED_CONTEXT`), applying a 2.5x threat score boost for rare or novel binaries across the company fleet.

### 3. Natural Language Trigger Examples

#### ⏱️ Timing Regularity & C2 Beaconing (CV & Jitter)
* *"Hunt for low-prevalence C2 beaconing with random timing jitter in outbound proxy connections."*
* *"Find connections with suspiciously regular inter-arrival timing intervals over the last 24 hours."*

#### 🌊 Volumetric Byte Surges (Log-Normal Standardization)
* *"Hunt for extreme network egress spikes on endpoint dev-ub22-1 using log-normal volume standardization."*
* *"Find endpoints uploading abnormal volumes of data compared to their historical distribution."*

#### 💥 Password Sprays & Burst Clustering (Poisson Fano Factor)
* *"Find distributed password spray attempts against Active Directory pulsing in bursts over the last 12 hours."*
* *"Hunt for clustered authentication failure waves exceeding random Poisson dispersion."*

#### 🔦 Rare Tool Surges & Living-off-the-Land (Discrete Poisson Rarity)
* *"Hunt for rare administrative binaries (powershell, vssadmin, certutil) executing on normally quiet production servers."*
* *"Find anomalous process launches where execution counts are statistically unprecedented for this entity."*

#### 🛡️ Patch Tuesday Immunity (Dual-Baseline Delta-Z)
* *"Hunt for workstations with abnormal network egress, but apply fleet prevalence shielding so Patch Tuesday software updates don't trigger false positives."*
* *"Compare local endpoint authentication spikes against the enterprise fleet to isolate true outliers."*

#### 🌐 Enterprise Novelty & Entity Context Graph
* *"Find endpoints communicating with newly registered domains created within the last 14 days (WHOIS NRD)."*
* *"Hunt for hosts executing binaries that have been seen on fewer than 3 machines across the entire company."*

#### 🔀 Bilateral Handoff Triggers (Routing to `secops-risk-metrics-multistage`)
Requests referencing 30-day pre-computed behavioral metric tables, rolling UEBA baselines, or omnibus risk scores automatically emit the Markdown Skill Delegation Card and yield the turn:
* *"Run a 30-day UEBA baseline check on user Frank Kolzig."*
* *"Show me Frank's 360-degree risk metrics view across all 6 behavioral sectors."*
* *"Check for authentication anomalies using pre-computed risk metrics."*

---

## 🧪 Testing & Verification

The skill package is verified through a rigorous three-tier testing hierarchy:

### 1. Automated Unit Test Suite (`pytest`)
```bash
pytest tests/
```
* **Status**: **136 / 136 passing unit tests** across 13 test modules (100% pass rate).
* **Scope**: Enforces Chronicle AST grammar rules, KaTeX formatting compliance, prompt guardrail contracts, hands-off `run_command` restriction contracts, and template router permutations across all mathematical models.

### 2. Chronicle Compiler AST & Invariant Validation
```bash
python3 scripts/multistage_query_builder.py
```
* **Status**: **100% clean compilation** across all 21 golden pipeline templates.
* **Scope**: Verifies Malachite AST compliance, continuous outcome arithmetic, Function Factory built-ins (`math.*`), bare identifier match binding (`ZERO DOTS IN MATCH`), and safe non-zero dispersion floor guards.

### 3. Maintainer Dual-Platform Regression Validation
End-to-end multi-turn conversational regression is validated by the maintainer team via the automated regression testing platform (`secops-regress`):
* **Status**: **20 / 21 passing scenarios** (95.2% dual pass rate; **21 / 21 AgentAPI passing (100%)**).
* **Scope**: Evaluates full conversation flows against live Google SecOps customer instances (`gus-sdl`), ensuring zero-stall Turn 2 execution, nominal quiet baseline reporting ($Z=0.00\sigma$), single-surface visualization compliance, and bilateral handoff protocol adherence.

---

## 📦 Release Notes

### v2.7.2 (September 29, 2026) — Advanced Information-Theoretic & Long-Tail Analytical Models
* **Four New Information-Theoretic & Long-Tail Models**: Added Markov 2-Gram Transition Rarity (`markov_2gram_transition_rarity_2stage.yl2`), Shannon Character-Class Entropy (`shannon_entropy_character_2stage.yl2`), Power-Law / Zipfian Long-Tail Process Rarity (`zipfian_process_rarity_2stage.yl2`), and Intraday EWMA Burst Velocity (`ewma_burst_velocity_2stage.yl2`), expanding golden pipelines from 17 to 21.
* **Architecture, Routing & Sensitivity Mapping**: Added parameter bounds across conservative, balanced, and aggressive tiers in `SENSITIVITY_MAP`, registered archetypes in `MultiStageTemplateRouter`, and updated `HandoffEndpoint`.
* **Consultative Guidance & Worksheets**: Expanded consultative worksheet with telemetry deformations 7–10 and taxonomy sections 13–16.
* **Test Suite & Dual-Engine Regression Validation**: Expanded automated unit tests to 136/136 passing (100%). Achieved 20/21 dual-engine regression pass (21/21 AgentAPI 100% pass, 100% clean AST compilation) across all 21 live tenant scenarios.

### v2.7.1 (September 28, 2026) — Dispersion Denominator Purge, Affirmative Tool Guidance Architecture & Dual-Engine Parity
* **Dispersion Denominator Purge Across Pipeline Templates**: Converted all artificial additive `+ 1.0` dispersion denominators across 14 pipeline templates to canonical nested outcome logic (`$safe_sd = if($sd > 0, $sd, 1.0)` / `$safe_dispersion = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)`). Preserved mathematically legitimate Bayesian updating constants ($\beta_{\text{post}} = \beta_0 + 1.0$, Beta-Binomial conjugate updating, $\ln(B+1)$ transforms).
* **Affirmative Tool Guidance & Lifecycle Architecture**: Replaced negative prohibitions ("never execute", "strictly prohibited", "arbitrary case hijacking is strictly forbidden") with affirmative operational guidance in `SKILL.md`. Explicitly codified the hands-off `run_command` restriction ("There is no blanket approval for `run_command`, only explicit exemptions"), verified by unit tests.
* **Stripping of Legacy Tool Prefixes**: Purged legacy `secops-gus:` tool prefixes across instructions, references, and diagrams, standardizing on native MCP tool operations (`udm_search`, `import_logs`, `create_case_comment`).
* **Chronicle SIEM Compiler Grammar Codification**: Standardized explicit syntax patterns for case-insensitive regex (`re.regex(<field>, `(?i)...`)`) and cross-stage temporal window filtering (`$max_day = max($day_id)` bound before `match:` in downstream stages).
* **100% Dual-Engine Regression Parity (17 / 17 Invariants Passed)**: Evaluated across all 17 regression test scenarios in dual-engine mode (`agentapi` + `direct-mcp`) with 6 workers, achieving 100% invariant parity across all P0, P1, and P2 contracts (127/127 automated unit tests passing).

### v2.7.0 (September 27, 2026) — Function Factory Built-Ins, Outcomes-in-Outcomes Inlining, Daily Temporal Spine & Log-Normal Volumetric Surge
* **Chronicle Malachite Function Factory Built-Ins**: Adopted namespaced mathematical built-ins natively in raw UDM multi-stage queries (`math.sqrt`, `math.log`, `math.exp`, `math.min`, `math.max`, `math.round`).
* **Outcomes-in-Outcomes (OIO) In-Stage Inlining**: Enabled native outcome variable chaining within the same stage (`$diff = $obs - $avg`, `$z = $diff / $safe_sd`).
* **Safe Non-Zero Dispersion Floors**: Replaced double-padded denominators with exact conditional guards (`if($sd > 0, $sd, 1.0)`).
* **Log-Normal Volumetric Surge Pipeline**: Added `templates/pipelines/log_normal_volume_surge_2stage.yl2` implementing parametric log-normal standardization for heavy-tailed network egress distributions.
* **Daily Temporal Spine (`by 1d`)**: Automated `by 1d` bucket sizing on horizons $\ge 7$ days, reducing row cardinality by $24\times$.

### v2.6.1 (September 26, 2026) — DERIVED_CONTEXT File & Domain Prevalence Pipelines & Enterprise-Grounded Consultative Pattern
* **Entity Context Graph Prevalence Pipelines**: Added `derived_context_file_prevalence_3stage.yl2` and `derived_context_domain_prevalence_3stage.yl2` correlating execution and egress with persistent enterprise prevalence.
* **Enterprise-Grounded Consultative Pattern**: Added Tier A vs. Tier B scoping choices in `SKILL.md` and consultative worksheets.
* **State 1 Single-Tool Ceiling**: Reinforced Turn 1 single-tool probe ceiling (`udm_search(..., maxEvents=1)`).

### v2.6.0 (September 25, 2026) — Option A Affirmative Native-Chat Runtime & 6 Mandatory Root Outcome Variables
* **Option A Affirmative Native-Chat Runtime**: Enforced strict Option A architecture—scripts in `scripts/` reserved for offline CI testing (`pytest tests/`), while runtime operates natively through MCP tools (`udm_search`, `import_logs`, `create_case_comment`).
* **6 Mandatory Root Outcome Variables**: Standardized `$observation_count`, `$baseline_active_samples`, `$baseline_mean`, `$baseline_dispersion`, `$fleet_prevalence`, and `$distinct_binaries` across all pipelines.
* **Immediate Turn 2 Execution & 5-Section Triage Report**: Established deterministic execution upon analyst clearance without secondary clarification stalls.

### v2.5.1 (September 10, 2026) — Automated Clean Hand-Off Protocol Engine
* **Clean Hand-Off Engine (`scripts/clean_handoff.py`)**: Implemented dedicated helper for generating, validating, batching, and dispatching synthetic UDM events (`CUSTOM_SECURITY_DATA_ANALYTICS`).
* **Correlated Multi-Finding Batching**: Added native array batching binding all findings under a shared `Hunt Campaign ID`.

### v2.5.0 (September 10, 2026) — Dual-Client Multi-Platform Regression Suite
* **Dual-Client Multi-Platform Regression**: Evaluated across 10 scenarios in Dual-Engine Mode against `gus-sdl`, achieving 100% pass rate.
* **Strict Match Binding Invariant (`ZERO DOTS IN MATCH`)**: Codified and enforced simple bare identifiers in `match:` blocks.

---

## 🤝 Contributions
Contributions to this skill package are highly welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License
This project is licensed under the [Apache License 2.0](LICENSE).
```
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
