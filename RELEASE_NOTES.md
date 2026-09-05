# Release Notes: SecOps Statistical Hunter

## 📦 Version 2.3.1 (September 5, 2026) — Bilateral Cooperative Threat Hunting, Dual Grounding Invariants & Intermediate AST Grammar Hardening

* **Bilateral Cooperative Threat Hunting Architecture**:
  * Added `references/statistical-hunting-cooperative-framework.md` codifying the bilateral operating model between `secops-statistical-hunter` (Micro-Analysis: ad-hoc inline math, sub-second beaconing jitter, Poisson rarity, and Tukey fences on raw log streams) and `secops-risk-metrics-multistage` (Macro-Analysis: 30-day pre-computed behavioral baselines, peer group analytics, and CUSUM drift).
  * Formalized the **Zero-Code Handoff Invariant**: consultative handoff cards to peer skills must remain conceptual and architectural without emitting uncompiled code blocks.
* **The Dual Grounding Invariants (The Non-Negotiable Integrity Core)**:
  * **Zero Data Simulation ("Truth Over Completion")**: Prohibits fabricating statistics, calculating baselines in local Python scripts, or generating mock results on empty/error API responses.
  * **Zero Schema/Syntax Fantasy**: Prohibits hallucinating non-existent UDM fields or functions. All queries presented must be verified via a 10-minute compile probe prior to clearance.
* **The Closed 3-State Active Hunt Lifecycle**:
  * Structured workflows into a positive state machine: State 1 (Pre-Flight Clearance & Specification), State 2 (Deterministic Execution & 5-Section Triage Report), and State 3 (Iteration, Entity Shifts & Federated Bridge).
* **Active Hunt Session Lock & Boundary (Zero Cross-Skill Drift)**:
  * Enforced persistent session affinity across multi-turn follow-up queries, re-entering State 1 for new entities while strictly preventing fall-through to generic search skills or raw event dumps.
* **Intermediate Stage AST Grammar Hardening**:
  * Enhanced `multistage_query_builder.py` (`validate_multistage_syntax`) to reject bare scalar `if(...)` conditional branches inside intermediate stage outcome blocks.
  * Updated `templates/pipelines/c2_beaconing_jitter_2stage.yl2` to regularize interval calculation with linear division floor (`(max($ts) - min($ts)) / (count(metadata.id) - 0.999)`).
* **Lexical De-Baiting of Section 4**:
  * Renamed Section 4 from *"Immediate Drill-Down Investigation Query"* to *"Chronicle UI Manual Pivot (Triage Reference Only)"* and designated it as passive reference text, eliminating model bait for unintended automated tool executions.
* **Expanded Automated Test Suite**:
  * Added tests in `tests/test_compiler_grammar.py` (`test_reject_bare_scalar_if_in_stage_outcome`, `test_c2_beaconing_jitter_template_passes_cleanly`) and `tests/test_guardrail_contracts.py` verifying all cooperative contracts.

---

## 📦 Version 2.3.0 (September 3, 2026) — Risk Metrics Cross-Pollination, Common Compiler Conformance & Calibrated Risk Index (CRI)

* **Common Compiler AST Invariants & Syntax Traps**:
  * Added syntax trap `INVALID_STAGE_VARIABLE_SYNTAX` enforcing `$stage.var` instead of `stage.$var` to prevent compiler crashes.
  * Added syntax trap `INVALID_SQRT_FUNCTION` rejecting non-existent `sqrt()` / `math.sqrt()` in outcome expressions, enforcing squared distance/deviance norms ($D^2$, $Z_{\text{poisson}}^2$) and ordering by `$score_sq desc`.
  * Added syntax trap `INVALID_DETECTION_RULE_SYNTAX` preventing wrapping multi-stage search queries in streaming detection rule wrappers (`rule ... { ... }`).
  * Enforced event-section arithmetic prohibition (binary variable operations prohibited above `match:`).
* **Calibrated Risk Index (CRI [0–100]) Standard**:
  * Implemented logistic sigmoid normalization $\text{CRI} = \text{round}(100 / (1 + \exp(-0.6 \cdot (Z - 3.0))))$ in `multistage_query_builder.py` (`calculate_cri`, `get_cri_badge`), anchoring $Z = 3.0\sigma$ at CRI = 50.
  * Updated 5-Section triage reporting to render CRI scores across Ranked Outlier Summary, Top Outlier Spotlight, and Mathematical Appendix.
  * Documented architectural rationale and calibration curve in `references/calibrated-risk-index-guide.md`.
* **Data Reduction Engine (`DataReductionEngine`)**:
  * Added context window protection engine that truncates large search result payloads into structured summaries and top $N$ anomalies, preventing LLM token exhaustion.
* **API Response Payload Auditing & Auto-Remediation (`PostFlightExecutionAuditor`)**:
  * Enhanced post-flight auditing to validate response structures, detecting unaggregated event dumps (`RAW_LOG_DUMP_DETECTED`) and setting `status = AuditStatus.RETRY_REQUIRED`.
  * Integrated auto-recommended query synthesis via template routing.
* **Golden Pipeline Templates & Multi-Stage Router (`MultiStageTemplateRouter`)**:
  * Packaged 9 canonical pipeline templates into `templates/pipelines/*.yl2` covering all major statistical hunting models.
  * Added `--build_query` CLI integration in `scripts/multistage_query_builder.py` to compile parameterized multi-stage queries from templates.
* **Clean Hand-Off (CH) & Synthetic UDM Event Ingestion**:
  * Formulated the Clean Hand-Off protocol in `references/clean-handoff-udm-schema.md` establishing Path A (default synthetic UDM event ingestion via `import_logs` for catch-all rule promotion) and Path B (active case comment attachment via `create_case_comment` only when an explicit `case_id` is specified).
  * Enforced strict prohibition against arbitrary case hijacking.
* **Non-Negotiable Execution & Integrity Contracts**:
  * Codified the Hard Stop on API Error, Native Execution Guarantee (zero Python simulation scripting), Literal Query Display Mandate, and Strict Nomenclature Mandate (Query vs. Rule).
* **Expanded Automated Test Suite**:
  * Added `tests/test_cri_and_math.py` and `tests/test_guardrail_contracts.py`. Full test suite now features 51 passing unit tests (100% pass rate).

---

## 📦 Version 2.2.1 (September 1, 2026) — Dual Multi-Stage Taxonomy & Architecture Disambiguation

* **Dual Multi-Stage Architecture Boundary**:
  * Documented explicit data plane boundaries between ad-hoc raw telemetry DAG queries (`UDM_EVENTS`) and pre-computed 30-day UEBA metric tables (`secops-risk-metrics-multistage`).
  * Disambiguated shared mathematical models that execute via multi-stage DAGs:
    * **Dual-Baseline Delta-$Z$**: Raw concurrent enterprise fleet shift suppression (*Patch Tuesday Shield*) vs. 30-day pre-computed department peer cohort comparisons.
    * **Multi-Sector Threat Fusion**: Raw cross-silo orthogonal event counting (*Combined Arms Radar*) vs. multi-dimensional 30-day baseline deviation norms ($D = \sqrt{\sum Z_i^2}$).
* **Exclusive Capability Clarifications**:
  * Formalized that timing jitter ($\text{CV} \le 0.20$) and connection inter-arrival intervals ($\Delta t_i = t_i - t_{i-1}$) strictly require raw event timestamps and are physically impossible on daily pre-computed metric tables.
  * Formalized that 30-day rolling behavioral baselines, department cohorts, and 360° health checks belong exclusively to `secops-risk-metrics-multistage`.
* **Guardrail & Linter Updates**:
  * Updated `EXCLUDED_PATTERNS` in `scripts/multistage_query_builder.py` and `references/scope-exclusions-guardrail.md` to reference `secops-risk-metrics-multistage` (replacing legacy `secops-risk-analytics`).

---

## 📦 Version 2.2.0 (September 1, 2026) — AST Pre-Flight Guards & Post-Flight API Response Payload Auditing

* **Advanced Compiler Syntax & Token Traps**:
  * Added pre-flight detection for illegal exponent operator `^` (enforces `$var * $var` for squared Euclidean norms).
  * Added detection for invalid Python/SQL string tuples `in ("A", "B")` (enforces disjunctions `(field = "A" or field = "B")` or regex).
  * Added rejection of invalid `by 24h` duration tokens (enforces canonical `by 1d`).
  * Added rejection of `$` prefixes in stage declarations (`stage $name {`).
* **Multi-Vector Cramming Detection**: Implemented domain-aware telemetry silo analysis (`check_multivector_cramming`) to prevent mixing cross-domain event categories (Auth + Endpoint + Network + Cloud) in single unseparated stage blocks.
* **Entity Context Graph (ECG) Limit Enforcement**: Added AST check (`check_ecg_limits`) enforcing max 1 Entity Context Graph alias per stage (`$e.graph...` limit = 1) to prevent F1 memory exhaustion.
* **Post-Flight API Response Payload Auditing (`PostFlightExecutionAuditor`)**:
  * Implemented `audit_api_response_payload()` and `PostFlightExecutionAuditor` to ensure queries execute mathematical aggregations inside Chronicle's F1 data plane, actively flagging un-aggregated raw event dumps (`RAW_LOG_DUMP_DETECTED`).
  * Added `--audit_response <api_response.json>` CLI integration.
* **Expanded Test Coverage**: Added comprehensive test suites in `tests/test_compiler_grammar.py` and `tests/test_query_auditor.py` (30 total tests, 100% pass rate).

---

## 📦 Version 2.1.0 (August 26, 2026) — Progressive Architecture, Intent Auditing & Unit Testing

* **Progressive Disclosure Instruction Architecture**: Refactored `SKILL.md` down to a lean, token-efficient ~125 lines focused on core routing and execution contracts, moving comprehensive math taxonomy, DAG grammar, dynamic windowing formulas, chart schemas, auditing rules, and SOC playbooks into modular guides in `references/`.
* **Post-Query Intent & Architecture Auditor (`QueryIntentAuditor`)**: Implemented automated AST verification (`--audit_intent`, `--audit_model`) in `multistage_query_builder.py` that confirms the executed query matches the exact stage depth (Single-Stage vs. 2/3/4-Stage DAG) and mathematical signatures promised to the user.
* **Automated Unit Test Suite (`tests/`)**: Added a 20-test automated test suite across 6 test modules (`test_compiler_grammar.py`, `test_math_models.py`, `test_window_adaptation.py`, `test_triage_reporting.py`, `test_chart_specifications.py`, `test_query_auditor.py`) ensuring 100% test coverage over grammar rules, Bayesian math, and visualization specifications.
* **Advanced Raw Telemetry Hunting Models**: Added reference queries and math models for Poisson-Gamma Bayesian Credibility Shrinkage ("The Seasoned SOC Detective"), Beta-Binomial Failure Rate Regularization ("Small-Sample Ratio Regularizer"), Dual-Baseline Delta-$Z$ ("The Patch Tuesday Shield"), and Multi-Sector Threat Fusion ("The Combined Arms Radar").
* **Consistent Authorship Attribution**: Standardized authorship attribution to Greg Kushmerek across `SKILL.md`, `README.md`, and Python modules across both `secops-statistical-hunter` and `secops-risk_metrics-multistage`.

---

## 📦 Version 2.0.1 (August 24, 2026) — Non-CLI & Rich Charting Clarifications

* **Mandatory 5-Section Reporting Enforcement**: Clarified instructions so that non-CLI agents do not regress to free-form bullet points; enforces all 5 sections (Executive Envelope, Ranked Outlier Summary Table, Spotlight with 6 Evidence Pillars, 1-Click Drilldown, and Collapsible Technical Appendix).
* **Strict Axis Type Isolation for UI Charting**: Added explicit rules and copy-pasteable Vega-Lite / Chart.js schemas to prevent mixed string/numeric data corruption on chart Y-axes (categorical strings belong only on the nominal X-axis or in tooltips).
* **Search-Only Action Playbook Guardrail**: Reinforced the constraint that multi-stage queries cannot be deployed as continuous real-time alert rules, ensuring action playbooks only recommend scheduled cron searches, dashboards, or allowlist reviews.
* **CLI Chart Helper Enhancements**: Added `generate_chartjs_spec()` and `CATEGORICAL_BAR` generation in `multistage_query_builder.py`.

---

## 🌟 Version 2.0.0 (August 24, 2026) — Major Architectural Upgrade

### Executive Summary

This release represents a comprehensive overhaul of the **`secops-statistical-hunter`** skill. Key additions include the **Four-Stage DAG Pipeline Architecture**, **Race-Free Compiler Materialization**, an **Adaptive Dynamic Time-Window Protocol**, **6 Forensic Evidence Pillars**, **Fleet-Wide Multiple-Comparison Scaling**, and a **Plain-English SOC Triage Reporting Engine** designed specifically for security practitioners without a mathematics background.

---

## 🚀 Key Additions & New Features

### 1. Four-Stage DAG Pipeline Architecture
* **Extended Pipeline Depth**: Formalized support for up to **4 named intermediate stages plus 1 unwrapped root stage (5 stages total)**, allowing multi-stage aggregation pipelines (e.g. Host Extraction $\to$ Baseline Normalization $\to$ Fleet Grouping $\to$ Scoring & Evidence Emission).
* **20-Variable Outcome Enforcement**: Added strict tracking to ensure no single `outcome:` block exceeds the Malachite compiler limit of **20 variables** (`OutcomeLimit = 20`).

### 2. The 6 Standardized Forensic Evidence Pillars
Every statistical hunt now emits a standardized 6-variable forensic payload in its `outcome:` block, guaranteeing full traceability:
1. **Observation Count (`$observation_count`)**: Active burst volume in the anomaly window.
2. **Baseline Sample Density (`$baseline_active_samples`)**: Total historical observation intervals evaluated.
3. **Central Tendency (`$baseline_mean`)**: Expected historical Mean ($\mu$) or Median ($\tilde{x}$) during calm operations.
4. **Baseline Dispersion (`$baseline_dispersion`)**: Historical Standard Deviation ($\sigma$) or Median Absolute Deviation ($\text{MAD}$).
5. **Peer Fleet Prevalence (`$fleet_prevalence`)**: Enterprise-wide count of hosts exhibiting the activity.
6. **Artifact Cardinality (`$distinct_binaries`)**: Distinct child binaries, command paths, or destination domains.

### 3. Dynamic Time-Window Protocol & Adaptive Granularity
* **Arbitrary Time-Window Flexibility**: Inherently adapts to any analyst request ("today", "past 2 days", "past week", "days this month so far", or "past 30 days").
* **Adaptive Granularity Matrix**: Dynamically adjusts bucket sizing to provide sufficient statistical sample density:
  * **Intra-Day ($\le 24\text{h}$)**: `by 10m` or `by 15m` ($96–144$ sample buckets).
  * **Short ($24\text{h}–7\text{d}$)**: `by 1h` ($48–168$ hourly buckets).
  * **Extended ($7\text{d}–30\text{d}$)**: `by 1h` or `by 1d` ($168–720$ hourly / $7–30$ daily buckets).
* **Proportional Sample Density Floor Rule**: Scales condition floors proportionally ($\text{Floor} = \max(3, \min(\text{Default}, \lfloor 0.25 \times N_{\text{total\_intervals}} \rfloor)$) to eliminate false-negative dropouts and automatic query failures on narrow windows.

### 4. Human-Centered Plain-English Triage Reporting
* **Executive Story Headline**: Summarizes the physical finding, surge multiplier (e.g. `3.4x higher than normal`), and organizational breadth in plain language.
* **Forensic Evidence Breakdown**: Translates each of the 6 Evidence Pillars into direct investigation meanings.
* **Real-World Attack Scenarios vs. Benign Causes**: Directly contrasts potential attack mechanics against legitimate business causes (build tools, SCCM pushes, backup windows).
* **Prescriptive 4-Step SOC Action Plan**: Provides step-by-step triage actions requiring no mathematics background.
* **Collapsible Technical Appendix**: Encloses exact formulas, degrees of freedom ($N$), dispersion derivations, and multiple-comparison proofs inside a clean, collapsible `<details>` block at the bottom of the report.

### 5. Fleet-Wide Multiple-Comparison Scaling (Bonferroni Adjustment)
* Integrated the extreme-value fleet scaling formula to prevent false positives when evaluating large fleets ($N$ endpoints):
  $$Z_{\text{adj}} \approx \sqrt{2 \ln(N)}$$
* Added `--fleet_size <N>` flag to the query builder to compute adjusted significance thresholds.

---

## 🛠️ Bug Fixes & Architectural Improvements

### 1. Elimination of Outcome AST Race Conditions
* **Issue**: Upstream queries defined outcome variables and reused them as operands within the same `outcome:` block (e.g. `$diff = $a - $b` followed by `$z = $diff / $sd`), causing compiler evaluation race conditions.
* **Fix**: Implemented the **Clean Materialization Barrier Rule**. Arithmetic is now computed in the event plane before `match:` or decomposed cleanly across intermediate DAG stages.

### 2. Linearized AST Outcome Arithmetic
* **Issue**: Parenthesized expressions like `($a - $b) / $c` failed Malachite AST compilation.
* **Fix**: All mathematical expressions are strictly linearized into single-operation steps with non-zero divisor gating in `condition:`.

### 3. Factory Function Subsystem Integration
* **Update**: Cataloged and verified built-in Malachite factory functions: `math.sqrt()`, `math.pow()`, `math.floor()`, `math.ceil()`, `window.median()`, `window.percentile()`, `cast.*`, `strings.*`, `re.*`, and `timestamp.*`.

### 4. Window-Sample Mismatch Linter
* **Feature**: Added automatic detection in `scripts/multistage_query_builder.py` (`check_search_window()`) to catch queries where condition floors exceed the total available time units in the search window.

---

## 📂 Updated Files & Artifacts

| Component | File Path | Description |
| :--- | :--- | :--- |
| **Release Notes** | [`RELEASE_NOTES.md`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/RELEASE_NOTES.md) | Official release notes detailing v2.0 upgrade changes. |
| **Core Skill Definition** | [`SKILL.md`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/SKILL.md) | Updated with 4-Stage DAG rules, Dynamic Time-Window Protocol, and accessible reporting format. |
| **Linter & Report Tool** | [`scripts/multistage_query_builder.py`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/scripts/multistage_query_builder.py) | Upgraded with race checks, 20-var limit, adaptive window calculator (`--window_hours`), and technical appendix generator. |
| **Glossary Reference** | [`references/cyber-practitioner-glossary.md`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/references/cyber-practitioner-glossary.md) | Added plain-English evidence translations, confidence tiers, and triage checklists. |
| **Taxonomy Reference** | [`references/statistical-models-taxonomy.md`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/references/statistical-models-taxonomy.md) | Added 4-stage architecture, adaptive granularity matrix, and factory function catalog. |
| **Search Templates (8)** | [`examples/*.yara`](file:///usr/local/google/home/kushmerek/projects/secops-statistical-hunter/examples) | Upgraded all 8 reference YARA-L queries to 4-stage race-free pipelines with 6 Evidence Pillars (100% validated). |
