# Release Notes: SecOps Statistical Hunter (v2.0 Upgrade)

**Release Date:** August 24, 2026  
**Module:** `secops-statistical-hunter`  
**Scope:** Architecture, Compiler Compliance, Time-Windowing, Statistical Rigor, and SOC Explainability  

---

## 🌟 Executive Summary

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
