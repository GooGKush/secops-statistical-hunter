# Release Notes: SecOps Statistical Hunter

## 📦 Version 3.0.0 (October 29, 2026) — Cross-Review Remediation Release: 27 Verified Pipelines, `D1`/`D4`/`D5`/`D6`/`D7` Dispositions, Vetted Python Helpers (`G1`–`G5`), Score Semantics Registry & Cross-Skill Contracts

* **Data Behavior, Zero-Bucket Reconstruction, Tenant Identifier Coverage & ECG Lag Safeguards (`WS1-06`, `WS1-07`, `WS1-08`)**:
  * **Zero-Inclusive Raw Dispersion (`WS1-06`, `PF-4`)**: Added `{{total_window_buckets}}` ($T$) to `poisson_burst_clustering_2stage.yl2` so Stage 2 reconstructs zero-count buckets ($\mu = \sum x / T$, $\sigma^2 = \sum x^2 / T - \mu^2$) rather than averaging active-only match buckets, alongside target-keyed and source-keyed spray variants.
  * **Per-Tenant Identifier Coverage Probe (`WS1-07`, `D4`, `PF-9`)**: Added `build_identifier_coverage_probe()`, `select_identifier_from_coverage()`, and `identifier_coverage_payload` in `MultiStageTemplateRouter.build_query()` to select `principal.asset.hostname` when hostname coverage $\ge 20\%$ (or $\ge$ IP coverage) else `principal.ip`, joining hostnames to IPs strictly through `DERIVED_CONTEXT` `ASSET` stages.
  * **Entity Context Graph Freshness, Inner-Join Disclosure & Day-0 Companion (`WS1-08`, `PF-8`)**: Anchored `DERIVED_CONTEXT` hunts at `D-2` (`compute_ecg_search_window`), enforced `prevalence.day_count = 10` and `count_distinct(window_start)` sample grains across `derived_context_*` and `global_threat_intel_enrichment_3stage.yl2`, added `build_day0_companion_query()` for unindexed Day-0 artifacts, disclosed inner-join filtering in triage reports, and disabled `<7d` ECG novelty when `first_seen_time = 0` (deferring to `secops-risk-metrics-multistage` `metrics.*` `first_seen`).
* **Micro Pipeline Rebuilds, `D1` Retirement & Learned 24-Bin Hour-of-Day Circadian Profile (`WS5`, `D1`, `WS5-HOD`)**:
  * **Retired `IMPOSSIBLE_TRAVEL_GEO_VELOCITY` (`D1`)**: Removed `impossible_travel_geo_velocity_2stage.yl2` from active templates while retaining backward-compatible aliases (`IMPOSSIBLE_TRAVEL_GEO_VELOCITY`, `IMPOSSIBLE_TRAVEL`, `GEO_VELOCITY`, `SUPERSONIC_TRAVEL`) that raise a deterministic `ValueError` (`RETIRED_IMPOSSIBLE_TRAVEL_MESSAGE`) pointing to `HOUR_OF_DAY_PROFILE` and `PRIVILEGED_LATERAL_EXPANSION`.
  * **Learned 24-Bin Hour-of-Day Profile (`HOUR_OF_DAY_PROFILE`, `templates/pipelines/hour_of_day_profile_3stage.yl2`, `WS5-HOD`)**: Scores each hour in the scoring window out-of-sample against the entity's prior $D_{\text{base}}$ calendar days (`timestamp.get_hour` in `{{tenant_tz}}`) with zero-inclusive variance, continuous Poisson SD floor $\sqrt{\max(\mu_h, 1.0)}$, and `$hour_profile_mass` replacing macro hourly-Z and circadian models.
  * **Out-of-Sample Baselines, Root `$ws` Keying & Empirical-Bayes Rebuilds (`WS5`)**: Added `$ws` to root `match:` across windowed pipelines (`S-WS`), made minimum sample floors mode-dependent (`S-M30`), restricted `$fleet_prevalence` to surging entities with honest pass/fail reporting (`S-FP`), excluded scored buckets via leave-one-out moments with continuous SD floors across `zscore_process_surge_2stage.yl2`, `log_normal_volume_surge_2stage.yl2`, `multi_sector_threat_fusion_4stage.yl2`, `producer_consumer_ratio_inversion_2stage.yl2`, and `privileged_lateral_expansion_2stage.yl2`, rebuilt `bayesian_gamma_shrinkage_4stage.yl2`, `beta_binomial_failure_4stage.yl2` (including `FAIL` actions), `dual_baseline_delta_z_3stage.yl2`, `two_part_hurdle_2stage.yl2`, `poisson_rare_surge_2stage.yl2` (`{{window_days}}` host-online days), `markov_2gram_transition_rarity_2stage.yl2` (Laplace-smoothed whole-window surprisal), `zipfian_process_rarity_2stage.yl2` ($\ln(N_{\text{fleet}}/H)$), `hybrid_entropy_concentration_2stage.yl2` (positive-rectified destination diversity deficit + elephant-flow concentration), `iqr_tukey_skew_fences_3stage.yl2` (recalibrated 1.35 Bowley exponent + scale-invariant `$fence_z`), and standalone `examples/*.yara`.
* **Vetted Repository Python Helpers & Stateless `D6-G5` Screens (`WS6-02`, `WS6-03`, `WS6-04`, `D6` Guardrails `G1`–`G5`)**:
  * Shipped `scripts/micro_python_helpers.py` (`ewma`, `shannon`, `c2-jitter`) operating strictly over raw `udm_search` JSON (`G1`: never LLM-typed numbers; `G2`: exit `2` fail-closed on missing/malformed input; `G3`: query/payload SHA-256 + helper version in `Provenance Appendix`; `G4`: offline golden-tested with zero network calls; `G5`: honest fallback `"this model needs a client that can run local scripts"` when `local_execution_available=False` / `--no-local-scripts`).
  * Added three dedicated stateless in-query screens (`burst_z_screen_2stage.yl2` / `BURST_Z_SCREEN`, `long_string_screen_2stage.yl2` / `LONG_STRING_SCREEN`, and `flow_gap_ratio_screen_2stage.yl2` / `FLOW_GAP_RATIO_SCREEN`) under their own honest screen names, expanding the active pipeline catalog to **27 `.yl2` templates**.
* **Unified CRI, Score Semantics Registry, Expected-Maximum Fleet Reference & Fusion Correlation (`WS7-01`, `WS7-02`, `WS7-03`, `D5`, `WS2-08`)**:
  * Centralized canonical CRI (`Z = 3.0 -> CRI = 50`, `Z <= 0 -> 0`, missing/error `-> N/A`, bands `26/46/70/90`) and fusion/write-back constants in `scripts/ueba_constants.py` (`WS7-01`, `WS2-08`).
  * Added the Z-equivalent score semantics registry (`get_score_semantics`, `score_to_z_equivalent`, `cri_from_model_score`, `format_score_with_unit`) mapping inverted ratios (`cv`), Fano offsets, and squared Poisson deviance onto `Z = 3.0` at threshold while emitting `σ` strictly on true $\sigma$ scores (`WS7-02`).
  * Replaced mislabeled `"Bonferroni"` claims on $\sqrt{2 \ln N}$ with the accurate Gaussian extreme-value **expected-maximum** approximation ($\mathbb{E}[\max_{1 \le i \le N} Z_i] \approx \sqrt{2 \ln N}$), documented that multi-sector fusion false-positive rates depend on sector correlation (positively correlated sectors exceed independent $\chi^2_k$ tail rates), and corrected nominal CRI example concordance in `references/calibrated-risk-index-guide.md` (`WS7-03`).
* **Cross-Skill Glue, Target-Entity Binding, Canonical Routing & Documentation Concordance (`WS8-01`–`WS8-04`, `D7`, `WS9-03`, `WS9-04`)**:
  * Fixed `HandoffEndpoint.ingest()` and `MultiStageTemplateRouter.build_query()` (`WS8-01`) to bind `target_entity.value` across all 27 active templates (Stage 1 predicates for self-baseline pipelines; Root before `match:` for fleet/cohort/prevalence pipelines), verified by `QueryIntegrityGate.verify_pre_dispatch()`.
  * Synchronized `CANONICAL_SKILL_ROUTING_TABLE` across `SKILL.md` and `check_routing_recommendation()` with zero cross-skill ping-pong (`WS8-02`), pinned the frozen `D7` write-back contract in `tests/test_ws8_03_writeback_frozen_contract.py` (`WS8-03` — zero changes to `scripts/clean_handoff.py`), and routed `EXFILTRATION_IQR_OUTLIER` to `iqr_tukey_skew_fences_3stage.yl2` over `NETWORK_CONNECTION` `sum(network.sent_bytes)` (`WS8-04`).
  * Upgraded `scripts/generate_references.py` (`WS9-03`) to generate a complete 27-pipeline slot, topology, execution-mode, match-spine, and primary-score matrix plus `D1` retired dispositions in `references/statistical-models-taxonomy.md` (enforced byte-for-byte in CI), and documented explicit `D6` `G1`–`G5` guardrails in `SKILL.md` (`WS9-04`, maintained `<= 28,200` bytes).
* **Verification**:
  * **Unit, Contract & Golden Math Suite (`WS0-01`–`WS0-05`)**: `326 passed, 1 live-opt-in skipped, 788 subtests passed` (`0 failed`) across all test modules, plus opt-in `tests/live/test_live_compile_matrix.py` (`WS0-03`) verified against `gus-sdl`.


## 📦 Version 2.9.0 (October 28, 2026) — Non-Parametric Quantiles (`window.percentile`), Bowley Quartile Skewness, Hubert–Vandervieren Skewness-Adjusted Tukey Fences, Intra-Bucket Payload Shape Fingerprinting & Ingestion-Lag Quantile Auditing

* **24th Golden Pipeline Template: 1-Stage Quantile Envelope & Skewness-Adjusted Tukey Fence (`templates/pipelines/iqr_tukey_skew_fences_3stage.yl2`, `IQR_TUKEY_SKEW_FENCES`)**:
  * Computes the 5-point empirical quantile envelope ($P_{10}, Q_1, Q_2, Q_3, P_{90}$) in a **single intermediate stage** (`quantile_fences`) via `window.percentile(expr, P)`, saving 1 full stage and 1 join compared to 2-stage MAD (`median_stats` $\to$ `mad_stats`).
  * Frees Stage 3 for native enterprise fleet prevalence (`stage fleet_breadth`), enabling `🟢 HIGH CONFIDENCE` triage ratings alongside non-parametric outlier scoring.
  * Computes **Bowley's Quartile Skewness** $B_{\text{skew}} = (Q_3 + Q_1 - 2 Q_2) / \max(\text{IQR}, 1.0) \in [-1, +1]$, **Moors Interdecile-to-Interquartile Tail-Heaviness Ratio** $T_{\text{ratio}} = (P_{90} - P_{10}) / \max(\text{IQR}, 1.0)$, and the **Hubert–Vandervieren Skewness-Adjusted Tukey Upper Fence** $Q_3 + 1.5 \cdot e^{3 \cdot \max(0, B_{\text{skew}})} \cdot \max(\text{IQR}, 1.0)$ via `math.pow(2.718281828, 3.0 * $pos_skew)`.
* **Malachite Function Factory Matrix & Consultative Worksheet Expansion (`references/malachite-function-factory-matrix.md`, `references/consultative-worksheet.md`, `examples/iqr_tukey_fences_egress.yara`)**:
  * Documented `window.percentile(expr, P)` ($P \in [0, 100]$) and `window.median(expr, bool)` in the Malachite Function Factory Matrix, including Section 6 covering 1-stage quantile envelopes, Quartile Coefficient of Dispersion ($\text{QCD} = (Q_3 - Q_1)/(Q_3 + Q_1)$ as an outlier-immune replacement for $CV = \sigma/\mu$), intra-bucket payload shape fingerprinting, and ingestion-lag auditing.
  * Expanded `references/consultative-worksheet.md` to **14 Raw Behavioral Telemetry Deformations** (adding Deformation 14: *Quantile Asymmetry & Tail Skew / Lag Drift*) and added the **Real-World Non-Parametric Quantile & Skewness Hunting Playbook** with live-verified compilable YARA-L 2.0 examples for Intra-Bucket Payload Quantile Shape Fingerprinting ($P_{50}$ vs $P_{90}$ separating C2 heartbeat + burst exfiltration from uniform backups) and Telemetry Ingestion Lag / Clock-Skew / Timestomping Quantile Auditing (`metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds`).
  * Upgraded `examples/iqr_tukey_fences_egress.yara` to canonical `by 1d` buckets, OIO Bowley skewness, and Hubert–Vandervieren skewness-adjusted upper fences.
* **Verification**:
  * **Unit Test Suite**: `179 / 179` unit tests passing (`100%`), with `SKILL.md` maintained within the `28.0 KB` ceiling.
  * **Live Chronicle SIEM (`gus-sdl`)**: All 24 golden pipeline templates and consultative quantile/skewness queries verified live via `udm_search`.


## 📦 Version 2.8.3 (October 27, 2026) — The Bilateral UEBA Harness Co-Execution, Telemetry Physics & Window Guardrail & Multi-Plane CTI / Exploit Synthesis

* **Bilateral UEBA Harness Co-Execution (`SKILL.md`, `references/statistical-hunting-cooperative-framework.md` §8)**:
  * Added **Bilateral UEBA Harness Co-Execution** to `0. Pre-Flight Routing Interceptor`: when an analyst asks for an open-ended "UEBA solution" to detect a threat, exploit, vulnerability, CTI report (e.g., `http2shell` / `CVE-2026-111497`), or curated detection gap without restricting `Active Skill: secops-statistical-hunter`, co-executes with `secops-risk-metrics-multistage` and `agentic_ueba` (`PlaybookRunner`) rather than emitting a single-skill delegation card or discarding UEBA.
  * Preserves 100% of single-skill Pre-Flight Routing Interceptor delegations whenever `Active Skill: secops-statistical-hunter` is specified or when a single-skill 30d `metrics.*` / peer cohort / 360° radar request is made.
* **Strict Telemetry Physics & Window Guardrail (`SKILL.md`, `references/statistical-hunting-cooperative-framework.md` §8)**:
  * Enforces the bilateral boundary: `secops-risk-metrics-multistage` owns all 30-day (`by 1d`) volumetric, failure, and ratio baselines (`metrics.*`), while `secops-statistical-hunter` executes strictly over bounded windows (`1h–24h` for high-volume HTTP/DNS/network logs or `7d–14d` for filtered/sparse process transitions using `by 5m`, `by 1h`, `by 2h`, `by 1d`) for structural/sequence anomalies (`MARKOV_2GRAM_TRANSITION_RARITY`, `SHANNON_ENTROPY_CHARACTER`, `POISSON_BURST_CLUSTERING`, `EWMA_BURST_VELOCITY`, `C2_BEACONING_JITTER`, `ZIPFIAN_PROCESS_RARITY`), chained via `PlaybookRunner` Options 1–3 (`hybrid_metric_raw_enrichment_2stage.yl2`, `/* UPSTREAM_CANDIDATE_IPS */` seeding, or `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` loopback).
  * Strictly prohibits running 30-day raw UDM baseline scans over high-volume telemetry (`metrics.*` domains such as VPC flow logs, DNS, HTTP, Auth, or Process counts).
* **Verification**:
  * **Unit Test Suite**: `178 / 178` unit tests (`18` subtests) passing (`100%`), with `SKILL.md` maintained within the `28.0 KB` ceiling (`28,663` bytes / `230` lines).
  * **Live Dual-Engine Regression (`secops-regress`)**: `23 / 23` (`100.0%`) passing on `Direct MCP` and `100%` pass rate across all Pre-Flight Routing Interceptor (`SH-P1-03`, `SH-P1-04`, `SH-P1-05`, `SH-P1-06`) and micro-model tests (`SH-P1-09` through `SH-P1-12`) on both engines.


## 📦 Version 2.8.2 (October 21, 2026) — Full Audit Remediation: Compiler-Safe `if()`/Division Guards, Rectified Multi-Sector Fusion, 10-Day ECG Prevalence Invariant & 28.0 KB Progressive-Loading Ceiling

* **Chronicle YARA-L 2.0 Compiler-Safe Outcome `if()` & Division Guards (`templates/pipelines/*.yl2`, `examples/*.yara`)**:
  * Extracted all nested arithmetic and logical expressions out of `if()` true/false return branches into intermediate Outcomes-in-Outcomes (OIO) variables and guarded every division denominator across `bayesian_gamma_shrinkage_4stage.yl2`, `beta_binomial_failure_4stage.yl2`, `dual_baseline_delta_z_3stage.yl2`, `ewma_burst_velocity_2stage.yl2`, `hybrid_entropy_concentration_2stage.yl2`, `impossible_travel_geo_velocity_2stage.yl2`, `log_normal_volume_surge_2stage.yl2`, `markov_2gram_transition_rarity_2stage.yl2`, `multi_sector_threat_fusion_4stage.yl2`, `poisson_rare_surge_2stage.yl2`, `privileged_lateral_expansion_2stage.yl2`, `shannon_entropy_character_2stage.yl2`, `two_part_hurdle_2stage.yl2`, `zipfian_process_rarity_2stage.yl2`, and standalone `.yara` examples.
* **Rectified Euclidean Multi-Sector Threat Fusion (`templates/pipelines/multi_sector_threat_fusion_4stage.yl2`, `examples/multi_sector_threat_fusion.yara`)**:
  * Rectified per-sector Z-scores (`$pos_z = if($z > 0, $z, 0.0)`) prior to squaring in $D = \sqrt{\sum \max(0, Z_i)^2}$ so below-average activity ($Z < 0$) never inflates composite threat distance.
* **10-Day Entity Context Graph (`DERIVED_CONTEXT`) Prevalence Invariant & Epoch-Zero Guards**:
  * Enforced `prevalence.day_count = 10` and `prevalence.rolling_max > 0` across `derived_context_domain_prevalence_3stage.yl2`, `derived_context_file_prevalence_3stage.yl2`, and `derived_context_prevalence_3stage.yl2`, and guarded missing `first_seen_time` / WHOIS `creation_time` (`> 0`) in `global_threat_intel_enrichment_3stage.yl2` so unindexed assets/domains never masquerade as newly registered or infant entities.
* **Python Builder, Clean Hand-Off & Progressive-Loading Ceiling (`scripts/*.py`, `SKILL.md`, `tests/*.py`)**:
  * Updated `scripts/multistage_query_builder.py`, `scripts/clean_handoff.py` (`forwarder_id` support and `allow_zero_values = true` catch-all rule), and `scripts/generate_references.py` so all 18 statistical models and 23 golden pipeline templates are exposed and validated.
  * Updated the `SKILL.md` progressive-loading ceiling in `tests/test_guardrail_contracts.py` to `28.0 KB` (`28,672` bytes) / `275` lines with YAML `description <= 1,024` characters.
* **Verification**:
  * **Unit Test Suite**: `178 / 178` unit tests (`18` subtests) passing (`100%`).
  * **Live Dual-Engine Regression (`secops-regress`)**: `23 / 23` scenarios passing (`100.0%` Invariant Parity across both `AgentAPI` and `Direct MCP` on `gus-sdl`, resolving `SH-P1-10-SHANNON-CHARACTER-ENTROPY`).


## 📦 Version 2.8.1 (October 21, 2026) — Native SecOps UEBA Architectural Demarcation & Silent Zero-BigQuery Guardrail

* **Native SecOps Data Plane Demarcation (`SKILL.md`, `references/scope-exclusions-guardrail.md`)**:
  * Updated the cross-skill Data Plane comparison table and architectural grounding to clarify that both raw UDM multi-stage hunting (`UDM_EVENTS`) and `metrics.*` pre-computed UEBA baselines are 100% native to Google SecOps, leveraging core Google infrastructure.
  * Added a silent conditional anti-hallucination guardrail: never claim or imply that BigQuery powers, computes, or stores `metrics.*` or SecOps UEBA; do not bring up BigQuery unprompted, and if asked about BigQuery's role, state directly that **BigQuery contributes nothing to SecOps UEBA** (appearing only as a monitored customer cloud target in `GCP_CLOUDAUDIT` telemetry).
* **Verification**:
  * **Unit Test Suite**: `173 / 173` unit tests passing (`100%`).
  * **Live Dual-Engine Regression (`secops-regress`)**: `0 / 83` unprompted BigQuery mentions across all 166 conversations; `23 / 23` (`100%`) passing on `Direct MCP` and `22 / 23` (`95.7%`) overall Dual-Engine (`SH-P0-07-WINDOW-ALIGNMENT` resolved to `PASS`).

## 📦 Version 2.8.0 (October 20, 2026) — Impossible Travel Geodesic Velocity, Producer-Consumer Ratio Inversion, `QueryIntegrityGate`, 13 Consultative Deformations & Streamlined 5-Section Reports

* **Two New Golden Statistical Pipeline Templates (`templates/pipelines/`, 21 ──► 23 models)**:
  * **Impossible Travel / Supersonic Geodesic Velocity (`templates/pipelines/impossible_travel_geo_velocity_2stage.yl2`)**:
    * Evaluates physical travel distance ($\text{km}$) and geodesic travel velocity ($\text{km/h}$) across consecutive login coordinates within a time bucket using Chronicle's native Haversine function `math.geo_distance($lon1, $lat1, $lon2, $lat2)`.
    * Flags logins from distinct source IPs exceeding commercial flight velocity (`CONSERVATIVE`: $\ge 1200\text{ km/h}, \ge 800\text{ km}$; `BALANCED`: $\ge 900\text{ km/h}, \ge 500\text{ km}$; `AGGRESSIVE`: $\ge 600\text{ km/h}, \ge 250\text{ km}$).
  * **Producer-Consumer Byte Ratio Inversion (`templates/pipelines/producer_consumer_ratio_inversion_2stage.yl2`)**:
    * Evaluates directional byte asymmetry $\rho = \text{sent\_bytes} / (\text{sent\_bytes} + \text{received\_bytes} + 1.0)$ paired with a per-entity historical outbound byte Z-score.
    * Isolates workstation and client endpoints shifting from net data consumers ($\rho \ll 0.30$) to net data producers ($\rho \ge 0.80$) during staging, exfiltration, or lateral payload hosting.
* **Pre/Post Execution `QueryIntegrityGate` & Data Table Syntax Validation (`scripts/multistage_query_builder.py`, `SKILL.md`)**:
  * Added `QueryIntegrityGate.verify_pre_dispatch()` and `QueryIntegrityGate.verify_backend_response()` to block unresolved template placeholders (`{{...}}`), missing target entity scoping, malformed `%<table_name>.<column>` Data Table syntax (`validate_data_table_syntax`), or Chronicle backend compiler/RPC errors from silently degrading into false `0.00σ` clean baselines.
* **Consultative Worksheet Expansion (`references/consultative-worksheet.md`, `references/statistical-models-taxonomy.md`)**:
  * Expanded the consultative framework from 10 to **13 Behavioral Telemetry Deformations** (adding Deformation 11 Producer-Consumer Role Inversion, Deformation 12 Geospatial / Physical Velocity, and Deformation 13 Graph / Relational Bipartite Fan-Out & Fan-In) with **Executable Disambiguation Controls (`[A]` / `[B]` / `[C]`)**.
  * Regenerated `references/statistical-models-taxonomy.md` with Sections 17–18 covering Geodesic Haversine Velocity and Directional Byte Asymmetry Ratio.
* **Streamlined 5-Section Triage Report (`SKILL.md`, `scripts/multistage_query_builder.py`)**:
  * Removed the redundant `Executed Multi-Stage Query (Verbatim Provenance)` code dump from Section 5 of Turn 2 reports while preserving the 1-Click Manual Raw UDM Drill-Down Query (`text` block) and all 6 forensic evidence pillars.
* **Test Suite & Live Dual-Engine Regression**:
  * **Unit Test Suite**: **173 / 173 unit tests passing (100%)** across 17 test modules.
  * **Golden Templates**: **23 / 23 golden pipeline templates** passing 100% AST and compiler validation.
  * **Live Dual-Engine Regression (`secops-regress`)**: **23 / 23 scenarios passing (`100.0%`)** across both `AgentAPI` (`23/23`) and `Direct MCP` (`23/23`) on `gus-sdl`.

## 📦 Version 2.7.5 (October 19, 2026) — Native Float `confidence_score` & Multi-Sector `SECTOR_VECTOR` UDM Hand-Off

* **`scripts/clean_handoff.py` & `references/clean-handoff-udm-schema.md`**:
  * Single-vector statistical findings now populate `"confidence_score": round(float(z_score), 2)` directly on `security_result[0]` alongside `"risk_score": int(cri_score)`, enabling direct numeric YARA-L (`$top_z = max($e.security_result.confidence_score)`) and SecOps Native Dashboard queries without string/regex parsing.
  * Multi-sector statistical findings (`MULTI_SECTOR_THREAT_FUSION` when `sector_vectors` is passed to `build_synthetic_udm_event()`) now emit unbundled `Peak Vector`, `Peak CRI`, `Peak Z`, and `Breached Vectors` labels, tag `security_result[0]` as `"rule_type": "COMPOSITE_FUSION"`, and append one `"rule_type": "SECTOR_VECTOR"` entry per non-zero sector sorted descending by Z-score in `security_result[1..N]` with native `risk_score` and `confidence_score`.
* **Test Suite**: 169/169 unit tests (`test_multi_sector_fusion_emits_sector_vector_security_results` added in `tests/test_clean_handoff.py`).

## 📦 Version 2.7.4 (October 15, 2026) — Scoped Mode Labels & Cross-Skill Time-Window Clarity

* **Why**: agents that loaded both skills applied this skill's rolling 24-hour window to risk-metrics Mode A hunts. Both skills call their horizons "Mode A" / "Mode B", but this skill's Mode A is a rolling 24-hour raw-event window and the risk-metrics Mode A is today `00:00Z` → now in UTC day buckets.
* **`SKILL.md`**:
  * Clearance question: **Mode A (Rolling 24-Hour Raw-Event Window)** or **Mode B (14-Day Raw-Event Timeline)** (was "24-Hour Snapshot" / "14-Day Timeline"). The default-mode sentence in State 2 uses the new label.
  * New scope line: these raw-event windows belong to this skill only; `secops-risk-metrics-multistage` defines its own Mode A/B and they do not transfer.
  * The words "Mode A" / "Mode B" are unchanged, so routing and clearance detection still match.
* **`references/statistical-hunting-cooperative-framework.md`**: the risk-metrics "Lookback Horizon" no longer says "30-day sliding baseline window". It now says the 30-day baseline is anchored once per search request at its `startTime` day, scored in UTC days (verified in the Malachite query engine, `query_engine/qesql/ueba.go`).
* **Match-window grammar corrected**: `by 24h` is valid YARA-L. On gus-sdl it returns the same `00:00Z` buckets and counts as `by 1d`. `multi-stage-query-guide.md` and `query-auditing-guide.md` no longer call it rejected or invalid. `SKILL.md` (Canonical Match Windows) now says daily buckets are written `by 1d`, and that collapsing the whole search window uses an unbucketed key (`match: $binary`), not a bucket sized to the window. `multistage_query_builder.py` still flags `by 24h`, now as `NONCANONICAL_WINDOW_TOKEN` (was `INVALID_WINDOW_SYNTAX`).
* No template or routing changes.
* **Test Suite**: 168/168 unit tests.

## 📦 Version 2.7.3 (October 8, 2026) — MAD / Modified Z-Score Template Correctness & Cross-Skill MAD Routing

* **Renamed** `templates/pipelines/mad_exfiltration_2stage.yl2` ──► `templates/pipelines/mad_modified_z_4stage.yl2` (the pipeline has 4 stages: `daily_stats` → `median_stats` → `mad_stats` → root). All routing (`ARCHETYPE_TEMPLATE_MAP`), `SKILL.md`, `README.md`, and `references/` pointers updated; history entries below are left as written.
* **Honest scope**: header now describes a standalone MAD / Modified Z hunt over any window or raw field (vs. the sibling `secops-risk-metrics-multistage` skill, which uses MAD as a cross-check next to its 30-day UEBA baseline).
* **New slots**: `{{daily_aggregation}}` (daily observed value; default `count(metadata.id)`, e.g. `sum(network.sent_bytes)` for bytes) and `{{sample_field}}` (evidence sampling; defaulted per event type via `MAD_SAMPLE_FIELD_BY_EVENT_TYPE`). `build_query()` accepts `daily_aggregation=` / `sample_field=`.
* **Math fixes**:
  * Iglewicz-Hoaglin MAD=0 fallback: scale = MAD/0.6745 if MAD > 0, else 1.253314 × meanAD (meanAD computed in `mad_stats`), else `{{dispersion_floor}}`. `$m_z_score = (observed - median) / scale`.
  * `window.median(..., false)` for both the daily median and MAD: the old `true` (`should_ignore_zero_values`) discarded zero deviations of days at the median and inflated MAD. Even-count medians pick one middle value (no interpolation) — documented.
  * Removed the `$baseline_dispersion >= {{min_mad}}` gate that silently dropped perfectly steady entities (and made the old fallback dead code).
  * `{{min_mb}}` renamed to `{{min_daily_volume}}` (it is compared to the daily value, not megabytes).
  * Default Modified-Z cut-off is now 3.5 (BALANCED); CONSERVATIVE 5.0, AGGRESSIVE 3.0.
* **Evidence pillars**: added `$baseline_median` (the 6-pillar `$baseline_mean` slot is retained for the contract and documented as holding the median); `$distinct_binaries` now counts distinct `{{sample_field}}` values on the scored day; `$fleet_prevalence = 0 - 1` is explicitly documented as the uncomputed sentinel (not computed by this per-entity template).
* **Fleet prevalence "not computed" sentinel**: the MAD template now emits `$fleet_prevalence = 0 - 1` (value -1) instead of a fake `1`; a bare `-1` literal is rejected by the compiler (verified live 2026-10-07). `resolve_fleet_prevalence()` treats missing or negative prevalence as unknown; `evaluate_confidence_tier()` caps unknown prevalence at MODERATE, and the triage report shows `not computed` instead of claiming isolation. Documented in the `SKILL.md` 6-pillar contract.
* Added `tests/test_mad_cross_skill_sync.py` (copied verbatim from `secops-risk-metrics-multistage`): name-independent guard that the MAD math is identical in both skills; skips if the sibling repo is absent.
* **Validator**: `validate_multistage_syntax()` now flags `$var = -<number>` (`BARE_NEGATIVE_LITERAL`) and suggests `0 - <number>`. No other template or example in the repo used the pattern.
* **Triage report pivot**: the manual Chronicle filter now uses the hunted `event_type` and entity field (explicit args > inferred from `query_text` via `infer_hunt_scope()` > legacy defaults) and the hunted bucket width (1d for Modified-Z rows) instead of hard-coded `principal.hostname` / `PROCESS_LAUNCH` / 1h. `--format_report` passes `--event_type` and `--query_file`.
* **MAD formula display**: the report shows the full Iglewicz-Hoaglin scale (MAD/0.6745, 1.253314·meanAD fallback, dispersion floor) and states which branch applied to the top row.
* **Documented caveats**: median/MAD are over active days only (zero-activity days emit no row); the scored day is included in its own baseline.
* MAD archetype aliases (`MAD`, `MODIFIED_Z`, ...) now always resolve the `DATA_EXFILTRATION_SPIKE` threshold set (previously fell back to Z-score thresholds).
* **Cross-skill MAD routing**: the skill description scopes this skill to standalone MAD over raw fields or custom windows, and names `secops-risk-metrics-multistage` for MAD against a 30-day `metrics.*` baseline on a metric-catalog vector. A new SKILL.md interceptor bullet ("MAD Against a 30-Day / `metrics.*` Baseline") hands off only when that baseline is requested. `test_mad_cross_skill_sync.py` checks both skills' descriptions.
* Added `tests/test_mad_modified_z_template.py` (11 tests). **Test Suite**: 168/168 unit tests across 17 modules (was 136).
* **Dual-engine regression**: 21/21 stats-hunter scenarios pass (SH-P1-10 passed on rerun after a Gemini safety-filter refusal on the first attempt).

## 📦 Version 2.7.2 (September 29, 2026) — Advanced Information-Theoretic & Long-Tail Analytical Models (Markov 2-Gram, Shannon Character Entropy, Zipfian Process Rarity & Intraday EWMA Burst Velocity)

* **Four New Information-Theoretic & Tail-Analysis Analytical Models**:
  * **Markov 2-Gram Transition Rarity (`templates/pipelines/markov_2gram_transition_rarity_2stage.yl2`)**:
    * Evaluates conditional process transition probability $P(B \mid A) = \text{Count}(A \to B) / \text{Count}(A)$ and information surprisal $I(B \mid A) = -\ln P(B \mid A) = \ln(\text{Count}(A)) - \ln(\text{Count}(A \to B))$.
    * Isolates rare Living-off-the-Land execution chains (e.g. `word.exe` $\to$ `cmd.exe`, `sqlservr.exe` $\to$ `powershell.exe`) while ignoring ubiquitous administrative parent-child hierarchies (`services.exe` $\to$ `svchost.exe`).
  * **Shannon Character-Class Entropy (`templates/pipelines/shannon_entropy_character_2stage.yl2`)**:
    * Computes character information density and length ratio over command-line arguments and domain names.
    * Flags obfuscated scripts, base64 payloads, and algorithmic DGA domains that exhibit collapsed compression redundancy.
  * **Power-Law / Zipfian Long-Tail Process Rarity (`templates/pipelines/zipfian_process_rarity_2stage.yl2`)**:
    * Exploits enterprise fleet power-law distributions ($f(k) \propto 1/k^s$) to isolate rare administrative utilities (`vssadmin`, `certutil`, `whoami`) operating in the extreme asymptotic tail ($\le 2$ adopter hosts).
  * **Intraday EWMA Burst Velocity (`templates/pipelines/ewma_burst_velocity_2stage.yl2`)**:
    * Applies recursive exponential weighting ($S_t = \alpha \cdot x_t + (1 - \alpha) \cdot S_{t-1}$, $\alpha = 0.30$) to capture instantaneous rate acceleration without lagging behind abrupt shifts, isolating sudden kinetic bursts from smoothed trailing trajectories.
* **Architecture, Routing & Sensitivity Mapping**:
  * Added conservative, balanced, and aggressive parameter boundaries for all 4 models to `SENSITIVITY_MAP` in `scripts/multistage_query_builder.py`.
  * Registered archetypes and aliases in `MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP` and `HandoffEndpoint.INTENT_ROUTING_MAP`.
  * Expanded golden pipeline templates suite from 17 to 21 (`len(yl2_files) == 21`).
* **Consultative Guidance & Documentation**:
  * Expanded `references/consultative-worksheet.md` with telemetry deformations 7–10 (Lineage Surprisal, Syntactic Entropy, Long-Tail Rarity, Kinetic Acceleration) and new Domain 3/4 consultative options.
  * Regenerated `references/statistical-models-taxonomy.md` (Sections 13–16).
  * Updated `SKILL.md` trigger catalog and physical analogies.
* **Test Suite Expansion & Dual-Engine Regression Validation**:
  * Expanded automated unit test suite from 127 to 136 tests (100% pass rate) in `pytest tests/`.
  * Verified 100% clean AST compilation across all 21 golden pipeline templates (`scripts/multistage_query_builder.py`).
  * Executed 21-scenario maintainer dual-engine regression suite against live Chronicle SIEM tenant (`gus-sdl`):
    * **Dual-Engine Composite**: **20 / 21 scenarios passed (95.2%)**.
    * **AgentAPI Engine**: **21 / 21 scenarios passed (100%)**.
    * **Chronicle YARA-L 2.0 Invariants**: 100% verified across all 21 scenarios.
    * All 4 new model regression scenarios (`SH-P1-09` Markov 2-Gram, `SH-P1-10` Shannon Entropy, `SH-P1-11` Zipfian Long Tail, and `SH-P1-12` Intraday EWMA Burst Velocity) passed cleanly on the first run.

---

## 📦 Version 2.7.1 (September 28, 2026) — Dispersion Denominator Purge, Affirmative Tool Guidance Architecture & Dual-Engine Parity

* **Comprehensive Dispersion Denominator Purge Across Pipeline Templates**:
  * Converted all artificial additive `+ 1.0` dispersion denominators across all 14 pipeline templates (`templates/pipelines/*.yl2`) to canonical nested outcome logic:
    * `$safe_sd = if($sd > 0, $sd, 1.0)`
    * `$safe_dispersion = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)`
  * Completely eliminated statistical distortion in Fano factor, standard score, and Poisson dispersion ratios on quiet baselines without artificial variance blunting.
  * Preserved mathematically legitimate Bayesian updates ($\beta_{\text{post}} = \beta_0 + 1.0$, Beta-Binomial conjugate updating, $\ln(B+1)$ transforms).
  * Harmonized reference documentation in `references/multi-stage-query-guide.md` and `references/statistical-hunting-cooperative-framework.md`.
* **Affirmative Tool Guidance & Lifecycle Architecture in `SKILL.md`**:
  * Systematically purged negative prohibitions ("never execute", "strictly prohibited", "arbitrary case hijacking is strictly forbidden") across all operational phases in favor of clear affirmative guidance.
  * Enforced affirmative execution of Turn 2 multi-stage queries upon clearance and affirmative nominal baseline reporting on zero-finding sweeps.
  * Explicitly codified the hands-off `run_command` restriction: *"There is no blanket approval for `run_command`, only explicit exemptions."* Added unit test contract enforcement (`test_run_command_explicit_exemption_contract_present`).
* **Stripping of Legacy `secops-gus:` Tool Prefixes**:
  * Removed legacy `secops-gus:` tool prefixes across instructions, reference guides, diagrams, and python helpers, aligning with native MCP tool identifiers (`udm_search`, `import_logs`, `create_case_comment`).
* **Chronicle SIEM Compiler Grammar Codification**:
  * Codified explicit syntax requirements for case-insensitive regex matching (`re.regex(<field>, `(?i)...`)`).
  * Codified cross-stage temporal window filtering requirements for downstream stages (`$max_day = max($day_id)` aggregated in Stage 2, bound before `match:` in Stage 3).
* **100% Invariant Parity Across Dual-Engine Regression Suite (17 / 17 Tests Passed)**:
  * Evaluated across all 17 regression test scenarios in dual-engine mode (`agentapi` + `direct-mcp`) with 6 workers against tenant `gus-sdl`, achieving 100% invariant parity across all P0, P1, and P2 contracts.
  * Expanded automated unit test suite to **127 tests (100% pass rate)** in `pytest tests/`.

---

## 📦 Version 2.7.0 (September 27, 2026) — Function Factory Built-Ins, Outcomes-in-Outcomes Inlining, Daily Temporal Spine & Log-Normal Volumetric Surge

* **Function Factory Mathematical Built-Ins (`math.*`) Across Raw UDM Pipelines**:
  * Adopted Chronicle Malachite namespaced mathematical built-ins natively in raw UDM multi-stage queries:
    * `math.sqrt()`: Computes true Euclidean Threat Distance ($D = \sqrt{Z_{\text{auth}}^2 + Z_{\text{proc}}^2 + Z_{\text{net}}^2}$) in multi-sector threat fusion.
    * `math.log()`: Natural logarithm transformation ($\ln(B + 1)$) for variance stabilization over heavy-tailed network and byte telemetry.
    * `math.pow(2.718281828, x)`: Exponential base-$e$ power evaluation (since `math.exp()` does not exist in YARA-L 2.0).
    * 3-argument `if($a > $b, $a, $b)`: Dynamic scalar clamping (since `math.min()` and `math.max()` do not exist in YARA-L 2.0).
    * `math.round()` & `math.pow()`: Integer discretization and power operations directly in YARA-L outcomes.
  * Preserved strict syntax guards rejecting bare `sqrt()` without the `math.` namespace.
* **Outcomes-in-Outcomes (OIO) In-Stage Inlining**:
  * Explicitly codified and enabled native in-stage outcome variable derivation: intermediate and root outcome blocks can directly reference earlier outcome variables within the same stage (e.g., `$diff = $obs - $avg`, `$z = $diff / $safe_sd`).
  * Eliminated artificial stage decomposition previously required to circumvent intermediate variable chaining.
* **Safe Non-Zero Dispersion Floor Guards**:
  * Replaced double-padded denominators and artificial additive floors with exact conditional guards (`$safe_sd = if($sd > 0, $sd, 1.0)` or `$safe_lambda = if($lambda > 0, $lambda, 1.0)`).
  * Implemented robust balanced-parenthesis parsing in the AST validator supporting nested aggregation calls inside `if()` conditionals.
  * Fixed Coefficient of Variation (CV) in `templates/pipelines/c2_beaconing_jitter_2stage.yl2` to calculate $\text{CV} = \sigma / \mu$ cleanly without double-padding distortion.
* **New Golden Pipeline Template: Log-Normal Volumetric Surge (`log_normal_volume_surge_2stage.yl2`)**:
  * Added `templates/pipelines/log_normal_volume_surge_2stage.yl2` implementing parametric log-normal standardization:
    $$Z_{\log} = \frac{\ln(B + 1) - \mu_{\ln}}{\sigma_{\ln}}$$
  * Stabilizes extreme volumetric network egress distributions across enterprise endpoints and applies continuous Sigmoid CRI translation.
* **Timeline Optimization: The Daily Temporal Spine (`by 1d`)**:
  * Updated adaptive window parameter calculation (`get_adaptive_window_parameters`) to automatically select `bucket_size = "1d"` when search horizons reach or exceed 7 days ($\ge 168\text{h}$) for macro-aligned daily models (`MULTI_SECTOR_FUSION`, `LOG_NORMAL_VOLUME`, `DATA_EXFILTRATION_SPIKE`, `TWO_PART_HURDLE`, `DERIVED_CONTEXT_PREVALENCE`, `FLEET_PEER_ZSCORE`, `BAYESIAN_GAMMA_SHRINKAGE`).
  * Slashes intermediate row cardinality by $24\times$ ($336 \rightarrow 14$ rows per entity over 14 days), preventing memory pressure on the analytical engine.
  * Achieves 1:1 metric reconciliation and temporal alignment with `secops-risk-metrics-multistage`.
  * Preserves high-frequency resolution (`10m`, `15m`, `1h`) for intraday and timing jitter archetypes (`C2_BEACONING_JITTER`, `POISSON_BURST_CLUSTERING`).
* **Strengthened Pre-Flight Delegation Interceptor**:
  * Elevated the Pre-Flight Delegation Gate into an affirmative, top-level directive in `SKILL.md`: inquiries containing `"UEBA"`, `"30-day baseline"`, `"peer cohort"`, or `"risk score"` immediately yield the turn with the canonical Markdown Skill Delegation Card (0 tool calls).
  * Strictly forbids consultative discovery or vector selection for requests belonging to `secops-risk-metrics-multistage`.
* **Foundational Reference Guides & Function Factory Documentation**:
  * Added `references/malachite-function-factory-matrix.md` documenting all supported `math.*`, `strings.*`, `arrays.*`, and `timestamp.*` functions over raw UDM event telemetry.
  * Updated `references/statistical-models-taxonomy.md` with Euclidean distance, log-normal standardization, and continuous CRI equations.
  * Updated `references/dynamic-windowing-matrix.md` with the Dual Temporal Spine architecture.

---

## 📦 Version 2.6.1 (September 26, 2026) — DERIVED_CONTEXT File & Domain Prevalence Pipelines, Enterprise-Grounded Consultative Pattern & 100% Dual-Engine Parity

* **`DERIVED_CONTEXT` File & Domain Prevalence Multi-Stage Pipelines**:
  * Added golden pipeline templates:
    * `templates/pipelines/derived_context_file_prevalence_3stage.yl2`: Correlates endpoint `PROCESS_LAUNCH` execution bursts with Chronicle's persistent Entity Context Graph (`DERIVED_CONTEXT` on `FILE` via `target.process.file.sha256 = graph.entity.file.sha256`).
    * `templates/pipelines/derived_context_domain_prevalence_3stage.yl2`: Correlates network outbound flows and DNS queries with `DERIVED_CONTEXT` on `DOMAIN_NAME` (`target.hostname = graph.entity.hostname`).
  * Employs dual-sided enterprise prevalence filtering: suppresses ubiquitous corporate software and domains while applying a 2.5x threat score boost for rare/novel entities with `prevalence.rolling_max <= 3` and `> 0` (`prevalence.day_count = 10`).
* **Enterprise-Grounded Consultative Discovery Pattern**:
  * Expanded `references/consultative-worksheet.md` with the 6th Raw Behavioral Telemetry Deformation: **Enterprise Novelty (First-Contact / Unprecedented Telemetry)**.
  * Cross-pollinated Domains 1 (Endpoint), 3 (Network Egress), and 5 (Identity & Auth) with persistent context and novelty options.
  * Added Section *"The Enterprise-Grounded Hunt & Dual-Sided Prevalence Filtering Pattern"* to provide consultative structure for combining local statistical volume deviations with enterprise-wide novelty.
  * Updated `SKILL.md` (State 1 §2) to proactively offer the two-tier scoping choice: **Tier A (Pure Local Baseline)** vs **Tier B (Enterprise-Grounded Hunt)**.
* **Comprehensive Entity Context Graph Architectural Guide**:
  * Updated `references/entity-context-graph-guide.md` with complete UDM schemas for `FILE`, `DOMAIN_NAME`, `USER`, and `ASSET` graph entities.
  * Documented verified Malachite compiler invariants: `ECG_LIMIT = 1` (at most one graph stage per pipeline), 3-stage + root maximum ceiling, and strict separation of raw event math from graph metadata joins.
  * Updated `scripts/multistage_query_builder.py` with archetype mapping and handoff endpoints for `DERIVED_CONTEXT_FILE_PREVALENCE` and `DERIVED_CONTEXT_DOMAIN_PREVALENCE`.
* **State 1 Protocol Resilience & Single-Tool Ceiling**:
  * Preserved the canonical State 1 header: `### 🚦 State 1: Pre-Flight Clearance & Specification (Interactive Verification Gate)` intact for complete compatibility with frontend parsers, UI widgets, and hybrid interfaces.
  * Reinforced Turn 1 single-tool ceiling in body invariants: strictly capped at at most one 1-shot schema validation probe (`udm_search(..., maxEvents=1)`), maintaining an absolute code embargo on executing multi-stage queries prior to explicit Turn 2 clearance.
  * Corrected Direct MCP harness persona (`direct_mcp_engine.py`) to scope query invariants dynamically and eliminate cross-project `metrics.*` leakage into `stats-hunter`.
* **100% Invariant Parity Across Dual-Engine Regression Suite (15 / 15 Tests Passed)**:
  * Expanded unit tests to **120 passing tests** across 13 test suites (`pytest tests/`).
  * Validated against production tenant `gus-sdl` (`8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5`) across both execution engines (`agentapi` + `direct-mcp`), achieving **15 / 15 Passed (100% Invariant Parity)**.

---

## 📦 Version 2.6.0 (September 25, 2026) — Affirmative Native-Chat Runtime, Universal Pre-Flight Gate, 6 Root Outcome Variables & 15/15 Dual-Engine Regression Parity

* **Option A Affirmative Native-Chat Runtime Architecture**:
  * Established strict architectural separation: Python helper scripts (`scripts/`) are reserved exclusively for offline developer tooling and automated CI testing (`pytest tests/`), while the runtime conversational agent operates natively through Google SecOps MCP tools (`secops-gus:udm_search`, `secops-gus:import_logs`, `secops-gus:create_case_comment`) and Markdown presentations.
  * Purged all agent-facing script execution instructions and CLI invocation examples (`python scripts/...`) from `SKILL.md` and runtime references, ensuring hermetic, native execution within conversational chat environments.
* **Universal Pre-Flight Gate & Interactive Scoping Protocol**:
  * Unified all threat hunting entry points under State 1: all analytical, investigative, and statistical inquiries (whether explicit or open-ended) first formulate the hunting methodology, explain the operational analogy, render a structured Pre-Flight Specification Card, display a candidate query preview, and solicit execution clearance.
  * Standardized the **Pre-Flight Hunting Specification Card** layout in Markdown across six core parameters: Target Entity / Scope, Threat Hypothesis, Baseline Horizon Spine, Statistical Model, Significance Threshold, and Compiler Probe.
  * Enforced the **Single-Cycle Schema Validation Probe**: Turn 1 probes are limited to a 1-shot `udm_search(maxEvents=1)` over a 10-minute ISO 8601 window (capped at 1 initial probe + 1 retry) for schema validation, with an immediate probe-then-yield transition to prevent turn exhaustion.
* **6 Mandatory Root Outcome Variables Protocol**:
  * Codified the standardized 6 root-stage outcome columns across all multi-stage YARA-L pipelines:
    * `$observation_count`: Observed count in the spike window.
    * `$baseline_active_samples`: Historical active baseline sample depth.
    * `$baseline_mean`: Baseline central tendency.
    * `$baseline_dispersion`: Baseline spread / deviation.
    * `$fleet_prevalence`: Enterprise-wide breadth in the window.
    * `$distinct_binaries`: Distinct programs, processes, destination IPs, or targets involved.
  * Generalized `$distinct_binaries` across all telemetry sectors (process launches, network connections, authentication, DNS, file events), cleanly mapping each root outcome variable to its corresponding pillar in the forensic evidence table.
* **Chronicle SIEM Compiler Grammar & Bare Identifier Match Invariants**:
  * Standardized all `match:` expressions to use simple bare identifiers exclusively (`$entity by 1h`, `$entity, $window_start by 1h`), completely eliminating dotted paths in match headers.
  * Enforced **Target Entity Scoping Protocol**: literal entities (`principal.hostname = "dev-ub22-1"`) are bound directly in primary stage event predicates before match binding, anchoring the historical baseline cleanly.
  * Codified linear and deviance formulations (squared Euclidean distance and squared Poisson deviance `$poisson_z_sq = $diff_sq / ($safe_lambda + 1.0)`) complying with Chronicle Malachite compiler grammar without `sqrt()`.
* **Immediate Turn 2 Execution Contract & 5-Section CommonMark Triage Report**:
  * Established deterministic Turn 2 clearance handling: receiving analyst clearance ("Clearance granted", "Proceed", "Go ahead") triggers immediate submission of the full multi-stage YARA-L query via `secops-gus:udm_search(query=...)` over Mode A (24-Hour Snapshot) or the cleared horizon, eliminating secondary clarification stalls.
  * Standardized the 5-Section CommonMark Triage Report layout across all surfaces:
    1. Executive Outlier Report (`### ⚡ Statistical Outlier Report: ...`)
    2. Ranked Outlier Summary table (`#### 📊 Ranked Outlier Summary`)
    3. Top Outlier Spotlight (`#### 🔍 Top Outlier Spotlight: ...`) featuring the 6 Mandatory Forensic Evidence Pillars table (with standard handling for nominal baselines: `#### 🔍 Top Outlier Spotlight: Nominal Baseline (0 Outliers Detected)`)
    4. Chronicle UI Manual Pivot (`#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)` in a single-line `text` code fence)
    5. Statistical & Mathematical Appendix (`<details><summary>🔬 <b>Statistical & Mathematical Appendix</b></summary>` containing the verbatim executed multi-stage query in the report's sole `yara` fence).
* **Pre-Flight Routing Interceptor & Federated Delegation**:
  * Formalized strict-precedence routing interceptor: UEBA keywords, 30-day rolling baselines, pre-computed `metrics.*`, and peer cohorts emit the Markdown Skill Delegation Card routing to `secops-risk-metrics-multistage` (0 tools, immediate turn yield).
  * Sub-second timing jitter, discrete rarity, and raw UDM outlier hunts stay inline under the Expert Bypass Rule.
* **100% Invariant Parity Across Dual-Engine Regression Suite (15 / 15 Tests Passed)**:
  * Evaluated across the complete 15-test regression matrix spanning P0 (Critical Invariants), P1 (Domain Boundaries), and P2 (Surface Integrity) in dual-engine mode (`agentapi` + `direct-mcp`) with 9 concurrent workers against tenant `gus-sdl`.
  * Achieved **15 / 15 Passed (100% Invariant Parity)** with zero regressions and zero persistent defects.
  * De-coached test harness and engine: completely eliminated legacy coaching mandates and coached personas, ensuring rigorous, symmetric testing.
  * Automated offline unit test suite expanded to **116 unit tests** (13 test modules, 100% pass rate).

---

## 📦 Version 2.5.1 (September 10, 2026) — Clean Hand-Off Synthetic UDM Ingestion, Correlated Multi-Finding Batching & Chronicle Specification Conformance

* **Automated Clean Hand-Off (CH) Protocol Engine (`scripts/clean_handoff.py`)**:
  * Implemented dedicated helper module `scripts/clean_handoff.py` for generating, validating, batching, and dispatching synthetic UDM events to Chronicle SIEM and SOAR.
  * Formatted for seamless, in-band ingestion via `secops-gus:import_logs` into Chronicle Event Store (`gus-sdl`, customer `8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5`) using log type `CUSTOM_SECURITY_DATA_ANALYTICS`.
  * Catches synthetic events with the persistent tenant rule `secops_statistical_hunter_alert_catchall` to promote high-significance outliers ($Z \ge 3.0\sigma$, $	ext{CRI} \ge 50$) into security alerts and investigative cases without arbitrary case comment pollution.
* **Official Google Cloud Chronicle UDM Conformance & Invariants**:
  * Corrected obsolete integer resource types (`resource_type: 0`) in `references/clean-handoff-udm-schema.md` to official Chronicle string enumeration `"RESOURCE_TYPE_UNSPECIFIED"`.
  * Standardized complete `observer` metadata block (`hostname: "secops-statistical-hunter"`, `application: "Google SecOps Statistical Outlier Hunter"`).
  * Enforced microsecond-precision ISO 8601 UTC timestamps ending strictly with `Z`.
  * Standardized `security_result` array with MITRE ATT&CK taxonomy (`threat_id_namespace: "MITRE_ATTACK"`), integer Calibrated Risk Index (`risk_score` $0 \le 	ext{CRI} \le 100$), and automated CRI-to-severity mapping (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
* **Multi-Finding Correlated Batching (`build_multi_event_batch`)**:
  * Added native support for multi-event array generation `[ {"udm": ...}, {"udm": ...} ]` for hunts uncovering multiple concurrent outlier entities (e.g. volumetric burst + beaconing + rare exfiltration).
  * Automatically binds all findings in a hunt session under a shared, unique `Hunt Campaign ID` (`hunt-<hex>`) across SIEM events, case attributes, and detection fields.
* **Affirmative Trigger Routing & Pre-Ingestion Clearance Card**:
  * Enforced affirmative intent recognition in `SKILL.md` (*"create a UDM alert"*, *"alert on this"*, *"log in Chronicle"*, *"send this in"*, *"escalate"*, *"generate synthetic event"*).
  * Standardized the Pre-Ingestion Clearance Card format, previewing target tenant, campaign ID, catch-all rule, entity breakdown table, and explicitly yielding the turn (0 tools) for analyst authorization.
* **Direct In-Band API vs. Forwarder Hierarchy**:
  * Designated direct Chronicle API ingestion via IAM credentials as primary, establishing forwarders (`forwarderId`) as strictly optional on-prem network fallback.
  * Formalized resilient operational fallback ladder: if API ingestion is unavailable, delivers structured UDM JSON artifact or provides case comment attachment (`create_case_comment`) if an explicit case ID was specified.
* **Test Suite Expansion & Dual-Engine Regression Suite Validation (93/93 Passed, 100% Green)**:
  * Added `tests/test_clean_handoff.py` (8 tests / 11 subtests) verifying all canonical statistical product event types, schema validation, timestamp conformance, integer resource rejection, batching, clearance card rendering, and payload argument serialization.
  * Re-validated full multi-platform regression test suite in dual-engine mode (AgentAPI & Direct MCP) against tenant `gus-sdl`, verifying 100% invariant parity across all core scenarios and 93/93 passing automated unit tests.

## 📦 Version 2.5.0 (September 10, 2026) — Dual-Client Multi-Platform Regression Suite, Strict Match Binding & Additive Dispersion Floor

* **Dual-Client Multi-Platform Regression Suite (AgentAPI & Direct MCP)**:
  * Integrated full regression harness evaluation against production-like Google SecOps SIEM tenant (`gus-sdl`, `8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5`).
  * Validated across 10 multi-turn test scenarios covering P0 critical invariants, P1 domain boundaries, and P2 presentation/surface integrity.
  * Achieved **100% pass rate (10/10)** with complete cross-engine invariant parity between workspace-based AgentAPI and headless Direct MCP client.
  * Established strict multi-branch reporting federation and ledger isolation (`reports/stats-hunter/branches/main/`) with independent POSIX file locking (`fcntl`), preventing cross-project pollution with `secops-risk-metrics-multistage`.
  * Integrated automated live HTML dashboards, concise launch feedback reporting, and multi-branch master hub navigation (`reports/index.html`).
* **YARA-L 2.0 Match Invariant Enforcement (`ZERO DOTS IN MATCH`)**:
  * Codified and enforced that YARA-L 2.0 `match:` blocks accept strictly simple bare identifiers (`$host by 1h`, `$entity, $ws by 1h`).
  * Prohibited member dot-notation (`$e.principal.hostname`, `$stage1.host`, `$hourly.window_start`) in `match:`, mandating explicit attribute binding in stage event predicates or root bindings prior to `match:` (`$entity = $e.principal.asset.hostname` or `$host = $stage1.host`).
* **Additive Dispersion Floor (`+ 1.0`) Divisor Protection**:
  * Enforced the standardized additive dispersion floor `+ 1.0` in all outcome division expressions across all 14 golden pipeline templates (`templates/pipelines/*.yl2`).
  * Completely eliminates division-by-zero crashes on idle or quiet baselines (`($obs - $mean) / ($std + 1.0)`) without violating the Chronicle Malachite compiler constraint requiring linear expressions in `outcome:` sections.
* **Self-Healing Compiler Syntax Feedback & Grammar Ceilings**:
  * Upgraded query syntax guidance in `references/multi-stage-query-guide.md` and runtime engines with automatic self-healing loops for match dot-notation, `if()` compound expressions, and `re.match` patterns.
  * Codified pre-preview 1-shot compiler probing restricted to single-event UDM filters (`metadata.event_type = "..."`) with strict ISO 8601 timestamps against a 10-minute horizon, capped at 2 probes maximum.
  * Banned non-linear functions like `sqrt()` / `math.sqrt()`, standardizing Poisson deviance and Euclidean distances on squared formulations (`$diff_sq / ($safe_lambda + 1.0)` with threshold $3.5^2 = 12.25$).
* **Affirmative Guidance Directives in `SKILL.md`**:
  * Refactored negative constraint directives into positive, constructive engineering guidance throughout `SKILL.md`.
  * Enforced standardized 5-Section CommonMark Triage Reporting and 6 Forensic Evidence Pillars across all hunt responses.

---

## 📦 Version 2.4.2 (September 9, 2026) — Entity Context Graph (GLOBAL_CONTEXT & DERIVED_CONTEXT), 1–3 Named Stage Ceiling & Regression Suite

* **Entity Context Graph (ECG) Architecture & Golden Pipeline Templates (New Feature)**:
  * Added `references/entity-context-graph-guide.md` codifying Chronicle's Entity Context Graph integration for both `GLOBAL_CONTEXT` (GCTI threat intelligence, WHOIS Newly Registered Domains (NRD), SafeBrowsing) and `DERIVED_CONTEXT` (enterprise entity prevalence, asset/user first-seen time, and last-seen time).
  * Added `templates/pipelines/global_threat_intel_enrichment_3stage.yl2`:
    * Multi-stage YARA-L 2.0 pipeline (3 named intermediate stages + 1 root stage) correlating raw network connection volume bursts with WHOIS NRD / GCTI threat intelligence, positive divisor protection, and standardized 6 Evidence Pillars output for SOC triage.
  * Added `templates/pipelines/derived_context_prevalence_3stage.yl2`:
    * Multi-stage YARA-L 2.0 pipeline (3 named intermediate stages + 1 root stage) hunting authentication anomalies against newly commissioned, unestablished assets using `DERIVED_CONTEXT` asset first-seen time age evaluation (`$asset_age_days < 7.0`), positive divisor protection, and standardized 6 Evidence Pillars output.
  * Codified Chronicle F1 compiler invariants for ECG: maximum 1 ECG graph alias per stage, zero event arithmetic on graph records, and linearized `if()` expressions.
* **Stage Allowance Boundary Enforcement (1–3 Named Stages + 1 Root Stage) (Specification Fix & Hardening)**:
  * Corrected multi-stage query guidance in `references/multi-stage-query-guide.md` and compiler guardrails to strictly enforce the Google SecOps platform constraint of **1 to 3 named intermediate stages plus 1 unwrapped root stage** (up to 4 stages total).
  * Added validator enforcement in `scripts/multistage_query_builder.py` (`len(stages) > 3`) rejecting any pipeline that defines $> 3$ named intermediate stages (`STAGE COUNT LIMIT EXCEEDED`).
* **Federated Intent Routing & Ingestion for ECG (New Feature)**:
  * Registered `GLOBAL_THREAT_INTEL`, `GLOBAL_THREAT_INTEL_ENRICHMENT`, `GLOBAL_CONTEXT`, `GCTI_ENRICHMENT`, `WHOIS_NRD_EGRESS`, `DERIVED_CONTEXT_PREVALENCE`, `DERIVED_CONTEXT`, `ASSET_AGE_PREVALENCE`, and `NEW_ASSET_AUTHENTICATION` in `MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP`, `HandoffEndpoint.INTENT_ROUTING_MAP`, and `SENSITIVITY_MAP`.
  * Updated `audit_query_execution()` to recognize `GLOBAL_THREAT_INTEL_4STAGE` and `DERIVED_CONTEXT_4STAGE`.
* **Consultative Intent Catalog & Non-Statistician Analogies (New Feature)**:
  * Added *"The Flash in the Dark"* (`GLOBAL_THREAT_INTEL`) and *"The Unfamiliar Machine"* (`DERIVED_CONTEXT_PREVALENCE`) operational concepts, trigger keywords, and sensitivity band parameters to `SKILL.md` and `references/statistical-models-taxonomy.md`.
* **Golden Pipeline Template Portfolio Expansion**:
  * Expanded portfolio to **14 golden multi-stage pipeline templates** (all 14 pass compiler grammar, AST scope, and positive divisor validation).
* **Automated Regression Test Suite Expansion**:
  * Expanded automated test suite to **85 unit and regression tests** across 8 test modules with 100% pass rate.
  * Added `tests/test_global_context_syntax.py` (7 tests) verifying ECG syntax compilation, graph entity limit enforcement, safe divisor injection, and federated handoff ingestion for ECG intents.
  * Added `test_reject_excessive_named_stages` in `tests/test_compiler_grammar.py` verifying stage limit enforcement.
  * Confirmed 100% cross-repository regression compatibility with `secops-risk_metrics-multistage` (193/193 tests passing; 278/278 total passing ecosystem-wide).

---

## 📦 Version 2.4.1 (September 9, 2026) — Privileged Account Lateral Movement, Divisor Hardening & Two-Part Hurdle

* **Privileged Account Lateral Movement & Destination Breadth Expansion (New Feature)**:
  * Added `templates/pipelines/privileged_lateral_expansion_2stage.yl2`:
    * Multi-stage YARA-L 2.0 pipeline measuring daily unique destination machine footprint (`count_distinct(target.asset.hostname)`) across an ad-hoc bounded lookback window (e.g. 90 days) on raw `USER_LOGIN` events.
    * Incorporates Active Directory privileged account qualification (`$user in %privileged_ad_accounts` or naming convention regex).
    * Evaluates destination breadth expansion ($Z_{\text{breadth}} = \frac{k - \mu_{\text{dest}}}{\sigma_{\text{dest}} + 0.001}$) and isolates visits to internal workstations/servers with zero prior access history.
    * Standardized 6 Evidence Pillars output for SOC triage.
* **Safe Zero-Divisor Hardening Across Golden Templates (Bug Fix & Stability)**:
  * Hardened arithmetic divisions across all golden multi-stage pipeline templates (`templates/pipelines/*.yl2`) using explicit positive divisor gating (`if($sd > 0, $sd, 1.0)` and `if($mean > 0, $mean, 1.0)`).
  * Prevents Chronicle F1 query execution runtime crashes during low-activity or calm operational windows where baseline dispersion ($\sigma$) or mean ($\mu$) equals zero.
* **Two-Part Hurdle Model Pipeline Template (New Feature)**:
  * Added `templates/pipelines/two_part_hurdle_2stage.yl2` separating zero-inflated binary occurrence hurdle ($\Pr(Y > 0)$) from conditional continuous/count severity ($\text{E}[Y \mid Y > 0]$).
* **Federated Intent Routing & Ingestion (New Feature)**:
  * Added `PRIVILEGED_LATERAL_EXPANSION`, `LATERAL_MOVEMENT_BIPARTITE`, `BIPARTITE_AUTH_RARITY`, and `UNSEEN_ENDPOINT_ACCESS` to `HandoffEndpoint.INTENT_ROUTING_MAP` and `MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP`.
  * Seamlessly receives and ACKs incoming handoff payloads from `secops-risk-metrics-multistage`.
* **Consultative Intent Catalog & Non-Statistician Analogies (New Feature)**:
  * Added *"The Explorer off the Beaten Path"* operational concept and trigger keywords to `SKILL.md` and created `references/consultative-worksheet.md`.
* **Golden Pipeline Template Portfolio**:
  * Expanded portfolio to **12 golden multi-stage pipeline templates** (all 12 pass compiler grammar and AST scope validation).
* **Automated Unit Test Suite Expansion**:
  * Expanded automated test suite to **77 unit tests** across 10 test modules with 100% pass rate (added `test_ingest_valid_handoff_privileged_lateral_expansion` and divisor validation tests).

---

## 📦 Version 2.4.0 (September 7, 2026) — Dynamic Root-Stage Condition Filtering, Anti-Degradation Audit & 6 Hybrid Models

* **Dynamic Root-Stage Condition Filtering & Noise Level Steering**:
  * Enabled root-stage condition filtering and noise level steering in `MultiStageTemplateRouter`.
  * Support sensitivity bands, single thresholds, and compound boolean expressions in condition blocks.
* **Anti-Degradation Auditing**:
  * Upgraded `PostFlightExecutionAuditor` to detect stage degradation and enforce user narrative concordance.
* **6 Hybrid Mathematical Models**:
  * Diversity Deficit, Elephant Flow Concentration, Orthogonal Threat Space, Bayesian Joint Odds, Two-Part Hurdle, and Fleet Prevalence Normalization.
  * Canonical 2-stage raw UDM pipeline for Diversity Deficit & Elephant Flow Concentration (`hybrid_entropy_concentration_2stage.yl2`).
* **AST Guardrails**:
  * Added AST guardrails for root stage events blocks and match member dot-notation.
* **Code-as-Single-Source-of-Truth Reference Generator**:
  * Implemented `scripts/generate_references.py` to auto-generate reference docs from Python schemas.
* **Automated Test Suite Expansion**:
  * Expanded test suite to 75 unit tests with 100% pass rate.

---

## 📦 Version 2.3.3 (September 5, 2026) — Dual-Plane Hybrid Enrichment Routing & Section 7 Framework Sync

* **Dual-Plane & Telemetry Enrichment Intent Routing**:
  * Added routing support in `HandoffEndpoint.INTENT_ROUTING_MAP` and `MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP` for:
    * `RAW_TELEMETRY_ENRICHMENT` ──► `DATA_EXFILTRATION_SPIKE` (`mad_exfiltration_2stage.yl2`)
    * `TELEMETRY_ENRICHMENT` ──► `DATA_EXFILTRATION_SPIKE` (`mad_exfiltration_2stage.yl2`)
    * `DUAL_PLANE_CORRELATION` ──► `DATA_EXFILTRATION_SPIKE` (`mad_exfiltration_2stage.yl2`)
    * `DUAL_PLANE_HYBRID` ──► `DATA_EXFILTRATION_SPIKE` (`mad_exfiltration_2stage.yl2`)
  * Enables seamless two-phase federated handoff from `secops-risk-metrics-multistage` (Phase 1 macro baseline sieve ──► Phase 2 micro telemetry enrichment on candidate entities).
* **Bilateral Framework Synchronization**:
  * Synchronized Section 7 (*Dual-Plane Macro Baseline + Micro Telemetry Enrichment*) into `references/statistical-hunting-cooperative-framework.md`, documenting Pattern A (Intra-Query Golden Template) and Pattern B (Two-Phase Federated Funnel).
* **Automated Test Suite Expansion**:
  * Added unit tests in `tests/test_handoff_endpoint.py` verifying `RAW_TELEMETRY_ENRICHMENT` and `DUAL_PLANE_CORRELATION` handoff ingestion, returning `HANDOFF_ACK_ACCEPTED` and `STEP_OUT_CONFIRMED` (66/66 tests passing).

---

## 📦 Version 2.3.2 (September 5, 2026) — Federated Ingestion Endpoint, Intent Routing & Handoff Protocol

* **Federated Threat Hunt Ingestion Endpoint (`--ingest_handoff`)**:
  * Implemented `HandoffEndpoint` in `scripts/multistage_query_builder.py` accepting JSON envelope payloads conforming to `secops-threat-hunt-handoff-v1`.
  * Validates protocol, target skill, search window, and entity parameters.
* **Dynamic Intent Routing Engine**:
  * Added `INTENT_ROUTING_MAP` supporting intent-to-template compilation:
    * `SCHEDULED_EXFILTRATION_TIMING` / `C2_BEACONING_JITTER` ──► `templates/pipelines/c2_beaconing_jitter_2stage.yl2`
    * `POISSON_BURST_CLUSTERING` ──► `templates/pipelines/poisson_burst_clustering_2stage.yl2`
    * `POISSON_RARE_SURGE` ──► `templates/pipelines/poisson_rare_surge_2stage.yl2`
    * `DATA_EXFILTRATION_SPIKE` ──► `templates/pipelines/mad_exfiltration_2stage.yl2`
    * `DUAL_BASELINE_DELTA_Z` ──► `templates/pipelines/dual_baseline_delta_z_3stage.yl2`
    * `ZSCORE_PROCESS_SURGE` ──► `templates/pipelines/zscore_process_surge_2stage.yl2`
* **Mutual ACK Contract & Step-Out Directive**:
  * Returns standardized acknowledgment: `HANDOFF_ACK_ACCEPTED`, `STEP_OUT_CONFIRMED`, compiled YARA-L 2.0 query, and formal `step_out_directive`.
* **Cooperative Framework Documentation**:
  * Documented Section 6 (*The Federated Handoff Protocol*) in `references/statistical-hunting-cooperative-framework.md`.
* **Automated Test Suite**:
  * Added `tests/test_handoff_endpoint.py` covering valid ingestion, intent routing, schema rejection, and step-out directive contracts (64/64 tests passing).

---

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
