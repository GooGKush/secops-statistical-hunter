<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->

# Mathematical Models & Statistical Taxonomy for Threat Hunting

This reference details the mathematical physics, derivations, and formulas used across `secops-statistical-hunter`.

---

## 1. Leave-One-Out Parametric Historical Standardization ($Z$-Score)
* **Goal**: Detect sudden vertical bursts in volume over an out-of-sample Gaussian historical baseline.
* **Formula**:
  $$Z = \frac{x_t - \mu_{-t}}{\max\left(s_{-t}, \sqrt{\max(\mu_{-t}, 1.0)}\right)}$$
* **Where**:
  - $x_t$: Scored bucket observation count (`$observation_count`).
  - $\mu_{-t}, s_{-t}$: Leave-one-out ($n - 1$) sample mean and sample standard deviation excluding bucket $t$.
* **Guards**: Replaces brittle `min_sd` condition cliffs with the continuous Poisson floor $\sqrt{\max(\mu_{-t}, 1.0)}$.

---

## 2. Poisson-Gamma Bayesian Predictive Standardization (`BAYESIAN_GAMMA_SHRINKAGE`)
* **Goal**: Isolate high-confidence bursts on stable hosts while shrinking steady overdispersed servers.
* **Leave-One-Out Conjugate Gamma Prior & Excess Overdispersion**:
  $$\alpha_{\text{prior}} = \alpha_0 + S_{-t}, \quad \beta_{\text{prior}} = \beta_0 + T_{\text{prior}}, \quad \mu_0 = \frac{\alpha_{\text{prior}}}{\beta_{\text{prior}}}$$
  $$\sigma_{\text{pred}}^2 = \max\left(1.0, \mu_0 \frac{\beta_{\text{prior}} + 1}{\beta_{\text{prior}}} + \max\left(0, \frac{Q_{-t}}{T_{\text{prior}}} - \bar{x}_{-t}^2 - \bar{x}_{-t}\right)\right), \quad Z_{\text{Bayes}} = \frac{x_t - \mu_0}{\sqrt{\sigma_{\text{pred}}^2}}$$

---

## 3. Beta-Binomial Predictive Failure Standardization (`BETA_BINOMIAL_FAILURE`)
* **Goal**: Regularize small-sample failure ratios while suppressing accounts with chronically elevated historical failure rates.
* **Leave-One-Out Conjugate Beta Prior**: $\alpha_{\text{prior}} = 1.0 + F_{-t}, \quad \beta_{\text{prior}} = 19.0 + (N_{-t} - F_{-t}), \quad p_0 = \frac{\alpha_{\text{prior}}}{M}$, where $M = \alpha_{\text{prior}} + \beta_{\text{prior}}$.
* **Predictive Failure $Z$-Score (`$fail_z`)**:
  $$\text{Var}_{\text{pred}} = \max\left(0.25, n_t p_0 (1 - p_0) \frac{M + n_t}{M + 1}\right), \quad Z_{\text{fail}} = \frac{f_t - n_t p_0}{\sqrt{\text{Var}_{\text{pred}}}}$$

---

## 4. Dual-Baseline Delta-$Z$ ("The Patch Tuesday Shield")
* **Goal**: Isolate targeted endpoint spikes from company-wide software deployments across mature peers.
* **Formula**:
  $$\Delta Z = Z_{\text{Personal, LOO}} - \max(0, Z_{\text{Fleet Mature Shift}})$$
* **Behavior**:
  - Company-wide deployment across mature peers: $Z_{\text{Personal}} \approx 12.0$, $Z_{\text{Fleet}} \approx 12.0 \implies \Delta Z \approx 0.0$ (Suppressed).
  - Targeted single-host attack: $Z_{\text{Personal}} \approx 12.0$, $Z_{\text{Fleet}} \approx 0.0 \implies \Delta Z \approx 12.0$ (Triggered).

---

## 5. Multi-Sector Threat Fusion ("Combined Arms Radar")
* **Goal**: Detect coordinated low-and-slow kill chains across Auth, Endpoint, and Network silos.
* **Orthogonal Euclidean Threat Vector Distance**:
  $$D = \sqrt{Z_{\text{Auth}}^2 + Z_{\text{Process}}^2 + Z_{\text{Network}}^2}$$
* **YARA-L Optimization**: Evaluated via squared distance $D^2 = Z_1^2 + Z_2^2 + Z_3^2 \ge 9.0$ ($D \ge 3.0\sigma$).

---

## 6. Poisson Dispersion / Fano Factor ($F$)
* **Goal**: Detect synchronized attack pulses, brute-force waves, and beaconing bursts.
* **Formula**:
  $$F = \frac{\sigma^2}{\mu}$$
* **Interpretation**:
  - $F \approx 1.0$: Pure random Poisson background noise (human activity).
  - $F \gg 3.0$: Heavy super-Poisson clustering (automated attack scripts).

---

## 7. Destination Diversity & Concentration Screen (`HYBRID_ENTROPY_CONCENTRATION`)
* **Goal**: Detect destination diversity collapse paired with single-flow outbound byte concentration using strictly non-negative thresholds.
* **Formulas**:
  $$Z_{\text{deficit}} = \max\left(0, \frac{\mu_{d,-t} - d_t}{\max(s_{d,-t}, \sqrt{\max(\mu_{d,-t}, 1.0)})}\right), \quad \text{ConcRatio} = \frac{\text{PeakBytes}_t}{\max(\text{SumBytes}_t, 1)}$$
  $$\text{ThreatScore} = 3.0 \cdot \sqrt{\left(\frac{Z_{\text{deficit}}}{Z_{\min}}\right)^2 + \left(\frac{\text{ConcRatio}}{C_{\min}}\right)^2}$$

---

## 8. Elephant Flow Concentration Ratio
* **Goal**: Detect single massive exfiltration bursts masked within routine traffic.
* **Formula**:
  $$\text{Concentration Ratio} = \frac{\text{Peak Transfer}}{\max(\sum \text{Transfers}, 1)}$$
* **Interpretation**:
  - Extreme concentration ($\text{Concentration Ratio} \ge 0.65$) indicates an isolated elephant flow.

---

## 9. Multiple-Comparison Fleet Correction (Bonferroni Extreme Value Bound)
* **Goal**: Scale anomaly thresholds automatically when scanning large fleets ($N$ hosts).
* **Formula**:
  $$Z_{\text{adj}} = \max\left(Z_{\text{base}}, \sqrt{2 \ln N}\right)$$

---

## 10. Multi-Sector Orthogonal Euclidean Threat Distance ($D$)
* **Goal**: Synthesize multi-stage kill chains across Authentication, Endpoint, and Network into a single orthogonal Euclidean distance norm using Malachite Function Factory `math.sqrt()`.
* **Formula**:
  $$D = \sqrt{\sum_{i=1}^{k} Z_i^2} = \text{math.sqrt}(Z_{\text{auth}}^2 + Z_{\text{proc}}^2 + Z_{\text{net}}^2)$$
* **Interpretation**:
  - Replaces squared-distance workarounds ($D^2$) with true Euclidean metric distance $D \ge 3.0\sigma$.

---

## 11. Leave-One-Out Log-Normal Volumetric Standardization ($Z_{\log}$)
* **Goal**: Isolate extreme byte bursts over heavy-tailed, skewed network and data exfiltration streams without parametric Gaussian distortion.
* **Formula**:
  $$Y_t = \text{math.log}(\text{bytes}_t + 1.0), \quad Z_{\log} = \frac{Y_t - \mu_{Y,-t}}{\max(s_{Y,-t}, 0.25)}$$
* **Interpretation**:
  - Leave-one-out log-standardization with a continuous $0.25$ log-SD floor suppresses routine $<2\times$ jitter while keeping all 6 Evidence Pillars in byte units.

---

## 12. Continuous Calibrated Risk Index (CRI [0–100]) Post-Processing & Translation
* **Goal**: Translate raw multi-stage $Z$-scores or threat distances into a bounded [0, 100] SOC operational triage index.
* **Piecewise Logistic Sigmoid Formula** (computed in Python post-processing via `calculate_cri()`, or in YARA-L outcome expressions using `math.pow(2.718281828, ...)` since `math.exp()` is not registered in the Malachite YARA-L 2.0 function factory):
  $$\text{CRI}(Z) = \begin{cases} 0 & Z \le 0 \\ \text{round}\left(\frac{100.0}{1.0 + 2.718281828^{-0.6 \cdot (Z - 3.0)}}\right) & Z > 0 \end{cases}$$
* **YARA-L 2.0 Outcome Equivalent**:
  `$cri = if($z_score <= 0, 0, math.round(100.0 / (1.0 + math.pow(2.718281828, (0 - 0.6) * ($z_score - 3.0)))))`

---

## 13. Markov 2-Gram Laplace-Smoothed Transition Surprisal (`MARKOV_2GRAM_TRANSITION_RARITY`)
* **Goal**: Detect rare living-off-the-land process execution chains and unusual parent-child lineages without artificial step cliffs.
* **Formula**:
  $$P(B \mid A) = \frac{\text{Count}(A \to B) + 1.0}{\text{Count}(A) + V}, \quad \text{Score} = \ln\left(\frac{\text{Count}(A) + V}{\text{Count}(A \to B) + 1.0}\right)$$
* **Interpretation**:
  - Whole-window Laplace smoothing ($V = 100$) enables single rare macro-to-shell transitions (`winword.exe` $\to$ `powershell.exe`) to score $\ln(101/2) \approx 3.92 \ge 3.0$ while decaying smoothly and monotonically.

---

## 14. Length-Normalized Shannon Entropy (`SHANNON_ENTROPY_CHARACTER`) & Long-String Screen (`LONG_STRING_SCREEN` — long-string screen)
* **Goal**: Measure exact per-character Shannon entropy $H(s) = -\sum_c p(c)\log_2 p(c)$ (bits/char) on `{{token_field}}` standardized against length-matched $[0.65 L, 1.50 L]$ multi-host benign strings via `scripts/micro_python_helpers.py shannon` (`WS6-03`), while preserving `LONG_STRING_SCREEN` (`long_string_screen_2stage.yl2`) as the stateless in-query **long-string screen** (`D6 G5`).
* **Formulas**:
  $$Z_H = \frac{H(s) - \mu_{H,\text{benign}(L)}}{\max(\sigma_{H,\text{benign}(L)}, 0.15)}, \quad \text{ScreenScore} = \ln(\text{Length}) + \ln\left(1.0 + \frac{N_{\text{entity}}}{N_{\text{token}}}\right)$$
* **Guards**: Enforces minimum token length ($L \ge 25$ in `BALANCED`) on parameterized `{{token_field}}`, requires $\ge 3$ benign reference strings (`INSUFFICIENT_BENIGN_LENGTH_COHORT` fail-closed), and fails closed with `"this model needs a client that can run local scripts"` when `--no-local-scripts` is set.
* **Interpretation**:
  - Separates genuinely random base64/encrypted/DGA strings from equally long low-entropy enterprise CLI paths.

---

## 15. Host-Prevalence Inverse Document Frequency Rarity (`ZIPFIAN_PROCESS_RARITY`)
* **Goal**: Isolate rare binaries in the enterprise long tail by pure host adoption breadth without mixing event volume and host counts.
* **Formula**:
  $$\text{ZipfScore} = \ln\left(\frac{N_{\text{fleet hosts}}}{N_{\text{adopter hosts}}}\right)$$
* **Interpretation**:
  - Novel single-host binaries in a 50-host fleet score $\ln(50/1) \approx 3.91$, strictly outranking chatty multi-host daemons.

---

## 16. Vetted Python-Helper Models (`EWMA_BURST_VELOCITY`, `C2_BEACONING_JITTER`) & Stateless Screens (`BURST_Z_SCREEN` — burst Z, `FLOW_GAP_RATIO_SCREEN` — flow-gap ratio)
* **Goal**: Pair ungated YARA-L extractors with `scripts/micro_python_helpers.py` (`ewma`, `c2-jitter`) under `D6 G1-G5`, while preserving `BURST_Z_SCREEN` (**burst Z**) and `FLOW_GAP_RATIO_SCREEN` (**flow-gap ratio**) for clients without local script execution (`--no-local-scripts`).
* **Formulas**:
  $$S_t = \lambda x_t + (1-\lambda) S_{t-1}, \quad \text{UCL} = \mu_0 + L\,\sigma_0\sqrt{\frac{\lambda}{2-\lambda}}, \quad \text{CV}_{\Delta t} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$
  $$\text{Burst } Z = \frac{x_t - \mu_{-t}}{\max\left(s_{-t}, \sqrt{\max(\mu_{-t}, 1.0)}\right)}, \quad \text{Flow-Gap Ratio CV} = \frac{s_{\text{gap}}}{\max(\mu_{\text{gap}}, 1.0)}$$
* **Where**: `ewma` zero-fills missing buckets across the dense $T$-bucket grid (`PF-4`), `c2-jitter` stitches hourly `array_distinct($ts)` buckets and warns on the 25-element cap while excluding RFC 1918, loopback, multicast (`224.0.0.0/4`, `ff00::/8`), broadcast (`255.255.255.255/32`), and link-local (`169.254.0.0/16`, `fe80::/10`) traffic.

---

## 17. Learned 24-Bin Hour-of-Day Profile (`HOUR_OF_DAY_PROFILE`)
* **Goal**: Detect off-hours or circadian out-of-profile activity per entity without relying on hardcoded UTC business hours or noisy city-centroid geo-velocity (`IMPOSSIBLE_TRAVEL_GEO_VELOCITY` retired under `D1`).
* **Formula**:
  $$\mu_h = \frac{\sum_{t \notin S} x_{t,h}}{D_{\text{base}}}, \quad \sigma_h^2 = \max\left(0, \frac{\sum_{t \notin S} x_{t,h}^2}{D_{\text{base}}} - \mu_h^2\right), \quad \sigma_{\text{safe},h} = \max\left(\sqrt{\sigma_h^2}, \sqrt{\max(\mu_h, 1.0)}\right), \quad Z_{\text{hod}} = \frac{x_{\text{obs},h} - \mu_h}{\sigma_{\text{safe},h}}$$
* **Interpretation**:
  - Scores each hour in the final scoring window out-of-sample against the prior $D_{\text{base}}$ calendar days (zero-count hours included via $D_{\text{base}}$ and stabilized by the continuous Poisson floor $\sqrt{\max(\mu_h, 1.0)}$), alongside `$hour_profile_mass` measuring the entity's historical fraction of activity in hour $h$.

---

## 18. Leave-One-Out Producer–Consumer Ratio Inversion (`PRODUCER_CONSUMER_RATIO_INVERSION`)
* **Goal**: Detect an endpoint shifting from a net data consumer to a net data producer while suppressing steady high-ratio log forwarders.
* **Formula**:
  $$\rho_t = \frac{\text{SentBytes}_t}{\text{SentBytes}_t + \text{ReceivedBytes}_t + 1.0}, \quad Z_{\rho} = \frac{\rho_t - \mu_{\rho,-t}}{\max(s_{\rho,-t}, 0.05)}$$
* **Interpretation**:
  - Dedicated forwarders with steady $\rho \approx 0.90$ yield $Z_{\rho} \approx 0$, whereas a consumer workstation ($\mu_{\rho} \approx 0.10$) inverting to $\rho_t = 0.85$ triggers $Z_{\rho} \gg 3.0$.

---

## 19. Recalibrated Bowley Skewness-Adjusted Tukey Fence Excess $Z$ (`IQR_TUKEY_SKEW_FENCES`)
* **Goal**: Isolate heavy-tailed volumetric surges in scale-invariant standard-deviation units using a single 5-point quantile stage.
* **Formulas**:
  $$\text{SafeIQR} = \max(Q_3 - Q_1, \max(0.01 Q_2, 1.0)), \quad B_{\text{skew}} = \frac{Q_3 + Q_1 - 2 Q_2}{\text{SafeIQR}} \in [-1, +1]$$
  $$\text{Fence}_{\text{adj}} = Q_3 + 1.5 \cdot e^{1.35 \cdot \max(0, B_{\text{skew}})} \cdot \text{SafeIQR}, \quad Z_{\text{fence}} = \frac{x_t - \text{Fence}_{\text{adj}}}{\text{SafeIQR} / 1.349}$$
* **Interpretation**:
  - Recalibrates the Hubert-Vandervieren exponent to $1.35$ for bounded Bowley quartile skewness, replaces fixed IQR cliffs with a continuous relative floor, and frees Stage 3 for enterprise fleet prevalence (`$fleet_prevalence`).

---

## 20. Per-Pipeline Template & Slot Specification Matrix (27 Active Templates)

| Pipeline Template (`.yl2`) | Canonical `SENSITIVITY_MAP` Key | Stages & Execution Mode | Default Event / Entity & Match Spine | Primary Score Outcome (`order:`) | Template `{{slot}}` Placeholders |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `bayesian_gamma_shrinkage_4stage.yl2` | `BAYESIAN_GAMMA_SHRINKAGE` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $host, $ws by {{bucket_size}}` | `$bayesian_z` (`linear`, `order: $bayesian_z desc`) | `{{bayesian_z}}`, `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_count}}`, `{{prior_alpha0}}`, `{{prior_beta0}}`, `{{prior_window_buckets}}`, `{{tier}}` |
| `beta_binomial_failure_4stage.yl2` | `BETA_BINOMIAL_FAILURE` | 4 stages (3 named + root) · In-query SIEM | `USER_LOGIN` / `principal.hostname` · Root `match: $user, $ws by {{bucket_size}}` | `$fail_z` (`linear`, `order: $fail_z desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{fail_z}}`, `{{min_active_samples}}`, `{{min_attempts}}`, `{{min_fails}}`, `{{prior_alpha0}}`, `{{prior_beta0}}`, `{{tier}}` |
| `burst_z_screen_2stage.yl2` | `BURST_Z_SCREEN` | 3 stages (2 named + root) · Stateless screen (`D6-G5` for `ewma`) | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$burst_z` (`linear`, `order: $burst_z desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_count}}`, `{{tier}}`, `{{velocity_threshold}}` |
| `c2_beaconing_jitter_2stage.yl2` | `C2_BEACONING_JITTER` | 4 stages (3 named + root) · Vetted helper: `micro_python_helpers.py c2-jitter` (`D6`; screen: `FLOW_GAP_RATIO_SCREEN`) | `NETWORK_CONNECTION` / `principal.asset.ip` · Root `match: $src_ip, $dst_ip, $ws` | `$total_conns` (`linear`, `order: $total_conns desc`) | `{{bucket_size}}`, `{{cv}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{max_conns}}`, `{{min_active_hours}}`, `{{min_conns}}`, `{{prevalence}}`, `{{tier}}` |
| `derived_context_domain_prevalence_3stage.yl2` | `DERIVED_CONTEXT_DOMAIN_PREVALENCE` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_CONNECTION` / `principal.asset.hostname` · Root `match: $host, $domain, $ws by 1h` | `$threat_score` (`linear`, `order: $threat_score desc`) | `{{ecg_event_time_filter}}`, `{{ecg_scoring_end_epoch}}`, `{{ecg_scoring_start_epoch}}`, `{{entity_field}}`, `{{min_active_hours}}`, `{{min_obs_bytes}}`, `{{rare_multiplier}}`, `{{threat_score}}`, `{{tier}}` |
| `derived_context_file_prevalence_3stage.yl2` | `DERIVED_CONTEXT_FILE_PREVALENCE` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.asset.hostname` · Root `match: $host, $sha256, $ws by 1h` | `$threat_score` (`linear`, `order: $threat_score desc`) | `{{ecg_event_time_filter}}`, `{{ecg_scoring_end_epoch}}`, `{{ecg_scoring_start_epoch}}`, `{{min_active_hours}}`, `{{min_execs}}`, `{{rare_multiplier}}`, `{{threat_score}}`, `{{tier}}` |
| `derived_context_prevalence_3stage.yl2` | `DERIVED_CONTEXT_PREVALENCE` | 4 stages (3 named + root) · In-query SIEM | `USER_LOGIN` / `target.asset.hostname` · Root `match: $user, $host, $ws by 1d` | `$threat_score` (`linear`, `order: $threat_score desc`) | `{{ecg_event_time_filter}}`, `{{ecg_scoring_end_epoch}}`, `{{ecg_scoring_start_epoch}}`, `{{min_active_days}}`, `{{min_logins}}`, `{{new_asset_multiplier}}`, `{{threat_score}}`, `{{tier}}` |
| `dual_baseline_delta_z_3stage.yl2` | `DUAL_BASELINE_DELTA_Z` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $host, $ws by {{bucket_size}}` | `$delta_z` (`linear`, `order: $delta_z desc`) | `{{bucket_size}}`, `{{delta_z}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_active_hosts}}`, `{{min_active_samples}}`, `{{min_host_count}}`, `{{tier}}` |
| `ewma_burst_velocity_2stage.yl2` | `EWMA_BURST_VELOCITY` | 4 stages (3 named + root) · Vetted helper: `micro_python_helpers.py ewma` (`D6`; screen: `BURST_Z_SCREEN`) | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$total_events` (`linear`, `order: $total_events desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_count}}`, `{{tier}}` |
| `flow_gap_ratio_screen_2stage.yl2` | `FLOW_GAP_RATIO_SCREEN` | 4 stages (3 named + root) · Stateless screen (`D6-G5` for `c2-jitter`) | `NETWORK_CONNECTION` / `principal.asset.ip` · Root `match: $src_ip, $dst_ip` | `$cv` (`inverted_ratio`, `order: $cv asc`) | `{{bucket_size}}`, `{{cv}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_active_hours}}`, `{{min_conns}}`, `{{prevalence}}`, `{{tier}}` |
| `global_threat_intel_enrichment_3stage.yl2` | `GLOBAL_THREAT_INTEL_ENRICHMENT` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_CONNECTION` / `principal.asset.hostname` · Root `match: $host, $domain, $ws by 1h` | `$threat_score` (`linear`, `order: $threat_score desc`) | `{{ecg_event_time_filter}}`, `{{ecg_scoring_end_epoch}}`, `{{ecg_scoring_start_epoch}}`, `{{entity_field}}`, `{{min_active_hours}}`, `{{min_obs_bytes}}`, `{{nrd_multiplier}}`, `{{threat_score}}`, `{{tier}}` |
| `hour_of_day_profile_3stage.yl2` | `HOUR_OF_DAY_PROFILE` | 4 stages (3 named + root) · In-query SIEM | `USER_LOGIN` / `principal.hostname` · Root `match: $entity, $hod, $ws by 1h` | `$hod_z_score` (`linear`, `order: $hod_z_score desc`) | `{{baseline_days}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{hod_scoring_end_epoch}}`, `{{hod_scoring_start_epoch}}`, `{{min_active_samples}}`, `{{sample_field}}`, `{{tenant_tz}}`, `{{tier}}`, `{{z_threshold}}` |
| `hybrid_entropy_concentration_2stage.yl2` | `HYBRID_ENTROPY_CONCENTRATION` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_CONNECTION` / `principal.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$threat_score` (`linear`, `order: $threat_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{max_diversity_ratio}}`, `{{min_active_samples}}`, `{{min_concentration_ratio}}`, `{{min_deficit_z}}`, `{{min_events}}`, `{{tier}}` |
| `iqr_tukey_skew_fences_3stage.yl2` | `IQR_TUKEY_SKEW_FENCES` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_DNS` / `principal.hostname` · Root `match: $entity, $window_start by {{bucket_size}}` | `$fence_z` (`linear`, `order: $fence_z desc`) | `{{bucket_size}}`, `{{daily_aggregation}}`, `{{entity_field}}`, `{{event_type}}`, `{{fence_z}}`, `{{min_baseline_days}}`, `{{min_daily_volume}}`, `{{sample_field}}`, `{{tier}}` |
| `log_normal_volume_surge_2stage.yl2` | `LOG_NORMAL_VOLUME_SURGE` | 3 stages (2 named + root) · In-query SIEM | `NETWORK_CONNECTION` / `principal.hostname` · Root `match: $host, $ws by {{bucket_size}}` | `$z_log` (`linear`, `order: $z_log desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_filter}}`, `{{min_active_samples}}`, `{{min_bytes}}`, `{{tier}}`, `{{z_score}}` |
| `long_string_screen_2stage.yl2` | `LONG_STRING_SCREEN` | 3 stages (2 named + root) · Stateless screen (`D6-G5` for `shannon`) | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $entity, $token, $ws by {{bucket_size}}` | `$shannon_entropy_score` (`linear`, `order: $shannon_entropy_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{entropy_threshold}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_length}}`, `{{tier}}`, `{{token_field}}` |
| `mad_modified_z_4stage.yl2` | `DATA_EXFILTRATION_SPIKE` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_DNS` / `principal.hostname` · Root `match: $entity, $window_start by 1d` | `$m_z_score` (`linear`, `order: $m_z_score desc`) | `{{daily_aggregation}}`, `{{dispersion_floor}}`, `{{entity_field}}`, `{{event_type}}`, `{{m_z}}`, `{{min_baseline_days}}`, `{{min_daily_volume}}`, `{{sample_field}}`, `{{tier}}` |
| `markov_2gram_transition_rarity_2stage.yl2` | `MARKOV_2GRAM_TRANSITION_RARITY` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $host, $parent, $child, $ws by {{bucket_size}}` | `$markov_threat_score` (`linear`, `order: $markov_threat_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_parent_count}}`, `{{surprisal_threshold}}`, `{{tier}}`, `{{vocab_smooth}}` |
| `multi_sector_threat_fusion_4stage.yl2` | `MULTI_SECTOR_THREAT_FUSION` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_CONNECTION`, `PROCESS_LAUNCH`, `USER_LOGIN` / `principal.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$threat_distance` (`linear`, `order: $threat_distance desc`) | `{{bucket_size}}`, `{{event_filter}}`, `{{fusion_entity_expr}}`, `{{min_active_samples}}`, `{{min_events}}`, `{{threat_distance}}`, `{{tier}}` |
| `poisson_burst_clustering_2stage.yl2` | `POISSON_BURST_CLUSTERING` | 4 stages (3 named + root) · In-query SIEM | `USER_LOGIN` / `principal.hostname` · Root `match: $entity` | `$fano_factor` (`baseline_offset`, `order: $fano_factor desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{fano_factor}}`, `{{min_burst_fails}}`, `{{min_fails}}`, `{{min_mu}}`, `{{peer_sample_field}}`, `{{tier}}`, `{{total_window_buckets}}` |
| `poisson_rare_surge_2stage.yl2` | `POISSON_RARE_SURGE` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $entity, $tool, $ws by 1d` | `$poisson_z_sq` (`squared`, `order: $poisson_z_sq desc`) | `{{entity_field}}`, `{{event_type}}`, `{{max_lambda}}`, `{{min_baseline_days}}`, `{{min_observed}}`, `{{poisson_z}}`, `{{poisson_z_sq}}`, `{{tier}}`, `{{window_days}}` |
| `privileged_lateral_expansion_2stage.yl2` | `PRIVILEGED_LATERAL_EXPANSION` | 5 stages (4 named + root) · In-query SIEM | `USER_LOGIN` / `target.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$z_score` (`linear`, `order: $z_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_distinct_targets}}`, `{{tier}}`, `{{z_score}}` |
| `producer_consumer_ratio_inversion_2stage.yl2` | `PRODUCER_CONSUMER_RATIO_INVERSION` | 4 stages (3 named + root) · In-query SIEM | `NETWORK_CONNECTION` / `principal.asset.hostname` · Root `match: $entity, $ws by {{bucket_size}}` | `$z_score` (`linear`, `order: $z_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_producer_ratio}}`, `{{min_sent_bytes}}`, `{{tier}}`, `{{z_score}}` |
| `shannon_entropy_character_2stage.yl2` | `SHANNON_ENTROPY_CHARACTER` | 2 stages (1 named + root) · Vetted helper: `micro_python_helpers.py shannon` (`D6`; screen: `LONG_STRING_SCREEN`) | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $token` | `$raw_length` (`linear`, `order: $raw_length desc`) | `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_length}}`, `{{tier}}`, `{{token_field}}` |
| `two_part_hurdle_2stage.yl2` | `TWO_PART_HURDLE` | 3 stages (2 named + root) · In-query SIEM | `USER_LOGIN` / `principal.hostname` · Root `match: $entity, $window_start by {{bucket_size}}` | `$hurdle_threat_score` (`linear`, `order: $hurdle_threat_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_awakening_volume}}`, `{{min_count}}`, `{{tier}}`, `{{z_score}}` |
| `zipfian_process_rarity_2stage.yl2` | `ZIPFIAN_PROCESS_RARITY` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $host, $binary, $ws by {{bucket_size}}` | `$zipf_rarity_score` (`linear`, `order: $zipf_rarity_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_type}}`, `{{max_adopters}}`, `{{min_count}}`, `{{min_fleet_hosts}}`, `{{tier}}`, `{{zipf_threshold}}` |
| `zscore_process_surge_2stage.yl2` | `ZSCORE_PROCESS_SURGE` | 4 stages (3 named + root) · In-query SIEM | `PROCESS_LAUNCH` / `principal.hostname` · Root `match: $entity, $window_start by {{bucket_size}}` | `$z_score` (`linear`, `order: $z_score desc`) | `{{bucket_size}}`, `{{entity_field}}`, `{{event_filter}}`, `{{event_type}}`, `{{min_active_samples}}`, `{{min_count}}`, `{{tier}}`, `{{z_score}}` |

### Retired Dispositions (`D1`)

* **`impossible_travel_geo_velocity_2stage.yl2` (`IMPOSSIBLE_TRAVEL_GEO_VELOCITY`, aliases `IMPOSSIBLE_TRAVEL`, `GEO_VELOCITY`, `SUPERSONIC_TRAVEL`) — Retired (`D1`)**: Removed from active templates and raises a deterministic `ValueError` (`"IMPOSSIBLE_TRAVEL_GEO_VELOCITY is retired (D1): city-centroid geo-velocity and VPN egress produce systematic false positives; use HOUR_OF_DAY_PROFILE or DERIVED_CONTEXT_PREVALENCE instead."`). Use `HOUR_OF_DAY_PROFILE` (`hour_of_day_profile_3stage.yl2`) for circadian out-of-profile login anomalies or `PRIVILEGED_LATERAL_EXPANSION` (`privileged_lateral_expansion_2stage.yl2`) for first-seen destination expansion.

---

## 21. Sensitivity & Anomaly Threshold Map

| Archetype | Tier | Thresholds & Parameters |
| :--- | :--- | :--- |
| `BAYESIAN_GAMMA_SHRINKAGE` | **CONSERVATIVE** | `bayesian_z=4.0`, `min_count=30`, `min_active_samples=60` |
| `BAYESIAN_GAMMA_SHRINKAGE` | **BALANCED** | `bayesian_z=3.0`, `min_count=15`, `min_active_samples=30` |
| `BAYESIAN_GAMMA_SHRINKAGE` | **AGGRESSIVE** | `bayesian_z=2.0`, `min_count=5`, `min_active_samples=14` |
| `BETA_BINOMIAL_FAILURE` | **CONSERVATIVE** | `fail_z=4.0`, `posterior_fail_prob=0.65`, `min_attempts=30`, `min_fails=15`, `min_active_samples=24` |
| `BETA_BINOMIAL_FAILURE` | **BALANCED** | `fail_z=3.0`, `posterior_fail_prob=0.5`, `min_attempts=15`, `min_fails=8`, `min_active_samples=12` |
| `BETA_BINOMIAL_FAILURE` | **AGGRESSIVE** | `fail_z=2.0`, `posterior_fail_prob=0.35`, `min_attempts=8`, `min_fails=4`, `min_active_samples=6` |
| `BURST_Z_SCREEN` | **CONSERVATIVE** | `velocity_threshold=4.0`, `min_count=50`, `min_sd=5.0`, `min_active_samples=60` |
| `BURST_Z_SCREEN` | **BALANCED** | `velocity_threshold=3.0`, `min_count=25`, `min_sd=2.0`, `min_active_samples=30` |
| `BURST_Z_SCREEN` | **AGGRESSIVE** | `velocity_threshold=2.0`, `min_count=10`, `min_sd=1.0`, `min_active_samples=14` |
| `C2_BEACONING_JITTER` | **CONSERVATIVE** | `cv=0.05`, `min_conns=25`, `max_conns=400`, `prevalence=1`, `min_active_hours=12` |
| `C2_BEACONING_JITTER` | **BALANCED** | `cv=0.2`, `min_conns=10`, `max_conns=500`, `prevalence=2`, `min_active_hours=6` |
| `C2_BEACONING_JITTER` | **AGGRESSIVE** | `cv=0.4`, `min_conns=6`, `max_conns=600`, `prevalence=3`, `min_active_hours=3` |
| `CATEGORICAL_FLEET_PREVALENCE` | **CONSERVATIVE** | `max_adopters=1`, `min_events=10`, `min_active_hours=12` |
| `CATEGORICAL_FLEET_PREVALENCE` | **BALANCED** | `max_adopters=2`, `min_events=5`, `min_active_hours=6` |
| `CATEGORICAL_FLEET_PREVALENCE` | **AGGRESSIVE** | `max_adopters=3`, `min_events=2`, `min_active_hours=1` |
| `DATA_EXFILTRATION_SPIKE` | **CONSERVATIVE** | `m_z=5.0`, `min_daily_volume=500`, `dispersion_floor=1.0`, `min_baseline_days=14` |
| `DATA_EXFILTRATION_SPIKE` | **BALANCED** | `m_z=3.5`, `min_daily_volume=100`, `dispersion_floor=1.0`, `min_baseline_days=7` |
| `DATA_EXFILTRATION_SPIKE` | **AGGRESSIVE** | `m_z=3.0`, `min_daily_volume=25`, `dispersion_floor=1.0`, `min_baseline_days=3` |
| `DERIVED_CONTEXT_DOMAIN_PREVALENCE` | **CONSERVATIVE** | `threat_score=3.5`, `min_obs_bytes=1000000.0`, `min_active_hours=24`, `rare_multiplier=2.5` |
| `DERIVED_CONTEXT_DOMAIN_PREVALENCE` | **BALANCED** | `threat_score=2.5`, `min_obs_bytes=100000.0`, `min_active_hours=12`, `rare_multiplier=2.5` |
| `DERIVED_CONTEXT_DOMAIN_PREVALENCE` | **AGGRESSIVE** | `threat_score=1.5`, `min_obs_bytes=10000.0`, `min_active_hours=6`, `rare_multiplier=2.0` |
| `DERIVED_CONTEXT_FILE_PREVALENCE` | **CONSERVATIVE** | `threat_score=3.5`, `min_execs=10`, `min_active_hours=24`, `rare_multiplier=2.5` |
| `DERIVED_CONTEXT_FILE_PREVALENCE` | **BALANCED** | `threat_score=2.5`, `min_execs=5`, `min_active_hours=12`, `rare_multiplier=2.5` |
| `DERIVED_CONTEXT_FILE_PREVALENCE` | **AGGRESSIVE** | `threat_score=1.5`, `min_execs=2`, `min_active_hours=6`, `rare_multiplier=2.0` |
| `DERIVED_CONTEXT_PREVALENCE` | **CONSERVATIVE** | `threat_score=3.5`, `min_logins=10`, `min_active_days=14`, `new_asset_multiplier=2.0` |
| `DERIVED_CONTEXT_PREVALENCE` | **BALANCED** | `threat_score=2.5`, `min_logins=5`, `min_active_days=7`, `new_asset_multiplier=2.0` |
| `DERIVED_CONTEXT_PREVALENCE` | **AGGRESSIVE** | `threat_score=1.5`, `min_logins=2`, `min_active_days=3`, `new_asset_multiplier=1.5` |
| `DISCRETE_ENTITY_RARITY` | **CONSERVATIVE** | `max_adopters=1`, `min_events=10`, `min_active_hours=12` |
| `DISCRETE_ENTITY_RARITY` | **BALANCED** | `max_adopters=2`, `min_events=5`, `min_active_hours=6` |
| `DISCRETE_ENTITY_RARITY` | **AGGRESSIVE** | `max_adopters=3`, `min_events=2`, `min_active_hours=1` |
| `DIVERSITY_DEFICIT` | **CONSERVATIVE** | `min_deficit_z=2.5`, `max_diversity_ratio=0.1`, `min_concentration_ratio=0.8`, `min_events=100`, `min_active_samples=48` |
| `DIVERSITY_DEFICIT` | **BALANCED** | `min_deficit_z=1.5`, `max_diversity_ratio=0.2`, `min_concentration_ratio=0.65`, `min_events=50`, `min_active_samples=24` |
| `DIVERSITY_DEFICIT` | **AGGRESSIVE** | `min_deficit_z=1.0`, `max_diversity_ratio=0.35`, `min_concentration_ratio=0.5`, `min_events=20`, `min_active_samples=12` |
| `DORMANT_ACCOUNT_AWAKENING` | **CONSERVATIVE** | `z_score=4.0`, `min_count=10`, `min_awakening_volume=20`, `dormant_weight=3.0`, `min_active_samples=14` |
| `DORMANT_ACCOUNT_AWAKENING` | **BALANCED** | `z_score=3.0`, `min_count=5`, `min_awakening_volume=10`, `dormant_weight=2.0`, `min_active_samples=7` |
| `DORMANT_ACCOUNT_AWAKENING` | **AGGRESSIVE** | `z_score=2.0`, `min_count=2`, `min_awakening_volume=5`, `dormant_weight=1.5`, `min_active_samples=3` |
| `DUAL_BASELINE_DELTA_Z` | **CONSERVATIVE** | `delta_z=4.0`, `min_count=50`, `min_sd=5.0`, `min_active_samples=60`, `min_active_hosts=10` |
| `DUAL_BASELINE_DELTA_Z` | **BALANCED** | `delta_z=3.0`, `min_count=25`, `min_sd=2.0`, `min_active_samples=30`, `min_active_hosts=5` |
| `DUAL_BASELINE_DELTA_Z` | **AGGRESSIVE** | `delta_z=2.0`, `min_count=10`, `min_sd=1.0`, `min_active_samples=14`, `min_active_hosts=3` |
| `ELEPHANT_FLOW_CONCENTRATION` | **CONSERVATIVE** | `min_deficit_z=2.5`, `max_diversity_ratio=0.1`, `min_concentration_ratio=0.8`, `min_events=100`, `min_active_samples=48` |
| `ELEPHANT_FLOW_CONCENTRATION` | **BALANCED** | `min_deficit_z=1.5`, `max_diversity_ratio=0.2`, `min_concentration_ratio=0.65`, `min_events=50`, `min_active_samples=24` |
| `ELEPHANT_FLOW_CONCENTRATION` | **AGGRESSIVE** | `min_deficit_z=1.0`, `max_diversity_ratio=0.35`, `min_concentration_ratio=0.5`, `min_events=20`, `min_active_samples=12` |
| `EWMA_BURST_VELOCITY` | **CONSERVATIVE** | `velocity_threshold=4.0`, `min_count=50`, `min_sd=5.0`, `min_active_samples=60` |
| `EWMA_BURST_VELOCITY` | **BALANCED** | `velocity_threshold=3.0`, `min_count=25`, `min_sd=2.0`, `min_active_samples=30` |
| `EWMA_BURST_VELOCITY` | **AGGRESSIVE** | `velocity_threshold=2.0`, `min_count=10`, `min_sd=1.0`, `min_active_samples=14` |
| `FLEET_PEER_ZSCORE` | **CONSERVATIVE** | `fleet_z=3.5`, `min_host_count=50`, `min_fleet_sd=10.0`, `min_active_hosts=25` |
| `FLEET_PEER_ZSCORE` | **BALANCED** | `fleet_z=2.5`, `min_host_count=25`, `min_fleet_sd=5.0`, `min_active_hosts=15` |
| `FLEET_PEER_ZSCORE` | **AGGRESSIVE** | `fleet_z=2.0`, `min_host_count=10`, `min_fleet_sd=2.0`, `min_active_hosts=10` |
| `FLOW_GAP_RATIO_SCREEN` | **CONSERVATIVE** | `cv=0.05`, `min_conns=50`, `prevalence=1`, `min_active_hours=12` |
| `FLOW_GAP_RATIO_SCREEN` | **BALANCED** | `cv=0.2`, `min_conns=25`, `prevalence=2`, `min_active_hours=6` |
| `FLOW_GAP_RATIO_SCREEN` | **AGGRESSIVE** | `cv=0.4`, `min_conns=15`, `prevalence=1`, `min_active_hours=3` |
| `GLOBAL_THREAT_INTEL` | **CONSERVATIVE** | `threat_score=4.0`, `min_obs_bytes=1000000.0`, `min_active_hours=24`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL` | **BALANCED** | `threat_score=3.0`, `min_obs_bytes=100000.0`, `min_active_hours=12`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL` | **AGGRESSIVE** | `threat_score=2.0`, `min_obs_bytes=10000.0`, `min_active_hours=6`, `nrd_multiplier=2.0` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **CONSERVATIVE** | `threat_score=4.0`, `min_obs_bytes=1000000.0`, `min_active_hours=24`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **BALANCED** | `threat_score=3.0`, `min_obs_bytes=100000.0`, `min_active_hours=12`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **AGGRESSIVE** | `threat_score=2.0`, `min_obs_bytes=10000.0`, `min_active_hours=6`, `nrd_multiplier=2.0` |
| `HEAVY_TAIL_OUTLIERS` | **CONSERVATIVE** | `fence_z=5.0`, `surge_ratio=3.0`, `min_daily_volume=500`, `min_baseline_days=14` |
| `HEAVY_TAIL_OUTLIERS` | **BALANCED** | `fence_z=3.5`, `surge_ratio=2.0`, `min_daily_volume=100`, `min_baseline_days=7` |
| `HEAVY_TAIL_OUTLIERS` | **AGGRESSIVE** | `fence_z=2.0`, `surge_ratio=1.5`, `min_daily_volume=25`, `min_baseline_days=3` |
| `HOUR_OF_DAY_PROFILE` | **CONSERVATIVE** | `z_threshold=4.0`, `min_active_samples=48` |
| `HOUR_OF_DAY_PROFILE` | **BALANCED** | `z_threshold=3.0`, `min_active_samples=24` |
| `HOUR_OF_DAY_PROFILE` | **AGGRESSIVE** | `z_threshold=2.0`, `min_active_samples=12` |
| `HYBRID_ENTROPY_CONCENTRATION` | **CONSERVATIVE** | `min_deficit_z=2.5`, `max_diversity_ratio=0.1`, `min_concentration_ratio=0.8`, `min_events=100`, `min_active_samples=48` |
| `HYBRID_ENTROPY_CONCENTRATION` | **BALANCED** | `min_deficit_z=1.5`, `max_diversity_ratio=0.2`, `min_concentration_ratio=0.65`, `min_events=50`, `min_active_samples=24` |
| `HYBRID_ENTROPY_CONCENTRATION` | **AGGRESSIVE** | `min_deficit_z=1.0`, `max_diversity_ratio=0.35`, `min_concentration_ratio=0.5`, `min_events=20`, `min_active_samples=12` |
| `IQR_TUKEY_SKEW_FENCES` | **CONSERVATIVE** | `fence_z=5.0`, `surge_ratio=3.0`, `min_daily_volume=500`, `min_baseline_days=14` |
| `IQR_TUKEY_SKEW_FENCES` | **BALANCED** | `fence_z=3.5`, `surge_ratio=2.0`, `min_daily_volume=100`, `min_baseline_days=7` |
| `IQR_TUKEY_SKEW_FENCES` | **AGGRESSIVE** | `fence_z=2.0`, `surge_ratio=1.5`, `min_daily_volume=25`, `min_baseline_days=3` |
| `LOG_NORMAL_VOLUME` | **CONSERVATIVE** | `z_score=3.5`, `min_bytes=100000000.0`, `min_sd=1.0`, `min_active_samples=14` |
| `LOG_NORMAL_VOLUME` | **BALANCED** | `z_score=2.5`, `min_bytes=10000000.0`, `min_sd=0.5`, `min_active_samples=7` |
| `LOG_NORMAL_VOLUME` | **AGGRESSIVE** | `z_score=1.8`, `min_bytes=1000000.0`, `min_sd=0.2`, `min_active_samples=3` |
| `LOG_NORMAL_VOLUME_SURGE` | **CONSERVATIVE** | `z_score=3.5`, `min_bytes=100000000.0`, `min_sd=1.0`, `min_active_samples=14` |
| `LOG_NORMAL_VOLUME_SURGE` | **BALANCED** | `z_score=2.5`, `min_bytes=10000000.0`, `min_sd=0.5`, `min_active_samples=7` |
| `LOG_NORMAL_VOLUME_SURGE` | **AGGRESSIVE** | `z_score=1.8`, `min_bytes=1000000.0`, `min_sd=0.2`, `min_active_samples=3` |
| `LONG_STRING_SCREEN` | **CONSERVATIVE** | `entropy_threshold=7.0`, `min_length=40` |
| `LONG_STRING_SCREEN` | **BALANCED** | `entropy_threshold=5.5`, `min_length=25` |
| `LONG_STRING_SCREEN` | **AGGRESSIVE** | `entropy_threshold=4.0`, `min_length=15` |
| `MARKOV_2GRAM_TRANSITION_RARITY` | **CONSERVATIVE** | `surprisal_threshold=4.2`, `min_parent_count=3`, `vocab_smooth=100.0` |
| `MARKOV_2GRAM_TRANSITION_RARITY` | **BALANCED** | `surprisal_threshold=3.0`, `min_parent_count=1`, `vocab_smooth=100.0` |
| `MARKOV_2GRAM_TRANSITION_RARITY` | **AGGRESSIVE** | `surprisal_threshold=2.0`, `min_parent_count=1`, `vocab_smooth=100.0` |
| `MULTI_SECTOR_FUSION` | **CONSERVATIVE** | `threat_distance=4.0`, `min_active_samples=14`, `min_events=10` |
| `MULTI_SECTOR_FUSION` | **BALANCED** | `threat_distance=3.0`, `min_active_samples=7`, `min_events=5` |
| `MULTI_SECTOR_FUSION` | **AGGRESSIVE** | `threat_distance=2.0`, `min_active_samples=3`, `min_events=2` |
| `MULTI_SECTOR_THREAT_FUSION` | **CONSERVATIVE** | `threat_distance=4.0`, `min_active_samples=14`, `min_events=10` |
| `MULTI_SECTOR_THREAT_FUSION` | **BALANCED** | `threat_distance=3.0`, `min_active_samples=7`, `min_events=5` |
| `MULTI_SECTOR_THREAT_FUSION` | **AGGRESSIVE** | `threat_distance=2.0`, `min_active_samples=3`, `min_events=2` |
| `POISSON_BURST_CLUSTERING` | **CONSERVATIVE** | `fano_factor=8.0`, `min_fails=30`, `min_mu=0.2`, `min_active_samples=60` |
| `POISSON_BURST_CLUSTERING` | **BALANCED** | `fano_factor=4.0`, `min_fails=15`, `min_mu=0.1`, `min_active_samples=30` |
| `POISSON_BURST_CLUSTERING` | **AGGRESSIVE** | `fano_factor=2.5`, `min_fails=10`, `min_mu=0.05`, `min_active_samples=15` |
| `POISSON_RARE_SURGE` | **CONSERVATIVE** | `poisson_z=5.0`, `min_observed=5`, `max_lambda=1.0`, `min_baseline_days=14` |
| `POISSON_RARE_SURGE` | **BALANCED** | `poisson_z=3.5`, `min_observed=3`, `max_lambda=2.0`, `min_baseline_days=7` |
| `POISSON_RARE_SURGE` | **AGGRESSIVE** | `poisson_z=2.5`, `min_observed=2`, `max_lambda=3.0`, `min_baseline_days=3` |
| `PRIVILEGED_LATERAL_EXPANSION` | **CONSERVATIVE** | `z_score=3.5`, `min_distinct_targets=5`, `min_active_samples=30` |
| `PRIVILEGED_LATERAL_EXPANSION` | **BALANCED** | `z_score=2.5`, `min_distinct_targets=3`, `min_active_samples=14` |
| `PRIVILEGED_LATERAL_EXPANSION` | **AGGRESSIVE** | `z_score=1.5`, `min_distinct_targets=2`, `min_active_samples=7` |
| `PRODUCER_CONSUMER_RATIO_INVERSION` | **CONSERVATIVE** | `min_producer_ratio=0.85`, `z_score=3.5`, `min_sent_bytes=50000000`, `min_active_samples=14` |
| `PRODUCER_CONSUMER_RATIO_INVERSION` | **BALANCED** | `min_producer_ratio=0.7`, `z_score=2.5`, `min_sent_bytes=10000000`, `min_active_samples=7` |
| `PRODUCER_CONSUMER_RATIO_INVERSION` | **AGGRESSIVE** | `min_producer_ratio=0.55`, `z_score=1.8`, `min_sent_bytes=1000000`, `min_active_samples=3` |
| `SHANNON_ENTROPY_CHARACTER` | **CONSERVATIVE** | `entropy_threshold=7.0`, `min_length=40` |
| `SHANNON_ENTROPY_CHARACTER` | **BALANCED** | `entropy_threshold=5.5`, `min_length=25` |
| `SHANNON_ENTROPY_CHARACTER` | **AGGRESSIVE** | `entropy_threshold=4.0`, `min_length=15` |
| `TWO_PART_HURDLE` | **CONSERVATIVE** | `z_score=4.0`, `min_count=10`, `min_awakening_volume=20`, `dormant_weight=3.0`, `min_active_samples=14` |
| `TWO_PART_HURDLE` | **BALANCED** | `z_score=3.0`, `min_count=5`, `min_awakening_volume=10`, `dormant_weight=2.0`, `min_active_samples=7` |
| `TWO_PART_HURDLE` | **AGGRESSIVE** | `z_score=2.0`, `min_count=2`, `min_awakening_volume=5`, `dormant_weight=1.5`, `min_active_samples=3` |
| `VELOCITY_SURGE_RATIO` | **CONSERVATIVE** | `ratio_1v7=5.0`, `ratio_1v30=8.0`, `min_today=200`, `min_baseline_days=20` |
| `VELOCITY_SURGE_RATIO` | **BALANCED** | `ratio_1v7=3.0`, `ratio_1v30=5.0`, `min_today=100`, `min_baseline_days=14` |
| `VELOCITY_SURGE_RATIO` | **AGGRESSIVE** | `ratio_1v7=2.0`, `ratio_1v30=3.0`, `min_today=50`, `min_baseline_days=7` |
| `ZIPFIAN_PROCESS_RARITY` | **CONSERVATIVE** | `zipf_threshold=4.0`, `max_adopters=1`, `min_count=2`, `min_fleet_hosts=15` |
| `ZIPFIAN_PROCESS_RARITY` | **BALANCED** | `zipf_threshold=2.5`, `max_adopters=2`, `min_count=1`, `min_fleet_hosts=10` |
| `ZIPFIAN_PROCESS_RARITY` | **AGGRESSIVE** | `zipf_threshold=1.5`, `max_adopters=3`, `min_count=1`, `min_fleet_hosts=5` |
| `ZSCORE_PROCESS_SURGE` | **CONSERVATIVE** | `z_score=3.0`, `min_count=50`, `min_sd=10.0`, `min_active_samples=120` |
| `ZSCORE_PROCESS_SURGE` | **BALANCED** | `z_score=2.0`, `min_count=25`, `min_sd=5.0`, `min_active_samples=60` |
| `ZSCORE_PROCESS_SURGE` | **AGGRESSIVE** | `z_score=1.5`, `min_count=10`, `min_sd=2.0`, `min_active_samples=30` |

---
*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*
