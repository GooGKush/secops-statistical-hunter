<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->

# Mathematical Models & Statistical Taxonomy for Threat Hunting

This reference details the mathematical physics, derivations, and formulas used across `secops-statistical-hunter`.

---

## 1. Parametric Historical Standardization ($Z$-Score)
* **Goal**: Detect sudden vertical bursts in volume over a Gaussian historical baseline.
* **Formula**:
  $$Z = \frac{x - \mu}{\sigma}$$
* **Where**:
  - $x$: Current window observation count (`$obs`).
  - $\mu$: Historical sample mean (`$mu = \text{avg}(\$stage1.count)`).
  - $\sigma$: Historical standard deviation (`$sd = \text{stddev}(\$stage1.count)`).
* **Guards**: Requires $\sigma > 0$ and $N \ge 24$ active baseline intervals.

---

## 2. Poisson-Gamma Bayesian Credibility Shrinkage ("The Seasoned SOC Detective")
* **Goal**: Isolate high-confidence bursts on stable hosts while preventing false alarms on erratic endpoints.
* **Method of Moments Gamma Prior**:
  $$\text{Var} = \sigma^2, \quad \beta_0 = \frac{\mu}{\text{Var}}, \quad \alpha_0 = \mu \cdot \beta_0$$
* **Conjugate Posterior Updating** (for observation $k$ across time $t=1$):
  $$\alpha_{\text{post}} = \alpha_0 + k, \quad \beta_{\text{post}} = \beta_0 + 1.0$$
* **Posterior Expected Arrival Rate & Credibility Weights**:
  $$\lambda_{\text{post}} = \frac{\alpha_{\text{post}}}{\beta_{\text{post}}}, \quad W_{\text{prior}} = \frac{\beta_0}{\beta_{\text{post}}}, \quad W_{\text{evidence}} = \frac{1}{\beta_{\text{post}}}$$
* **Belief Shift Ratio**:
  $$\text{Shift Ratio} = \frac{\lambda_{\text{post}}}{\mu}$$

---

## 3. Beta-Binomial Failure Ratio Regularization ("Small-Sample Ratio Regularizer")
* **Goal**: Prevent false positives from $1/1 = 100\%$ failure rates on single-trial mistakes.
* **Informative Corporate Prior**: $\alpha_0 = 1.0, \beta_0 = 9.0$ ($\sim 10\%$ normal background error rate).
* **Conjugate Posterior Update**:
  $$\alpha_{\text{post}} = \alpha_0 + \text{fails}, \quad \beta_{\text{post}} = \beta_0 + \text{successes}$$
* **Regularized Posterior Failure Probability**:
  $$P(\text{Fail}) = \frac{\alpha_{\text{post}}}{\alpha_{\text{post}} + \beta_{\text{post}}}$$

---

## 4. Dual-Baseline Delta-$Z$ ("The Patch Tuesday Shield")
* **Goal**: Isolate targeted endpoint spikes from company-wide software deployments.
* **Formula**:
  $$\Delta Z = Z_{\text{Personal}} - Z_{\text{Fleet Today}} = \left(\frac{x - \mu_{\text{personal}}}{\sigma_{\text{personal}}}\right) - \left(\frac{x - \mu_{\text{fleet}}}{\sigma_{\text{fleet}}}\right)$$
* **Behavior**:
  - Company-wide deployment: $Z_{\text{Personal}} \approx 10.0$, $Z_{\text{Fleet}} \approx 9.8 \implies \Delta Z \approx 0.2$ (Ignored).
  - Targeted attack: $Z_{\text{Personal}} \approx 8.5$, $Z_{\text{Fleet}} \approx 0.1 \implies \Delta Z \approx 8.4$ (Triggered).

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

## 7. Information-Theoretic Diversity Deficit (Entropy Proxy)
* **Goal**: Detect automated scripted exfiltration where an entity touches many destinations with minimal vocabulary entropy.
* **Formula**:
  $$\text{Diversity Ratio} = \frac{k_{\text{vocab}}}{N_{\text{events}} + 1.0}$$
* **Interpretation**:
  - Scripted exfiltration produces severe diversity collapse ($\text{Diversity Ratio} \le 0.20$).

---

## 8. Elephant Flow Concentration (HHI / Gini Proxy)
* **Goal**: Detect single massive exfiltration bursts masked within routine traffic.
* **Formula**:
  $$\text{Concentration Ratio} = \frac{\text{Peak Transfer}}{\sum \text{Transfers} + 1.0}$$
* **Interpretation**:
  - Extreme concentration ($\text{Concentration Ratio} \ge 0.70$) indicates an isolated elephant flow.

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

## 11. Log-Normal Volumetric Standardization ($Z_{\log}$)
* **Goal**: Isolate extreme byte bursts over heavy-tailed, skewed network and data exfiltration streams without parametric Gaussian distortion.
* **Formula**:
  $$Y = \text{math.log}(\text{bytes} + 1.0), \quad Z_{\log} = \frac{Y - \mu_Y}{\sigma_Y}$$
* **Interpretation**:
  - Log-transform stabilizes variance across several orders of magnitude, isolating true exfiltration anomalies.

---

## 12. Continuous Calibrated Risk Index (CRI [0–100]) In-Stage Translation
* **Goal**: Translate raw multi-stage $Z$-scores or threat distances into a bounded [0, 100] triage score directly inside YARA-L query outcomes.
* **Formula**:
  $$\text{CRI} = \text{math.round}\left(\frac{100.0}{1.0 + \text{math.exp}(-0.6 \cdot (Z - 3.0))}\right)$$

---

## 13. Sensitivity & Anomaly Threshold Map

| Archetype | Tier | Thresholds & Parameters |
| :--- | :--- | :--- |
| `C2_BEACONING_JITTER` | **CONSERVATIVE** | `cv=0.05`, `min_conns=50`, `prevalence=1`, `min_active_hours=12` |
| `C2_BEACONING_JITTER` | **BALANCED** | `cv=0.2`, `min_conns=25`, `prevalence=2`, `min_active_hours=6` |
| `C2_BEACONING_JITTER` | **AGGRESSIVE** | `cv=0.4`, `min_conns=15`, `prevalence=1`, `min_active_hours=3` |
| `CATEGORICAL_FLEET_PREVALENCE` | **CONSERVATIVE** | `max_adopters=1`, `min_events=10`, `min_active_hours=12` |
| `CATEGORICAL_FLEET_PREVALENCE` | **BALANCED** | `max_adopters=2`, `min_events=5`, `min_active_hours=6` |
| `CATEGORICAL_FLEET_PREVALENCE` | **AGGRESSIVE** | `max_adopters=3`, `min_events=2`, `min_active_hours=1` |
| `DATA_EXFILTRATION_SPIKE` | **CONSERVATIVE** | `m_z=3.5`, `min_mb=500.0`, `min_mad=20.0`, `min_baseline_days=14` |
| `DATA_EXFILTRATION_SPIKE` | **BALANCED** | `m_z=2.5`, `min_mb=100.0`, `min_mad=10.0`, `min_baseline_days=7` |
| `DATA_EXFILTRATION_SPIKE` | **AGGRESSIVE** | `m_z=2.0`, `min_mb=25.0`, `min_mad=5.0`, `min_baseline_days=3` |
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
| `DORMANT_ACCOUNT_AWAKENING` | **CONSERVATIVE** | `z_score=3.5`, `min_count=10`, `dormant_weight=3.0`, `min_sd=1.0`, `min_active_samples=14` |
| `DORMANT_ACCOUNT_AWAKENING` | **BALANCED** | `z_score=2.5`, `min_count=5`, `dormant_weight=2.0`, `min_sd=0.5`, `min_active_samples=7` |
| `DORMANT_ACCOUNT_AWAKENING` | **AGGRESSIVE** | `z_score=1.5`, `min_count=2`, `dormant_weight=1.5`, `min_sd=0.2`, `min_active_samples=3` |
| `FLEET_PEER_ZSCORE` | **CONSERVATIVE** | `fleet_z=3.5`, `min_host_count=50`, `min_fleet_sd=10.0`, `min_active_hosts=25` |
| `FLEET_PEER_ZSCORE` | **BALANCED** | `fleet_z=2.5`, `min_host_count=25`, `min_fleet_sd=5.0`, `min_active_hosts=15` |
| `FLEET_PEER_ZSCORE` | **AGGRESSIVE** | `fleet_z=2.0`, `min_host_count=10`, `min_fleet_sd=2.0`, `min_active_hosts=10` |
| `GLOBAL_THREAT_INTEL` | **CONSERVATIVE** | `threat_score=4.0`, `min_obs_bytes=1000000.0`, `min_active_hours=24`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL` | **BALANCED** | `threat_score=3.0`, `min_obs_bytes=100000.0`, `min_active_hours=12`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL` | **AGGRESSIVE** | `threat_score=2.0`, `min_obs_bytes=10000.0`, `min_active_hours=6`, `nrd_multiplier=2.0` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **CONSERVATIVE** | `threat_score=4.0`, `min_obs_bytes=1000000.0`, `min_active_hours=24`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **BALANCED** | `threat_score=3.0`, `min_obs_bytes=100000.0`, `min_active_hours=12`, `nrd_multiplier=2.5` |
| `GLOBAL_THREAT_INTEL_ENRICHMENT` | **AGGRESSIVE** | `threat_score=2.0`, `min_obs_bytes=10000.0`, `min_active_hours=6`, `nrd_multiplier=2.0` |
| `HEAVY_TAIL_OUTLIERS` | **CONSERVATIVE** | `surge_ratio=3.0`, `min_iqr=50.0`, `min_baseline_days=14` |
| `HEAVY_TAIL_OUTLIERS` | **BALANCED** | `surge_ratio=2.0`, `min_iqr=10.0`, `min_baseline_days=7` |
| `HEAVY_TAIL_OUTLIERS` | **AGGRESSIVE** | `surge_ratio=1.5`, `min_iqr=5.0`, `min_baseline_days=3` |
| `LOG_NORMAL_VOLUME` | **CONSERVATIVE** | `z_score=3.5`, `min_bytes=100000000.0`, `min_sd=1.0`, `min_active_samples=14` |
| `LOG_NORMAL_VOLUME` | **BALANCED** | `z_score=2.5`, `min_bytes=10000000.0`, `min_sd=0.5`, `min_active_samples=7` |
| `LOG_NORMAL_VOLUME` | **AGGRESSIVE** | `z_score=1.8`, `min_bytes=1000000.0`, `min_sd=0.2`, `min_active_samples=3` |
| `LOG_NORMAL_VOLUME_SURGE` | **CONSERVATIVE** | `z_score=3.5`, `min_bytes=100000000.0`, `min_sd=1.0`, `min_active_samples=14` |
| `LOG_NORMAL_VOLUME_SURGE` | **BALANCED** | `z_score=2.5`, `min_bytes=10000000.0`, `min_sd=0.5`, `min_active_samples=7` |
| `LOG_NORMAL_VOLUME_SURGE` | **AGGRESSIVE** | `z_score=1.8`, `min_bytes=1000000.0`, `min_sd=0.2`, `min_active_samples=3` |
| `MULTI_SECTOR_FUSION` | **CONSERVATIVE** | `threat_distance=4.0`, `min_active_samples=14`, `min_events=10` |
| `MULTI_SECTOR_FUSION` | **BALANCED** | `threat_distance=3.0`, `min_active_samples=7`, `min_events=5` |
| `MULTI_SECTOR_FUSION` | **AGGRESSIVE** | `threat_distance=2.0`, `min_active_samples=3`, `min_events=2` |
| `MULTI_SECTOR_THREAT_FUSION` | **CONSERVATIVE** | `threat_distance=4.0`, `min_active_samples=14`, `min_events=10` |
| `MULTI_SECTOR_THREAT_FUSION` | **BALANCED** | `threat_distance=3.0`, `min_active_samples=7`, `min_events=5` |
| `MULTI_SECTOR_THREAT_FUSION` | **AGGRESSIVE** | `threat_distance=2.0`, `min_active_samples=3`, `min_events=2` |
| `POISSON_BURST_CLUSTERING` | **CONSERVATIVE** | `fano_factor=8.0`, `min_fails=30`, `min_mu=2.0`, `min_active_samples=60` |
| `POISSON_BURST_CLUSTERING` | **BALANCED** | `fano_factor=4.0`, `min_fails=15`, `min_mu=1.0`, `min_active_samples=30` |
| `POISSON_BURST_CLUSTERING` | **AGGRESSIVE** | `fano_factor=2.5`, `min_fails=10`, `min_mu=0.5`, `min_active_samples=15` |
| `POISSON_RARE_SURGE` | **CONSERVATIVE** | `poisson_z=5.0`, `min_observed=5`, `max_lambda=1.0`, `min_baseline_days=14` |
| `POISSON_RARE_SURGE` | **BALANCED** | `poisson_z=3.5`, `min_observed=3`, `max_lambda=2.0`, `min_baseline_days=7` |
| `POISSON_RARE_SURGE` | **AGGRESSIVE** | `poisson_z=2.5`, `min_observed=2`, `max_lambda=3.0`, `min_baseline_days=3` |
| `PRIVILEGED_LATERAL_EXPANSION` | **CONSERVATIVE** | `z_score=3.0`, `min_distinct_targets=5`, `min_sd=1.0`, `min_active_samples=30` |
| `PRIVILEGED_LATERAL_EXPANSION` | **BALANCED** | `z_score=2.0`, `min_distinct_targets=3`, `min_sd=0.5`, `min_active_samples=14` |
| `PRIVILEGED_LATERAL_EXPANSION` | **AGGRESSIVE** | `z_score=1.5`, `min_distinct_targets=2`, `min_sd=0.2`, `min_active_samples=7` |
| `TWO_PART_HURDLE` | **CONSERVATIVE** | `z_score=3.5`, `min_count=10`, `dormant_weight=3.0`, `min_sd=1.0`, `min_active_samples=14` |
| `TWO_PART_HURDLE` | **BALANCED** | `z_score=2.5`, `min_count=5`, `dormant_weight=2.0`, `min_sd=0.5`, `min_active_samples=7` |
| `TWO_PART_HURDLE` | **AGGRESSIVE** | `z_score=1.5`, `min_count=2`, `dormant_weight=1.5`, `min_sd=0.2`, `min_active_samples=3` |
| `VELOCITY_SURGE_RATIO` | **CONSERVATIVE** | `ratio_1v7=5.0`, `ratio_1v30=8.0`, `min_today=200`, `min_baseline_days=20` |
| `VELOCITY_SURGE_RATIO` | **BALANCED** | `ratio_1v7=3.0`, `ratio_1v30=5.0`, `min_today=100`, `min_baseline_days=14` |
| `VELOCITY_SURGE_RATIO` | **AGGRESSIVE** | `ratio_1v7=2.0`, `ratio_1v30=3.0`, `min_today=50`, `min_baseline_days=7` |
| `ZSCORE_PROCESS_SURGE` | **CONSERVATIVE** | `z_score=3.0`, `min_count=50`, `min_sd=10.0`, `min_active_samples=120` |
| `ZSCORE_PROCESS_SURGE` | **BALANCED** | `z_score=2.0`, `min_count=25`, `min_sd=5.0`, `min_active_samples=60` |
| `ZSCORE_PROCESS_SURGE` | **AGGRESSIVE** | `z_score=1.5`, `min_count=10`, `min_sd=2.0`, `min_active_samples=30` |

---
*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*
