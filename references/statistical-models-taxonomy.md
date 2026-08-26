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

## 7. Multiple-Comparison Fleet Correction (Bonferroni Extreme Value Bound)
* **Goal**: Scale anomaly thresholds automatically when scanning large fleets ($N$ hosts).
* **Formula**:
  $$Z_{\text{adj}} = \max\left(Z_{\text{base}}, \sqrt{2 \ln N}\right)$$
