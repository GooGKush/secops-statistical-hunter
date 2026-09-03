# 🎚️ The Calibrated Risk Index (CRI) Reference Guide

**Author**: Greg Kushmerek  
**Skill**: `secops-statistical-hunter`

The **Calibrated Risk Index (CRI)** is the standardized **[0–100] Threat Normalization Layer** for Google SecOps Statistical Outlier Hunting. It transforms raw statistical deviations ($Z$-scores, Modified $Z$ via MAD, Poisson standardized deviance scores, composite Euclidean distance norms $D$, and Coefficient of Variation jitter) into an intuitive, bounded, and cross-comparable threat scale.

---

## 1. ❓ Why CRI Exists: The Zero-Inflated Baseline Problem

In enterprise security telemetry, many high-risk behaviors (e.g. rare administrative tool execution, outbound tunneling, credential stuffing waves) are **Zero-Inflated**:
* 99% of observation intervals have exactly **0 occurrences** ($\mu = 0.0, \sigma = 0.0$).
* When a quiet host or user suddenly generates 50 or 500 events, standard Gaussian normalization with $+0.1$ or $+0.001$ regularization produces extreme mathematical artifacts:
  $$Z = \frac{x - \mu}{\sigma + 0.001} = \frac{50 - 0}{0.001} = \mathbf{+50,000\sigma}$$
* While statistically indicative of extreme rarity, unbounded floats ranging from $-2.0$ to $+50,000$ create severe operational friction:
  1. **Cognitive Distortion**: Tier 1 SOC analysts struggle to prioritize a $+4.16\sigma$ auth surge against a $+5,000\sigma$ process burst.
  2. **Cross-Sector Incomparability**: Network connection count standard deviations cannot be directly combined with process execution counts without severe distortion.
  3. **UI Layout Breakage**: Unbounded floating point numbers break tabular triage summaries and dashboards.

**The Solution**: CRI maps all statistical indicators onto a monotonic, non-linear **[0–100] S-Curve**.

> [!IMPORTANT]
> **Post-Processing Transformation Layer (Never in YARA-L Queries)**:
> CRI is strictly a **post-query presentation and triage transformation** executed in Python reporting scripts (`scripts/multistage_query_builder.py`), triage reports, and SOAR playbooks.
> - **YARA-L Responsibility**: Chronicle queries calculate raw statistical deviations ($Z$-score, $\text{MAD } Z$, Poisson $Z^2$, Coefficient of Variation $\text{CV}$, Euclidean distance norm $D^2$) and order results via `order: <score> desc`.
> - **Post-Processing Responsibility**: Python / reporting layers consume the raw statistical outputs and apply the logistic sigmoid function to normalize scores into the [0–100] CRI range.
> - **Do NOT implement CRI in YARA-L**: Chronicle YARA-L does not support `math.exp()`, and computing non-linear sigmoid curves inside database queries is unnecessary and anti-idiomatic.

---

## 2. 🧮 Mathematical Formulation

The Calibrated Risk Index applies a logistic (Sigmoid) transformation calibrated to anchor the **3-Sigma Alertable Statistical Boundary ($Z = 3.0\sigma$) at exactly CRI = 50**:

$$\text{CRI}(Z) = \begin{cases} 
0 & \text{if } Z \le 0 \\
\text{round}\left( \frac{100}{1 + \exp\left(-\alpha \cdot (Z - Z_{\text{mid}})\right)} \right) & \text{if } Z > 0 
\end{cases}$$

### Calibration Parameters:
* **Inflection Point ($Z_{\text{mid}} = 3.0\sigma$)**: The statistical threshold for a "True Statistical Anomaly" (the 99.87th percentile tail under Gaussian assumptions).
* **Steepness Parameter ($\alpha = 0.6$)**: Calibrates the transition slope so that moderate drift ($Z = 2.0\sigma$) sits in the low 30s, while multi-sigma breakouts ($Z \ge 5.0\sigma$) enter high-threat tiers ($>75$).

---

## 3. 🎯 Calibration Values & Mapping Curve

| Raw $Z$-Score | Mathematical Derivation ($\frac{100}{1 + e^{-0.6(Z - 3.0)}}$) | CRI Score | Severity Tier | Visual Badge |
| :---: | :--- | :---: | :--- | :---: |
| $\le 0.0\sigma$ | $\frac{100}{1 + e^{1.8}} = \frac{100}{1 + 6.05} \to 0$ (clamped) | **0** | **Nominal** | 🟢 `[CRI: 0]` |
| $+1.0\sigma$ | $\frac{100}{1 + e^{1.2}} = \frac{100}{1 + 3.32} = 23.1$ | **23** | **Nominal** | 🟢 `[CRI: 23]` |
| $+1.5\sigma$ | $\frac{100}{1 + e^{0.9}} = \frac{100}{1 + 2.46} = 28.9$ | **29** | **Low Drift** | 🟡 `[CRI: 29]` |
| $+2.0\sigma$ | $\frac{100}{1 + e^{0.6}} = \frac{100}{1 + 1.82} = 35.4$ | **35** | **Low Drift** | 🟡 `[CRI: 35]` |
| $+2.5\sigma$ | $\frac{100}{1 + e^{0.3}} = \frac{100}{1 + 1.35} = 42.6$ | **43** | **Low Drift** | 🟡 `[CRI: 43]` |
| **$+3.0\sigma$** | $\frac{100}{1 + e^{0.0}} = \frac{100}{1 + 1.00} = 50.0$ | **50** | **Medium Outlier (Alertable Anchor)** | 🟠 `[CRI: 50]` |
| $+3.5\sigma$ | $\frac{100}{1 + e^{-0.3}} = \frac{100}{1 + 0.74} = 57.4$ | **57** | **Medium Outlier** | 🟠 `[CRI: 57]` |
| $+4.0\sigma$ | $\frac{100}{1 + e^{-0.6}} = \frac{100}{1 + 0.55} = 64.6$ | **65** | **Medium Outlier** | 🟠 `[CRI: 65]` |
| $+4.5\sigma$ | $\frac{100}{1 + e^{-0.9}} = \frac{100}{1 + 0.41} = 71.1$ | **71** | **High Threat** | 🔴 `[CRI: 71]` |
| $+5.0\sigma$ | $\frac{100}{1 + e^{-1.2}} = \frac{100}{1 + 0.30} = 76.9$ | **77** | **High Threat** | 🔴 `[CRI: 77]` |
| $+6.0\sigma$ | $\frac{100}{1 + e^{-1.8}} = \frac{100}{1 + 0.165} = 85.8$ | **86** | **High Threat** | 🔴 `[CRI: 86]` |
| $+7.0\sigma$ | $\frac{100}{1 + e^{-2.4}} = \frac{100}{1 + 0.091} = 91.7$ | **92** | **Critical Outlier** | 🚨 `[CRI: 92]` |
| $+10.0\sigma$| $\frac{100}{1 + e^{-4.2}} = \frac{100}{1 + 0.015} = 98.5$ | **99** | **Critical Outlier** | 🚨 `[CRI: 99]` |
| **$+3,320\sigma$**| $\frac{100}{1 + e^{-1990.2}} \approx 100.0$ | **100** | **Critical Outlier (Saturated Cap)** | 🚨 `[CRI: 100]` |

---

## 4. 🧭 How to Interpret CRI in SOC Operations

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CRI OPERATIONAL TRIAGE ACTION TIERS                             │
│                                                                                        │
│  [ CRI: 0 – 25 ]   🟢 NOMINAL         • Expected day-to-day variance. Log only.        │
│  [ CRI: 26 – 45 ]  🟡 LOW DRIFT       • Minor elevation. Contextual review.            │
│  [ CRI: 46 – 69 ]  🟠 MEDIUM OUTLIER  • True Statistical Anomaly (Z >= 3.0σ). Triage.  │
│  [ CRI: 70 – 89 ]  🔴 HIGH THREAT     • Severe Multi-Sigma Breakout. Immediate SOC.    │
│  [ CRI: 90 – 100 ] 🚨 CRITICAL        • Extreme Surge or Zero-Baseline Breakout. Esc.  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Operational Guidance:
1. **Tier 1 (CRI 0–25) — Nominal Behavior**:
   * **Interpretation**: The observed activity is well within the entity baseline envelope or peer group norm.
   * **Action**: Suppress alert; no SOC investigation required.
2. **Tier 2 (CRI 26–45) — Low Drift / Early Warning**:
   * **Interpretation**: Moderate elevation above baseline ($1.5\sigma \le Z < 3.0\sigma$).
   * **Action**: Monitor in longitudinal tracking; do not page analysts.
3. **Tier 3 (CRI 46–69) — Medium Outlier (Alertable)**:
   * **Interpretation**: **True Statistical Anomaly**. Probability that this activity occurred by random chance is $p < 0.0013$ ($Z \ge 3.0\sigma$).
   * **Action**: Triage with standard priority. Cross-reference peers and execute drill-down query.
4. **Tier 4 (CRI 70–89) — High Threat**:
   * **Interpretation**: Severe anomaly ($4.5\sigma \le Z < 7.0\sigma$). Strong multi-vector divergence from historical baseline.
   * **Action**: Immediate analyst intervention. Inspect process execution lineage and network destinations.
5. **Tier 5 (CRI 90–100) — Critical Outlier**:
   * **Interpretation**: Massive breakout ($Z \ge 7.0\sigma$) or dormant zero-baseline awakening.
   * **Action**: High-priority incident response escalation. Isolate host or suspend user credentials if paired with suspicious command-line artifacts.

---

## 5. 🔬 Dual-Indicator Reporting Standard

In all Statistical Outlier Hunter reports, always report the exact statistical metric alongside the normalized CRI badge:

```markdown
| Target Entity | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `host-alpha-prod` | 2026-08-24T08:00 | **850** | 250 ± 35 | 🟢 **HIGH CONFIDENCE** | 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | 🚨 `[CRI: 100]` | `██████████` |
| `host-dev-02` | 2026-08-24T08:00 | **120** | 45 ± 15 | 🟡 **MODERATE CONFIDENCE** | 🟠 **[MEDIUM OUTLIER]** (`+3.80σ`) | 🟠 `[CRI: 62]` | `██████    ` |
| `host-quiet-09` | 2026-08-24T08:00 | **12** | 10 ± 8 | 🟢 **HIGH CONFIDENCE** | 🟢 **[INFORMATIONAL]** (`+0.25σ`) | 🟢 `[CRI: 0]` | `          ` |
```
