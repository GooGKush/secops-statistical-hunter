# SecOps Statistical Hunter — Statistical Models Taxonomy

This document outlines the mathematical models supported by `secops-statistical-hunter`, their physical adversary TTP mappings, and the **Semantic Sensitivity Tiers** to use when guiding non-practitioners.

---

## 1. Timing Jitter via Coefficient of Variation ($\text{CV}_{\Delta t}$)

* **Primary Adversary Behavior**: C2 Beaconing (Cobalt Strike, Sliver, Metasploit, Custom Implants), automated data synchronization, keep-alive polling.
* **Mathematical Formula**:
  $$\text{CV} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$
  where $\Delta t_i = t_i - t_{i-1}$ is the time interval between consecutive network connections or requests.

### Sensitivity Tiers (`C2_BEACONING_JITTER`)

| Tier | Mathematical Boundary | Physical Interpretation | Recommended Secondary Filters |
| :--- | :--- | :--- | :--- |
| **`PRECISION`** | $\text{CV} \le 0.05$ | Hardcoded fixed interval ($\pm 3\%$ jitter). Robotic polling. | None needed. |
| **`BALANCED`** | $\text{CV} \le 0.20$ | Standard default C2 sleep jitter ($15\%–20\%$ variance). | `fleet_prevalence <= 2` hosts |
| **`AGGRESSIVE`** | $\text{CV} \le 0.40$ | Heavily randomized C2 sleep intervals designed to evade basic detection. | `fleet_prevalence == 1` & `min_conns >= 50` |
| ❌ **`NOISE CLIFF`** | $\text{CV} > 0.50$ | Approaching Poisson randomness (normal web browsing). | **Refuse search.** |

---

## 2. Modified Z-Score via Median Absolute Deviation ($M_Z$)

* **Primary Adversary Behavior**: DNS Tunneling, DGA subdomain explosion, massive data exfiltration spikes.
* **Mathematical Formula**:
  $$\text{MAD} = \text{median}(|x_i - \tilde{x}|)$$
  $$M_Z = \frac{0.6745 \cdot (x_i - \tilde{x})}{\text{MAD}}$$
* **Why MAD over Standard $Z$-Score?**
  In security telemetry, a single massive exfiltration day ($100\text{ GB}$) inflates the standard deviation ($\sigma$) so much that $Z$-score drops below $2.0$. MAD is **breakdown-resilient up to $50\%$ outliers**, making it the premier metric for security volume anomalies.

### Sensitivity Tiers (`MODIFIED_Z_SCORE_MAD`)

| Tier | Mathematical Boundary | Physical Interpretation | Volume Floor Guardrail |
| :--- | :--- | :--- | :--- |
| **`PRECISION`** | $M_Z > 3.5$ | Top $\approx 0.05\%$ extreme distribution tail. Major operational event. | `$MAD > 10` |
| **`BALANCED`** | $M_Z > 2.5$ | Top $\approx 2\%$ anomalies above personal entity median. | `$MAD > 5` |
| **`AGGRESSIVE`** | $M_Z > 2.0$ | Top $\approx 5\%$ surges. Good for hunting stealthy data leakage. | `$MAD > 2` |
| ❌ **`NOISE CLIFF`** | $M_Z < 1.5$ | Daily peak hour traffic fluctuations. | **Refuse search.** |

---

## 3. Parametric Historical Z-Score per Entity ($Z = (x - \mu) / \sigma$)

* **Primary Adversary Behavior**: Process launch storms, rapid batch lateral movement, ransomware staging, compiler abuse loops.
* **Mathematical Formula**:
  $$Z = \frac{x - \mu}{\sigma}$$
  where $x$ is the hourly/daily execution count for an entity, and $\mu, \sigma$ are the entity's historical mean and standard deviation across the baseline window.

### Sensitivity Tiers (`ZSCORE_PROCESS_SURGE`)

| Tier | Mathematical Boundary | Physical Interpretation | Variance Floor Guardrail |
| :--- | :--- | :--- | :--- |
| **`CONSERVATIVE`** | $Z > 3.0$ | 3-Sigma threshold (top $0.13\%$ distribution tail). Very low noise. | `$stddev >= 10.0`, `$obs >= 50` |
| **`BALANCED`** | $Z > 2.0$ | 2-Sigma threshold (top $\approx 2.5\%$ distribution tail). Standard baseline sweep. | `$stddev >= 5.0`, `$obs >= 25` |
| **`AGGRESSIVE`** | $Z > 1.5$ | 1.5-Sigma threshold (top $\approx 7\%$ distribution tail). Sensitive hunt. | `$stddev >= 2.0`, `$obs >= 10` |
| ❌ **`NOISE CLIFF`** | $Z \le 1.0$ | Within standard daily operational variance. | **Refuse search.** |

---

## 4. Poisson Burstiness via Fano Factor ($F = \sigma^2 / \mu$)

* **Primary Adversary Behavior**: Password spraying, automated credential stuffing waves, intermittent lateral recon sweeps that stay under volume caps.
* **Mathematical Formula**:
  $$F = \frac{\sigma^2}{\mu}$$
  * $F < 1.0$: Robotic/Periodic timing.
  * $F \approx 1.0$: Memoryless Poisson process (random independent human errors).
  * $F > 4.0$: **Over-dispersed cluster attack waves** (burst activity).

### Sensitivity Tiers (`POISSON_BURST_CLUSTERING`)

| Tier | Mathematical Boundary | Physical Interpretation | Floor Guardrail |
| :--- | :--- | :--- | :--- |
| **`CONSERVATIVE`** | $F \ge 8.0$ | Severe synchronized attack downpours. | `min_fails >= 30, mu >= 2.0` |
| **`BALANCED`** | $F \ge 4.0$ | Clear wave-like password spraying / recon pulses. | `min_fails >= 15, mu >= 1.0` |
| **`AGGRESSIVE`** | $F \ge 2.5$ | Moderate clumping in authentication failures. | `min_fails >= 10, mu >= 0.5` |
| ❌ **`NOISE CLIFF`** | $F \le 1.5$ | Independent random login typos. | **Refuse search.** |

---

## 5. Discrete Poisson Arrival Score ($\text{Poisson } Z = \frac{k - \lambda}{\sqrt{\lambda}}$)

* **Primary Adversary Behavior**: Sensitive administrative tool invocations (`vssadmin`, `certutil`, `whoami`, `dsquery`) on endpoints with near-zero baseline history.
* **Mathematical Formula**:
  $$\text{Poisson } Z = \frac{k - \lambda}{\sqrt{\lambda}}$$
  where $k$ is observed executions today and $\lambda$ is historical daily mean arrival rate.

### Sensitivity Tiers (`POISSON_RARE_SURGE`)

| Tier | Mathematical Boundary | Physical Interpretation | Floor Guardrail |
| :--- | :--- | :--- | :--- |
| **`CONSERVATIVE`** | $\text{Poisson } Z \ge 5.0$ | Extreme mathematical impossibility on quiet host. | `k >= 5, lambda <= 1.0` |
| **`BALANCED`** | $\text{Poisson } Z \ge 3.5$ | Improbable jump in rare administrative execution. | `k >= 3, lambda <= 2.0` |
| **`AGGRESSIVE`** | $\text{Poisson } Z \ge 2.5$ | Noticeable uptick in low-frequency binary usage. | `k >= 2, lambda <= 3.0` |

---

## 6. Non-Parametric IQR / Tukey Fences

* **Primary Adversary Behavior**: Heavy-tailed egress data transfers, unusual file access counts.
* **Mathematical Formula**:
  $$\text{IQR} = Q_3 - Q_1$$
  $$\text{Upper Fence} = Q_3 + (1.5 \cdot \text{IQR})$$
  $$\text{Surge Ratio} = \frac{x_{\text{today}}}{\text{Upper Fence}}$$

---

## 7. Multi-Window Rolling Ratios ($1\text{d}$ vs $7\text{d}$ vs $30\text{d}$)

* **Primary Adversary Behavior**: Credential stuffing bursts, brute force authentication waves, sudden scan sweeps.
* **Mathematical Formula**:
  $$\text{Ratio}_{1v7} = \frac{S_{1\text{d}}}{\text{avg}_{7\text{d}}}, \quad \text{Ratio}_{1v30} = \frac{S_{1\text{d}}}{\text{avg}_{30\text{d}}}$$

---

## 8. Categorical Dispersion (Herfindahl-Hirschman Index / Simpson Index)

* **Primary Adversary Behavior**: Internal lateral movement (reconnaissance sweeps across many internal IPs/ports).
* **Mathematical Formula**:
  $$D = 1 - \sum_{i=1}^{k} \left(\frac{n_i}{N}\right)^2$$
  where $n_i$ is connections to target $i$ and $N$ is total connections. When an entity talks to only 1 server, $D = 0$. When an entity scans 100 servers equally, $D \to 1.0$.

---

## 9. Impossible Travel Velocity (Haversine Kinematics)

* **Primary Adversary Behavior**: Stolen session cookie reuse, geo-impossible credential login.
* **Mathematical Formula**:
  $$\text{Speed} = \frac{\text{math.geo\_distance}(\text{lat}_1, \text{lon}_1, \text{lat}_2, \text{lon}_2)}{|t_2 - t_1| / 3600} \quad (\text{km/h})$$
  *Threshold*: `Speed > 800 km/h` (faster than commercial jet travel).

---

## 10. Multi-Dimensional Threat Visualizations & Dual-Y Charts

1. **Dual-Y Axis Outlier Timeline (`DUAL_Y_TIMESERIES`)**:
   * **Shared $X$-Axis**: Time Window (UTC).
   * **Left $Y$-Axis**: Observed Physical Volume / Count (Bar or Area mark).
   * **Right $Y$-Axis**: Statistical Anomaly Score ($Z$, Fano, Modified $Z$) (Line + Points).
   * **Vega-Lite Encodings**: Resolves independent $Y$-scales with `resolve: { scale: { y: "independent" } }`.
2. **4D Threat Bubble Plot (`4D_BUBBLE`)**:
   * **$X$-Axis**: Timing Interval ($\Delta t$).
   * **$Y$-Axis**: Observed Event Volume.
   * **Bubble Size**: Cardinality (Distinct target IPs, unique binaries, or users).
   * **Bubble Color**: Statistical Anomaly Score ($Z$, $M_Z$, or $\text{CV}$).
3. **3D Temporal Density Heatmap (`HEATMAP`)**:
   * **$X$-Axis**: Hour of Day ($00–23$).
   * **$Y$-Axis**: Day of Week (Monday–Sunday) or Subnet.
   * **Color Density**: Anomaly Score or Event Concentration.

---

## 11. Malachite AST Linearization & Compiler Rules

When implementing any statistical model in YARA-L 2.0 multi-stage queries, strictly adhere to the following Malachite AST rules:

| Statistical Model | Formula | Malachite AST Linear Syntax | Zero-Division Protection (Condition) |
| :--- | :--- | :--- | :--- |
| **Parametric $Z$-Score** | $Z = \frac{x - \mu}{\sigma}$ | `$diff = $obs - $mu`<br>`$z_score = $diff / $sigma` | `condition: $sigma >= 5.0 and $z_score > 3.0` |
| **Poisson Fano Factor** | $F = \frac{\sigma^2}{\mu}$ | `$var = $sigma * $sigma`<br>`$fano = $var / $mu` | `condition: $mu >= 1.0 and $fano >= 4.0` |
| **Poisson Rare Arrival** | $Z_P = \frac{k - \lambda}{\sqrt{\lambda}}$ | `$poisson_sd = math.sqrt($lambda)`<br>`$diff = $k - $lambda`<br>`$poisson_z = $diff / $poisson_sd` | `condition: $lambda > 0.0 and $poisson_sd > 0.0 and $poisson_z >= 3.5` |
| **Modified $Z$ (MAD)** | $M_Z = \frac{0.6745 \cdot \|x - \tilde{x}\|}{\text{MAD}}$ | `$diff = $obs - $median`<br>`$abs_diff = math.abs($diff)`<br>`$scaled = 0.6745 * $abs_diff`<br>`$m_z = $scaled / $mad` | `condition: $mad > 5.0 and $m_z > 2.5` |
| **Timing Jitter ($\text{CV}$)** | $\text{CV} = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$ | `$span = $last - $first`<br>`$intervals = $count - 1`<br>`$gap = $span / $intervals`<br>`$cv = $stddev_gap / $mean_gap` | `condition: $mean_gap >= 30.0 and $cv <= 0.20` |
| **Tukey Upper Fence** | $Q_3 + (1.5 \cdot \text{IQR})$ | `$iqr = $q3 - $q1`<br>`$margin = 1.5 * $iqr`<br>`$fence = $q3 + $margin`<br>`$surge = $obs / $fence` | `condition: $iqr >= 10.0 and $surge >= 2.0` |
| **Conditional Counting** | Count matching events | `$count = sum(if(condition, 1, 0))` | *Never use `count(if(...))`.* |
