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

## 3. Non-Parametric IQR / Tukey Fences

* **Primary Adversary Behavior**: Heavy-tailed egress data transfers, unusual file access counts.
* **Mathematical Formula**:
  $$\text{IQR} = Q_3 - Q_1$$
  $$\text{Upper Fence} = Q_3 + (1.5 \cdot \text{IQR})$$
  $$\text{Surge Ratio} = \frac{x_{\text{today}}}{\text{Upper Fence}}$$

---

## 4. Multi-Window Rolling Ratios ($1\text{d}$ vs $7\text{d}$ vs $30\text{d}$)

* **Primary Adversary Behavior**: Credential stuffing bursts, brute force authentication waves, sudden scan sweeps.
* **Mathematical Formula**:
  $$\text{Ratio}_{1v7} = \frac{S_{1\text{d}}}{\text{avg}_{7\text{d}}}, \quad \text{Ratio}_{1v30} = \frac{S_{1\text{d}}}{\text{avg}_{30\text{d}}}$$

---

## 5. Categorical Dispersion (Herfindahl-Hirschman Index / Simpson Index)

* **Primary Adversary Behavior**: Internal lateral movement (reconnaissance sweeps across many internal IPs/ports).
* **Mathematical Formula**:
  $$D = 1 - \sum_{i=1}^{k} \left(\frac{n_i}{N}\right)^2$$
  where $n_i$ is connections to target $i$ and $N$ is total connections. When an entity talks to only 1 server, $D = 0$. When an entity scans 100 servers equally, $D \to 1.0$.

---

## 6. Impossible Travel Velocity (Haversine Kinematics)

* **Primary Adversary Behavior**: Stolen session cookie reuse, geo-impossible credential login.
* **Mathematical Formula**:
  $$\text{Speed} = \frac{\text{math.geo\_distance}(\text{lat}_1, \text{lon}_1, \text{lat}_2, \text{lon}_2)}{|t_2 - t_1| / 3600} \quad (\text{km/h})$$
  *Threshold*: `Speed > 800 km/h` (faster than commercial jet travel).
