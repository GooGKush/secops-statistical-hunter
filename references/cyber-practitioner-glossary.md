# Cyber Practitioner's Statistical Translation Manual

This manual is a practical field guide for Security Operations Center (SOC) analysts, incident responders, and threat hunters. It translates abstract mathematical metrics into **physical adversary mechanics**, **threat severity levels**, **common false positives**, and **investigation playbooks**.

---

## 1. Metric-to-Threat Translation Glossary

| Statistical Metric | Plain-English Concept | Physical Threat Meaning | Normal vs. Malicious Threshold |
| :--- | :--- | :--- | :--- |
| **Coefficient of Variation ($\text{CV} = \sigma / \mu$)** | **Timing Jitter / Regularity** | Automated implant sleep routines (Cobalt Strike, Sliver). Lower CV means more robotic regularity. | **Normal**: $\text{CV} > 0.50$ (Human browsing)<br>**Threat**: $\text{CV} \le 0.20$ (Implant with $\le 20\%$ jitter) |
| **Parametric $Z$-Score ($Z = (x - \mu) / \sigma$)** | **Standard Deviation Surge** | Sudden volume explosion above historical personal baseline (mass script loops, build storms, encryption). | **Normal**: $Z \le 1.5\sigma$<br>**Threat**: $Z > 3.0\sigma$ (Top $0.13\%$ historical tail) |
| **Modified $Z$-Score ($M_Z$) via MAD** | **Median-Anchored Spike** | Data exfiltration or DNS tunneling on skewed data where a huge outlier would break standard deviation. | **Normal**: $M_Z \le 1.5$<br>**Threat**: $M_Z > 2.5$ (Outlier above personal median) |
| **Fano Factor ($F = \sigma^2 / \mu$)** | **Attack Wave Clustering** | Intermittent, bursty attack campaigns (slow-and-low password spraying, periodic recon pulses) that evade rate caps. | **Normal**: $F \approx 1.0$ (Random independent Poisson chatter)<br>**Threat**: $F > 4.0$ (Synchronized attack waves) |
| **Discrete Poisson Score ($\frac{k - \lambda}{\sqrt{\lambda}}$)** | **Improbable Rare Event Surge** | Sensitive administrative tools (`vssadmin`, `whoami`, `certutil`) firing on quiet hosts with near-zero baseline. | **Normal**: Historical rate $\lambda \le 0.5$<br>**Threat**: $\text{Poisson Score} \ge 3.5\sigma$ ($k \ge 3$ runs today) |
| **Tukey's Upper Fence ($Q_3 + 1.5 \cdot \text{IQR}$)** | **Non-Parametric Ceiling** | Outbound data transfers or file reads exceeding the 75th percentile spread without Gaussian assumptions. | **Normal**: Observed $\le \text{Upper Fence}$<br>**Threat**: Observed $> 2.0\times$ Upper Fence |
| **Haversine Speed ($\text{km/h}$)** | **Kinematic Impossible Travel** | Stolen session cookies or compromised credentials used from physically impossible geographic distances. | **Normal**: $< 800\text{ km/h}$ (Commercial airliner speed)<br>**Threat**: $> 1{,}000\text{ km/h}$ (Impossible travel) |

---

## 2. Standard SOC Severity & Operational Confidence Badges

When presenting findings to stakeholders, convert mathematical values into operational action tiers:

```
🚨 [CRITICAL OUTLIER]  ──► Z >= 4.0σ | CV <= 0.08 | Poisson >= 5.0 | Fano >= 8.0
                          • Rarity: < 1 in 100,000 baseline hours (< 0.003% probability).
                          • Recommended Action: Immediate triage, host isolation review, kill process.

⚠️ [HIGH SUSPICION]    ──► Z >= 3.0σ | CV <= 0.20 | Poisson >= 3.5 | Fano >= 4.0
                          • Rarity: Top 0.13% statistical tail. Standard C2/burst profile.
                          • Recommended Action: Investigate parent binary lineage & destination IP reputation.

🟡 [ELEVATED WATCH]    ──► Z >= 2.0σ | CV <= 0.35 | Poisson >= 2.0 | Fano >= 2.5
                          • Rarity: Top 2.5% deviation.
                          • Recommended Action: Correlate with concurrent user alerts, review user role.

🟢 [INFORMATIONAL]     ──► Z < 2.0σ | CV > 0.50 | Fano ≈ 1.0
                          • Rarity: Within standard daily operational variance.
                          • Recommended Action: No action required. Natural Poisson background chatter.
```

---

## 3. False Positive Reality Checks & Triage Playbooks

Every anomaly model has legitimate business causes. Use these checklists to rule out noise quickly:

### A. Process Execution Surges ($Z > 3.0$)
* **Common False Positives**:
  - Software developer builds / compilations (`ninja.exe`, `msbuild.exe`, `gcc`, `cargo`).
  - Endpoint management / deployment scripts (SCCM, Ansible, Microsoft Endpoint Manager).
  - Security sensor upgrades (CrowdStrike, Carbon Black, Defender agent updates).
* **SOC Triage Checklist**:
  1. [ ] Check Parent Binary: Is spawning process `cmd.exe`/`powershell.exe` vs `devenv.exe`/`CcmExec.exe`?
  2. [ ] Check User Account: Is the executor a service account vs an interactive end-user?
  3. [ ] Check Execution Paths: Are files launching from user-writable paths (`C:\Users\*\AppData\Local\Temp`)?

### B. Periodic Beaconing ($\text{CV} \le 0.20$)
* **Common False Positives**:
  - Network Time Protocol (NTP) synchronization polls.
  - OS telemetry & health check pings (Microsoft Windows Update, Apple APNS).
  - Corporate SaaS sync clients (Slack, Zoom, Teams, Google Drive keep-alives).
* **SOC Triage Checklist**:
  1. [ ] Check Fleet Prevalence: Does this external IP communicate with $> 10$ enterprise hosts? If yes $\to$ likely CDN/SaaS.
  2. [ ] Check TLS Certificate: Inspect SNI and Subject Alternative Name in `NETWORK_HTTP` events.
  3. [ ] Check Payload Entropy & Size: Are request/response sizes identical on every call?

### C. Burst Authentication Clustering ($\text{Fano} > 4.0$)
* **Common False Positives**:
  - Cached credential failure loops (Outlook / Mobile mail client with expired password).
  - Network mount reconnection retries (mapped SMB drive with old credentials).
* **SOC Triage Checklist**:
  1. [ ] Check Failure Reason: Is error code `STATUS_WRONG_PASSWORD` vs `STATUS_ACCOUNT_LOCKED_OUT`?
  2. [ ] Check Source IP Diversity: Are failures originating from a single internal IP (cached cred) or rotating external IPs (spray)?
