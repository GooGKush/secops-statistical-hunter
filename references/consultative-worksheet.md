# Consultative Threat Hunting Worksheet: Mapping Raw Telemetry Intent to Statistical Models

> ⚡ **JETSKI / MCP AGENT INSTRUCTION**:
> Inspect this master worksheet during **State 1 (Phase 1A)** when an analyst specifies an entity or hunting objective over raw UDM logs without naming an exact statistical model or event type.
> 
> **EXPERT BYPASS RULE**: If the analyst provides both the target telemetry (e.g. `PROCESS_LAUNCH` or `NETWORK_CONNECTION`) and statistical model (e.g. `MAD`, `Z-score`, or `CV`), **DO NOT CONSULT**. Bypass this worksheet immediately and emit the Pre-Flight Hunting Specification Card.

---

## 🧭 First Principles: The 5 Raw Behavioral Telemetry Deformations

Every threat—known, emerging, or zero-day—physically deforms raw UDM event streams in one of five distinct ways. When an analyst describes a scenario over raw logs, classify the underlying deformation to select the optimal statistical model:

```
┌─────────────────────────────┬───────────────────────────────┬──────────────────────────────────────┐
│ Telemetry Deformation       │ Physical Telemetry Signature │ Recommended Mathematical Model       │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 1. Robotic Timing Regularity│ Clockwork inter-arrival delays│ Coefficient of Variation (CV <= 0.20)│
│    ("The Machine Pulse")    │ (Δt) with low variance/jitter │ on raw network/DNS connections       │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 2. State Transition         │ Transition from 0 to positive │ Two-Part Hurdle Model                │
│    ("The Dormancy Break")   │ activity on quiet entities    │ (Discrete Hurdle + Intensity Z)      │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 3. Volumetric Shock         │ Sudden explosive surge over   │ Asymmetric Directional Z (ReLU),     │
│    ("The Spiky Rupture")    │ historical hourly baseline    │ Piecewise CRI, or Median Absolute Dev│
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 4. Repetitive Clumping      │ Synchronized bursts of logins │ Fano Factor Poisson Dispersion       │
│    ("The Burst Wave")       │ cycling to evade rate limits  │ (F = σ² / μ > 4.0)                   │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 5. Orthogonal Dispersion    │ Mild elevations across Auth,  │ Multi-Sector Threat Fusion           │
│    ("The Multi-Vector Fog") │ Endpoint, and Network silos   │ with Euclidean Norm (D >= 3.0σ)      │
└─────────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

---

## 🎯 The Three Threat Tiers

### Tier 1: Known Knowns (Immediate SOC Objectives)
* **High-Volume Exfiltration**: Massive outbound network or DNS byte spikes (`mad_exfiltration_2stage.yl2`).
* **Volumetric Password Sprays**: Massive authentication failures against single or multiple targets (`poisson_burst_clustering_2stage.yl2`).
* **Living-off-the-Land Process Surges**: Sudden spikes in administrative or dual-use binaries (`zscore_process_surge_2stage.yl2`).

### Tier 2: Known Unknowns (High-Impact Threats Static Rules Miss)
* **C2 Beaconing with Jitter**: Automated malware implants communicating at periodic intervals with randomized sleep delays (`c2_beaconing_jitter_2stage.yl2`).
* **Dormant Account Awakening**: Inactive service accounts or admin credentials suddenly initiating sessions (`two_part_hurdle_2stage.yl2`).
* **Privileged Lateral Traversal**: Administrators or service accounts logging into unprecedented clusters of workstations/servers (`privileged_lateral_expansion_2stage.yl2`).
* **Single-Trial Ratio Regularization**: High failure rates on low sample volumes regularized against population baselines (`beta_binomial_failure_4stage.yl2`).
* **Low-Entropy Scripted Exfiltration**: Automated transfers touching many destinations with low distinct URI/IP diversity (`hybrid_entropy_concentration_2stage.yl2`).

### Tier 3: Unknown Unknowns (Complex Multi-Vector Discovery)
* **Cross-Sector Multi-Vector Kill Chains**: Advanced campaigns where individual telemetry logs remain below single-point thresholds, but orthogonal Euclidean distance reveals compound anomaly (`multi_sector_threat_fusion_4stage.yl2`).

---

## 📋 The 5 Canonical Raw Hunting Domains & Summary View Menus

When engaging the analyst during State 1, use the **Summary View** menus below to present 2–3 targeted hypotheses mapped to static rule failure modes:

### Domain 1: In-Flight C2 & Covert Channels
* **Why Static Rules Miss It**: Fixed threshold alerts (e.g. `connections > 100`) miss implants sleeping for minutes, while interval alerts miss randomized jitter.
* **Summary View Options**:
  1. *Clockwork Beaconing with Jitter*: Evaluate inter-arrival timing consistency on outbound connections (**Coefficient of Variation CV <= 0.20** on `NETWORK_CONNECTION`).
  2. *Low-Entropy Scripted Staging*: Detect high-volume elephant flows to external destinations (**Elephant Flow Concentration** on `NETWORK_HTTP`).
  3. *DNS Tunneling & Chunked Egress*: Isolate anomalous payload sizes over port 53 (**Modified Z-Score via MAD** on `NETWORK_DNS`).

### Domain 2: Identity, Credential Stuffing & Dormancy
* **Why Static Rules Miss It**: Attackers rotate IPs to stay below lockout thresholds, and dormant accounts lack active baseline variance.
* **Summary View Options**:
  1. *Dormant Account Awakening*: Flag historically inactive users/service accounts initiating sessions (**Two-Part Hurdle Model** on `USER_LOGIN`).
  2. *Intermittent Burst Spray*: Surface clumping authentication waves designed to evade rolling rate limiters (**Fano Factor Poisson Dispersion** on `USER_LOGIN`).
  3. *Small-Sample Error Ratios*: Evaluate failure probability without false positives on 1-trial mistakes (**Beta-Binomial Regularization** on `USER_LOGIN`).

### Domain 3: Living-off-the-Land & Binary Execution Surges
* **Why Static Rules Miss It**: Administrative binaries (`powershell.exe`, `certutil.exe`) are legitimately used; static rules either drown in noise or miss localized machine surges.
* **Summary View Options**:
  1. *Parametric Host Surge*: Detect endpoints executing binaries at > 3 standard deviations above baseline (**Standard Z-Score** on `PROCESS_LAUNCH`).
  2. *Quiet Server Command Rarity*: Surface rarely executed tools on historically quiet infrastructure (**Discrete Poisson Rarity** on `PROCESS_LAUNCH`).
  3. *Fleet Prevalence Shielding*: Isolate targeted malware execution from company-wide software deployments (**Dual-Baseline Delta-Z** on `PROCESS_LAUNCH`).

### Domain 4: Scripted Staging & Bulk Data Exfiltration
* **Why Static Rules Miss It**: Attackers fragment data into sub-threshold uploads or exfiltrate across non-standard protocols.
* **Summary View Options**:
  1. *Robust Heavy-Tail Surges*: Identify extreme volumetric uploads resilient to historical outlier pollution (**Median Absolute Deviation MAD** on network egress).
  2. *Vocabulary Diversity Deficit*: Detect scripted automated dumps exhibiting extreme target concentration (**Diversity Deficit k/(N+1)** on HTTP requests).

### Domain 5: Lateral Movement & Privileged Account Traversal
* **Why Static Rules Miss It**: Admins have valid credentials across many hosts; point-in-time alerts cannot track machine radius expansion.
* **Summary View Options**:
  1. *Machine Radius Expansion*: Detect privileged users connecting to an unprecedented number of target hosts (**Privileged Lateral Expansion Z-Score** on `USER_LOGIN`).
  2. *Bipartite Host Origin Rarity*: Surface service accounts accessing repositories from unexpected source machines (**Poisson Origin Rarity** on `USER_RESOURCE_ACCESS`).

---

## 🔀 Inverted Cooperative Handoff Protocol (Steering to Risk Metrics)

* If the analyst asks for **30-day pre-computed behavioral baselines** (`metrics.*`), emit a **Skill Handoff Card** to `secops-risk-metrics-multistage` (`protocol: secops-threat-hunt-handoff-v1`).
* If the analyst requests **peer/cohort group UEBA comparisons** or **360° entity health check radars** -> steer to `secops-risk-metrics-multistage`.
* If the analyst needs **ad-hoc custom time slicing**, **sub-second Δt timing**, **command-line arguments**, or **raw UDM event forensics** -> retain execution in `secops-statistical-hunter`.
