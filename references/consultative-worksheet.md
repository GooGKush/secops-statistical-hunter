# Consultative Threat Hunting Worksheet: Mapping Raw Telemetry Intent to Statistical Models

> ⚡ **JETSKI / MCP AGENT INSTRUCTION**:
> Inspect this master worksheet during **State 1 (Phase 1A)** when an analyst specifies an entity or hunting objective over raw UDM logs without naming an exact statistical model or event type.
> 
> **EXPERT BYPASS RULE**: If the analyst provides both the target telemetry (e.g. `PROCESS_LAUNCH` or `NETWORK_CONNECTION`) and statistical model (e.g. `MAD`, `Z-score`, or `CV`), **DO NOT CONSULT**. Bypass this worksheet immediately and emit the Pre-Flight Hunting Specification Card.

---

## 🧭 First Principles: The 6 Raw Behavioral Telemetry Deformations

Every threat—known, emerging, or zero-day—physically deforms raw UDM event streams in one of six distinct ways. When an analyst describes a scenario over raw logs, classify the underlying deformation to select the optimal statistical model:

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
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 6. Enterprise Novelty       │ Activity involving entities   │ Z-Score with Derived Context         │
│    ("The Unseen Intruder")  │ with near-zero enterprise     │ Prevalence Multiplier                │
│                             │ presence (rolling_max <= 3)     │ (File / Domain 3-stage DAG)          │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 7. Lineage Surprisal        │ Benign parent spawning rare   │ Markov 2-Gram Transition Rarity      │
│    ("The Broken Chain")     │ anomalous child process       │ (-ln(P(B|A)) >= 3.0 surprisal score) │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 8. Syntactic Entropy        │ High character randomness in  │ Shannon Character-Class Entropy      │
│    ("The Scrambled Command")│ command lines, scripts, or DGA│ (Length & Information Density Score) │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 9. Long-Tail Rarity         │ Executions of tools in extreme│ Power-Law / Zipfian Inverse Rank     │
│    ("The Asymptotic Tool")  │ asymptotic tail (<= 2 hosts)  │ Frequency Rarity (f(k) ~ 1/k^s)      │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 10. Kinetic Acceleration    │ Instantaneous rate departure  │ Intraday Exponentially Weighted      │
│    ("The Sudden Thrust")    │ from smoothed trajectory      │ Moving Average (EWMA Velocity)       │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 11. Bipartite Fan-Out/Fan-In│ 1 source -> N targets (1 -> N)│ Privileged Lateral Expansion Z-Score │
│    ("The Graph Spider")     │ or N sources -> 1 host (N -> 1│ (`privileged_lateral_expansion_2stage│
│                             │ internal staging convergence) │ .yl2`) & Distinct Target Cardinality │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 12. Role Inversion (ρ)      │ Net consumer endpoint flips to│ Producer–Consumer Byte Ratio         │
│    ("The Role Reversal")    │ net producer (sent/(sent+recv)│ Inversion (`producer_consumer_ratio_ │
│                             │ >= 0.70 directional shift)    │ inversion_2stage.yl2`)               │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 13. Geospatial Velocity     │ Consecutive logins across     │ Haversine Geodesic Velocity          │
│    ("Supersonic Commuter")  │ unreachable coordinates       │ (`math.geo_distance`, Δd/Δt > 900    │
│                             │                               │ km/h, `impossible_travel_...yl2`)    │
├─────────────────────────────┼───────────────────────────────┼──────────────────────────────────────┤
│ 14. Quantile Asymmetry &    │ Right-skewed bursts, intra-   │ 1-Stage Quantiles (`window.percentile│
│     Tail Skew / Lag Drift   │ bucket payload bimodal split  │ P10..P90`), Bowley Skewness, Tail    │
│    ("The Asymmetric Tail")  │ (P90 >> P50), or clock skew   │ Ratio, QCD & Skew-Adjusted Tukey     │
│                             │ / ingestion lag (P10 < 0)     │ Fence (`iqr_tukey_skew_fences_...`)  │
└─────────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

### Persona-Conditioned Prior Matrix (Condition Model on Entity Persona First)

Before selecting a statistical model in State 1, condition your baseline expectations on the **target entity persona**:

| Entity Persona | Normal Baseline Physics | High-Signal Anomaly Signature & Model |
| :--- | :--- | :--- |
| **Human Interactive User** | Diurnal variance expected; chaotic inter-arrival intervals ($\text{CV} > 0.50$); bounded geography and host radius. | Robotic timing regularity (**`C2_BEACONING_JITTER`**, $\text{CV} \le 0.20$), supersonic geographic velocity (**`IMPOSSIBLE_TRAVEL_GEO_VELOCITY`**, $> 900\text{ km/h}$ via `math.geo_distance`), or machine radius expansion (**`PRIVILEGED_LATERAL_EXPANSION`**). |
| **Service Account / Workload Identity** | Clockwork timing is *normal*; fixed source runner IPs/hosts (`count_distinct(principal.ip) == 1`); deterministic repository scope. | **Source-IP/Host Breadth Expansion** ($>1$ origin via **`POISSON_ORIGIN_RARITY`**), interactive logon types, or dormancy awakening (**`TWO_PART_HURDLE`**). |
| **CI/CD Runner / Admin Jump Host** | High process/connection volume is normal; wide internal destination fan-out is routine. | **Long-Tail Zipfian Process Rarity** (**`ZIPFIAN_PROCESS_RARITY`**), **Parent-Child Markov Surprisal** (**`MARKOV_2GRAM_TRANSITION_RARITY`**), **First-Seen Domain Egress** (**`DERIVED_CONTEXT_DOMAIN_PREVALENCE`**), or **Producer–Consumer Byte Ratio Inversion** ($\rho \ge 0.70$). |

### Pre/Post Event-Anchored Changepoint Framing ($T_0$)

When an analyst asks *"Did behavior change after event $T_0$ (e.g., IAM role grant, HR termination notice, binary deployment, or firewall change)?"*:
* Partition the search into a **Pre-Event Baseline Window** $[T_0 - W, T_0)$ and a **Post-Event Observation Window** $[T_0, \text{now})$.
* Compare post-event intensity, breadth, or directional byte ratio ($\rho = \text{sent} / (\text{sent} + \text{received})$) against the pre-$T_0$ baseline distribution, or pair with **Intraday EWMA Burst Velocity** (`ewma_burst_velocity_2stage.yl2`) to isolate instantaneous post-$T_0$ trajectory departures.

### Executable Confounder Disambiguation & SecOps Data Tables (`%<table_name>`)

Pair each of the 4 Common-Sense Confounder Checks with its concrete query-level control:
1. **Innocent Corporate Explanation (Patch Tuesday / Mass Rollout)** $\rightarrow$ Enforce **Fleet Concurrency Count ($K$)** via `dual_baseline_delta_z_3stage.yl2` ($\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$) or `DERIVED_CONTEXT` prevalence (`prevalence.day_count = 10`, `prevalence.rolling_max <= 3` and `> 0`).
2. **Quiet Entity Trap (Zero-Inflated / Dormant Baseline)** $\rightarrow$ Use **Two-Part Hurdle** (`two_part_hurdle_2stage.yl2`) or **Discrete Poisson Rarity** (`poisson_rare_surge_2stage.yl2`) with non-zero dispersion floor (`if($sd > 0, $sd, 1.0)`).
3. **Past Noise Camouflage (Historical Outlier Pollution)** $\rightarrow$ Switch from parametric $Z$-score to **Median Absolute Deviation (MAD)** (`mad_modified_z_4stage.yl2`, $M_Z = 0.6745 \cdot (x - \tilde{x}) / \text{MAD}$).
4. **Approved Scanner / VIP Prior Adjustments (SecOps Data Tables `%<table_name>.<column>`)** $\rightarrow$ Suppress authorized scanners via `not principal.hostname in %authorized_scanners.hostname`, join entity risk priors via `%ueba_entity_priors.entity`, or consume Phase 1 bridge cohorts via `%ueba_hunt_bridge.hostname`.

---

## 🎯 The Three Threat Tiers

### Tier 1: Known Knowns (Immediate SOC Objectives)
* **High-Volume Exfiltration**: Massive outbound network or DNS byte spikes (`mad_modified_z_4stage.yl2`, with `daily_aggregation=sum(network.sent_bytes)` for byte volume).
* **Volumetric Password Sprays**: Massive authentication failures against single or multiple targets (`poisson_burst_clustering_2stage.yl2`).
* **Living-off-the-Land Process Surges**: Sudden spikes in administrative or dual-use binaries (`zscore_process_surge_2stage.yl2`).

### Tier 2: Known Unknowns (High-Impact Threats Static Rules Miss)
* **C2 Beaconing with Jitter**: Automated malware implants communicating at periodic intervals with randomized sleep delays (`c2_beaconing_jitter_2stage.yl2`).
* **Dormant Account Awakening**: Inactive service accounts or admin credentials suddenly initiating sessions (`two_part_hurdle_2stage.yl2`).
* **Privileged Lateral Traversal**: Administrators or service accounts logging into unprecedented clusters of workstations/servers (`privileged_lateral_expansion_2stage.yl2`).
* **Single-Trial Ratio Regularization**: High failure rates on low sample volumes regularized against population baselines (`beta_binomial_failure_4stage.yl2`).
* **Low-Entropy Scripted Exfiltration**: Automated transfers touching many destinations with low distinct URI/IP diversity (`hybrid_entropy_concentration_2stage.yl2`).
* **Enterprise-Unseen Binary Execution**: Local process execution spikes of binaries with zero or low enterprise-wide prevalence (`derived_context_file_prevalence_3stage.yl2`).
* **First-Contact Domain Egress**: Outbound connections to domains never observed in enterprise history (`derived_context_domain_prevalence_3stage.yl2`).
* **Unfamiliar Machine Logins**: Privileged accounts authenticating to newly commissioned assets (`derived_context_prevalence_3stage.yl2`).

### Tier 3: Unknown Unknowns (Complex Multi-Vector Discovery)
* **Cross-Sector Multi-Vector Kill Chains**: Advanced campaigns where individual telemetry logs remain below single-point thresholds, but orthogonal Euclidean distance reveals compound anomaly (`multi_sector_threat_fusion_4stage.yl2`).

---

## 📋 The 6 Canonical Raw Hunting Domains & Summary View Menus

When engaging the analyst during State 1, use the **Summary View** menus below to present 2–3 targeted hypotheses mapped to static rule failure modes:

### Domain 1: In-Flight C2 & Covert Channels
* **Why Static Rules Miss It**: Fixed threshold alerts (e.g. `connections > 100`) miss implants sleeping for minutes, while interval alerts miss randomized jitter.
* **Summary View Options**:
  1. *Clockwork Beaconing with Jitter*: Evaluate inter-arrival timing consistency on outbound connections (**Coefficient of Variation CV <= 0.20** on `NETWORK_CONNECTION`).
  2. *Outlier-Immune Quartile Dispersion (QCD)*: Detect periodic C2 beaconing on noisy endpoints where sporadic admin bursts inflate parametric $\sigma$ (**Quartile Coefficient of Dispersion $\text{QCD} = (Q_3 - Q_1)/(Q_3 + Q_1) \le 0.15$** via `window.percentile`).
  3. *Low-Entropy Scripted Staging*: Detect high-volume elephant flows to external destinations (**Elephant Flow Concentration** on `NETWORK_HTTP`).
  4. *DNS Tunneling & Chunked Egress*: Isolate anomalous payload sizes over port 53 (**Modified Z-Score via MAD** or **Skewness-Adjusted Tukey Fence** on `NETWORK_DNS`).
  5. *Beaconing to Enterprise-Unseen Domains*: Prioritize clockwork timing regularity targeting destinations contacted on $\le 5$ calendar days enterprise-wide (**C2 Jitter with Domain Prevalence** on `NETWORK_CONNECTION`).

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
  2. *Markov Parent-Child Transition Surprisal*: Flag anomalous child process spawning lineages (e.g. Word -> cmd, SQL Server -> PowerShell) (**Markov 2-Gram Information Surprisal** on `PROCESS_LAUNCH`).
  3. *Power-Law Zipfian Tool Long Tail*: Isolate rare administrative utility execution in the asymptotic fleet tail (**Zipfian Inverse Rank Rarity** on `PROCESS_LAUNCH`).
  4. *Obfuscated Scripting & Command Randomness*: Detect base64 encoding and high-entropy parameters (**Shannon Character-Class Entropy** on `PROCESS_LAUNCH`).
  5. *Quiet Server Command Rarity*: Surface rarely executed tools on historically quiet infrastructure (**Discrete Poisson Rarity** on `PROCESS_LAUNCH`).
  6. *Fleet Prevalence Shielding*: Isolate targeted malware execution from company-wide software deployments (**Dual-Baseline Delta-Z** on `PROCESS_LAUNCH`).
  7. *Unseen Staged Binary Bursts*: Isolate localized execution spikes while using enterprise host prevalence (`prevalence.rolling_max <= 3`) to separate unseen binaries from ubiquitous administrative utilities (**Derived Context File Prevalence** on `PROCESS_LAUNCH`).

### Domain 4: Scripted Staging & Bulk Data Exfiltration
* **Why Static Rules Miss It**: Attackers fragment data into sub-threshold uploads or exfiltrate across non-standard protocols.
* **Summary View Options**:
  1. *Robust Heavy-Tail Surges*: Identify extreme volumetric uploads resilient to historical outlier pollution (**Median Absolute Deviation MAD** on network egress).
  2. *Skewness-Adjusted Tukey Fence & Fleet Breadth*: Compute the 5-point quantile envelope ($P_{10}, Q_1, Q_2, Q_3, P_{90}$), Bowley quartile skewness ($B_{\text{skew}}$), and Hubert–Vandervieren skewness-adjusted upper fence in 1 stage while preserving Stage 3 for enterprise fleet prevalence (**`IQR_TUKEY_SKEW_FENCES`**, `iqr_tukey_skew_fences_3stage.yl2`).
  3. *Intra-Bucket Payload Quantile Shape Fingerprinting*: Separate C2 heartbeat keepalives mixed with burst exfiltration ($P_{50}$ tiny, $P_{90}$ huge, $B_{\text{skew}} \to +1.0$) from uniform bulk backups ($P_{50} \approx P_{90}$, $B_{\text{skew}} \approx 0$) inside a single stage.
  4. *Intraday Kinetic Acceleration*: Detect acute rate bursts without lagging trailing historical baselines (**Intraday EWMA Burst Velocity** on `PROCESS_LAUNCH` or `NETWORK_CONNECTION`).
  5. *Vocabulary Diversity Deficit*: Detect scripted automated dumps exhibiting extreme target concentration (**Diversity Deficit k/(N+1)** on HTTP requests).

### Domain 5: Lateral Movement & Privileged Account Traversal
* **Why Static Rules Miss It**: Admins have valid credentials across many hosts; point-in-time alerts cannot track machine radius expansion.
* **Summary View Options**:
  1. *Machine Radius Expansion*: Detect privileged users connecting to an unprecedented number of target hosts (**Privileged Lateral Expansion Z-Score** on `USER_LOGIN`).
  2. *Bipartite Host Origin Rarity*: Surface service accounts accessing repositories from unexpected source machines (**Poisson Origin Rarity** on `USER_RESOURCE_ACCESS`).
  3. *Traversal to Newly Commissioned Assets*: Detect privileged accounts expanding laterally into machines seen for the first time within the last 7 days (**Derived Context Asset Age** on `USER_LOGIN`).

### Domain 6: Persistent Context & Derived Prevalence Hunting
* **Why Static Rules Miss It**: In-flight telemetry lacks historical enterprise perspective; an unknown binary executed 5 times might look benign in a 1-hour window, but is acutely alarming if it has rare across the enterprise (`prevalence.rolling_max <= 3` and `> 0` over `prevalence.day_count = 10`).
* **Summary View Options**:
  1. *Unseen Binary Execution Bursts*: Detect localized process execution spikes of binaries with low enterprise-wide prevalence (**Derived Context File Prevalence** on `PROCESS_LAUNCH`).
  2. *First-Seen Domain Egress*: Identify high-volume outbound network transfers to domains never previously contacted by the enterprise (**Derived Context Domain Prevalence** on `NETWORK_CONNECTION`).
  3. *Unfamiliar Machine Authentication*: Detect privileged accounts logging into newly commissioned or historically unseen endpoints (**Derived Context Asset Age** on `USER_LOGIN`).

---

## 🛡️ The Enterprise-Grounded Hunt & Dual-Sided Prevalence Filtering Pattern

When scoping hunts with analysts, present `DERIVED_CONTEXT` as a dual-sided intelligence instrument that both **escalates genuine zero-days** and **suppresses alert fatigue**:

### 1. The Cold-Start Blindspot
Short-horizon raw telemetry searches (e.g. 24h or 7d) are blind to enterprise history:
- An attacker executing a newly compiled dropper 3 times on a single quiet host looks like a minor statistical fluctuation ($Z \approx 1.5\sigma$).
- A legitimate monitoring agent executing 500 times an hour looks like a catastrophic statistical surge ($Z > 10.0\sigma$).
Chronicle's Entity Context Graph (`DERIVED_CONTEXT`) bridges this gap by persisting enterprise prevalence over configured rolling horizons (`prevalence.day_count = 10`, `prevalence.rolling_max`, `first_seen_time`).

### 2. The Two-Tier Scoping Choice
When discussing candidate queries with an analyst exploring endpoint or network anomalies, offer the two-tier scoping choice:
* **Tier A (Pure Local Baseline)**: Evaluates spikes strictly against that endpoint's local historical mean and standard deviation.
* **Tier B (Enterprise-Grounded Hunt)**: Joins Chronicle `DERIVED_CONTEXT` to cross-reference enterprise prevalence, boosting rare tools and suppressing ubiquitous fleet software.

### 3. Dual-Sided Prevalence Filtering Mechanics
* **Upward Escalation ($2.5\times$ Boost)**: Applies a multiplier to threat scores when the entity's peak daily enterprise host count is $\le 3$ (`prevalence.rolling_max <= 3` and `> 0` with `prevalence.day_count = 10`), ensuring rare tools break through alerting thresholds.
* **Downward Suppression (Allowlisting via Prevalence)**: Down-ranks or filters out binaries and domains that exhibit extensive enterprise history (`prevalence.rolling_max > 500` hosts), protecting the SOC from Patch Tuesday and corporate software deployments.

---

## 📐 Real-World Non-Parametric Quantile & Skewness Hunting Playbook (`window.percentile`)

Because `window.percentile(expr, P)` evaluates any percentile $P \in [0, 100]$ over raw event expressions or upstream stage variables in a **single stage**, it unlocks four real-world hunting capabilities that previously required either 2 stages (MAD) or parametric assumptions ($\mu, \sigma$):

### Use Case 1: Skewness-Adjusted Tukey Upper Fence with Native Fleet Prevalence (`IQR_TUKEY_SKEW_FENCES`)
* **Operational Problem**: Standard Tukey fences ($Q_3 + 1.5 \cdot \text{IQR}$) generate false positives on naturally right-skewed servers (e.g., build runners or DNS forwarders), while 2-stage MAD (`median_stats` $\to$ `mad_stats`) consumes 2 intermediate stages, leaving no stage for fleet prevalence (`$fleet_prevalence = -1`) or Entity Context Graph enrichment in a 3-stage pipeline.
* **Mathematical Solution**: Compute $P_{10}, Q_1, Q_2, Q_3, P_{90}$ in a single stage (`quantile_fences`), compute **Bowley's Quartile Skewness** $B_{\text{skew}} = (Q_3 + Q_1 - 2 Q_2) / \text{IQR}$, and apply the **Hubert–Vandervieren Skewness-Adjusted Upper Fence** $Q_3 + 1.5 \cdot e^{3 \cdot \max(0, B_{\text{skew}})} \cdot \text{IQR}$ (`templates/pipelines/iqr_tukey_skew_fences_3stage.yl2`).

### Use Case 2: Intra-Bucket Payload Quantile Shape Fingerprinting (C2 Heartbeat + Exfil vs. Bulk Backup)
* **Operational Problem**: Two hosts each transfer 50 MB in 1 hour (`sum(network.sent_bytes)` is identical). Host A is running a uniform nightly backup (`1,000` flows of `50 KB` each: $P_{50} \approx P_{90}$). Host B is running a C2 beacon sending 64-byte keepalives every 5 seconds plus three 16 MB stolen archive uploads ($P_{50} = 64\text{ B}$, $P_{90} = 16\text{ MB}$, $B_{\text{skew}} \to +1.0$).
* **Compilable YARA-L 2.0 Pattern** (verified on Chronicle SIEM):
```yara
// Goal: Distinguish C2 heartbeat + burst exfiltration (high intra-bucket Bowley skew & P90/P50 ratio) from uniform bulk backups.
stage stage1_flow_shape {
    metadata.event_type = "NETWORK_CONNECTION"
    principal.hostname = $entity
    $entity != ""
    target.ip = $dst_ip
    $dst_ip != ""
    network.sent_bytes > 0
  match:
    $entity by 1h
  outcome:
    $flow_count = count(metadata.id)
    $total_bytes = sum(network.sent_bytes)
    $distinct_targets = count_distinct($dst_ip)
    $sample_targets = array_distinct($dst_ip)
    $p25_bytes = window.percentile(network.sent_bytes, 25)
    $p50_bytes = window.percentile(network.sent_bytes, 50)
    $p75_bytes = window.percentile(network.sent_bytes, 75)
    $p90_bytes = window.percentile(network.sent_bytes, 90)
}
stage stage2_host_baseline {
    $entity = $stage1_flow_shape.entity
  match:
    $entity
  outcome:
    $active_hours = count_distinct($stage1_flow_shape.window_start)
    $median_hourly_bytes = window.percentile($stage1_flow_shape.total_bytes, 50)
    $q75_hourly_bytes = window.percentile($stage1_flow_shape.total_bytes, 75)
    $q25_hourly_bytes = window.percentile($stage1_flow_shape.total_bytes, 25)
}
$entity = $stage1_flow_shape.entity
$entity = $stage2_host_baseline.entity
$ws = $stage1_flow_shape.window_start
match:
  $entity, $ws by 1h
outcome:
  $observation_count = max($stage1_flow_shape.total_bytes)
  $baseline_active_samples = max($stage2_host_baseline.active_hours)
  $baseline_mean = max($stage2_host_baseline.median_hourly_bytes)
  $baseline_dispersion = max($stage2_host_baseline.q75_hourly_bytes) - max($stage2_host_baseline.q25_hourly_bytes)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($stage1_flow_shape.distinct_targets)
  $sample_commands = array_distinct($stage1_flow_shape.sample_targets)

  $flows_in_hour = max($stage1_flow_shape.flow_count)
  $q25_flow = max($stage1_flow_shape.p25_bytes)
  $q50_flow = max($stage1_flow_shape.p50_bytes)
  $q75_flow = max($stage1_flow_shape.p75_bytes)
  $p90_flow = max($stage1_flow_shape.p90_bytes)
  $flow_iqr = $q75_flow - $q25_flow
  $safe_flow_iqr = if($flow_iqr > 0, $flow_iqr, 1.0)
  $flow_bowley_num = $q75_flow + $q25_flow - (2.0 * $q50_flow)
  $flow_bowley_skew = $flow_bowley_num / $safe_flow_iqr
  $safe_p50 = if($q50_flow > 0, $q50_flow, 1.0)
  $p90_to_p50_ratio = $p90_flow / $safe_p50
condition:
  $baseline_active_samples >= 6
  and $flows_in_hour >= 20
  and $p90_to_p50_ratio >= 10.0
order:
  $p90_to_p50_ratio desc
```

### Use Case 3: Outlier-Immune Beaconing Regularity via Quartile Coefficient of Dispersion (`QCD`)
* **Operational Problem**: A C2 beacon firing every 5 minutes produces rock-steady hourly connection counts ($Q_1 \approx Q_2 \approx Q_3$), but if the user opens a browser for 10 minutes during the day, a single hourly spike inflates parametric $\sigma$, pushing $CV = \sigma / \mu$ above `0.20` and blinding standard CV beaconing detection.
* **Mathematical Solution**: Compute the **Quartile Coefficient of Dispersion** $\text{QCD} = (Q_3 - Q_1) / (Q_3 + Q_1) \in [0, 1]$. Because $Q_1$ and $Q_3$ have a 25% breakdown point, up to 25% of hours can contain noisy interactive browsing without affecting $\text{QCD} \le 0.15$!

### Use Case 4: Telemetry Ingestion Lag, Clock-Skew & Log-Tampering / Timestomping Quantile Audit
* **Operational Problem**: Endpoint clock drift, VM snapshot restores, adversary timestomping, or log-forwarder batch buffering can cause events to arrive with negative lag (`ingested_timestamp < event_timestamp`, $P_{10} < 0$) or severe right-skewed ingestion delay ($P_{90} \gg P_{50}$, $B_{\text{skew}} \to +1.0$), blinding real-time detection rules and Mode A windows.
* **Compilable YARA-L 2.0 Pattern** (verified on Chronicle SIEM):
```yara
// Goal: Profile telemetry ingestion lag quantiles, Bowley skewness, and negative clock-skew / timestomp anomalies per log_type.
metadata.event_timestamp.seconds > 0
$log_type = metadata.log_type
$log_type != ""

match:
  $log_type by 1h

outcome:
  $event_count = count(metadata.id)
  $p10 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 10)
  $p25 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 25)
  $p50 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 50)
  $p75 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 75)
  $p90 = window.percentile(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds, 90)

  $iqr = $p75 - $p25
  $bowley_num = $p75 + $p25 - (2 * $p50)
  $safe_iqr = if($iqr > 0, $iqr, 1.0)
  $bowley_skew = $bowley_num / $safe_iqr
  $idr = $p90 - $p10
  $tail_heaviness = $idr / $safe_iqr

condition:
  $event_count >= 10 and ($p10 < 0 or $p90 >= 300 or $bowley_skew >= 0.75)

order:
  $p90 desc
```

---

## 🔀 Inverted Cooperative Handoff Protocol (Steering to Risk Metrics)

* If the analyst asks for **30-day pre-computed behavioral baselines** (`metrics.*`), emit a **Skill Handoff Card** to `secops-risk-metrics-multistage` (`protocol: secops-threat-hunt-handoff-v1`; e.g., failed-login 30d baselines route to `metrics.auth_attempts_fail`, while general login volume routes to `metrics.auth_attempts_total`).
* If the analyst requests **peer/cohort group UEBA comparisons** or **360° entity health check radars** -> steer to `secops-risk-metrics-multistage`.
* If the analyst needs **ad-hoc custom time slicing**, **sub-second Δt timing**, **command-line arguments**, or **raw UDM event forensics** -> retain execution in `secops-statistical-hunter`.
