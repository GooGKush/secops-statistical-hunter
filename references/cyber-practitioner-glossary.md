# Cyber Practitioner Glossary & SOC Triage Playbooks

This guide provides down-to-earth analogies, operational concepts, false positive checklists, and step-by-step triage playbooks for statistical anomaly hunts.

---

## 1. Core SOC Detective Analogies

### 🕵️ "The Seasoned SOC Detective" (Poisson-Gamma Bayesian Credibility Shrinkage)
* **The Concept**: When a normally erratic, noisy host spikes, the detective demands massive evidence before declaring an alert. When a rock-solid, predictable machine spikes even slightly, the detective immediately investigates.
* **Math Behind It**: Gamma prior stability weights current evidence against historical volatility.

### 🛡️ "The Patch Tuesday Immunity Shield" (Dual-Baseline Delta-$Z$)
* **The Concept**: When IT pushes a monthly software update, thousands of machines spike simultaneously. The shield subtracts the company-wide fleet surge from the host's personal surge ($\Delta Z = Z_p - Z_f$), ensuring zero false alarms during fleet deployments.

### 📡 "The Combined Arms Threat Radar" (Multi-Sector Threat Fusion)
* **The Concept**: Sophisticated attackers operate "low-and-slow" across multiple silos (Auth, Process, Network) to stay under single-domain alert thresholds ($Z \approx 2.0\sigma$). The Combined Arms Radar computes the unified orthogonal vector distance $D = \sqrt{Z_{\text{auth}}^2 + Z_{\text{proc}}^2 + Z_{\text{net}}^2}$, detecting coordinated kill chains that traditional point detectors miss.

---

## 2. Standard Triage Playbooks

### Process Execution Surges
1. **Command Line Inspection**: Run drilldown query to check process paths (`.exe`, `.sh`) and arguments.
2. **User Account Context**: Is it an interactive employee account or a background service account (`SYSTEM`, `root`, `svc-`)?
3. **Execution Path Analysis**: Are binaries launching from temporary folders (`C:\Temp`, `AppData\Local\Temp`, `/tmp`)?
4. **Follow-On Network Activity**: Did the host establish sudden outbound network connections immediately following the process spike?

### Authentication Failures & Bursts
1. **Source IP Analysis**: Check internal subnet vs. external IP geolocation and ASN.
2. **User Account Breadth**: Is the attack spraying across multiple user accounts or hammering a single privileged account?
3. **Target Service**: Is the failure hitting SSH, RDP, VPN, Okta/IDP, or Workspace SSO?
