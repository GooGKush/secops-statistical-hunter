#!/usr/bin/env python3
# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Generates references/statistical-models-taxonomy.md and references/dynamic-windowing-matrix.md
# directly from scripts/multistage_query_builder.py, ensuring Code-as-Single-Source-of-Truth.

from pathlib import Path
import sys

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

from scripts.multistage_query_builder import (
    SENSITIVITY_MAP,
    MultiStageTemplateRouter,
    get_adaptive_window_parameters,
    calculate_fleet_adjusted_threshold,
)


def generate_statistical_taxonomy() -> str:
  lines = [
      "<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->",
      "",
      "# Mathematical Models & Statistical Taxonomy for Threat Hunting",
      "",
      "This reference details the mathematical physics, derivations, and formulas used across `secops-statistical-hunter`.",
      "",
      "---",
      "",
      "## 1. Leave-One-Out Parametric Historical Standardization ($Z$-Score)",
      "* **Goal**: Detect sudden vertical bursts in volume over an out-of-sample Gaussian historical baseline.",
      "* **Formula**:",
      "  $$Z = \\frac{x_t - \\mu_{-t}}{\\max\\left(s_{-t}, \\sqrt{\\max(\\mu_{-t}, 1.0)}\\right)}$$",
      "* **Where**:",
      "  - $x_t$: Scored bucket observation count (`$observation_count`).",
      "  - $\\mu_{-t}, s_{-t}$: Leave-one-out ($n - 1$) sample mean and sample standard deviation excluding bucket $t$.",
      "* **Guards**: Replaces brittle `min_sd` condition cliffs with the continuous Poisson floor $\\sqrt{\\max(\\mu_{-t}, 1.0)}$.",
      "",
      "---",
      "",
      "## 2. Poisson-Gamma Bayesian Predictive Standardization (`BAYESIAN_GAMMA_SHRINKAGE`)",
      "* **Goal**: Isolate high-confidence bursts on stable hosts while shrinking steady overdispersed servers.",
      "* **Leave-One-Out Conjugate Gamma Prior & Excess Overdispersion**:",
      "  $$\\alpha_{\\text{prior}} = \\alpha_0 + S_{-t}, \\quad \\beta_{\\text{prior}} = \\beta_0 + T_{\\text{prior}}, \\quad \\mu_0 = \\frac{\\alpha_{\\text{prior}}}{\\beta_{\\text{prior}}}$$",
      "  $$\\sigma_{\\text{pred}}^2 = \\max\\left(1.0, \\mu_0 \\frac{\\beta_{\\text{prior}} + 1}{\\beta_{\\text{prior}}} + \\max\\left(0, \\frac{Q_{-t}}{T_{\\text{prior}}} - \\bar{x}_{-t}^2 - \\bar{x}_{-t}\\right)\\right), \\quad Z_{\\text{Bayes}} = \\frac{x_t - \\mu_0}{\\sqrt{\\sigma_{\\text{pred}}^2}}$$",
      "",
      "---",
      "",
      "## 3. Beta-Binomial Predictive Failure Standardization (`BETA_BINOMIAL_FAILURE`)",
      "* **Goal**: Regularize small-sample failure ratios while suppressing accounts with chronically elevated historical failure rates.",
      "* **Leave-One-Out Conjugate Beta Prior**: $\\alpha_{\\text{prior}} = 1.0 + F_{-t}, \\quad \\beta_{\\text{prior}} = 19.0 + (N_{-t} - F_{-t}), \\quad p_0 = \\frac{\\alpha_{\\text{prior}}}{M}$, where $M = \\alpha_{\\text{prior}} + \\beta_{\\text{prior}}$.",
      "* **Predictive Failure $Z$-Score (`$fail_z`)**:",
      "  $$\\text{Var}_{\\text{pred}} = \\max\\left(0.25, n_t p_0 (1 - p_0) \\frac{M + n_t}{M + 1}\\right), \\quad Z_{\\text{fail}} = \\frac{f_t - n_t p_0}{\\sqrt{\\text{Var}_{\\text{pred}}}}$$",
      "",
      "---",
      "",
      "## 4. Dual-Baseline Delta-$Z$ (\"The Patch Tuesday Shield\")",
      "* **Goal**: Isolate targeted endpoint spikes from company-wide software deployments across mature peers.",
      "* **Formula**:",
      "  $$\\Delta Z = Z_{\\text{Personal, LOO}} - \\max(0, Z_{\\text{Fleet Mature Shift}})$$",
      "* **Behavior**:",
      "  - Company-wide deployment across mature peers: $Z_{\\text{Personal}} \\approx 12.0$, $Z_{\\text{Fleet}} \\approx 12.0 \\implies \\Delta Z \\approx 0.0$ (Suppressed).",
      "  - Targeted single-host attack: $Z_{\\text{Personal}} \\approx 12.0$, $Z_{\\text{Fleet}} \\approx 0.0 \\implies \\Delta Z \\approx 12.0$ (Triggered).",
      "",
      "---",
      "",
      "## 5. Multi-Sector Threat Fusion (\"Combined Arms Radar\")",
      "* **Goal**: Detect coordinated low-and-slow kill chains across Auth, Endpoint, and Network silos.",
      "* **Orthogonal Euclidean Threat Vector Distance**:",
      "  $$D = \\sqrt{Z_{\\text{Auth}}^2 + Z_{\\text{Process}}^2 + Z_{\\text{Network}}^2}$$",
      "* **YARA-L Optimization**: Evaluated via squared distance $D^2 = Z_1^2 + Z_2^2 + Z_3^2 \\ge 9.0$ ($D \\ge 3.0\\sigma$).",
      "",
      "---",
      "",
      "## 6. Poisson Dispersion / Fano Factor ($F$)",
      "* **Goal**: Detect synchronized attack pulses, brute-force waves, and beaconing bursts.",
      "* **Formula**:",
      "  $$F = \\frac{\\sigma^2}{\\mu}$$",
      "* **Interpretation**:",
      "  - $F \\approx 1.0$: Pure random Poisson background noise (human activity).",
      "  - $F \\gg 3.0$: Heavy super-Poisson clustering (automated attack scripts).",
      "",
      "---",
      "",
      "## 7. Destination Diversity & Concentration Screen (`HYBRID_ENTROPY_CONCENTRATION`)",
      "* **Goal**: Detect destination diversity collapse paired with single-flow outbound byte concentration using strictly non-negative thresholds.",
      "* **Formulas**:",
      "  $$Z_{\\text{deficit}} = \\max\\left(0, \\frac{\\mu_{d,-t} - d_t}{\\max(s_{d,-t}, \\sqrt{\\max(\\mu_{d,-t}, 1.0)})}\\right), \\quad \\text{ConcRatio} = \\frac{\\text{PeakBytes}_t}{\\max(\\text{SumBytes}_t, 1)}$$",
      "  $$\\text{ThreatScore} = 3.0 \\cdot \\sqrt{\\left(\\frac{Z_{\\text{deficit}}}{Z_{\\min}}\\right)^2 + \\left(\\frac{\\text{ConcRatio}}{C_{\\min}}\\right)^2}$$",
      "",
      "---",
      "",
      "## 8. Elephant Flow Concentration Ratio",
      "* **Goal**: Detect single massive exfiltration bursts masked within routine traffic.",
      "* **Formula**:",
      "  $$\\text{Concentration Ratio} = \\frac{\\text{Peak Transfer}}{\\max(\\sum \\text{Transfers}, 1)}$$",
      "* **Interpretation**:",
      "  - Extreme concentration ($\\text{Concentration Ratio} \\ge 0.65$) indicates an isolated elephant flow.",
      "",
      "---",
      "",
      "## 9. Multiple-Comparison Fleet Correction (Bonferroni Extreme Value Bound)",
      "* **Goal**: Scale anomaly thresholds automatically when scanning large fleets ($N$ hosts).",
      "* **Formula**:",
      "  $$Z_{\\text{adj}} = \\max\\left(Z_{\\text{base}}, \\sqrt{2 \\ln N}\\right)$$",
      "",
      "---",
      "",
      "## 10. Multi-Sector Orthogonal Euclidean Threat Distance ($D$)",
      "* **Goal**: Synthesize multi-stage kill chains across Authentication, Endpoint, and Network into a single orthogonal Euclidean distance norm using Malachite Function Factory `math.sqrt()`.",
      "* **Formula**:",
      "  $$D = \\sqrt{\\sum_{i=1}^{k} Z_i^2} = \\text{math.sqrt}(Z_{\\text{auth}}^2 + Z_{\\text{proc}}^2 + Z_{\\text{net}}^2)$$",
      "* **Interpretation**:",
      "  - Replaces squared-distance workarounds ($D^2$) with true Euclidean metric distance $D \\ge 3.0\\sigma$.",
      "",
      "---",
      "",
      "## 11. Leave-One-Out Log-Normal Volumetric Standardization ($Z_{\\log}$)",
      "* **Goal**: Isolate extreme byte bursts over heavy-tailed, skewed network and data exfiltration streams without parametric Gaussian distortion.",
      "* **Formula**:",
      "  $$Y_t = \\text{math.log}(\\text{bytes}_t + 1.0), \\quad Z_{\\log} = \\frac{Y_t - \\mu_{Y,-t}}{\\max(s_{Y,-t}, 0.25)}$$",
      "* **Interpretation**:",
      "  - Leave-one-out log-standardization with a continuous $0.25$ log-SD floor suppresses routine $<2\\times$ jitter while keeping all 6 Evidence Pillars in byte units.",
      "",
      "---",
      "",
      "## 12. Continuous Calibrated Risk Index (CRI [0–100]) Post-Processing & Translation",
      "* **Goal**: Translate raw multi-stage $Z$-scores or threat distances into a bounded [0, 100] SOC operational triage index.",
      "* **Piecewise Logistic Sigmoid Formula** (computed in Python post-processing via `calculate_cri()`, or in YARA-L outcome expressions using `math.pow(2.718281828, ...)` since `math.exp()` is not registered in the Malachite YARA-L 2.0 function factory):",
      "  $$\\text{CRI}(Z) = \\begin{cases} 0 & Z \\le 0 \\\\ \\text{round}\\left(\\frac{100.0}{1.0 + 2.718281828^{-0.6 \\cdot (Z - 3.0)}}\\right) & Z > 0 \\end{cases}$$",
      "* **YARA-L 2.0 Outcome Equivalent**:",
      "  `$cri = if($z_score <= 0, 0, math.round(100.0 / (1.0 + math.pow(2.718281828, (0 - 0.6) * ($z_score - 3.0)))))`",
      "",
      "---",
      "",
      "## 13. Markov 2-Gram Laplace-Smoothed Transition Surprisal (`MARKOV_2GRAM_TRANSITION_RARITY`)",
      "* **Goal**: Detect rare living-off-the-land process execution chains and unusual parent-child lineages without artificial step cliffs.",
      "* **Formula**:",
      "  $$P(B \\mid A) = \\frac{\\text{Count}(A \\to B) + 1.0}{\\text{Count}(A) + V}, \\quad \\text{Score} = \\ln\\left(\\frac{\\text{Count}(A) + V}{\\text{Count}(A \\to B) + 1.0}\\right)$$",
      "* **Interpretation**:",
      "  - Whole-window Laplace smoothing ($V = 100$) enables single rare macro-to-shell transitions (`winword.exe` $\\to$ `powershell.exe`) to score $\\ln(101/2) \\approx 3.92 \\ge 3.0$ while decaying smoothly and monotonically.",
      "",
      "---",
      "",
      "## 14. Long-String & Rare-Token Candidate Screen (`SHANNON_ENTROPY_CHARACTER` — long-string screen)",
      "* **Goal**: Screen unusually long and rare command lines (`principal.process.command_line`), URLs, or DNS query names (`{{token_field}}`) in stateless YARA-L (`D6 G5`; true per-character Shannon entropy runs in the vetted Python helper `WS6-03`).",
      "* **Formula**:",
      "  $$\\text{Score} = \\ln(\\text{Length}) + \\ln\\left(1.0 + \\frac{N_{\\text{entity}}}{N_{\\text{token}}}\\right)$$",
      "* **Guards**: Enforces minimum token length ($L \\ge 25$ in `BALANCED`) on parameterized `{{token_field}}`.",
      "* **Interpretation**:",
      "  - Suppresses short repetitive command flags while surfacing long, low-frequency obfuscated command lines and rare DGA query strings for character-entropy inspection.",
      "",
      "---",
      "",
      "## 15. Host-Prevalence Inverse Document Frequency Rarity (`ZIPFIAN_PROCESS_RARITY`)",
      "* **Goal**: Isolate rare binaries in the enterprise long tail by pure host adoption breadth without mixing event volume and host counts.",
      "* **Formula**:",
      "  $$\\text{ZipfScore} = \\ln\\left(\\frac{N_{\\text{fleet hosts}}}{N_{\\text{adopter hosts}}}\\right)$$",
      "* **Interpretation**:",
      "  - Novel single-host binaries in a 50-host fleet score $\\ln(50/1) \\approx 3.91$, strictly outranking chatty multi-host daemons.",
      "",
      "---",
      "",
      "## 16. Leave-One-Out Intraday Burst Z (`EWMA_BURST_VELOCITY` — burst Z) & Flow-Gap Ratio (`C2_BEACONING_JITTER` — flow-gap ratio)",
      "* **Goal**: Provide honest stateless in-query YARA-L screens (`D6 G5`) where recursive lag EWMA (`WS6-02`) and consecutive inter-arrival jitter (`WS6-04`) require vetted Python helpers.",
      "* **Formulas**:",
      "  $$\\text{Burst } Z = \\frac{x_t - \\mu_{-t}}{\\max\\left(s_{-t}, \\sqrt{\\max(\\mu_{-t}, 1.0)}\\right)}, \\quad \\text{Flow-Gap Ratio CV} = \\frac{s_{\\text{gap}}}{\\max(\\mu_{\\text{gap}}, 1.0)}$$",
      "* **Where**: `burst Z` excludes the scored bucket ($n - 1$) with a continuous Poisson floor, and `flow-gap ratio` excludes RFC 1918, multicast (`224.0.0.0/4`, `ff00::/8`), broadcast (`255.255.255.255/32`), and link-local (`169.254.0.0/16`, `fe80::/10`) traffic.",
      "",
      "---",
      "",
      "## 17. Learned 24-Bin Hour-of-Day Profile (`HOUR_OF_DAY_PROFILE`)",
      "* **Goal**: Detect off-hours or circadian out-of-profile activity per entity without relying on hardcoded UTC business hours or noisy city-centroid geo-velocity (`IMPOSSIBLE_TRAVEL_GEO_VELOCITY` retired under `D1`).",
      "* **Formula**:",
      "  $$\\mu_h = \\frac{\\sum_{t \\notin S} x_{t,h}}{D_{\\text{base}}}, \\quad \\sigma_h^2 = \\max\\left(0, \\frac{\\sum_{t \\notin S} x_{t,h}^2}{D_{\\text{base}}} - \\mu_h^2\\right), \\quad \\sigma_{\\text{safe},h} = \\max\\left(\\sqrt{\\sigma_h^2}, \\sqrt{\\max(\\mu_h, 1.0)}\\right), \\quad Z_{\\text{hod}} = \\frac{x_{\\text{obs},h} - \\mu_h}{\\sigma_{\\text{safe},h}}$$",
      "* **Interpretation**:",
      "  - Scores each hour in the final scoring window out-of-sample against the prior $D_{\\text{base}}$ calendar days (zero-count hours included via $D_{\\text{base}}$ and stabilized by the continuous Poisson floor $\\sqrt{\\max(\\mu_h, 1.0)}$), alongside `$hour_profile_mass` measuring the entity's historical fraction of activity in hour $h$.",
      "",
      "---",
      "",
      "## 18. Leave-One-Out Producer–Consumer Ratio Inversion (`PRODUCER_CONSUMER_RATIO_INVERSION`)",
      "* **Goal**: Detect an endpoint shifting from a net data consumer to a net data producer while suppressing steady high-ratio log forwarders.",
      "* **Formula**:",
      "  $$\\rho_t = \\frac{\\text{SentBytes}_t}{\\text{SentBytes}_t + \\text{ReceivedBytes}_t + 1.0}, \\quad Z_{\\rho} = \\frac{\\rho_t - \\mu_{\\rho,-t}}{\\max(s_{\\rho,-t}, 0.05)}$$",
      "* **Interpretation**:",
      "  - Dedicated forwarders with steady $\\rho \\approx 0.90$ yield $Z_{\\rho} \\approx 0$, whereas a consumer workstation ($\\mu_{\\rho} \\approx 0.10$) inverting to $\\rho_t = 0.85$ triggers $Z_{\\rho} \\gg 3.0$.",
      "",
      "---",
      "",
      "## 19. Recalibrated Bowley Skewness-Adjusted Tukey Fence Excess $Z$ (`IQR_TUKEY_SKEW_FENCES`)",
      "* **Goal**: Isolate heavy-tailed volumetric surges in scale-invariant standard-deviation units using a single 5-point quantile stage.",
      "* **Formulas**:",
      "  $$\\text{SafeIQR} = \\max(Q_3 - Q_1, \\max(0.01 Q_2, 1.0)), \\quad B_{\\text{skew}} = \\frac{Q_3 + Q_1 - 2 Q_2}{\\text{SafeIQR}} \\in [-1, +1]$$",
      "  $$\\text{Fence}_{\\text{adj}} = Q_3 + 1.5 \\cdot e^{1.35 \\cdot \\max(0, B_{\\text{skew}})} \\cdot \\text{SafeIQR}, \\quad Z_{\\text{fence}} = \\frac{x_t - \\text{Fence}_{\\text{adj}}}{\\text{SafeIQR} / 1.349}$$",
      "* **Interpretation**:",
      "  - Recalibrates the Hubert-Vandervieren exponent to $1.35$ for bounded Bowley quartile skewness, replaces fixed IQR cliffs with a continuous relative floor, and frees Stage 3 for enterprise fleet prevalence (`$fleet_prevalence`).",
      "",
      "---",
      "",
      "## 20. Canonical Golden Pipeline Template Mapping (24 Templates)",
      "",
      "| Pipeline Template (`.yl2`) | Canonical `SENSITIVITY_MAP` Key |",
      "| :--- | :--- |",
  ]

  for tmpl_file, sens_key in sorted(MultiStageTemplateRouter.TEMPLATE_TO_SENSITIVITY_KEY.items()):
    lines.append(f"| `{tmpl_file}` | `{sens_key}` |")

  lines.extend([
      "",
      "---",
      "",
      "## 21. Sensitivity & Anomaly Threshold Map",
      "",
      "| Archetype | Tier | Thresholds & Parameters |",
      "| :--- | :--- | :--- |",
  ])

  for arch, tiers in sorted(SENSITIVITY_MAP.items()):
    for tier_name, params in tiers.items():
      param_str = ", ".join(f"`{k}={v}`" for k, v in params.items())
      lines.append(f"| `{arch}` | **{tier_name}** | {param_str} |")

  lines.extend([
      "",
      "---",
      "*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*",
      "",
  ])
  return "\n".join(lines)


def generate_dynamic_windowing_matrix() -> str:
  lines = [
      "<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->",
      "",
      "# Dynamic Windowing & Adaptation Matrix",
      "",
      "This matrix defines adaptive bucket granularity and proportional sample floors across search durations, supporting both the **Micro Temporal Spine** (`10m`, `15m`, `1h`) and the **Daily Macro Spine** (`1d`).",
      "",
      "### 1. Dual Temporal Spines Architecture",
      "| Horizon | Target Use Case | Recommended Bucket | Sample Floor | Temporal Alignment |",
      "| :--- | :--- | :--- | :--- | :--- |",
      "| **Short Horizon (6h – 72h)** | Intra-day bursts, C2 beaconing jitter, password sprays | `10m`, `15m`, `1h` | 9 to 24 samples | Micro-analysis of sub-daily timing variance |",
      "| **Multi-Day Horizon (7d – 30d)** | Multi-sector threat fusion, volume surges, dormant awakening | `1d` | 3 to 12 samples | **1:1 reconciliation with `secops-risk-metrics-multistage`** |",
      "| **High-Frequency Multi-Day (7d – 14d)** | Multi-day beaconing persistence with sleep jitter | `1h` | 42 to 60 samples | Preserves hourly resolution across weeks |",
      "",
      "### 2. Proportional Duration Matrix",
      "| Duration | Micro Bucket | Daily Macro Bucket | Proportional Sample Floor | Total Horizon |",
      "| :--- | :--- | :--- | :--- | :--- |",
  ]

  durations = [
      (6.0, "6 Hours (Near-Real-Time)"),
      (12.0, "12 Hours (Half-Day Shift)"),
      (24.0, "24 Hours (Daily Rolling)"),
      (72.0, "72 Hours (Weekend Burst)"),
      (168.0, "7 Days (Weekly Horizon)"),
      (336.0, "14 Days (Bi-Weekly Horizon)"),
      (720.0, "30 Days (Monthly Baseline)"),
  ]

  for hours, label in durations:
    micro = get_adaptive_window_parameters(hours, "C2_BEACONING_JITTER", "BALANCED")
    macro = get_adaptive_window_parameters(hours, "MULTI_SECTOR_FUSION", "BALANCED")
    macro_bucket = f"`{macro['recommended_bucket']}`" if hours >= 168.0 else "*N/A (Intra-day)*"
    lines.append(
        f"| **{label}** | `{micro['recommended_bucket']}` | {macro_bucket} | `{macro['proportional_sample_floor']}` samples | `{hours:.0f}h` |"
    )

  lines.extend([
      "",
      "---",
      "*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*",
      "",
  ])
  return "\n".join(lines)


def main():
  taxonomy_path = REPO_DIR / "references" / "statistical-models-taxonomy.md"
  windowing_path = REPO_DIR / "references" / "dynamic-windowing-matrix.md"

  taxonomy_content = generate_statistical_taxonomy()
  taxonomy_path.write_text(taxonomy_content, encoding="utf-8")
  print(f"✅ Generated {taxonomy_path}")

  windowing_content = generate_dynamic_windowing_matrix()
  windowing_path.write_text(windowing_content, encoding="utf-8")
  print(f"✅ Generated {windowing_path}")


if __name__ == "__main__":
  main()
