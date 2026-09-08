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
      "## 1. Parametric Historical Standardization ($Z$-Score)",
      "* **Goal**: Detect sudden vertical bursts in volume over a Gaussian historical baseline.",
      "* **Formula**:",
      "  $$Z = \\frac{x - \\mu}{\\sigma}$$",
      "* **Where**:",
      "  - $x$: Current window observation count (`$obs`).",
      "  - $\\mu$: Historical sample mean (`$mu = \\text{avg}(\\$stage1.count)`).",
      "  - $\\sigma$: Historical standard deviation (`$sd = \\text{stddev}(\\$stage1.count)`).",
      "* **Guards**: Requires $\\sigma > 0$ and $N \\ge 24$ active baseline intervals.",
      "",
      "---",
      "",
      "## 2. Poisson-Gamma Bayesian Credibility Shrinkage (\"The Seasoned SOC Detective\")",
      "* **Goal**: Isolate high-confidence bursts on stable hosts while preventing false alarms on erratic endpoints.",
      "* **Method of Moments Gamma Prior**:",
      "  $$\\text{Var} = \\sigma^2, \\quad \\beta_0 = \\frac{\\mu}{\\text{Var}}, \\quad \\alpha_0 = \\mu \\cdot \\beta_0$$",
      "* **Conjugate Posterior Updating** (for observation $k$ across time $t=1$):",
      "  $$\\alpha_{\\text{post}} = \\alpha_0 + k, \\quad \\beta_{\\text{post}} = \\beta_0 + 1.0$$",
      "* **Posterior Expected Arrival Rate & Credibility Weights**:",
      "  $$\\lambda_{\\text{post}} = \\frac{\\alpha_{\\text{post}}}{\\beta_{\\text{post}}}, \\quad W_{\\text{prior}} = \\frac{\\beta_0}{\\beta_{\\text{post}}}, \\quad W_{\\text{evidence}} = \\frac{1}{\\beta_{\\text{post}}}$$",
      "* **Belief Shift Ratio**:",
      "  $$\\text{Shift Ratio} = \\frac{\\lambda_{\\text{post}}}{\\mu}$$",
      "",
      "---",
      "",
      "## 3. Beta-Binomial Failure Ratio Regularization (\"Small-Sample Ratio Regularizer\")",
      "* **Goal**: Prevent false positives from $1/1 = 100\\%$ failure rates on single-trial mistakes.",
      "* **Informative Corporate Prior**: $\\alpha_0 = 1.0, \\beta_0 = 9.0$ ($\\sim 10\\%$ normal background error rate).",
      "* **Conjugate Posterior Update**:",
      "  $$\\alpha_{\\text{post}} = \\alpha_0 + \\text{fails}, \\quad \\beta_{\\text{post}} = \\beta_0 + \\text{successes}$$",
      "* **Regularized Posterior Failure Probability**:",
      "  $$P(\\text{Fail}) = \\frac{\\alpha_{\\text{post}}}{\\alpha_{\\text{post}} + \\beta_{\\text{post}}}$$",
      "",
      "---",
      "",
      "## 4. Dual-Baseline Delta-$Z$ (\"The Patch Tuesday Shield\")",
      "* **Goal**: Isolate targeted endpoint spikes from company-wide software deployments.",
      "* **Formula**:",
      "  $$\\Delta Z = Z_{\\text{Personal}} - Z_{\\text{Fleet Today}} = \\left(\\frac{x - \\mu_{\\text{personal}}}{\\sigma_{\\text{personal}}}\\right) - \\left(\\frac{x - \\mu_{\\text{fleet}}}{\\sigma_{\\text{fleet}}}\\right)$$",
      "* **Behavior**:",
      "  - Company-wide deployment: $Z_{\\text{Personal}} \\approx 10.0$, $Z_{\\text{Fleet}} \\approx 9.8 \\implies \\Delta Z \\approx 0.2$ (Ignored).",
      "  - Targeted attack: $Z_{\\text{Personal}} \\approx 8.5$, $Z_{\\text{Fleet}} \\approx 0.1 \\implies \\Delta Z \\approx 8.4$ (Triggered).",
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
      "## 7. Information-Theoretic Diversity Deficit (Entropy Proxy)",
      "* **Goal**: Detect automated scripted exfiltration where an entity touches many destinations with minimal vocabulary entropy.",
      "* **Formula**:",
      "  $$\\text{Diversity Ratio} = \\frac{k_{\\text{vocab}}}{N_{\\text{events}} + 1.0}$$",
      "* **Interpretation**:",
      "  - Scripted exfiltration produces severe diversity collapse ($\\text{Diversity Ratio} \\le 0.20$).",
      "",
      "---",
      "",
      "## 8. Elephant Flow Concentration (HHI / Gini Proxy)",
      "* **Goal**: Detect single massive exfiltration bursts masked within routine traffic.",
      "* **Formula**:",
      "  $$\\text{Concentration Ratio} = \\frac{\\text{Peak Transfer}}{\\sum \\text{Transfers} + 1.0}$$",
      "* **Interpretation**:",
      "  - Extreme concentration ($\\text{Concentration Ratio} \\ge 0.70$) indicates an isolated elephant flow.",
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
      "## 10. Sensitivity & Anomaly Threshold Map",
      "",
      "| Archetype | Tier | Thresholds & Parameters |",
      "| :--- | :--- | :--- |",
  ]

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
      "This matrix defines adaptive bucket granularity and proportional sample floors across search durations.",
      "",
      "| Duration | Bucket Size | Minimum Sample Floor | Proportional Horizon |",
      "| :--- | :--- | :--- | :--- |",
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
    adapt = get_adaptive_window_parameters(hours, "ZSCORE_PROCESS_SURGE", "BALANCED")
    lines.append(
        f"| **{label}** | `{adapt['recommended_bucket']}` | `{adapt['proportional_sample_floor']}` samples | `{hours:.0f}h` |"
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
