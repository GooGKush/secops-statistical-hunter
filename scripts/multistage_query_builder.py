#!/usr/bin/env python3
"""
secops-statistical-hunter Helper Utility: multistage_query_builder.py

Validates multi-stage YARA-L search queries, enforces the UEBA/Risk Analytics
Scope Exclusions Guardrail, verifies Canonical Multi-Stage Syntax (no 'events:' headers in stages,
no '$s in stage' pseudo-syntax, unwrapped root stages, no rule wrappers),
formats and inspects the mandatory Self-Documenting Methodology Header,
and maps Semantic Sensitivity Tiers to math boundaries.
"""

import argparse
import re
import sys
from typing import Dict, List, Optional, Tuple

EXCLUDED_PATTERNS = [
    (r"\bmetrics\.", "UEBA metric functions (metrics.*) are excluded from ad-hoc time range searches. Use secops-risk-analytics."),
    (r"\brisk_score\b", "Entity Risk Score fields (risk_score) are excluded. Use secops-risk-analytics."),
    (r"\bgraph\.risk_score", "Entity Risk Graph tables are excluded. Use secops-risk-analytics."),
    (r"UEBA_EVENTS", "UEBA_EVENTS source dataset is excluded. Use raw UDM_EVENTS or RULE_DETECTIONS."),
    (r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", "Multi-stage queries CANNOT be wrapped in rule blocks or deployed to the Rules Engine. They are Search/Dashboard-only."),
]

SYNTAX_TRAPS = [
    (r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\bevents\s*:", "SYNTAX ERROR: Multi-stage named stages do NOT use an 'events:' header. Place event filters directly inside the stage block."),
    (r"\$\w+\s+in\s+\$?[a-zA-Z0-9_]+", "SYNTAX ERROR: Do NOT use '$var in stage_name'. Access stage outputs directly via '$stage_name.variable_name' or '$var = $stage_name.variable_name'."),
]

SENSITIVITY_MAP = {
    "FLEET_ZSCORE_OUTLIER": {
        "CONSERVATIVE": {"z_score": 3.0, "min_count": 50, "min_sd": 10.0},
        "BALANCED": {"z_score": 2.0, "min_count": 25, "min_sd": 5.0},
        "AGGRESSIVE": {"z_score": 1.5, "min_count": 10, "min_sd": 2.0},
    },
    "C2_BEACONING_JITTER": {
        "CONSERVATIVE": {"cv": 0.05, "min_conns": 50, "prevalence": 1},
        "BALANCED": {"cv": 0.20, "min_conns": 25, "prevalence": 2},
        "AGGRESSIVE": {"cv": 0.40, "min_conns": 15, "prevalence": 1},
    },
    "DATA_EXFILTRATION_SPIKE": {
        "CONSERVATIVE": {"m_z": 3.5, "min_mb": 500.0, "min_mad": 20.0},
        "BALANCED": {"m_z": 2.5, "min_mb": 100.0, "min_mad": 10.0},
        "AGGRESSIVE": {"m_z": 2.0, "min_mb": 25.0, "min_mad": 5.0},
    },
    "HEAVY_TAIL_OUTLIERS": {
        "CONSERVATIVE": {"surge_ratio": 3.0, "min_iqr": 50.0},
        "BALANCED": {"surge_ratio": 2.0, "min_iqr": 10.0},
        "AGGRESSIVE": {"surge_ratio": 1.5, "min_iqr": 5.0},
    },
    "VELOCITY_SURGE_RATIO": {
        "CONSERVATIVE": {"ratio_1v7": 5.0, "ratio_1v30": 8.0, "min_today": 200},
        "BALANCED": {"ratio_1v7": 3.0, "ratio_1v30": 5.0, "min_today": 100},
        "AGGRESSIVE": {"ratio_1v7": 2.0, "ratio_1v30": 3.0, "min_today": 50},
    },
}


def check_scope_exclusions(query: str) -> List[str]:
  """Checks query string for unauthorized UEBA/Risk Analytics functions or rule headers."""
  violations = []
  for pattern, explanation in EXCLUDED_PATTERNS:
    if re.search(pattern, query, re.IGNORECASE | re.MULTILINE):
      violations.append(f"VIOLATION ({pattern}): {explanation}")
  return violations


def validate_multistage_syntax(query: str) -> List[str]:
  """Performs structural validation on multi-stage YARA-L search queries."""
  errors = []

  # Check known syntax traps
  for pattern, msg in SYNTAX_TRAPS:
    if re.search(pattern, query, re.DOTALL | re.MULTILINE):
      errors.append(msg)

  # Check for stage blocks
  stages = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", query)
  if not stages:
    errors.append("MISSING STAGES: A multi-stage query requires at least one named 'stage <name> { ... }' block.")

  # Check for unwrapped root outcome section
  # Strip all named stage blocks to find if there is an outcome: at root level
  stripped = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", query, flags=re.DOTALL)
  if not re.search(r"^\s*outcome\s*:", stripped, re.MULTILINE):
    errors.append("MISSING UNWRAPPED ROOT OUTCOME: The final stage must NOT be inside a named 'stage { ... }' block. It must be unwrapped at the root level.")

  # Check for methodology header
  if not re.search(r"//\s*Goal:", query, re.IGNORECASE):
    errors.append("MISSING METHODOLOGY HEADER: Recommended to include '// Goal:' and '// Statistical Model:' methodology block.")

  return errors


def generate_methodology_header(
    goal: str, telemetry: str, model: str, rationale: str, boundary: str
) -> str:
  """Generates a standardized Self-Documenting Query Header."""
  header = (
      "// ============================================================================\n"
      "// METHODOLOGY & HUNTING GOAL\n"
      f"// Goal: {goal}\n"
      f"// Target Telemetry: {telemetry}\n"
      f"// Statistical Model: {model}\n"
      "// Mathematical Rationale:\n"
      f"//   {rationale}\n"
      f"// Sensitivity Boundary: {boundary}\n"
      "// ============================================================================\n"
  )
  return header


def get_thresholds_for_tier(
    archetype: str, tier: str
) -> Dict[str, float]:
  """Resolves semantic sensitivity tier to concrete statistical thresholds."""
  archetype_up = archetype.upper()
  tier_up = tier.upper()
  if archetype_up not in SENSITIVITY_MAP:
    raise ValueError(f"Unknown threat archetype: {archetype}")
  if tier_up not in SENSITIVITY_MAP[archetype_up]:
    raise ValueError(
        f"Invalid sensitivity tier '{tier}' for {archetype}. Choose from"
        f" {list(SENSITIVITY_MAP[archetype_up].keys())}."
    )
  return SENSITIVITY_MAP[archetype_up][tier_up]


def main():
  parser = argparse.ArgumentParser(
      description="secops-statistical-hunter Query Validation & Boundary Utility"
  )
  parser.add_argument(
      "--query_file", help="Path to YARA-L query file to validate"
  )
  parser.add_argument(
      "--archetype",
      help="Threat archetype to lookup sensitivity thresholds for",
  )
  parser.add_argument(
      "--tier",
      default="BALANCED",
      help="Sensitivity tier (CONSERVATIVE, BALANCED, AGGRESSIVE)",
  )

  args = parser.parse_args()

  if args.archetype:
    try:
      thresholds = get_thresholds_for_tier(args.archetype, args.tier)
      print(
          f"=== Thresholds for {args.archetype} ({args.tier.upper()}) ==="
      )
      for k, v in thresholds.items():
        print(f"  {k} = {v}")
      sys.exit(0)
    except Exception as e:
      print(f"Error: {e}", file=sys.stderr)
      sys.exit(1)

  if args.query_file:
    with open(args.query_file, "r") as f:
      query = f.read()

    print(f"Validating {args.query_file}...")
    violations = check_scope_exclusions(query)
    syntax_errors = validate_multistage_syntax(query)

    fatal_errors = violations + [e for e in syntax_errors if not e.startswith("MISSING METHODOLOGY HEADER")]

    if fatal_errors:
      print("\n❌ VALIDATION FAILED:")
      for v in violations:
        print(f"  [SCOPE] {v}")
      for s in syntax_errors:
        print(f"  [SYNTAX] {s}")
      sys.exit(1)
    else:
      if any(e.startswith("MISSING METHODOLOGY HEADER") for e in syntax_errors):
        print("⚠️ Warning: Query lacks standard methodology comment header.")
      print("✅ Query passed all canonical multi-stage grammar and scope exclusion checks.")
      sys.exit(0)


if __name__ == "__main__":
  main()
