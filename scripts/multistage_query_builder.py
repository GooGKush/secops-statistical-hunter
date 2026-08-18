#!/usr/bin/env python3
"""
secops-statistical-hunter Helper Utility: multistage_query_builder.py

Validates multi-stage YARA-L search queries, enforces the UEBA/Risk Analytics
Scope Exclusions Guardrail, verifies Canonical Multi-Stage Syntax (no 'events:' headers in stages,
no '$s in stage' pseudo-syntax, unwrapped root stages, mandatory stage binding in root events block,
no math.max/min, no rule wrappers), formats and inspects the mandatory Self-Documenting Methodology Header,
formats 4-Tier Structured Triage Reports (with ASCII magnitude bars), generates graph specifications,
and maps Semantic Sensitivity Tiers to math boundaries.
"""

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

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
    (r"\bmath\.(max|min)\b", "SYNTAX ERROR: 'math.max' and 'math.min' do NOT exist in YARA-L. Use aggregate max()/min(), condition floors, or if(cond, val1, val2)."),
]

SENSITIVITY_MAP = {
    "ZSCORE_PROCESS_SURGE": {
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
  stripped = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", query, flags=re.DOTALL)
  if not re.search(r"^\s*outcome\s*:", stripped, re.MULTILINE):
    errors.append("MISSING UNWRAPPED ROOT OUTCOME: The final stage must NOT be inside a named 'stage { ... }' block. It must be unwrapped at the root level.")

  # Check root stage stage-binding (ValidateEventVariablesExist rule)
  outcome_match = re.search(r"^\s*outcome\s*:(.*?)(\ncondition\s*:|\norder\s*:|$)", stripped, flags=re.DOTALL | re.MULTILINE)
  if outcome_match:
    outcome_text = outcome_match.group(1)
    outcome_stages = set(re.findall(r"\$([a-zA-Z0-9_]+)\.[a-zA-Z0-9_]+", outcome_text))
    root_events_text = stripped[:outcome_match.start()]
    for stage_name in outcome_stages:
      if not re.search(r"\$" + stage_name + r"\.", root_events_text):
        errors.append(
            f"STAGE BINDING ERROR: Stage '{stage_name}' is referenced in the root outcome block "
            f"but is not declared in the root events section (above match:). "
            f"Add '$var = ${stage_name}.<key>' or 'cross join ...' to bind it."
        )

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


def parse_columnar_stats(stats_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Converts Chronicle columnar stats results into a list of row dictionaries."""
  if "stats" in stats_dict:
    stats_dict = stats_dict["stats"]
  if "results" not in stats_dict:
    return []

  columns = []
  col_values = []
  for col_entry in stats_dict["results"]:
    col_name = col_entry.get("column", "")
    columns.append(col_name)
    vals = []
    for item in col_entry.get("values", []):
      val_obj = item.get("value", {})
      for k in ["stringVal", "int64Val", "doubleVal", "timestampVal", "boolVal"]:
        if k in val_obj:
          vals.append(val_obj[k])
          break
      else:
        vals.append(None)
    col_values.append(vals)

  if not col_values:
    return []

  row_count = max(len(v) for v in col_values)
  rows = []
  for r in range(row_count):
    row_dict = {}
    for c_idx, col_name in enumerate(columns):
      row_dict[col_name] = col_values[c_idx][r] if r < len(col_values[c_idx]) else None
    rows.append(row_dict)
  return rows


def generate_visual_bar(score: float, max_score: float = 6.0, bar_length: int = 10) -> str:
  """Generates an ASCII/Unicode magnitude bar (e.g. █████████▌) for relative visual severity."""
  if max_score <= 0:
    max_score = 1.0
  ratio = min(max(score / max_score, 0.0), 1.0)
  blocks = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
  full_blocks = int(ratio * bar_length)
  remainder = int((ratio * bar_length - full_blocks) * 8)
  bar = "█" * full_blocks
  if full_blocks < bar_length and remainder > 0:
    bar += blocks[remainder]
  return bar.ljust(bar_length, " ")


def format_triage_report(
    title: str,
    stats_payload: Dict[str, Any],
    top_n: int = 5,
    event_type: str = "PROCESS_LAUNCH"
) -> str:
  """Renders raw Chronicle multi-stage stats into the 4-Tier Structured Triage Report."""
  rows = parse_columnar_stats(stats_payload)
  if not rows:
    return "⚡ STATISTICAL HUNT VERDICT: No outlier entities exceeded the configured anomaly threshold."

  # Sort by anomaly metric (z_score, cv, surge_ratio, m_z_score)
  sort_keys = ["z_score", "m_z_score", "surge_ratio", "ratio_1v30", "cv"]
  chosen_key = next((k for k in sort_keys if k in rows[0]), None)
  if chosen_key:
    if chosen_key == "cv":
      rows.sort(key=lambda x: float(x.get(chosen_key) or 999))
    else:
      rows.sort(key=lambda x: float(x.get(chosen_key) or 0), reverse=True)

  total_outliers = len(rows)
  top_rows = rows[:top_n]
  entity_col = next((c for c in ["host", "user", "src_ip", "dst_ip"] if c in rows[0]), "entity")

  out = []
  out.append("══════════════════════════════════════════════════════════════════════════════")
  out.append(f"⚡ STATISTICAL OUTLIER REPORT: {title}")
  out.append("══════════════════════════════════════════════════════════════════════════════")
  out.append(f"• Outliers Detected: {total_outliers} entities exceeded anomaly threshold")
  if "mean_val" in rows[0] and "stddev_val" in rows[0]:
    out.append(f"• Baseline Envelope: Mean (μ) ≈ {float(rows[0]['mean_val']):.1f} | StdDev (σ) ≈ {float(rows[0]['stddev_val']):.1f}")
  out.append("")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  out.append("📊 RANKED OUTLIER SUMMARY (Top Anomalies by Severity)")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  out.append("| Entity Identifier | Spike Window | Observed | Baseline (μ ± σ) | Severity Score | Visual Magnitude |")
  out.append("| :---------------- | :----------- | :------- | :--------------- | :------------- | :--------------- |")

  max_score = float(top_rows[0].get(chosen_key, 6.0)) if chosen_key and top_rows[0].get(chosen_key) else 6.0
  for row in top_rows:
    ent = str(row.get(entity_col, "unknown"))
    tb = str(row.get("TIME_BUCKET", row.get("window_start", "Window")))
    obs = str(row.get("observed_count", row.get("daily_mb", row.get("today_fails", ""))))
    
    base_str = "Baseline"
    if "mean_val" in row and "stddev_val" in row:
      base_str = f"{float(row['mean_val']):.0f} ± {float(row['stddev_val']):.0f}"
    
    score_val = float(row.get(chosen_key, 0.0)) if chosen_key else 0.0
    score_str = f"+{score_val:.2f}σ" if chosen_key == "z_score" else f"{score_val:.2f}"
    vbar = f"`{generate_visual_bar(score_val, max_score)}`"
    
    out.append(f"| **{ent}** | {tb[:16]} | **{obs}** | {base_str} | **{score_str}** | {vbar} |")

  top_ent = top_rows[0]
  top_score_val = float(top_ent.get(chosen_key, 0.0)) if chosen_key else 0.0
  top_score_str = f"+{top_score_val:.2f}σ" if chosen_key == "z_score" else f"{top_score_val:.2f}"

  out.append("")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  out.append(f"🔍 TOP OUTLIER SPOTLIGHT: `{top_ent.get(entity_col)}` ({top_score_str})")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  if "observed_count" in top_ent and "mean_val" in top_ent:
    diff = float(top_ent['observed_count']) - float(top_ent['mean_val'])
    pct = (diff / float(top_ent['mean_val'])) * 100 if float(top_ent['mean_val']) > 0 else 0
    out.append(f"• Activity Surge   : {top_ent['observed_count']} executions (+{pct:.1f}% above historical mean).")
  if "distinct_binaries" in top_ent:
    out.append(f"• Binary Diversity : {top_ent['distinct_binaries']} distinct full binary paths executed.")

  out.append("")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  out.append("🎯 IMMEDIATE DRILL-DOWN INVESTIGATION QUERY")
  out.append("──────────────────────────────────────────────────────────────────────────────")
  drilldown_str = f'principal.hostname = "{top_ent.get(entity_col)}" AND metadata.event_type = "{event_type}"'
  if "window_start" in top_ent and top_ent["window_start"]:
    ws = int(top_ent["window_start"])
    drilldown_str += f" AND metadata.event_timestamp.seconds >= {ws} AND metadata.event_timestamp.seconds <= {ws + 3600}"
  out.append(drilldown_str)

  return "\n".join(out)


def generate_chart_spec(stats_payload: Dict[str, Any], title: str = "Outlier Detection Timeseries") -> Dict[str, Any]:
  """Generates a Vega-Lite chart specification for clients supporting graphing."""
  rows = parse_columnar_stats(stats_payload)
  spec = {
      "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
      "title": title,
      "width": 600,
      "height": 300,
      "data": {"values": rows},
      "mark": {"type": "line", "point": True},
      "encoding": {
          "x": {"field": "TIME_BUCKET", "type": "temporal", "title": "Timestamp (UTC)"},
          "y": {"field": "observed_count", "type": "quantitative", "title": "Observed Value"},
          "color": {"field": "host", "type": "nominal", "title": "Host"},
          "tooltip": [
              {"field": "host", "type": "nominal"},
              {"field": "TIME_BUCKET", "type": "temporal"},
              {"field": "observed_count", "type": "quantitative"},
              {"field": "z_score", "type": "quantitative"}
          ]
      }
  }
  return spec


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
  parser.add_argument(
      "--format_report",
      help="Path to raw stats JSON to format into 4-Tier Triage Report",
  )

  args = parser.parse_args()

  if args.format_report:
    with open(args.format_report, "r") as f:
      data = json.load(f)
    print(format_triage_report("Process Execution Outliers", data))
    sys.exit(0)

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
