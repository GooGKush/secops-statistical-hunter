#!/usr/bin/env python3
"""
secops-statistical-hunter Helper Utility: multistage_query_builder.py

Validates multi-stage YARA-L search queries, enforces the UEBA/Risk Analytics
Scope Exclusions Guardrail, verifies Canonical Multi-Stage Syntax (no 'events:' headers in stages,
no '$s in stage' pseudo-syntax, unwrapped root stages, mandatory stage binding in root events block,
no math.max/min, no rule wrappers), formats and inspects the mandatory Self-Documenting Methodology Header,
formats Clean CommonMark/HTML-Safe Cyber-First 4-Tier Structured Triage Reports (with Unicode visual bars,
Threat Translation Callout Cards, SOC Severity Badges, Common False Positives, and SOC Playbooks),
generates Strictly-Typed Multi-Dimensional Graph Specs (Dual-Y Axis Timelines, 4D Bubble Plots, Heatmaps),
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
    "POISSON_BURST_CLUSTERING": {
        "CONSERVATIVE": {"fano_factor": 8.0, "min_fails": 30, "min_mu": 2.0},
        "BALANCED": {"fano_factor": 4.0, "min_fails": 15, "min_mu": 1.0},
        "AGGRESSIVE": {"fano_factor": 2.5, "min_fails": 10, "min_mu": 0.5},
    },
    "POISSON_RARE_SURGE": {
        "CONSERVATIVE": {"poisson_z": 5.0, "min_observed": 5, "max_lambda": 1.0},
        "BALANCED": {"poisson_z": 3.5, "min_observed": 3, "max_lambda": 2.0},
        "AGGRESSIVE": {"poisson_z": 2.5, "min_observed": 2, "max_lambda": 3.0},
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

THREAT_EXPLANATIONS = {
    "z_score": {
        "name": "Parametric Z-Score (Standard Deviation Surge)",
        "meaning": "Volume explosion exceeding personal 30-day host baseline. Indicates script loops, build storms, mass lateral movement, or ransomware staging.",
        "false_positives": "Software compiler builds (MSBuild/Ninja/GCC), SCCM/Ansible endpoint management jobs, local developer testing.",
        "playbook": [
            "Inspect Parent Binary Lineage (e.g. `cmd.exe` vs `devenv.exe` / `CcmExec.exe`).",
            "Verify executing User Account (Service Account vs Interactive End-User).",
            "Check for executions from user-writable directories (`C:\\Temp`, `AppData\\Local\\Temp`, `/tmp`)."
        ]
    },
    "fano_factor": {
        "name": "Poisson Dispersion / Fano Factor (Attack Wave Clustering)",
        "meaning": "Authentication failures or events arriving in synchronized, intermittent bursts rather than steady background trickle. Classic indicator of password spraying.",
        "false_positives": "Cached credential failure loops (Outlook/Mail client after password change), mapped SMB drive reconnection loops.",
        "playbook": [
            "Check Failure Error Sub-Status (`STATUS_WRONG_PASSWORD` vs `STATUS_ACCOUNT_LOCKED_OUT`).",
            "Examine Source IP Diversity (Single internal IP = cached cred; Rotating external IPs = spray attack).",
            "Correlate with successful logins from the same source IP shortly thereafter."
        ]
    },
    "poisson_z": {
        "name": "Discrete Poisson Rarity Score",
        "meaning": "Statistically improbable spike in sensitive administrative tools (vssadmin, certutil, whoami, dsquery) on hosts with near-zero baseline.",
        "false_positives": "Scheduled IT administrator maintenance, endpoint backup jobs, authorized sysadmin troubleshooting.",
        "playbook": [
            "Verify whether user is an authorized Domain / Enterprise Administrator.",
            "Inspect exact command line parameters and arguments passed to the utility.",
            "Check for network connections established by the administrative binary."
        ]
    },
    "cv": {
        "name": "Coefficient of Variation (Inter-Arrival Timing Jitter)",
        "meaning": "Low timing variance in network callbacks. Indicates automated malware beaconing (Cobalt Strike, Sliver) with configured sleep jitter.",
        "false_positives": "NTP time sync, OS update telemetry pings, corporate SaaS keep-alive polling (Slack/Teams).",
        "playbook": [
            "Check Fleet Prevalence (Does destination IP talk to >10 hosts? If yes, likely CDN/SaaS).",
            "Inspect TLS Certificate SNI and Subject Alternative Name in `NETWORK_HTTP`.",
            "Check Payload Size consistency across all requests."
        ]
    },
    "m_z_score": {
        "name": "Modified Z-Score via Median Absolute Deviation (MAD)",
        "meaning": "Robust volume surge on heavily skewed telemetry (e.g. DNS tunneling or data egress) that ignores distorted averages.",
        "false_positives": "Large database backups, authorized cloud sync uploads (OneDrive/Google Drive), OS image transfers.",
        "playbook": [
            "Check destination IP / Domain ASN and reputation.",
            "Verify transfer protocol (e.g., DNS queries with high entropy vs HTTPS upload).",
            "Confirm whether transfer aligns with scheduled backup windows."
        ]
    }
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

  for pattern, msg in SYNTAX_TRAPS:
    if re.search(pattern, query, re.DOTALL | re.MULTILINE):
      errors.append(msg)

  stages = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", query)
  if not stages:
    errors.append("MISSING STAGES: A multi-stage query requires at least one named 'stage <name> { ... }' block.")

  stripped = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", query, flags=re.DOTALL)
  if not re.search(r"^\s*outcome\s*:", stripped, re.MULTILINE):
    errors.append("MISSING UNWRAPPED ROOT OUTCOME: The final stage must NOT be inside a named 'stage { ... }' block. It must be unwrapped at the root level.")

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
  """Converts Chronicle columnar stats results into a sanitized list of typed row dictionaries."""
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
      # Strictly preserve typed numeric primitives
      if "int64Val" in val_obj:
        try:
          vals.append(int(val_obj["int64Val"]))
        except (ValueError, TypeError):
          vals.append(val_obj["int64Val"])
      elif "doubleVal" in val_obj:
        try:
          vals.append(float(val_obj["doubleVal"]))
        except (ValueError, TypeError):
          vals.append(val_obj["doubleVal"])
      elif "stringVal" in val_obj:
        vals.append(val_obj["stringVal"])
      elif "timestampVal" in val_obj:
        vals.append(val_obj["timestampVal"])
      elif "boolVal" in val_obj:
        vals.append(val_obj["boolVal"])
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


def get_soc_severity_badge(chosen_key: str, score: float) -> str:
  """Translates statistical score into a standard SOC operational rating."""
  if chosen_key in ["z_score", "poisson_z"]:
    if score >= 4.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 3.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 2.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key == "fano_factor":
    if score >= 8.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 4.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 2.5:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key == "cv":
    if score <= 0.08:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score <= 0.20:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score <= 0.35:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key == "m_z_score":
    if score >= 3.5:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 2.5:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 2.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  return "⚠️ **[ANOMALY DETECTED]**"


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
  """Renders raw Chronicle multi-stage stats into a Clean CommonMark/HTML-Safe 4-Tier Report."""
  rows = parse_columnar_stats(stats_payload)
  if not rows:
    return "⚡ **STATISTICAL HUNT VERDICT**: No outlier entities exceeded the configured anomaly threshold."

  sort_keys = ["z_score", "poisson_z", "fano_factor", "m_z_score", "surge_ratio", "ratio_1v30", "cv"]
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
  out.append(f"### ⚡ Statistical Outlier Report: {title}")
  out.append("")
  out.append(f"* **Outliers Detected**: **{total_outliers} entities** exceeded the configured anomaly threshold.")
  
  if "mean_val" in rows[0] and "stddev_val" in rows[0]:
    out.append(f"* **Baseline Envelope**: Mean ($\\mu$) $\\approx {float(rows[0]['mean_val']):.1f}$ | StdDev ($\\sigma$) $\\approx {float(rows[0]['stddev_val']):.1f}$")
  elif "mu" in rows[0] and "stddev_val" in rows[0]:
    out.append(f"* **Baseline Envelope**: Mean ($\\mu$) $\\approx {float(rows[0]['mu']):.1f}$ | StdDev ($\\sigma$) $\\approx {float(rows[0]['stddev_val']):.1f}$")
  elif "historical_lambda" in rows[0]:
    out.append(f"* **Baseline Envelope**: Historical Daily Rate ($\\lambda$) $\\approx {float(rows[0]['historical_lambda']):.2f}\\text{ runs/day}$")

  out.append("")
  out.append("---")
  out.append("")
  out.append("#### 📊 Ranked Outlier Summary (Top Anomalies by Severity)")
  out.append("")
  out.append("| Entity Identifier | Spike Window | Observed | Baseline Envelope | Severity Rating | Visual Magnitude |")
  out.append("| :---------------- | :----------- | :------- | :---------------- | :-------------- | :--------------- |")

  max_score = float(top_rows[0].get(chosen_key, 6.0)) if chosen_key and top_rows[0].get(chosen_key) else 6.0
  for row in top_rows:
    ent = str(row.get(entity_col, "unknown"))
    tb = str(row.get("TIME_BUCKET", row.get("window_start", "Full Window")))
    obs = str(row.get("observed_count", row.get("observed_today", row.get("total_fails", row.get("daily_mb", "")))))
    
    base_str = "Baseline"
    if "mean_val" in row and "stddev_val" in row:
      base_str = f"{float(row['mean_val']):.0f} ± {float(row['stddev_val']):.0f}"
    elif "mu" in row and "stddev_val" in row:
      base_str = f"{float(row['mu']):.0f} ± {float(row['stddev_val']):.0f}"
    elif "historical_lambda" in row:
      base_str = f"λ = {float(row['historical_lambda']):.2f}/d"
    
    score_val = float(row.get(chosen_key, 0.0)) if chosen_key else 0.0
    badge = get_soc_severity_badge(chosen_key, score_val)
    score_str = f"+{score_val:.2f}σ" if chosen_key in ["z_score", "poisson_z"] else f"{score_val:.2f}"
    vbar = f"`{generate_visual_bar(score_val, max_score)}`"
    
    out.append(f"| `{ent}` | {tb[:16]} | **{obs}** | {base_str} | {badge} (`{score_str}`) | {vbar} |")

  top_ent = top_rows[0]
  top_score_val = float(top_ent.get(chosen_key, 0.0)) if chosen_key else 0.0
  top_score_str = f"+{top_score_val:.2f}σ" if chosen_key in ["z_score", "poisson_z"] else f"{top_score_val:.2f}"
  top_badge = get_soc_severity_badge(chosen_key, top_score_val)

  out.append("")
  out.append("---")
  out.append("")
  out.append(f"#### 🔍 Top Outlier Spotlight: `{top_ent.get(entity_col)}` — {top_badge} (`{top_score_str}`)")
  out.append("")
  if "observed_count" in top_ent and "mean_val" in top_ent:
    diff = float(top_ent['observed_count']) - float(top_ent['mean_val'])
    pct = (diff / float(top_ent['mean_val'])) * 100 if float(top_ent['mean_val']) > 0 else 0
    out.append(f"* **Activity Surge**: **{top_ent['observed_count']} executions** (+{pct:.1f}% above historical personal mean).")
  elif "total_fails" in top_ent and "mu" in top_ent:
    out.append(f"* **Burst Volume**: **{top_ent['total_fails']} total failures** across active hours (Clustering Factor $F = {top_score_str}$).")
  elif "observed_today" in top_ent and "historical_lambda" in top_ent:
    out.append(f"* **Rare Invocations**: **{top_ent['observed_today']} executions today** vs historical baseline rate of {top_ent['historical_lambda']} runs/day.")

  if "distinct_binaries" in top_ent:
    out.append(f"* **Binary Diversity**: **{top_ent['distinct_binaries']} distinct full binary paths** executed.")

  if chosen_key and chosen_key in THREAT_EXPLANATIONS:
    expl = THREAT_EXPLANATIONS[chosen_key]
    out.append("")
    out.append("> [!IMPORTANT]")
    out.append(f"> **Threat Translation: {expl['name']}**")
    out.append(f"> * **Threat Meaning**: {expl['meaning']}")
    out.append(f"> * **Common False Positives**: {expl['false_positives']}")
    out.append("> * **SOC Triage Playbook**:")
    for step in expl["playbook"]:
      out.append(f">   1. {step}")

  out.append("")
  out.append("---")
  out.append("")
  out.append("#### 🎯 Immediate Drill-Down Investigation Query")
  out.append("")
  out.append("```yara")
  drilldown_str = f'principal.hostname = "{top_ent.get(entity_col)}" AND metadata.event_type = "{event_type}"'
  if "user" in top_ent and top_ent["user"]:
    drilldown_str = f'target.user.userid = "{top_ent.get("user")}" AND metadata.event_type = "{event_type}"'
  if "window_start" in top_ent and top_ent["window_start"]:
    ws = int(top_ent["window_start"])
    drilldown_str += f"\nAND metadata.event_timestamp.seconds >= {ws} AND metadata.event_timestamp.seconds <= {ws + 3600}"
  out.append(drilldown_str)
  out.append("```")

  return "\n".join(out)


def generate_chart_spec(
    stats_payload: Dict[str, Any],
    plot_type: str = "DUAL_Y_TIMESERIES",
    title: str = "Outlier Investigation Chart"
) -> Dict[str, Any]:
  """Generates Strictly-Typed Multi-Dimensional Vega-Lite chart specs (Dual-Y, 4D Bubble, Heatmap)."""
  rows = parse_columnar_stats(stats_payload)
  
  if plot_type == "DUAL_Y_TIMESERIES":
    # Dual-Y Axis Chart (Shared X-Axis): Volume Bars on Left Y-Axis, Statistical Anomaly Line on Right Y-Axis
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 650,
        "height": 320,
        "data": {"values": rows},
        "resolve": {"scale": {"y": "independent"}},
        "layer": [
            {
                "mark": {"type": "bar", "opacity": 0.45, "color": "#1a73e8"},
                "encoding": {
                    "x": {"field": "TIME_BUCKET", "type": "temporal", "title": "Time Window (UTC)"},
                    "y": {"field": "observed_count", "type": "quantitative", "title": "Observed Event Volume (Left Axis)"},
                    "tooltip": [
                        {"field": "host", "type": "nominal", "title": "Entity"},
                        {"field": "TIME_BUCKET", "type": "temporal", "title": "Time"},
                        {"field": "observed_count", "type": "quantitative", "title": "Volume"}
                    ]
                }
            },
            {
                "mark": {"type": "line", "point": {"filled": True, "size": 60}, "color": "#d93025", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": "TIME_BUCKET", "type": "temporal"},
                    "y": {"field": "z_score", "type": "quantitative", "title": "Statistical Anomaly Score (Z / Fano) (Right Axis)"},
                    "tooltip": [
                        {"field": "host", "type": "nominal", "title": "Entity"},
                        {"field": "z_score", "type": "quantitative", "title": "Anomaly Score (Z)"}
                    ]
                }
            }
        ]
    }
  elif plot_type == "4D_BUBBLE":
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 650,
        "height": 350,
        "data": {"values": rows},
        "mark": "circle",
        "encoding": {
            "x": {"field": "TIME_BUCKET", "type": "temporal", "title": "Timestamp / Window (UTC)"},
            "y": {"field": "observed_count", "type": "quantitative", "title": "Observed Intensity / Volume"},
            "size": {"field": "distinct_binaries", "type": "quantitative", "title": "Cardinality / Breadth", "scale": {"range": [50, 600]}},
            "color": {
                "field": "z_score",
                "type": "quantitative",
                "title": "Anomaly Score (Z)",
                "scale": {"scheme": "redyellowblue", "reverse": True}
            },
            "tooltip": [
                {"field": "host", "type": "nominal"},
                {"field": "TIME_BUCKET", "type": "temporal"},
                {"field": "observed_count", "type": "quantitative"},
                {"field": "z_score", "type": "quantitative"}
            ]
        }
    }
  elif plot_type == "HEATMAP":
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 600,
        "height": 300,
        "data": {"values": rows},
        "mark": "rect",
        "encoding": {
            "x": {"field": "TIME_BUCKET", "type": "temporal", "timeUnit": "hours", "title": "Hour of Day (UTC)"},
            "y": {"field": "host", "type": "nominal", "title": "Entity / Host"},
            "color": {"field": "z_score", "type": "quantitative", "title": "Anomaly Density", "scale": {"scheme": "magma"}}
        }
    }
  else:
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 600,
        "height": 300,
        "data": {"values": rows},
        "mark": {"type": "line", "point": True},
        "encoding": {
            "x": {"field": "TIME_BUCKET", "type": "temporal", "title": "Timestamp (UTC)"},
            "y": {"field": "observed_count", "type": "quantitative", "title": "Observed Metric"},
            "color": {"field": "host", "type": "nominal"}
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
      help="Path to raw stats JSON to format into Clean CommonMark 4-Tier Triage Report",
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
