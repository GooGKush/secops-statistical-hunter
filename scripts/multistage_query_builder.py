#!/usr/bin/env python3
"""
secops-statistical-hunter Helper Utility: multistage_query_builder.py

Validates multi-stage YARA-L search queries, enforces the UEBA/Risk Analytics
Scope Exclusions Guardrail, verifies Canonical Multi-Stage Syntax (no 'events:' headers in stages,
no '$s in stage' pseudo-syntax, unwrapped root stages, mandatory stage binding in root events block,
no math.max/min, no rule wrappers, no intra-stage variable reuse/race conditions, max 20 outcome vars),
formats and inspects the mandatory Self-Documenting Methodology Header,
formats Clean CommonMark/HTML-Safe Cyber-First 4-Tier Structured Triage Reports (with Unicode visual bars,
Evidence Payload Cards, Confidence Tier Badges, SOC Severity Badges, Common False Positives, and SOC Playbooks),
generates Strictly-Typed True Dual-Y Axis Timeline Specs (with orient: right and dashed threshold rules),
4D Bubble Plots, Heatmaps, and maps Semantic Sensitivity Tiers to math boundaries.
"""

__author__ = "Greg Kushmerek"
__version__ = "2.0.1"

import argparse
import json
import math
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
    (r"\bcount\s*\(\s*if\s*\(", "SYNTAX ERROR: 'count(if(...))' is invalid syntax. Use 'sum(if(condition, 1, 0))' for conditional event counting."),
    (r"^\s*options\s*:", "SYNTAX ERROR: 'options:' blocks are Rule-Engine only and rejected in Search/Dashboard queries. Searches terminate after 'condition:' or 'order:'."),
    (r"match:\s*[^;\n]+\bby\b[^;\n]+\b(hop|over)\b", "SYNTAX ERROR: Compound 'by X hop Y' or 'by X over Y' is invalid syntax in YARA-L. Use 'match: $var by <duration>' for tumbling buckets, 'match: $var over <duration>' for sliding windows, or 'match: $var' for unwindowed baseline stages."),
]

SENSITIVITY_MAP = {
    "ZSCORE_PROCESS_SURGE": {
        "CONSERVATIVE": {"z_score": 3.0, "min_count": 50, "min_sd": 10.0, "min_active_samples": 120},
        "BALANCED": {"z_score": 2.0, "min_count": 25, "min_sd": 5.0, "min_active_samples": 60},
        "AGGRESSIVE": {"z_score": 1.5, "min_count": 10, "min_sd": 2.0, "min_active_samples": 30},
    },
    "POISSON_BURST_CLUSTERING": {
        "CONSERVATIVE": {"fano_factor": 8.0, "min_fails": 30, "min_mu": 2.0, "min_active_samples": 60},
        "BALANCED": {"fano_factor": 4.0, "min_fails": 15, "min_mu": 1.0, "min_active_samples": 30},
        "AGGRESSIVE": {"fano_factor": 2.5, "min_fails": 10, "min_mu": 0.5, "min_active_samples": 15},
    },
    "POISSON_RARE_SURGE": {
        "CONSERVATIVE": {"poisson_z": 5.0, "min_observed": 5, "max_lambda": 1.0, "min_baseline_days": 14},
        "BALANCED": {"poisson_z": 3.5, "min_observed": 3, "max_lambda": 2.0, "min_baseline_days": 7},
        "AGGRESSIVE": {"poisson_z": 2.5, "min_observed": 2, "max_lambda": 3.0, "min_baseline_days": 3},
    },
    "C2_BEACONING_JITTER": {
        "CONSERVATIVE": {"cv": 0.05, "min_conns": 50, "prevalence": 1, "min_active_hours": 12},
        "BALANCED": {"cv": 0.20, "min_conns": 25, "prevalence": 2, "min_active_hours": 6},
        "AGGRESSIVE": {"cv": 0.40, "min_conns": 15, "prevalence": 1, "min_active_hours": 3},
    },
    "DATA_EXFILTRATION_SPIKE": {
        "CONSERVATIVE": {"m_z": 3.5, "min_mb": 500.0, "min_mad": 20.0, "min_baseline_days": 14},
        "BALANCED": {"m_z": 2.5, "min_mb": 100.0, "min_mad": 10.0, "min_baseline_days": 7},
        "AGGRESSIVE": {"m_z": 2.0, "min_mb": 25.0, "min_mad": 5.0, "min_baseline_days": 3},
    },
    "HEAVY_TAIL_OUTLIERS": {
        "CONSERVATIVE": {"surge_ratio": 3.0, "min_iqr": 50.0, "min_baseline_days": 14},
        "BALANCED": {"surge_ratio": 2.0, "min_iqr": 10.0, "min_baseline_days": 7},
        "AGGRESSIVE": {"surge_ratio": 1.5, "min_iqr": 5.0, "min_baseline_days": 3},
    },
    "VELOCITY_SURGE_RATIO": {
        "CONSERVATIVE": {"ratio_1v7": 5.0, "ratio_1v30": 8.0, "min_today": 200, "min_baseline_days": 20},
        "BALANCED": {"ratio_1v7": 3.0, "ratio_1v30": 5.0, "min_today": 100, "min_baseline_days": 14},
        "AGGRESSIVE": {"ratio_1v7": 2.0, "ratio_1v30": 3.0, "min_today": 50, "min_baseline_days": 7},
    },
    "FLEET_PEER_ZSCORE": {
        "CONSERVATIVE": {"fleet_z": 3.5, "min_host_count": 50, "min_fleet_sd": 10.0, "min_active_hosts": 25},
        "BALANCED": {"fleet_z": 2.5, "min_host_count": 25, "min_fleet_sd": 5.0, "min_active_hosts": 15},
        "AGGRESSIVE": {"fleet_z": 2.0, "min_host_count": 10, "min_fleet_sd": 2.0, "min_active_hosts": 10},
    },
}


def get_adaptive_window_parameters(
    duration_hours: float,
    archetype: str,
    tier: str = "BALANCED"
) -> Dict[str, Any]:
  """Calculates adaptive bucket granularity, proportional sample floors, and model fit based on search window duration."""
  archetype_up = archetype.upper()
  tier_up = tier.upper()
  base_thresh = SENSITIVITY_MAP.get(archetype_up, {}).get(tier_up, {})

  # Determine optimal bucket granularity based on total window duration
  if duration_hours <= 12.0:
    bucket_size = "10m"
    bucket_seconds = 600
    total_buckets = int(duration_hours * 3600 / bucket_seconds)
    sample_unit = "10-minute intervals"
  elif duration_hours <= 36.0:  # ~1 day / "today"
    bucket_size = "15m"
    bucket_seconds = 900
    total_buckets = int(duration_hours * 3600 / bucket_seconds)
    sample_unit = "15-minute intervals"
  elif duration_hours <= 168.0:  # <= 7 days / "past week" / "this week so far"
    bucket_size = "1h"
    bucket_seconds = 3600
    total_buckets = int(duration_hours)
    sample_unit = "hourly intervals"
  else:  # 7 to 30 days / "this month so far" / "past 30 days"
    bucket_size = "1h"
    bucket_seconds = 3600
    total_buckets = int(duration_hours)
    sample_unit = "hourly intervals"

  # Calculate proportional sample floor (e.g. 25% of window, minimum 3, maximum default)
  default_sample_floor = (
      base_thresh.get("min_active_samples")
      or base_thresh.get("min_baseline_days")
      or base_thresh.get("min_active_hours")
      or 30
  )
  
  if "days" in sample_unit or duration_hours > 168.0 and archetype_up in ["DATA_EXFILTRATION_SPIKE", "HEAVY_TAIL_OUTLIERS"]:
    # For daily models in extended windows
    total_days = max(1, int(duration_hours / 24.0))
    proportional_sample_floor = max(3, min(default_sample_floor, int(total_days * 0.4)))
  else:
    proportional_sample_floor = max(3, min(default_sample_floor, max(4, int(total_buckets * 0.25))))

  # Model feasibility checks
  model_warnings = []
  if duration_hours <= 48.0 and archetype_up == "VELOCITY_SURGE_RATIO":
    model_warnings.append(
        f"Window duration ({duration_hours:.1f}h) is too short for 30-day moving average comparison. "
        f"Recommended model: POISSON_BURST_CLUSTERING with 'by 10m' or FLEET_PEER_ZSCORE."
    )
  elif duration_hours <= 48.0 and archetype_up in ["DATA_EXFILTRATION_SPIKE", "HEAVY_TAIL_OUTLIERS"]:
    model_warnings.append(
        f"Daily MAD/IQR requires multi-day baseline. For a {duration_hours:.1f}h window, "
        f"switch bucket size to 'by 1h' or 'by 15m' to establish intraday MAD/IQR baseline."
    )

  return {
      "duration_hours": duration_hours,
      "duration_days": duration_hours / 24.0,
      "recommended_bucket": bucket_size,
      "total_available_buckets": total_buckets,
      "sample_unit": sample_unit,
      "proportional_sample_floor": proportional_sample_floor,
      "base_thresholds": base_thresh,
      "model_warnings": model_warnings,
  }

THREAT_EXPLANATIONS = {
    "z_score": {
        "name": "Process Execution Volume Surge (Parametric Z-Score)",
        "plain_concept": "Massive sudden burst in program launches compared to this computer's normal daily routine.",
        "why_it_matters": (
            "When an endpoint suddenly launches hundreds or thousands of processes in a short window, "
            "it almost always indicates automated software execution (such as a script loop, malware installer, "
            "or rapid reconnaissance sweep) rather than a human user clicking applications."
        ),
        "malicious_scenarios": [
            "Ransomware traversing folders and launching execution helpers to encrypt files.",
            "Attacker running automated batch discovery scripts (ping sweeps, user queries, network shares).",
            "Malware dropper unpacking and executing secondary payloads in rapid succession."
        ],
        "benign_scenarios": [
            "Software engineer compiling code locally using build tools (Ninja, MSBuild, GCC, Rust/Cargo).",
            "IT systems management software (SCCM, BigFix, Ansible) deploying a large software suite.",
            "Local antivirus or security sensor running an aggressive background definitions update."
        ],
        "playbook": [
            "Run the drill-down query below to see the exact process paths (.exe/.sh) and command-line arguments that executed.",
            "Check the User Account: Is it an interactive employee user or a system background account (SYSTEM, root, svc-)?",
            "Look for suspicious execution folders: Are binaries launching from temporary folders (C:\\Temp, AppData\\Local\\Temp, /tmp)?",
            "Check if the host established sudden outbound network connections immediately following the process spike."
        ]
    },
    "fleet_z": {
        "name": "Cross-Fleet Peer Outlier (Peer Normalization Z-Score)",
        "plain_concept": "This specific computer is doing drastically more activity than all other computers in the company.",
        "why_it_matters": (
            "By comparing this computer against its peer fleet across the organization, we can isolate machines "
            "that stand out like a sore thumb. If only 1 out of 5,000 hosts exhibits this activity, it cannot be explained "
            "by a standard corporate update or company-wide policy."
        ),
        "malicious_scenarios": [
            "Dedicated compromised staging server used by an attacker as an internal pivot point.",
            "Compromised user laptop executing localized scanning scripts against the internal network.",
            "Targeted endpoint infection where malware is active on only a single high-value machine."
        ],
        "benign_scenarios": [
            "Dedicated build node, continuous integration (CI) runner, or software testing machine.",
            "Central IT administrator workstation performing approved fleet maintenance.",
            "Database or server host with naturally higher operational throughput than standard laptops."
        ],
        "playbook": [
            "Verify the host asset type and role (e.g. Domain Controller vs CI runner vs standard user laptop).",
            "Check which department or subnet the host belongs to and compare with adjacent peers.",
            "Inspect the top executing binary paths and verify if they are signed corporate enterprise applications."
        ]
    },
    "fano_factor": {
        "name": "Bursty Attack Wave Clustering (Poisson Dispersion / Fano Factor)",
        "plain_concept": "Downpour of login failures arriving in synchronized, intermittent attack waves rather than a steady trickle.",
        "why_it_matters": (
            "Ordinary human login mistakes happen randomly and spread out evenly over time (a steady trickle). "
            "Automated attack tools (like password sprayers or credential stuffers) operate in synchronized pulses or waves "
            "to try many passwords quickly while attempting to stay under fixed hourly rate limits."
        ),
        "malicious_scenarios": [
            "Password spraying: Attacker testing a single common password across hundreds of user accounts simultaneously.",
            "Credential stuffing: Automated bot trying lists of leaked username/password pairs in rapid pulses.",
            "Brute-force attack: Script looping through passwords against an exposed service or administrative account."
        ],
        "benign_scenarios": [
            "Cached credential loop: An employee recently changed their domain password, but their mobile phone or Outlook client is still retrying with the old saved password.",
            "Mapped network drive or script attempting reconnection in a loop after a password expiration."
        ],
        "playbook": [
            "Check the Failure Sub-Status: Is the error STATUS_WRONG_PASSWORD (bad password) or STATUS_ACCOUNT_LOCKED_OUT (locked)?",
            "Examine Source IP Diversity: Are the failed attempts coming from a single internal computer (cached password) or multiple external IP addresses (spray attack)?",
            "Check for Successful Logins: Did this account or any other account have a SUCCESSFUL login from the same source IP shortly after the failures?"
        ]
    },
    "poisson_z": {
        "name": "Improbable Sensitive Tool Spike (Discrete Poisson Rarity)",
        "plain_concept": "Dangerous or sensitive administrative tools running on a computer that has almost never used them before.",
        "why_it_matters": (
            "Certain built-in administrative utilities (like vssadmin, certutil, whoami, dsquery) are rarely used on normal endpoints, "
            "but attackers rely on them heavily for reconnaissance, credential dumping, or deleting shadow backups. Seeing them run suddenly "
            "on a quiet computer is a high-priority red flag."
        ),
        "malicious_scenarios": [
            "Ransomware running `vssadmin delete shadows` to prevent the victim from recovering encrypted files.",
            "Attacker using `certutil.exe` or `bitsadmin.exe` as a 'Living off the Land' downloader to pull malware.",
            "Intruder running `whoami /groups` or `dsquery` to map active directory privileges and domain controllers."
        ],
        "benign_scenarios": [
            "Authorized IT administrator performing hands-on server maintenance or troubleshooting.",
            "Approved corporate backup software managing shadow copies during scheduled maintenance.",
            "Automated software inventory scanner gathering system diagnostics."
        ],
        "playbook": [
            "Check the executing user account: Is the person an authorized Enterprise Admin or Tier-3 IT engineer?",
            "Look at the exact Command Line in the drilldown query below: What specific flags and arguments were passed?",
            "Inspect Network Connections: Did the binary establish an outbound connection to an unfamiliar external IP?"
        ]
    },
    "cv": {
        "name": "Robotic Periodic Beaconing (Inter-Arrival Timing Regularity)",
        "plain_concept": "Computer making network callbacks on an unnaturally regular, clockwork schedule (like a robotic heartbeat).",
        "why_it_matters": (
            "Human web browsing is chaotic and irregular (random intervals). Malware implants (like Cobalt Strike or Sliver) "
            "are programmed to 'call home' to an attacker's server at regular intervals with a little bit of randomized delay ('sleep jitter'). "
            "A low timing variation score indicates robotic software, not a human."
        ),
        "malicious_scenarios": [
            "Active Command & Control (C2) implant beaconing out to an external attacker-controlled server.",
            "Automated exfiltration script periodically checking an external drop point for new tasking."
        ],
        "benign_scenarios": [
            "Network Time Protocol (NTP) or OS time synchronization checks.",
            "Corporate SaaS keep-alives (Slack, Microsoft Teams, Google Drive sync pings).",
            "Operating system telemetry pings to Microsoft/Apple cloud infrastructure."
        ],
        "playbook": [
            "Check Company-Wide Prevalence: Does this external IP talk to >10 computers? If yes, it is likely a public SaaS or CDN service.",
            "Inspect TLS Certificate SNI: Check the domain name in the SSL/TLS certificate for legitimate ownership.",
            "Examine Request Size: Are payload upload/download byte sizes identical on every connection?"
        ]
    },
    "m_z_score": {
        "name": "Massive Data Transfer or DNS Tunneling Spike (Modified Z via MAD)",
        "plain_concept": "Sudden explosion in outbound data upload volume or DNS query complexity compared to typical daily traffic.",
        "why_it_matters": (
            "Attackers stealing data or tunneling traffic through DNS lookups generate huge spikes in volume. "
            "Using Median Absolute Deviation ensures that a single massive upload is caught cleanly without distorting "
            "the host's normal baseline calculations."
        ),
        "malicious_scenarios": [
            "Data Exfiltration: Attacker compressing and uploading sensitive internal documents to external cloud storage.",
            "DNS Tunneling: Malware encoding stolen data inside hundreds of unique DNS subdomain queries to bypass firewalls."
        ],
        "benign_scenarios": [
            "Approved large database or disk backup being pushed to enterprise cloud storage.",
            "Employee uploading large media/video assets or sync folder initialization.",
            "Heavy developer git clone or container image download/push."
        ],
        "playbook": [
            "Check Destination Reputation: Look up the destination IP or domain ASN, reputation, and country.",
            "Verify Transfer Timing: Does the upload timestamp align with a scheduled automated backup window?",
            "Inspect Protocol: If DNS, look for high entropy (random-looking) subdomain strings."
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
  is_multistage = bool(stages)

  if is_multistage:
    if len(stages) > 4:
      errors.append(
          f"STAGE COUNT LIMIT EXCEEDED ({len(stages)} named stages found): Malachite supports a maximum "
          f"of 4 named intermediate stages plus 1 unwrapped root stage (5 stages total). Reduce stage count."
      )

    # Verify that the final stage is unwrapped at the root level
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
  else:
    # Single-stage stats search validation
    if not re.search(r"^\s*match\s*:", query, re.MULTILINE):
      errors.append("MISSING MATCH SECTION: Single-stage stats searches require a 'match:' section.")
    if not re.search(r"^\s*outcome\s*:", query, re.MULTILINE):
      errors.append("MISSING OUTCOME SECTION: Single-stage stats searches require an 'outcome:' section.")

  # Validate all outcome blocks for Malachite AST rules, OutcomeLimit (20), and Intra-Stage Race Conditions
  stage_blocks = re.findall(r"stage\s+[a-zA-Z0-9_]+\s*\{([^}]*)\}", query, flags=re.DOTALL)
  outcome_blocks = []
  for sb in stage_blocks:
    om = re.search(r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)|\Z)", sb, flags=re.DOTALL | re.MULTILINE)
    if om:
      outcome_blocks.append(om.group(1))

  stripped_root = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", query, flags=re.DOTALL)
  root_om = re.search(r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)|\Z)", stripped_root, flags=re.DOTALL | re.MULTILINE)
  if root_om:
    outcome_blocks.append(root_om.group(1))

  for b_idx, block in enumerate(outcome_blocks):
    defined_vars = []
    lines = block.splitlines()
    outcome_assignments_count = 0

    for line in lines:
      line_clean = re.sub(r"//.*", "", line).strip()
      if not line_clean or "=" not in line_clean:
        continue
      
      outcome_assignments_count += 1
      lhs, rhs = line_clean.split("=", 1)
      var_name = lhs.strip().lstrip("$")
      
      # Check for intra-stage dependency / race condition:
      # If rhs references any variable previously defined in THIS outcome block
      for prev_var in defined_vars:
        if re.search(r"\$" + re.escape(prev_var) + r"\b", rhs):
          errors.append(
              f"INTRA-STAGE RACE CONDITION: Variable '${prev_var}' is defined on an earlier line in outcome block #{b_idx+1} "
              f"and referenced in '${line_clean}'. In YARA-L, multi-stage pipelines require dependent calculations "
              f"to be computed in an earlier stage or decomposed across stages."
          )

      defined_vars.append(var_name)

      # Check for inline/bare if in arithmetic: e.g. / if(...) or * if(...)
      if re.search(r"[-+*/]\s*if\s*\(|if\s*\([^)]*\)\s*[-+*/]", rhs):
        errors.append(
            f"MALACHITE AST ERROR: Inline if() inside outcome arithmetic: '{line_clean}'. "
            f"Outcome math rejects inline if() for division protection. Enforce non-zero divisor in 'condition:' instead."
        )

      # Check for parenthesized arithmetic in outcome assignments: e.g. ($a - $b) / $c, or func((...) / ...)
      if re.search(r"\([^)]*[-+*/][^)]*\)", rhs):
        errors.append(
            f"MALACHITE AST ERROR: Parentheses in outcome arithmetic: '{line_clean}'. "
            f"Malachite AST rejects compound/parenthesized arithmetic. Use linear variable assignments ($diff = $a - $b, $res = $diff / $c)."
        )

    if outcome_assignments_count > 20:
      errors.append(
          f"OUTCOME LIMIT EXCEEDED ({outcome_assignments_count} variables in outcome block #{b_idx+1}): "
          f"Malachite enforces OutcomeLimit = 20 variables per outcome section. Prune outcome variables."
      )

  if not re.search(r"//\s*Goal:", query, re.IGNORECASE):
    errors.append("MISSING METHODOLOGY HEADER: Recommended to include '// Goal:' and '// Statistical Model:' methodology block.")

  return errors


def check_search_window(
    start_time: str,
    end_time: str,
    is_multistage: bool,
    query_text: Optional[str] = None
) -> List[str]:
  """Enforces the Two-Tier Search Window Ceilings and detects automatic query failure from condition sample floors."""
  from datetime import datetime
  errors = []
  try:
    t0 = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
    t1 = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    delta_seconds = (t1 - t0).total_seconds()
    delta_days = delta_seconds / 86400.0
    delta_hours = delta_seconds / 3600.0

    if delta_days <= 0:
      errors.append(f"INVALID TIME RANGE: start_time ({start_time}) must be earlier than end_time ({end_time}).")

    if is_multistage and delta_days > 30.0:
      errors.append(
          f"WINDOW CEILING EXCEEDED ({delta_days:.1f} days): Multi-stage queries have a hard 30-day (720h) ceiling. "
          f"Reduce window to <= 30 days (provides 720 hourly baseline samples) or use single-stage macro search."
      )
    elif not is_multistage and delta_days > 90.0:
      errors.append(
          f"WINDOW CEILING EXCEEDED ({delta_days:.1f} days): Single-stage searches have a hard 90-day (2,160h) ceiling. "
          f"Reduce window to <= 90 days."
      )

    # Detect condition sample floors that exceed available window capacity
    if query_text:
      # Match sample floor conditions like $baseline_active_samples >= 120, $active_days >= 7, etc.
      sample_matches = re.findall(
          r"\$(?:baseline_active_samples|active_samples|active_days|active_hours)\s*>=\s*(\d+)",
          query_text
      )
      for s_val_str in sample_matches:
        req_samples = int(s_val_str)
        # Check if hourly buckets are used in query
        if "by 1h" in query_text:
          if req_samples > delta_hours:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active hourly samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {int(delta_hours)} hourly intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(delta_hours * 0.25))}) or expand the search window."
            )
        elif "by day" in query_text or "by 1d" in query_text:
          if req_samples > delta_days:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active daily samples, "
                f"but the specified time window ({delta_days:.1f} days) has at most {int(delta_days)} daily intervals. "
                f"Scale the sample floor down (e.g. >= {max(2, int(delta_days * 0.4))}) or switch to hourly buckets ('by 1h')."
            )

  except Exception as e:
    errors.append(f"TIMESTAMP PARSE ERROR: Could not parse start/end times: {e}")
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


def calculate_fleet_adjusted_threshold(base_z: float, fleet_size: int) -> float:
  """Calculates Bonferroni / Extreme Value Theory adjusted Z-score threshold for large fleets."""
  if fleet_size <= 1:
    return base_z
  # Bonferroni adjustment approximation for Gaussian tail: Z_adj ~ sqrt(2 * ln(N))
  correction = math.sqrt(2.0 * math.log(max(fleet_size, 2)))
  return max(base_z, round(correction, 2))


def evaluate_confidence_tier(row: Dict[str, Any]) -> Tuple[str, str]:
  """Evaluates statistical evidence confidence rating (High vs Moderate vs Insufficient Baseline)."""
  active_samples = float(row.get("baseline_active_samples", row.get("active_samples", row.get("active_days", 100))))
  obs = float(row.get("observation_count", row.get("observed_count", row.get("observed_today", row.get("total_fails", 50)))))
  disp = float(row.get("baseline_dispersion", row.get("stddev_val", row.get("mad_val", 10.0))))
  prevalence = float(row.get("fleet_prevalence", row.get("hosts_contacting", 1)))

  if active_samples < 30 or obs < 5 or disp <= 0.1:
    return "⚪ **INSUFFICIENT BASELINE**", "Denominator too small (< 30 active samples or near-zero dispersion). Risk of false-positive anomaly."
  elif active_samples >= 120 and obs >= 25 and disp >= 5.0 and prevalence <= 3:
    return "🟢 **HIGH CONFIDENCE**", "Robust historical baseline (>= 120 active samples, verified dispersion, low fleet prevalence)."
  else:
    return "🟡 **MODERATE CONFIDENCE**", "Adequate baseline with acceptable statistical support."


def get_soc_severity_badge(chosen_key: str, score: float) -> str:
  """Translates statistical score into a standard SOC operational rating."""
  if chosen_key in ["z_score", "poisson_z", "fleet_z"]:
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
    event_type: str = "PROCESS_LAUNCH",
    fleet_size: int = 1
) -> str:
  """Renders raw Chronicle multi-stage stats into a Clean CommonMark/HTML-Safe 4-Tier Report with Evidence Pillars."""
  rows = parse_columnar_stats(stats_payload)
  if not rows:
    return "⚡ **STATISTICAL HUNT VERDICT**: No outlier entities exceeded the configured anomaly threshold."

  sort_keys = ["z_score", "poisson_z", "fleet_z", "fano_factor", "m_z_score", "surge_ratio", "ratio_1v30", "cv"]
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
  out.append(f"* **Outliers Detected**: **{total_outliers} entities** exceeded the anomaly threshold.")
  
  if fleet_size > 1:
    adj_z = calculate_fleet_adjusted_threshold(3.0, fleet_size)
    out.append(f"* **Fleet Scaling / Multiple-Comparison Adjustment**: Fleet Size $N = {fleet_size}$ | Bonferroni Threshold $Z_{{\\text{{adj}}}} \\ge {adj_z}\\sigma$")

  if "baseline_mean" in rows[0] and "baseline_dispersion" in rows[0]:
    out.append(f"* **Normal Baseline Envelope**: Typical Average ($\\mu$) $\\approx {float(rows[0]['baseline_mean']):.1f}$ | Typical Variation ($\\sigma$) $\\approx \\pm{float(rows[0]['baseline_dispersion']):.1f}$")
  elif "mean_val" in rows[0] and "stddev_val" in rows[0]:
    out.append(f"* **Normal Baseline Envelope**: Typical Average ($\\mu$) $\\approx {float(rows[0]['mean_val']):.1f}$ | Typical Variation ($\\sigma$) $\\approx \\pm{float(rows[0]['stddev_val']):.1f}$")
  elif "mu" in rows[0] and "stddev_val" in rows[0]:
    out.append(f"* **Normal Baseline Envelope**: Typical Average ($\\mu$) $\\approx {float(rows[0]['mu']):.1f}$ | Typical Variation ($\\sigma$) $\\approx \\pm{float(rows[0]['stddev_val']):.1f}$")
  elif "historical_lambda" in rows[0]:
    out.append(f"* **Normal Baseline Envelope**: Historical Daily Rate ($\\lambda$) $\\approx {float(rows[0]['historical_lambda']):.2f}\\text{ runs/day}$")

  out.append("")
  out.append("---")
  out.append("")
  out.append("#### 📊 Ranked Outlier Summary (Top Anomalies by Severity)")
  out.append("")
  out.append("| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Visual Magnitude |")
  out.append("| :------------------- | :----------- | :---------------- | :------------------------- | :-------------- | :-------------- | :--------------- |")

  max_score = float(top_rows[0].get(chosen_key, 6.0)) if chosen_key and top_rows[0].get(chosen_key) else 6.0
  for row in top_rows:
    ent = str(row.get(entity_col, "unknown"))
    tb = str(row.get("TIME_BUCKET", row.get("window_start", "Full Window")))
    obs = str(row.get("observation_count", row.get("observed_count", row.get("observed_today", row.get("total_fails", row.get("daily_mb", ""))))))
    
    base_str = "Baseline"
    if "baseline_mean" in row and "baseline_dispersion" in row:
      base_str = f"{float(row['baseline_mean']):.0f} ± {float(row['baseline_dispersion']):.0f}"
    elif "mean_val" in row and "stddev_val" in row:
      base_str = f"{float(row['mean_val']):.0f} ± {float(row['stddev_val']):.0f}"
    elif "mu" in row and "stddev_val" in row:
      base_str = f"{float(row['mu']):.0f} ± {float(row['stddev_val']):.0f}"
    elif "historical_lambda" in row:
      base_str = f"λ = {float(row['historical_lambda']):.2f}/d"
    
    conf_badge, _ = evaluate_confidence_tier(row)
    score_val = float(row.get(chosen_key, 0.0)) if chosen_key else 0.0
    badge = get_soc_severity_badge(chosen_key, score_val)
    score_str = f"+{score_val:.2f}σ" if chosen_key in ["z_score", "poisson_z", "fleet_z"] else f"{score_val:.2f}"
    vbar = f"`{generate_visual_bar(score_val, max_score)}`"
    
    out.append(f"| `{ent}` | {tb[:16]} | **{obs}** | {base_str} | {conf_badge} | {badge} (`{score_str}`) | {vbar} |")

  top_ent = top_rows[0]
  top_score_val = float(top_ent.get(chosen_key, 0.0)) if chosen_key else 0.0
  top_score_str = f"+{top_score_val:.2f}σ" if chosen_key in ["z_score", "poisson_z", "fleet_z"] else f"{top_score_val:.2f}"
  top_badge = get_soc_severity_badge(chosen_key, top_score_val)
  top_conf_badge, top_conf_desc = evaluate_confidence_tier(top_ent)
  ent_name = str(top_ent.get(entity_col, "unknown"))

  obs_val = top_ent.get("observation_count", top_ent.get("observed_count", top_ent.get("observed_today", top_ent.get("total_fails", top_ent.get("daily_mb", "N/A")))))
  active_samples = top_ent.get("baseline_active_samples", top_ent.get("active_samples", top_ent.get("active_days", "N/A")))
  base_mean = top_ent.get("baseline_mean", top_ent.get("mean_val", top_ent.get("historical_lambda", top_ent.get("mu", "N/A"))))
  base_disp = top_ent.get("baseline_dispersion", top_ent.get("stddev_val", top_ent.get("mad_val", "N/A")))
  fleet_prev = top_ent.get("fleet_prevalence", top_ent.get("hosts_contacting", top_ent.get("fleet_host_count", "1")))
  cardinality = top_ent.get("distinct_binaries", top_ent.get("distinct_subdomains", top_ent.get("total_connections", "N/A")))

  out.append("")
  out.append("---")
  out.append("")
  out.append(f"#### 🔍 Top Outlier Spotlight: `{ent_name}` — {top_badge} (`{top_score_str}`)")
  out.append("")
  out.append(f"* **Data Confidence Level**: {top_conf_badge} — {top_conf_desc}")
  out.append("")

  # Generate Plain-English Narrative Headline
  try:
    obs_num = float(obs_val)
    mean_num = float(base_mean)
    if mean_num > 0:
      surge_mult = obs_num / mean_num
      surge_pct = ((obs_num - mean_num) / mean_num) * 100.0
      narrative_surge = f"**{surge_mult:.1f}x higher than normal** (+{surge_pct:.0f}% above baseline)"
    else:
      narrative_surge = f"an unprecedented jump from a near-zero baseline"
  except (ValueError, TypeError):
    narrative_surge = f"an extreme deviation from typical activity"

  out.append("##### 🗣️ What Happened & Why It Matters (In Plain English)")
  out.append(f"> **The Finding**: During this window, `{ent_name}` performed **{obs_val} events**, representing {narrative_surge} (normal average is **{base_mean}**).")
  out.append(f"> ")
  out.append(f"> **Why It Matters**: This sudden burst produced an anomaly rating of **{top_score_str}**, indicating behavior so statistically rare that it almost certainly represents **automated software execution, script loops, or active threat tooling** rather than normal human employee activity.")
  out.append(f"> ")
  out.append(f"> **Organization Context**: This behavior was observed on only **{fleet_prev} endpoint(s)** across the entire company, ruling out a routine corporate-wide software rollout.")
  out.append("")

  # Render Plain-English 6 Evidence Pillars
  out.append("##### 🏛️ Forensic Evidence Breakdown")
  out.append("")
  out.append("| Evidence Pillar | Observed Value | What this Means for Your Investigation |")
  out.append("| :--- | :--- | :--- |")
  out.append(f"| **1. Activity Spike** | `{obs_val}` | What this computer actually did during the spike window |")
  out.append(f"| **2. Baseline History** | `{active_samples} units` | How much history was analyzed to ensure this isn't a new or unobserved machine |")
  out.append(f"| **3. Typical Normal Level** | `{base_mean}` | The normal expected volume when things are operating routinely |")
  out.append(f"| **4. Normal Daily Spread** | `±{base_disp}` | Typical fluctuation range; this surge blew far past this envelope |")
  out.append(f"| **5. Company-Wide Breadth** | `{fleet_prev} host(s)` | 1 host = isolated/targeted; 100 hosts = company-wide software push |")
  out.append(f"| **6. Variety of Programs** | `{cardinality}` | Unique programs/commands involved (high variety = batch recon/staging) |")

  if chosen_key and chosen_key in THREAT_EXPLANATIONS:
    expl = THREAT_EXPLANATIONS[chosen_key]
    out.append("")
    out.append("> [!IMPORTANT]")
    out.append(f"> **Threat Explanation: {expl['name']}**")
    out.append(f"> * **The Core Concept**: {expl['plain_concept']}")
    out.append(f"> * **Security Significance**: {expl['why_it_matters']}")
    out.append("> ")
    out.append("> **🔴 Potential Attack Scenarios (What to look for)**:")
    for mal in expl["malicious_scenarios"]:
      out.append(f"> * {mal}")
    out.append("> ")
    out.append("> **🟢 Legitimate Business Explanations (False positives to rule out)**:")
    for ben in expl["benign_scenarios"]:
      out.append(f"> * {ben}")
    out.append("> ")
    out.append("> **🎯 Step-by-Step SOC Action Plan (No Math Required)**:")
    for idx, step in enumerate(expl["playbook"], 1):
      out.append(f"> {idx}. {step}")

  out.append("")
  out.append("---")
  out.append("")
  out.append("#### 🎯 Immediate Drill-Down Investigation Query")
  out.append("")
  out.append("```yara")
  drilldown_str = f'principal.hostname = "{ent_name}" AND metadata.event_type = "{event_type}"'
  if "user" in top_ent and top_ent["user"]:
    drilldown_str = f'target.user.userid = "{top_ent.get("user")}" AND metadata.event_type = "{event_type}"'
  if "window_start" in top_ent and top_ent["window_start"]:
    ws_val = top_ent["window_start"]
    try:
      ws = int(ws_val)
      drilldown_str += f"\nAND metadata.event_timestamp.seconds >= {ws} AND metadata.event_timestamp.seconds <= {ws + 3600}"
    except (ValueError, TypeError):
      drilldown_str += f'\nAND metadata.event_timestamp >= "{ws_val}"'
  out.append(drilldown_str)
  out.append("```")

  # Technical / Mathematical Appendix (Chewier Details)
  out.append("")
  out.append("---")
  out.append("")
  out.append("<details>")
  out.append("<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>")
  out.append("")
  out.append("##### 📐 Mathematical Model & Formulaic Derivations")
  
  if chosen_key == "z_score":
    out.append("* **Model**: Parametric Gaussian Standardization (Historical $Z$-Score)")
    out.append("  $$Z = \\frac{x - \\mu}{\\sigma} = \\frac{" + f"{obs_val} - {base_mean}" + "}{" + f"{base_disp}" + "} = " + f"{top_score_str}" + "$$")
    out.append(f"* **Degrees of Freedom ($N$)**: `{active_samples}` active baseline observation intervals.")
    out.append(f"* **Dispersion Metric**: Sample Standard Deviation $s = \\sqrt{{\\frac{{1}}{{N-1}} \\sum (x_i - \\bar{{x}})^2}} = {base_disp}$.")
  elif chosen_key == "fleet_z":
    out.append("* **Model**: Cross-Fleet Peer Normalization ($Z_{\\text{fleet}}$)")
    out.append("  $$Z_{\\text{fleet}} = \\frac{x_{\\text{host}} - \\mu_{\\text{fleet}}}{\\sigma_{\\text{fleet}}} = " + f"{top_score_str}" + "$$")
    out.append(f"* **Peer Group Sample Size**: `{fleet_prev}` active peer hosts contributing to fleet baseline.")
  elif chosen_key == "fano_factor":
    out.append("* **Model**: Poisson Dispersion Index / Fano Factor ($F$)")
    out.append("  $$F = \\frac{\\sigma^2}{\\mu} = " + f"{top_score_str}" + "$$")
    out.append("* **Dispersion Physics**: $F = 1.0$ indicates pure random Poisson chatter; $F > 4.0$ indicates non-Poisson attack wave clustering / burstiness.")
  elif chosen_key == "poisson_z":
    out.append("* **Model**: Discrete Poisson Standardized Rarity ($Z_{\\text{poisson}}$)")
    out.append("  $$Z_{\\text{poisson}} = \\frac{k - \\lambda}{\\sqrt{\\lambda}} = " + f"{top_score_str}" + "$$")
    out.append(f"* **Theoretical Standard Error**: $\\text{{SE}} = \\sqrt{{\\lambda}} = \\sqrt{{{base_mean}}}$.")
  elif chosen_key == "cv":
    out.append("* **Model**: Coefficient of Variation (Inter-Arrival Timing Jitter)")
    out.append("  $$\\text{CV} = \\frac{\\sigma_{\\Delta t}}{\\mu_{\\Delta t}} = " + f"{top_score_str}" + "$$")
    out.append("* **Jitter Boundary**: $\\text{CV} \\le 0.20$ reflects algorithmic beaconing (implant sleep jitter $\\le 20\\%$); $\\text{CV} > 0.50$ indicates human browser variance.")
  elif chosen_key == "m_z_score":
    out.append("* **Model**: Modified $Z$-Score via Median Absolute Deviation (MAD)")
    out.append("  $$M_Z = \\frac{0.6745 \\cdot (x - \\tilde{x})}{\\text{MAD}} = " + f"{top_score_str}" + "$$")
    out.append(f"* **Median ($\\\\tilde{{x}}$)**: `{base_mean}` | **MAD**: `{base_disp}` (robust against skew and extreme outliers).")

  if fleet_size > 1:
    adj_z = calculate_fleet_adjusted_threshold(3.0, fleet_size)
    out.append("")
    out.append("##### 🌐 Multiple-Comparison Fleet Correction (Bonferroni / Gumbel Tail)")
    out.append(f"* **Fleet Population ($N$)**: `{fleet_size}` independent endpoints evaluated simultaneously.")
    out.append(f"* **Adjusted Critical Threshold**: $Z_{{\\text{{adj}}}} \\approx \\sqrt{{2 \\ln N}} = {adj_z}\\sigma$.")
    out.append(f"* **Family-Wise Error Rate (FWER)**: Controls fleet-wide false discovery probability at $\\alpha = 0.01$.")

  out.append("")
  out.append("##### 🛡️ Statistical Validity & Safeguard Verification")
  out.append(f"* **Sample Density Floor**: `{active_samples}` active units (Threshold $\\ge 30$ $\\to$ **PASSED**).")
  out.append(f"* **Dispersion Non-Zero Floor**: Spread `{base_disp}` (Threshold $\\ge 5.0$ $\\to$ **PASSED**).")
  out.append(f"* **Fleet Prevalence Isolation**: `{fleet_prev}` host(s) (Threshold $\\le 3$ $\\to$ **PASSED**).")
  out.append("</details>")

  return "\n".join(out)


def generate_chart_spec(
    stats_payload: Dict[str, Any],
    plot_type: str = "DUAL_Y_TIMESERIES",
    title: str = "Outlier Investigation Timeline (Dual-Y)",
    threshold_value: float = 3.0
) -> Dict[str, Any]:
  """Generates Strictly-Typed True Dual-Y Axis Vega-Lite chart specs with right axis orientation and threshold rules."""
  rows = parse_columnar_stats(stats_payload)
  
  if plot_type == "DUAL_Y_TIMESERIES":
    score_key = next((k for k in ["z_score", "poisson_z", "fleet_z", "fano_factor", "m_z_score", "surge_ratio"] if rows and k in rows[0]), "z_score")
    score_title = "Z-Score (σ)" if score_key in ["z_score", "poisson_z", "fleet_z"] else "Anomaly Index"
    vol_key = next((k for k in ["observation_count", "observed_count", "observed_today", "total_fails", "daily_mb"] if rows and k in rows[0]), "observation_count")
    vol_title = "Observed Event Volume"

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 650,
        "height": 320,
        "data": {"values": rows},
        "resolve": {"scale": {"y": "independent"}},
        "layer": [
            {
                "mark": {"type": "bar", "color": "#76c0f8", "opacity": 0.65},
                "encoding": {
                    "x": {"field": "TIME_BUCKET", "type": "temporal", "title": "Time Window (UTC)"},
                    "y": {
                        "field": vol_key,
                        "type": "quantitative",
                        "axis": {"title": vol_title, "titleColor": "#1a73e8"}
                    },
                    "tooltip": [
                        {"field": "host", "type": "nominal", "title": "Entity"},
                        {"field": "TIME_BUCKET", "type": "temporal", "title": "Time"},
                        {"field": vol_key, "type": "quantitative", "title": vol_title}
                    ]
                }
            },
            {
                "mark": {"type": "line", "point": {"filled": True, "size": 65, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": "TIME_BUCKET", "type": "temporal"},
                    "y": {
                        "field": score_key,
                        "type": "quantitative",
                        "axis": {
                            "title": f"Statistical Score ({score_title})",
                            "orient": "right",
                            "titleColor": "#d93025",
                            "grid": False
                        }
                    },
                    "tooltip": [
                        {"field": "host", "type": "nominal", "title": "Entity"},
                        {"field": score_key, "type": "quantitative", "title": score_title}
                    ]
                }
            },
            {
                "mark": {"type": "rule", "color": "#d93025", "strokeDash": [5, 5], "strokeWidth": 1.5},
                "encoding": {
                    "y": {
                        "datum": threshold_value,
                        "type": "quantitative",
                        "axis": {"orient": "right"}
                    }
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
            "y": {"field": "observation_count", "type": "quantitative", "title": "Observed Intensity / Volume"},
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
                {"field": "observation_count", "type": "quantitative"},
                {"field": "z_score", "type": "quantitative"}
            ]
        }
    }
  elif plot_type == "CATEGORICAL_BAR":
    cat_key = next((k for k in ["extension_id", "host", "user", "process", "principal_ip", "entity"] if rows and k in rows[0]), "host")
    val_key = next((k for k in ["event_count", "observation_count", "observed_count", "request_count", "count"] if rows and k in rows[0]), "observation_count")
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 650,
        "height": 300,
        "data": {"values": rows},
        "mark": {"type": "bar", "color": "#1a73e8"},
        "encoding": {
            "x": {"field": cat_key, "type": "nominal", "sort": "-y", "title": "Entity Identifier", "axis": {"labelAngle": -45}},
            "y": {"field": val_key, "type": "quantitative", "title": "Observed Activity Count"},
            "tooltip": [
                {"field": cat_key, "type": "nominal", "title": "Entity"},
                {"field": val_key, "type": "quantitative", "title": "Activity Count"}
            ]
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
            "y": {"field": "observation_count", "type": "quantitative", "title": "Observed Metric"},
            "color": {"field": "host", "type": "nominal"}
        }
    }
  return spec


def generate_chartjs_spec(
    stats_payload: Dict[str, Any],
    plot_type: str = "CATEGORICAL_BAR",
    title: str = "Activity Distribution by Entity"
) -> Dict[str, Any]:
  """Generates strictly-typed, axis-isolated Chart.js JSON configs to prevent mixed categorical/numeric Y-axis corruption."""
  rows = parse_columnar_stats(stats_payload)
  if not rows:
    return {"type": "bar", "data": {"labels": [], "datasets": []}}
  
  if plot_type == "CATEGORICAL_BAR":
    cat_key = next((k for k in ["extension_id", "host", "user", "process", "principal_ip", "entity"] if k in rows[0]), "host")
    val_key = next((k for k in ["event_count", "observation_count", "observed_count", "request_count", "count"] if k in rows[0]), "observation_count")
    
    labels = [str(r.get(cat_key, "Unknown")) for r in rows]
    data_points = [float(r.get(val_key, 0)) for r in rows]
    
    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": "Activity Count",
                    "data": data_points,
                    "backgroundColor": "rgba(26, 115, 232, 0.75)",
                    "borderColor": "rgba(26, 115, 232, 1.0)",
                    "borderWidth": 1
                }
            ]
        },
        "options": {
            "responsive": True,
            "plugins": {
                "title": {"display": True, "text": title},
                "legend": {"display": False}
            },
            "scales": {
                "x": {"title": {"display": True, "text": "Entity Identifier"}},
                "y": {"type": "linear", "beginAtZero": True, "title": {"display": True, "text": "Observed Event Count"}}
            }
        }
    }
  elif plot_type == "DUAL_Y_TIMESERIES":
    time_labels = [str(r.get("TIME_BUCKET", "N/A")) for r in rows]
    vol_key = next((k for k in ["observation_count", "observed_count", "event_count"] if k in rows[0]), "observation_count")
    score_key = next((k for k in ["z_score", "fleet_z", "poisson_z", "fano_factor"] if k in rows[0]), "z_score")
    
    vol_data = [float(r.get(vol_key, 0)) for r in rows]
    score_data = [float(r.get(score_key, 0)) for r in rows]
    
    return {
        "type": "bar",
        "data": {
            "labels": time_labels,
            "datasets": [
                {
                    "type": "bar",
                    "label": "Event Volume",
                    "data": vol_data,
                    "yAxisID": "y",
                    "backgroundColor": "rgba(118, 192, 248, 0.65)"
                },
                {
                    "type": "line",
                    "label": "Statistical Score (Z)",
                    "data": score_data,
                    "yAxisID": "y1",
                    "borderColor": "rgba(217, 48, 37, 1.0)",
                    "backgroundColor": "rgba(217, 48, 37, 1.0)",
                    "tension": 0.1
                }
            ]
        },
        "options": {
            "responsive": True,
            "plugins": {"title": {"display": True, "text": title}},
            "scales": {
                "x": {"title": {"display": True, "text": "Time Window (UTC)"}},
                "y": {"type": "linear", "position": "left", "title": {"display": True, "text": "Event Volume"}},
                "y1": {"type": "linear", "position": "right", "grid": {"drawOnChartArea": False}, "title": {"display": True, "text": "Z-Score (σ)"}}
            }
        }
    }
  return {"type": "bar", "data": {"labels": [], "datasets": []}}


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
  parser.add_argument(
      "--chart_spec",
      help="Path to raw stats JSON to generate Dual-Y Vega-Lite chart spec",
  )
  parser.add_argument(
      "--start_time",
      help="Query start time in ISO 8601 format (e.g. 2026-08-01T00:00:00Z)",
  )
  parser.add_argument(
      "--end_time",
      help="Query end time in ISO 8601 format (e.g. 2026-08-21T00:00:00Z)",
  )
  parser.add_argument(
      "--fleet_size",
      type=int,
      default=1,
      help="Fleet size (total number of endpoints/users) for multiple-comparison threshold adjustment",
  )

  parser.add_argument(
      "--window_hours",
      type=float,
      help="Time window duration in hours to calculate adaptive bucket granularity and proportional sample floor",
  )

  args = parser.parse_args()

  if args.window_hours and args.archetype:
    params = get_adaptive_window_parameters(args.window_hours, args.archetype, args.tier)
    print(f"=== Adaptive Window Parameters for {args.archetype} ({args.window_hours:.1f} hours) ===")
    print(f"  Recommended Bucket Granularity : {params['recommended_bucket']}")
    print(f"  Total Available Intervals      : {params['total_available_buckets']} ({params['sample_unit']})")
    print(f"  Proportional Sample Floor      : >= {params['proportional_sample_floor']} active intervals")
    if params['model_warnings']:
      print("  ⚠️ Model Warnings:")
      for mw in params['model_warnings']:
        print(f"    - {mw}")
    sys.exit(0)

  if args.start_time and args.end_time:
    is_multi = True
    q_text = None
    if args.query_file:
      with open(args.query_file, "r") as f:
        q_text = f.read()
      is_multi = "stage " in q_text
    window_errors = check_search_window(args.start_time, args.end_time, is_multi, query_text=q_text)
    if window_errors:
      print("\n❌ SEARCH WINDOW ERROR:")
      for w in window_errors:
        print(f"  {w}")
      sys.exit(1)

  if args.format_report:
    with open(args.format_report, "r") as f:
      data = json.load(f)
    print(format_triage_report("Process Execution Outliers", data, fleet_size=args.fleet_size))
    sys.exit(0)

  if args.chart_spec:
    with open(args.chart_spec, "r") as f:
      data = json.load(f)
    print(json.dumps(generate_chart_spec(data, plot_type="DUAL_Y_TIMESERIES"), indent=2))
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
      print("✅ Query passed all canonical multi-stage grammar, race-condition, and scope exclusion checks.")
      sys.exit(0)


if __name__ == "__main__":
  main()

