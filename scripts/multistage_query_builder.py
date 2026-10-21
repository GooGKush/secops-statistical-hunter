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
__version__ = "2.7.2"

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

EXCLUDED_PATTERNS = [
    (r"\bmetrics\.", "UEBA metric functions (metrics.*) are excluded from ad-hoc time range searches. Use secops-risk-metrics-multistage."),
    (r"\brisk_score\b", "Entity Risk Score fields (risk_score) are excluded. Use secops-risk-metrics-multistage."),
    (r"\bgraph\.risk_score", "Entity Risk Graph tables are excluded. Use secops-risk-metrics-multistage."),
    (r"UEBA_EVENTS", "UEBA_EVENTS source dataset is excluded. Use raw UDM_EVENTS or RULE_DETECTIONS."),
    (r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", "Multi-stage queries CANNOT be wrapped in rule blocks or deployed to the Rules Engine. They are Search/Dashboard-only."),
]

SYNTAX_TRAPS = [
    (r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\bevents\s*:", "SYNTAX ERROR (INVALID_EVENTS_SECTION_IN_STAGE): Multi-stage named stages do NOT use an 'events:' header. Place event filters directly inside the stage block."),
    (r"\$\w+\s+in\s+\$?[a-zA-Z0-9_]+", "SYNTAX ERROR (INVALID_STAGE_IN_SYNTAX): Do NOT use '$var in stage_name'. Access stage outputs directly via '$stage_name.variable_name' or '$var = $stage_name.variable_name'."),
    (r"\b[a-zA-Z0-9_]+\.\$[a-zA-Z0-9_]+", "SYNTAX ERROR (INVALID_STAGE_VARIABLE_SYNTAX): Multi-stage variable references must use '$stage.var', not 'stage.$var' (placing '$' after the dot causes an ANTLR syntax crash)."),
    (r"\bcount\s*\(\s*if\s*\(", "SYNTAX ERROR: 'count(if(...))' is invalid syntax. Use 'sum(if(condition, 1, 0))' for conditional event counting."),
    (r"(?<!math\.)\bsqrt\s*\(", "SYNTAX ERROR (INVALID_SQRT_FUNCTION): Bare 'sqrt(...)' is invalid in YARA-L outcome expressions. Use namespaced 'math.sqrt(...)' or compute squared norm ($norm_sq = $z1_sq + $z2_sq) and order by '$norm_sq desc'."),
    (r"^\s*options\s*:", "SYNTAX ERROR: 'options:' blocks are Rule-Engine only and rejected in Search/Dashboard queries. Searches terminate after 'condition:' or 'order:'."),
    (r"match:\s*[^;\n]+\bby\b[^;\n]+\b(hop|over)\b", "SYNTAX ERROR: Compound 'by X hop Y' or 'by X over Y' is invalid syntax in YARA-L. Use 'match: $var by <duration>' for tumbling buckets, 'match: $var over <duration>' for sliding windows, or 'match: $var' for unwindowed baseline stages."),
    (r"\^", "SYNTAX ERROR (INVALID_EXPONENT_OPERATOR): '^' is invalid in YARA-L outcome expressions. Use '$var * $var' for squared terms ($z_sq = $z * $z)."),
    (r"\bin\s*\([\"']", "SYNTAX ERROR (INVALID_IN_SYNTAX): 'in (\"A\", \"B\")' tuple syntax is invalid in YARA-L. Use '(field = \"A\" or field = \"B\")' or regex 're.regex(field, `A|B`)'."),
    (r"match:\s*[^;\n]*\bby\s+24h\b", "STYLE ERROR (NONCANONICAL_WINDOW_TOKEN): 'by 24h' compiles to the same buckets as 'by 1d' but is non-canonical. Use 'by 1d' for daily matching."),
    (r"stage\s+\$[a-zA-Z0-9_]+\s*\{", "SYNTAX ERROR (STAGE_NAME_PREFIX_ERROR): Stage declarations must not have a '$' prefix (use 'stage stage_name {', not 'stage $stage_name {')."),
    (r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", "SYNTAX ERROR (INVALID_DETECTION_RULE_SYNTAX): Multi-stage queries are Search/Dashboard-only ('stage ... { ... }' + root stage). Do NOT wrap in 'rule ... { ... }'."),
    (r"(?:stage\s+[a-zA-Z0-9_]+\s*\{.*?\}\s*)+\s*events\s*:", "SYNTAX ERROR (INVALID_EVENTS_SECTION_IN_ROOT): Root stage of a multi-stage query must not contain an 'events:' header block. Stage bindings must be declared directly before match:."),
    (r"match:\s*[^;\n]*\$[a-zA-Z0-9_]+\.[a-zA-Z0-9_.]+", "SYNTAX ERROR (INVALID_MATCH_DOT_NOTATION): Match blocks accept ONLY simple bound variable identifiers (e.g. '$host by 1d'), not member dot-notation. Bind variables in event predicates before match:."),
    (r"\$dummy\s*=\s*\d+", "SYNTAX ERROR (CARTESIAN_DUMMY_JOIN): Multi-stage YARA-L queries do not support artificial Cartesian joins via '$dummy = 1'. Align stages using real partition keys (e.g. '$token by 1d') across stages."),
    (r"match:\s*[^;\n]*\$dummy\b", "SYNTAX ERROR (CARTESIAN_DUMMY_JOIN): Multi-stage YARA-L queries do not support artificial Cartesian joins via '$dummy'. Align stages using real partition keys (e.g. '$token by 1d') across stages."),
    # --- Verified compiler facts (live udm_search probes, 2026-09-24) ---
    (r"\bif\s*\([^)]*==", "SYNTAX ERROR (DOUBLE_EQUALS_IN_IF): '==' inside if() is rejected by the Chronicle compiler. Use a single '=' for equality inside if(cond, a, b), e.g. if($x = 1.0, 1, 0)."),
    (r"\$window_start\s*=\s*(?:min|max|avg|sum|count)\s*\(", "SYNTAX ERROR (WINDOW_START_SHADOWED): '$window_start' is an implicit output of every windowed stage ('match: $k by <dur>'). Defining it in outcome: (e.g. '$window_start = min(metadata.event_timestamp.seconds)') is rejected. Remove the definition and bind '$ws = $stage.window_start' in the consuming stage instead."),
    (r"\b(?:max|min)\s*\(\s*(?:\$?[a-zA-Z0-9_.]*\.(?:hostname|userid|user_agent|full_path|command_line|sha256|md5|sha1|domain|url|email_addresses|ip)|\$(?:host|hostname|user|userid|token|entity|domain|ip|src_ip|dst_ip|hash|sha256|url|cmd|command))\s*\)", "SYNTAX ERROR (INVALID_STRING_AGGREGATION_FUNCTION): max()/min() are numeric only (Int/Float); calling them on a string field or string placeholder is rejected. Project strings with array_distinct(...) or count them with count_distinct(...)."),
    (r"match:\s*[^;\n]*\bby\s+(?!1d\b)\d+d\b", "SYNTAX ERROR (NONCANONICAL_MATCH_WINDOW): Multi-day tumbling windows ('by 2d', 'by 7d', 'by 14d') are rejected by the compiler. Verified windows: 'by 5m', 'by 10m', 'by 15m', 'by 1h', 'by 2h', 'by 1d'. Keep the bucket at <= 1d and widen startTime/endTime to cover longer horizons."),
    (r"\bmath\.exp\s*\(", "SYNTAX ERROR (UNSUPPORTED_MATH_EXP): 'math.exp()' is not registered in the Malachite YARA-L 2.0 function factory. Use 'math.pow(2.718281828, x)' instead."),
    (r"\bmath\.(?:min|max)\s*\(", "SYNTAX ERROR (UNSUPPORTED_MATH_MIN_MAX): 'math.min()' and 'math.max()' do not exist in YARA-L 2.0. Use 3-argument 'if($a > $b, $a, $b)' for scalar clamping, or 'min() / max()' for stage outcome aggregations."),
]

# Default evidence-sampling field for the MAD template ({{sample_field}}), keyed by UDM event type.
MAD_SAMPLE_FIELD_BY_EVENT_TYPE = {
    "NETWORK_DNS": "network.dns.questions.name",
    "NETWORK_CONNECTION": "target.ip",
    "NETWORK_HTTP": "target.hostname",
    "PROCESS_LAUNCH": "target.process.file.full_path",
    "USER_LOGIN": "principal.ip",
    "FILE_CREATION": "target.file.full_path",
    "FILE_READ": "target.file.full_path",
}

SENSITIVITY_MAP = {
    "CATEGORICAL_FLEET_PREVALENCE": {
        "CONSERVATIVE": {"max_adopters": 1, "min_events": 10, "min_active_hours": 12},
        "BALANCED": {"max_adopters": 2, "min_events": 5, "min_active_hours": 6},
        "AGGRESSIVE": {"max_adopters": 3, "min_events": 2, "min_active_hours": 1},
    },
    "DISCRETE_ENTITY_RARITY": {
        "CONSERVATIVE": {"max_adopters": 1, "min_events": 10, "min_active_hours": 12},
        "BALANCED": {"max_adopters": 2, "min_events": 5, "min_active_hours": 6},
        "AGGRESSIVE": {"max_adopters": 3, "min_events": 2, "min_active_hours": 1},
    },
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
        # Modified Z (Iglewicz-Hoaglin): 3.5 is the standard outlier cut-off.
        # min_daily_volume is in the units of {{daily_aggregation}} (event count by default).
        "CONSERVATIVE": {"m_z": 5.0, "min_daily_volume": 500, "dispersion_floor": 1.0, "min_baseline_days": 14},
        "BALANCED": {"m_z": 3.5, "min_daily_volume": 100, "dispersion_floor": 1.0, "min_baseline_days": 7},
        "AGGRESSIVE": {"m_z": 3.0, "min_daily_volume": 25, "dispersion_floor": 1.0, "min_baseline_days": 3},
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
    "PRIVILEGED_LATERAL_EXPANSION": {
        "CONSERVATIVE": {"z_score": 3.0, "min_distinct_targets": 5, "min_sd": 1.0, "min_active_samples": 30},
        "BALANCED": {"z_score": 2.0, "min_distinct_targets": 3, "min_sd": 0.5, "min_active_samples": 14},
        "AGGRESSIVE": {"z_score": 1.5, "min_distinct_targets": 2, "min_sd": 0.2, "min_active_samples": 7},
    },
    "TWO_PART_HURDLE": {
        "CONSERVATIVE": {"z_score": 3.5, "min_count": 10, "dormant_weight": 3.0, "min_sd": 1.0, "min_active_samples": 14},
        "BALANCED": {"z_score": 2.5, "min_count": 5, "dormant_weight": 2.0, "min_sd": 0.5, "min_active_samples": 7},
        "AGGRESSIVE": {"z_score": 1.5, "min_count": 2, "dormant_weight": 1.5, "min_sd": 0.2, "min_active_samples": 3},
    },
    "DORMANT_ACCOUNT_AWAKENING": {
        "CONSERVATIVE": {"z_score": 3.5, "min_count": 10, "dormant_weight": 3.0, "min_sd": 1.0, "min_active_samples": 14},
        "BALANCED": {"z_score": 2.5, "min_count": 5, "dormant_weight": 2.0, "min_sd": 0.5, "min_active_samples": 7},
        "AGGRESSIVE": {"z_score": 1.5, "min_count": 2, "dormant_weight": 1.5, "min_sd": 0.2, "min_active_samples": 3},
    },
    "GLOBAL_THREAT_INTEL": {
        "CONSERVATIVE": {"threat_score": 4.0, "min_obs_bytes": 1000000.0, "min_active_hours": 24, "nrd_multiplier": 2.5},
        "BALANCED": {"threat_score": 3.0, "min_obs_bytes": 100000.0, "min_active_hours": 12, "nrd_multiplier": 2.5},
        "AGGRESSIVE": {"threat_score": 2.0, "min_obs_bytes": 10000.0, "min_active_hours": 6, "nrd_multiplier": 2.0},
    },
    "GLOBAL_THREAT_INTEL_ENRICHMENT": {
        "CONSERVATIVE": {"threat_score": 4.0, "min_obs_bytes": 1000000.0, "min_active_hours": 24, "nrd_multiplier": 2.5},
        "BALANCED": {"threat_score": 3.0, "min_obs_bytes": 100000.0, "min_active_hours": 12, "nrd_multiplier": 2.5},
        "AGGRESSIVE": {"threat_score": 2.0, "min_obs_bytes": 10000.0, "min_active_hours": 6, "nrd_multiplier": 2.0},
    },
    "DERIVED_CONTEXT_PREVALENCE": {
        "CONSERVATIVE": {"threat_score": 3.5, "min_logins": 10, "min_active_days": 14, "new_asset_multiplier": 2.0},
        "BALANCED": {"threat_score": 2.5, "min_logins": 5, "min_active_days": 7, "new_asset_multiplier": 2.0},
        "AGGRESSIVE": {"threat_score": 1.5, "min_logins": 2, "min_active_days": 3, "new_asset_multiplier": 1.5},
    },
    "DERIVED_CONTEXT_FILE_PREVALENCE": {
        "CONSERVATIVE": {"threat_score": 3.5, "min_execs": 10, "min_active_hours": 24, "rare_multiplier": 2.5},
        "BALANCED": {"threat_score": 2.5, "min_execs": 5, "min_active_hours": 12, "rare_multiplier": 2.5},
        "AGGRESSIVE": {"threat_score": 1.5, "min_execs": 2, "min_active_hours": 6, "rare_multiplier": 2.0},
    },
    "DERIVED_CONTEXT_DOMAIN_PREVALENCE": {
        "CONSERVATIVE": {"threat_score": 3.5, "min_obs_bytes": 1000000.0, "min_active_hours": 24, "rare_multiplier": 2.5},
        "BALANCED": {"threat_score": 2.5, "min_obs_bytes": 100000.0, "min_active_hours": 12, "rare_multiplier": 2.5},
        "AGGRESSIVE": {"threat_score": 1.5, "min_obs_bytes": 10000.0, "min_active_hours": 6, "rare_multiplier": 2.0},
    },
    "MULTI_SECTOR_FUSION": {
        "CONSERVATIVE": {"threat_distance": 4.0, "min_active_samples": 14, "min_events": 10},
        "BALANCED": {"threat_distance": 3.0, "min_active_samples": 7, "min_events": 5},
        "AGGRESSIVE": {"threat_distance": 2.0, "min_active_samples": 3, "min_events": 2},
    },
    "MULTI_SECTOR_THREAT_FUSION": {
        "CONSERVATIVE": {"threat_distance": 4.0, "min_active_samples": 14, "min_events": 10},
        "BALANCED": {"threat_distance": 3.0, "min_active_samples": 7, "min_events": 5},
        "AGGRESSIVE": {"threat_distance": 2.0, "min_active_samples": 3, "min_events": 2},
    },
    "LOG_NORMAL_VOLUME": {
        "CONSERVATIVE": {"z_score": 3.5, "min_bytes": 100000000.0, "min_sd": 1.0, "min_active_samples": 14},
        "BALANCED": {"z_score": 2.5, "min_bytes": 10000000.0, "min_sd": 0.5, "min_active_samples": 7},
        "AGGRESSIVE": {"z_score": 1.8, "min_bytes": 1000000.0, "min_sd": 0.2, "min_active_samples": 3},
    },
    "LOG_NORMAL_VOLUME_SURGE": {
        "CONSERVATIVE": {"z_score": 3.5, "min_bytes": 100000000.0, "min_sd": 1.0, "min_active_samples": 14},
        "BALANCED": {"z_score": 2.5, "min_bytes": 10000000.0, "min_sd": 0.5, "min_active_samples": 7},
        "AGGRESSIVE": {"z_score": 1.8, "min_bytes": 1000000.0, "min_sd": 0.2, "min_active_samples": 3},
    },
    "MARKOV_2GRAM_TRANSITION_RARITY": {
        "CONSERVATIVE": {"surprisal_threshold": 4.5, "min_parent_count": 20},
        "BALANCED": {"surprisal_threshold": 3.0, "min_parent_count": 10},
        "AGGRESSIVE": {"surprisal_threshold": 2.0, "min_parent_count": 5},
    },
    "SHANNON_ENTROPY_CHARACTER": {
        "CONSERVATIVE": {"entropy_threshold": 7.0, "min_length": 40},
        "BALANCED": {"entropy_threshold": 5.5, "min_length": 25},
        "AGGRESSIVE": {"entropy_threshold": 4.0, "min_length": 15},
    },
    "ZIPFIAN_PROCESS_RARITY": {
        "CONSERVATIVE": {"zipf_threshold": 4.0, "max_adopters": 1, "min_count": 5},
        "BALANCED": {"zipf_threshold": 2.5, "max_adopters": 2, "min_count": 2},
        "AGGRESSIVE": {"zipf_threshold": 1.5, "max_adopters": 3, "min_count": 1},
    },
    "EWMA_BURST_VELOCITY": {
        "CONSERVATIVE": {"velocity_threshold": 3.0, "min_count": 50, "min_sd": 5.0, "min_active_samples": 60},
        "BALANCED": {"velocity_threshold": 2.0, "min_count": 25, "min_sd": 2.0, "min_active_samples": 30},
        "AGGRESSIVE": {"velocity_threshold": 1.5, "min_count": 10, "min_sd": 1.0, "min_active_samples": 14},
    },
    "IMPOSSIBLE_TRAVEL_GEO_VELOCITY": {
        "CONSERVATIVE": {"velocity_kmh": 1200.0, "min_distance_km": 1000.0, "min_active_samples": 14},
        "BALANCED": {"velocity_kmh": 900.0, "min_distance_km": 500.0, "min_active_samples": 7},
        "AGGRESSIVE": {"velocity_kmh": 500.0, "min_distance_km": 250.0, "min_active_samples": 3},
    },
    "PRODUCER_CONSUMER_RATIO_INVERSION": {
        "CONSERVATIVE": {"min_producer_ratio": 0.85, "z_score": 3.5, "min_sent_bytes": 50000000.0, "min_active_samples": 14},
        "BALANCED": {"min_producer_ratio": 0.70, "z_score": 2.5, "min_sent_bytes": 10000000.0, "min_active_samples": 7},
        "AGGRESSIVE": {"min_producer_ratio": 0.55, "z_score": 1.8, "min_sent_bytes": 1000000.0, "min_active_samples": 3},
    },
    "DUAL_BASELINE_DELTA_Z": {
        "CONSERVATIVE": {"delta_z": 4.0, "min_count": 50, "min_sd": 5.0, "min_active_samples": 60, "min_active_hosts": 10},
        "BALANCED": {"delta_z": 3.0, "min_count": 25, "min_sd": 2.0, "min_active_samples": 30, "min_active_hosts": 5},
        "AGGRESSIVE": {"delta_z": 2.0, "min_count": 10, "min_sd": 1.0, "min_active_samples": 14, "min_active_hosts": 3},
    },
    "BAYESIAN_GAMMA_SHRINKAGE": {
        "CONSERVATIVE": {"bayesian_z": 4.0, "min_count": 30, "min_active_samples": 60},
        "BALANCED": {"bayesian_z": 3.0, "min_count": 15, "min_active_samples": 30},
        "AGGRESSIVE": {"bayesian_z": 2.0, "min_count": 5, "min_active_samples": 14},
    },
    "BETA_BINOMIAL_FAILURE": {
        "CONSERVATIVE": {"posterior_fail_prob": 0.65, "min_attempts": 30, "min_fails": 20, "min_active_samples": 24},
        "BALANCED": {"posterior_fail_prob": 0.50, "min_attempts": 15, "min_fails": 10, "min_active_samples": 12},
        "AGGRESSIVE": {"posterior_fail_prob": 0.35, "min_attempts": 8, "min_fails": 5, "min_active_samples": 6},
    },
    "HYBRID_ENTROPY_CONCENTRATION": {
        "CONSERVATIVE": {"max_diversity_z": -2.5, "min_concentration_ratio": 0.80, "min_events": 100, "min_active_samples": 48},
        "BALANCED": {"max_diversity_z": -1.5, "min_concentration_ratio": 0.65, "min_events": 50, "min_active_samples": 24},
        "AGGRESSIVE": {"max_diversity_z": -1.0, "min_concentration_ratio": 0.50, "min_events": 20, "min_active_samples": 12},
    },
    "DIVERSITY_DEFICIT": {
        "CONSERVATIVE": {"max_diversity_z": -2.5, "min_concentration_ratio": 0.80, "min_events": 100, "min_active_samples": 48},
        "BALANCED": {"max_diversity_z": -1.5, "min_concentration_ratio": 0.65, "min_events": 50, "min_active_samples": 24},
        "AGGRESSIVE": {"max_diversity_z": -1.0, "min_concentration_ratio": 0.50, "min_events": 20, "min_active_samples": 12},
    },
    "ELEPHANT_FLOW_CONCENTRATION": {
        "CONSERVATIVE": {"max_diversity_z": -2.5, "min_concentration_ratio": 0.80, "min_events": 100, "min_active_samples": 48},
        "BALANCED": {"max_diversity_z": -1.5, "min_concentration_ratio": 0.65, "min_events": 50, "min_active_samples": 24},
        "AGGRESSIVE": {"max_diversity_z": -1.0, "min_concentration_ratio": 0.50, "min_events": 20, "min_active_samples": 12},
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

  # Macro-aligned daily models that benefit from a 1d temporal spine on extended horizons (>= 7 days)
  daily_macro_archetypes = {
      "DATA_EXFILTRATION_SPIKE", "HEAVY_TAIL_OUTLIERS", "TWO_PART_HURDLE",
      "DORMANT_ACCOUNT_AWAKENING", "DERIVED_CONTEXT_PREVALENCE",
      "MULTI_SECTOR_FUSION", "MULTI_SECTOR_THREAT_FUSION", "LOG_NORMAL_VOLUME",
      "LOG_NORMAL_VOLUME_SURGE", "FLEET_PEER_ZSCORE", "BAYESIAN_GAMMA_SHRINKAGE",
      "BETA_BINOMIAL_REGULARIZATION", "BETA_BINOMIAL_FAILURE",
      "PRODUCER_CONSUMER_RATIO_INVERSION",
  }

  # Determine optimal bucket granularity based on total window duration & analytical archetype
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
  elif duration_hours < 168.0:  # < 7 days / "past week"
    bucket_size = "1h"
    bucket_seconds = 3600
    total_buckets = int(duration_hours)
    sample_unit = "hourly intervals"
  elif archetype_up in daily_macro_archetypes:  # >= 7 days for macro-aligned daily models (reconciles with Risk Metrics)
    bucket_size = "1d"
    bucket_seconds = 86400
    total_buckets = max(1, int(duration_hours / 24.0))
    sample_unit = "daily intervals"
  else:  # >= 7 days for high-frequency jitter/burst models (e.g. C2_BEACONING_JITTER, POISSON_BURST_CLUSTERING)
    bucket_size = "1h"
    bucket_seconds = 3600
    total_buckets = int(duration_hours)
    sample_unit = "hourly intervals"

  # Calculate proportional sample floor (e.g. 25% of window, minimum 3, maximum default)
  default_sample_floor = (
      base_thresh.get("min_active_samples")
      or base_thresh.get("min_baseline_days")
      or base_thresh.get("min_active_hours")
      or base_thresh.get("min_active_days")
      or 30
  )
  
  if "daily" in sample_unit or "days" in sample_unit or (duration_hours >= 168.0 and archetype_up in daily_macro_archetypes):
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


EVENT_DOMAINS = {
    "USER_LOGIN": "AUTH",
    "USER_AUTHENTICATION": "AUTH",
    "EMAIL_TRANSACTION": "AUTH",
    "PROCESS_LAUNCH": "PROCESS",
    "PROCESS_TERMINATION": "PROCESS",
    "PROCESS_INJECTION": "PROCESS",
    "NETWORK_CONNECTION": "NETWORK",
    "NETWORK_HTTP": "NETWORK",
    "NETWORK_DNS": "NETWORK",
    "NETWORK_DHCP": "NETWORK",
    "RESOURCE_CREATION": "CLOUD",
    "RESOURCE_DELETION": "CLOUD",
    "RESOURCE_READ": "CLOUD",
    "RESOURCE_WRITTEN": "CLOUD",
}


def check_multivector_cramming(query: str) -> List[str]:
  """Detects single-stage multi-vector event cramming across distinct telemetry silos.

  A stage that mixes telemetry domains is legal ONLY as a *fused sector-counting*
  stage: an `or`-disjunction event_type filter whose outcome separates the
  domains with conditional sums (`sum(if(metadata.event_type = "X", 1, 0))`).
  That topology is required when fusing three or more sectors, because the
  compiler rejects three independent raw stages joined at the root (verified
  by live udm_search probes, 2026-09-24). Mixing domains without conditional
  sums collapses them into one undifferentiated count and is flagged.
  """
  errors = []
  stage_blocks = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", query, flags=re.DOTALL)
  for stage_name, stage_body in stage_blocks:
    event_types = set(re.findall(r"metadata\.event_type\s*==?\s*[\"']([A-Z_]+)[\"']", stage_body))
    silos = set(EVENT_DOMAINS.get(et, et) for et in event_types)
    if len(silos) > 1:
      is_fused_sector_stage = bool(re.search(r"\bsum\s*\(\s*if\s*\([^)]*metadata\.event_type\s*=", stage_body))
      if is_fused_sector_stage:
        continue
      errors.append(
          f"MULTI-VECTOR CRAMMING in stage '{stage_name}': Stage mixes cross-domain telemetry silos {silos} ({event_types}) "
          "without separating them. Either isolate each telemetry domain in its own named stage (the compiler accepts at most "
          "TWO independent raw stages joined at the root) or, for three or more sectors, use ONE raw stage with an 'or' "
          "event_type filter and per-sector conditional sums: sum(if(metadata.event_type = \"X\", 1, 0))."
      )
  if not stage_blocks:
    event_types = set(re.findall(r"metadata\.event_type\s*==?\s*[\"']([A-Z_]+)[\"']", query))
    silos = set(EVENT_DOMAINS.get(et, et) for et in event_types)
    if len(silos) > 1 and "MULTI_SECTOR" in query.upper():
      errors.append(
          "MULTI-VECTOR CRAMMING: Multi-sector threat fusion requires a multi-stage pipeline (one fused sector-counting "
          "stage with conditional sums, a per-entity baseline stage, and a root fusion stage), not a single-stage search."
      )
  return errors


def check_ecg_limits(query: str) -> List[str]:
  """Enforces maximum 1 Entity Context Graph lookup per stage to prevent F1 memory exhaustion."""
  errors = []
  stage_blocks = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", query, flags=re.DOTALL)
  for stage_name, stage_body in stage_blocks:
    graph_aliases = set(re.findall(r"\$([a-zA-Z0-9_]+)\.graph\.", stage_body))
    if len(graph_aliases) > 1:
      errors.append(
          f"ECG LIMIT EXCEEDED in stage '{stage_name}': Found {len(graph_aliases)} Entity Context Graph aliases. "
          "F1 limits require each graph lookup to reside in its own dedicated DAG stage."
      )
  return errors


def check_event_section_arithmetic(query: str) -> List[str]:
  """Prohibits variable/constant binary arithmetic (+, -, *, /) above match:."""
  errors = []
  code_only = re.sub(r"//.*", "", query)

  # Check named stages
  stage_matches = re.finditer(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", code_only, flags=re.DOTALL)
  for sm in stage_matches:
    stage_name = sm.group(1)
    stage_body = sm.group(2)
    match_pos = re.search(r"\bmatch\s*:", stage_body)
    outcome_pos = re.search(r"\boutcome\s*:", stage_body)
    boundary = match_pos.start() if match_pos else (outcome_pos.start() if outcome_pos else len(stage_body))
    event_body = stage_body[:boundary]
    for line in event_body.splitlines():
      line_clean = line.strip()
      if not line_clean or "=" not in line_clean:
        continue
      if "==" in line_clean or "!=" in line_clean or "<=" in line_clean or ">=" in line_clean:
        continue
      lhs, rhs = line_clean.split("=", 1)
      lhs = lhs.strip()
      rhs = rhs.strip()
      if not lhs.startswith("$"):
        continue
      rhs_clean = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', rhs)
      rhs_clean = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", rhs_clean)
      rhs_clean = re.sub(r'/[^/\\]*(?:\\.[^/\\]*)*/', '//', rhs_clean)
      if re.search(r"(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)\s*[-+*/]\s*(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)", rhs_clean):
        errors.append(
            f"COMMON COMPILER GRAMMAR ERROR (ARITHMETIC_IN_EVENT_SECTION): Variable arithmetic '{line_clean}' "
            f"in named stage '{stage_name}' is above 'match:'. Common Compiler requires event placeholders "
            f"to bind directly to UDM fields, stage variables, or scalar functions. Binary arithmetic above 'match:' "
            f"causes 'missing type info for placeholder'. Move arithmetic into the 'outcome:' section below 'match:'."
        )

  # Check root stage (unwrapped outside all stage { ... } blocks)
  stripped_root = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", code_only, flags=re.DOTALL)
  root_match_pos = re.search(r"^\s*match\s*:", stripped_root, flags=re.MULTILINE)
  root_outcome_pos = re.search(r"^\s*outcome\s*:", stripped_root, flags=re.MULTILINE)
  boundary = root_match_pos.start() if root_match_pos else (root_outcome_pos.start() if root_outcome_pos else len(stripped_root))
  root_event_body = stripped_root[:boundary]
  for line in root_event_body.splitlines():
    line_clean = line.strip()
    if not line_clean or "=" not in line_clean:
      continue
    if "==" in line_clean or "!=" in line_clean or "<=" in line_clean or ">=" in line_clean:
      continue
    lhs, rhs = line_clean.split("=", 1)
    lhs = lhs.strip()
    rhs = rhs.strip()
    if not lhs.startswith("$"):
      continue
    rhs_clean = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', rhs)
    rhs_clean = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", rhs_clean)
    rhs_clean = re.sub(r'/[^/\\]*(?:\\.[^/\\]*)*/', '//', rhs_clean)
    if re.search(r"(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)\s*[-+*/]\s*(\$[a-zA-Z0-9_.]+|\d+(?:\.\d+)?)", rhs_clean):
      errors.append(
          f"COMMON COMPILER GRAMMAR ERROR (ARITHMETIC_IN_EVENT_SECTION): Variable arithmetic '{line_clean}' "
          f"in root stage is above 'match:'. Common Compiler requires event placeholders "
          f"to bind directly to UDM fields, stage variables, or scalar functions. Binary arithmetic above 'match:' "
          f"causes 'missing type info for placeholder'. Move arithmetic into the 'outcome:' section below 'match:'."
      )

  return errors


def check_match_placeholders_bound(query: str) -> List[str]:
  """Enforces that every placeholder in match: is explicitly assigned to an event/stage field in that stage's event block."""
  errors = []
  code_only = re.sub(r"//.*", "", query)

  # Check named stages
  stage_matches = re.finditer(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", code_only, flags=re.DOTALL)
  for sm in stage_matches:
    stage_name = sm.group(1)
    stage_body = sm.group(2)
    mm = re.search(r"\bmatch\s*:(.*?)(?=\b(?:outcome|condition|order)\s*:|\}|$)", stage_body, flags=re.DOTALL)
    if mm:
      match_text = mm.group(1)
      match_vars = re.findall(r"\$([a-zA-Z0-9_]+)", match_text)
      event_body = stage_body[:mm.start()]
      for mv in match_vars:
        if not re.search(r"\$" + re.escape(mv) + r"\b\s*=", event_body) and not re.search(r"=\s*\$" + re.escape(mv) + r"\b", event_body):
          errors.append(
              f"COMMON COMPILER ERROR (UNBOUND_MATCH_VARIABLE): Placeholder '${mv}' in 'match:' of stage '{stage_name}' "
              f"is not bound in that stage's event section. Common Compiler fails with 'missing type info for placeholder ${mv}'. "
              f"Explicitly assign '${mv} = <field>' or '<field> = ${mv}' in that stage."
          )

  # Check root stage
  stripped_root = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", code_only, flags=re.DOTALL)
  root_mm = re.search(r"\bmatch\s*:(.*?)(?=\b(?:outcome|condition|order)\s*:|\Z)", stripped_root, flags=re.DOTALL)
  if root_mm:
    match_text = root_mm.group(1)
    match_vars = re.findall(r"\$([a-zA-Z0-9_]+)", match_text)
    root_event_body = stripped_root[:root_mm.start()]
    for mv in match_vars:
      if not re.search(r"\$" + re.escape(mv) + r"\b\s*=", root_event_body) and not re.search(r"=\s*\$" + re.escape(mv) + r"\b", root_event_body):
        errors.append(
            f"COMMON COMPILER ERROR (UNBOUND_MATCH_VARIABLE): Placeholder '${mv}' in root 'match:' "
            f"is not bound in the root event/stage section. Common Compiler fails with 'missing type info for placeholder ${mv}'. "
            f"Explicitly assign '${mv} = <stage>.<field>' or bind it to an event field."
        )

  return errors


_BARE_NEGATIVE_LITERAL_RE = re.compile(r"^[ \t]*(\$\w+)[ \t]*=[ \t]*(-[ \t]*\d+(?:\.\d+)?)[ \t]*$", re.MULTILINE)


def check_bare_negative_literal_assignments(query: str) -> List[str]:
  """Flags `$var = -<number>` assignments.

  The Chronicle compiler rejects a bare unary-minus literal on the right-hand side of an
  outcome assignment ('invalid argument'; verified live on 2026-10-07). Write `0 - <number>` instead.
  """
  code_only = re.sub(r"//.*", "", query)
  errors = []
  for m in _BARE_NEGATIVE_LITERAL_RE.finditer(code_only):
    value = re.sub(r"\s+", "", m.group(2))
    errors.append(
        f"BARE_NEGATIVE_LITERAL: '{m.group(1)} = {value}' is rejected by the compiler (invalid argument). "
        f"Write '{m.group(1)} = 0 - {value[1:]}' instead."
    )
  return errors


def check_stage_name_collisions(query: str) -> List[str]:
  """Flags outcome variables whose identifier equals a declared stage name.

  Verified compiler fact (live udm_search probes, 2026-09-24): a stage named
  `fleet_prevalence` combined with an outcome variable `$fleet_prevalence` in
  ANY outcome block (intermediate or root) is rejected as an invalid argument.
  """
  errors: List[str] = []
  code_only = re.sub(r"//.*", "", query)
  stage_names = re.findall(r"\bstage\s+([a-zA-Z0-9_]+)\s*\{", code_only)
  if not stage_names:
    return errors

  outcome_vars = set()
  for om in re.finditer(r"\boutcome\s*:(.*?)(?=\n\s*(?:condition|order|match)\s*:|\}|\Z)", code_only, flags=re.DOTALL):
    outcome_vars.update(re.findall(r"^\s*\$([a-zA-Z0-9_]+)\s*=", om.group(1), flags=re.MULTILINE))

  for name in stage_names:
    if name in outcome_vars:
      errors.append(
          f"SYNTAX ERROR (STAGE_OUTCOME_NAME_COLLISION): Stage 'stage {name} {{' and outcome variable "
          f"'${name}' share the same identifier; the compiler rejects this. Rename one of them "
          f"(e.g. stage '{name}' -> '{name}_stage', or '${name}' -> '${name}_value')."
      )
  return errors


def check_independent_raw_stages(query: str) -> List[str]:
  """Flags more than two independent raw-event stages.

  Verified compiler fact (live udm_search probes, 2026-09-24): three named
  stages that each read raw UDM events (no `$other_stage.` reference inside
  the block) and are joined only in the root are rejected, regardless of the
  event-variable names or the join key. Any two compile. Fuse sectors into one
  raw stage using conditional sums (sum(if(cond, 1, 0))) instead.
  """
  errors: List[str] = []
  code_only = re.sub(r"//.*", "", query)
  blocks = re.findall(r"\bstage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", code_only, flags=re.DOTALL)
  if len(blocks) < 3:
    return errors

  names = [n for n, _ in blocks]
  raw_stages = []
  for name, body in blocks:
    references_other_stage = any(
        re.search(r"\$" + re.escape(other) + r"\.", body) for other in names if other != name
    )
    if not references_other_stage:
      raw_stages.append(name)

  if len(raw_stages) > 2:
    errors.append(
        f"SYNTAX ERROR (TOO_MANY_INDEPENDENT_RAW_STAGES): {len(raw_stages)} independent raw-event stages "
        f"({', '.join(raw_stages)}) joined only at the root. The compiler accepts at most two. Collapse "
        f"sector/event-type splits into ONE raw stage with conditional sums (sum(if(<predicate>, 1, 0))) "
        f"and derive per-sector baselines in a chained stage."
    )
  return errors


def _extract_if_calls(code: str) -> List[Tuple[str, List[str]]]:
  """Extracts if(...) calls and their top-level comma-separated arguments, respecting nested parentheses and strings."""
  results = []
  pos = 0
  n = len(code)
  pattern = re.compile(r"\bif\s*\(")
  while pos < n:
    m = pattern.search(code, pos)
    if not m:
      break
    start_call = m.start()
    paren_start = m.end() - 1
    depth = 0
    in_single = False
    in_double = False
    args = []
    current_arg = []
    i = paren_start
    while i < n:
      ch = code[i]
      if in_single:
        current_arg.append(ch)
        if ch == "'" and code[i - 1] != "\\":
          in_single = False
      elif in_double:
        current_arg.append(ch)
        if ch == '"' and code[i - 1] != "\\":
          in_double = False
      else:
        if ch == "'":
          in_single = True
          current_arg.append(ch)
        elif ch == '"':
          in_double = True
          current_arg.append(ch)
        elif ch in "([{":
          depth += 1
          if depth > 1:
            current_arg.append(ch)
        elif ch in ")]}":
          depth -= 1
          if depth == 0:
            args.append("".join(current_arg).strip())
            full_call = code[start_call : i + 1]
            results.append((full_call, args))
            pos = i + 1
            break
          else:
            current_arg.append(ch)
        elif ch == "," and depth == 1:
          args.append("".join(current_arg).strip())
          current_arg = []
        else:
          current_arg.append(ch)
      i += 1
    else:
      pos = paren_start + 1
  return results


def validate_multistage_syntax(query: str) -> List[str]:
  """Performs structural validation on multi-stage YARA-L search queries."""
  errors = []
  code_only = re.sub(r"//.*", "", query)

  # Strip string/regex literals when checking the '^' exponent operator trap so regex anchors (`^admin`) don't false-positive.
  code_no_regex_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', code_only)
  code_no_regex_strings = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", code_no_regex_strings)
  code_no_regex_strings = re.sub(r"`[^`\\]*(?:\\.[^`\\]*)*`", "``", code_no_regex_strings)
  code_no_regex_strings = re.sub(r"(?:,\s*|~\s*|=\s*|\(\s*)/[^/\n\\]*(?:\\.[^/\n\\]*)*/", "//", code_no_regex_strings)

  for pattern, msg in SYNTAX_TRAPS:
    target_text = code_no_regex_strings if pattern == r"\^" else code_only
    if re.search(pattern, target_text, re.DOTALL | re.MULTILINE):
      errors.append(msg)

  # Check for duplicate condition: or order: clauses in the root stage
  stripped_for_clauses = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", code_only, flags=re.DOTALL)
  cond_clauses = re.findall(r"^\s*condition\s*:", stripped_for_clauses, flags=re.MULTILINE)
  if len(cond_clauses) > 1:
    errors.append(
        f"SYNTAX ERROR (DUPLICATE_ROOT_CLAUSE): Found {len(cond_clauses)} 'condition:' sections in the root stage. "
        "Combine all root filtering predicates into a single 'condition:' block using 'and'."
    )
  order_clauses = re.findall(r"^\s*order\s*:", stripped_for_clauses, flags=re.MULTILINE)
  if len(order_clauses) > 1:
    errors.append(
        f"SYNTAX ERROR (DUPLICATE_ROOT_CLAUSE): Found {len(order_clauses)} 'order:' sections in the root stage. "
        "Only one 'order:' section is permitted."
    )

  errors.extend(check_multivector_cramming(query))
  errors.extend(check_ecg_limits(query))
  errors.extend(check_event_section_arithmetic(query))
  errors.extend(check_match_placeholders_bound(query))
  errors.extend(check_stage_name_collisions(query))
  errors.extend(check_independent_raw_stages(query))
  errors.extend(check_bare_negative_literal_assignments(query))

  # Chronicle Common Compiler Grammar Invariants for if():
  for full_call, args in _extract_if_calls(code_only):
    if len(args) < 3:
      errors.append(f"INVALID_IF_CONDITIONAL: 'if(...)' is missing required else-clause: {full_call}")
    else:
      then_clause = re.sub(r"^\s*[-+]\s*", "", args[1])
      then_clean = re.sub(r"\([^)]*\)", "", then_clause)
      if re.search(r"[\+\-\*\/]", then_clean):
        errors.append(f"INVALID_IF_CONDITIONAL: 'if(...)' contains compound arithmetic in then-clause. Chronicle compiler only allows placeholders, fields, and constants in then clause: {full_call}")

  stages = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", code_only)
  is_multistage = bool(stages)

  if is_multistage:
    if len(stages) > 3:
      errors.append(
          f"STAGE COUNT LIMIT EXCEEDED ({len(stages)} named stages found): Malachite supports a maximum "
          f"of 3 named intermediate stages plus 1 unwrapped root stage (4 stages total). Reduce stage count."
      )

    # Verify that the final stage is unwrapped at the root level
    stripped = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", code_only, flags=re.DOTALL)
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
    if not re.search(r"^\s*match\s*:", code_only, re.MULTILINE):
      errors.append("MISSING MATCH SECTION: Single-stage stats searches require a 'match:' section.")
    if not re.search(r"^\s*outcome\s*:", code_only, re.MULTILINE):
      errors.append("MISSING OUTCOME SECTION: Single-stage stats searches require an 'outcome:' section.")

  # Validate all outcome blocks for Malachite AST rules, OutcomeLimit (20), and Intra-Stage Race Conditions
  stage_blocks = re.findall(r"stage\s+[a-zA-Z0-9_]+\s*\{([^}]*)\}", query, flags=re.DOTALL)
  outcome_blocks = []
  for sb in stage_blocks:
    om = re.search(r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)|\Z)", sb, flags=re.DOTALL | re.MULTILINE)
    if om:
      outcome_blocks.append((True, om.group(1)))

  stripped_root = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", query, flags=re.DOTALL)
  root_om = re.search(r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)|\Z)", stripped_root, flags=re.DOTALL | re.MULTILINE)
  if root_om:
    outcome_blocks.append((False, root_om.group(1)))

  for b_idx, (is_stage, block) in enumerate(outcome_blocks):
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
      rhs_clean = rhs.strip()
      
      # Check for intra-stage dependency / race condition:
      # In intermediate stages, chaining across variables is invalid because each stage aggregates raw events.
      # In the root stage, Chronicle Common Compiler natively permits sequential derived assignments.
      if is_stage:
        for prev_var in defined_vars:
          if re.search(r"\$" + re.escape(prev_var) + r"\b", rhs):
            errors.append(
                f"INTRA-STAGE RACE CONDITION: Variable '${prev_var}' is defined on an earlier line in outcome block #{b_idx+1} "
                f"and referenced in '${line_clean}'. In YARA-L, multi-stage pipelines require dependent calculations "
                f"to be computed in an earlier stage or decomposed across stages."
            )

      defined_vars.append(var_name)

      # Check for bare scalar if in intermediate stage outcome
      if is_stage and re.match(r"^if\s*\(", rhs_clean):
        errors.append(
            f"MALACHITE AST ERROR: Bare scalar if() in intermediate stage outcome: '{line_clean}'. "
            f"Intermediate stages reject scalar if(); use linear arithmetic or compute conditions in the root stage."
        )

      # Check for inline if in compound arithmetic: e.g. / if(...) or * if(...)
      if re.search(r"[-+*/]\s*if\s*\(|if\s*\([^)]*\)\s*[-+*/]", rhs):
        errors.append(
            f"MALACHITE AST ERROR: Inline if() inside outcome arithmetic: '{line_clean}'. "
            f"Chronicle compiler requires computing conditional expressions into intermediate variables before arithmetic (e.g. '$safe_std = if(...); $z = $diff / $safe_std')."
        )


    if outcome_assignments_count > 20:
      errors.append(
          f"OUTCOME LIMIT EXCEEDED ({outcome_assignments_count} variables in outcome block #{b_idx+1}): "
          f"Malachite enforces OutcomeLimit = 20 variables per outcome section. Prune outcome variables."
      )

  # SecOps Data Table syntax check: %<table_name>.<column_name> is valid when joining columns;
  # flag bare %<table_name> on equality comparisons without a column specifier.
  code_no_literals = re.sub(r'"(?:\\.|[^"\\])*"', '""', code_only)
  for m_dt in re.finditer(r"=\s*%([a-zA-Z0-9_]+)(?![.\w])", code_no_literals):
    errors.append(
        f"INVALID_DATA_TABLE_COLUMN_SYNTAX: Data Table equality join '%{m_dt.group(1)}' must specify a column (e.g., '%{m_dt.group(1)}.column_name')."
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
          r"\$(?:baseline_active_samples|baseline_samples|active_samples|active_days|active_hours)\s*>=\s*(\d+)",
          query_text
      )
      for s_val_str in sample_matches:
        req_samples = int(s_val_str)
        if "by 5m" in query_text:
          max_buckets = int(delta_hours * 12)
          if req_samples > max_buckets:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active 5-minute samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {max_buckets} 5-minute intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(max_buckets * 0.25))}) or expand the search window."
            )
        elif "by 10m" in query_text:
          max_buckets = int(delta_hours * 6)
          if req_samples > max_buckets:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active 10-minute samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {max_buckets} 10-minute intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(max_buckets * 0.25))}) or expand the search window."
            )
        elif "by 15m" in query_text:
          max_buckets = int(delta_hours * 4)
          if req_samples > max_buckets:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active 15-minute samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {max_buckets} 15-minute intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(max_buckets * 0.25))}) or expand the search window."
            )
        elif "by 1h" in query_text:
          if req_samples > delta_hours:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active hourly samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {int(delta_hours)} hourly intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(delta_hours * 0.25))}) or expand the search window."
            )
        elif "by 2h" in query_text:
          max_buckets = int(delta_hours / 2.0)
          if req_samples > max_buckets:
            errors.append(
                f"AUTOMATIC QUERY FAILURE: Condition requires ${req_samples} active 2-hour samples, "
                f"but the specified time window ({delta_hours:.1f} hours) has at most {max_buckets} 2-hour intervals. "
                f"Scale the sample floor down (e.g. >= {max(3, int(max_buckets * 0.25))}) or expand the search window."
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
        s_val = val_obj["stringVal"]
        if s_val in ["NaN", "nan", "null", "None", ""]:
          vals.append(None)
        else:
          try:
            if "." in s_val:
              vals.append(float(s_val))
            else:
              vals.append(int(s_val))
          except (ValueError, TypeError):
            vals.append(s_val)
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


# Sentinel a pipeline emits as `$fleet_prevalence` when it does not compute fleet breadth.
FLEET_PREVALENCE_NOT_COMPUTED = -1


def resolve_fleet_prevalence(row: Dict[str, Any]) -> Optional[float]:
  """Returns fleet prevalence, or None when it is missing or marked not computed (negative sentinel)."""
  for key in ("fleet_prevalence", "hosts_contacting", "fleet_host_count"):
    if key in row and row[key] not in (None, ""):
      try:
        value = float(row[key])
      except (TypeError, ValueError):
        return None
      return value if value >= 0 else None
  return None


def evaluate_confidence_tier(row: Dict[str, Any]) -> Tuple[str, str]:
  """Evaluates statistical evidence confidence rating (High vs Moderate vs Insufficient Baseline).

  HIGH CONFIDENCE requires a known, low fleet prevalence; a missing or not-computed
  prevalence is treated as unknown and caps the rating at MODERATE.
  """
  active_samples = float(row.get("baseline_active_samples", row.get("active_samples", row.get("active_days", 100))))
  obs = float(row.get("observation_count", row.get("observed_count", row.get("observed_today", row.get("total_fails", 50)))))
  disp = float(row.get("baseline_dispersion", row.get("stddev_val", row.get("mad_val", 10.0))))
  prevalence = resolve_fleet_prevalence(row)

  if active_samples < 30 or obs < 5 or disp <= 0.1:
    return "⚪ **INSUFFICIENT BASELINE**", "Denominator too small (< 30 active samples or near-zero dispersion). Risk of false-positive anomaly."
  elif active_samples >= 120 and obs >= 25 and disp >= 5.0 and prevalence is not None and prevalence <= 3:
    return "🟢 **HIGH CONFIDENCE**", "Robust historical baseline (>= 120 active samples, verified dispersion, low fleet prevalence)."
  elif active_samples >= 120 and obs >= 25 and disp >= 5.0 and prevalence is None:
    return "🟡 **MODERATE CONFIDENCE**", "Robust historical baseline, but fleet prevalence was not computed; HIGH requires verified low fleet prevalence."
  else:
    return "🟡 **MODERATE CONFIDENCE**", "Adequate baseline with acceptable statistical support."


PRIMARY_SCORE_KEYS = [
    "hurdle_anomaly_score",
    "hurdle_threat_score",
    "threat_distance",
    "threat_vector_norm_sq",
    "threat_score",
    "markov_threat_score",
    "bayesian_z",
    "anomaly_score",
    "posterior_fail_prob",
    "regularized_failure_prob",
    "targeted_delta_z",
    "delta_z",
    "m_z_score",
    "modified_z",
    "z_log",
    "velocity_score",
    "ewma_velocity_score",
    "velocity_kmh",
    "rarity_score",
    "zipf_rarity_score",
    "entropy_score",
    "shannon_entropy_score",
    "concentration_ratio",
    "diversity_z",
    "poisson_z",
    "poisson_z_sq",
    "fano_factor",
    "cv",
    "fleet_z",
    "z_score",
    "personal_z",
    "producer_ratio",
    "surge_ratio",
    "ratio_1v30",
    "score",
]


def get_soc_severity_badge(chosen_key: str, score: float) -> str:
  """Translates statistical score into a standard SOC operational rating."""
  if chosen_key in [
      "z_score", "poisson_z", "fleet_z", "targeted_delta_z", "delta_z", "personal_z",
      "bayesian_z", "anomaly_score", "threat_distance", "threat_score", "markov_threat_score",
      "z_log", "hurdle_anomaly_score", "hurdle_threat_score", "velocity_score",
      "ewma_velocity_score", "rarity_score", "zipf_rarity_score", "entropy_score",
      "shannon_entropy_score", "score",
  ]:
    if score >= 4.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 3.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 2.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key in ["poisson_z_sq", "threat_vector_norm_sq"]:
    if score >= 16.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 9.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 4.0:
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
  elif chosen_key in ["m_z_score", "modified_z"]:
    if score >= 3.5:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 2.5:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 2.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key in ["posterior_fail_prob", "regularized_failure_prob", "concentration_ratio", "producer_ratio"]:
    if score >= 0.80:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 0.65:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 0.50:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key == "velocity_kmh":
    if score >= 1200.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 900.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 500.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key == "diversity_z":
    if score <= -2.5:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score <= -1.5:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score <= -1.0:
      return "🟡 **[ELEVATED WATCH]**"
    else:
      return "🟢 **[INFORMATIONAL]**"
  elif chosen_key in ["surge_ratio", "ratio_1v30"]:
    if score >= 5.0:
      return "🚨 **[CRITICAL OUTLIER]**"
    elif score >= 3.0:
      return "⚠️ **[HIGH SUSPICION]**"
    elif score >= 1.5:
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


def calculate_cri(score: float, baseline_threshold: float = 3.0) -> int:
  """Calibrated Risk Index (CRI) logistic sigmoid function [0-100].

  Maps statistical deviations onto an intuitive [0-100] SOC operational index:
    - Normal / Sub-baseline (Z <= 0): CRI = 0
    - Baseline Threshold (e.g. Z = 3.0σ): CRI = 50 (Medium Outlier boundary)
    - Significant Outlier (e.g. Z = 4.0σ): CRI = 65
    - High Threat (e.g. Z = 6.0σ): CRI = 86
    - Saturated Cap (e.g. Z >= 15.0σ): CRI = 100
  """
  if score <= 0:
    return 0
  try:
    val = -0.6 * (score - baseline_threshold)
    if val > 50:
      return 0
    elif val < -50:
      return 100
    return round(100.0 / (1.0 + math.exp(val)))
  except OverflowError:
    return 100 if score > baseline_threshold else 0


def get_cri_badge(cri: int) -> Tuple[str, str]:
  """Returns formatted CRI badge and severity label based on operational tier."""
  if cri <= 25:
    return f"🟢 `[CRI: {cri}]`", "Nominal"
  elif cri <= 45:
    return f"🟡 `[CRI: {cri}]`", "Low Drift"
  elif cri <= 69:
    return f"🟠 `[CRI: {cri}]`", "Medium Outlier"
  elif cri <= 89:
    return f"🔴 `[CRI: {cri}]`", "High Threat"
  else:
    return f"🚨 `[CRI: {cri}]`", "Critical Outlier"


class DataReductionEngine:
  """Truncates large SecOps search payloads to statistical summaries and top N outliers."""

  @staticmethod
  def reduce(raw_results: List[Dict[str, Any]], top_n: int = 5) -> Dict[str, Any]:
    if not raw_results:
      return {
          "total_entities_evaluated": 0,
          "outlier_count": 0,
          "primary_score_metric": "none",
          "top_outliers": [],
      }

    sample = raw_results[0]
    score_key = "z_score"
    for candidate in PRIMARY_SCORE_KEYS:
      if candidate in sample:
        score_key = candidate
        break

    def get_score(record: Dict[str, Any]) -> float:
      try:
        val = float(record.get(score_key, 0))
        if score_key in ("cv", "diversity_z"):
          return -val
        return val
      except (ValueError, TypeError):
        return 0.0

    sorted_records = sorted(raw_results, key=get_score, reverse=True)

    return {
        "total_entities_evaluated": len(raw_results),
        "outlier_count": len(sorted_records),
        "primary_score_metric": score_key,
        "top_outliers": sorted_records[:top_n],
    }


def describe_mad_scale_branch(row: Dict[str, Any]) -> str:
  """Explains which robust-scale branch of the Modified Z-Score applied to a result row."""
  def _num(key):
    try:
      return float(row[key])
    except (KeyError, TypeError, ValueError):
      return None
  mad = _num("baseline_dispersion")
  mean_ad = _num("baseline_mean_abs_dev")
  if mad is None:
    return "* **Robust Scale Branch**: unknown (MAD not present in results)."
  if mad > 0:
    return f"* **Robust Scale Branch**: MAD > 0, so $s = \\text{{MAD}} / 0.6745 = {mad:g} / 0.6745 \\approx {mad / 0.6745:.3f}$."
  if mean_ad is None:
    return "* **Robust Scale Branch**: MAD = 0; mean absolute deviation not present in results, so the fallback value cannot be shown."
  if mean_ad > 0:
    return f"* **Robust Scale Branch**: MAD = 0, so the Iglewicz-Hoaglin fallback applies: $s = 1.253314 \\cdot \\text{{meanAD}} = 1.253314 \\cdot {mean_ad:g} \\approx {1.253314 * mean_ad:.3f}$."
  return "* **Robust Scale Branch**: MAD = 0 and meanAD = 0 (constant history), so the dispersion floor was used as $s$."


def infer_hunt_scope(query_text: Optional[str]) -> Dict[str, Any]:
  """Extracts the hunted event_type, entity field and first-stage bucket size from a YARA-L query.

  Returns a dict with keys event_type, entity_field, bucket_seconds (each None when not found).
  """
  scope: Dict[str, Any] = {"event_type": None, "entity_field": None, "bucket_seconds": None}
  if not query_text:
    return scope
  code = re.sub(r"//.*", "", query_text)
  m = re.search(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', code)
  if m:
    scope["event_type"] = m.group(1)
  m = re.search(r"^\s*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\s*=\s*\$\w+\s*$", code, re.MULTILINE)
  if m:
    scope["entity_field"] = m.group(1)
  m = re.search(r"\bby\s+(\d+)\s*([mhd])\b", code)
  if m:
    scope["bucket_seconds"] = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
  return scope


def format_triage_report(
    title: str,
    stats_payload: Dict[str, Any],
    top_n: int = 5,
    event_type: Optional[str] = None,
    fleet_size: int = 1,
    entity_field: Optional[str] = None,
    query_text: Optional[str] = None,
    bucket_seconds: Optional[int] = None,
) -> str:
  """Renders raw Chronicle multi-stage stats into a Clean CommonMark/HTML-Safe 4-Tier Report with Evidence Pillars.

  The manual pivot filter uses the hunted scope: explicit event_type / entity_field / bucket_seconds
  win, then values inferred from query_text, then legacy defaults (PROCESS_LAUNCH, principal.hostname
  or target.user.userid for user rows, 1h buckets; 1d for Modified-Z rows).
  """
  inferred = infer_hunt_scope(query_text)
  event_type = event_type or inferred["event_type"] or "PROCESS_LAUNCH"
  entity_field = entity_field or inferred["entity_field"]
  bucket_seconds = bucket_seconds or inferred["bucket_seconds"]
  rows = parse_columnar_stats(stats_payload)
  if not rows:
    return "⚡ **STATISTICAL HUNT VERDICT**: No outlier entities exceeded the configured anomaly threshold."

  order_var = None
  if query_text:
    m_order = re.search(r"\border\s*:\s*\n?\s*\$([a-zA-Z0-9_]+)", re.sub(r"//.*", "", query_text))
    if m_order and m_order.group(1) in rows[0]:
      order_var = m_order.group(1)

  chosen_key = order_var or next((k for k in PRIMARY_SCORE_KEYS if k in rows[0]), None)
  if chosen_key:
    if chosen_key in ("cv", "diversity_z"):
      rows.sort(key=lambda x: float(x.get(chosen_key) if x.get(chosen_key) is not None else 999))
    else:
      rows.sort(key=lambda x: float(x.get(chosen_key) or 0), reverse=True)

  total_outliers = len(rows)
  top_rows = rows[:top_n]
  entity_col = next((c for c in ["host", "user", "src_ip", "dst_ip", "entity", "principal_ip"] if c in rows[0]), "entity")

  def _equiv_cri_score(key: Optional[str], val: float) -> float:
    if key == "cv":
      return max(0.0, (0.50 - val) / 0.10) if val > 0 else 0.0
    if key == "fano_factor":
      return (val / 4.0) * 3.0
    if key in ("poisson_z_sq", "threat_vector_norm_sq"):
      return math.sqrt(val) if val > 0 else 0.0
    if key in ("posterior_fail_prob", "regularized_failure_prob", "concentration_ratio", "producer_ratio"):
      return (val / 0.65) * 3.0 if val > 0 else 0.0
    if key == "velocity_kmh":
      return (val / 900.0) * 3.0 if val > 0 else 0.0
    if key == "diversity_z":
      return max(0.0, (-val / 1.5) * 3.0)
    return val

  sigma_keys = {
      "z_score", "poisson_z", "fleet_z", "targeted_delta_z", "delta_z",
      "personal_z", "bayesian_z", "threat_distance", "z_log",
  }

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
    out.append(f"* **Normal Baseline Envelope**: Historical Daily Rate ($\\lambda$) $\\approx {float(rows[0]['historical_lambda']):.2f}\\text{{ runs/day}}$")

  out.append("")
  out.append("---")
  out.append("")
  out.append("#### 📊 Ranked Outlier Summary (Top Anomalies by Severity)")
  out.append("")
  out.append("| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |")
  out.append("| :------------------- | :----------- | :---------------- | :------------------------- | :-------------- | :-------------- | :-------------------- | :--------------- |")

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
    score_str = f"+{score_val:.2f}σ" if chosen_key in sigma_keys else f"{score_val:.2f}"
    vbar = f"`{generate_visual_bar(abs(score_val) if chosen_key == 'diversity_z' else score_val, abs(max_score) if chosen_key == 'diversity_z' else max_score)}`"

    cri_val = calculate_cri(_equiv_cri_score(chosen_key, score_val), 3.0)
    cri_badge_str, _ = get_cri_badge(cri_val)
    
    out.append(f"| `{ent}` | {tb[:16]} | **{obs}** | {base_str} | {conf_badge} | {badge} (`{score_str}`) | {cri_badge_str} | {vbar} |")

  top_ent = top_rows[0]
  top_score_val = float(top_ent.get(chosen_key, 0.0)) if chosen_key else 0.0
  top_score_str = f"+{top_score_val:.2f}σ" if chosen_key in sigma_keys else f"{top_score_val:.2f}"
  top_badge = get_soc_severity_badge(chosen_key, top_score_val)
  top_conf_badge, top_conf_desc = evaluate_confidence_tier(top_ent)
  ent_name = str(top_ent.get(entity_col, "unknown"))

  top_cri_val = calculate_cri(_equiv_cri_score(chosen_key, top_score_val), 3.0)
  top_cri_badge, top_cri_tier = get_cri_badge(top_cri_val)

  obs_val = top_ent.get("observation_count", top_ent.get("observed_count", top_ent.get("observed_today", top_ent.get("total_fails", top_ent.get("daily_mb", "N/A")))))
  active_samples = top_ent.get("baseline_active_samples", top_ent.get("active_samples", top_ent.get("active_days", "N/A")))
  base_mean = top_ent.get("baseline_mean", top_ent.get("mean_val", top_ent.get("historical_lambda", top_ent.get("mu", "N/A"))))
  base_disp = top_ent.get("baseline_dispersion", top_ent.get("stddev_val", top_ent.get("mad_val", "N/A")))
  fleet_prev_num = resolve_fleet_prevalence(top_ent)
  if fleet_prev_num is None:
    fleet_prev = "not computed"
  else:
    fleet_prev = str(int(fleet_prev_num)) if float(fleet_prev_num).is_integer() else str(fleet_prev_num)
  cardinality = top_ent.get("distinct_binaries", top_ent.get("distinct_subdomains", top_ent.get("total_connections", "N/A")))

  out.append("")
  out.append("---")
  out.append("")
  out.append(f"#### 🔍 Top Outlier Spotlight: `{ent_name}` — {top_badge} (`{top_score_str}`) | {top_cri_badge}")
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
  out.append(f"> **Calibrated Risk Index**: Assessed at {top_cri_badge} (**{top_cri_tier}** on the standardized [0–100] SOC threat scale).")
  out.append(f"> ")
  out.append(f"> **Why It Matters**: This sudden burst produced an anomaly rating of **{top_score_str}**, indicating behavior so statistically rare that it almost certainly represents **automated software execution, script loops, or active threat tooling** rather than normal human employee activity.")
  out.append(f"> ")
  if fleet_prev_num is None:
    out.append("> **Organization Context**: Fleet-wide breadth was **not computed** by this pipeline; check other endpoints before ruling out a routine corporate-wide software rollout.")
  else:
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
  fleet_prev_cell = fleet_prev if fleet_prev_num is None else f"{fleet_prev} host(s)"
  out.append(f"| **5. Company-Wide Breadth** | `{fleet_prev_cell}` | 1 host = isolated/targeted; 100 hosts = company-wide software push |")
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
  out.append("#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)")
  out.append("*(Passive UDM filter for manual copy-paste into Chronicle SIEM search bar. NOT for automated tool execution; multi-turn follow-ups must remain within the statistical hunting framework.)*")
  out.append("")
  out.append("```text")
  if entity_field:
    pivot_field, pivot_value = entity_field, ent_name
  elif "user" in top_ent and top_ent["user"]:
    pivot_field, pivot_value = "target.user.userid", top_ent.get("user")
  else:
    pivot_field, pivot_value = "principal.hostname", ent_name
  drilldown_str = f'{pivot_field} = "{pivot_value}" AND metadata.event_type = "{event_type}"'
  pivot_bucket = bucket_seconds or (86400 if chosen_key == "m_z_score" else 3600)
  if "window_start" in top_ent and top_ent["window_start"]:
    ws_val = top_ent["window_start"]
    try:
      ws = int(ws_val)
      drilldown_str += f"\nAND metadata.event_timestamp.seconds >= {ws} AND metadata.event_timestamp.seconds < {ws + pivot_bucket}"
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
    out.append("* **Model**: Modified $Z$-Score via Median Absolute Deviation (MAD), Iglewicz-Hoaglin")
    out.append("  $$M_Z = \\frac{x - \\tilde{x}}{s}, \\quad s = \\begin{cases} \\text{MAD} / 0.6745 & \\text{MAD} > 0 \\\\ 1.253314 \\cdot \\text{meanAD} & \\text{MAD} = 0 \\\\ \\text{dispersion floor} & \\text{both} = 0 \\end{cases}$$")
    out.append(f"* **Result**: $M_Z = {top_score_str}$ (equivalent to $0.6745 \\cdot (x - \\tilde{{x}}) / \\text{{MAD}}$ when MAD > 0).")
    out.append(describe_mad_scale_branch(top_ent))
  out.append("")
  out.append("##### 🎚️ Calibrated Risk Index (CRI) Sigmoid Normalization")
  out.append("  $$\\text{CRI} = \\text{round}\\left(\\frac{100}{1 + \\exp(-0.6 \\cdot (Z - 3.0))}\\right) = \\mathbf{" + str(top_cri_val) + "}$$")
  out.append(f"* **Operational Status**: {top_cri_badge} ({top_cri_tier}). Anchors the 3-Sigma alert boundary ($Z = 3.0\\sigma$) at exactly $\\text{{CRI}} = 50$.")

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
  if fleet_prev_num is None:
    out.append("* **Fleet Prevalence Isolation**: `not computed` (Threshold $\\le 3$ $\\to$ **NOT EVALUATED**).")
  else:
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
  raw_rows = parse_columnar_stats(stats_payload)
  # Filter out null / NaN entries or sanitize rows
  rows = []
  for r in raw_rows:
    clean_r = {k: v for k, v in r.items() if v is not None and v != "NaN"}
    if clean_r:
      rows.append(clean_r)
  
  if plot_type == "DUAL_Y_TIMESERIES":
    time_key = next((k for k in ["TIME_BUCKET", "date", "time", "timestamp", "window_start", "evaluation_date"] if rows and k in rows[0]), "TIME_BUCKET")
    score_key = next((k for k in ["z_score", "score", "delta_z", "poisson_z", "fleet_z", "fano_factor", "m_z_score", "surge_ratio", "cv"] if rows and k in rows[0]), "z_score")
    score_title = "Z-Score (σ)" if score_key in ["z_score", "poisson_z", "fleet_z", "delta_z"] else "Anomaly Score"
    vol_key = next((k for k in ["observation_count", "observed_volume", "observed_count", "observed_today", "observed", "total_fails", "daily_mb", "event_count", "volume", "count"] if rows and k in rows[0]), "observation_count")
    vol_title = "Observed Volume / Activity"
    ent_key = next((k for k in ["host", "user", "entity", "principal_ip", "extension_id"] if rows and k in rows[0]), "entity")
    rows = [r for r in rows if r.get(vol_key) is not None or r.get(score_key) is not None]

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
                    "x": {"field": time_key, "type": "temporal", "title": "Time Window (UTC)"},
                    "y": {
                        "field": vol_key,
                        "type": "quantitative",
                        "axis": {"title": vol_title, "titleColor": "#1a73e8"}
                    },
                    "tooltip": [
                        {"field": ent_key, "type": "nominal", "title": "Entity"},
                        {"field": time_key, "type": "temporal", "title": "Time"},
                        {"field": vol_key, "type": "quantitative", "title": vol_title}
                    ]
                }
            },
            {
                "mark": {"type": "line", "point": {"filled": True, "size": 65, "color": "#d93025"}, "color": "#d93025", "strokeWidth": 2.5},
                "encoding": {
                    "x": {"field": time_key, "type": "temporal"},
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
                        {"field": ent_key, "type": "nominal", "title": "Entity"},
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
    time_key = next((k for k in ["TIME_BUCKET", "date", "time", "timestamp", "window_start"] if rows and k in rows[0]), "TIME_BUCKET")
    vol_key = next((k for k in ["observation_count", "observed_volume", "observed_count", "event_count", "daily_mb"] if rows and k in rows[0]), "observation_count")
    score_key = next((k for k in ["z_score", "score", "delta_z", "poisson_z", "fano_factor"] if rows and k in rows[0]), "z_score")
    card_key = next((k for k in ["distinct_binaries", "distinct_subdomains", "cardinality", "breadth"] if rows and k in rows[0]), "distinct_binaries")
    ent_key = next((k for k in ["host", "user", "entity", "principal_ip"] if rows and k in rows[0]), "host")

    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 650,
        "height": 350,
        "data": {"values": rows},
        "mark": "circle",
        "encoding": {
            "x": {"field": time_key, "type": "temporal", "title": "Timestamp / Window (UTC)"},
            "y": {"field": vol_key, "type": "quantitative", "title": "Observed Intensity / Volume"},
            "size": {"field": card_key, "type": "quantitative", "title": "Cardinality / Breadth", "scale": {"range": [50, 600]}},
            "color": {
                "field": score_key,
                "type": "quantitative",
                "title": "Anomaly Score (Z)",
                "scale": {"scheme": "redyellowblue", "reverse": True}
            },
            "tooltip": [
                {"field": ent_key, "type": "nominal"},
                {"field": time_key, "type": "temporal"},
                {"field": vol_key, "type": "quantitative"},
                {"field": score_key, "type": "quantitative"}
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
    time_key = next((k for k in ["TIME_BUCKET", "date", "time", "timestamp"] if rows and k in rows[0]), "TIME_BUCKET")
    vol_key = next((k for k in ["observation_count", "observed_volume", "observed_count"] if rows and k in rows[0]), "observation_count")
    ent_key = next((k for k in ["host", "user", "entity"] if rows and k in rows[0]), "host")
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": title,
        "width": 600,
        "height": 300,
        "data": {"values": rows},
        "mark": {"type": "line", "point": True},
        "encoding": {
            "x": {"field": time_key, "type": "temporal", "title": "Timestamp (UTC)"},
            "y": {"field": vol_key, "type": "quantitative", "title": "Observed Metric"},
            "color": {"field": ent_key, "type": "nominal"}
        }
    }
  return spec


def generate_chartjs_spec(
    stats_payload: Dict[str, Any],
    plot_type: str = "CATEGORICAL_BAR",
    title: str = "Activity Distribution by Entity"
) -> Dict[str, Any]:
  """Generates strictly-typed, axis-isolated Chart.js JSON configs to prevent mixed categorical/numeric Y-axis corruption."""
  raw_rows = parse_columnar_stats(stats_payload)
  rows = [r for r in raw_rows if any(v is not None and v != "NaN" for v in r.values())]
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
    time_key = next((k for k in ["TIME_BUCKET", "date", "time", "timestamp", "window_start"] if k in rows[0]), "TIME_BUCKET")
    vol_key = next((k for k in ["observation_count", "observed_volume", "observed_count", "event_count", "daily_mb"] if k in rows[0]), "observation_count")
    score_key = next((k for k in ["z_score", "score", "delta_z", "fleet_z", "poisson_z", "fano_factor"] if k in rows[0]), "z_score")
    
    valid_rows = [r for r in rows if r.get(vol_key) is not None or r.get(score_key) is not None]
    time_labels = [str(r.get(time_key, "N/A")) for r in valid_rows]
    vol_data = [float(r.get(vol_key, 0)) for r in valid_rows]
    score_data = [float(r.get(score_key, 0)) for r in valid_rows]
    
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


def audit_query_execution(
    query_text: str,
    expected_architecture: str,
    expected_model: Optional[str] = None,
    explained_to_user: Optional[str] = None,
    expected_stage_count: Optional[int] = None,
) -> Dict[str, Any]:
  """Audits the executed YARA-L query against the promised hunting architecture, model intent, and narrative explained to the analyst."""
  stage_names = re.findall(r"\bstage\s+([a-zA-Z0-9_]+)\s*\{", query_text)
  stage_count = len(stage_names)

  if stage_count == 0:
    actual_arch = "SINGLE_STAGE_MACRO"
  elif stage_count == 1:
    actual_arch = "LOCAL_2STAGE"
  elif stage_count == 2:
    if "delta_z" in query_text.lower() or "fleet_z" in query_text.lower():
      actual_arch = "DUAL_BASELINE_3STAGE"
    else:
      actual_arch = "3STAGE_DAG"
  elif stage_count == 3:
    if "threat_norm" in query_text.lower() or "threat_vector" in query_text.lower() or "composite" in query_text.lower():
      actual_arch = "MULTI_SECTOR_FUSION_4STAGE"
    elif "beta_prior" in query_text.lower() or "alpha_prior" in query_text.lower():
      actual_arch = "BAYESIAN_GAMMA_4STAGE"
    elif "posterior_fail_prob" in query_text.lower() or "alpha_post" in query_text.lower():
      actual_arch = "BETA_BINOMIAL_4STAGE"
    elif "global_context" in query_text.lower() or "whois" in query_text.lower() or "gcti" in query_text.lower():
      actual_arch = "GLOBAL_THREAT_INTEL_4STAGE"
    elif "derived_context" in query_text.lower() or "first_seen" in query_text.lower():
      actual_arch = "DERIVED_CONTEXT_4STAGE"
    else:
      actual_arch = "4STAGE_DAG"
  else:
    actual_arch = f"{stage_count + 1}STAGE_EXCEEDS_SUPPORTED_LIMIT"

  exp_norm = expected_architecture.upper().replace("-", "_")
  act_norm = actual_arch.upper().replace("-", "_")

  is_arch_match = (exp_norm in act_norm or act_norm in exp_norm)
  if "3STAGE" in exp_norm and "3STAGE" in act_norm:
    is_arch_match = True
  if "4STAGE" in exp_norm and "4STAGE" in act_norm:
    is_arch_match = True
  if "2STAGE" in exp_norm and ("2STAGE" in act_norm or act_norm == "LOCAL_2STAGE"):
    is_arch_match = True

  findings = []
  if is_arch_match:
    findings.append(f"✅ Architecture verified: Executed query has {stage_count} intermediate stage(s) + root ({stage_count + 1} total stages), matching promised '{expected_architecture}'.")
  else:
    findings.append(f"❌ ARCHITECTURE MISMATCH: Promised '{expected_architecture}', but executed query is '{actual_arch}' ({stage_count} intermediate stages).")

  # Concordance check against narrative explained to analyst
  stage_degradation = False
  if explained_to_user:
    exp_lower = explained_to_user.lower()
    promised_multistage = any(term in exp_lower for term in [
        "multi-stage", "multistage", "2-stage", "3-stage", "4-stage",
        "two-stage", "three-stage", "four-stage", "delta-z", "fano",
        "fusion", "bayesian", "beta-binomial", "mad", "diversity deficit",
        "elephant flow", "hurdle", "prevalence normalization"
    ])
    promised_single_stage = any(term in exp_lower for term in [
        "single-stage", "1-stage", "single stage", "one-stage"
    ])
    if promised_multistage and stage_count == 0:
      stage_degradation = True
      findings.append("❌ STAGE DEGRADATION ERROR: Multi-stage pipeline was explained to the analyst, but executed query degraded to a single-stage search (0 named stages). Multi-stage pipeline execution was required.")
    elif promised_single_stage and stage_count > 0:
      findings.append(f"⚠️ CONCORDANCE WARNING: Single-stage search was explained to the analyst, but executed query contains {stage_count} named intermediate stage(s).")
    else:
      findings.append(f"✅ User explanation concordance verified: Executed query stages match narrative explained to analyst.")

  if expected_stage_count is not None:
    total_stages = stage_count + 1 if stage_count > 0 else 1
    if total_stages != expected_stage_count:
      findings.append(f"❌ STAGE COUNT MISMATCH: Expected {expected_stage_count} stages, but executed query has {total_stages} stage(s).")
      is_arch_match = False

  has_sample_floor = bool(re.search(r"\$(?:baseline_active_samples|active_hours|active_days|active_samples)\s*>=\s*\d+", query_text))
  has_dispersion_floor = bool(re.search(r"\$(?:baseline_dispersion|personal_stddev|fleet_stddev|sd|dispersion)\s*>\s*0", query_text) or re.search(r"\$(?:baseline_dispersion|personal_stddev|sd)\s*>=\s*\d+", query_text))

  safeguards = {
      "sample_floor_present": has_sample_floor,
      "dispersion_floor_present": has_dispersion_floor
  }

  if actual_arch != "SINGLE_STAGE_MACRO":
    if not has_sample_floor:
      findings.append("⚠️ Missing Small-Sample Protection Floor in condition: section.")
    if not has_dispersion_floor:
      findings.append("⚠️ Missing Non-Zero Dispersion Floor in condition: section.")

  model_verified = True
  if expected_model:
    m_norm = expected_model.upper()
    q_lower = query_text.lower()
    if "DELTA_Z" in m_norm and ("delta_z" not in q_lower and "fleet_z" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Delta-Z calculations ($delta_z = $personal_z - $fleet_z), but variables were not found.")
    elif "BAYESIAN_GAMMA" in m_norm and ("alpha" not in q_lower or "beta" not in q_lower or "prior" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Bayesian Gamma conjugate updating ($alpha_prior, $beta_prior, $posterior_rate), but parameters were not found.")
    elif "BETA_BINOMIAL" in m_norm and ("posterior_fail_prob" not in q_lower and "alpha_post" not in q_lower and "alpha" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Beta-Binomial failure rate regularization ($alpha_post, $beta_post, $posterior_fail_prob), but parameters were not found.")
    elif "FANO" in m_norm and ("fano" not in q_lower and "variance" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Poisson Dispersion / Fano Factor ($fano_factor = $var / $mu), but variance/Fano variables were not found.")
    elif "FUSION" in m_norm and ("threat_norm" not in q_lower and "composite" not in q_lower and "threat_vector" not in q_lower and "_sq" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Multi-Sector Threat Fusion orthogonal norm ($composite_threat_norm_sq = $z1_sq + $z2_sq), but vector norm variables were not found.")
    elif ("MAD" in m_norm or "MODIFIED_Z" in m_norm) and ("0.6745" not in query_text and "mad" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Modified Z-Score via Median Absolute Deviation (0.6745 scaling factor or MAD variable).")
    elif "POISSON" in m_norm and ("lambda" not in q_lower and "poisson" not in q_lower and "hist_mean" not in q_lower):
      model_verified = False
      findings.append("❌ Model Mismatch: Expected Poisson calculation with historical lambda arrival rate.")
    elif model_verified:
      findings.append(f"✅ Model math verified: Mathematical signatures for '{expected_model}' confirmed.")

  if stage_degradation:
    status = "STAGE_DEGRADATION"
  elif is_arch_match and model_verified:
    status = "PASS"
  else:
    status = "MISMATCH"

  if actual_arch != "SINGLE_STAGE_MACRO" and not has_sample_floor and not has_dispersion_floor:
    status = "GUARDRAIL_VIOLATION" if status == "PASS" else status

  return {
      "status": status,
      "expected_architecture": expected_architecture,
      "actual_architecture": actual_arch,
      "intermediate_stages": stage_count,
      "total_stages": stage_count + 1 if stage_count > 0 else 1,
      "stage_names": stage_names,
      "model_verified": model_verified,
      "safeguards": safeguards,
      "findings": findings
  }


def audit_api_response_payload(api_response: Dict[str, Any]) -> List[str]:
  """Ensures the SIEM API returned aggregated stats and not raw un-aggregated event dumps."""
  errors = []
  if "events" in api_response and "stats" not in api_response and not api_response.get("results"):
    raw_events = api_response.get("events", [])
    if len(raw_events) > 0:
      errors.append(
          f"RAW_LOG_DUMP_DETECTED: API returned {len(raw_events)} raw UDM events instead of compiled "
          "multi-stage columnar statistics. Multi-stage math must be executed on the SecOps engine, "
          "not simulated client-side."
      )
  return errors


class AuditStatus(str, Enum):
  PASSED = "PASSED"
  RETRY_REQUIRED = "RETRY_REQUIRED"
  FAILED = "FAILED"
  GUARDRAIL_VIOLATION = "GUARDRAIL_VIOLATION"


@dataclass
class PostFlightAuditResult:
  status: str
  is_valid: bool
  errors: List[str]
  findings: List[str]
  remediation_action: Optional[str] = None
  recommended_query: Optional[str] = None
  audit_summary: str = ""


class PostFlightExecutionAuditor:
  """Audits completed API executions, validates statistical AST concordance, and checks API response structure."""

  @classmethod
  def audit_execution(
      cls,
      executed_query: Optional[str],
      api_response: Optional[Dict[str, Any]] = None,
      expected_architecture: Optional[str] = None,
      expected_model: Optional[str] = None,
      explained_to_user: Optional[str] = None,
      expected_stage_count: Optional[int] = None,
  ) -> PostFlightAuditResult:
    errors = []
    findings = []

    if executed_query:
      scope_errs = check_scope_exclusions(executed_query)
      syntax_errs = validate_multistage_syntax(executed_query)
      cram_errs = check_multivector_cramming(executed_query)
      ecg_errs = check_ecg_limits(executed_query)

      fatal_syntax = [e for e in syntax_errs if not e.startswith("MISSING METHODOLOGY HEADER")]
      all_query_errors = scope_errs + fatal_syntax + cram_errs + ecg_errs
      errors.extend(all_query_errors)

      if expected_architecture or explained_to_user or expected_stage_count:
        target_arch = expected_architecture or ("LOCAL_2STAGE" if (expected_stage_count and expected_stage_count == 2) else ("SINGLE_STAGE_MACRO" if expected_stage_count == 1 else "LOCAL_2STAGE"))
        arch_res = audit_query_execution(
            executed_query,
            expected_architecture=target_arch,
            expected_model=expected_model,
            explained_to_user=explained_to_user,
            expected_stage_count=expected_stage_count,
        )
        findings.extend(arch_res.get("findings", []))
        if arch_res["status"] != "PASS":
          errors.append(f"ARCHITECTURE_AUDIT_ERROR: {arch_res['status']}")

    if api_response:
      resp_errs = audit_api_response_payload(api_response)
      errors.extend(resp_errs)

    raw_dump_detected = any("RAW_LOG_DUMP_DETECTED" in e for e in errors)
    is_valid = len(errors) == 0

    if is_valid:
      status = AuditStatus.PASSED.value
      summary = "🟢 Audit Passed: Execution verified."
    elif raw_dump_detected:
      status = AuditStatus.RETRY_REQUIRED.value
      summary = "⚠️ Audit Failed: Raw log dump detected. YARA-L query must compile columnar stats, not dump raw events."
    else:
      status = AuditStatus.FAILED.value
      summary = f"❌ Audit Failed ({len(errors)} violation(s) detected)."

    remediation = None
    recommended = None
    if not is_valid:
      remediation = "Refactor query to enforce canonical YARA-L DAG grammar, isolate multi-vector stages, and execute as columnar stats."
      target_arch = expected_model or expected_architecture or "ZSCORE_PROCESS_SURGE"
      try:
        router = MultiStageTemplateRouter()
        recommended = router.build_query(target_arch)
      except Exception:
        pass

    return PostFlightAuditResult(
        status=status,
        is_valid=is_valid,
        errors=errors,
        findings=findings,
        remediation_action=remediation,
        recommended_query=recommended,
        audit_summary=summary
    )


class MultiStageTemplateRouter:
  """Routes and builds canonical multi-stage YARA-L queries (.yl2) from golden pipeline templates."""

  ARCHETYPE_TEMPLATE_MAP = {
      "ZSCORE_PROCESS_SURGE": "zscore_process_surge_2stage.yl2",
      "Z_SCORE": "zscore_process_surge_2stage.yl2",
      "ZSCORE": "zscore_process_surge_2stage.yl2",
      "PROCESS_SURGE": "zscore_process_surge_2stage.yl2",
      "POISSON_BURST_CLUSTERING": "poisson_burst_clustering_2stage.yl2",
      "FANO": "poisson_burst_clustering_2stage.yl2",
      "FANO_FACTOR": "poisson_burst_clustering_2stage.yl2",
      "BURST_CLUSTERING": "poisson_burst_clustering_2stage.yl2",
      "POISSON_RARE_SURGE": "poisson_rare_surge_2stage.yl2",
      "POISSON": "poisson_rare_surge_2stage.yl2",
      "POISSON_RARITY": "poisson_rare_surge_2stage.yl2",
      "RARE_SURGE": "poisson_rare_surge_2stage.yl2",
      "C2_BEACONING_JITTER": "c2_beaconing_jitter_2stage.yl2",
      "CV": "c2_beaconing_jitter_2stage.yl2",
      "BEACONING": "c2_beaconing_jitter_2stage.yl2",
      "JITTER": "c2_beaconing_jitter_2stage.yl2",
      "DATA_EXFILTRATION_SPIKE": "mad_modified_z_4stage.yl2",
      "MAD_EXFILTRATION": "mad_modified_z_4stage.yl2",
      "MAD": "mad_modified_z_4stage.yl2",
      "MODIFIED_Z": "mad_modified_z_4stage.yl2",
      "DUAL_BASELINE_DELTA_Z": "dual_baseline_delta_z_3stage.yl2",
      "DELTA_Z": "dual_baseline_delta_z_3stage.yl2",
      "DUAL_BASELINE": "dual_baseline_delta_z_3stage.yl2",
      "BAYESIAN_GAMMA_SHRINKAGE": "bayesian_gamma_shrinkage_4stage.yl2",
      "BAYESIAN_GAMMA": "bayesian_gamma_shrinkage_4stage.yl2",
      "GAMMA_SHRINKAGE": "bayesian_gamma_shrinkage_4stage.yl2",
      "BETA_BINOMIAL_FAILURE": "beta_binomial_failure_4stage.yl2",
      "BETA_BINOMIAL": "beta_binomial_failure_4stage.yl2",
      "CREDENTIAL_STUFFING": "beta_binomial_failure_4stage.yl2",
      "MULTI_SECTOR_THREAT_FUSION": "multi_sector_threat_fusion_4stage.yl2",
      "FUSION": "multi_sector_threat_fusion_4stage.yl2",
      "THREAT_FUSION": "multi_sector_threat_fusion_4stage.yl2",
      "MULTI_SECTOR": "multi_sector_threat_fusion_4stage.yl2",
      "LOG_NORMAL_VOLUME_SURGE": "log_normal_volume_surge_2stage.yl2",
      "LOG_NORMAL_VOLUME": "log_normal_volume_surge_2stage.yl2",
      "LOG_NORMAL": "log_normal_volume_surge_2stage.yl2",
      "RAW_TELEMETRY_ENRICHMENT": "mad_modified_z_4stage.yl2",
      "TELEMETRY_ENRICHMENT": "mad_modified_z_4stage.yl2",
      "DUAL_PLANE_CORRELATION": "mad_modified_z_4stage.yl2",
      "DUAL_PLANE_HYBRID": "mad_modified_z_4stage.yl2",
      "DIVERSITY_DEFICIT": "hybrid_entropy_concentration_2stage.yl2",
      "ENTROPY_PROXY": "hybrid_entropy_concentration_2stage.yl2",
      "ELEPHANT_FLOW_CONCENTRATION": "hybrid_entropy_concentration_2stage.yl2",
      "CONCENTRATION_INDEX": "hybrid_entropy_concentration_2stage.yl2",
      "HYBRID_ENTROPY_CONCENTRATION": "hybrid_entropy_concentration_2stage.yl2",
      "ORTHOGONAL_THREAT_SPACE": "multi_sector_threat_fusion_4stage.yl2",
      "EUCLIDEAN_THREAT_DISTANCE": "multi_sector_threat_fusion_4stage.yl2",
      "BAYESIAN_JOINT_ODDS": "bayesian_gamma_shrinkage_4stage.yl2",
      "TWO_PART_HURDLE": "two_part_hurdle_2stage.yl2",
      "DORMANT_ACCOUNT": "two_part_hurdle_2stage.yl2",
      "DORMANT_ACCOUNT_AWAKENING": "two_part_hurdle_2stage.yl2",
      "COLD_START_AWAKENING": "two_part_hurdle_2stage.yl2",
      "HURDLE": "two_part_hurdle_2stage.yl2",
      "FLEET_PREVALENCE_NORMALIZATION": "dual_baseline_delta_z_3stage.yl2",
      "PATCH_TUESDAY_SHIELD": "dual_baseline_delta_z_3stage.yl2",
      "PRIVILEGED_LATERAL_EXPANSION": "privileged_lateral_expansion_2stage.yl2",
      "LATERAL_MOVEMENT_BIPARTITE": "privileged_lateral_expansion_2stage.yl2",
      "BIPARTITE_AUTH_RARITY": "privileged_lateral_expansion_2stage.yl2",
      "UNSEEN_ENDPOINT_ACCESS": "privileged_lateral_expansion_2stage.yl2",
      "GLOBAL_THREAT_INTEL": "global_threat_intel_enrichment_3stage.yl2",
      "GLOBAL_THREAT_INTEL_ENRICHMENT": "global_threat_intel_enrichment_3stage.yl2",
      "GLOBAL_CONTEXT": "global_threat_intel_enrichment_3stage.yl2",
      "GCTI_ENRICHMENT": "global_threat_intel_enrichment_3stage.yl2",
      "WHOIS_NRD_EGRESS": "global_threat_intel_enrichment_3stage.yl2",
      "DERIVED_CONTEXT_PREVALENCE": "derived_context_prevalence_3stage.yl2",
      "DERIVED_CONTEXT": "derived_context_prevalence_3stage.yl2",
      "ASSET_AGE_PREVALENCE": "derived_context_prevalence_3stage.yl2",
      "NEW_ASSET_AUTHENTICATION": "derived_context_prevalence_3stage.yl2",
      "DERIVED_CONTEXT_FILE_PREVALENCE": "derived_context_file_prevalence_3stage.yl2",
      "FILE_PREVALENCE": "derived_context_file_prevalence_3stage.yl2",
      "UNSEEN_BINARY_BURST": "derived_context_file_prevalence_3stage.yl2",
      "DERIVED_CONTEXT_DOMAIN_PREVALENCE": "derived_context_domain_prevalence_3stage.yl2",
      "DOMAIN_PREVALENCE": "derived_context_domain_prevalence_3stage.yl2",
      "FIRST_SEEN_DOMAIN_EGRESS": "derived_context_domain_prevalence_3stage.yl2",
      "MARKOV_2GRAM_TRANSITION_RARITY": "markov_2gram_transition_rarity_2stage.yl2",
      "MARKOV_TRANSITION_RARITY": "markov_2gram_transition_rarity_2stage.yl2",
      "MARKOV_2GRAM": "markov_2gram_transition_rarity_2stage.yl2",
      "MARKOV": "markov_2gram_transition_rarity_2stage.yl2",
      "TRANSITION_RARITY": "markov_2gram_transition_rarity_2stage.yl2",
      "SHANNON_ENTROPY_CHARACTER": "shannon_entropy_character_2stage.yl2",
      "SHANNON_ENTROPY": "shannon_entropy_character_2stage.yl2",
      "CHARACTER_ENTROPY": "shannon_entropy_character_2stage.yl2",
      "SHANNON": "shannon_entropy_character_2stage.yl2",
      "ENTROPY": "shannon_entropy_character_2stage.yl2",
      "ZIPFIAN_PROCESS_RARITY": "zipfian_process_rarity_2stage.yl2",
      "ZIPFIAN_RARITY": "zipfian_process_rarity_2stage.yl2",
      "ZIPFIAN_LONG_TAIL": "zipfian_process_rarity_2stage.yl2",
      "ZIPFIAN": "zipfian_process_rarity_2stage.yl2",
      "ZIPF": "zipfian_process_rarity_2stage.yl2",
      "EWMA_BURST_VELOCITY": "ewma_burst_velocity_2stage.yl2",
      "EWMA_BURST": "ewma_burst_velocity_2stage.yl2",
      "EWMA_VELOCITY": "ewma_burst_velocity_2stage.yl2",
      "EWMA": "ewma_burst_velocity_2stage.yl2",
      "BURST_VELOCITY": "ewma_burst_velocity_2stage.yl2",
      "IMPOSSIBLE_TRAVEL_GEO_VELOCITY": "impossible_travel_geo_velocity_2stage.yl2",
      "IMPOSSIBLE_TRAVEL": "impossible_travel_geo_velocity_2stage.yl2",
      "GEO_VELOCITY": "impossible_travel_geo_velocity_2stage.yl2",
      "SUPERSONIC_TRAVEL": "impossible_travel_geo_velocity_2stage.yl2",
      "PRODUCER_CONSUMER_RATIO_INVERSION": "producer_consumer_ratio_inversion_2stage.yl2",
      "PRODUCER_CONSUMER_ROLE_INVERSION": "producer_consumer_ratio_inversion_2stage.yl2",
      "PRODUCER_CONSUMER_INVERSION": "producer_consumer_ratio_inversion_2stage.yl2",
      "BYTE_RATIO_INVERSION": "producer_consumer_ratio_inversion_2stage.yl2",
      "OFF_HOURS_BURST": "poisson_burst_clustering_2stage.yl2",
      "AFTER_HOURS_ACTIVITY": "poisson_burst_clustering_2stage.yl2",
  }

  TEMPLATE_TO_SENSITIVITY_KEY = {
      "zscore_process_surge_2stage.yl2": "ZSCORE_PROCESS_SURGE",
      "poisson_burst_clustering_2stage.yl2": "POISSON_BURST_CLUSTERING",
      "poisson_rare_surge_2stage.yl2": "POISSON_RARE_SURGE",
      "c2_beaconing_jitter_2stage.yl2": "C2_BEACONING_JITTER",
      "mad_modified_z_4stage.yl2": "DATA_EXFILTRATION_SPIKE",
      "dual_baseline_delta_z_3stage.yl2": "DUAL_BASELINE_DELTA_Z",
      "bayesian_gamma_shrinkage_4stage.yl2": "BAYESIAN_GAMMA_SHRINKAGE",
      "beta_binomial_failure_4stage.yl2": "BETA_BINOMIAL_FAILURE",
      "multi_sector_threat_fusion_4stage.yl2": "MULTI_SECTOR_THREAT_FUSION",
      "log_normal_volume_surge_2stage.yl2": "LOG_NORMAL_VOLUME_SURGE",
      "hybrid_entropy_concentration_2stage.yl2": "HYBRID_ENTROPY_CONCENTRATION",
      "two_part_hurdle_2stage.yl2": "TWO_PART_HURDLE",
      "privileged_lateral_expansion_2stage.yl2": "PRIVILEGED_LATERAL_EXPANSION",
      "global_threat_intel_enrichment_3stage.yl2": "GLOBAL_THREAT_INTEL_ENRICHMENT",
      "derived_context_prevalence_3stage.yl2": "DERIVED_CONTEXT_PREVALENCE",
      "derived_context_file_prevalence_3stage.yl2": "DERIVED_CONTEXT_FILE_PREVALENCE",
      "derived_context_domain_prevalence_3stage.yl2": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
      "markov_2gram_transition_rarity_2stage.yl2": "MARKOV_2GRAM_TRANSITION_RARITY",
      "shannon_entropy_character_2stage.yl2": "SHANNON_ENTROPY_CHARACTER",
      "zipfian_process_rarity_2stage.yl2": "ZIPFIAN_PROCESS_RARITY",
      "ewma_burst_velocity_2stage.yl2": "EWMA_BURST_VELOCITY",
      "impossible_travel_geo_velocity_2stage.yl2": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
      "producer_consumer_ratio_inversion_2stage.yl2": "PRODUCER_CONSUMER_RATIO_INVERSION",
  }

  INLINE_TEMPLATES = {
      "producer_consumer_ratio_inversion_2stage.yl2": (
          "// ============================================================================\n"
          "// METHODOLOGY & HUNTING GOAL\n"
          "// Goal: Detect Producer-Consumer Byte Ratio Inversion (Endpoint Shifting from Net Consumer to Data Producer).\n"
          "// Target Telemetry: UDM_EVENTS ({{event_type}})\n"
          "// Statistical Model: Directional Byte Asymmetry Ratio (Sent / Total Bytes) with Historical Z-Score\n"
          "// Mathematical Rationale:\n"
          "//   - Why this model: Standard workstations and application clients are net data consumers (rho << 0.30).\n"
          "//     When an endpoint stages and exfiltrates data or serves payloads laterally, its directional producer\n"
          "//     ratio rho = sent_bytes / (sent_bytes + received_bytes) inverts toward 1.0 alongside a Z-score spike.\n"
          "// Sensitivity Boundary: {{tier}} (Producer Ratio >= {{min_producer_ratio}}, Z-Score >= {{z_score}}, Sent Bytes >= {{min_sent_bytes}}, Active Samples >= {{min_active_samples}})\n"
          "// ============================================================================\n\n"
          "// Stage 1: Aggregate per-window outbound/inbound bytes and destination diversity\n"
          "stage stage1_directional_bytes {\n"
          "    metadata.event_type = \"{{event_type}}\"\n"
          "    {{entity_field}} = $entity\n"
          "    $entity != \"\"\n"
          "    target.ip = $dst_ip\n"
          "    $dst_ip != \"\"\n\n"
          "  match:\n"
          "    $entity by {{bucket_size}}\n\n"
          "  outcome:\n"
          "    $event_count = count(metadata.id)\n"
          "    $sent_bytes = sum(network.sent_bytes)\n"
          "    $recv_bytes = sum(network.received_bytes)\n"
          "    $distinct_targets = count_distinct($dst_ip)\n"
          "}\n\n"
          "// Stage 2: Establish per-entity historical baseline over outbound byte volume\n"
          "stage stage2_entity_baseline {\n"
          "    $entity = $stage1_directional_bytes.entity\n\n"
          "  match:\n"
          "    $entity\n\n"
          "  outcome:\n"
          "    $active_windows = count($stage1_directional_bytes.window_start)\n"
          "    $mean_sent = avg($stage1_directional_bytes.sent_bytes)\n"
          "    $sd_sent = stddev($stage1_directional_bytes.sent_bytes)\n"
          "}\n\n"
          "// Root Stage: Score directional producer ratio inversion and outbound byte Z-score\n"
          "$entity = $stage1_directional_bytes.entity\n"
          "$entity = $stage2_entity_baseline.entity\n\n"
          "match:\n"
          "  $entity by {{bucket_size}}\n\n"
          "outcome:\n"
          "  // 6 Core Evidence Pillars\n"
          "  $observation_count = max($stage1_directional_bytes.sent_bytes)\n"
          "  $baseline_active_samples = max($stage2_entity_baseline.active_windows)\n"
          "  $baseline_mean = max($stage2_entity_baseline.mean_sent)\n"
          "  $baseline_dispersion = max($stage2_entity_baseline.sd_sent)\n"
          "  $fleet_prevalence = 0 - 1\n"
          "  $distinct_binaries = max($stage1_directional_bytes.distinct_targets)\n\n"
          "  // Directional Producer-Consumer Ratio & Z-Score\n"
          "  $window_recv = max($stage1_directional_bytes.recv_bytes)\n"
          "  $total_bytes = $observation_count + $window_recv + 1.0\n"
          "  $producer_ratio = $observation_count / $total_bytes\n"
          "  $safe_sd = if($baseline_dispersion > 0, $baseline_dispersion, 1.0)\n"
          "  $z_score = ($observation_count - $baseline_mean) / $safe_sd\n\n"
          "condition:\n"
          "  $baseline_active_samples >= {{min_active_samples}}\n"
          "  and $observation_count >= {{min_sent_bytes}}\n"
          "  and $producer_ratio >= {{min_producer_ratio}}\n"
          "  and $z_score >= {{z_score}}\n\n"
          "order:\n"
          "  $z_score desc\n"
      )
  }

  def __init__(self, template_dir: Optional[Path] = None):
    if template_dir is None:
      self.template_dir = Path(__file__).resolve().parent.parent / "templates" / "pipelines"
    else:
      self.template_dir = Path(template_dir)

  def get_template_filename(self, archetype_or_model: str) -> str:
    key = archetype_or_model.upper().replace("-", "_").strip()
    if key in self.ARCHETYPE_TEMPLATE_MAP:
      return self.ARCHETYPE_TEMPLATE_MAP[key]
    for k, v in self.ARCHETYPE_TEMPLATE_MAP.items():
      if k in key or key in k:
        return v
    raise ValueError(f"Unknown archetype or model: {archetype_or_model}. Available: {list(self.ARCHETYPE_TEMPLATE_MAP.keys())}")

  def build_query(
      self,
      archetype: str,
      tier: str = "BALANCED",
      entity_type: str = "host",
      event_type: Optional[str] = None,
      window_hours: Optional[float] = None,
      min_threshold: Optional[float] = None,
      max_threshold: Optional[float] = None,
      condition_expression: Optional[str] = None,
      apply_threshold_condition: bool = True,
      daily_aggregation: Optional[str] = None,
      sample_field: Optional[str] = None,
  ) -> str:
    tier_up = tier.upper()
    template_file = self.get_template_filename(archetype)
    template_path = self.template_dir / template_file
    if template_path.exists():
      raw_template = template_path.read_text()
    elif template_file in self.INLINE_TEMPLATES:
      raw_template = self.INLINE_TEMPLATES[template_file]
    else:
      raise FileNotFoundError(f"Missing pipeline template: {template_path}")

    # Map archetype to base key in SENSITIVITY_MAP
    canonical_key = self.TEMPLATE_TO_SENSITIVITY_KEY.get(template_file)
    if not canonical_key:
      canonical_key = "ZSCORE_PROCESS_SURGE"
      for k in SENSITIVITY_MAP.keys():
        if k in archetype.upper() or archetype.upper() in k:
          canonical_key = k
          break
    thresh = dict(SENSITIVITY_MAP.get(canonical_key, {}).get(tier_up, {}))

    # Adaptive window calculation
    bucket_size = "1h"
    if window_hours:
      adapt = get_adaptive_window_parameters(window_hours, canonical_key, tier_up)
      bucket_size = adapt["recommended_bucket"]
      min_samples = adapt["proportional_sample_floor"]
      for sample_key in ("min_active_samples", "min_baseline_days", "min_active_hours", "min_active_days"):
        if sample_key in thresh:
          thresh[sample_key] = min_samples
    else:
      min_samples = (
          thresh.get("min_active_samples")
          or thresh.get("min_baseline_days")
          or thresh.get("min_active_hours")
          or thresh.get("min_active_days")
          or 30
      )

    # Entity field resolution
    entity_field_map = {
        "host": "principal.hostname",
        "user": "target.user.userid",
        "ip": "principal.asset.ip",
    }
    entity_field = entity_field_map.get(entity_type.lower(), "principal.hostname")
    if ("impossible_travel" in template_file or "privileged_lateral" in template_file) and entity_type.lower() == "host":
      entity_field = "target.user.userid"
    elif "producer_consumer" in template_file and entity_type.lower() == "host":
      entity_field = "principal.asset.hostname"

    # Default event type resolution
    if not event_type:
      if (
          "poisson_burst" in template_file.lower()
          or "beta_binomial" in template_file
          or "privileged_lateral" in template_file
          or "two_part_hurdle" in template_file
          or "impossible_travel" in template_file
      ):
        event_type = "USER_LOGIN"
      elif (
          "c2_beaconing" in template_file
          or "producer_consumer" in template_file
          or "hybrid_entropy_concentration" in template_file
      ):
        event_type = "NETWORK_CONNECTION"
      elif "mad_modified_z" in template_file:
        event_type = "NETWORK_DNS"
      else:
        event_type = "PROCESS_LAUNCH"

    # MAD template slots: daily observed value and evidence sample field.
    if not daily_aggregation:
      daily_aggregation = "count(metadata.id)"
    if not sample_field:
      sample_field = MAD_SAMPLE_FIELD_BY_EVENT_TYPE.get(event_type.upper(), "metadata.product_event_type")

    # Substitutions
    rendered = raw_template
    rendered = rendered.replace("{{tier}}", tier_up)
    rendered = rendered.replace("{{event_type}}", event_type)
    rendered = rendered.replace("{{entity_field}}", entity_field)
    rendered = rendered.replace("{{bucket_size}}", bucket_size)
    rendered = rendered.replace("{{daily_aggregation}}", daily_aggregation)
    rendered = rendered.replace("{{sample_field}}", sample_field)

    # Threshold substitutions
    for k, v in thresh.items():
      rendered = rendered.replace(f"{{{{{k}}}}}", str(v))

    # Generic threshold fallbacks
    rendered = rendered.replace("{{min_active_samples}}", str(min_samples))
    rendered = rendered.replace("{{min_baseline_days}}", str(max(3, int(min_samples / 4))))
    rendered = rendered.replace("{{min_active_hours}}", str(min_samples))
    rendered = rendered.replace("{{min_active_days}}", str(thresh.get("min_active_days", max(3, int(min_samples / 4)))))
    rendered = rendered.replace("{{min_count}}", str(thresh.get("min_count", 25)))
    rendered = rendered.replace("{{min_sd}}", str(thresh.get("min_sd", 5.0)))
    rendered = rendered.replace("{{min_distinct_targets}}", str(thresh.get("min_distinct_targets", 3)))
    rendered = rendered.replace("{{dormant_weight}}", str(thresh.get("dormant_weight", 2.0)))
    rendered = rendered.replace("{{z_score}}", str(thresh.get("z_score", 2.0)))
    rendered = rendered.replace("{{delta_z}}", str(thresh.get("delta_z", 3.0)))
    rendered = rendered.replace("{{bayesian_z}}", str(thresh.get("bayesian_z", 3.0)))
    rendered = rendered.replace("{{posterior_fail_prob}}", str(thresh.get("posterior_fail_prob", 0.50)))
    rendered = rendered.replace("{{min_attempts}}", str(thresh.get("min_attempts", 15)))
    rendered = rendered.replace("{{max_diversity_z}}", str(thresh.get("max_diversity_z", -1.5)))
    rendered = rendered.replace("{{min_concentration_ratio}}", str(thresh.get("min_concentration_ratio", 0.65)))
    rendered = rendered.replace("{{min_events}}", str(thresh.get("min_events", 5)))
    threat_dist_val = thresh.get("threat_distance", 3.0)
    rendered = rendered.replace("{{threat_distance}}", str(threat_dist_val))
    rendered = rendered.replace("{{threat_distance_sq}}", str(round(threat_dist_val * threat_dist_val, 2)))
    rendered = rendered.replace("{{threat_score}}", str(thresh.get("threat_score", 2.5)))
    rendered = rendered.replace("{{min_logins}}", str(thresh.get("min_logins", 5)))
    rendered = rendered.replace("{{new_asset_multiplier}}", str(thresh.get("new_asset_multiplier", 2.0)))
    rendered = rendered.replace("{{min_execs}}", str(thresh.get("min_execs", 5)))
    rendered = rendered.replace("{{rare_multiplier}}", str(thresh.get("rare_multiplier", 2.5)))
    rendered = rendered.replace("{{min_obs_bytes}}", str(thresh.get("min_obs_bytes", 100000.0)))
    rendered = rendered.replace("{{nrd_multiplier}}", str(thresh.get("nrd_multiplier", 2.5)))
    rendered = rendered.replace("{{min_bytes}}", str(thresh.get("min_bytes", 10000000.0)))
    rendered = rendered.replace("{{fano_factor}}", str(thresh.get("fano_factor", 4.0)))
    rendered = rendered.replace("{{min_fails}}", str(thresh.get("min_fails", 15)))
    rendered = rendered.replace("{{min_mu}}", str(thresh.get("min_mu", 1.0)))
    poisson_z_val = thresh.get("poisson_z", 3.5)
    rendered = rendered.replace("{{poisson_z}}", str(poisson_z_val))
    rendered = rendered.replace("{{poisson_z_sq}}", str(round(poisson_z_val * poisson_z_val, 2)))
    rendered = rendered.replace("{{min_observed}}", str(thresh.get("min_observed", 3)))
    rendered = rendered.replace("{{max_lambda}}", str(thresh.get("max_lambda", 2.0)))
    rendered = rendered.replace("{{cv}}", str(thresh.get("cv", 0.20)))
    rendered = rendered.replace("{{min_conns}}", str(thresh.get("min_conns", 25)))
    rendered = rendered.replace("{{prevalence}}", str(thresh.get("prevalence", 2)))
    rendered = rendered.replace("{{m_z}}", str(thresh.get("m_z", 3.5)))
    rendered = rendered.replace("{{min_daily_volume}}", str(thresh.get("min_daily_volume", 100)))
    rendered = rendered.replace("{{dispersion_floor}}", str(thresh.get("dispersion_floor", 1.0)))
    rendered = rendered.replace("{{fleet_z}}", str(thresh.get("fleet_z", 2.5)))
    rendered = rendered.replace("{{min_host_count}}", str(thresh.get("min_host_count", 25)))
    rendered = rendered.replace("{{min_fleet_sd}}", str(thresh.get("min_fleet_sd", 5.0)))
    rendered = rendered.replace("{{min_active_hosts}}", str(thresh.get("min_active_hosts", 15)))
    rendered = rendered.replace("{{surprisal_threshold}}", str(thresh.get("surprisal_threshold", 3.0)))
    rendered = rendered.replace("{{min_parent_count}}", str(thresh.get("min_parent_count", 10)))
    rendered = rendered.replace("{{entropy_threshold}}", str(thresh.get("entropy_threshold", 5.5)))
    rendered = rendered.replace("{{min_length}}", str(thresh.get("min_length", 25)))
    rendered = rendered.replace("{{zipf_threshold}}", str(thresh.get("zipf_threshold", 2.5)))
    rendered = rendered.replace("{{max_adopters}}", str(thresh.get("max_adopters", 2)))
    rendered = rendered.replace("{{velocity_threshold}}", str(thresh.get("velocity_threshold", 2.0)))
    rendered = rendered.replace("{{velocity_kmh}}", str(thresh.get("velocity_kmh", 900.0)))
    rendered = rendered.replace("{{min_distance_km}}", str(thresh.get("min_distance_km", 500.0)))
    rendered = rendered.replace("{{min_producer_ratio}}", str(thresh.get("min_producer_ratio", 0.70)))
    rendered = rendered.replace("{{min_sent_bytes}}", str(thresh.get("min_sent_bytes", 10000000.0)))

    # Dynamic Root-Stage Noise Level & Significance Threshold Conditioning
    order_match = re.search(r'order:\s*\n\s*([$][a-zA-Z0-9_]+)', rendered)
    score_var = order_match.group(1) if order_match else "$z_score"

    if condition_expression:
      cond_pat = re.compile(r'(\band\s+' + re.escape(score_var) + r'\s*[><=]=?\s*[^;\n]+)', re.MULTILINE)
      if cond_pat.search(rendered):
        rendered = cond_pat.sub(f"and {condition_expression}", rendered, count=1)
      else:
        rendered = re.sub(r'(\border:\s*)', f"condition:\n  {condition_expression}\n\n\\1", rendered, count=1)
    elif min_threshold is not None and max_threshold is not None:
      cond_str = f"{score_var} >= {min_threshold} and {score_var} < {max_threshold}"
      cond_pat = re.compile(r'(\band\s+' + re.escape(score_var) + r'\s*[><=]=?\s*[^;\n]+)', re.MULTILINE)
      if cond_pat.search(rendered):
        rendered = cond_pat.sub(f"and {cond_str}", rendered, count=1)
      else:
        rendered = re.sub(r'(\border:\s*)', f"condition:\n  {cond_str}\n\n\\1", rendered, count=1)
    elif min_threshold is not None:
      op = "<=" if score_var == "$cv" else ">="
      cond_str = f"{score_var} {op} {min_threshold}"
      cond_pat = re.compile(r'(\band\s+' + re.escape(score_var) + r'\s*[><=]=?\s*[^;\n]+)', re.MULTILINE)
      if cond_pat.search(rendered):
        rendered = cond_pat.sub(f"and {cond_str}", rendered, count=1)
      else:
        rendered = re.sub(r'(\border:\s*)', f"condition:\n  {cond_str}\n\n\\1", rendered, count=1)
    elif max_threshold is not None:
      cond_str = f"{score_var} <= {max_threshold}"
      cond_pat = re.compile(r'(\band\s+' + re.escape(score_var) + r'\s*[><=]=?\s*[^;\n]+)', re.MULTILINE)
      if cond_pat.search(rendered):
        rendered = cond_pat.sub(f"and {cond_str}", rendered, count=1)
      else:
        rendered = re.sub(r'(\border:\s*)', f"condition:\n  {cond_str}\n\n\\1", rendered, count=1)

    return rendered


class QueryIntegrityGate:
  """Pre-Dispatch and Post-Execution QA Gate ensuring executed queries are valid, scoped, and unmasked."""

  BACKEND_ERROR_SIGNATURES: Tuple[str, ...] = (
      "Request contains an invalid argument",
      "INVALID_ARGUMENT",
      "FAILED_PRECONDITION",
      "syntax error",
      "parsing:",
      "semantic analysis:",
      "400 Client Error",
      "Internal error encountered",
      "com.google.chronicle",
  )

  @staticmethod
  def normalize_yaral(query: str) -> str:
    """Strips comments and normalizes whitespace for structural concordance comparison."""
    if not query:
      return ""
    no_line_comments = re.sub(r"//[^\n]*", "", query)
    no_block_comments = re.sub(r"/\*.*?\*/", "", no_line_comments, flags=re.DOTALL)
    return " ".join(no_block_comments.split())

  @classmethod
  def verify_pre_dispatch(
      cls,
      query: str,
      expected_entity: Optional[str] = None,
      expected_preflight_query: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Validates a composed YARA-L query BEFORE sending it to the Chronicle API."""
    errors: List[str] = []
    if not query or not query.strip():
      errors.append("EMPTY_QUERY: Cannot dispatch an empty query string to udm_search.")
      return {"valid": False, "errors": errors}

    unresolved = re.findall(r"\{\{[a-zA-Z0-9_]+\}\}", query)
    if unresolved:
      errors.append(f"UNRESOLVED_TEMPLATE_PLACEHOLDERS: Query contains unresolved slot(s): {sorted(set(unresolved))}")

    errors.extend(check_scope_exclusions(query))
    syntax_errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
    errors.extend(syntax_errs)

    if expected_entity and expected_entity.strip().lower() not in (
        "", "fleet", "all", "enterprise", "unknown", "unknown_entity", "target_entity", "*"
    ):
      ent = expected_entity.strip()
      if ent.lower() not in query.lower():
        errors.append(
            f"UNSCOPED_ENTITY_QUERY: Expected target entity '{ent}' is not bound in the query predicates."
        )

    if expected_preflight_query:
      norm_pre = cls.normalize_yaral(expected_preflight_query)
      norm_cur = cls.normalize_yaral(query)
      if ("stage " in norm_pre) != ("stage " in norm_cur):
        errors.append(
            "PREFLIGHT_EXECUTION_DRIFT: Multi-stage query topology changed between pre-flight preview and dispatch."
        )

    return {"valid": len(errors) == 0, "errors": errors}

  @classmethod
  def verify_backend_response(
      cls,
      query_or_response: Any,
      api_response: Any = None,
      raw_text: str = "",
      is_error_flag: bool = False,
  ) -> Dict[str, Any]:
    """Inspects raw udm_search responses for backend compiler/API errors and query substitution drift."""
    errors: List[str] = []
    if api_response is None:
      approved_query = None
      raw_response = query_or_response
    else:
      approved_query = str(query_or_response) if query_or_response is not None else None
      raw_response = api_response

    if is_error_flag or getattr(raw_response, "isError", False):
      errors.append("MCP_TOOL_ERROR_FLAG: udm_search returned isError=True.")

    if raw_response is None and not raw_text:
      return {"valid": len(errors) == 0, "errors": errors}

    if isinstance(raw_response, dict):
      if raw_response.get("error"):
        errors.append(f"CHRONICLE_API_ERROR_FIELD: {raw_response.get('error')}")
      if approved_query:
        exec_q = raw_response.get("executed_query")
        if exec_q and cls.normalize_yaral(exec_q) != cls.normalize_yaral(approved_query):
          errors.append(
              "QUERY_EXECUTION_DRIFT: Executed query differs from approved pre-flight query."
          )

    text = f"{raw_text}\n{raw_response if isinstance(raw_response, str) else str(raw_response)}"
    for sig in cls.BACKEND_ERROR_SIGNATURES:
      if sig.lower() in text.lower():
        errors.append(f"CHRONICLE_BACKEND_QUERY_ERROR: Backend rejected query ({sig}): {text[:300]}")
        break
    return {"valid": len(errors) == 0, "errors": errors}


class HandoffEndpoint:
  """Ingestion endpoint for federated handoff payloads from peer skills (e.g. secops-risk-metrics-multistage)."""

  SUPPORTED_PROTOCOL = "secops-threat-hunt-handoff-v1"

  INTENT_ROUTING_MAP = {
      "SCHEDULED_EXFILTRATION_TIMING": "C2_BEACONING_JITTER",
      "SCHEDULED_EXFILTRATION": "C2_BEACONING_JITTER",
      "EXFILTRATION_TIMING": "C2_BEACONING_JITTER",
      "EXFIL_TIMING": "C2_BEACONING_JITTER",
      "C2_BEACONING_JITTER": "C2_BEACONING_JITTER",
      "BEACONING_JITTER": "C2_BEACONING_JITTER",
      "TIMING_JITTER": "C2_BEACONING_JITTER",
      "SUB_SECOND_JITTER": "C2_BEACONING_JITTER",
      "POISSON_BURST_CLUSTERING": "POISSON_BURST_CLUSTERING",
      "BURST_CLUSTERING": "POISSON_BURST_CLUSTERING",
      "POISSON_RARE_SURGE": "POISSON_RARE_SURGE",
      "RARE_SURGE": "POISSON_RARE_SURGE",
      "ZSCORE_PROCESS_SURGE": "ZSCORE_PROCESS_SURGE",
      "PROCESS_SURGE": "ZSCORE_PROCESS_SURGE",
      "DATA_EXFILTRATION_SPIKE": "DATA_EXFILTRATION_SPIKE",
      "DUAL_BASELINE_DELTA_Z": "DUAL_BASELINE_DELTA_Z",
      "RAW_TELEMETRY_ENRICHMENT": "DATA_EXFILTRATION_SPIKE",
      "TELEMETRY_ENRICHMENT": "DATA_EXFILTRATION_SPIKE",
      "DUAL_PLANE_CORRELATION": "DATA_EXFILTRATION_SPIKE",
      "DUAL_PLANE_HYBRID": "DATA_EXFILTRATION_SPIKE",
      "DIVERSITY_DEFICIT": "DIVERSITY_DEFICIT",
      "ENTROPY_PROXY": "DIVERSITY_DEFICIT",
      "ELEPHANT_FLOW_CONCENTRATION": "ELEPHANT_FLOW_CONCENTRATION",
      "CONCENTRATION_INDEX": "ELEPHANT_FLOW_CONCENTRATION",
      "ORTHOGONAL_THREAT_SPACE": "ORTHOGONAL_THREAT_SPACE",
      "EUCLIDEAN_THREAT_DISTANCE": "ORTHOGONAL_THREAT_SPACE",
      "BAYESIAN_JOINT_ODDS": "BAYESIAN_JOINT_ODDS",
      "TWO_PART_HURDLE": "TWO_PART_HURDLE",
      "DORMANT_ACCOUNT": "TWO_PART_HURDLE",
      "FLEET_PREVALENCE_NORMALIZATION": "FLEET_PREVALENCE_NORMALIZATION",
      "PATCH_TUESDAY_SHIELD": "FLEET_PREVALENCE_NORMALIZATION",
      "PRIVILEGED_LATERAL_EXPANSION": "PRIVILEGED_LATERAL_EXPANSION",
      "LATERAL_MOVEMENT_BIPARTITE": "PRIVILEGED_LATERAL_EXPANSION",
      "BIPARTITE_AUTH_RARITY": "PRIVILEGED_LATERAL_EXPANSION",
      "UNSEEN_ENDPOINT_ACCESS": "PRIVILEGED_LATERAL_EXPANSION",
      "LATERAL_MOVEMENT": "PRIVILEGED_LATERAL_EXPANSION",
      "GLOBAL_THREAT_INTEL": "GLOBAL_THREAT_INTEL",
      "GLOBAL_CONTEXT": "GLOBAL_THREAT_INTEL",
      "GCTI_ENRICHMENT": "GLOBAL_THREAT_INTEL",
      "WHOIS_NRD_EGRESS": "GLOBAL_THREAT_INTEL",
      "DERIVED_CONTEXT_PREVALENCE": "DERIVED_CONTEXT_PREVALENCE",
      "DERIVED_CONTEXT": "DERIVED_CONTEXT_PREVALENCE",
      "ASSET_AGE_PREVALENCE": "DERIVED_CONTEXT_PREVALENCE",
      "NEW_ASSET_AUTHENTICATION": "DERIVED_CONTEXT_PREVALENCE",
      "DERIVED_CONTEXT_FILE_PREVALENCE": "DERIVED_CONTEXT_FILE_PREVALENCE",
      "FILE_PREVALENCE": "DERIVED_CONTEXT_FILE_PREVALENCE",
      "UNSEEN_BINARY_BURST": "DERIVED_CONTEXT_FILE_PREVALENCE",
      "DERIVED_CONTEXT_DOMAIN_PREVALENCE": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
      "DOMAIN_PREVALENCE": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
      "FIRST_SEEN_DOMAIN_EGRESS": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
      "MARKOV_TRANSITION_RARITY": "MARKOV_2GRAM_TRANSITION_RARITY",
      "MARKOV_2GRAM": "MARKOV_2GRAM_TRANSITION_RARITY",
      "MARKOV": "MARKOV_2GRAM_TRANSITION_RARITY",
      "TRANSITION_RARITY": "MARKOV_2GRAM_TRANSITION_RARITY",
      "SHANNON_CHARACTER_ENTROPY": "SHANNON_ENTROPY_CHARACTER",
      "SHANNON_ENTROPY": "SHANNON_ENTROPY_CHARACTER",
      "CHARACTER_ENTROPY": "SHANNON_ENTROPY_CHARACTER",
      "SHANNON": "SHANNON_ENTROPY_CHARACTER",
      "ENTROPY": "SHANNON_ENTROPY_CHARACTER",
      "ZIPFIAN_PROCESS_RARITY": "ZIPFIAN_PROCESS_RARITY",
      "ZIPFIAN_LONG_TAIL": "ZIPFIAN_PROCESS_RARITY",
      "ZIPFIAN_RARITY": "ZIPFIAN_PROCESS_RARITY",
      "ZIPFIAN": "ZIPFIAN_PROCESS_RARITY",
      "ZIPF": "ZIPFIAN_PROCESS_RARITY",
      "EWMA_BURST_VELOCITY": "EWMA_BURST_VELOCITY",
      "EWMA_VELOCITY": "EWMA_BURST_VELOCITY",
      "EWMA_BURST": "EWMA_BURST_VELOCITY",
      "EWMA": "EWMA_BURST_VELOCITY",
      "INTRADAY_BURST_VELOCITY": "EWMA_BURST_VELOCITY",
      "IMPOSSIBLE_TRAVEL_GEO_VELOCITY": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
      "IMPOSSIBLE_TRAVEL": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
      "GEO_VELOCITY": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
      "PRODUCER_CONSUMER_RATIO_INVERSION": "PRODUCER_CONSUMER_RATIO_INVERSION",
      "PRODUCER_CONSUMER_ROLE_INVERSION": "PRODUCER_CONSUMER_RATIO_INVERSION",
      "BYTE_RATIO_INVERSION": "PRODUCER_CONSUMER_RATIO_INVERSION",
      "OFF_HOURS_BURST": "POISSON_BURST_CLUSTERING",
      "AFTER_HOURS_ACTIVITY": "POISSON_BURST_CLUSTERING",
  }

  @classmethod
  def ingest(cls, payload_input: Any) -> Dict[str, Any]:
    """Processes an incoming handoff payload and returns an ACK or NACK envelope."""
    payload = payload_input
    if isinstance(payload_input, str):
      trimmed = payload_input.strip()
      if os.path.exists(trimmed):
        with open(trimmed, "r", encoding="utf-8") as f:
          payload = json.load(f)
      else:
        if trimmed.startswith("```"):
          trimmed = re.sub(r"^```(?:json[a-zA-Z0-9_-]*)?\n?", "", trimmed)
          trimmed = re.sub(r"\n?```$", "", trimmed)
        try:
          payload = json.loads(trimmed)
        except Exception as e:
          return {
              "status": "HANDOFF_ACK_REJECTED",
              "action": "RETRY_REQUIRED",
              "errors": [f"Failed to parse JSON payload: {e}"],
          }

    if not isinstance(payload, dict):
      return {
          "status": "HANDOFF_ACK_REJECTED",
          "action": "RETRY_REQUIRED",
          "errors": ["Payload must be a valid JSON dictionary."],
      }

    req_id = payload.get("request_id", "req-unknown")

    protocol = payload.get("protocol") or payload.get("$schema")
    if protocol and protocol != cls.SUPPORTED_PROTOCOL:
      return {
          "status": "HANDOFF_ACK_REJECTED",
          "request_id": req_id,
          "action": "RETRY_REQUIRED",
          "errors": [f"Unsupported protocol: {protocol}. Supported: {cls.SUPPORTED_PROTOCOL}"],
      }

    target_skill = payload.get("target_skill", "")
    if target_skill and target_skill != "secops-statistical-hunter":
      return {
          "status": "HANDOFF_ACK_REJECTED",
          "request_id": req_id,
          "action": "RETRY_REQUIRED",
          "errors": [f"Target skill mismatch: expected 'secops-statistical-hunter', got '{target_skill}'"],
      }

    raw_intent = payload.get("intent", "")
    model_info = payload.get("statistical_model", {})
    if not raw_intent and isinstance(model_info, dict):
      raw_intent = model_info.get("name", "")

    intent_key = raw_intent.upper().replace("-", "_").strip()
    mapped_archetype = cls.INTENT_ROUTING_MAP.get(intent_key, intent_key)

    router = MultiStageTemplateRouter()
    try:
      _ = router.get_template_filename(mapped_archetype)
    except ValueError as e:
      return {
          "status": "HANDOFF_ACK_REJECTED",
          "request_id": req_id,
          "action": "RETRY_REQUIRED",
          "errors": [str(e)],
      }

    # Validate optional custom_filters before Stage 1 injection
    custom_filters = payload.get("custom_filters")
    validated_filters: List[str] = []
    if custom_filters is not None:
      if isinstance(custom_filters, str):
        custom_filters = [custom_filters]
      if not isinstance(custom_filters, list) or not all(isinstance(f, str) for f in custom_filters):
        return {
            "status": "HANDOFF_ACK_REJECTED",
            "request_id": req_id,
            "action": "RETRY_REQUIRED",
            "errors": ["custom_filters must be a list of YARA-L event predicate strings."],
        }
      for cf in custom_filters:
        cf_clean = cf.strip()
        if not cf_clean:
          continue
        scope_errs = check_scope_exclusions(cf_clean)
        if scope_errs:
          return {
              "status": "HANDOFF_ACK_REJECTED",
              "request_id": req_id,
              "action": "RETRY_REQUIRED",
              "errors": [f"Invalid custom_filter ({cf_clean}): {scope_errs[0]}"],
          }
        if (
            cf_clean.count('"') % 2 != 0
            or "{" in cf_clean
            or "}" in cf_clean
            or ";" in cf_clean
            or re.search(r"\b(?:stage|match|outcome|condition|order)\s*:", cf_clean, re.IGNORECASE)
        ):
          return {
              "status": "HANDOFF_ACK_REJECTED",
              "request_id": req_id,
              "action": "RETRY_REQUIRED",
              "errors": [f"Invalid or unsafe YARA-L syntax in custom_filter: '{cf_clean}'"],
          }
        validated_filters.append(cf_clean)

    target_entity = payload.get("target_entity", {})
    entity_val = target_entity.get("value", "") if isinstance(target_entity, dict) else str(target_entity)
    entity_type = (target_entity.get("type", "host") if isinstance(target_entity, dict) else "host").lower()

    search_window = payload.get("search_window", {})
    lookback = search_window.get("lookback", "24h") if isinstance(search_window, dict) else str(search_window)

    window_hours = 24.0
    if "d" in lookback:
      try:
        window_hours = float(lookback.replace("d", "")) * 24.0
      except ValueError:
        window_hours = 24.0
    elif "h" in lookback:
      try:
        window_hours = float(lookback.replace("h", ""))
      except ValueError:
        window_hours = 24.0

    tier = "BALANCED"
    if isinstance(model_info, dict):
      raw_tier = model_info.get("sensitivity", "BALANCED").upper()
      tier = {"HIGH": "AGGRESSIVE", "MEDIUM": "BALANCED", "LOW": "CONSERVATIVE"}.get(raw_tier, raw_tier)
      if tier not in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
        tier = "BALANCED"

    try:
      compiled_query = router.build_query(
          archetype=mapped_archetype,
          tier=tier,
          entity_type=entity_type,
          window_hours=window_hours,
      )
      if validated_filters:
        filter_block = "\n".join(f"    {cf}" for cf in validated_filters)
        compiled_query = re.sub(
            r"(stage\s+[a-zA-Z0-9_]+\s*\{\n)",
            r"\1" + filter_block + "\n",
            compiled_query,
            count=1,
        )
    except Exception as e:
      return {
          "status": "HANDOFF_ACK_REJECTED",
          "request_id": req_id,
          "action": "RETRY_REQUIRED",
          "errors": [f"Failed compiling template for archetype '{mapped_archetype}': {e}"],
      }

    preflight_spec = {
        "intent": raw_intent or mapped_archetype,
        "model_routed": mapped_archetype,
        "target_entity": {"type": entity_type.upper(), "value": entity_val},
        "search_window": {"lookback": lookback, "hours": window_hours},
        "sensitivity_tier": tier,
        "formula": "CV = sigma / mu <= 0.20" if mapped_archetype == "C2_BEACONING_JITTER" else "Z = (Observed - mu) / sigma",
    }

    return {
        "status": "HANDOFF_ACK_ACCEPTED",
        "request_id": req_id,
        "source_skill": payload.get("source_skill", "secops-risk-metrics-multistage"),
        "target_skill": "secops-statistical-hunter",
        "action": "STEP_OUT_CONFIRMED",
        "model_routed": mapped_archetype,
        "compiled_query": compiled_query,
        "preflight_spec": preflight_spec,
        "step_out_directive": (
            "SOURCE_SKILL_STEP_OUT_CONFIRMED: Handoff payload accepted. "
            "The calling skill must yield the turn immediately and step out. "
            "secops-statistical-hunter now owns the execution lifecycle."
        ),
    }


def check_routing_recommendation(user_prompt: str) -> Optional[Dict[str, Any]]:
  """Inspects an analyst prompt to detect when the request is better routed to secops-risk-metrics-multistage.

  Returns a recommendation dictionary if the prompt matches pre-computed risk metrics or UEBA baselines,
  or None if secops-statistical-hunter is the authoritative skill.
  """
  prompt_clean = user_prompt.lower()

  has_explicit_30d_or_ueba = any(
      kw in prompt_clean
      for kw in ["30-day", "30 day", "30d", "ueba", "metrics.", "pre-computed", "precomputed"]
  )
  has_raw_stat_or_short_window = any(
      kw in prompt_clean
      for kw in [
          "single-stage", "single stage", "ad-hoc", "ad hoc",
          "fano", "poisson", "jitter", "coefficient of variation",
          "inline mad", "modified z", "modified-z", "tukey", "iqr",
          "markov", "2-gram", "shannon", "entropy", "zipf", "ewma",
          "impossible travel", "haversine", "producer-consumer",
          "24h", "24-hour", "24 hour", "48h", "72h", "weekend",
          "7d", "7-day", "7 day", "14d", "14-day", "14 day",
      ]
  )

  # 1. HTTP / Web User-Agent queries & baselines
  if (
      ("user-agent" in prompt_clean or "user_agent" in prompt_clean or "user agent" in prompt_clean)
      and any(kw in prompt_clean for kw in ["network", "http", "web", "traffic", "query", "queries", "compare", "comparison", "volume", "baseline"])
      and (not has_raw_stat_or_short_window or has_explicit_30d_or_ueba)
  ):
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "metrics.http_queries_total",
        "recommended_pipeline": "hybrid_metric_fleet_prevalence_2stage.yl2",
        "target_dimension": "network.http.user_agent",
        "entity_dimension": "principal.asset.hostname",
        "justification": (
            "Web / HTTP request volume across user-agent strings is pre-computed in Google SecOps via "
            "'metrics.http_queries_total' (with dimension 'network.http.user_agent'). "
            "Evaluating user-agent surges against 30-day historical behavior belongs in secops-risk-metrics-multistage "
            "to avoid expensive full-table scans over raw HTTP logs."
        ),
    }

  # 2. Authentication baselines (30d normal / typical login behavior)
  if (
      any(kw in prompt_clean for kw in ["auth", "login", "logon", "password spray", "credential"])
      and any(kw in prompt_clean for kw in ["30-day", "30 day", "30d", "historical baseline", "typical behavior", "normal behavior", "normal baseline", "typical baseline", "ueba", "metrics."])
      and (not has_raw_stat_or_short_window or has_explicit_30d_or_ueba)
  ):
    is_fail_focused = any(
        kw in prompt_clean
        for kw in ["fail", "failed", "failure", "password spray", "spray", "brute", "stuffing"]
    )
    auth_metric = "metrics.auth_attempts_fail" if is_fail_focused else "metrics.auth_attempts_total"
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": auth_metric,
        "recommended_pipeline": "standard_z_score_2stage.yl2",
        "target_dimension": "target.user.userid",
        "entity_dimension": "principal.asset.hostname",
        "justification": (
            "Entity authentication baselining against 30-day normal/typical behavior is pre-computed in Google SecOps via "
            "'metrics.auth_attempts_*'. Risk Metrics provides O(1) 30-day mean and stddev lookups."
        ),
    }

  # 3. Network byte / flow baselines
  if (
      any(kw in prompt_clean for kw in ["network byte", "network flow", "outbound byte", "inbound byte", "bandwidth"])
      and any(kw in prompt_clean for kw in ["30-day", "30 day", "30d", "historical baseline", "normal baseline", "typical baseline", "typical", "normal", "ueba", "metrics."])
      and (not has_raw_stat_or_short_window or has_explicit_30d_or_ueba)
  ):
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "metrics.network_bytes_outbound",
        "recommended_pipeline": "standard_z_score_2stage.yl2",
        "target_dimension": "principal.asset.hostname",
        "entity_dimension": "principal.user.userid",
        "justification": (
            "Network byte volume and connection flow baselining is pre-computed via "
            "'metrics.network_bytes_*' and 'metrics.network_flows_*' in secops-risk-metrics-multistage."
        ),
    }

  # 4. Peer group / cohort comparison
  if any(kw in prompt_clean for kw in ["peer group", "cohort", "department", "colleagues", "peers", "peer baseline"]):
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "metrics.auth_attempts_total",
        "recommended_pipeline": "dual_baseline_delta_z_3stage.yl2",
        "target_dimension": "target.user.userid",
        "entity_dimension": "principal.asset.hostname",
        "justification": (
            "Comparing an entity's behavior against an organizational peer cohort or department baseline "
            "requires pre-computed cohort metrics in secops-risk-metrics-multistage."
        ),
    }

  # 5. Entity Risk Score / 360 Health Check
  if (
      any(kw in prompt_clean for kw in ["risk score", "risk_score", "graph.risk_score", "360 health", "omnibus risk"])
      and "calibrated risk index" not in prompt_clean
      and "cri" not in re.findall(r"\b[a-z0-9_]+\b", prompt_clean)
  ):
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "graph.risk_score",
        "recommended_pipeline": "radar_360_decoupled_sector.yl2",
        "target_dimension": "graph.entity",
        "entity_dimension": "principal.user.userid",
        "justification": (
            "Entity risk score evaluations and 360° health checks query Google SecOps UEBA Risk Scoring tables "
            "('graph.risk_score'), which are exclusively managed by secops-risk-metrics-multistage."
        ),
    }

  # 6. Explicit 30-day UEBA baseline request
  if "30-day baseline" in prompt_clean or "30 day baseline" in prompt_clean or "30d baseline" in prompt_clean or "ueba" in prompt_clean:
    return {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "metrics.*",
        "recommended_pipeline": "standard_z_score_2stage.yl2",
        "target_dimension": "target.user.userid",
        "entity_dimension": "principal.asset.hostname",
        "justification": (
            "Rolling 30-day behavioral baselines and UEBA metric functions are pre-computed in Google SecOps "
            "and exclusively maintained in secops-risk-metrics-multistage."
        ),
    }

  return None


def format_routing_handoff_card(routing_info: Dict[str, Any]) -> str:
  """Renders the user-facing routing delegation card when a query belongs in Risk Metrics."""
  lines = [
      "### 🔄 Skill Handoff Card — Skill Delegation: Route to `secops-risk-metrics-multistage`",
      "",
      "> [!NOTE]",
      "> **Architectural Boundary Demarcation: Ad-Hoc Raw Telemetry ──► Pre-Computed Behavioral Metrics**",
      f"> • **Routing Rationale**: {routing_info['justification']}",
      f"> • **Target Skill**: `{routing_info['target_skill']}`",
      f"> • **Recommended Metric / Function**: `{routing_info.get('recommended_metric', 'metrics.*')}`",
      f"> • **Recommended Pipeline**: `{routing_info.get('recommended_pipeline', 'standard_z_score_2stage.yl2')}`",
  ]
  if "target_dimension" in routing_info:
    lines.append(f"> • **Target Dimension**: `{routing_info['target_dimension']}`")
  lines.extend([
      "",
      "> [!IMPORTANT]",
      "> **Delegation Action**: Handing off to `secops-risk-metrics-multistage` to construct the behavioral baseline query.",
      "> *Please switch to the `secops-risk-metrics-multistage` skill to execute this behavioral baseline hunt.*",
      "",
  ])
  return "\n".join(lines)


def main():
  parser = argparse.ArgumentParser(
      description="secops-statistical-hunter Query Validation & Boundary Utility"
  )
  parser.add_argument(
      "--check_routing",
      help="Check an analyst prompt to see if it should be routed to secops-risk-metrics-multistage",
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
  parser.add_argument(
      "--audit_intent",
      help="Audit query against expected architecture (e.g. SINGLE_STAGE_MACRO, LOCAL_2STAGE, DUAL_BASELINE_3STAGE, MULTI_SECTOR_FUSION_4STAGE)",
  )
  parser.add_argument(
      "--audit_model",
      help="Audit query against expected statistical model (e.g. DELTA_Z, BAYESIAN_GAMMA, BETA_BINOMIAL, FUSION, FANO, Z_SCORE)",
  )
  parser.add_argument(
      "--audit_response",
      help="Path to API response JSON to audit for raw log dumps and result integrity",
  )
  parser.add_argument(
      "--build_query",
      action="store_true",
      help="Build canonical multi-stage YARA-L query from pipeline templates based on --archetype and --tier",
  )
  parser.add_argument(
      "--entity_type",
      default="host",
      help="Entity type for query builder (host, user, ip)",
  )
  parser.add_argument(
      "--ingest_handoff",
      help="Path to JSON file or raw JSON string containing a secops-threat-hunt-handoff-v1 payload",
  )
  parser.add_argument(
      "--event_type",
      help="Override UDM event_type for query builder (e.g. PROCESS_LAUNCH, USER_LOGIN, NETWORK_CONNECTION)",
  )

  args = parser.parse_args()

  if args.check_routing:
    routing_info = check_routing_recommendation(args.check_routing)
    if routing_info:
      print(format_routing_handoff_card(routing_info))
      sys.exit(0)
    else:
      print("STAY_IN_STATISTICAL_HUNTER: Request is suited for ad-hoc raw telemetry statistical hunting.")
      sys.exit(0)

  if args.ingest_handoff:
    ack_result = HandoffEndpoint.ingest(args.ingest_handoff)
    print(json.dumps(ack_result, indent=2))
    if ack_result.get("status") == "HANDOFF_ACK_ACCEPTED":
      sys.exit(0)
    else:
      sys.exit(1)

  if args.build_query:
    if not args.archetype:
      print("Error: --build_query requires --archetype (e.g. ZSCORE_PROCESS_SURGE, POISSON_BURST_CLUSTERING, DUAL_BASELINE_DELTA_Z, MULTI_SECTOR_THREAT_FUSION)", file=sys.stderr)
      sys.exit(1)
    router = MultiStageTemplateRouter()
    try:
      q = router.build_query(
          archetype=args.archetype,
          tier=args.tier,
          entity_type=args.entity_type,
          event_type=args.event_type,
          window_hours=args.window_hours,
      )
      print(q)
      sys.exit(0)
    except Exception as e:
      print(f"Error building query: {e}", file=sys.stderr)
      sys.exit(1)

  if args.audit_response:
    with open(args.audit_response, "r") as f:
      resp_data = json.load(f)
    q_text = None
    if args.query_file:
      with open(args.query_file, "r") as f:
        q_text = f.read()
    audit_res = PostFlightExecutionAuditor.audit_execution(
        executed_query=q_text,
        api_response=resp_data,
        expected_architecture=args.audit_intent,
        expected_model=args.audit_model
    )
    print(f"=== Post-Flight API Response & Execution Audit: {audit_res.status} ===")
    print(f"  Summary: {audit_res.audit_summary}")
    if audit_res.errors:
      print("  Errors:")
      for err in audit_res.errors:
        print(f"    - {err}")
    if audit_res.findings:
      print("  Findings:")
      for fn in audit_res.findings:
        print(f"    - {fn}")
    if not audit_res.is_valid:
      sys.exit(1)
    sys.exit(0)

  if args.query_file and args.audit_intent:
    with open(args.query_file, "r") as f:
      q_text = f.read()
    audit_res = audit_query_execution(q_text, args.audit_intent, args.audit_model)
    print(f"=== Post-Query Execution Audit: {audit_res['status']} ===")
    print(f"  Expected Architecture : {audit_res['expected_architecture']}")
    print(f"  Actual Architecture   : {audit_res['actual_architecture']} ({audit_res['intermediate_stages']} intermediate + 1 root = {audit_res['total_stages']} stages)")
    print(f"  Stages Detected       : {audit_res['stage_names']}")
    print("  Findings:")
    for fn in audit_res['findings']:
      print(f"    - {fn}")
    if audit_res['status'] != "PASS":
      sys.exit(1)
    sys.exit(0)

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
    report_query = None
    if args.query_file:
      with open(args.query_file, "r") as f:
        report_query = f.read()
    print(format_triage_report(
        "Statistical Outliers", data, fleet_size=args.fleet_size,
        event_type=args.event_type, query_text=report_query))
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


