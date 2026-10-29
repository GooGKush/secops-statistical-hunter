# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract and regression tests for WS8-01 (target-entity binding) and WS8-04 (EXFILTRATION_IQR_OUTLIER routing)."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from multistage_query_builder import (  # pylint: disable=wrong-import-position
    HandoffEndpoint,
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    RETIRED_ARCHETYPES,
)


def _split_stages_and_root(query: str) -> Tuple[List[Tuple[str, str]], str]:
  """Splits a multi-stage YARA-L query into [(stage_name, stage_body), ...] and unwrapped root_body."""
  code_only = re.sub(r"//[^\n]*", "", query)
  stages: List[Tuple[str, str]] = []
  last_end = 0
  for m in re.finditer(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", code_only, flags=re.DOTALL):
    stages.append((m.group(1), m.group(2)))
    last_end = m.end()
  return stages, code_only[last_end:]


class TestWS801AndWS804HandoffContracts(unittest.TestCase):
  """Verifies WS8-01 target-entity binding across all templates/intents and WS8-04 EXFILTRATION_IQR_OUTLIER routing."""

  FLEET_ROOT_SCOPED_TEMPLATES: Dict[str, str] = {
      "dual_baseline_delta_z_3stage.yl2": "$host",
      "bayesian_gamma_shrinkage_4stage.yl2": "$host",
      "beta_binomial_failure_4stage.yl2": "$user",
      "multi_sector_threat_fusion_4stage.yl2": "$entity",
      "zipfian_process_rarity_2stage.yl2": "$host",
      "markov_2gram_transition_rarity_2stage.yl2": "$host",
      "shannon_entropy_character_2stage.yl2": "$entity",
      "c2_beaconing_jitter_2stage.yl2": "$src_ip",
      "flow_gap_ratio_screen_2stage.yl2": "$src_ip",
      "ewma_burst_velocity_2stage.yl2": "$entity",
  }

  SELF_BASELINE_TEMPLATES = (
      "poisson_burst_clustering_2stage.yl2",
      "poisson_rare_surge_2stage.yl2",
      "zscore_process_surge_2stage.yl2",
      "mad_modified_z_4stage.yl2",
      "iqr_tukey_skew_fences_3stage.yl2",
      "log_normal_volume_surge_2stage.yl2",
      "privileged_lateral_expansion_2stage.yl2",
      "two_part_hurdle_2stage.yl2",
      "hybrid_entropy_concentration_2stage.yl2",
      "hour_of_day_profile_3stage.yl2",
      "producer_consumer_ratio_inversion_2stage.yl2",
      "burst_z_screen_2stage.yl2",
      "long_string_screen_2stage.yl2",
      "global_threat_intel_enrichment_3stage.yl2",
      "derived_context_prevalence_3stage.yl2",
      "derived_context_file_prevalence_3stage.yl2",
      "derived_context_domain_prevalence_3stage.yl2",
  )

  def test_ws8_04_exfiltration_iqr_outlier_routes_to_iqr_tukey_skew_fences_with_formula(self) -> None:
    """EXFILTRATION_IQR_OUTLIER and aliases route to IQR_TUKEY_SKEW_FENCES (never coerced to C2_BEACONING_JITTER)."""
    for intent in (
        "EXFILTRATION_IQR_OUTLIER",
        "IQR_TUKEY_SKEW_FENCES",
        "TUKEY_IQR_OUTLIER",
        "QUANTILE_IQR_SKEW",
    ):
      with self.subTest(intent=intent):
        self.assertEqual(HandoffEndpoint.INTENT_ROUTING_MAP.get(intent), "IQR_TUKEY_SKEW_FENCES")
        payload = {
            "protocol": "secops-threat-hunt-handoff-v1",
            "request_id": f"req-ws804-{intent.lower()}",
            "source_skill": "secops-risk-metrics-multistage",
            "target_skill": "secops-statistical-hunter",
            "intent": intent,
            "target_entity": {"type": "HOSTNAME", "value": "wkstn-prod-042"},
            "search_window": {"lookback": "14d"},
            "statistical_model": {"name": intent, "sensitivity": "BALANCED"},
            "justification": "Macro exfiltration IQR outlier stepped down to micro Tukey fences.",
        }
        ack = HandoffEndpoint.ingest(payload)
        self.assertEqual(ack["status"], "HANDOFF_ACK_ACCEPTED")
        self.assertEqual(ack["model_routed"], "IQR_TUKEY_SKEW_FENCES")
        self.assertEqual(
            ack["preflight_spec"]["formula"],
            "tukey_excess_z = (obs - upper_fence) / safe_scale >= 1.0",
        )
        self.assertIn("stage quantile_fences", ack["compiled_query"])
        self.assertIn("$fence_z", ack["compiled_query"])
        gate = QueryIntegrityGate.verify_pre_dispatch(ack["compiled_query"], expected_entity="wkstn-prod-042")
        self.assertEqual(gate, {"valid": True, "errors": []})

  def test_ws8_04_preflight_formula_accuracy_across_archetypes(self) -> None:
    """preflight_spec['formula'] matches the routed model's mathematical gate."""
    cases = [
        ("EXFILTRATION_IQR_OUTLIER", "tukey_excess_z = (obs - upper_fence) / safe_scale >= 1.0"),
        ("DATA_EXFILTRATION_SPIKE", "m_z_score = 0.6745 * (obs - median) / MAD >= 3.5"),
        ("RAW_TELEMETRY_ENRICHMENT", "m_z_score = 0.6745 * (obs - median) / MAD >= 3.5"),
        ("SCHEDULED_EXFILTRATION_TIMING", "CV = sigma / mu <= 0.20"),
        ("FLOW_GAP_RATIO_SCREEN", "CV = sigma / mu <= 0.20"),
    ]
    for intent, expected_formula in cases:
      with self.subTest(intent=intent):
        ack = HandoffEndpoint.ingest({
            "protocol": "secops-threat-hunt-handoff-v1",
            "request_id": f"req-formula-{intent.lower()}",
            "source_skill": "secops-risk-metrics-multistage",
            "target_skill": "secops-statistical-hunter",
            "intent": intent,
            "target_entity": {"type": "HOSTNAME", "value": "wkstn-prod-042"},
            "search_window": {"lookback": "24h"},
        })
        self.assertEqual(ack["status"], "HANDOFF_ACK_ACCEPTED")
        self.assertEqual(ack["preflight_spec"]["formula"], expected_formula)

  def test_ws8_01_every_non_retired_intent_binds_target_entity_and_passes_pre_dispatch(self) -> None:
    """Every non-retired intent in INTENT_ROUTING_MAP binds HOSTNAME, USER, and IP and passes QueryIntegrityGate."""
    non_retired_intents = sorted(
        intent
        for intent, arch in HandoffEndpoint.INTENT_ROUTING_MAP.items()
        if arch not in RETIRED_ARCHETYPES
    )
    self.assertGreaterEqual(len(non_retired_intents), 70)

    entity_cases = [
        ("HOSTNAME", "wkstn-prod-042"),
        ("USER", "charles.hardy"),
        ("IP", "10.128.0.15"),
    ]
    for intent in non_retired_intents:
      for etype, eval_str in entity_cases:
        with self.subTest(intent=intent, entity_type=etype):
          ack = HandoffEndpoint.ingest({
              "protocol": "secops-threat-hunt-handoff-v1",
              "request_id": f"req-{intent.lower()}-{etype.lower()}",
              "source_skill": "secops-risk-metrics-multistage",
              "target_skill": "secops-statistical-hunter",
              "intent": intent,
              "target_entity": {"type": etype, "value": eval_str},
              "search_window": {"lookback": "24h"},
          })
          self.assertEqual(
              ack["status"],
              "HANDOFF_ACK_ACCEPTED",
              f"Unexpected NACK for ({intent}, {etype}): {ack.get('errors')}",
          )
          spec_ent = ack["preflight_spec"]["target_entity"]
          self.assertEqual(spec_ent["value"], eval_str)
          self.assertIn("field", spec_ent)
          self.assertTrue(bool(spec_ent["field"]))

          gate = QueryIntegrityGate.verify_pre_dispatch(
              ack["compiled_query"],
              expected_entity=eval_str,
          )
          self.assertEqual(
              gate,
              {"valid": True, "errors": []},
              f"Pre-dispatch failed for ({intent}, {etype}): {gate['errors']}\nQuery:\n{ack['compiled_query']}",
          )

  def test_ws8_01_entity_type_synonym_normalization_and_field_overrides(self) -> None:
    """Synonyms (ASSET, SERVICE_ACCOUNT, SRC_IP, CALLER_IP, DOMAIN) and explicit field overrides resolve cleanly."""
    synonym_cases = [
        ("ASSET", "srv-db-01.corp.lan", "HOST", "principal.hostname"),
        ("HOST", "srv-db-01.corp.lan", "HOST", "principal.hostname"),
        ("DOMAIN", "corp.example.com", "HOST", "principal.hostname"),
        ("USER_ID", "maya.goodman", "USER", "target.user.userid"),
        ("SERVICE_ACCOUNT", "svc-ci-runner", "USER", "target.user.userid"),
        ("SRC_IP", "10.44.12.9", "IP", "principal.ip"),
        ("CALLER_IP", "10.44.12.9", "IP", "principal.ip"),
    ]
    for raw_type, val, expected_norm_type, expected_field in synonym_cases:
      with self.subTest(raw_type=raw_type):
        ack = HandoffEndpoint.ingest({
            "protocol": "secops-threat-hunt-handoff-v1",
            "request_id": f"req-syn-{raw_type.lower()}",
            "source_skill": "secops-risk-metrics-multistage",
            "target_skill": "secops-statistical-hunter",
            "intent": "ZSCORE_PROCESS_SURGE",
            "target_entity": {"type": raw_type, "value": val},
            "search_window": {"lookback": "24h"},
        })
        self.assertEqual(ack["status"], "HANDOFF_ACK_ACCEPTED")
        self.assertEqual(ack["preflight_spec"]["target_entity"]["type"], expected_norm_type)
        self.assertEqual(ack["preflight_spec"]["target_entity"]["field"], expected_field)
        self.assertIn(f'{expected_field} = "{val}"', ack["compiled_query"])

    # Explicit target_entity.field and top-level entity_field overrides
    ack_nested = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-field-nested",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "ZSCORE_PROCESS_SURGE",
        "target_entity": {"type": "USER", "value": "frank.kolzig", "field": "principal.user.userid"},
        "search_window": {"lookback": "24h"},
    })
    self.assertEqual(ack_nested["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(ack_nested["preflight_spec"]["target_entity"]["field"], "principal.user.userid")
    self.assertIn('principal.user.userid = "frank.kolzig"', ack_nested["compiled_query"])

    ack_top = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-field-top",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "ZSCORE_PROCESS_SURGE",
        "target_entity": {"type": "IP", "value": "10.128.0.15"},
        "entity_field": "src.ip",
        "search_window": {"lookback": "24h"},
    })
    self.assertEqual(ack_top["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(ack_top["preflight_spec"]["target_entity"]["field"], "src.ip")
    self.assertIn('src.ip = "10.128.0.15"', ack_top["compiled_query"])

    # ECG artifact entity types (FILE / DOMAIN_NAME) bind cleanly with event aliases
    ack_file = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-ecg-file",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DERIVED_CONTEXT_FILE_PREVALENCE",
        "target_entity": {"type": "FILE", "value": "updater.exe"},
        "search_window": {"lookback": "24h"},
    })
    self.assertEqual(ack_file["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(
        QueryIntegrityGate.verify_pre_dispatch(ack_file["compiled_query"], expected_entity="updater.exe"),
        {"valid": True, "errors": []},
    )

    ack_dom = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-ecg-dom",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
        "target_entity": {"type": "DOMAIN_NAME", "value": "sync-tunnel.xyz"},
        "search_window": {"lookback": "24h"},
    })
    self.assertEqual(ack_dom["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(
        QueryIntegrityGate.verify_pre_dispatch(ack_dom["compiled_query"], expected_entity="sync-tunnel.xyz"),
        {"valid": True, "errors": []},
    )

  def test_ws8_01_fleet_vs_self_baseline_scoping_topology(self) -> None:
    """Fleet/cohort pipelines scope ONLY at Root (preserving fleet N); self-baseline pipelines prune at Stage 1."""
    router = MultiStageTemplateRouter()

    # 1. All 10 fleet-normalized / empirical-Bayes / prevalence / cohort templates on disk
    for tpl_file, expected_root_var in self.FLEET_ROOT_SCOPED_TEMPLATES.items():
      arch = router.TEMPLATE_TO_SENSITIVITY_KEY[tpl_file]
      with self.subTest(fleet_template=tpl_file):
        q = router.build_query(
            arch,
            tier="BALANCED",
            entity_type="host",
            target_entity_value="wkstn-prod-042",
        )
        stages, root_body = _split_stages_and_root(q)
        self.assertGreaterEqual(len(stages), 1)
        for st_name, st_body in stages:
          self.assertNotIn(
              "wkstn-prod-042",
              st_body,
              f"Fleet template {tpl_file} leaked entity filter into named stage '{st_name}' (would collapse fleet N to 1)!",
          )
        root_before_match = root_body.split("match:")[0]
        self.assertIn(
            f'{expected_root_var} = "wkstn-prod-042"',
            root_before_match,
            f"Fleet template {tpl_file} missing '{expected_root_var} = \"wkstn-prod-042\"' above Root match:",
        )
        self.assertEqual(QueryIntegrityGate.verify_pre_dispatch(q, expected_entity="wkstn-prod-042")["errors"], [])

    # Also verify inline fleet_prevalence_normalization_2stage.yl2 fallback handling if loaded from INLINE_TEMPLATES
    inline_router = MultiStageTemplateRouter(template_dir=REPO_ROOT / "nonexistent_templates_dir_for_inline_test")
    custom_inline = (
        "// Goal: Inline fleet prevalence normalization test\n"
        "stage host_counts {\n"
        "  metadata.event_type = \"PROCESS_LAUNCH\"\n"
        "  {{entity_field}} = $host\n"
        "  $host != \"\"\n"
        "  match:\n"
        "    $host by 1h\n"
        "  outcome:\n"
        "    $c = count(metadata.id)\n"
        "}\n"
        "stage fleet_norm {\n"
        "  $ws = $host_counts.window_start\n"
        "  match:\n"
        "    $ws by 1h\n"
        "  outcome:\n"
        "    $n_hosts = count_distinct($host_counts.host)\n"
        "}\n"
        "$host = $host_counts.host\n"
        "$ws = $host_counts.window_start\n"
        "$ws = $fleet_norm.ws\n"
        "match:\n"
        "  $host, $ws by 1h\n"
        "outcome:\n"
        "  $observation_count = max($host_counts.c)\n"
        "  $baseline_active_samples = max($fleet_norm.n_hosts)\n"
        "  $baseline_mean = 1.0\n"
        "  $baseline_dispersion = 1.0\n"
        "  $fleet_prevalence = max($fleet_norm.n_hosts)\n"
        "  $distinct_binaries = 1\n"
        "  $z_score = 1.0 * $observation_count\n"
        "condition:\n"
        "  $z_score >= 1.0\n"
        "order:\n"
        "  $z_score desc\n"
    )
    orig_inline = dict(MultiStageTemplateRouter.INLINE_TEMPLATES)
    orig_arch = dict(MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP)
    try:
      MultiStageTemplateRouter.INLINE_TEMPLATES["fleet_prevalence_normalization_2stage.yl2"] = custom_inline
      MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP["INLINE_FLEET_PREV_TEST"] = "fleet_prevalence_normalization_2stage.yl2"
      q_inline = inline_router.build_query("INLINE_FLEET_PREV_TEST", target_entity_value="wkstn-prod-042")
      in_stages, in_root = _split_stages_and_root(q_inline)
      self.assertNotIn("wkstn-prod-042", in_stages[0][1])
      self.assertIn('$host = "wkstn-prod-042"', in_root.split("match:")[0])
    finally:
      MultiStageTemplateRouter.INLINE_TEMPLATES.clear()
      MultiStageTemplateRouter.INLINE_TEMPLATES.update(orig_inline)
      MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP.clear()
      MultiStageTemplateRouter.ARCHETYPE_TEMPLATE_MAP.update(orig_arch)

    # 2. All 17 single-entity self-baseline templates prune at Stage 1 (and Stage 2/3 when independent raw scans)
    for tpl_file in self.SELF_BASELINE_TEMPLATES:
      arch = router.TEMPLATE_TO_SENSITIVITY_KEY[tpl_file]
      with self.subTest(self_baseline_template=tpl_file):
        q = router.build_query(
            arch,
            tier="BALANCED",
            entity_type="host",
            target_entity_value="wkstn-prod-042",
        )
        stages, root_body = _split_stages_and_root(q)
        self.assertIn(
            '"wkstn-prod-042"',
            stages[0][1],
            f"Self-baseline template {tpl_file} did not prune target entity in Stage 1 '{stages[0][0]}'!",
        )
        self.assertNotIn(
            '"wkstn-prod-042"',
            root_body,
            f"Self-baseline template {tpl_file} should scope raw stages, not Root!",
        )
        if tpl_file == "long_string_screen_2stage.yl2":
          # Stage 2 (token_observation) is an independent raw scan and must ALSO be scoped
          self.assertIn('"wkstn-prod-042"', stages[1][1])
        if tpl_file == "poisson_rare_surge_2stage.yl2":
          # Stage 3 (host_online_baseline) is an independent raw scan and must ALSO be scoped
          self.assertIn('"wkstn-prod-042"', stages[2][1])
        if tpl_file == "privileged_lateral_expansion_2stage.yl2":
          # Hostname handoff scopes target.hostname while keeping user regex on target.user.userid intact
          self.assertIn('target.hostname = "wkstn-prod-042"', stages[0][1])
          self.assertIn("re.regex(target.user.userid,", stages[0][1])

        self.assertEqual(QueryIntegrityGate.verify_pre_dispatch(q, expected_entity="wkstn-prod-042")["errors"], [])

  def test_ws8_01_fleet_wildcards_and_injection_rejection(self) -> None:
    """Fleet wildcards leave queries unscoped; unsafe characters in entity value or field fail closed."""
    router = MultiStageTemplateRouter()
    baseline_unscoped = router.build_query("ZSCORE_PROCESS_SURGE", tier="BALANCED", entity_type="host")

    for wildcard in (None, "", "  ", "fleet", "ALL", "enterprise", "unknown", "unknown_entity", "target_entity", "*"):
      with self.subTest(wildcard=wildcard):
        q = router.build_query(
            "ZSCORE_PROCESS_SURGE",
            tier="BALANCED",
            entity_type="host",
            target_entity_value=wildcard,
        )
        self.assertEqual(q, baseline_unscoped)

    # Unsafe target_entity_value characters -> ValueError in build_query & HANDOFF_ACK_REJECTED in ingest
    for bad_val in (
        'wkstn" OR 1=1 //',
        "wkstn\nmatch:",
        "wkstn\rbad",
        "wkstn{stage}",
        "wkstn}root",
        "wkstn;drop",
        "wkstn\x00null",
    ):
      with self.subTest(bad_val=repr(bad_val)):
        with self.assertRaises(ValueError):
          router.build_query("ZSCORE_PROCESS_SURGE", target_entity_value=bad_val)
        ack = HandoffEndpoint.ingest({
            "protocol": "secops-threat-hunt-handoff-v1",
            "request_id": "req-inj-val",
            "source_skill": "secops-risk-metrics-multistage",
            "target_skill": "secops-statistical-hunter",
            "intent": "ZSCORE_PROCESS_SURGE",
            "target_entity": {"type": "HOSTNAME", "value": bad_val},
        })
        self.assertEqual(ack["status"], "HANDOFF_ACK_REJECTED")

    # Unsafe entity_field override characters -> ValueError / HANDOFF_ACK_REJECTED
    for bad_field in (
        'principal.hostname" OR "',
        "principal.hostname'bad",
        "principal.hostname\nmatch:",
        "principal.hostname{x}",
        "principal.hostname}x",
        "principal.hostname;drop",
    ):
      with self.subTest(bad_field=repr(bad_field)):
        with self.assertRaises(ValueError):
          router.build_query("ZSCORE_PROCESS_SURGE", entity_field=bad_field, target_entity_value="wkstn-01")
        ack = HandoffEndpoint.ingest({
            "protocol": "secops-threat-hunt-handoff-v1",
            "request_id": "req-inj-field",
            "source_skill": "secops-risk-metrics-multistage",
            "target_skill": "secops-statistical-hunter",
            "intent": "ZSCORE_PROCESS_SURGE",
            "target_entity": {"type": "HOSTNAME", "value": "wkstn-01", "field": bad_field},
        })
        self.assertEqual(ack["status"], "HANDOFF_ACK_REJECTED")


if __name__ == "__main__":
  unittest.main()
