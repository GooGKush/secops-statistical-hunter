# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Characterization tests pinning the D7 frozen Clean Hand-Off write-back schema (WS8-03).

Per Plan §2 D7, §0 Rule 10, and §6 WS8-03, the synthetic UDM write-back contract in
scripts/clean_handoff.py and SKILL.md Section 3 is a frozen interface with zero permitted
schema drift.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import clean_handoff  # pylint: disable=wrong-import-position


class TestWS803WritebackFrozenContract(unittest.TestCase):
  """Pins every constant, field name, type, envelope wrapper, rule, and SKILL.md instruction under D7."""

  EXPECTED_PRODUCT_EVENT_TYPES = [
      "VOLUMETRIC_BASELINE_ANOMALY",
      "INLINE_MAD_OUTLIER",
      "POISSON_BURST_CLUSTERING",
      "POISSON_DEVIANCE_RARITY",
      "C2_BEACONING_JITTER",
      "TUKEY_IQR_FENCE_ANOMALY",
      "BAYESIAN_SHRINKAGE_ANOMALY",
      "TWO_PART_HURDLE_AWAKENING",
      "MULTI_SECTOR_THREAT_FUSION",
      "HYBRID_ENTROPY_CONCENTRATION",
      "FEDERATED_MACRO_MICRO_CORRELATION",
  ]

  def test_d7_frozen_module_constants_and_severity_tiers(self) -> None:
    self.assertEqual(clean_handoff.CANONICAL_PRODUCT_EVENT_TYPES, self.EXPECTED_PRODUCT_EVENT_TYPES)
    self.assertEqual(len(clean_handoff.CANONICAL_PRODUCT_EVENT_TYPES), 11)
    self.assertEqual(clean_handoff.CHRONICLE_INGESTION_LOG_TYPE, "CUSTOM_SECURITY_DATA_ANALYTICS")
    self.assertEqual(clean_handoff.CATCHALL_RULE_NAME, "secops_statistical_hunter_alert_catchall")
    self.assertEqual(
        clean_handoff.VALID_SEVERITIES,
        {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
    )
    self.assertEqual(clean_handoff.map_cri_to_severity(0), "INFORMATIONAL")
    self.assertEqual(clean_handoff.map_cri_to_severity(19), "INFORMATIONAL")
    self.assertEqual(clean_handoff.map_cri_to_severity(20), "LOW")
    self.assertEqual(clean_handoff.map_cri_to_severity(40), "MEDIUM")
    self.assertEqual(clean_handoff.map_cri_to_severity(60), "HIGH")
    self.assertEqual(clean_handoff.map_cri_to_severity(80), "CRITICAL")

  def test_d7_build_synthetic_udm_event_schema_across_all_11_event_types_and_entities(self) -> None:
    entity_variants = [
        ("USER", "charles.hardy", {"user": {"userid": "charles.hardy"}}),
        ("SERVICE_ACCOUNT", "svc-ci-runner", {"user": {"userid": "svc-ci-runner"}}),
        (
            "HOSTNAME",
            "wkstn-prod-042",
            {"hostname": "wkstn-prod-042", "asset": {"hostname": "wkstn-prod-042"}},
        ),
    ]
    fixed_ts = "2026-10-28T12:00:00Z"

    for pet in self.EXPECTED_PRODUCT_EVENT_TYPES:
      for ent_type, ent_id, expected_principal in entity_variants:
        with self.subTest(product_event_type=pet, entity_type=ent_type):
          event = clean_handoff.build_synthetic_udm_event(
              product_event_type=pet,
              entity_id=ent_id,
              entity_type=ent_type,
              statistical_model="Modified Z-Score (MAD)",
              z_score=5.42,
              cri_score=81,
              observed_value=785,
              historical_mean=164.6,
              historical_stddev=114.49,
              summary="Anomalous activity burst above robust baseline.",
              hunt_campaign_id="hunt-d7pin01",
              event_timestamp=fixed_ts,
              threat_id="T1078",
              mitre_tactics=["TA0001"],
              mitre_techniques=["T1078"],
              extra_labels={"Analyst": "ueba-pin"},
          )
          self.assertEqual(set(event.keys()), {"udm"})
          udm = event["udm"]
          self.assertEqual(
              set(udm.keys()),
              {"metadata", "observer", "principal", "target", "security_result"},
          )

          meta = udm["metadata"]
          self.assertEqual(meta["event_timestamp"], fixed_ts)
          self.assertEqual(meta["ingested_timestamp"], fixed_ts)
          self.assertEqual(meta["product_name"], "SecOps Statistical Hunter")
          self.assertEqual(meta["vendor_name"], "Google SecOps")
          self.assertEqual(meta["event_type"], "GENERIC_EVENT")
          self.assertEqual(meta["product_event_type"], pet)
          self.assertEqual(
              meta["ingestion_labels"],
              [
                  {"key": "hunt_campaign_id", "value": "hunt-d7pin01"},
                  {"key": "source_skill", "value": "secops-statistical-hunter"},
                  {"key": "statistical_model", "value": "Modified Z-Score (MAD)"},
              ],
          )

          self.assertEqual(
              udm["observer"],
              {
                  "hostname": "secops-statistical-hunter",
                  "application": "Google SecOps Statistical Outlier Hunter",
              },
          )
          self.assertEqual(udm["principal"], expected_principal)

          res_block = udm["target"]["resource"]
          self.assertEqual(res_block["name"], pet)
          self.assertEqual(res_block["resource_type"], "RESOURCE_TYPE_UNSPECIFIED")
          label_keys = [lbl["key"] for lbl in res_block["attribute"]["labels"]]
          self.assertEqual(
              label_keys,
              [
                  "Hunt Campaign ID",
                  "Statistical Model",
                  "Observed Value",
                  "Baseline Mean",
                  "Baseline Dispersion / StdDev",
                  "Z-Score",
                  "Calibrated Risk Index",
                  "Analyst",
              ],
          )

          self.assertEqual(len(udm["security_result"]), 1)
          sr = udm["security_result"][0]
          self.assertIs(type(sr["risk_score"]), int)
          self.assertEqual(sr["risk_score"], 81)
          self.assertIs(type(sr["confidence_score"]), float)
          self.assertAlmostEqual(sr["confidence_score"], 5.42, places=2)
          self.assertIs(type(sr["severity"]), str)
          self.assertEqual(sr["severity"], "CRITICAL")
          self.assertEqual(sr["threat_id"], "T1078")
          self.assertEqual(sr["threat_id_namespace"], "MITRE_ATTACK")
          self.assertEqual(sr["category"], ["SUSPICIOUS_ACTIVITY"])
          self.assertEqual(sr["category_details"], [pet])
          self.assertEqual(sr["action"], ["UNKNOWN_ACTION"])
          det_keys = [d["key"] for d in sr["detection_fields"]]
          self.assertEqual(
              det_keys,
              [
                  "source_skill",
                  "hunt_campaign_id",
                  "z_score",
                  "cri_score",
                  "mitre_tactics",
                  "mitre_techniques",
              ],
          )

          self.assertEqual(clean_handoff.validate_clean_handoff_udm(event), [])

    with self.assertRaises(ValueError):
      clean_handoff.build_synthetic_udm_event(
          product_event_type="NON_CANONICAL_EVENT_TYPE",
          entity_id="charles.hardy",
          entity_type="USER",
          statistical_model="Z-Score",
          z_score=4.0,
          cri_score=65,
          observed_value=100,
          historical_mean=10.0,
          historical_stddev=2.0,
          summary="Invalid event type test.",
      )

  def test_d7_composite_fusion_sector_vectors_schema(self) -> None:
    event = clean_handoff.build_synthetic_udm_event(
        product_event_type="MULTI_SECTOR_THREAT_FUSION",
        entity_id="wkstn-prod-042",
        entity_type="HOSTNAME",
        statistical_model="Multi-Sector Threat Fusion",
        z_score=4.85,
        cri_score=75,
        observed_value=420,
        historical_mean=50.0,
        historical_stddev=12.0,
        summary="Multi-sector anomaly across auth and process telemetry.",
        hunt_campaign_id="hunt-fusion01",
        event_timestamp="2026-10-28T12:00:00Z",
        sector_vectors={
            "endpoint": {"z": 4.2, "cri": 67},
            "auth": {"z": 2.4, "cri": 41},
            "zero_sector": {"z": 0.0, "cri": 0},
        },
    )
    self.assertEqual(clean_handoff.validate_clean_handoff_udm(event), [])
    udm = event["udm"]
    srs = udm["security_result"]
    self.assertEqual(len(srs), 3)

    primary = srs[0]
    self.assertEqual(primary["rule_type"], "COMPOSITE_FUSION")
    self.assertNotIn("confidence_score", primary)
    self.assertIs(type(primary["risk_score"]), int)
    self.assertEqual(primary["risk_score"], 75)

    sec_ep = srs[1]
    self.assertEqual(sec_ep["rule_type"], "SECTOR_VECTOR")
    self.assertEqual(sec_ep["threat_name"], "ENDPOINT")
    self.assertIs(type(sec_ep["risk_score"]), int)
    self.assertEqual(sec_ep["risk_score"], 67)
    self.assertIs(type(sec_ep["confidence_score"]), float)
    self.assertAlmostEqual(sec_ep["confidence_score"], 4.2, places=2)
    self.assertEqual(sec_ep["threat_status"], "ACTIVE")

    sec_auth = srs[2]
    self.assertEqual(sec_auth["rule_type"], "SECTOR_VECTOR")
    self.assertEqual(sec_auth["threat_name"], "AUTH")
    self.assertEqual(sec_auth["threat_status"], "CLEARED")

    labels = {
        item["key"]: item["value"]
        for item in udm["target"]["resource"]["attribute"]["labels"]
    }
    self.assertEqual(labels["Peak Vector"], "ENDPOINT")
    self.assertEqual(labels["Peak CRI"], "67")
    self.assertEqual(labels["Peak Z"], "4.20")
    self.assertEqual(labels["Breached Vectors"], "ENDPOINT")

  def test_d7_import_logs_udm_envelope_batch_and_catchall_rule(self) -> None:
    batch = clean_handoff.build_multi_event_batch(
        [
            {
                "product_event_type": "INLINE_MAD_OUTLIER",
                "entity_id": "charles.hardy",
                "entity_type": "USER",
                "statistical_model": "MAD",
                "z_score": 5.42,
                "cri_score": 81,
                "observed_value": 785,
                "historical_mean": 164.6,
                "historical_stddev": 114.49,
                "summary": "MAD outlier.",
                "event_timestamp": "2026-10-28T12:00:00Z",
            },
            {
                "product_event_type": "TUKEY_IQR_FENCE_ANOMALY",
                "entity_id": "wkstn-prod-042",
                "entity_type": "HOSTNAME",
                "statistical_model": "Tukey Skew Fence",
                "z_score": 4.10,
                "cri_score": 66,
                "observed_value": 9200,
                "historical_mean": 800.0,
                "historical_stddev": 210.0,
                "summary": "Tukey fence outlier.",
                "event_timestamp": "2026-10-28T12:00:00Z",
            },
        ],
        hunt_campaign_id="hunt-batch01",
    )
    self.assertEqual(len(batch), 2)
    for ev in batch:
      self.assertEqual(clean_handoff.validate_clean_handoff_udm(ev), [])

    args_with_fwd = clean_handoff.prepare_chronicle_import_logs_args(
        batch=batch,
        customer_id="8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5",
        project_id="gus-sdl",
        region="us",
        forwarder_id="fwd-12345",
    )
    self.assertEqual(args_with_fwd["logType"], "CUSTOM_SECURITY_DATA_ANALYTICS")
    self.assertEqual(args_with_fwd["forwarderId"], "fwd-12345")
    mcp_args = args_with_fwd["mcp_import_logs_args"]
    self.assertEqual(mcp_args["log_type"], "UDM")
    self.assertEqual(mcp_args["forwarderId"], "fwd-12345")
    self.assertEqual(len(mcp_args["logs"]), 2)
    for idx, env_str in enumerate(mcp_args["logs"]):
      parsed = json.loads(env_str)
      self.assertEqual(parsed, {"events": [{"event": batch[idx]["udm"]}]})

    args_no_fwd = clean_handoff.prepare_chronicle_import_logs_args(
        batch=batch,
        customer_id="8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5",
        project_id="gus-sdl",
        region="us",
    )
    self.assertNotIn("forwarderId", args_no_fwd)
    self.assertNotIn("forwarderId", args_no_fwd["mcp_import_logs_args"])

    instr = clean_handoff.format_mcp_ingestion_instruction(batch=batch, forwarder_id="fwd-12345")
    self.assertIn('ToolName="import_logs"', instr)
    self.assertIn('"log_type": "UDM"', instr)
    self.assertIn('"forwarderId": "fwd-12345"', instr)

    preview = clean_handoff.format_pre_ingestion_clearance_card(
        batch=batch,
        customer_id="8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5",
        project_id="gus-sdl",
        campaign_id="hunt-batch01",
    )
    self.assertIn("PRE-INGESTION CLEARANCE SPECIFICATION (CLEAN HAND-OFF)", preview)
    self.assertIn("secops_statistical_hunter_alert_catchall", preview)

    rule_text = clean_handoff.generate_catchall_yaral_rule()
    self.assertIn("rule secops_statistical_hunter_alert_catchall {", rule_text)
    self.assertIn('$e.metadata.event_type = "GENERIC_EVENT"', rule_text)
    self.assertIn('$e.metadata.product_name = "SecOps Statistical Hunter"', rule_text)
    self.assertIn('$e.security_result.detection_fields["source_skill"] = "secops-statistical-hunter"', rule_text)
    self.assertIn("allow_zero_values = true", rule_text)

  def test_d7_skill_md_section_3_clean_handoff_instructions_intact(self) -> None:
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    required_snippets = [
        "### 3. Clean Hand-Off (CH) Protocol (Synthetic UDM Event Ingestion vs. Active Case Wall)",
        "Path A (Standard Escalation Default — Synthetic Event Ingestion)",
        'product_name: "SecOps Statistical Hunter"',
        'resource_type: "RESOURCE_TYPE_UNSPECIFIED"',
        "import_logs",
        'log_type: "UDM"',
        "forwarderId",
        '{"events": [{"event": ...}]}',
        "Path B (Explicit Active Case Attachment)",
        "create_case_comment",
        "Conceptual Handoff Contract (Cross-Skill Steering Protocol)",
    ]
    for snippet in required_snippets:
      with self.subTest(snippet=snippet):
        self.assertIn(snippet, skill_md)


if __name__ == "__main__":
  unittest.main()
