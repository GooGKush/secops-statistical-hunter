# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression test suite for Clean Hand-Off (CH) synthetic UDM ingestion in Google SecOps.

Validates:
1. Synthetic UDM event generation across all canonical statistical product event types.
2. Strict compliance with official Chronicle UDM specification.
3. Correlated multi-event batching with shared Hunt Campaign ID.
4. Rejection of invalid/obsolete schema constructs (e.g. integer resource_type).
5. Pre-ingestion clearance card formatting and affirmative workflow.
6. Ingestion payload serialization for Chronicle SIEM API / SecOps GUS MCP.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import unittest

# Ensure skill root is in path
SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT))

from scripts.clean_handoff import (
    CANONICAL_PRODUCT_EVENT_TYPES,
    CHRONICLE_INGESTION_LOG_TYPE,
    CATCHALL_RULE_NAME,
    build_synthetic_udm_event,
    build_multi_event_batch,
    validate_clean_handoff_udm,
    format_pre_ingestion_clearance_card,
    prepare_chronicle_import_logs_args,
    map_cri_to_severity,
)


class TestCleanHandoffRegression(unittest.TestCase):
  """Regression test suite asserting complete Clean Hand-Off compliance and Chronicle ingestion."""

  def setUp(self):
    self.customer_id = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
    self.project_id = "gus-sdl"
    self.region = "us"
    self.forwarder_id = "155c709b-37f1-46fc-be7e-5af35db0ea5c"

  def test_all_canonical_product_event_types_generate_valid_udm(self):
    """Every one of the canonical product_event_type variants must pass strict UDM validation."""
    for pet in CANONICAL_PRODUCT_EVENT_TYPES:
      with self.subTest(product_event_type=pet):
        event = build_synthetic_udm_event(
            product_event_type=pet,
            entity_id="test-entity-01",
            entity_type="USER",
            statistical_model=pet.replace("_", " ").title(),
            z_score=3.85,
            cri_score=72,
            observed_value=15,
            historical_mean=1.2,
            historical_stddev=0.4,
            summary=f"Automated regression test event for {pet}",
            hunt_campaign_id="hunt-regression-test-01",
            event_timestamp="2026-09-10T20:00:00Z",
        )
        errors = validate_clean_handoff_udm(event)
        self.assertEqual(errors, [], f"Validation errors for {pet}: {errors}")

        udm = event["udm"]
        self.assertEqual(udm["metadata"]["product_event_type"], pet)
        self.assertEqual(udm["metadata"]["product_name"], "SecOps Statistical Hunter")
        self.assertEqual(udm["metadata"]["vendor_name"], "Google SecOps")
        self.assertEqual(udm["metadata"]["event_type"], "GENERIC_EVENT")
        self.assertEqual(udm["observer"]["hostname"], "secops-statistical-hunter")
        self.assertEqual(udm["observer"]["application"], "Google SecOps Statistical Outlier Hunter")
        self.assertEqual(udm["target"]["resource"]["resource_type"], "RESOURCE_TYPE_UNSPECIFIED")
        self.assertEqual(udm["security_result"][0]["threat_id_namespace"], "MITRE_ATTACK")
        self.assertEqual(udm["security_result"][0]["risk_score"], 72)
        self.assertEqual(udm["security_result"][0]["severity"], "HIGH")

  def test_rejection_of_unknown_product_event_type(self):
    """Building an event with an unknown product_event_type must raise ValueError."""
    with self.assertRaises(ValueError):
      build_synthetic_udm_event(
          product_event_type="UNREGISTERED_ANOMALY_TYPE",
          entity_id="user01",
          entity_type="USER",
          statistical_model="Z-Score",
          z_score=3.5,
          cri_score=65,
          observed_value=10,
          historical_mean=2.0,
          historical_stddev=0.5,
          summary="Should fail",
      )

  def test_validator_rejects_obsolete_integer_resource_type(self):
    """Validator must reject obsolete integer 'resource_type: 0'."""
    event = build_synthetic_udm_event(
        product_event_type="VOLUMETRIC_BASELINE_ANOMALY",
        entity_id="win-host-01",
        entity_type="HOSTNAME",
        statistical_model="Parametric Historical Z-Score",
        z_score=4.2,
        cri_score=80,
        observed_value=500,
        historical_mean=50.0,
        historical_stddev=10.0,
        summary="Integer resource_type test",
    )
    # Tamper to simulate obsolete schema
    event["udm"]["target"]["resource"]["resource_type"] = 0
    errors = validate_clean_handoff_udm(event)
    self.assertTrue(any("Obsolete integer 'resource_type: 0' is forbidden" in e for e in errors))

  def test_validator_enforces_iso8601_utc_timestamps(self):
    """Timestamps must strictly adhere to ISO 8601 UTC ending in 'Z'."""
    event = build_synthetic_udm_event(
        product_event_type="INLINE_MAD_OUTLIER",
        entity_id="host-02",
        entity_type="HOSTNAME",
        statistical_model="Median Absolute Deviation",
        z_score=3.5,
        cri_score=60,
        observed_value=250,
        historical_mean=30.0,
        historical_stddev=5.0,
        summary="Timestamp test",
    )
    # Tamper timestamp
    event["udm"]["metadata"]["event_timestamp"] = "2026-09-10 12:00:00"
    errors = validate_clean_handoff_udm(event)
    self.assertTrue(any("must be ISO 8601 UTC string ending in 'Z'" in e for e in errors))

  def test_multi_event_batch_correlation_and_shared_campaign_id(self):
    """Multi-event batches must bind all constituent findings with a shared Hunt Campaign ID."""
    findings = [
        {
            "product_event_type": "VOLUMETRIC_BASELINE_ANOMALY",
            "entity_id": "user-alice",
            "entity_type": "USER",
            "statistical_model": "Historical Z-Score",
            "z_score": 4.1,
            "cri_score": 75,
            "observed_value": 450,
            "historical_mean": 50.0,
            "historical_stddev": 10.0,
            "summary": "Surge finding",
        },
        {
            "product_event_type": "C2_BEACONING_JITTER",
            "entity_id": "host-beacon-01",
            "entity_type": "HOSTNAME",
            "statistical_model": "Coefficient of Variation",
            "z_score": 3.8,
            "cri_score": 68,
            "observed_value": 0.04,
            "historical_mean": 0.55,
            "historical_stddev": 0.12,
            "summary": "Beaconing finding",
        },
    ]
    batch = build_multi_event_batch(findings, hunt_campaign_id="hunt-shared-12345")
    self.assertEqual(len(batch), 2)

    for item in batch:
      errors = validate_clean_handoff_udm(item)
      self.assertEqual(errors, [])
      labels = item["udm"]["metadata"]["ingestion_labels"]
      campaign_label = next(l["value"] for l in labels if l["key"] == "hunt_campaign_id")
      self.assertEqual(campaign_label, "hunt-shared-12345")

  def test_cri_to_severity_mapping(self):
    """CRI must map correctly to Chronicle severities."""
    self.assertEqual(map_cri_to_severity(85), "CRITICAL")
    self.assertEqual(map_cri_to_severity(80), "CRITICAL")
    self.assertEqual(map_cri_to_severity(75), "HIGH")
    self.assertEqual(map_cri_to_severity(60), "HIGH")
    self.assertEqual(map_cri_to_severity(55), "MEDIUM")
    self.assertEqual(map_cri_to_severity(40), "MEDIUM")
    self.assertEqual(map_cri_to_severity(35), "LOW")
    self.assertEqual(map_cri_to_severity(20), "LOW")
    self.assertEqual(map_cri_to_severity(10), "INFORMATIONAL")

  def test_pre_ingestion_clearance_card_format(self):
    """Pre-ingestion card must display structured table and prompt for authorization."""
    findings = [{
        "product_event_type": "POISSON_BURST_CLUSTERING",
        "entity_id": "db-server-09",
        "entity_type": "HOSTNAME",
        "statistical_model": "Fano Factor Poisson Burst",
        "z_score": 4.5,
        "cri_score": 82,
        "observed_value": 850,
        "historical_mean": 100.0,
        "historical_stddev": 15.0,
        "summary": "Burst cluster test",
    }]
    batch = build_multi_event_batch(findings, hunt_campaign_id="hunt-card-test")
    card = format_pre_ingestion_clearance_card(
        batch,
        customer_id=self.customer_id,
        project_id=self.project_id,
        campaign_id="hunt-card-test",
    )

    self.assertIn("PRE-INGESTION CLEARANCE SPECIFICATION", card)
    self.assertIn(self.customer_id, card)
    self.assertIn(self.project_id, card)
    self.assertIn(CATCHALL_RULE_NAME, card)
    self.assertIn("`db-server-09`", card)
    self.assertIn("POISSON_BURST_CLUSTERING", card)
    self.assertIn("CRITICAL", card)
    self.assertIn("Would you like me to ingest this Synthetic UDM Security Event batch", card)

  def test_chronicle_import_logs_payload_structure(self):
    """prepare_chronicle_import_logs_args must serialize batch properly."""
    findings = [{
        "product_event_type": "VOLUMETRIC_BASELINE_ANOMALY",
        "entity_id": "svc_backup",
        "entity_type": "SERVICE_ACCOUNT",
        "statistical_model": "Z-Score",
        "z_score": 3.9,
        "cri_score": 70,
        "observed_value": 12000,
        "historical_mean": 1000.0,
        "historical_stddev": 250.0,
        "summary": "Service account spike",
    }]
    batch = build_multi_event_batch(findings)
    args = prepare_chronicle_import_logs_args(
        batch=batch,
        customer_id=self.customer_id,
        project_id=self.project_id,
        region=self.region,
        forwarder_id=self.forwarder_id,
    )

    self.assertEqual(args["customerId"], self.customer_id)
    self.assertEqual(args["projectId"], self.project_id)
    self.assertEqual(args["region"], self.region)
    self.assertEqual(args["logType"], CHRONICLE_INGESTION_LOG_TYPE)
    self.assertEqual(args["forwarderId"], self.forwarder_id)
    self.assertEqual(len(args["logs"]), 1)

    # Must be valid JSON string
    parsed = json.loads(args["logs"][0])
    self.assertIn("udm", parsed)


if __name__ == "__main__":
  unittest.main()
