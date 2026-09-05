# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for HandoffEndpoint federated handoff ingestion in secops-statistical-hunter."""

import json
import unittest
from scripts.multistage_query_builder import HandoffEndpoint


class TestHandoffEndpoint(unittest.TestCase):

  def setUp(self):
    self.valid_exfil_payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-exfil-unit-01",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "SCHEDULED_EXFILTRATION_TIMING",
        "target_entity": {
            "type": "HOSTNAME",
            "value": "site-rev-proxy.lan"
        },
        "search_window": {
            "lookback": "24h"
        },
        "statistical_model": {
            "name": "C2_BEACONING_JITTER",
            "sensitivity": "BALANCED",
            "parameters": {
                "max_cv": 0.20,
                "min_observations": 10
            }
        },
        "justification": "Scheduled cron exfil requires inter-arrival timing CV analysis."
    }

  def test_ingest_valid_handoff_scheduled_exfiltration(self):
    """Valid handoff payload must return HANDOFF_ACK_ACCEPTED and valid compiled query."""
    res = HandoffEndpoint.ingest(self.valid_exfil_payload)
    self.assertEqual(res["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res["action"], "STEP_OUT_CONFIRMED")
    self.assertEqual(res["model_routed"], "C2_BEACONING_JITTER")
    self.assertIn("stage host_intervals", res["compiled_query"])
    self.assertIn("order:\n  $cv asc", res["compiled_query"])
    self.assertIn("CV = sigma / mu <= 0.20", res["preflight_spec"]["formula"])

  def test_ingest_json_string_with_fences(self):
    """Payload provided as markdown-fenced JSON string must parse and compile cleanly."""
    json_str = "```json\n" + json.dumps(self.valid_exfil_payload) + "\n```"
    res = HandoffEndpoint.ingest(json_str)
    self.assertEqual(res["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res["request_id"], "req-exfil-unit-01")

  def test_reject_unsupported_protocol(self):
    """Payload with invalid protocol version must return HANDOFF_ACK_REJECTED."""
    bad_payload = dict(self.valid_exfil_payload)
    bad_payload["protocol"] = "unsupported-protocol-v99"
    res = HandoffEndpoint.ingest(bad_payload)
    self.assertEqual(res["status"], "HANDOFF_ACK_REJECTED")
    self.assertTrue(any("Unsupported protocol" in err for err in res["errors"]))

  def test_reject_target_skill_mismatch(self):
    """Payload targeted to another skill must return HANDOFF_ACK_REJECTED."""
    bad_payload = dict(self.valid_exfil_payload)
    bad_payload["target_skill"] = "secops-siem-search"
    res = HandoffEndpoint.ingest(bad_payload)
    self.assertEqual(res["status"], "HANDOFF_ACK_REJECTED")
    self.assertTrue(any("Target skill mismatch" in err for err in res["errors"]))

  def test_reject_unknown_intent(self):
    """Payload with unroutable intent must return HANDOFF_ACK_REJECTED."""
    bad_payload = dict(self.valid_exfil_payload)
    bad_payload["intent"] = "COMPLETELY_UNKNOWN_THREAT_MODEL_XYZ"
    res = HandoffEndpoint.ingest(bad_payload)
    self.assertEqual(res["status"], "HANDOFF_ACK_REJECTED")
    self.assertTrue(any("Unknown archetype" in err for err in res["errors"]))


if __name__ == "__main__":
  unittest.main()
