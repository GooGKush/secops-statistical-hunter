# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit and contract tests for shared UEBA constants in secops-statistical-hunter (WS2-08)."""

import hashlib
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import multistage_query_builder as mqb
from scripts import ueba_constants


class TestUEBAConstantsContract(unittest.TestCase):
  """Verifies centralized thresholds, tier resolution, and micro module wiring (WS2-08)."""

  def test_canonical_sensitivity_threshold_map_values(self):
    self.assertEqual(
        ueba_constants.SENSITIVITY_THRESHOLD_MAP,
        {
            "HIGH_RECALL": {
                "anomaly_threshold": 2.0,
                "fold_change_threshold": 1.5,
                "fusion_threshold_sq": 6.25,
                "robust_threshold": 2.5,
            },
            "BALANCED": {
                "anomaly_threshold": 3.0,
                "fold_change_threshold": 2.0,
                "fusion_threshold_sq": 12.25,
                "robust_threshold": 3.5,
            },
            "HIGH_PRECISION": {
                "anomaly_threshold": 4.0,
                "fold_change_threshold": 3.0,
                "fusion_threshold_sq": 20.25,
                "robust_threshold": 4.5,
            },
        },
    )

  def test_operational_threshold_constants(self):
    self.assertEqual(ueba_constants.DEFAULT_SENSITIVITY_TIER, "BALANCED")
    self.assertEqual(ueba_constants.DEFAULT_ANOMALY_THRESHOLD, 3.0)
    self.assertEqual(ueba_constants.DEFAULT_FOLD_CHANGE_THRESHOLD, 2.0)
    self.assertEqual(ueba_constants.DEFAULT_FUSION_THRESHOLD_SQ, 12.25)
    self.assertEqual(ueba_constants.DEFAULT_ROBUST_THRESHOLD, 3.5)
    self.assertEqual(ueba_constants.DEFAULT_MIN_BASELINE_DAYS, 7)
    self.assertEqual(ueba_constants.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(ueba_constants.WRITEBACK_CRI_THRESHOLD, 50)
    self.assertEqual(ueba_constants.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD, 25.0)
    self.assertEqual(ueba_constants.LOOPBACK_MIN_DISTINCT_HITS, 2)
    self.assertEqual(ueba_constants.MAX_MODE_B_DAYS_MACRO, 3)
    self.assertEqual(ueba_constants.MAX_CUSUM_MODE_B_DAYS_MACRO, 14)
    self.assertEqual(ueba_constants.MAX_MODE_C_DAYS_MACRO, 30)
    self.assertEqual(ueba_constants.MAX_MODE_B_DAYS_MICRO, 14)

  def test_micro_modules_wire_ueba_constants_and_cross_skill_tier_aliases(self):
    self.assertIs(mqb.SENSITIVITY_THRESHOLD_MAP, ueba_constants.SENSITIVITY_THRESHOLD_MAP)
    self.assertEqual(mqb.DEFAULT_MIN_BASELINE_DAYS, ueba_constants.DEFAULT_MIN_BASELINE_DAYS)
    self.assertEqual(mqb.RADAR_FUSION_DISTANCE_THRESHOLD, ueba_constants.RADAR_FUSION_DISTANCE_THRESHOLD)
    self.assertEqual(mqb.WRITEBACK_CRI_THRESHOLD, ueba_constants.WRITEBACK_CRI_THRESHOLD)
    self.assertEqual(mqb.MAX_MODE_B_DAYS_MICRO, ueba_constants.MAX_MODE_B_DAYS_MICRO)

    # Cross-skill sensitivity aliases (HIGH_RECALL -> AGGRESSIVE, HIGH_PRECISION -> CONSERVATIVE)
    self.assertEqual(
        mqb.get_thresholds_for_tier("DATA_EXFILTRATION_SPIKE", "HIGH_RECALL"),
        mqb.SENSITIVITY_MAP["DATA_EXFILTRATION_SPIKE"]["AGGRESSIVE"],
    )
    self.assertEqual(
        mqb.get_thresholds_for_tier("DATA_EXFILTRATION_SPIKE", "HIGH_PRECISION"),
        mqb.SENSITIVITY_MAP["DATA_EXFILTRATION_SPIKE"]["CONSERVATIVE"],
    )
    self.assertEqual(
        mqb.get_thresholds_for_tier("DATA_EXFILTRATION_SPIKE", "BALANCED")["m_z"],
        ueba_constants.DEFAULT_ROBUST_THRESHOLD,
    )

    # Router and HandoffEndpoint accept macro tier names directly without collapsing to BALANCED
    router = mqb.MultiStageTemplateRouter()
    q_hr = router.build_query("DATA_EXFILTRATION_SPIKE", tier="HIGH_RECALL")
    q_agg = router.build_query("DATA_EXFILTRATION_SPIKE", tier="AGGRESSIVE")
    self.assertEqual(q_hr, q_agg)

    handoff_hr = mqb.HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-ws2-08",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DATA_EXFILTRATION_SPIKE",
        "target_entity": {"type": "HOSTNAME", "value": "srv-01"},
        "search_window": {"lookback": "24h"},
        "statistical_model": {"name": "DATA_EXFILTRATION_SPIKE", "sensitivity": "HIGH_RECALL"},
    })
    self.assertEqual(handoff_hr["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(handoff_hr["preflight_spec"]["sensitivity_tier"], "AGGRESSIVE")

  def test_sibling_skill_ueba_constants_identical_if_present(self):
    here = Path(__file__).resolve().parent.parent
    local_file = here / "scripts" / "ueba_constants.py"
    self.assertTrue(local_file.exists())

    candidates = []
    if here.name.startswith("secops-statistical-hunter-"):
      suffix = here.name.replace("secops-statistical-hunter-", "")
      candidates.append(here.parent / f"secops-risk-metrics-multistage-{suffix}" / "scripts" / "ueba_constants.py")
    candidates.append(here.parent / "secops-risk-metrics-multistage" / "scripts" / "ueba_constants.py")

    sibling = next((p for p in candidates if p.exists()), None)
    if sibling is None:
      self.skipTest("Sibling ueba_constants.py not yet checked out next to this worktree")
    h1 = hashlib.sha256(local_file.read_bytes()).hexdigest()
    h2 = hashlib.sha256(sibling.read_bytes()).hexdigest()
    self.assertEqual(h1, h2, f"ueba_constants.py drifted between skills: {local_file} vs {sibling}")


if __name__ == "__main__":
  unittest.main()
