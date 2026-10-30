# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Tests for WS7-03 (expected-maximum fleet label, fusion sector correlation, CRI guide fix) and WS8-04 byte defaults."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.multistage_query_builder import (  # pylint: disable=wrong-import-position
    HandoffEndpoint,
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    calculate_cri,
    calculate_fleet_adjusted_threshold,
    format_triage_report,
)


def _make_columnar_stats(score_col: str, score_val: float, entity: str = "host-alpha") -> dict:
  return {
      "stats": {
          "results": [
              {"column": "host", "values": [{"value": {"stringVal": entity}}]},
              {"column": "TIME_BUCKET", "values": [{"value": {"stringVal": "2026-08-24T08:00:00Z"}}]},
              {"column": "observation_count", "values": [{"value": {"int64Val": 850}}]},
              {"column": "baseline_active_samples", "values": [{"value": {"int64Val": 120}}]},
              {"column": "baseline_mean", "values": [{"value": {"doubleVal": 250.0}}]},
              {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 35.0}}]},
              {"column": "fleet_prevalence", "values": [{"value": {"int64Val": 1}}]},
              {"column": "distinct_binaries", "values": [{"value": {"int64Val": 42}}]},
              {"column": score_col, "values": [{"value": {"doubleVal": score_val}}]},
          ]
      }
  }


class TestWS703AndWS804Polish(unittest.TestCase):
  """Verifies WS7-03 statistical documentation accuracy and WS8-04 EXFILTRATION_IQR_OUTLIER byte defaults."""

  def test_ws7_03_fleet_threshold_labeled_as_expected_maximum_not_bonferroni(self) -> None:
    """sqrt(2 ln N) is labeled as the Gaussian expected-maximum approximation, never as a Bonferroni bound."""
    doc = (calculate_fleet_adjusted_threshold.__doc__ or "").lower()
    self.assertIn("expected-maximum", doc)
    self.assertNotIn("bonferroni / extreme value", doc)

    report = format_triage_report(
        "Process Surge",
        _make_columnar_stats("z_score", 17.14),
        fleet_size=1000,
    )
    self.assertIn("Expected-Maximum", report)
    self.assertIn(r"\sqrt{2 \ln N}", report)
    self.assertIn("not a Bonferroni correction", report)
    self.assertNotIn("Bonferroni Threshold", report)
    self.assertNotIn("Bonferroni / Gumbel Tail", report)
    self.assertNotIn("Controls fleet-wide false discovery probability at", report)

    taxonomy_md = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    self.assertNotIn("Bonferroni Extreme Value Bound", taxonomy_md)
    self.assertIn("Expected-Maximum", taxonomy_md)
    self.assertIn("not** a Bonferroni correction", taxonomy_md)

    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("Expected Maximum", skill_md)
    self.assertIn("not Bonferroni", skill_md)

  def test_ws7_03_multi_sector_fusion_sector_correlation_caveat_documented(self) -> None:
    """SKILL.md, taxonomy, CRI guide, and fusion triage reports state that fusion FP rates depend on sector correlation."""
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    fusion_lines = [line for line in skill_md.splitlines() if "MULTI_SECTOR_FUSION" in line]
    self.assertTrue(fusion_lines)
    self.assertTrue(
        any("correlat" in line.lower() for line in fusion_lines),
        "SKILL.md MULTI_SECTOR_FUSION row must disclose sector-correlation impact on false-positive rates.",
    )

    taxonomy_md = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    sec5 = taxonomy_md.split("## 5.", 1)[1].split("## 6.", 1)[0]
    sec10 = taxonomy_md.split("## 10.", 1)[1].split("## 11.", 1)[0]
    self.assertIn("correlated", sec5.lower())
    self.assertIn("\\chi^2", sec5)
    self.assertIn("correlated", sec10.lower())

    cri_guide = (REPO_ROOT / "references" / "calibrated-risk-index-guide.md").read_text(encoding="utf-8")
    self.assertIn("sector correlation", cri_guide.lower())
    self.assertIn("not a bonferroni correction", cri_guide.lower())

    fusion_report = format_triage_report(
        "Multi-Sector Fusion",
        _make_columnar_stats("threat_distance", 5.20, entity="wkstn-prod-042"),
    )
    self.assertIn("correlat", fusion_report.lower())

  def test_ws7_03_calibrated_risk_index_guide_examples_match_calculate_cri(self) -> None:
    """Every example row in calibrated-risk-index-guide.md §5 matches calculate_cri(z) (no +0.25σ -> CRI 0)."""
    cri_guide = (REPO_ROOT / "references" / "calibrated-risk-index-guide.md").read_text(encoding="utf-8")
    self.assertNotIn("`+0.25σ`", cri_guide)
    pairs = re.findall(r"\(`([+-]?\d+(?:\.\d+)?)σ`\)\s*\|\s*[^|]*`\[CRI:\s*(\d+)\]`", cri_guide)
    self.assertGreaterEqual(len(pairs), 3)
    for z_str, cri_str in pairs:
      z_val = float(z_str)
      expected_cri = calculate_cri(z_val)
      self.assertEqual(
          int(cri_str),
          expected_cri,
          f"CRI guide mismatch for Z={z_val}: guide has CRI={cri_str}, calculate_cri={expected_cri}",
      )

  def test_ws8_04_exfiltration_iqr_outlier_defaults_to_network_connection_sent_bytes(self) -> None:
    """EXFILTRATION_IQR_OUTLIER defaults to NETWORK_CONNECTION + sum(network.sent_bytes) while generic IQR stays DNS."""
    router = MultiStageTemplateRouter()
    exfil_q = router.build_query("EXFILTRATION_IQR_OUTLIER", target_entity_value="wkstn-prod-042")
    self.assertIn('metadata.event_type = "NETWORK_CONNECTION"', exfil_q)
    self.assertIn("$daily_value = sum(network.sent_bytes)", exfil_q)
    self.assertIn("count_distinct(target.ip)", exfil_q)
    self.assertEqual(
        QueryIntegrityGate.verify_pre_dispatch(exfil_q, expected_entity="wkstn-prod-042"),
        {"valid": True, "errors": []},
    )

    generic_q = router.build_query("IQR_TUKEY_SKEW_FENCES", target_entity_value="wkstn-prod-042")
    self.assertIn('metadata.event_type = "NETWORK_DNS"', generic_q)
    self.assertIn("$daily_value = count(metadata.id)", generic_q)

    ack = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-exfil-iqr-bytes",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "EXFILTRATION_IQR_OUTLIER",
        "target_entity": {"type": "HOSTNAME", "value": "wkstn-prod-042"},
        "search_window": {"lookback": "14d"},
    })
    self.assertEqual(ack["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(ack["model_routed"], "IQR_TUKEY_SKEW_FENCES")
    self.assertIn('metadata.event_type = "NETWORK_CONNECTION"', ack["compiled_query"])
    self.assertIn("$daily_value = sum(network.sent_bytes)", ack["compiled_query"])

    bad_ack = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-exfil-bad-agg",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "EXFILTRATION_IQR_OUTLIER",
        "target_entity": {"type": "HOSTNAME", "value": "wkstn-prod-042"},
        "daily_aggregation": "sum(network.sent_bytes); condition: true",
    })
    self.assertEqual(bad_ack["status"], "HANDOFF_ACK_REJECTED")


if __name__ == "__main__":
  unittest.main()
