# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for WS7-01 (D5 canonical CRI) in secops-statistical-hunter."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
  sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scripts import multistage_query_builder as mqb
from scripts import ueba_constants as uc


class TestWS701CanonicalCRI(unittest.TestCase):
  """WS7-01 / D5: One canonical CRI (0..100, 0 for Z<=0, 26/46/70/90 bands, N/A on missing/error)."""

  def test_canonical_cri_zero_floor_anchors_and_saturation(self) -> None:
    self.assertEqual(uc.calculate_cri(0.0), 0)
    self.assertEqual(uc.calculate_cri(-0.001), 0)
    self.assertEqual(uc.calculate_cri(-5.0), 0)
    self.assertEqual(uc.cri_from_score(0.0), 0)
    self.assertEqual(uc.calculate_cri(3.0), 50)
    self.assertEqual(uc.calculate_cri(6.0), 86)
    self.assertEqual(uc.calculate_cri(15.0), 100)
    self.assertEqual(uc.calculate_cri(3000.0), 100)

    self.assertEqual(mqb.calculate_cri(0.0), 0)
    self.assertEqual(mqb.calculate_cri(-3.0), 0)
    self.assertEqual(mqb.calculate_cri(3.0), 50)
    self.assertEqual(mqb.calculate_cri(6.0), 86)
    self.assertEqual(mqb.calculate_cri(15.0), 100)

  def test_canonical_cri_missing_and_error_values_return_none_and_na(self) -> None:
    for bad_input in (
        None,
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        "N/A",
        "NaN",
        "-",
        "",
        "unparseable_error",
    ):
      with self.subTest(bad_input=bad_input):
        self.assertIsNone(uc.calculate_cri(bad_input))
        self.assertIsNone(mqb.calculate_cri(bad_input))
        self.assertEqual(uc.format_cri(bad_input), "N/A")
        self.assertEqual(mqb.get_cri_badge(bad_input), ("⚪ `[CRI: N/A]`", "N/A"))

  def test_canonical_cri_exact_band_cutoffs_26_46_70_90(self) -> None:
    expected = (
        (0, "INFORMATIONAL", "Nominal", "🟢"),
        (25, "INFORMATIONAL", "Nominal", "🟢"),
        (26, "LOW", "Low Drift", "🟡"),
        (45, "LOW", "Low Drift", "🟡"),
        (46, "MEDIUM", "Medium Outlier", "🟠"),
        (69, "MEDIUM", "Medium Outlier", "🟠"),
        (70, "HIGH", "High Threat", "🔴"),
        (89, "HIGH", "High Threat", "🔴"),
        (90, "CRITICAL", "Critical Outlier", "🚨"),
        (100, "CRITICAL", "Critical Outlier", "🚨"),
    )
    for cri_val, code, label, emoji in expected:
      with self.subTest(cri=cri_val):
        self.assertEqual(uc.get_cri_band_info(cri_val), (code, label, emoji))
        self.assertEqual(mqb.get_cri_badge(cri_val), (f"{emoji} `[CRI: {cri_val}]`", label))

  def test_format_triage_report_missing_or_nan_score_renders_na_cri(self) -> None:
    missing_score_payload = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-missing-score"}}]},
                {"column": "observation_count", "values": [{"value": {"int64Val": "42"}}]},
                {"column": "baseline_active_samples", "values": [{"value": {"int64Val": "120"}}]},
                {"column": "baseline_mean", "values": [{"value": {"doubleVal": 10.0}}]},
                {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 2.0}}]},
            ]
        }
    }
    report_missing = mqb.format_triage_report("Missing Score Test", missing_score_payload)
    self.assertIn("⚪ `[CRI: N/A]`", report_missing)
    self.assertNotIn("`[CRI: 0]`", report_missing)

    nan_score_payload = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-nan-score"}}]},
                {"column": "observation_count", "values": [{"value": {"int64Val": "42"}}]},
                {"column": "z_score", "values": [{"value": {"doubleVal": float("nan")}}]},
            ]
        }
    }
    report_nan = mqb.format_triage_report("NaN Score Test", nan_score_payload)
    self.assertIn("⚪ `[CRI: N/A]`", report_nan)


if __name__ == "__main__":
  unittest.main()
