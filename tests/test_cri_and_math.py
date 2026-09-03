"""Unit tests for Calibrated Risk Index (CRI) and DataReductionEngine."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import calculate_cri, get_cri_badge, DataReductionEngine


class TestCRIAndMath(unittest.TestCase):

  def test_cri_nominal_baseline(self):
    """Zero or negative deviations must yield CRI = 0 (Nominal)."""
    self.assertEqual(calculate_cri(0.0), 0)
    self.assertEqual(calculate_cri(-1.5), 0)
    self.assertEqual(calculate_cri(-100.0), 0)

  def test_cri_medium_outlier_boundary(self):
    """Z = 3.0σ must strictly map to CRI = 50 (Medium Outlier boundary)."""
    self.assertEqual(calculate_cri(3.0), 50)

  def test_cri_high_threat_threshold(self):
    """Z = 6.0σ must exceed High Threat boundary (CRI >= 84 and <= 88)."""
    cri_6 = calculate_cri(6.0)
    self.assertGreaterEqual(cri_6, 84)
    self.assertLessEqual(cri_6, 88)

  def test_cri_asymptotic_upper_bound(self):
    """Extreme Z-scores (e.g. +3000σ on quiet accounts) must asymptote safely to 100 without overflow."""
    self.assertEqual(calculate_cri(15.0), 100)
    self.assertEqual(calculate_cri(100.0), 100)
    self.assertEqual(calculate_cri(3000.0), 100)

  def test_cri_tier_badges(self):
    """Operational tier badges must correctly reflect CRI score ranges."""
    badge_0, tier_0 = get_cri_badge(0)
    self.assertIn("🟢", badge_0)
    self.assertEqual(tier_0, "Nominal")

    badge_35, tier_35 = get_cri_badge(35)
    self.assertIn("🟡", badge_35)
    self.assertEqual(tier_35, "Low Drift")

    badge_50, tier_50 = get_cri_badge(50)
    self.assertIn("🟠", badge_50)
    self.assertEqual(tier_50, "Medium Outlier")

    badge_75, tier_75 = get_cri_badge(75)
    self.assertIn("🔴", badge_75)
    self.assertEqual(tier_75, "High Threat")

    badge_95, tier_95 = get_cri_badge(95)
    self.assertIn("🚨", badge_95)
    self.assertEqual(tier_95, "Critical Outlier")

  def test_data_reduction_engine_empty(self):
    """DataReductionEngine must handle empty payloads safely."""
    reduced = DataReductionEngine.reduce([], top_n=5)
    self.assertEqual(reduced["total_entities_evaluated"], 0)
    self.assertEqual(reduced["outlier_count"], 0)
    self.assertEqual(reduced["top_outliers"], [])

  def test_data_reduction_engine_sorting_and_truncation(self):
    """DataReductionEngine must sort by anomaly score descending and truncate to top_n."""
    raw = [
        {"host": "host-1", "z_score": 2.5},
        {"host": "host-2", "z_score": 8.1},
        {"host": "host-3", "z_score": 1.2},
        {"host": "host-4", "z_score": 15.4},
        {"host": "host-5", "z_score": 4.0},
        {"host": "host-6", "z_score": 0.5},
    ]
    reduced = DataReductionEngine.reduce(raw, top_n=3)
    self.assertEqual(reduced["total_entities_evaluated"], 6)
    self.assertEqual(reduced["outlier_count"], 6)
    self.assertEqual(len(reduced["top_outliers"]), 3)
    self.assertEqual(reduced["top_outliers"][0]["host"], "host-4")
    self.assertEqual(reduced["top_outliers"][1]["host"], "host-2")
    self.assertEqual(reduced["top_outliers"][2]["host"], "host-5")

  def test_data_reduction_engine_cv_inversion(self):
    """For Coefficient of Variation, lower jitter (lower CV) is more anomalous."""
    raw = [
        {"host": "host-1", "cv": 0.45},
        {"host": "host-2", "cv": 0.05},
        {"host": "host-3", "cv": 0.18},
    ]
    reduced = DataReductionEngine.reduce(raw, top_n=2)
    self.assertEqual(reduced["top_outliers"][0]["host"], "host-2")  # CV = 0.05 (most anomalous)
    self.assertEqual(reduced["top_outliers"][1]["host"], "host-3")  # CV = 0.18


if __name__ == "__main__":
  unittest.main()
