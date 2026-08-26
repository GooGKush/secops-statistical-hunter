"""Unit tests for Dynamic Time-Window Adaptation and Sample Floor Scaling."""

import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import get_adaptive_window_parameters, check_search_window


class TestWindowAdaptation(unittest.TestCase):

  def test_intra_day_adaptive_parameters(self):
    # 12-hour window -> 10m bins, ~72 buckets, proportional floor >= 12
    p_12h = get_adaptive_window_parameters(12.0, "POISSON_BURST_CLUSTERING", "BALANCED")
    self.assertEqual(p_12h["recommended_bucket"], "10m")
    self.assertEqual(p_12h["total_available_buckets"], 72)
    self.assertGreaterEqual(p_12h["proportional_sample_floor"], 12)

    # 24-hour window -> 15m bins, 96 buckets, proportional floor >= 24
    p_24h = get_adaptive_window_parameters(24.0, "ZSCORE_PROCESS_SURGE", "BALANCED")
    self.assertEqual(p_24h["recommended_bucket"], "15m")
    self.assertEqual(p_24h["total_available_buckets"], 96)
    self.assertEqual(p_24h["proportional_sample_floor"], 24)

  def test_short_window_adaptive_parameters(self):
    # 48-hour window (2 days) -> 1h bins, 48 buckets, proportional floor = 12
    p_48h = get_adaptive_window_parameters(48.0, "ZSCORE_PROCESS_SURGE", "BALANCED")
    self.assertEqual(p_48h["recommended_bucket"], "1h")
    self.assertEqual(p_48h["total_available_buckets"], 48)
    self.assertEqual(p_48h["proportional_sample_floor"], 12)

    # 168-hour window (7 days) -> 1h bins, 168 buckets, proportional floor = 42
    p_7d = get_adaptive_window_parameters(168.0, "ZSCORE_PROCESS_SURGE", "BALANCED")
    self.assertEqual(p_7d["recommended_bucket"], "1h")
    self.assertEqual(p_7d["total_available_buckets"], 168)
    self.assertEqual(p_7d["proportional_sample_floor"], 42)

  def test_search_window_ceilings(self):
    # Valid 7-day multi-stage window -> No errors
    errs_valid = check_search_window("2026-08-01T00:00:00Z", "2026-08-08T00:00:00Z", is_multistage=True)
    self.assertEqual(errs_valid, [])

    # Invalid 45-day multi-stage window -> Violates 30d ceiling
    errs_multi_45d = check_search_window("2026-07-01T00:00:00Z", "2026-08-15T00:00:00Z", is_multistage=True)
    self.assertTrue(any("30-day" in e.lower() for e in errs_multi_45d))

    # Valid 60-day single-stage window -> Allowed under 90d single-stage ceiling
    errs_single_60d = check_search_window("2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z", is_multistage=False)
    self.assertEqual(errs_single_60d, [])

    # Invalid 120-day single-stage window -> Violates 90d ceiling
    errs_single_120d = check_search_window("2026-04-01T00:00:00Z", "2026-08-01T00:00:00Z", is_multistage=False)
    self.assertTrue(any("90-day" in e.lower() for e in errs_single_120d))

  def test_window_sample_mismatch_linter(self):
    # Query requiring 120 active samples executed over a 2-day (48-hour) window -> Mismatch detected!
    mismatch_query = """
    stage s1 { metadata.event_type = "PROCESS_LAUNCH" match: $host by 1h outcome: $c = count(metadata.id) }
    stage s2 { $host = $s1.host match: $host outcome: $active = count($s1.window_start) }
    $host = $s1.host
    match: $host by 1h
    outcome: $out = max($s1.c)
    condition:
      $baseline_active_samples >= 120
    """
    errs_mismatch = check_search_window("2026-08-01T00:00:00Z", "2026-08-03T00:00:00Z", is_multistage=True, query_text=mismatch_query)
    self.assertTrue(any("AUTOMATIC QUERY FAILURE" in e for e in errs_mismatch))


if __name__ == "__main__":
  unittest.main()
