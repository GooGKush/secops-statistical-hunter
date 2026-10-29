"""Regression and golden-math tests for WS1-06: Zero-Inclusive Raw Dispersion & Spray Variants."""

import os
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
import multistage_query_builder as mqb
from multistage_query_builder import (
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    SENSITIVITY_MAP,
    validate_multistage_syntax,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestWS106ZeroInclusiveDispersion(unittest.TestCase):
  """Verifies PF-4 / WS1-06 zero-inclusive Fano dispersion math and template rendering."""

  def test_golden_gus_sdl_zero_inclusive_fano_entities(self):
    """Golden math check on gus-sdl concentrated failure entities over T=168 hourly buckets."""
    self.assertTrue(
        hasattr(mqb, "compute_zero_inclusive_dispersion"),
        "compute_zero_inclusive_dispersion must be exported by multistage_query_builder",
    )
    fn = mqb.compute_zero_inclusive_dispersion

    # 1. Source IP 10.1.0.50: 648 failures/hr across 7 active hours out of 168h (sum=4536)
    # Active-only variance is 0.0 (Fano=0.0), hiding the spray completely; zero-inclusive Fano is 621.0.
    res_ip = fn([648] * 7, total_buckets=168)
    self.assertEqual(res_ip["active_buckets"], 7)
    self.assertEqual(res_ip["total_buckets"], 168)
    self.assertAlmostEqual(res_ip["sum_x"], 4536.0, places=6)
    self.assertAlmostEqual(res_ip["sum_x2"], 2939328.0, places=6)
    self.assertAlmostEqual(res_ip["mean"], 27.0, places=6)
    self.assertAlmostEqual(res_ip["variance"], 16767.0, places=6)
    self.assertAlmostEqual(res_ip["fano_factor"], 621.0, places=6)

    # 2. Target user frank.kolzig: 60 failures/hr across 7 active hours out of 168h (sum=420)
    res_fk = fn([60] * 7, total_buckets=168)
    self.assertAlmostEqual(res_fk["sum_x"], 420.0, places=6)
    self.assertAlmostEqual(res_fk["mean"], 2.5, places=6)
    self.assertAlmostEqual(res_fk["variance"], 143.75, places=6)
    self.assertAlmostEqual(res_fk["fano_factor"], 57.5, places=6)

    # 3. Target user jeff.armstrong: 50 failures/hr across 7 active hours out of 168h (sum=350)
    res_ja = fn([50] * 7, total_buckets=168)
    self.assertAlmostEqual(res_ja["sum_x"], 350.0, places=6)
    self.assertAlmostEqual(res_ja["mean"], 2.0833333333, places=6)
    self.assertAlmostEqual(res_ja["variance"], 99.8263888889, places=6)
    self.assertAlmostEqual(res_ja["fano_factor"], 47.9166666667, places=6)

    # 4. Empty bucket list returns zeroed statistics safely; non-positive T fails closed.
    res_empty = fn([], total_buckets=168)
    self.assertEqual(res_empty["mean"], 0.0)
    self.assertEqual(res_empty["variance"], 0.0)
    self.assertEqual(res_empty["fano_factor"], 0.0)
    with self.assertRaises(ValueError):
      fn([10], total_buckets=0)
    with self.assertRaises(ValueError):
      fn([10, 20, 30], total_buckets=2)

  def test_total_window_buckets_computation_and_override(self):
    """Router computes {{total_window_buckets}} from window_hours & bucket_size, with override support."""
    self.assertTrue(
        hasattr(mqb, "compute_total_window_buckets"),
        "compute_total_window_buckets must be exported by multistage_query_builder",
    )
    self.assertEqual(mqb.compute_total_window_buckets(168, "1h"), 168)
    self.assertEqual(mqb.compute_total_window_buckets(24, "1h"), 24)
    self.assertEqual(mqb.compute_total_window_buckets(336, "1d"), 14)
    self.assertEqual(mqb.compute_total_window_buckets(24, "15m"), 96)
    self.assertEqual(mqb.compute_total_window_buckets(12, "10m"), 72)

    router = MultiStageTemplateRouter()
    q_7d = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="user", window_hours=168)
    self.assertIn("$total_buckets = 168", q_7d)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_7d)["valid"])

    q_14d_daily = router.build_query(
        "POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="user", window_hours=336, bucket_size="1d"
    )
    self.assertIn("$total_buckets = 14", q_14d_daily)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_14d_daily)["valid"])

    q_override = router.build_query(
        "POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="user", window_hours=168, total_window_buckets=200
    )
    self.assertIn("$total_buckets = 200", q_override)

  def test_stage2_unnesting_invariant_and_zero_inclusive_ast(self):
    """Stage 2 (dispersion_baseline) must be 100% numeric with zero array_distinct alongside sum()."""
    router = MultiStageTemplateRouter()
    query = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="user", window_hours=168)

    # Extract Stage 2 dispersion_baseline block
    m_stage2 = re.search(r"stage\s+dispersion_baseline\s*\{([^}]*)\}", query, re.DOTALL)
    self.assertIsNotNone(m_stage2, "dispersion_baseline stage missing")
    stage2_body = m_stage2.group(1)
    self.assertNotIn("array_distinct", stage2_body, "YARA-L unnesting hazard: never put array_distinct in Stage 2 alongside sum()")
    self.assertNotIn("avg(", stage2_body, "Active-only avg() must not be used in dispersion_baseline")
    self.assertNotIn("stddev(", stage2_body, "Active-only stddev() must not be used in dispersion_baseline")
    self.assertIn("$sum_x = sum($hourly_failures.hourly_fails)", stage2_body)
    self.assertIn("$sum_x2 = sum($hourly_failures.hourly_fails_sq)", stage2_body)
    self.assertIn("$active_hours = count($hourly_failures.window_start)", stage2_body)

    # Root stage computes zero-inclusive mean, variance, sd, and Fano factor cleanly
    for expected_snippet in (
        "$zero_incl_mean = $sum_x / $safe_buckets",
        "$mean_sq = $sum_x2 / $safe_buckets",
        "$raw_var = $mean_sq - ($zero_incl_mean * $zero_incl_mean)",
        "$zero_incl_var = if($raw_var > 0.0, $raw_var, 0.0)",
        "$zero_incl_sd = math.sqrt($zero_incl_var)",
        "$raw_fano = $zero_incl_var / $safe_mean",
        "$fano_factor = if($zero_incl_mean > 0.0, $raw_fano, 0.0)",
    ):
      self.assertIn(expected_snippet, query)

    errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(errs, [])

  def test_target_keyed_and_source_keyed_spray_variants(self):
    """POISSON_BURST_CLUSTERING supports both target-keyed (USER) and source-keyed (IP) spray hunts."""
    router = MultiStageTemplateRouter()

    q_target = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="USER", window_hours=168)
    self.assertIn("target.user.userid = $entity", q_target)
    self.assertIn("array_distinct(principal.ip)", q_target)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_target)["valid"])

    q_source = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="IP", window_hours=168)
    self.assertIn("principal.ip = $entity", q_source)
    self.assertIn("array_distinct(target.user.userid)", q_source)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_source)["valid"])

  def test_sensitivity_calibration_allows_real_concentrated_bursts(self):
    """min_mu and condition gates allow concentrated 7-hour bursts over T=168h (and 336h) to pass."""
    pbc_tiers = SENSITIVITY_MAP["POISSON_BURST_CLUSTERING"]
    self.assertAlmostEqual(pbc_tiers["CONSERVATIVE"]["min_mu"], 0.2)
    self.assertAlmostEqual(pbc_tiers["BALANCED"]["min_mu"], 0.1)
    self.assertAlmostEqual(pbc_tiers["AGGRESSIVE"]["min_mu"], 0.05)

    # Verify that 7-active-hour bursts over T=168 (jeff.armstrong: active=7, sum=350, mu=2.083, F=47.92)
    # are NOT blocked by an active-only sample gate >= 30 in Root condition!
    router = MultiStageTemplateRouter()
    q_bal = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", entity_type="user", window_hours=168)
    cond_match = re.search(r"condition:\s*(.*?)(?:\norder:|\Z)", q_bal, re.DOTALL)
    self.assertIsNotNone(cond_match)
    cond_text = cond_match.group(1)
    # Any gate on $baseline_active_samples in POISSON_BURST_CLUSTERING must allow concentrated bursts (<= 7 active hours)
    m_active_gate = re.search(r"\$baseline_active_samples\s*>=\s*(\d+)", cond_text)
    if m_active_gate:
      self.assertLessEqual(
          int(m_active_gate.group(1)),
          7,
          "Concentrated sprays occur in a handful of active hours (e.g. 1..7 of 168); $baseline_active_samples gate must not block them!",
      )

  def test_poisson_burst_clustering_example_fixed(self):
    """examples/poisson_burst_clustering.yara uses USER_LOGIN and zero-inclusive Fano math."""
    ex_path = REPO_ROOT / "examples" / "poisson_burst_clustering.yara"
    ex_text = ex_path.read_text()
    self.assertIn('metadata.event_type = "USER_LOGIN"', ex_text)
    self.assertNotIn('metadata.event_type = "PROCESS_LAUNCH"', ex_text)
    self.assertIn("$sum_x2 = sum($hourly_failures.hourly_fails_sq)", ex_text)
    self.assertIn("$zero_incl_var", ex_text)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(ex_text)["valid"])


if __name__ == "__main__":
  unittest.main()
