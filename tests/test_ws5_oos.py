"""Regression and golden math tests for WS5-OOS: Leave-One-Out Baselines & Continuous SD Floors."""

import math
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
    validate_multistage_syntax,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestWS5OutOfSampleBaselines(unittest.TestCase):
  """Verifies WS5-OOS leave-one-out (n-1) baselines, continuous SD floors, and multi-sector fusion."""

  def test_golden_compute_loo_zscore_eliminates_samuelson_masking_and_zero_sd_cliff(self):
    """Golden math: LOO Z-score unmasks single massive spikes and avoids σ=0 -> 1.0 cliffs."""
    self.assertTrue(
        hasattr(mqb, "compute_loo_zscore"),
        "multistage_query_builder must export compute_loo_zscore for WS5-OOS verification",
    )

    # 1. Single extreme spike [10, 10, 10, 10, 10, 100]:
    # In-sample gives mean=25, sample_sd=36.74 -> z=2.04 (masked below 3.0!).
    # LOO gives n_prior=5, loo_mean=10.0, loo_sd=0.0, poisson_floor=sqrt(10)=3.1623 -> z=28.46!
    spike_res = mqb.compute_loo_zscore([10, 10, 10, 10, 10], 100, floor_mode="poisson")
    self.assertEqual(spike_res["n_prior"], 5)
    self.assertAlmostEqual(spike_res["loo_mean"], 10.0, places=6)
    self.assertAlmostEqual(spike_res["loo_sd"], 0.0, places=6)
    self.assertAlmostEqual(spike_res["safe_sd"], math.sqrt(10.0), places=6)
    self.assertAlmostEqual(spike_res["z_score"], 90.0 / math.sqrt(10.0), places=5)

    # 2. Steady server [103]*10 with observed=106 (+3 events):
    # Under old σ=0 -> 1.0 fallback, +3 events triggered +3.0σ false positive!
    # Under continuous sqrt(max(mean, 1.0)) floor, safe_sd = sqrt(103) = 10.1489 -> z = 0.2956σ.
    steady_res = mqb.compute_loo_zscore([103] * 10, 106, floor_mode="poisson")
    self.assertAlmostEqual(steady_res["safe_sd"], math.sqrt(103.0), places=6)
    self.assertLess(steady_res["z_score"], 0.35)

    # 3. Log-normal 0.25 log-SD floor: <2x byte shift (ln(1.8M) vs ln(1.0M)) stays < 2.5σ,
    # whereas 10x exfiltration shift (ln(10M) vs ln(1M)) exceeds 9.0σ.
    prior_logs = [math.log(1_000_000.0 + 1.0)] * 8
    mild_shift = mqb.compute_loo_zscore(prior_logs, math.log(1_800_000.0 + 1.0), floor_mode="fixed", fixed_floor=0.25)
    self.assertAlmostEqual(mild_shift["safe_sd"], 0.25, places=6)
    self.assertLess(mild_shift["z_score"], 2.5)

    exfil_shift = mqb.compute_loo_zscore(prior_logs, math.log(10_000_000.0 + 1.0), floor_mode="fixed", fixed_floor=0.25)
    self.assertGreater(exfil_shift["z_score"], 9.0)

  def test_zscore_process_surge_uses_loo_baseline_and_continuous_poisson_floor(self):
    """zscore_process_surge_2stage.yl2 excludes scored bucket (n-1) and drops min_sd condition cliff."""
    router = MultiStageTemplateRouter()
    for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
      for entity_type in ("host", "user", "ip"):
        with self.subTest(tier=tier, entity_type=entity_type):
          q = router.build_query("ZSCORE_PROCESS_SURGE", tier=tier, entity_type=entity_type)
          gate = QueryIntegrityGate.verify_pre_dispatch(q)
          self.assertTrue(gate["valid"], f"Pre-dispatch failed ({tier}, {entity_type}): {gate['errors']}")
          self.assertIn("$hourly_count_sq", q)
          self.assertIn("$sum_x = sum($host_hourly.hourly_count)", q)
          self.assertIn("$sum_x2 = sum($host_hourly.hourly_count_sq)", q)
          self.assertNotIn("avg($host_hourly.hourly_count)", q)
          self.assertNotIn("stddev($host_hourly.hourly_count)", q)
          self.assertIn("max($host_stats.active_samples) - 1", q)
          self.assertIn("max($host_stats.sum_x) - $observation_count", q)
          self.assertIn("math.sqrt(", q)
          cond_section = q.split("condition:", 1)[1]
          self.assertNotIn("$baseline_dispersion >=", cond_section)

  def test_log_normal_volume_surge_uses_loo_025_floor_and_byte_consistent_pillars(self):
    """log_normal_volume_surge_2stage.yl2 uses LOO log stats, 0.25 log-SD floor, and byte-scale pillars."""
    router = MultiStageTemplateRouter()
    for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
      for entity_type in ("host", "user", "ip"):
        with self.subTest(tier=tier, entity_type=entity_type):
          q = router.build_query("LOG_NORMAL_VOLUME_SURGE", tier=tier, entity_type=entity_type)
          gate = QueryIntegrityGate.verify_pre_dispatch(q)
          self.assertTrue(gate["valid"], f"Pre-dispatch failed ({tier}, {entity_type}): {gate['errors']}")
          self.assertIn("$log_bytes_sq", q)
          self.assertIn("$sum_log = sum($host_bytes.log_bytes)", q)
          self.assertIn("$sum_log2 = sum($host_bytes.log_bytes_sq)", q)
          self.assertNotIn("avg($host_bytes.log_bytes)", q)
          self.assertNotIn("stddev($host_bytes.log_bytes)", q)
          self.assertIn("0.25", q)
          # Report pillars must all be in bytes (never mixing event_count, bytes, and log-bytes)
          self.assertIn("$observation_count = $observed_bytes", q)
          self.assertIn("$baseline_mean = math.pow(2.718281828, $baseline_mean_log)", q)
          self.assertRegex(
              q,
              r"\$baseline_dispersion\s*=\s*math\.pow\(2\.718281828,\s*\$baseline_mean_log\s*\+\s*\$baseline_dispersion_log\)\s*-\s*\$baseline_mean",
          )

  def test_multi_sector_threat_fusion_coalesces_entities_matches_fail_and_uses_loo_sector_floors(self):
    """multi_sector_threat_fusion_4stage.yl2 coalesces host/IP & target/principal user, checks BLOCK|FAIL, and uses LOO + sqrt(max(mean, 1.0))."""
    router = MultiStageTemplateRouter()

    q_host = router.build_query("MULTI_SECTOR_THREAT_FUSION", tier="BALANCED", entity_type="host")
    q_ip = router.build_query("MULTI_SECTOR_THREAT_FUSION", tier="BALANCED", entity_type="ip")
    q_user = router.build_query("MULTI_SECTOR_THREAT_FUSION", tier="BALANCED", entity_type="user")

    for mode, q in (("host", q_host), ("ip", q_ip), ("user", q_user)):
      with self.subTest(mode=mode):
        gate = QueryIntegrityGate.verify_pre_dispatch(q)
        self.assertTrue(gate["valid"], f"Pre-dispatch failed ({mode}): {gate['errors']}")
        errs = [e for e in validate_multistage_syntax(q) if not e.startswith("MISSING METHODOLOGY HEADER")]
        self.assertEqual(errs, [])
        # Must count both BLOCK and FAIL on USER_LOGIN
        self.assertIn('"BLOCK"', q)
        self.assertIn('"FAIL"', q)
        # Must compute leave-one-out means and variances in sector_loo via $n_prior and $df_prior
        # (Root never reads contaminated $host_sector_baseline moments directly)
        self.assertIn("$n_prior = if($raw_n_prior > 1, $raw_n_prior, 1)", q)
        self.assertIn("$df_prior = if($raw_df > 1, $raw_df, 1)", q)
        root_tail = q.split("stage sector_loo")[-1].split("}", 1)[-1]
        self.assertNotIn("$host_sector_baseline.", root_tail)
        self.assertIn("strings.coalesce(", q)
        # Positive-rectified sector Zs before squaring
        self.assertRegex(q, r"\$pos_z1\s*=\s*if\(\$z1\s*>\s*0(?:\.0)?,\s*\$z1,\s*0\.0\)")
        self.assertRegex(q, r"\$pos_z2\s*=\s*if\(\$z2\s*>\s*0(?:\.0)?,\s*\$z2,\s*0\.0\)")
        self.assertRegex(q, r"\$pos_z3\s*=\s*if\(\$z3\s*>\s*0(?:\.0)?,\s*\$z3,\s*0\.0\)")
        # True 4-stage pipeline (3 named stages + unwrapped root)
        named_stages = re.findall(r"\bstage\s+([a-zA-Z0-9_]+)\s*\{", q)
        self.assertEqual(len(named_stages), 3, f"Expected 3 named stages (+ root = 4 stages), got {named_stages}")

    # Host & IP modes coalesce principal.hostname and indexed principal.ip[0]
    self.assertIn("$e.principal.hostname", q_host)
    self.assertIn("$e.principal.ip[0]", q_host)
    self.assertIn("$e.principal.ip[0]", q_ip)
    self.assertIn("$e.principal.hostname", q_ip)

    # User mode coalesces target.user.userid and principal.user.userid
    self.assertIn("strings.coalesce($e.target.user.userid, $e.principal.user.userid)", q_user)


if __name__ == "__main__":
  unittest.main()
