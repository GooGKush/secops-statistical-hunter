"""Regression tests for WS5-LIVE-FIXES: Malachite compiler laws A-D and 4 fixed multi-stage topologies."""

from __future__ import annotations

import math
from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from multistage_query_builder import (  # noqa: E402
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    audit_query_execution,
    validate_multistage_syntax,
)


def _outcome_var_counts(query: str) -> list[int]:
  """Returns outcome assignment counts for each stage block and the unwrapped root block."""
  code = re.sub(r"//.*", "", query)
  counts: list[int] = []
  stage_blocks = re.findall(r"stage\s+[A-Za-z0-9_]+\s*\{([^}]*)\}", code, flags=re.DOTALL)
  for sb in stage_blocks:
    om = re.search(r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)|\Z)", sb, flags=re.DOTALL)
    if om:
      vars_found = re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", om.group(1))
      counts.append(len(vars_found))
  stripped_root = re.sub(r"stage\s+[A-Za-z0-9_]+\s*\{[^}]*\}", "", code, flags=re.DOTALL)
  rom = re.search(
      r"outcome\s*:(.*?)(?=\n\s*(?:condition|order)\s*:|\Z)",
      stripped_root,
      flags=re.DOTALL,
  )
  if rom:
    vars_found = re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", rom.group(1))
    counts.append(len(vars_found))
  return counts


class TestCompilerGuardrailLaws(unittest.TestCase):
  """Static QueryIntegrityGate / validate_multistage_syntax enforcement of Malachite Laws A-D."""

  def test_law_a_outcome_limit_20_enforced_in_stage_and_root(self) -> None:
    stage_21_vars = "\n".join(f"    $v{i} = count(metadata.id)" for i in range(21))
    bad_stage = f"""
    // Goal: Law A stage >20 outcomes
    stage s1 {{
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $h
      match: $h by 1h
      outcome:
{stage_21_vars}
    }}
    $h = $s1.h
    $ws = $s1.window_start
    match: $h, $ws by 1h
    outcome:
      $obs = max($s1.v0)
    condition:
      $obs >= 1
    """
    qa_stage = QueryIntegrityGate.verify_pre_dispatch(bad_stage)
    self.assertFalse(qa_stage["valid"])
    self.assertTrue(
        any("OutcomeLimit = 20" in e for e in qa_stage["errors"]),
        f"Expected OutcomeLimit = 20 error on stage, got: {qa_stage['errors']}",
    )

    root_21_vars = "\n".join(f"  $r{i} = max($s1.c) + {i}" for i in range(21))
    bad_root = f"""
    // Goal: Law A root >20 outcomes
    stage s1 {{
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $h
      match: $h by 1h
      outcome:
        $c = count(metadata.id)
    }}
    $h = $s1.h
    $ws = $s1.window_start
    match: $h, $ws by 1h
    outcome:
{root_21_vars}
    condition:
      $r0 >= 1
    """
    qa_root = QueryIntegrityGate.verify_pre_dispatch(bad_root)
    self.assertFalse(qa_root["valid"])
    self.assertTrue(
        any("OutcomeLimit = 20" in e for e in qa_root["errors"]),
        f"Expected OutcomeLimit = 20 error on root, got: {qa_root['errors']}",
    )

  def test_law_b_expanded_arithmetic_ops_limit_50_and_stage_boundary_reset(self) -> None:
    # $a has 4 ops; $b = $a + $a + $a + $a -> 4*4 + 3 = 19 ops;
    # $c = $b + $b + $b -> 3*19 + 2 = 59 ops > 50!
    bad_chained = """
    // Goal: Law B >50 expanded arithmetic ops
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $h
      match: $h by 1h
      outcome:
        $c = count(metadata.id)
    }
    $h = $s1.h
    $ws = $s1.window_start
    match: $h, $ws by 1h
    outcome:
      $x = max($s1.c)
      $a = $x + $x + $x + $x + $x
      $b = $a + $a + $a + $a
      $c = $b + $b + $b
    condition:
      $c >= 1
    """
    qa_bad = QueryIntegrityGate.verify_pre_dispatch(bad_chained)
    self.assertFalse(qa_bad["valid"])
    self.assertTrue(
        any("ARITHMETIC_OP_LIMIT_EXCEEDED" in e for e in qa_bad["errors"]),
        f"Expected ARITHMETIC_OP_LIMIT_EXCEEDED, got: {qa_bad['errors']}",
    )

    # Splitting $b into intermediate stage s2 resets ParentOutcomeVariables in root!
    good_split = """
    // Goal: Law B stage boundary resets op count
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $h
      match: $h by 1h
      outcome:
        $c = count(metadata.id)
    }
    stage s2 {
      $h = $s1.h
      $ws = $s1.window_start
      match: $h, $ws by 1h
      outcome:
        $x = max($s1.c)
        $a = $x + $x + $x + $x + $x
        $b = $a + $a + $a + $a
    }
    $h = $s2.h
    $ws = $s2.ws
    match: $h, $ws by 1h
    outcome:
      $c = max($s2.b) + max($s2.b) + max($s2.b)
    condition:
      $c >= 1
    """
    qa_good = QueryIntegrityGate.verify_pre_dispatch(good_split)
    self.assertTrue(qa_good["valid"], f"Stage-split query should pass: {qa_good['errors']}")

  def test_law_c_repeated_ip_in_strings_coalesce_rejected_unless_indexed(self) -> None:
    for bad_expr in (
        "strings.coalesce($e.principal.hostname, $e.principal.ip)",
        "strings.coalesce(target.asset.hostname, target.hostname, target.ip)",
        "strings.coalesce(principal.asset.hostname, principal.asset.ip)",
        "strings.coalesce(target.asset.ip, target.hostname)",
    ):
      with self.subTest(bad_expr=bad_expr):
        q = f"""
        // Goal: Law C unindexed repeated IP
        stage s1 {{
          $e.metadata.event_type = "USER_LOGIN"
          $entity = {bad_expr}
          $entity != ""
          match: $entity by 1h
          outcome:
            $c = count($e.metadata.id)
        }}
        $entity = $s1.entity
        $ws = $s1.window_start
        match: $entity, $ws by 1h
        outcome:
          $obs = max($s1.c)
        condition:
          $obs >= 1
        """
        qa = QueryIntegrityGate.verify_pre_dispatch(q)
        self.assertFalse(qa["valid"], f"Expected rejection for {bad_expr}")
        self.assertTrue(
            any("REPEATED_IP_IN_COALESCE" in e for e in qa["errors"]),
            f"Expected REPEATED_IP_IN_COALESCE for {bad_expr}, got: {qa['errors']}",
        )

    good_q = """
    // Goal: Law C indexed IP[0] in coalesce
    stage s1 {
      $e.metadata.event_type = "USER_LOGIN"
      $entity = strings.coalesce($e.principal.hostname, $e.principal.asset.hostname, $e.principal.ip[0])
      $entity != ""
      match: $entity by 1h
      outcome:
        $c = count($e.metadata.id)
    }
    $entity = $s1.entity
    $ws = $s1.window_start
    match: $entity, $ws by 1h
    outcome:
      $obs = max($s1.c)
    condition:
      $obs >= 1
    """
    qa_good = QueryIntegrityGate.verify_pre_dispatch(good_q)
    self.assertTrue(qa_good["valid"], f"Indexed .ip[0] should pass: {qa_good['errors']}")

  def test_law_d_uint64_bytes_if_conflict_raw_count_distinct_sq_and_placeholder_regex(self) -> None:
    bad_cd_sq = """
    // Goal: Law D count_distinct squaring in raw stage
    stage s1 {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.hostname = $h
      match: $h by 1h
      outcome:
        $k2 = 1.0 * count_distinct(target.ip) * count_distinct(target.ip)
    }
    $h = $s1.h
    $ws = $s1.window_start
    match: $h, $ws by 1h
    outcome:
      $obs = max($s1.k2)
    condition:
      $obs >= 1
    """
    qa_cd = QueryIntegrityGate.verify_pre_dispatch(bad_cd_sq)
    self.assertFalse(qa_cd["valid"])
    self.assertTrue(
        any("RAW_STAGE_COUNT_DISTINCT_SQUARING" in e for e in qa_cd["errors"]),
        f"Expected RAW_STAGE_COUNT_DISTINCT_SQUARING, got: {qa_cd['errors']}",
    )

    bad_uint64_if = """
    // Goal: Law D uint64/int64 conflict in if()
    stage s1 {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.hostname = $h
      match: $h by 1h
      outcome:
        $sum_bytes = sum(network.sent_bytes)
        $peak_bytes = max(network.sent_bytes)
    }
    $h = $s1.h
    $ws = $s1.window_start
    match: $h, $ws by 1h
    outcome:
      $safe_sum = if(max($s1.sum_bytes) > 0, max($s1.sum_bytes), 1)
      $ratio = 1.0 * max($s1.peak_bytes) / $safe_sum
    condition:
      $ratio >= 0.5
    """
    qa_u64 = QueryIntegrityGate.verify_pre_dispatch(bad_uint64_if)
    self.assertFalse(qa_u64["valid"])
    self.assertTrue(
        any("UINT64_BYTES_IF_LITERAL_CONFLICT" in e for e in qa_u64["errors"]),
        f"Expected UINT64_BYTES_IF_LITERAL_CONFLICT, got: {qa_u64['errors']}",
    )

    bad_regex = """
    // Goal: re.regex on bound placeholder
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      target.user.userid = $entity
      re.regex($entity, `(?i)admin.*`)
      match: $entity by 1h
      outcome:
        $c = count(metadata.id)
    }
    $entity = $s1.entity
    $ws = $s1.window_start
    match: $entity, $ws by 1h
    outcome:
      $obs = max($s1.c)
    condition:
      $obs >= 1
    """
    qa_rx = QueryIntegrityGate.verify_pre_dispatch(bad_regex)
    self.assertFalse(qa_rx["valid"])
    self.assertTrue(
        any("INVALID_REGEX_ON_PLACEHOLDER" in e for e in qa_rx["errors"]),
        f"Expected INVALID_REGEX_ON_PLACEHOLDER, got: {qa_rx['errors']}",
    )


class TestWS5LiveFixedPipelines(unittest.TestCase):
  """Regression tests for all 4 live-fixed pipelines and examples/multi_sector_threat_fusion.yara."""

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()

  def test_producer_consumer_ratio_inversion_4stage_topology_and_int_bytes(self) -> None:
    expected_bytes = {
        "CONSERVATIVE": "50000000",
        "BALANCED": "10000000",
        "AGGRESSIVE": "1000000",
    }
    for tier, exp_int in expected_bytes.items():
      q = self.router.build_query("PRODUCER_CONSUMER_RATIO_INVERSION", tier=tier, entity_type="host")
      qa = QueryIntegrityGate.verify_pre_dispatch(q)
      self.assertTrue(qa["valid"], f"{tier} failed pre-dispatch: {qa['errors']}")
      self.assertIn("stage stage1_directional_bytes", q)
      self.assertIn("stage stage2_window_ratio", q)
      self.assertIn("stage stage3_entity_baseline", q)
      self.assertNotIn("$dst_ip", q)
      self.assertIn('target.ip != ""', q)
      self.assertIn(f"$observation_count >= {exp_int}\n", q)
      self.assertNotIn(f"{exp_int}.0", q)
      self.assertTrue(all(c <= 20 for c in _outcome_var_counts(q)))
      audit = audit_query_execution(q, "4STAGE_DAG")
      self.assertEqual(audit["status"], "PASS", f"Audit failed: {audit}")

  def test_hybrid_entropy_concentration_4stage_loo_stats_and_safe_sum_bytes(self) -> None:
    for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
      q = self.router.build_query("HYBRID_ENTROPY_CONCENTRATION", tier=tier, entity_type="host")
      qa = QueryIntegrityGate.verify_pre_dispatch(q)
      self.assertTrue(qa["valid"], f"{tier} failed pre-dispatch: {qa['errors']}")
      self.assertIn("stage window_metrics", q)
      self.assertIn("stage entity_baseline", q)
      self.assertIn("stage loo_stats", q)
      self.assertNotIn("count_distinct(target.ip) * count_distinct(target.ip)", q)
      self.assertIn(
          "$conc_ratio = 1.0 * max($window_metrics.peak_bytes) / (max($window_metrics.sum_bytes) + 1.0)",
          q,
      )
      self.assertIn("$safe_sd = if($active_n > 1, max($entity_baseline.sd_targets), 0.0)", q)
      self.assertTrue(all(c <= 20 for c in _outcome_var_counts(q)))
      audit = audit_query_execution(q, "4STAGE_DAG")
      self.assertEqual(audit["status"], "PASS", f"Audit failed: {audit}")

  def test_privileged_lateral_expansion_5stage_window_breadth_and_indexed_ip(self) -> None:
    for entity_type, exp_field in (("user", "target.user.userid"), ("host", "target.user.userid")):
      q = self.router.build_query("PRIVILEGED_LATERAL_EXPANSION", tier="BALANCED", entity_type=entity_type)
      qa = QueryIntegrityGate.verify_pre_dispatch(q)
      self.assertTrue(qa["valid"], f"{entity_type} failed pre-dispatch: {qa['errors']}")
      self.assertIn("stage daily_user_breadth", q)
      self.assertIn("stage user_target_history", q)
      self.assertIn("stage window_user_breadth", q)
      self.assertIn("stage user_breadth_baseline", q)
      self.assertIn(f"re.regex({exp_field},", q)
      self.assertNotIn("re.regex($entity", q)
      self.assertIn("strings.coalesce(target.asset.hostname, target.hostname, target.ip[0])", q)
      self.assertTrue(all(c <= 20 for c in _outcome_var_counts(q)))
      audit = audit_query_execution(q, "5STAGE_DAG")
      self.assertEqual(audit["status"], "PASS", f"Audit failed: {audit}")

  def test_multi_sector_threat_fusion_and_example_algebraic_loo_and_indexed_ip(self) -> None:
    for mode in ("host", "user", "ip"):
      q = self.router.build_query("MULTI_SECTOR_THREAT_FUSION", tier="BALANCED", entity_type=mode)
      qa = QueryIntegrityGate.verify_pre_dispatch(q)
      self.assertTrue(qa["valid"], f"{mode} failed pre-dispatch: {qa['errors']}")
      self.assertNotIn("max(if(", q)
      self.assertIn("$n_all = max($host_sector_baseline.active_hours)", q)
      self.assertIn("$safe_sd_auth = if($n_all > 1, max($host_sector_baseline.sd_auth), 0.0)", q)
      if mode in ("host", "ip"):
        self.assertIn("$e.principal.ip[0]", q)
      counts = _outcome_var_counts(q)
      self.assertEqual(counts, [3, 10, 18, 19])
      audit = audit_query_execution(q, "MULTI_SECTOR_FUSION_4STAGE", "MULTI_SECTOR_THREAT_FUSION")
      self.assertEqual(audit["status"], "PASS", f"Audit failed ({mode}): {audit}")

    ex_path = REPO_ROOT / "examples" / "multi_sector_threat_fusion.yara"
    ex_q = ex_path.read_text(encoding="utf-8")
    qa_ex = QueryIntegrityGate.verify_pre_dispatch(ex_q)
    self.assertTrue(qa_ex["valid"], f"example failed pre-dispatch: {qa_ex['errors']}")
    self.assertIn("$e.principal.ip[0]", ex_q)
    self.assertNotIn("max(if(", ex_q)
    self.assertEqual(_outcome_var_counts(ex_q), [3, 10, 18, 19])

    # Algebraic identity check: (n - 1)*s^2 + n*mean^2 reconstructs exact sum(x^2) & LOO sample variance
    series = [2.0, 0.0, 3.0, 1.0, 4.0, 2.0, 1.0, 12.0]
    n_all = len(series)
    mean_all = sum(series) / n_all
    sd_all = math.sqrt(sum((x - mean_all) ** 2 for x in series) / (n_all - 1))
    reconstructed_sum_sq = (n_all - 1) * (sd_all**2) + n_all * (mean_all**2)
    self.assertAlmostEqual(reconstructed_sum_sq, sum(x * x for x in series), places=9)

    obs = series[-1]
    prior = series[:-1]
    n_prior = n_all - 1
    df_prior = n_all - 2
    loo_mean = (sum(series) - obs) / n_prior
    loo_var = ((reconstructed_sum_sq - obs * obs) - n_prior * (loo_mean**2)) / df_prior
    exact_prior_var = sum((x - loo_mean) ** 2 for x in prior) / (len(prior) - 1)
    self.assertAlmostEqual(loo_var, exact_prior_var, places=9)


if __name__ == "__main__":
  unittest.main()
