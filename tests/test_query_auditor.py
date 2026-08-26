"""Unit tests for Post-Query Execution Auditor and Intent Verification."""

import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import audit_query_execution


class TestQueryAuditor(unittest.TestCase):

  def test_single_stage_macro_audit(self):
    single_stage_query = """
    metadata.event_type = "PROCESS_LAUNCH"
    match: $host
    outcome:
      $total_count = count(metadata.id)
    condition:
      $total_count > 100
    """
    res = audit_query_execution(single_stage_query, "SINGLE_STAGE_MACRO")
    self.assertEqual(res["status"], "PASS")
    self.assertEqual(res["actual_architecture"], "SINGLE_STAGE_MACRO")
    self.assertEqual(res["total_stages"], 1)

  def test_multi_stage_audit_pass(self):
    two_stage_query = """
    stage s1 { metadata.event_type = "PROCESS_LAUNCH" match: $host by 1h outcome: $c = count(metadata.id) }
    $host = $s1.host
    match: $host by 1h
    outcome:
      $observation_count = max($s1.c)
      $baseline_active_samples = count($s1.window_start)
      $baseline_dispersion = stddev($s1.c)
      $z = max($s1.c)
    condition:
      $baseline_active_samples >= 24
      and $baseline_dispersion > 0
      and $z > 3.0
    """
    res = audit_query_execution(two_stage_query, "LOCAL_2STAGE", expected_model="Z_SCORE")
    self.assertEqual(res["status"], "PASS")
    self.assertEqual(res["actual_architecture"], "LOCAL_2STAGE")
    self.assertEqual(res["total_stages"], 2)

  def test_architecture_mismatch_detection(self):
    # Promised 4-stage Multi-Sector Fusion, but executed 1-stage macro query
    single_stage_query = "metadata.event_type = 'USER_LOGIN' match: $user outcome: $c = count(metadata.id)"
    res = audit_query_execution(single_stage_query, "MULTI_SECTOR_FUSION_4STAGE")
    self.assertEqual(res["status"], "MISMATCH")
    self.assertIn("ARCHITECTURE MISMATCH", res["findings"][0])

  def test_model_mismatch_detection(self):
    # Executed standard Z-score query, but expected Delta-Z
    z_query = """
    stage s1 { metadata.event_type = "PROCESS_LAUNCH" match: $host by 1h outcome: $c = count(metadata.id) }
    stage s2 { $host = $s1.host match: $host outcome: $avg = avg($s1.c) $sd = stddev($s1.c) }
    $host = $s1.host
    match: $host by 1h
    outcome: $z = max($s1.c)
    condition:
      $baseline_active_samples >= 24
      and $baseline_dispersion > 0
      and $z > 3.0
    """
    res = audit_query_execution(z_query, "3STAGE_DAG", expected_model="DELTA_Z")
    self.assertEqual(res["status"], "MISMATCH")
    self.assertFalse(res["model_verified"])


if __name__ == "__main__":
  unittest.main()
