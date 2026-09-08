"""Unit tests for Post-Query Execution Auditor and Intent Verification."""

import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import (
    audit_query_execution,
    audit_api_response_payload,
    PostFlightExecutionAuditor,
)


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

  def test_mad_model_signature_verification(self):
    mad_query = """
    stage s1 { metadata.event_type = "NETWORK_DNS" match: $host by 1d outcome: $c = count(metadata.id) }
    $host = $s1.host
    match: $host by 1d
    outcome:
      $m_z = 0.6745 * ($obs - $median) / $mad
    condition:
      $baseline_active_samples >= 7
      and $mad > 0
      and $m_z > 2.5
    """
    res = audit_query_execution(mad_query, "LOCAL_2STAGE", expected_model="MAD_MODIFIED_Z")
    self.assertEqual(res["status"], "PASS")
    self.assertTrue(res["model_verified"])

  def test_raw_log_dump_detection(self):
    raw_api_response = {
        "events": [
            {"metadata": {"id": "ev-1", "event_type": "PROCESS_LAUNCH"}},
            {"metadata": {"id": "ev-2", "event_type": "PROCESS_LAUNCH"}}
        ]
    }
    errors = audit_api_response_payload(raw_api_response)
    self.assertEqual(len(errors), 1)
    self.assertIn("RAW_LOG_DUMP_DETECTED", errors[0])

    valid_stats_response = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-1"}}]},
                {"column": "z_score", "values": [{"value": {"doubleVal": 4.5}}]}
            ]
        }
    }
    valid_errors = audit_api_response_payload(valid_stats_response)
    self.assertEqual(valid_errors, [])

  def test_post_flight_execution_auditor(self):
    valid_query = """
    stage s1 { metadata.event_type = "PROCESS_LAUNCH" principal.hostname = $host match: $host by 1h outcome: $c = count(metadata.id) }
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
    valid_stats = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-1"}}]}
            ]
        }
    }
    audit_res = PostFlightExecutionAuditor.audit_execution(
        executed_query=valid_query,
        api_response=valid_stats,
        expected_architecture="LOCAL_2STAGE",
        expected_model="Z_SCORE",
        explained_to_user="Running 2-stage multi-stage statistical outlier pipeline",
        expected_stage_count=2,
    )
    self.assertTrue(audit_res.is_valid)
    self.assertEqual(audit_res.status, "PASSED")

  def test_stage_degradation_detected_when_multistage_explained(self):
    """When a multi-stage pipeline was explained to the analyst, executing a 1-stage search must fail audit."""
    single_stage_query = """
    metadata.event_type = "PROCESS_LAUNCH"
    match: $host by 1h
    outcome:
      $observation_count = count(metadata.id)
      $baseline_active_samples = 24
      $baseline_dispersion = 5.0
      $z = 3.5
    condition:
      $z > 3.0
    """
    res = audit_query_execution(
        single_stage_query,
        expected_architecture="LOCAL_2STAGE",
        expected_model="Z_SCORE",
        explained_to_user="Proceeding with a 2-stage multi-stage Z-score hunt over process launches",
        expected_stage_count=2,
    )
    self.assertEqual(res["status"], "STAGE_DEGRADATION")
    self.assertTrue(any("STAGE DEGRADATION ERROR" in f for f in res["findings"]))

  def test_stage_count_mismatch_detection(self):
    """When expected 4-stage threat fusion, executing a 2-stage query must report stage count mismatch."""
    two_stage_query = """
    stage s1 { metadata.event_type = "PROCESS_LAUNCH" match: $host by 1h outcome: $c = count(metadata.id) }
    $host = $s1.host
    match: $host by 1h
    outcome:
      $observation_count = max($s1.c)
      $baseline_active_samples = 24
      $baseline_dispersion = 5.0
      $threat_vector_norm_sq = 10.0
    condition:
      $threat_vector_norm_sq >= 9.0
    """
    res = audit_query_execution(
        two_stage_query,
        expected_architecture="MULTI_SECTOR_FUSION_4STAGE",
        expected_model="MULTI_SECTOR_FUSION",
        explained_to_user="Running 4-stage multi-sector threat fusion across Auth, Endpoint, and Network",
        expected_stage_count=4,
    )
    self.assertEqual(res["status"], "MISMATCH")
    self.assertTrue(any("STAGE COUNT MISMATCH" in f for f in res["findings"]))

  def test_single_stage_explained_and_executed_passes(self):
    """When a single-stage search was explicitly explained and executed, concordance passes."""
    single_stage_query = """
    metadata.event_type = "PROCESS_LAUNCH"
    match: $host
    outcome:
      $total_count = count(metadata.id)
    condition:
      $total_count > 100
    """
    res = audit_query_execution(
        single_stage_query,
        expected_architecture="SINGLE_STAGE_MACRO",
        explained_to_user="Proceeding with a single-stage ad-hoc stats search",
        expected_stage_count=1,
    )
    self.assertEqual(res["status"], "PASS")
    self.assertTrue(any("User explanation concordance verified" in f for f in res["findings"]))


if __name__ == "__main__":
  unittest.main()
