"""Unit tests for compiler facts verified by live udm_search probes (2026-09-24).

Each test encodes a minimal pair that was submitted to the Chronicle compiler:
the rejected form must be flagged by the validator, and the accepted form must
pass cleanly (no false positives on legal multi-stage grammar).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import (  # noqa: E402
    check_independent_raw_stages,
    check_multivector_cramming,
    check_stage_name_collisions,
    validate_multistage_syntax,
)


def _fatal(errors):
  return [e for e in errors if not e.startswith("MISSING METHODOLOGY HEADER")]


LEGAL_TWO_STAGE = """
stage host_hourly {
  metadata.event_type = "PROCESS_LAUNCH"
  $host = principal.hostname
  match:
    $host by 1h
  outcome:
    $event_count = count(metadata.id)
}

stage fleet_breadth {
  $ws = $host_hourly.window_start
  match:
    $ws by 1h
  outcome:
    $fleet_hosts = count_distinct($host_hourly.host)
}

$host = $host_hourly.host
$ws = $host_hourly.window_start
$ws = $fleet_breadth.ws

match:
  $host, $ws by 1h

outcome:
  $observation_count = max($host_hourly.event_count)
  $fleet_prevalence = max($fleet_breadth.fleet_hosts)
  $is_unit = if($observation_count = 1.0, 1, 0)

condition:
  $observation_count > 0
"""


class TestVerifiedCompilerFacts(unittest.TestCase):

  def test_legal_two_stage_pipeline_passes(self):
    self.assertEqual(_fatal(validate_multistage_syntax(LEGAL_TWO_STAGE)), [])

  def test_unwindowed_entity_keyed_stage_is_legal(self):
    """Per-entity baseline collapse ('match: $host' with no window) compiles; must not be flagged."""
    q = LEGAL_TWO_STAGE.replace("$ws = $host_hourly.window_start\n  match:\n    $ws by 1h\n  outcome:\n    $fleet_hosts = count_distinct($host_hourly.host)",
                                "$host = $host_hourly.host\n  match:\n    $host\n  outcome:\n    $fleet_hosts = avg($host_hourly.event_count)")
    q = q.replace("$ws = $fleet_breadth.ws\n", "$host = $fleet_breadth.host\n")
    self.assertEqual(_fatal(validate_multistage_syntax(q)), [])

  def test_double_equals_in_if_rejected(self):
    bad = LEGAL_TWO_STAGE.replace("if($observation_count = 1.0, 1, 0)", "if($observation_count == 1.0, 1, 0)")
    errors = validate_multistage_syntax(bad)
    self.assertTrue(any("DOUBLE_EQUALS_IN_IF" in e for e in errors), errors)

  def test_window_start_shadowing_rejected(self):
    bad = LEGAL_TWO_STAGE.replace("$event_count = count(metadata.id)",
                                  "$event_count = count(metadata.id)\n    $window_start = min(metadata.event_timestamp.seconds)")
    errors = validate_multistage_syntax(bad)
    self.assertTrue(any("WINDOW_START_SHADOWED" in e for e in errors), errors)

  def test_root_window_start_binding_is_legal(self):
    ok = LEGAL_TWO_STAGE.replace("$ws = $host_hourly.window_start\n$ws = $fleet_breadth.ws",
                                 "$window_start = $host_hourly.window_start\n$window_start = $fleet_breadth.ws")
    ok = ok.replace("$host, $ws by 1h", "$host, $window_start by 1h")
    self.assertEqual(_fatal(validate_multistage_syntax(ok)), [])

  def test_multiday_match_window_rejected(self):
    for bad_window in ("2d", "7d", "14d"):
      with self.subTest(window=bad_window):
        bad = LEGAL_TWO_STAGE.replace("$host by 1h", f"$host by {bad_window}")
        errors = validate_multistage_syntax(bad)
        self.assertTrue(any("NONCANONICAL_MATCH_WINDOW" in e for e in errors), errors)

  def test_verified_match_windows_accepted(self):
    for good_window in ("5m", "1h", "2h", "1d"):
      with self.subTest(window=good_window):
        ok = LEGAL_TWO_STAGE.replace("by 1h", f"by {good_window}")
        self.assertEqual(_fatal(validate_multistage_syntax(ok)), [])

  def test_max_on_string_field_rejected(self):
    bad = LEGAL_TWO_STAGE.replace("$event_count = count(metadata.id)",
                                  "$event_count = count(metadata.id)\n    $top_path = max(target.process.file.full_path)")
    errors = validate_multistage_syntax(bad)
    self.assertTrue(any("INVALID_STRING_AGGREGATION_FUNCTION" in e for e in errors), errors)
    bad2 = LEGAL_TWO_STAGE.replace("$event_count = count(metadata.id)",
                                   "$event_count = count(metadata.id)\n    $h = max($host)")
    errors2 = validate_multistage_syntax(bad2)
    self.assertTrue(any("INVALID_STRING_AGGREGATION_FUNCTION" in e for e in errors2), errors2)

  def test_array_distinct_on_string_field_is_legal(self):
    ok = LEGAL_TWO_STAGE.replace("$event_count = count(metadata.id)",
                                 "$event_count = count(metadata.id)\n    $paths = array_distinct(target.process.file.full_path)")
    self.assertEqual(_fatal(validate_multistage_syntax(ok)), [])

  def test_stage_outcome_name_collision_rejected(self):
    bad = LEGAL_TWO_STAGE.replace("stage fleet_breadth {", "stage fleet_prevalence {") \
                         .replace("$fleet_breadth.", "$fleet_prevalence.")
    errors = check_stage_name_collisions(bad)
    self.assertEqual(len(errors), 1, errors)
    self.assertIn("STAGE_OUTCOME_NAME_COLLISION", errors[0])
    self.assertIn("fleet_prevalence", errors[0])
    self.assertEqual(check_stage_name_collisions(LEGAL_TWO_STAGE), [])

  def test_three_independent_raw_stages_rejected(self):
    bad = """
stage auth_sector {
  metadata.event_type = "USER_LOGIN"
  $host = principal.hostname
  match: $host by 1h
  outcome: $auth_count = count(metadata.id)
}
stage proc_sector {
  metadata.event_type = "PROCESS_LAUNCH"
  $host = principal.hostname
  match: $host by 1h
  outcome: $proc_count = count(metadata.id)
}
stage net_sector {
  metadata.event_type = "NETWORK_CONNECTION"
  $host = principal.hostname
  match: $host by 1h
  outcome: $net_count = count(metadata.id)
}
$host = $auth_sector.host
$host = $proc_sector.host
$host = $net_sector.host
match: $host by 1h
outcome:
  $total = max($auth_sector.auth_count) + max($proc_sector.proc_count) + max($net_sector.net_count)
condition:
  $total > 0
"""
    errors = check_independent_raw_stages(bad)
    self.assertEqual(len(errors), 1, errors)
    self.assertIn("TOO_MANY_INDEPENDENT_RAW_STAGES", errors[0])

  def test_two_raw_stages_plus_chained_stage_is_legal(self):
    """Two raw stages + one chained (references another stage) stage: only two are independent."""
    ok = """
stage auth_sector {
  metadata.event_type = "USER_LOGIN"
  $host = principal.hostname
  match: $host by 1h
  outcome: $auth_count = count(metadata.id)
}
stage proc_sector {
  metadata.event_type = "PROCESS_LAUNCH"
  $host = principal.hostname
  match: $host by 1h
  outcome: $proc_count = count(metadata.id)
}
stage auth_baseline {
  $host = $auth_sector.host
  match: $host
  outcome: $auth_mean = avg($auth_sector.auth_count)
}
$host = $auth_sector.host
$host = $proc_sector.host
$host = $auth_baseline.host
match: $host by 1h
outcome:
  $total = max($auth_sector.auth_count) + max($proc_sector.proc_count)
  $auth_mean = max($auth_baseline.auth_mean)
condition:
  $total > 0
"""
    self.assertEqual(check_independent_raw_stages(ok), [])

  def test_fused_sector_stage_with_conditional_sums_not_flagged_as_cramming(self):
    fused = """
stage sector_counts {
  $host = $e.principal.hostname
  (
    $e.metadata.event_type = "USER_LOGIN"
    or $e.metadata.event_type = "PROCESS_LAUNCH"
    or $e.metadata.event_type = "NETWORK_CONNECTION"
  )
  match: $host by 1h
  outcome:
    $auth = sum(if($e.metadata.event_type = "USER_LOGIN", 1, 0))
    $proc = sum(if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $net = sum(if($e.metadata.event_type = "NETWORK_CONNECTION", 1, 0))
}
$host = $sector_counts.host
match: $host by 1h
outcome:
  $total = max($sector_counts.auth) + max($sector_counts.proc) + max($sector_counts.net)
condition:
  $total > 0
"""
    self.assertEqual(check_multivector_cramming(fused), [])

  def test_mixed_domains_without_conditional_sums_still_flagged_as_cramming(self):
    crammed = """
stage mixed {
  $host = principal.hostname
  (metadata.event_type = "USER_LOGIN" or metadata.event_type = "NETWORK_CONNECTION")
  match: $host by 1h
  outcome:
    $n = count(metadata.id)
}
$host = $mixed.host
match: $host by 1h
outcome:
  $total = max($mixed.n)
condition:
  $total > 0
"""
    errors = check_multivector_cramming(crammed)
    self.assertEqual(len(errors), 1, errors)
    self.assertIn("MULTI-VECTOR CRAMMING", errors[0])


if __name__ == "__main__":
  unittest.main()
