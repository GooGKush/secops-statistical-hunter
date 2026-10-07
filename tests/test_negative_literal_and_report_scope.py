"""Bare negative literal guard, hunted-scope pivot filter, and MAD formula display."""

import glob
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from multistage_query_builder import (  # pylint: disable=g-import-not-at-top
    MultiStageTemplateRouter,
    check_bare_negative_literal_assignments,
    describe_mad_scale_branch,
    format_triage_report,
    infer_hunt_scope,
    validate_multistage_syntax,
)


def _mad_payload(mad, mean_ad, window_start=1791331200):
  def col(name, kind, value):
    return {"column": name, "values": [{"value": {kind: value}}]}
  return {"stats": {"results": [
      col("entity", "stringVal", "acc-win11-8"),
      col("window_start", "int64Val", window_start),
      col("observation_count", "int64Val", 351),
      col("baseline_active_samples", "int64Val", 30),
      col("baseline_mean", "doubleVal", 257.0),
      col("baseline_median", "doubleVal", 257.0),
      col("baseline_dispersion", "doubleVal", mad),
      col("baseline_mean_abs_dev", "doubleVal", mean_ad),
      col("fleet_prevalence", "int64Val", -1),
      col("distinct_binaries", "int64Val", 40),
      col("m_z_score", "doubleVal", 10.6),
  ]}}


class TestBareNegativeLiteral(unittest.TestCase):

  def test_flags_bare_negative_literals(self):
    for line in ["  $fleet_prevalence = -1", "$x = - 2.5", "\t$y=-3"]:
      errors = check_bare_negative_literal_assignments(f"outcome:\n{line}\n")
      self.assertEqual(len(errors), 1, line)
      self.assertIn("BARE_NEGATIVE_LITERAL", errors[0])
      self.assertIn("= 0 - ", errors[0])
    self.assertTrue(any("BARE_NEGATIVE_LITERAL" in e
                        for e in validate_multistage_syntax("outcome:\n  $x = -1\n")))

  def test_allows_safe_forms(self):
    for line in ["  $fleet_prevalence = 0 - 1", "  $d = $a - 1", "  $z = -1 * $a",
                 "  // $x = -1", "  $s = if($a > 0, $a, 1.0)"]:
      self.assertEqual(check_bare_negative_literal_assignments(f"outcome:\n{line}\n"), [], line)

  def test_no_template_or_example_uses_bare_negative_literal(self):
    files = (glob.glob(os.path.join(ROOT, "templates", "**", "*.yl2"), recursive=True)
             + glob.glob(os.path.join(ROOT, "examples", "*.yara")))
    self.assertTrue(files)
    for path in files:
      with open(path) as f:
        self.assertEqual(check_bare_negative_literal_assignments(f.read()), [], path)


class TestHuntScopePivot(unittest.TestCase):

  def setUp(self):
    query = MultiStageTemplateRouter().build_query("MAD", event_type="NETWORK_DNS")
    self.query = query.replace("    principal.hostname = $entity\n",
                               "    principal.asset.hostname = $entity\n")

  def test_infer_hunt_scope(self):
    self.assertEqual(infer_hunt_scope(self.query), {
        "event_type": "NETWORK_DNS",
        "entity_field": "principal.asset.hostname",
        "bucket_seconds": 86400,
    })
    self.assertEqual(infer_hunt_scope(None),
                     {"event_type": None, "entity_field": None, "bucket_seconds": None})

  def test_pivot_uses_hunted_scope_from_query(self):
    report = format_triage_report("MAD DNS", _mad_payload(6.0, 5.0), query_text=self.query)
    self.assertIn('principal.asset.hostname = "acc-win11-8" AND metadata.event_type = "NETWORK_DNS"', report)
    self.assertIn("metadata.event_timestamp.seconds < 1791417600", report)
    self.assertNotIn('principal.hostname = "acc-win11-8"', report)
    self.assertNotIn("PROCESS_LAUNCH", report)

  def test_explicit_args_override_query(self):
    report = format_triage_report("MAD", _mad_payload(6.0, 5.0), query_text=self.query,
                                  event_type="NETWORK_CONNECTION", entity_field="principal.ip")
    self.assertIn('principal.ip = "acc-win11-8" AND metadata.event_type = "NETWORK_CONNECTION"', report)

  def test_modified_z_rows_default_to_daily_bucket(self):
    report = format_triage_report("MAD", _mad_payload(6.0, 5.0))
    self.assertIn("metadata.event_timestamp.seconds < 1791417600", report)


class TestMadFormulaDisplay(unittest.TestCase):

  def test_report_shows_fallback_formula(self):
    report = format_triage_report("MAD", _mad_payload(6.0, 5.0))
    self.assertIn("1.253314 \\cdot \\text{meanAD}", report)
    self.assertIn("\\text{MAD} / 0.6745", report)
    self.assertIn("dispersion floor", report)

  def test_branch_mad_positive(self):
    self.assertIn("MAD > 0", describe_mad_scale_branch({"baseline_dispersion": 6.0, "baseline_mean_abs_dev": 5.0}))

  def test_branch_mean_ad_fallback(self):
    text = describe_mad_scale_branch({"baseline_dispersion": 0.0, "baseline_mean_abs_dev": 0.13})
    self.assertIn("fallback", text)
    self.assertIn("1.253314", text)

  def test_branch_floor_and_unknown(self):
    self.assertIn("dispersion floor",
                  describe_mad_scale_branch({"baseline_dispersion": 0, "baseline_mean_abs_dev": 0}))
    self.assertIn("unknown", describe_mad_scale_branch({}))


if __name__ == "__main__":
  unittest.main()
