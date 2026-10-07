"""Missing / not-computed fleet prevalence must be treated as unknown, never as 'isolated'."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import (  # pylint: disable=g-import-not-at-top
    FLEET_PREVALENCE_NOT_COMPUTED,
    evaluate_confidence_tier,
    format_triage_report,
    resolve_fleet_prevalence,
)

STRONG_ROW = {
    "baseline_active_samples": 168,
    "observation_count": 850,
    "baseline_dispersion": 35.0,
}


def _payload(fleet_value):
  results = [
      {"column": "host", "values": [{"value": {"stringVal": "host-alpha-prod"}}]},
      {"column": "observation_count", "values": [{"value": {"int64Val": 850}}]},
      {"column": "baseline_active_samples", "values": [{"value": {"int64Val": 168}}]},
      {"column": "baseline_mean", "values": [{"value": {"doubleVal": 250.0}}]},
      {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 35.0}}]},
      {"column": "distinct_binaries", "values": [{"value": {"int64Val": 42}}]},
      {"column": "m_z_score", "values": [{"value": {"doubleVal": 11.6}}]},
  ]
  if fleet_value is not None:
    results.append({"column": "fleet_prevalence", "values": [{"value": {"int64Val": fleet_value}}]})
  return {"stats": {"results": results}}


class TestFleetPrevalenceUnknown(unittest.TestCase):

  def test_sentinel_value(self):
    self.assertEqual(FLEET_PREVALENCE_NOT_COMPUTED, -1)

  def test_resolve(self):
    self.assertIsNone(resolve_fleet_prevalence({}))
    self.assertIsNone(resolve_fleet_prevalence({"fleet_prevalence": -1}))
    self.assertIsNone(resolve_fleet_prevalence({"fleet_prevalence": "-1"}))
    self.assertIsNone(resolve_fleet_prevalence({"fleet_prevalence": "n/a"}))
    self.assertEqual(resolve_fleet_prevalence({"fleet_prevalence": 2}), 2.0)
    self.assertEqual(resolve_fleet_prevalence({"hosts_contacting": 4}), 4.0)
    # An explicit not-computed marker must not fall through to another column.
    self.assertIsNone(resolve_fleet_prevalence({"fleet_prevalence": -1, "hosts_contacting": 1}))

  def test_known_low_prevalence_can_reach_high(self):
    row = dict(STRONG_ROW, fleet_prevalence=1)
    self.assertIn("HIGH CONFIDENCE", evaluate_confidence_tier(row)[0])

  def test_unknown_prevalence_caps_at_moderate(self):
    for row in (dict(STRONG_ROW), dict(STRONG_ROW, fleet_prevalence=-1)):
      badge, desc = evaluate_confidence_tier(row)
      self.assertIn("MODERATE CONFIDENCE", badge, row)
      self.assertIn("not computed", desc)

  def test_insufficient_baseline_unchanged(self):
    row = dict(STRONG_ROW, baseline_active_samples=5, fleet_prevalence=-1)
    self.assertIn("INSUFFICIENT BASELINE", evaluate_confidence_tier(row)[0])

  def test_report_does_not_claim_isolation_when_not_computed(self):
    for fleet_value in (-1, None):
      report = format_triage_report("MAD DNS", _payload(fleet_value), fleet_size=1)
      self.assertNotIn("HIGH CONFIDENCE", report)
      self.assertNotIn("-1 endpoint", report)
      self.assertNotIn("-1 host", report)
      self.assertNotIn("company, ruling out a routine corporate-wide software rollout", report)
      self.assertIn("breadth was **not computed**", report)
      self.assertIn("**5. Company-Wide Breadth** | `not computed`", report)
      self.assertIn("NOT EVALUATED", report)

  def test_report_known_prevalence_unchanged(self):
    report = format_triage_report("MAD DNS", _payload(1), fleet_size=1)
    self.assertIn("observed on only **1 endpoint(s)**", report)
    self.assertIn("`1 host(s)`", report)


if __name__ == "__main__":
  unittest.main()
