"""Correctness contract for the standalone MAD / Modified Z-Score template."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from multistage_query_builder import (  # pylint: disable=g-import-not-at-top
    MultiStageTemplateRouter,
    SENSITIVITY_MAP,
    validate_multistage_syntax,
)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates", "pipelines")
TEMPLATE_FILE = "mad_modified_z_4stage.yl2"


class TestMadModifiedZTemplate(unittest.TestCase):

  def setUp(self):
    self.router = MultiStageTemplateRouter()
    with open(os.path.join(TEMPLATE_DIR, TEMPLATE_FILE)) as f:
      self.raw = f.read()
    self.query = self.router.build_query("MAD")

  def test_renamed_file_and_aliases_route_to_it(self):
    self.assertFalse(os.path.exists(os.path.join(TEMPLATE_DIR, "mad_exfiltration_2stage.yl2")))
    for alias in ["MAD", "MODIFIED_Z", "MAD_EXFILTRATION", "DATA_EXFILTRATION_SPIKE"]:
      self.assertEqual(self.router.get_template_filename(alias), TEMPLATE_FILE)

  def test_four_stages(self):
    self.assertEqual(len(re.findall(r"^stage\s+\w+\s*\{", self.raw, re.MULTILINE)), 3)
    self.assertIn("match:\n  $entity, $window_start by 1d", self.raw)

  def test_rendered_query_has_no_placeholders_and_passes_validation(self):
    self.assertNotIn("{{", self.query)
    self.assertEqual(validate_multistage_syntax(self.query), [])

  def test_robust_median_and_mad(self):
    self.assertIn("window.median($daily_stats.daily_value, false)", self.raw)
    # should_ignore_zero_values must be false for MAD: zero deviations (days at the median) must count.
    self.assertIn(
        "window.median(math.abs($daily_stats.daily_value - $median_stats.baseline_median), false)",
        self.raw)
    self.assertNotRegex(self.raw, r"window\.median\([^\n]*,\s*true\s*\)")

  def test_iglewicz_hoaglin_mad_zero_fallback(self):
    self.assertIn("$mean_abs_dev = avg(math.abs(", self.raw)
    self.assertIn("$scale_from_mad = $baseline_dispersion / 0.6745", self.raw)
    self.assertIn("$scale_from_meanad = $baseline_mean_abs_dev * 1.253314", self.raw)
    self.assertIn(
        "$robust_scale = if($baseline_dispersion > 0, $scale_from_mad, $scale_from_meanad)", self.raw)
    self.assertIn(
        "$safe_robust_scale = if($robust_scale > 0, $robust_scale, {{dispersion_floor}})", self.raw)
    self.assertIn(
        "$m_z_score = ($observation_count - $baseline_median) / $safe_robust_scale", self.raw)

  def test_if_branches_are_plain_variables_or_literals(self):
    code = "\n".join(l for l in self.query.splitlines() if not l.strip().startswith("//"))
    calls = re.findall(r"\bif\(([^()]*)\)", code)
    self.assertEqual(len(calls), 2)
    for args in calls:
      _, a, b = [x.strip() for x in args.split(",")]
      for branch in (a, b):
        self.assertRegex(branch, r"^(\$\w+|-?\d+(\.\d+)?)$", f"arithmetic if() branch: {args}")

  def test_no_min_mad_gate_and_volume_floor_renamed(self):
    self.assertNotIn("min_mad", self.raw)
    self.assertNotIn("min_mb", self.raw)
    cond = self.raw.split("condition:")[1].split("order:")[0]
    self.assertNotIn("$baseline_dispersion", cond)
    self.assertIn("$observation_count >= {{min_daily_volume}}", cond)
    self.assertIn("$baseline_active_samples >= {{min_baseline_days}}", cond)

  def test_slots_and_no_process_path_hardcoding(self):
    self.assertIn("$daily_value = {{daily_aggregation}}", self.raw)
    self.assertIn("array_distinct({{sample_field}})", self.raw)
    self.assertNotIn("target.process.file.full_path)", self.raw.split("stage daily_stats")[1])
    self.assertIn("$daily_value = count(metadata.id)", self.query)
    self.assertIn("network.dns.questions.name", self.query)
    q = self.router.build_query(
        "MAD", event_type="NETWORK_CONNECTION", daily_aggregation="sum(network.sent_bytes)")
    self.assertIn("$daily_value = sum(network.sent_bytes)", q)
    self.assertIn("array_distinct(target.ip)", q)

  def test_six_pillar_contract_and_honest_median(self):
    for v in ["observation_count", "baseline_active_samples", "baseline_mean",
              "baseline_dispersion", "fleet_prevalence", "distinct_binaries"]:
      self.assertRegex(self.raw, rf"\n  \${v} = ")
    self.assertIn("$baseline_median = max($mad_stats.median_val)", self.raw)
    self.assertIn("$distinct_binaries = max($daily_stats.distinct_sample_values)", self.raw)
    self.assertIn("$fleet_prevalence = -1", self.raw)
    self.assertIn("NOT COMPUTED", self.raw)

  def test_default_threshold_is_iglewicz_hoaglin(self):
    self.assertEqual(SENSITIVITY_MAP["DATA_EXFILTRATION_SPIKE"]["BALANCED"]["m_z"], 3.5)
    self.assertIn("$m_z_score > 3.5", self.query)

  def test_caveats_documented(self):
    self.assertIn("ACTIVE days only", self.raw)
    self.assertIn("included in its own baseline", self.raw)


if __name__ == "__main__":
  unittest.main()
