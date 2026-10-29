# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Contract tests for WS7-01 (D5 canonical CRI) and WS7-02 (Z-equivalent registry & sigma units)."""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
  sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scripts import multistage_query_builder as mqb
from scripts import ueba_constants as uc


class TestWS701CanonicalCRI(unittest.TestCase):
  """WS7-01 / D5: One canonical CRI (0..100, 0 for Z<=0, 26/46/70/90 bands, N/A on missing/error)."""

  def test_canonical_cri_zero_floor_anchors_and_saturation(self) -> None:
    self.assertEqual(uc.calculate_cri(0.0), 0)
    self.assertEqual(uc.calculate_cri(-0.001), 0)
    self.assertEqual(uc.calculate_cri(-5.0), 0)
    self.assertEqual(uc.cri_from_score(0.0), 0)
    self.assertEqual(uc.calculate_cri(3.0), 50)
    self.assertEqual(uc.calculate_cri(6.0), 86)
    self.assertEqual(uc.calculate_cri(15.0), 100)
    self.assertEqual(uc.calculate_cri(3000.0), 100)

    self.assertEqual(mqb.calculate_cri(0.0), 0)
    self.assertEqual(mqb.calculate_cri(-3.0), 0)
    self.assertEqual(mqb.calculate_cri(3.0), 50)
    self.assertEqual(mqb.calculate_cri(6.0), 86)
    self.assertEqual(mqb.calculate_cri(15.0), 100)

  def test_canonical_cri_missing_and_error_values_return_none_and_na(self) -> None:
    for bad_input in (
        None,
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        "N/A",
        "NaN",
        "-",
        "",
        "unparseable_error",
    ):
      with self.subTest(bad_input=bad_input):
        self.assertIsNone(uc.calculate_cri(bad_input))
        self.assertIsNone(mqb.calculate_cri(bad_input))
        self.assertEqual(uc.format_cri(bad_input), "N/A")
        self.assertEqual(mqb.get_cri_badge(bad_input), ("⚪ `[CRI: N/A]`", "N/A"))

  def test_canonical_cri_exact_band_cutoffs_26_46_70_90(self) -> None:
    expected = (
        (0, "INFORMATIONAL", "Nominal", "🟢"),
        (25, "INFORMATIONAL", "Nominal", "🟢"),
        (26, "LOW", "Low Drift", "🟡"),
        (45, "LOW", "Low Drift", "🟡"),
        (46, "MEDIUM", "Medium Outlier", "🟠"),
        (69, "MEDIUM", "Medium Outlier", "🟠"),
        (70, "HIGH", "High Threat", "🔴"),
        (89, "HIGH", "High Threat", "🔴"),
        (90, "CRITICAL", "Critical Outlier", "🚨"),
        (100, "CRITICAL", "Critical Outlier", "🚨"),
    )
    for cri_val, code, label, emoji in expected:
      with self.subTest(cri=cri_val):
        self.assertEqual(uc.get_cri_band_info(cri_val), (code, label, emoji))
        self.assertEqual(mqb.get_cri_badge(cri_val), (f"{emoji} `[CRI: {cri_val}]`", label))

  def test_format_triage_report_missing_or_nan_score_renders_na_cri(self) -> None:
    missing_score_payload = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-missing-score"}}]},
                {"column": "observation_count", "values": [{"value": {"int64Val": "42"}}]},
                {"column": "baseline_active_samples", "values": [{"value": {"int64Val": "120"}}]},
                {"column": "baseline_mean", "values": [{"value": {"doubleVal": 10.0}}]},
                {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 2.0}}]},
            ]
        }
    }
    report_missing = mqb.format_triage_report("Missing Score Test", missing_score_payload)
    self.assertIn("⚪ `[CRI: N/A]`", report_missing)
    self.assertNotIn("`[CRI: 0]`", report_missing)

    nan_score_payload = {
        "stats": {
            "results": [
                {"column": "host", "values": [{"value": {"stringVal": "host-nan-score"}}]},
                {"column": "observation_count", "values": [{"value": {"int64Val": "42"}}]},
                {"column": "z_score", "values": [{"value": {"doubleVal": float("nan")}}]},
            ]
        }
    }
    report_nan = mqb.format_triage_report("NaN Score Test", nan_score_payload)
    self.assertIn("⚪ `[CRI: N/A]`", report_nan)


def _single_row_payload(entity: str, score_col: str, score_val: float) -> dict:
  return {
      "stats": {
          "results": [
              {"column": "host", "values": [{"value": {"stringVal": entity}}]},
              {"column": "TIME_BUCKET", "values": [{"value": {"stringVal": "2026-10-27T12:00:00Z"}}]},
              {"column": "observation_count", "values": [{"value": {"int64Val": "50"}}]},
              {"column": "baseline_active_samples", "values": [{"value": {"int64Val": "60"}}]},
              {"column": "baseline_mean", "values": [{"value": {"doubleVal": 10.0}}]},
              {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 2.0}}]},
              {"column": score_col, "values": [{"value": {"doubleVal": score_val}}]},
          ]
      }
  }


class TestWS702ScoreSemanticsRegistry(unittest.TestCase):
  """WS7-02: Z-equivalent registry mapping thresholds to 3.0, flipping inverted ratios, and restricting sigma unit."""

  def test_every_model_threshold_maps_to_z_equiv_3_0_and_cri_50(self) -> None:
    threshold_cases = (
        ("z_score", 3.0),
        ("personal_z", 3.0),
        ("modified_z", 3.5),
        ("m_z_score", 3.5),
        ("quantile_z", 3.5),
        ("fence_z", 3.5),
        ("fleet_z", 2.5),
        ("z_log", 2.5),
        ("fold_change", 2.0),
        ("surge_ratio", 2.0),
        ("tukey_fence_ratio", 2.0),
        ("bayes_shift_ratio", 2.0),
        ("posterior_lift", 2.0),
        ("ratio", 1.0),
        ("fano_factor", 4.0),
        ("cv", 0.20),
        ("diversity_z", -1.5),
        ("posterior_fail_prob", 0.50),
        ("regularized_failure_prob", 0.50),
        ("posterior_rate", 0.50),
        ("concentration_ratio", 0.65),
        ("producer_ratio", 0.70),
        ("sensitivity_excess", 0.0),
        ("composite_threat_norm_sq", 12.25),
        ("poisson_z_sq", 12.25),
        ("threat_vector_norm_sq", 9.0),
        ("shannon_entropy_score", 5.5),
        ("zipf_rarity_score", 2.5),
        ("velocity_score", 2.0),
        ("velocity_kmh", 900.0),
        ("cusum_drift_score", 3.0),
        ("hurdle_threat_score", 3.0),
        ("cri_score", 50.0),
    )
    for key, thresh_val in threshold_cases:
      with self.subTest(key=key, thresh=thresh_val):
        z_eq = uc.score_to_z_equivalent(key, thresh_val)
        self.assertAlmostEqual(z_eq, 3.0, places=4)
        self.assertEqual(uc.cri_from_model_score(key, thresh_val), 50)

  def test_cv_zero_jitter_and_nominal_baselines_behave_monotonically(self) -> None:
    # Zero-jitter robotic beacon (cv=0.0) must NOT map to CRI=0; it maps to Z_equiv=5.0, CRI=77
    self.assertAlmostEqual(uc.score_to_z_equivalent("cv", 0.0), 5.0)
    self.assertEqual(uc.cri_from_model_score("cv", 0.0), 77)
    self.assertEqual(uc.cri_from_model_score("cv", 0.50), 0)
    self.assertEqual(uc.cri_from_model_score("cv", 0.80), 0)
    self.assertIsNone(uc.score_to_z_equivalent("cv", -0.1))

    # Nominal Fano (1.0) and Surge Ratio (1.0) map to CRI=0
    self.assertEqual(uc.cri_from_model_score("fano_factor", 1.0), 0)
    self.assertEqual(uc.cri_from_model_score("surge_ratio", 1.0), 0)

  def test_format_triage_report_applies_z_equiv_cri_and_true_sigma_units_only(self) -> None:
    # 1. cv=0.0 (perfect zero-jitter beacon): CRI=77, formatted '0.00' (NO sigma), non-empty visual bar
    rep_cv0 = mqb.format_triage_report("C2 Jitter", _single_row_payload("beacon-0", "cv", 0.0))
    self.assertIn("`[CRI: 77]`", rep_cv0)
    self.assertIn("(`0.00`)", rep_cv0)
    self.assertNotIn("0.00σ", rep_cv0)
    self.assertIn("`██████████`", rep_cv0)

    # 2. m_z_score=3.5: threshold CRI=50, true sigma unit '+3.50σ'
    rep_mad = mqb.format_triage_report("MAD", _single_row_payload("host-mad", "m_z_score", 3.5))
    self.assertIn("`[CRI: 50]`", rep_mad)
    self.assertIn("(`+3.50σ`)", rep_mad)

    # 3. diversity_z=-1.5: threshold CRI=50, negative true sigma '-1.50σ' (NOT '+-1.50σ')
    rep_div = mqb.format_triage_report("Diversity Deficit", _single_row_payload("host-div", "diversity_z", -1.5))
    self.assertIn("`[CRI: 50]`", rep_div)
    self.assertIn("(`-1.50σ`)", rep_div)
    self.assertNotIn("+-", rep_div)

    # 4. Non-sigma models at threshold -> CRI=50 and NO sigma unit (including threat_distance)
    for col, val, expected_str in (
        ("surge_ratio", 2.0, "2.00"),
        ("fano_factor", 4.0, "4.00"),
        ("regularized_failure_prob", 0.50, "0.50"),
        ("shannon_entropy_score", 5.5, "5.50"),
        ("zipf_rarity_score", 2.5, "2.50"),
        ("velocity_score", 2.0, "2.00"),
        ("poisson_z_sq", 12.25, "12.25"),
        ("threat_distance", 3.0, "3.00"),
    ):
      with self.subTest(col=col):
        rep = mqb.format_triage_report(f"Test {col}", _single_row_payload("host-x", col, val))
        self.assertIn("`[CRI: 50]`", rep)
        self.assertIn(f"(`{expected_str}`)", rep)
        self.assertNotIn(f"{expected_str}σ", rep)


class TestWS702Phase4ScoreSemantics(unittest.TestCase):
  """Phase 4C (WS7-02): Synchronized macro + micro Phase 4 score semantics and boolean novelty_flag."""

  def test_phase4_score_semantics_registry_thresholds_and_sigma_flags(self) -> None:
    self.assertEqual(uc.DEFAULT_TUKEY_EXCESS_THRESHOLD, 1.0)
    self.assertEqual(uc.RADAR_FUSION_DISTANCE_THRESHOLD, 3.0)
    self.assertEqual(uc.RADAR_COMPOSITE_D_THRESHOLD, 3.5)

    phase4_cases = (
        ("tukey_excess_z", 1.0, False, "1.00"),
        ("adaptive_z", 3.0, False, "3.00"),
        ("rel_dev_z_equiv", 3.0, False, "3.00"),
        ("beta_binomial_z", 3.0, True, "+3.00σ"),
        ("posterior_fail_rate", 0.50, False, "0.50"),
        ("above_max_z", 3.0, True, "+3.00σ"),
        ("windowed_slack_sum", 3.0, False, "3.00"),
        ("flow_surge_score", 3.0, True, "+3.00σ"),
        ("hod_z_score", 3.0, True, "+3.00σ"),
        ("burst_z", 3.0, True, "+3.00σ"),
        ("deficit_z", 1.5, True, "+1.50σ"),
    )
    for key, thresh_val, expected_sigma, expected_fmt in phase4_cases:
      with self.subTest(key=key):
        sem = uc.get_score_semantics(key)
        self.assertIn(key, uc.SCORE_SEMANTICS_REGISTRY)
        self.assertEqual(sem.kind, "linear")
        self.assertAlmostEqual(sem.threshold, thresh_val, places=4)
        self.assertEqual(sem.neutral, 0.0)
        self.assertEqual(sem.is_true_sigma, expected_sigma)
        self.assertEqual(uc.is_true_sigma_key(key), expected_sigma)
        self.assertAlmostEqual(uc.score_to_z_equivalent(key, thresh_val), 3.0, places=4)
        self.assertEqual(uc.cri_from_model_score(key, thresh_val), 50)
        self.assertEqual(uc.format_score_with_unit(key, thresh_val), expected_fmt)

  def test_novelty_flag_boolean_semantics_never_sigma_or_cri(self) -> None:
    sem = uc.get_score_semantics("novelty_flag")
    self.assertEqual(sem, uc.ScoreSemantics("boolean_flag", 1.0, 0.0, False))
    self.assertFalse(uc.is_true_sigma_key("novelty_flag"))
    for flag_val in (0, 1, 0.0, 1.0):
      self.assertIsNone(uc.score_to_z_equivalent("novelty_flag", flag_val))
      self.assertIsNone(uc.cri_from_model_score("novelty_flag", flag_val))
      self.assertEqual(uc.format_cri(uc.cri_from_model_score("novelty_flag", flag_val)), "N/A")
      rendered = uc.format_score_with_unit("novelty_flag", flag_val)
      self.assertNotIn("σ", rendered)
    self.assertEqual(uc.format_score_with_unit("novelty_flag", 1), "NOVEL (flag=1)")
    self.assertEqual(uc.format_score_with_unit("novelty_flag", 0), "SEEN (flag=0)")

  def test_micro_triage_and_chart_consumers_wire_phase4_score_keys_and_novelty_flag(self) -> None:
    for col, val, expected_str, expect_sigma in (
        ("hod_z_score", 3.0, "+3.00σ", True),
        ("burst_z", 3.0, "+3.00σ", True),
        ("deficit_z", 1.5, "+1.50σ", True),
        ("beta_binomial_z", 3.0, "+3.00σ", True),
        ("above_max_z", 3.0, "+3.00σ", True),
        ("flow_surge_score", 3.0, "+3.00σ", True),
        ("tukey_excess_z", 1.0, "1.00", False),
        ("adaptive_z", 3.0, "3.00", False),
        ("rel_dev_z_equiv", 3.0, "3.00", False),
        ("posterior_fail_rate", 0.50, "0.50", False),
        ("windowed_slack_sum", 3.0, "3.00", False),
    ):
      with self.subTest(col=col):
        payload = _single_row_payload(f"host-{col}", col, val)
        rep = mqb.format_triage_report(f"Phase 4 {col}", payload)
        self.assertIn("`[CRI: 50]`", rep)
        self.assertIn(f"(`{expected_str}`)", rep)
        if not expect_sigma:
          self.assertNotIn(f"{expected_str}σ", rep)
        reduced = mqb.DataReductionEngine.reduce([{col: val, "host": f"host-{col}"}])
        self.assertEqual(reduced["primary_score_metric"], col)
        chart = mqb.generate_chart_spec(payload, plot_type="DUAL_Y_TIMESERIES")
        axis_title = chart["layer"][1]["encoding"]["y"]["axis"]["title"]
        if expect_sigma:
          self.assertIn("Z-Score (σ)", axis_title)
        else:
          self.assertIn("Anomaly Score", axis_title)
          self.assertNotIn("σ", axis_title)

    # deficit_z = 1.5 is the BALANCED alertable threshold -> HIGH SUSPICION
    rep_def = mqb.format_triage_report("Deficit Z", _single_row_payload("host-def", "deficit_z", 1.5))
    self.assertIn("[HIGH SUSPICION]", rep_def)

    # Boolean novelty_flag=1 renders NOVEL (flag=1) with CRI: N/A and zero sigma
    rep_nov = mqb.format_triage_report("First-Seen Novelty", _single_row_payload("host-nov", "novelty_flag", 1.0))
    self.assertIn("⚪ `[CRI: N/A]`", rep_nov)
    self.assertIn("`NOVEL (flag=1)`", rep_nov)
    self.assertNotIn("σ", rep_nov)


if __name__ == "__main__":
  unittest.main()
