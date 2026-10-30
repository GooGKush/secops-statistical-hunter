"""Tests for cross-cutting WS5 items: WS5-S-WS ($ws in Root match), WS5-S-M30 (tier/window min_active_samples), and WS5-S-FP (surging fleet prevalence & real PASSED/FAILED verdict)."""

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from multistage_query_builder import (  # pylint: disable=wrong-import-position
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    evaluate_confidence_tier,
    format_triage_report,
    get_adaptive_window_parameters,
)


class TestWS5RootWsBucketKey(unittest.TestCase):
  """WS5-S-WS: Every bucketed pipeline that scores individual time buckets must include $ws/$window_start in Root match:."""

  def test_no_bucketed_pipeline_omits_ws_from_root_match(self):
    router = MultiStageTemplateRouter()
    tpl_dir = REPO_ROOT / "templates" / "pipelines"
    yl2_files = sorted(tpl_dir.glob("*.yl2"))
    self.assertEqual(len(yl2_files), 27)

    for tpl_path in yl2_files:
      with self.subTest(template=tpl_path.name):
        code = re.sub(r"//.*", "", tpl_path.read_text(encoding="utf-8"))
        norm = re.sub(r"\{\{(\w+)\}\}", r"SLOT_\1", code)
        stages = re.findall(r"stage\s+(\w+)\s*\{([^}]*)\}", norm, flags=re.DOTALL)
        self.assertGreaterEqual(len(stages), 1, f"{tpl_path.name} has no intermediate stages")
        root = re.sub(r"stage\s+\w+\s*\{[^}]*\}", "", norm, flags=re.DOTALL)

        s1_match_m = re.search(r"match\s*:(.*?)(?:outcome|condition|order|\Z)", stages[0][1], flags=re.DOTALL)
        root_match_m = re.search(r"match\s*:(.*?)(?:outcome|condition|order|\Z)", root, flags=re.DOTALL)
        self.assertIsNotNone(s1_match_m)
        self.assertIsNotNone(root_match_m)
        s1_match = s1_match_m.group(1).strip()
        root_match = root_match_m.group(1).strip()

        # Any pipeline whose Stage 1 buckets by time AND whose Root scores per-bucket (`by ...`) must include $ws or $window_start
        if re.search(r"\bby\b", s1_match) and re.search(r"\bby\b", root_match):
          self.assertRegex(
              root_match,
              r"\$(?:ws|window_start)\b",
              f"{tpl_path.name} buckets in Stage 1 ({s1_match!r}) and Root ({root_match!r}) without $ws/$window_start!",
          )

    # Also check INLINE_TEMPLATES fallback
    for fname, raw_tpl in router.INLINE_TEMPLATES.items():
      code = re.sub(r"//.*", "", raw_tpl)
      norm = re.sub(r"\{\{(\w+)\}\}", r"SLOT_\1", code)
      root = re.sub(r"stage\s+\w+\s*\{[^}]*\}", "", norm, flags=re.DOTALL)
      root_match_m = re.search(r"match\s*:(.*?)(?:outcome|condition|order|\Z)", root, flags=re.DOTALL)
      if root_match_m and re.search(r"\bby\b", root_match_m.group(1)):
        self.assertRegex(root_match_m.group(1), r"\$(?:ws|window_start)\b", f"INLINE_TEMPLATES[{fname}] missing $ws")


class TestWS5ModeAndWindowMinActiveSamples(unittest.TestCase):
  """WS5-S-M30: Default min_active_samples scales by SensitivityTier and available buckets (never > buckets)."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_24h_by_1h_balanced_renders_at_most_12_and_scales_across_tiers(self):
    q_cons = self.router.build_query("ZSCORE_PROCESS_SURGE", tier="CONSERVATIVE", window_hours=24.0, bucket_size="1h")
    q_bal = self.router.build_query("ZSCORE_PROCESS_SURGE", tier="BALANCED", window_hours=24.0, bucket_size="1h")
    q_agg = self.router.build_query("ZSCORE_PROCESS_SURGE", tier="AGGRESSIVE", window_hours=24.0, bucket_size="1h")

    def _extract_floor(q: str) -> int:
      m = re.search(r"\$baseline_active_samples\s*>=\s*(\d+)", q)
      self.assertIsNotNone(m, f"Missing $baseline_active_samples >= N in:\n{q}")
      return int(m.group(1))

    f_cons = _extract_floor(q_cons)
    f_bal = _extract_floor(q_bal)
    f_agg = _extract_floor(q_agg)

    self.assertLessEqual(f_bal, 12, f"24h by 1h BALANCED must require <= 12 active buckets, got {f_bal}")
    self.assertLessEqual(f_cons, 12, f"24h by 1h CONSERVATIVE must not exceed half of 24 buckets, got {f_cons}")
    self.assertGreater(f_cons, f_bal, f"Expected CONSERVATIVE ({f_cons}) > BALANCED ({f_bal})")
    self.assertGreater(f_bal, f_agg, f"Expected BALANCED ({f_bal}) > AGGRESSIVE ({f_agg})")

  def test_adaptive_window_parameters_vary_monotonically_with_tier_and_never_exceed_buckets(self):
    p_cons = get_adaptive_window_parameters(24.0, "ZSCORE_PROCESS_SURGE", "CONSERVATIVE")
    p_bal = get_adaptive_window_parameters(24.0, "ZSCORE_PROCESS_SURGE", "BALANCED")
    p_agg = get_adaptive_window_parameters(24.0, "ZSCORE_PROCESS_SURGE", "AGGRESSIVE")
    self.assertGreater(p_cons["proportional_sample_floor"], p_bal["proportional_sample_floor"])
    self.assertGreater(p_bal["proportional_sample_floor"], p_agg["proportional_sample_floor"])

    # Ultra-short 1h window with 1h bucket: total buckets = 1 -> min_active_samples must be <= 1 (never 4 > 1!)
    q_1h = self.router.build_query("ZSCORE_PROCESS_SURGE", tier="BALANCED", window_hours=1.0, bucket_size="1h")
    m = re.search(r"\$baseline_active_samples\s*>=\s*(\d+)", q_1h)
    self.assertIsNotNone(m)
    self.assertLessEqual(int(m.group(1)), 1)

  def test_mad_daily_hunt_uses_min_active_samples_7_not_30(self):
    q_default = self.router.build_query("DATA_EXFILTRATION_SPIKE", tier="BALANCED")
    q_14d = self.router.build_query("DATA_EXFILTRATION_SPIKE", tier="BALANCED", window_hours=336.0)
    self.assertIn("$baseline_active_samples >= 7", q_default)
    self.assertIn("$baseline_active_samples >= 7", q_14d)

    # Confidence tier for a daily MAD outlier with 10 active days (>= 7, < 30) must NOT be INSUFFICIENT BASELINE
    tier_badge, _ = evaluate_confidence_tier({
        "observation_count": 250,
        "baseline_active_samples": 10,
        "baseline_mean": 40.0,
        "baseline_dispersion": 4.0,
        "fleet_prevalence": -1,
        "m_z_score": 6.2,
    })
    self.assertNotIn("INSUFFICIENT BASELINE", tier_badge)


class TestWS5RealFleetPrevalenceCheck(unittest.TestCase):
  """WS5-S-FP: Fleet-prevalence stages count surging entities, and report evaluates real PASSED vs FAILED."""

  def test_fleet_stages_count_surging_entities_not_all_active_entities(self):
    router = MultiStageTemplateRouter()
    for arch, stage_name in (
        ("ZSCORE_PROCESS_SURGE", "fleet_breadth"),
        ("BAYESIAN_GAMMA_SHRINKAGE", "fleet_context"),
        ("BETA_BINOMIAL_FAILURE", "fleet_stats"),
        ("IQR_TUKEY_SKEW_FENCES", "fleet_breadth"),
        ("POISSON_BURST_CLUSTERING", "fleet_breadth"),
    ):
      with self.subTest(archetype=arch):
        q = router.build_query(arch, tier="BALANCED")
        gate = QueryIntegrityGate.verify_pre_dispatch(q)
        self.assertTrue(gate["valid"], f"{arch} failed syntax gate: {gate['errors']}")
        m = re.search(rf"stage\s+{stage_name}\s*\{{([^}}]*)\}}", q, flags=re.DOTALL)
        self.assertIsNotNone(m, f"{arch} missing {stage_name}")
        stage_body = m.group(1)
        self.assertNotIn(
            "count_distinct(",
            stage_body,
            f"{arch} {stage_name} still counts all active entities via unconditional count_distinct!",
        )
        self.assertIn("sum(if(", stage_body, f"{arch} {stage_name} must count surging entities via sum(if(...))")

  def test_format_triage_report_evaluates_real_passed_vs_failed_fleet_prevalence(self):
    def _make_payload(fleet_prev: int):
      return {
          "stats": {
              "results": [
                  {"column": "host", "values": [{"value": {"stringVal": "wks-01"}}]},
                  {"column": "window_start", "values": [{"value": {"int64Val": "1761523200"}}]},
                  {"column": "observation_count", "values": [{"value": {"int64Val": "400"}}]},
                  {"column": "baseline_active_samples", "values": [{"value": {"int64Val": "140"}}]},
                  {"column": "baseline_mean", "values": [{"value": {"doubleVal": 50.0}}]},
                  {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 12.0}}]},
                  {"column": "fleet_prevalence", "values": [{"value": {"int64Val": str(fleet_prev)}}]},
                  {"column": "distinct_binaries", "values": [{"value": {"int64Val": "18"}}]},
                  {"column": "z_score", "values": [{"value": {"doubleVal": 6.5}}]},
              ]
          }
      }

    rep_isolated = format_triage_report("Surge Hunt", _make_payload(2))
    self.assertRegex(rep_isolated, r"Fleet Prevalence Isolation[^\n]*\*\*PASSED\*\*")

    rep_widespread = format_triage_report("Surge Hunt", _make_payload(25))
    self.assertRegex(rep_widespread, r"Fleet Prevalence Isolation[^\n]*\*\*FAILED\*\*")
    self.assertNotRegex(rep_widespread, r"Fleet Prevalence Isolation[^\n]*\*\*PASSED\*\*")


if __name__ == "__main__":
  unittest.main()
