"""Tests for WS5-D1 (retire impossible_travel_geo_velocity_2stage) and WS5-HOD (HOUR_OF_DAY_PROFILE)."""

import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import multistage_query_builder as mqb  # pylint: disable=wrong-import-position
from multistage_query_builder import (  # pylint: disable=wrong-import-position
    HandoffEndpoint,
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    check_scope_exclusions,
    get_thresholds_for_tier,
    validate_multistage_syntax,
)

EXPECTED_D1_RETIRED_MSG = (
    "IMPOSSIBLE_TRAVEL_GEO_VELOCITY is retired (D1): city-centroid geo-velocity and VPN egress "
    "produce systematic false positives; use HOUR_OF_DAY_PROFILE or DERIVED_CONTEXT_PREVALENCE instead."
)


class TestWS5D1RetireImpossibleTravel(unittest.TestCase):
  """WS5-D1: Retire impossible_travel_geo_velocity_2stage while keeping clear ValueError on aliases."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_template_removed_from_disk(self):
    tpl = REPO_ROOT / "templates" / "pipelines" / "impossible_travel_geo_velocity_2stage.yl2"
    self.assertFalse(tpl.exists(), "impossible_travel_geo_velocity_2stage.yl2 must be removed from active templates/")

  def test_model_archetype_preserves_retired_enum_member(self):
    self.assertTrue(hasattr(mqb, "ModelArchetype"))
    self.assertEqual(mqb.ModelArchetype.IMPOSSIBLE_TRAVEL_GEO_VELOCITY.value, "IMPOSSIBLE_TRAVEL_GEO_VELOCITY")

  def test_router_and_thresholds_raise_exact_retired_value_error(self):
    for alias in (
        "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        "IMPOSSIBLE_TRAVEL",
        "GEO_VELOCITY",
        "SUPERSONIC_TRAVEL",
        "impossible-travel-geo-velocity",
    ):
      with self.subTest(alias=alias):
        with self.assertRaises(ValueError) as ctx_fn:
          self.router.get_template_filename(alias)
        self.assertEqual(str(ctx_fn.exception), EXPECTED_D1_RETIRED_MSG)

        with self.assertRaises(ValueError) as ctx_bq:
          self.router.build_query(alias)
        self.assertEqual(str(ctx_bq.exception), EXPECTED_D1_RETIRED_MSG)

    with self.assertRaises(ValueError) as ctx_th:
      get_thresholds_for_tier("IMPOSSIBLE_TRAVEL_GEO_VELOCITY", "BALANCED")
    self.assertEqual(str(ctx_th.exception), EXPECTED_D1_RETIRED_MSG)

  def test_handoff_ingest_rejects_retired_intent_with_clear_message(self):
    res = HandoffEndpoint.ingest({
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-d1-retired",
        "target_skill": "secops-statistical-hunter",
        "intent": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        "entity": {"type": "user", "identifier": "alice@corp.com"},
    })
    self.assertEqual(res["status"], "HANDOFF_ACK_REJECTED")
    self.assertTrue(any(EXPECTED_D1_RETIRED_MSG in err for err in res["errors"]), res)

  def test_cli_build_query_reports_clear_retired_error(self):
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "multistage_query_builder.py"),
            "--build_query",
            "--archetype",
            "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertNotEqual(proc.returncode, 0)
    self.assertIn(EXPECTED_D1_RETIRED_MSG, proc.stderr)


class TestWS5HourOfDayProfile(unittest.TestCase):
  """WS5-HOD (D1a): Learned hour-of-day profile 3-stage pipeline and golden math verification."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_archetype_and_aliases_registered(self):
    self.assertEqual(mqb.ModelArchetype.HOUR_OF_DAY_PROFILE.value, "HOUR_OF_DAY_PROFILE")
    for alias in (
        "HOUR_OF_DAY_PROFILE",
        "HOURLY_TEMPORAL_ZSCORE",
        "CIRCADIAN_VON_MISES",
        "TIME_OF_DAY",
        "CIRCADIAN",
    ):
      with self.subTest(alias=alias):
        self.assertEqual(self.router.get_template_filename(alias), "hour_of_day_profile_3stage.yl2")

  def test_renders_clean_ast_across_tiers_and_entities(self):
    for entity_type in ("user", "host", "ip"):
      for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
        with self.subTest(entity_type=entity_type, tier=tier):
          q = self.router.build_query(
              "HOUR_OF_DAY_PROFILE",
              tier=tier,
              entity_type=entity_type,
              start_time="2026-10-21T00:00:00Z",
              end_time="2026-10-28T00:00:00Z",
          )
          gate = QueryIntegrityGate.verify_pre_dispatch(q)
          self.assertTrue(gate["valid"], f"Pre-dispatch errors for {entity_type}/{tier}: {gate['errors']}")
          self.assertEqual(check_scope_exclusions(q), [])
          self.assertEqual(validate_multistage_syntax(q), [])
          # Required stages and variables
          self.assertIn("stage hourly_activity", q)
          self.assertIn("stage hod_baseline", q)
          self.assertIn("stage entity_total_profile", q)
          self.assertIn('timestamp.get_hour(metadata.event_timestamp.seconds, "UTC")', q)
          self.assertIn("$in_scoring_window", q)
          self.assertIn("$base_obs", q)
          self.assertIn("$base_obs_sq", q)
          self.assertIn("$base_active", q)
          self.assertIn("$sum_x_hod", q)
          self.assertIn("$sum_x2_hod", q)
          self.assertIn("$active_days_hod", q)
          self.assertIn("$entity_base_total", q)
          self.assertIn("$entity_active_hours", q)
          self.assertIn("$observed", q)
          self.assertIn("$mu_hod", q)
          self.assertIn("$safe_sd_hod", q)
          self.assertIn("$hod_z_score", q)
          self.assertIn("$hour_profile_mass", q)
          self.assertRegex(q, r"match:\s*\$entity\s*,\s*\$hod\s*,\s*\$ws\b")

  def test_timezone_event_filter_and_baseline_days_validation(self):
    q = self.router.build_query(
        "CIRCADIAN_VON_MISES",
        tier="BALANCED",
        entity_type="user",
        tenant_tz="America/New_York",
        event_filter='target.application = "AWSConsole"',
        start_time="2026-10-14T00:00:00Z",
        end_time="2026-10-28T00:00:00Z",
    )
    self.assertIn('timestamp.get_hour(metadata.event_timestamp.seconds, "America/New_York")', q)
    self.assertIn('target.application = "AWSConsole"', q)
    # 14d total window - 1d scoring window = 13 baseline days
    self.assertIn("/ 13", q)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q)["valid"])

    with self.assertRaises(ValueError):
      self.router.build_query("HOUR_OF_DAY_PROFILE", baseline_days=0)

    with self.assertRaises(ValueError):
      mqb.compute_hod_window_slots(
          start_time_iso="2026-10-27T00:00:00Z",
          end_time_iso="2026-10-28T00:00:00Z",
          scoring_hours=24.0,
      )

  def test_golden_math_oos_exclusion_zero_inclusive_and_poisson_floor(self):
    # Case 1: 03:00 nocturnal anomaly (0 events in 6 baseline days, 90 business-hour baseline events, 12 at 03:00 on day 7)
    res_nocturnal = mqb.compute_hour_of_day_profile(
        observed=12,
        baseline_hour_counts=[],
        baseline_days=6,
        entity_base_total=90.0,
        entity_active_hours=36,
    )
    self.assertAlmostEqual(res_nocturnal["mu_hod"], 0.0, places=6)
    self.assertAlmostEqual(res_nocturnal["sd_hod"], 0.0, places=6)
    self.assertAlmostEqual(res_nocturnal["safe_sd_hod"], 1.0, places=6)
    self.assertAlmostEqual(res_nocturnal["hod_z_score"], 12.0, places=6)
    self.assertAlmostEqual(res_nocturnal["hour_profile_mass"], 0.0, places=6)

    # Case 2: Zero-inclusive variance over 6 days with active counts [10, 10, 10] on 3 days and 0 on 3 days
    res_half = mqb.compute_hour_of_day_profile(
        observed=25,
        baseline_hour_counts=[10, 10, 10],
        baseline_days=6,
        entity_base_total=120.0,
        entity_active_hours=24,
    )
    self.assertAlmostEqual(res_half["mu_hod"], 5.0, places=6)
    self.assertAlmostEqual(res_half["sd_hod"], 5.0, places=6)
    self.assertAlmostEqual(res_half["safe_sd_hod"], 5.0, places=6)
    self.assertAlmostEqual(res_half["hod_z_score"], 4.0, places=6)
    self.assertAlmostEqual(res_half["hour_profile_mass"], 30.0 / 120.0, places=6)

    # Case 3: Clockwork 9 events every day at 09:00 -> sd_hod = 0, floor = sqrt(9) = 3.0 -> observed 11 is only +0.67 sigma
    res_clockwork = mqb.compute_hour_of_day_profile(
        observed=11,
        baseline_hour_counts=[9, 9, 9, 9, 9, 9],
        baseline_days=6,
        entity_base_total=54.0,
        entity_active_hours=6,
    )
    self.assertAlmostEqual(res_clockwork["mu_hod"], 9.0, places=6)
    self.assertAlmostEqual(res_clockwork["sd_hod"], 0.0, places=6)
    self.assertAlmostEqual(res_clockwork["safe_sd_hod"], 3.0, places=6)
    self.assertAlmostEqual(res_clockwork["hod_z_score"], 2.0 / 3.0, places=6)


if __name__ == "__main__":
  unittest.main()
