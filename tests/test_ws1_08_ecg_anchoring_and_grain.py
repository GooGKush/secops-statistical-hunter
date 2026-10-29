"""Regression tests for WS1-08 (Micro Side): ECG D-2 Anchor, Grain/day_count Fixes, Disclosures & Day-0 Query."""

import os
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
import multistage_query_builder as mqb
from multistage_query_builder import (
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    format_triage_report,
    validate_multistage_syntax,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

ECG_ARCHETYPES = (
    "DERIVED_CONTEXT_PREVALENCE",
    "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
    "DERIVED_CONTEXT_FILE_PREVALENCE",
    "GLOBAL_THREAT_INTEL_ENRICHMENT",
)


def _ecg_result_payload(first_seen_val: int = 0):
  return {
      "stats": {
          "results": [
              {"column": "host", "values": [{"value": {"stringVal": "10.1.0.25"}}]},
              {"column": "domain", "values": [{"value": {"stringVal": "rare-c2.example"}}]},
              {"column": "ws", "values": [{"value": {"int64Val": "1793196000"}}]},
              {"column": "observation_count", "values": [{"value": {"int64Val": "524288"}}]},
              {"column": "baseline_active_samples", "values": [{"value": {"int64Val": "14"}}]},
              {"column": "baseline_mean", "values": [{"value": {"doubleVal": 20480.0}}]},
              {"column": "baseline_dispersion", "values": [{"value": {"doubleVal": 4096.0}}]},
              {"column": "fleet_prevalence", "values": [{"value": {"int64Val": "1"}}]},
              {"column": "distinct_binaries", "values": [{"value": {"int64Val": "1"}}]},
              {"column": "enterprise_first_seen", "values": [{"value": {"int64Val": str(first_seen_val)}}]},
              {"column": "threat_score", "values": [{"value": {"doubleVal": 12.5}}]},
          ]
      }
  }


class TestWS108EcgAnchoringAndGrain(unittest.TestCase):
  """Verifies PF-8 / WS1-08 ECG template fixes, D-2 search anchoring, Day-0 query, and report disclosures."""

  def test_all_4_ecg_templates_fix_grain_root_ws_event_anchored_age_and_day_count(self):
    """All 4 ECG templates use count_distinct(window_start), $ws in root match, event_ts age, and day_count=10."""
    router = MultiStageTemplateRouter()

    q_dom = router.build_query("DERIVED_CONTEXT_DOMAIN_PREVALENCE", tier="BALANCED")
    self.assertIn("$dom.graph.entity.domain.prevalence.day_count = 10", q_dom)
    self.assertIn("$dom.graph.entity.domain.prevalence.rolling_max > 0", q_dom)

    for arch in ECG_ARCHETYPES:
      with self.subTest(archetype=arch):
        q = router.build_query(arch, tier="BALANCED")
        # 1. Stage 3 uses count_distinct($raw_*.window_start), never count($raw_*.window_start)
        self.assertRegex(q, r"count_distinct\(\$raw_[a-z_]+\.window_start\)")
        self.assertNotRegex(q, r"\bcount\(\$raw_[a-z_]+\.window_start\)")

        # 2. Event-anchored age ($obs_ts = max($raw_*.event_ts)) instead of timestamp.current_seconds()
        self.assertNotIn("timestamp.current_seconds()", q)
        self.assertRegex(q, r"\$event_ts\s*=\s*max\(\$[a-z_]+\.metadata\.event_timestamp\.seconds\)")
        self.assertRegex(q, r"\$obs_ts\s*=\s*max\(\$raw_[a-z_]+\.event_ts\)")
        self.assertIn("$raw_age_days = ($obs_ts - ", q)

        # 3. Root match binds $ws = $raw_*.window_start and includes $ws in Root match:
        stripped_root = re.sub(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", "", q, flags=re.DOTALL)
        self.assertRegex(stripped_root, r"\$ws\s*=\s*\$raw_[a-z_]+\.window_start")
        m_match = re.search(r"match:\s*\n\s*([^\n]+)", stripped_root)
        self.assertIsNotNone(m_match)
        self.assertIn("$ws", m_match.group(1))

        # 4. Syntax & pre-dispatch clean (including <= 20 outcome vars and no compound math in if())
        gate = QueryIntegrityGate.verify_pre_dispatch(q)
        self.assertTrue(gate["valid"], f"Pre-dispatch errors for {arch}: {gate['errors']}")

  def test_compute_ecg_search_window_anchors_d_minus_2_and_pins_stage1_events(self):
    """A run requested starting today widens startTime to D-2 00:00Z while pinning Stage 1 events to today."""
    self.assertTrue(
        hasattr(mqb, "compute_ecg_search_window"),
        "compute_ecg_search_window must be exported by multistage_query_builder",
    )
    fn = mqb.compute_ecg_search_window

    # Request starting today (2026-10-28T00:00:00Z .. 2026-10-28T15:00:00Z)
    w_today = fn("2026-10-28T00:00:00Z", "2026-10-28T15:00:00Z", event_alias="$net")
    self.assertEqual(w_today["effective_start_time"], "2026-10-26T00:00:00Z")
    self.assertEqual(w_today["effective_end_time"], "2026-10-28T15:00:00Z")
    self.assertTrue(w_today["anchored_to_d_minus_2"])
    self.assertIn("$net.metadata.event_timestamp.seconds >=", w_today["ecg_event_time_filter"])
    self.assertIn("$net.metadata.event_timestamp.seconds <", w_today["ecg_event_time_filter"])

    # Router renders identical query & effective search window whether called starting today
    # vs anchored at D-2 with the same target event window!
    router = MultiStageTemplateRouter()
    q_today = router.build_query(
        "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
        tier="BALANCED",
        start_time="2026-10-28T00:00:00Z",
        end_time="2026-10-28T15:00:00Z",
    )
    q_d2_pinned = router.build_query(
        "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
        tier="BALANCED",
        start_time="2026-10-26T00:00:00Z",
        end_time="2026-10-28T15:00:00Z",
        ecg_event_time_filter=w_today["ecg_event_time_filter"],
    )
    self.assertEqual(q_today, q_d2_pinned)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_today)["valid"])

    # Historical window already starting <= D-2 needs no Stage 1 pin filter
    w_hist = fn("2026-10-14T00:00:00Z", "2026-10-28T00:00:00Z", event_alias="$net")
    self.assertEqual(w_hist["effective_start_time"], "2026-10-14T00:00:00Z")
    self.assertFalse(w_hist["anchored_to_d_minus_2"])
    self.assertEqual(w_hist["ecg_event_time_filter"], "")

  def test_day0_companion_query_builds_valid_graph_free_multistage_hunt(self):
    """build_day0_companion_query emits a compilable raw UDM companion query without DERIVED_CONTEXT joins."""
    self.assertTrue(
        hasattr(mqb, "build_day0_companion_query"),
        "build_day0_companion_query must be exported by multistage_query_builder",
    )
    for arch in ECG_ARCHETYPES:
      with self.subTest(archetype=arch):
        q_day0 = mqb.build_day0_companion_query(arch, tier="BALANCED", entity_type="IP")
        self.assertNotIn("DERIVED_CONTEXT", q_day0)
        self.assertNotIn("GLOBAL_CONTEXT", q_day0)
        self.assertNotIn(".graph.", q_day0)
        errs = [e for e in validate_multistage_syntax(q_day0) if not e.startswith("MISSING METHODOLOGY HEADER")]
        self.assertEqual(errs, [])
        self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_day0)["valid"])

  def test_triage_report_discloses_ecg_inner_join_day0_and_first_seen_zero(self):
    """format_triage_report discloses ECG inner-join filter, Day-0 companion, and first_seen_time = 0."""
    router = MultiStageTemplateRouter()
    q_ecg = router.build_query("DERIVED_CONTEXT_DOMAIN_PREVALENCE", tier="BALANCED")

    report_zero = format_triage_report(
        "Rare Domain Egress Hunt",
        _ecg_result_payload(first_seen_val=0),
        query_text=q_ecg,
    )
    self.assertIn("inner-join filter", report_zero)
    self.assertIn("Day-0", report_zero)
    self.assertIn(
        "<7d ECG novelty disabled because first_seen_time = 0; use secops-risk-metrics-multistage metrics.* first_seen novelty instead.",
        report_zero,
    )

    # When first_seen > 0, inner-join disclosure still appears, but first_seen_time = 0 warning does not
    report_nonzero = format_triage_report(
        "Rare Domain Egress Hunt",
        _ecg_result_payload(first_seen_val=1793000000),
        query_text=q_ecg,
    )
    self.assertIn("inner-join filter", report_nonzero)
    self.assertNotIn("first_seen_time = 0", report_nonzero)

    # Even on 0-row ECG verdicts, disclose the ECG inner-join filter and Day-0 companion query
    report_empty = format_triage_report("Rare Domain Egress Hunt", {}, query_text=q_ecg)
    self.assertIn("inner-join filter", report_empty)
    self.assertIn("Day-0", report_empty)

  def test_skill_md_documents_ecg_d_minus_2_inner_join_day0_and_first_seen_zero(self):
    """SKILL.md documents D-2 ECG anchoring, inner-join filter, Day-0 query, and first_seen_time = 0 fallback."""
    skill_text = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("D-2", skill_text)
    self.assertIn("inner-join filter", skill_text)
    self.assertIn("Day-0", skill_text)
    self.assertIn("first_seen_time = 0", skill_text)


if __name__ == "__main__":
  unittest.main()
