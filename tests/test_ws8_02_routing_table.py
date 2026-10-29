# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS8-02 contract tests: Canonical Cross-Skill Routing Table & Zero Ping-Pong."""

from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "scripts"))

import multistage_query_builder as mqb  # noqa: E402

START_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->"
END_TAG = "<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->"

RETIRED_TEMPLATES = (
    "fleet_prevalence_shield",
    "piecewise_cri",
    "hybrid_metric_orthogonal_space_2stage",
    "impossible_travel_geo_velocity_2stage",
    "hourly_temporal_zscore",
    "circadian_von_mises",
    "asymmetric_directional_z",
)


def _find_peer_repo(base_name: str) -> Path | None:
  parent = HERE.parent
  for candidate in (parent / f"{base_name}-WS8", parent / base_name):
    if candidate.exists():
      return candidate
  return None


def _extract_canonical_table(md_text: str) -> str:
  pattern = re.compile(
      re.escape(START_TAG) + r".*?" + re.escape(END_TAG),
      re.DOTALL,
  )
  matches = pattern.findall(md_text)
  if len(matches) != 1:
    raise AssertionError(
        f"Expected exactly 1 canonical routing table block, found {len(matches)}"
    )
  return matches[0]


class TestWS802CanonicalRoutingTable(unittest.TestCase):
  """Verifies byte-identical canonical routing table, ceilings, and zero B-E6 ping-pong."""

  def test_local_skill_md_has_canonical_routing_table_and_strict_ceilings(self):
    skill_md = (HERE / "SKILL.md").read_text(encoding="utf-8")
    raw_bytes = len(skill_md.encode("utf-8"))
    line_count = len(skill_md.splitlines())
    self.assertLessEqual(
        raw_bytes,
        28200,
        f"statistical-hunter SKILL.md must stay <= 28,200 bytes (found {raw_bytes})",
    )
    self.assertLessEqual(
        line_count,
        265,
        f"statistical-hunter SKILL.md must stay <= 265 lines (found {line_count})",
    )

    block = _extract_canonical_table(skill_md)
    idx_1 = block.find("1. `secops-statistical-hunter`")
    idx_2 = block.find("2. `secops-risk-metrics-multistage`")
    idx_3 = block.find("3. Bilateral Co-Execution")
    idx_4 = block.find("4. `secops-detection-engineering`")
    self.assertGreater(idx_1, 0, "Missing Precedence 1 row in canonical table")
    self.assertGreater(idx_2, idx_1, "Precedence 2 must follow Precedence 1")
    self.assertGreater(idx_3, idx_2, "Precedence 3 must follow Precedence 2")
    self.assertGreater(idx_4, idx_3, "Precedence 4 must follow Precedence 3")

    self.assertTrue(
        hasattr(mqb, "CANONICAL_ROUTING_TABLE_MD"),
        "multistage_query_builder missing CANONICAL_ROUTING_TABLE_MD",
    )
    self.assertEqual(
        block.encode("utf-8"),
        mqb.CANONICAL_ROUTING_TABLE_MD.encode("utf-8"),
        "SKILL.md canonical routing table drifted from CANONICAL_ROUTING_TABLE_MD",
    )

    for retired in RETIRED_TEMPLATES:
      self.assertNotIn(retired, block)

  def test_cross_skill_routing_table_byte_for_byte_parity(self):
    rm_root = _find_peer_repo("secops-risk-metrics-multistage")
    if rm_root is None:
      self.skipTest("secops-risk-metrics-multistage sibling repo not checked out")

    sh_block = _extract_canonical_table(
        (HERE / "SKILL.md").read_text(encoding="utf-8")
    )
    rm_block = _extract_canonical_table(
        (rm_root / "SKILL.md").read_text(encoding="utf-8")
    )
    self.assertEqual(
        sh_block.encode("utf-8"),
        rm_block.encode("utf-8"),
        "Canonical routing table drifted between statistical-hunter and risk-metrics SKILL.md",
    )

  def test_canonical_routing_matrix_and_zero_retired_templates(self):
    self.assertTrue(
        hasattr(mqb, "CANONICAL_ROUTING_MATRIX"),
        "multistage_query_builder missing CANONICAL_ROUTING_MATRIX",
    )
    matrix = mqb.CANONICAL_ROUTING_MATRIX
    self.assertEqual([entry["precedence"] for entry in matrix], [1, 2, 3, 4])

    sh_pipelines = {p.name for p in (HERE / "templates" / "pipelines").glob("*.yl2")}
    rm_root = _find_peer_repo("secops-risk-metrics-multistage")
    rm_pipelines = (
        {p.name for p in (rm_root / "templates" / "pipelines").glob("*.yl2")}
        if rm_root is not None
        else None
    )

    for entry in matrix:
      for tpl in entry.get("canonical_templates", ()):
        for retired in RETIRED_TEMPLATES:
          self.assertNotIn(retired, tpl)
        if entry["precedence"] == 1:
          self.assertIn(tpl, sh_pipelines)
        elif entry["precedence"] == 2 and rm_pipelines is not None:
          self.assertIn(tpl, rm_pipelines)

  def test_precedence_1_micro_prompts_never_ping_pong_with_ueba_or_30d(self):
    micro_prompts = [
        "Use UEBA to detect C2 beaconing jitter",
        "Detect off-hours circadian login anomalies by hour of day using UEBA",
        "Run MAD on raw DNS query string length",
        "Detect obfuscated PowerShell command lines with Shannon character entropy",
        "Use UEBA to detect Markov 2-gram rare parent-child process transitions over 30 days",
        "Hunt intraday EWMA burst velocity using UEBA",
        "Detect Zipfian rare process execution and producer-consumer byte ratio inversion with UEBA",
        "Use UEBA to hunt sub-hour Fano password spray bursts",
        "Use UEBA to run MAD on raw DNS query string length",
    ]
    for prompt in micro_prompts:
      rec = mqb.check_routing_recommendation(prompt)
      self.assertIsNone(
          rec,
          f"Precedence 1 micro-only prompt must return None (got {rec}): {prompt}",
      )

  def test_precedence_2_and_4_prompts_route_with_canonical_templates(self):
    rm_root = _find_peer_repo("secops-risk-metrics-multistage")
    rm_pipelines = (
        {p.name for p in (rm_root / "templates" / "pipelines").glob("*.yl2")}
        if rm_root is not None
        else None
    )

    macro_cases = [
        (
            "Run 30-day login baseline for charles.hardy",
            "metrics.auth_attempts_total",
            "standard_z_score_2stage.yl2",
        ),
        (
            "Compare user against IT department peer cohort",
            "metrics.auth_attempts_total",
            "dual_baseline_delta_z_3stage.yl2",
        ),
        (
            "Run 360 entity health check and risk score",
            "graph.risk_score",
            "radar_360_decoupled_sector.yl2",
        ),
        (
            "Detect 14-day longitudinal CUSUM exfiltration drift",
            "metrics.network_bytes_outbound",
            "longitudinal_cusum_series_3stage.yl2",
        ),
        (
            "Run 30-day MAD baseline on metrics.network_bytes_outbound",
            "metrics.network_bytes_outbound",
            "mad_robust_z_4stage.yl2",
        ),
        (
            "Evaluate 30-day metrics.auth_attempts_total first_seen novelty",
            "metrics.auth_attempts_total",
            "first_seen_novelty_2stage.yl2",
        ),
        (
            "Evaluate 30-day DNS query baseline for host-alpha",
            "metrics.dns_queries_total",
            "standard_z_score_2stage.yl2",
        ),
    ]
    for prompt, exp_metric, exp_pipeline in macro_cases:
      rec = mqb.check_routing_recommendation(prompt)
      self.assertIsNotNone(rec, f"Expected Risk Metrics routing for: {prompt}")
      self.assertTrue(rec["should_route"])
      self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
      self.assertEqual(rec["recommended_metric"], exp_metric)
      self.assertEqual(rec["recommended_pipeline"], exp_pipeline)
      for retired in RETIRED_TEMPLATES:
        self.assertNotIn(retired, rec["recommended_pipeline"])
      if rm_pipelines is not None:
        self.assertIn(rec["recommended_pipeline"], rm_pipelines)

    rule_rec = mqb.check_routing_recommendation(
        "Author and deploy a detection rule using create_rule for failed logins"
    )
    self.assertIsNotNone(rule_rec)
    self.assertEqual(rule_rec["target_skill"], "secops-detection-engineering")


if __name__ == "__main__":
  unittest.main()
