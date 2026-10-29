"""Regression tests for WS5-RENAMES: Honest In-Query Labels (D6 G5), token_field Slot & Multicast Exclusions."""

import os
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import (
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    evaluate_confidence_tier,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestWS5HonestInQueryRenames(unittest.TestCase):
  """Verifies WS5-RENAMES honest labels, LOO burst Z, token_field parameterization, and CIDR exclusions."""

  def test_ewma_burst_velocity_renamed_to_burst_z_with_loo_and_poisson_floor(self):
    """BURST_Z_SCREEN preserves the stateless LOO 'burst Z' screen while EWMA_BURST_VELOCITY emits the WS6-02 ungated extractor."""
    router = MultiStageTemplateRouter()
    for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
      for entity_type in ("host", "user", "ip"):
        with self.subTest(tier=tier, entity_type=entity_type):
          q_screen = router.build_query("BURST_Z_SCREEN", tier=tier, entity_type=entity_type, local_execution_available=False)
          gate_screen = QueryIntegrityGate.verify_pre_dispatch(q_screen)
          self.assertTrue(gate_screen["valid"], f"BURST_Z_SCREEN pre-dispatch failed ({tier}, {entity_type}): {gate_screen['errors']}")
          self.assertIn("burst Z", q_screen)
          self.assertNotIn("0.3 *", q_screen)
          self.assertNotIn("0.7 *", q_screen)
          self.assertIn("$window_events_sq", q_screen)
          self.assertIn("max($entity_historical_stats.active_windows) - 1", q_screen)
          self.assertIn("math.sqrt(", q_screen)
          self.assertRegex(q_screen, r"match:\s*\n\s*\$entity,\s*\$ws\s+by\s+")

          q_ewma = router.build_query("EWMA_BURST_VELOCITY", tier=tier, entity_type=entity_type)
          gate_ewma = QueryIntegrityGate.verify_pre_dispatch(q_ewma)
          self.assertTrue(gate_ewma["valid"], f"EWMA_BURST_VELOCITY pre-dispatch failed ({tier}, {entity_type}): {gate_ewma['errors']}")
          self.assertNotIn("0.3 *", q_ewma)
          self.assertNotIn("0.7 *", q_ewma)
          self.assertIn("stage entity_hourly", q_ewma)
          self.assertIn("stage entity_prefilter", q_ewma)
          self.assertRegex(q_ewma, r"match:\s*\n\s*\$entity,\s*\$ws\s+by\s+")

  def test_shannon_entropy_renamed_to_long_string_screen_with_token_field_slot(self):
    """LONG_STRING_SCREEN preserves the stateless 'long-string screen' while SHANNON_ENTROPY_CHARACTER emits the WS6-03 ungated token extractor with {{token_field}}."""
    router = MultiStageTemplateRouter()
    q_screen = router.build_query("LONG_STRING_SCREEN", tier="BALANCED", local_execution_available=False)
    gate_screen = QueryIntegrityGate.verify_pre_dispatch(q_screen)
    self.assertTrue(gate_screen["valid"], f"LONG_STRING_SCREEN pre-dispatch failed: {gate_screen['errors']}")
    self.assertIn("long-string screen", q_screen.lower())
    self.assertIn("$token = principal.process.command_line", q_screen)
    self.assertRegex(q_screen, r"match:\s*\n\s*\$entity,\s*\$token,\s*\$ws\s+by\s+")

    q_default = router.build_query("SHANNON_ENTROPY_CHARACTER", tier="BALANCED")
    gate_default = QueryIntegrityGate.verify_pre_dispatch(q_default)
    self.assertTrue(gate_default["valid"], f"Default pre-dispatch failed: {gate_default['errors']}")
    self.assertIn("stage token_stats", q_default)
    self.assertIn("$token = principal.process.command_line", q_default)
    self.assertIn("array_distinct($entity)", q_default)

    # Custom token_field for DNS / HTTP / PowerShell hunting on BOTH extractor and screen
    for arch in ("SHANNON_ENTROPY_CHARACTER", "LONG_STRING_SCREEN"):
      q_dns = router.build_query(
          arch,
          tier="BALANCED",
          event_type="NETWORK_DNS",
          entity_type="ip",
          token_field="network.dns.questions.name",
      )
      gate_dns = QueryIntegrityGate.verify_pre_dispatch(q_dns)
      self.assertTrue(gate_dns["valid"], f"{arch} DNS token_field pre-dispatch failed: {gate_dns['errors']}")
      self.assertIn('metadata.event_type = "NETWORK_DNS"', q_dns)
      self.assertIn("$token = network.dns.questions.name", q_dns)
      self.assertNotIn("target.process.command_line", q_dns)

  def test_c2_beaconing_jitter_renamed_to_flow_gap_ratio_and_excludes_multicast_link_local(self):
    """FLOW_GAP_RATIO_SCREEN preserves 'flow-gap ratio' while C2_BEACONING_JITTER emits the WS6-04 array_distinct($ts) extractor; both exclude multicast/broadcast/link-local."""
    router = MultiStageTemplateRouter()
    required_cidrs = (
        "224.0.0.0/4",
        "169.254.0.0/16",
        "255.255.255.255/32",
        "fe80::/10",
        "ff00::/8",
    )
    for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
      for entity_type in ("host", "user", "ip"):
        with self.subTest(tier=tier, entity_type=entity_type):
          q_screen = router.build_query("FLOW_GAP_RATIO_SCREEN", tier=tier, entity_type=entity_type, local_execution_available=False)
          gate_screen = QueryIntegrityGate.verify_pre_dispatch(q_screen)
          self.assertTrue(gate_screen["valid"], f"FLOW_GAP_RATIO_SCREEN pre-dispatch failed ({tier}, {entity_type}): {gate_screen['errors']}")
          self.assertIn("flow-gap ratio", q_screen.lower())
          for cidr in required_cidrs:
            self.assertIn(
                f'not net.ip_in_range_cidr($dst_ip, "{cidr}")',
                q_screen,
                f"Missing CIDR exclusion {cidr} in FLOW_GAP_RATIO_SCREEN",
            )
          self.assertRegex(q_screen, r"match:\s*\n\s*\$src_ip,\s*\$dst_ip\b")
          self.assertNotIn("count(metadata.id) + 1.0", q_screen)
          self.assertNotIn("$safe_mean + 1.0", q_screen)

          q_c2 = router.build_query("C2_BEACONING_JITTER", tier=tier, entity_type=entity_type)
          gate_c2 = QueryIntegrityGate.verify_pre_dispatch(q_c2)
          self.assertTrue(gate_c2["valid"], f"C2_BEACONING_JITTER pre-dispatch failed ({tier}, {entity_type}): {gate_c2['errors']}")
          self.assertIn("stage host_intervals", q_c2)
          self.assertIn("array_distinct($ts)", q_c2)
          for cidr in required_cidrs:
            self.assertIn(
                f'not net.ip_in_range_cidr($dst_ip, "{cidr}")',
                q_c2,
                f"Missing CIDR exclusion {cidr} in C2_BEACONING_JITTER",
            )
          self.assertRegex(q_c2, r"match:\s*\n\s*\$src_ip,\s*\$dst_ip,\s*\$ws\b")

    # Zero-dispersion clockwork flow-gap row (disp=0.0, cv=0.0) must NOT be marked INSUFFICIENT BASELINE
    badge, _ = evaluate_confidence_tier({
        "baseline_active_samples": 24,
        "observation_count": 48,
        "baseline_dispersion": 0.0,
        "fleet_prevalence": 1,
        "cv": 0.02,
    })
    self.assertNotIn("INSUFFICIENT BASELINE", badge)

  def test_skill_and_taxonomy_docs_disclose_honest_in_query_names(self):
    """SKILL.md and statistical-models-taxonomy.md carry the honest D6 G5 in-query names."""
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").lower()
    taxonomy_md = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8").lower()
    for phrase in ("burst z", "long-string screen", "flow-gap ratio"):
      self.assertIn(phrase, skill_md, f"SKILL.md missing honest label '{phrase}'")
      self.assertIn(phrase, taxonomy_md, f"statistical-models-taxonomy.md missing honest label '{phrase}'")


if __name__ == "__main__":
  unittest.main()
