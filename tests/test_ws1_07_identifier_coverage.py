"""Regression tests for WS1-07 (D4, Micro Side): Per-Tenant Identifier Coverage Probe & Router Choice."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
import multistage_query_builder as mqb
from multistage_query_builder import (
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    validate_multistage_syntax,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

NETWORK_TEMPLATES = (
    "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
    "GLOBAL_THREAT_INTEL_ENRICHMENT",
    "LOG_NORMAL_VOLUME_SURGE",
    "IQR_TUKEY_SKEW_FENCES",
    "C2_BEACONING_JITTER",
    "DUAL_BASELINE_DELTA_Z",
    "HYBRID_ENTROPY_CONCENTRATION",
    "PRODUCER_CONSUMER_RATIO_INVERSION",
)


def _columnar_probe_payload(total_events: int, hostname_events: int, ip_events: int, event_type: str = "NETWORK_DNS"):
  return {
      "stats": {
          "results": [
              {"column": "et", "values": [{"value": {"stringVal": event_type}}]},
              {"column": "total_events", "values": [{"value": {"int64Val": str(total_events)}}]},
              {"column": "hostname_events", "values": [{"value": {"int64Val": str(hostname_events)}}]},
              {"column": "ip_events", "values": [{"value": {"int64Val": str(ip_events)}}]},
          ]
      }
  }


class TestWS107IdentifierCoverage(unittest.TestCase):
  """Verifies D4 / WS1-07 per-tenant identifier coverage probe, selector, and router wiring."""

  def test_build_identifier_coverage_probe_syntax_and_roles(self):
    """Probe query is a valid read-only single-stage YARA-L stats query for principal/target roles."""
    self.assertTrue(
        hasattr(mqb, "build_identifier_coverage_probe"),
        "build_identifier_coverage_probe must be exported by multistage_query_builder",
    )
    q_dns = mqb.build_identifier_coverage_probe(event_type="NETWORK_DNS", role="principal")
    self.assertIn('metadata.event_type = "NETWORK_DNS"', q_dns)
    self.assertIn("$total_events = count(metadata.id)", q_dns)
    self.assertIn('sum(if(principal.asset.hostname != "", 1, 0))', q_dns)
    self.assertIn('sum(if(principal.ip != "", 1, 0))', q_dns)
    errs = [e for e in validate_multistage_syntax(q_dns) if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(errs, [])

    q_target = mqb.build_identifier_coverage_probe(event_type="NETWORK_HTTP", role="target")
    self.assertIn('metadata.event_type = "NETWORK_HTTP"', q_target)
    self.assertIn('sum(if(target.asset.hostname != "", 1, 0))', q_target)
    self.assertIn('sum(if(target.ip != "", 1, 0))', q_target)

    with self.assertRaises(ValueError):
      mqb.build_identifier_coverage_probe(event_type="", role="principal")
    with self.assertRaises(ValueError):
      mqb.build_identifier_coverage_probe(event_type="NETWORK_DNS", role="invalid_role")

  def test_select_identifier_from_coverage_empirical_gus_sdl_and_edr_tenants(self):
    """Selector chooses principal.ip when IP dominates (<20% hostname) and hostname when >=20%."""
    self.assertTrue(
        hasattr(mqb, "select_identifier_from_coverage"),
        "select_identifier_from_coverage must be exported by multistage_query_builder",
    )
    select_fn = mqb.select_identifier_from_coverage

    # Empirical gus-sdl DNS (total=582744, hostname=164 [0.028%], ip=582585 [99.97%]) -> principal.ip
    dns_res = select_fn(_columnar_probe_payload(582744, 164, 582585, "NETWORK_DNS"))
    self.assertEqual(dns_res["selected_field"], "principal.ip")
    self.assertEqual(dns_res["entity_type"], "ip")
    self.assertLess(dns_res["hostname_coverage"], 0.01)
    self.assertGreater(dns_res["ip_coverage"], 0.99)
    self.assertIn("DERIVED_CONTEXT", dns_res["join_guidance"])
    self.assertIn("ASSET", dns_res["join_guidance"])

    # Empirical gus-sdl HTTP (total=123467, hostname=628, ip=122839) -> principal.ip
    http_res = select_fn(_columnar_probe_payload(123467, 628, 122839, "NETWORK_HTTP"))
    self.assertEqual(http_res["selected_field"], "principal.ip")

    # Empirical gus-sdl NETWORK_CONNECTION (total=420290, hostname=3223, ip=420290) -> principal.ip
    net_res = select_fn(_columnar_probe_payload(420290, 3223, 420290, "NETWORK_CONNECTION"))
    self.assertEqual(net_res["selected_field"], "principal.ip")

    # EDR-enriched tenant (>=20% hostname coverage: 8500 / 10000 = 85%) -> principal.asset.hostname
    edr_res = select_fn(_columnar_probe_payload(10000, 8500, 10000, "NETWORK_DNS"))
    self.assertEqual(edr_res["selected_field"], "principal.asset.hostname")
    self.assertEqual(edr_res["entity_type"], "host")

    # Malformed input fails closed (G2)
    with self.assertRaises(ValueError):
      select_fn("not-a-dict")  # type: ignore[arg-type]
    with self.assertRaises(ValueError):
      select_fn({"unexpected": 123})

  def test_router_switches_all_8_network_templates_on_coverage_probe_and_ip_type(self):
    """All 8 network/DNS/HTTP templates switch to principal.ip when probe or entity_type='IP' is passed."""
    router = MultiStageTemplateRouter()
    sparse_hostname_payload = _columnar_probe_payload(582744, 164, 582585, "NETWORK_DNS")
    rich_hostname_payload = _columnar_probe_payload(10000, 8500, 10000, "NETWORK_DNS")

    for arch in NETWORK_TEMPLATES:
      with self.subTest(archetype=arch, mode="probe_ip_dominant"):
        q_probe = router.build_query(
            arch,
            tier="BALANCED",
            entity_type="HOST",
            identifier_coverage_payload=sparse_hostname_payload,
        )
        self.assertIn("principal.ip", q_probe, f"{arch} did not switch to principal.ip on sparse-hostname probe")
        self.assertNotIn("principal.asset.hostname", q_probe)
        self.assertTrue(
            QueryIntegrityGate.verify_pre_dispatch(q_probe)["valid"],
            f"Pre-dispatch failed for {arch}: {QueryIntegrityGate.verify_pre_dispatch(q_probe)['errors']}",
        )

      with self.subTest(archetype=arch, mode="entity_type_ip"):
        q_ip = router.build_query(arch, tier="BALANCED", entity_type="IP")
        self.assertIn("principal.ip", q_ip, f"{arch} did not switch to principal.ip on entity_type='IP'")
        self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_ip)["valid"])

      with self.subTest(archetype=arch, mode="probe_hostname_rich"):
        q_host = router.build_query(
            arch,
            tier="BALANCED",
            entity_type="HOST",
            identifier_coverage_payload=rich_hostname_payload,
        )
        self.assertIn("principal.asset.hostname", q_host)
        self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_host)["valid"])

      with self.subTest(archetype=arch, mode="preferred_entity_field"):
        q_pref = router.build_query(
            arch,
            tier="BALANCED",
            preferred_entity_field="principal.ip",
        )
        self.assertIn("principal.ip", q_pref)
        self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(q_pref)["valid"])

  def test_backward_compatible_host_defaults_when_no_probe_passed(self):
    """Calling build_query(..., entity_type='host') without a probe preserves backward-compatible fields."""
    router = MultiStageTemplateRouter()
    q_mad = router.build_query("MAD", event_type="NETWORK_DNS")
    self.assertIn("principal.hostname = $entity", q_mad)

    q_dom = router.build_query("DERIVED_CONTEXT_DOMAIN_PREVALENCE", entity_type="host")
    self.assertIn("$host = $net.principal.asset.hostname", q_dom)

    q_c2 = router.build_query("C2_BEACONING_JITTER", entity_type="host")
    self.assertIn("principal.asset.ip = $src_ip", q_c2)

  def test_skill_md_documents_d4_identifier_coverage_probe_and_asset_join_rule(self):
    """SKILL.md documents the D4 identifier coverage probe and DERIVED_CONTEXT ASSET join rule."""
    skill_text = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("build_identifier_coverage_probe", skill_text)
    self.assertIn("principal.ip", skill_text)
    self.assertIn("ASSET", skill_text)


if __name__ == "__main__":
  unittest.main()
