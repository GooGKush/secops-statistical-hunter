# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit and regression tests for Entity Context Graph (GLOBAL_CONTEXT and DERIVED_CONTEXT) multi-stage pipelines."""

import os
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from multistage_query_builder import (
    validate_multistage_syntax,
    check_ecg_limits,
    MultiStageTemplateRouter,
    HandoffEndpoint,
)


class TestGlobalContextSyntax(unittest.TestCase):
  """Validates syntax, AST compliance, and execution contracts for ECG pipelines."""

  def setUp(self):
    self.router = MultiStageTemplateRouter()

  def test_global_threat_intel_pipeline_compiles_cleanly(self):
    """GLOBAL_THREAT_INTEL template must compile without syntax or ECG errors."""
    query = self.router.build_query("GLOBAL_THREAT_INTEL")
    self.assertIn("GLOBAL_CONTEXT", query)
    self.assertIn("WHOIS", query)
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Syntax errors in GLOBAL_THREAT_INTEL: {errors}")
    ecg_errors = check_ecg_limits(query)
    self.assertEqual(ecg_errors, [], f"ECG limit errors in GLOBAL_THREAT_INTEL: {ecg_errors}")

  def test_derived_context_prevalence_pipeline_compiles_cleanly(self):
    """DERIVED_CONTEXT_PREVALENCE template must compile without syntax or ECG errors."""
    query = self.router.build_query("DERIVED_CONTEXT_PREVALENCE")
    self.assertIn("DERIVED_CONTEXT", query)
    self.assertIn("first_seen_time", query)
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Syntax errors in DERIVED_CONTEXT_PREVALENCE: {errors}")
    ecg_errors = check_ecg_limits(query)
    self.assertEqual(ecg_errors, [], f"ECG limit errors in DERIVED_CONTEXT_PREVALENCE: {ecg_errors}")

  def test_derived_context_file_prevalence_compiles_cleanly(self):
    """DERIVED_CONTEXT_FILE_PREVALENCE template must compile without syntax or ECG errors."""
    query = self.router.build_query("DERIVED_CONTEXT_FILE_PREVALENCE")
    self.assertIn("DERIVED_CONTEXT", query)
    self.assertIn("prevalence.day_count", query)
    self.assertIn("prevalence.rolling_max", query)
    self.assertIn("first_seen_time", query)
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Syntax errors in DERIVED_CONTEXT_FILE_PREVALENCE: {errors}")
    ecg_errors = check_ecg_limits(query)
    self.assertEqual(ecg_errors, [], f"ECG limit errors in DERIVED_CONTEXT_FILE_PREVALENCE: {ecg_errors}")

  def test_derived_context_domain_prevalence_compiles_cleanly(self):
    """DERIVED_CONTEXT_DOMAIN_PREVALENCE template must compile without syntax or ECG errors."""
    query = self.router.build_query("DERIVED_CONTEXT_DOMAIN_PREVALENCE")
    self.assertIn("DERIVED_CONTEXT", query)
    self.assertIn("prevalence.day_count", query)
    self.assertIn("prevalence.rolling_max", query)
    self.assertIn("first_seen_time", query)
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Syntax errors in DERIVED_CONTEXT_DOMAIN_PREVALENCE: {errors}")
    ecg_errors = check_ecg_limits(query)
    self.assertEqual(ecg_errors, [], f"ECG limit errors in DERIVED_CONTEXT_DOMAIN_PREVALENCE: {ecg_errors}")

  def test_ecg_limit_enforced_single_alias_per_stage(self):
    """Compiler rejects multiple Entity Context Graph aliases in a single stage."""
    query_with_double_ecg = """
    // Goal: Test multiple ECG rejection
    // Statistical Model: ECG Violator
    stage violator {
      $net.metadata.event_type = "NETWORK_CONNECTION"
      $domain = $net.target.hostname
      $whois.graph.entity.domain.name = $domain
      $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
      $gcti.graph.entity.hostname = $domain
      $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"
      match: $domain by 1h
      outcome: $cnt = count($net.metadata.id)
    }
    $domain = $violator.domain
    match: $domain by 1h
    outcome: $total = max($violator.cnt)
    condition: $total >= 1
    """
    ecg_errors = check_ecg_limits(query_with_double_ecg)
    self.assertTrue(any("ECG LIMIT EXCEEDED" in e for e in ecg_errors),
                    f"Expected ECG LIMIT EXCEEDED, got: {ecg_errors}")

  def test_handoff_ingestion_global_threat_intel(self):
    """HandoffEndpoint must ingest GLOBAL_THREAT_INTEL and return ACK accepted."""
    payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "GLOBAL_THREAT_INTEL",
        "target_entity": {"type": "HOSTNAME", "value": "gateway-proxy"},
        "search_window": {"lookback": "24h"},
    }
    res = HandoffEndpoint.ingest(payload)
    self.assertEqual(res.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res.get("action"), "STEP_OUT_CONFIRMED")
    self.assertIn("GLOBAL_CONTEXT", res.get("compiled_query", ""))

  def test_handoff_ingestion_derived_context(self):
    """HandoffEndpoint must ingest DERIVED_CONTEXT_PREVALENCE and return ACK accepted."""
    payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DERIVED_CONTEXT_PREVALENCE",
        "target_entity": {"type": "USER", "value": "admin_svc"},
        "search_window": {"lookback": "7d"},
    }
    res = HandoffEndpoint.ingest(payload)
    self.assertEqual(res.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res.get("action"), "STEP_OUT_CONFIRMED")
    self.assertIn("DERIVED_CONTEXT", res.get("compiled_query", ""))

  def test_handoff_ingestion_file_prevalence(self):
    """HandoffEndpoint must ingest DERIVED_CONTEXT_FILE_PREVALENCE and return ACK accepted."""
    payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DERIVED_CONTEXT_FILE_PREVALENCE",
        "target_entity": {"type": "FILE", "value": "updater.exe"},
        "search_window": {"lookback": "24h"},
    }
    res = HandoffEndpoint.ingest(payload)
    self.assertEqual(res.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res.get("action"), "STEP_OUT_CONFIRMED")
    self.assertIn("prevalence.day_count", res.get("compiled_query", ""))

  def test_handoff_ingestion_domain_prevalence(self):
    """HandoffEndpoint must ingest DERIVED_CONTEXT_DOMAIN_PREVALENCE and return ACK accepted."""
    payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
        "target_entity": {"type": "DOMAIN_NAME", "value": "sync-tunnel.xyz"},
        "search_window": {"lookback": "24h"},
    }
    res = HandoffEndpoint.ingest(payload)
    self.assertEqual(res.get("status"), "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res.get("action"), "STEP_OUT_CONFIRMED")
    self.assertIn("prevalence.day_count", res.get("compiled_query", ""))

  def test_safe_divisor_present_in_ecg_templates(self):
    """All ECG templates must implement positive divisor protection."""
    ecg_models = [
        "GLOBAL_THREAT_INTEL",
        "DERIVED_CONTEXT_PREVALENCE",
        "DERIVED_CONTEXT_FILE_PREVALENCE",
        "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
    ]
    for model in ecg_models:
      query = self.router.build_query(model)
      self.assertIn("if(", query, f"Model {model} must contain if() divisor protection")
      self.assertTrue(
          "$safe_sd = if(" in query or "if($sd" in query or "if($hist_sd" in query,
          f"Model {model} must protect denominator with if()"
      )

  def test_ecg_pipeline_conforms_to_3_named_stages_limit(self):
    """ECG pipelines must conform to strictly 1-3 named stages plus unwrapped root."""
    ecg_models = [
        "GLOBAL_THREAT_INTEL",
        "DERIVED_CONTEXT_PREVALENCE",
        "DERIVED_CONTEXT_FILE_PREVALENCE",
        "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
    ]
    for model in ecg_models:
      query = self.router.build_query(model)
      stages = re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", query)
      self.assertEqual(len(stages), 3, f"Expected exactly 3 named stages for {model}, got {len(stages)}")


if __name__ == "__main__":
  unittest.main()
