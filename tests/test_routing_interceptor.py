# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for the Pre-Flight Routing Interceptor in secops-statistical-hunter."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from multistage_query_builder import check_routing_recommendation, format_routing_handoff_card


class TestRoutingInterceptor(unittest.TestCase):

  def test_route_http_user_agent_network_data_to_risk_metrics(self):
    """Network data to user-agent comparison must route to metrics.http_queries_total."""
    prompt = "I need a comparison of network data to user-agent strings to detect anomalies."
    rec = check_routing_recommendation(prompt)
    self.assertIsNotNone(rec, "Prompt should be recognized as a Risk Metrics routing candidate")
    self.assertTrue(rec["should_route"])
    self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec["recommended_metric"], "metrics.http_queries_total")
    self.assertEqual(rec["recommended_pipeline"], "hybrid_metric_fleet_prevalence_2stage.yl2")
    self.assertEqual(rec["target_dimension"], "network.http.user_agent")

  def test_route_auth_attempts_30d_baseline_to_risk_metrics(self):
    """Authentication baseline against 30-day typical behavior must route to metrics.auth_attempts_fail or metrics.auth_attempts_total."""
    prompt_fail = "Detect users with failed logins surging above their 30-day normal baseline."
    rec_fail = check_routing_recommendation(prompt_fail)
    self.assertIsNotNone(rec_fail)
    self.assertEqual(rec_fail["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec_fail["recommended_metric"], "metrics.auth_attempts_fail")
    self.assertEqual(rec_fail["recommended_pipeline"], "standard_z_score_2stage.yl2")

    prompt_total = "Detect users with total login volume surging above their 30-day normal baseline."
    rec_total = check_routing_recommendation(prompt_total)
    self.assertIsNotNone(rec_total)
    self.assertEqual(rec_total["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec_total["recommended_metric"], "metrics.auth_attempts_total")
    self.assertEqual(rec_total["recommended_pipeline"], "standard_z_score_2stage.yl2")

  def test_negative_control_14d_raw_mad_and_24h_fano_stay_local(self):
    """14-day raw-field MAD and 24-hour Fano password spray hunts must stay in secops-statistical-hunter."""
    local_prompts = [
        "Run a 14-day standalone MAD hunt over raw network.sent_bytes to detect exfiltration outliers.",
        "Hunt for 24-hour Fano factor password spray bursts on raw USER_LOGIN events.",
    ]
    for p in local_prompts:
      self.assertIsNone(
          check_routing_recommendation(p),
          f"Expected negative control prompt to stay in secops-statistical-hunter: {p}",
      )

  def test_route_network_bytes_baseline_to_risk_metrics(self):
    """Outbound network bytes vs 30d typical behavior must route to metrics.network_bytes_outbound."""
    prompt = "Find hosts with outbound network bytes surging past their 30-day baseline."
    rec = check_routing_recommendation(prompt)
    self.assertIsNotNone(rec)
    self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec["recommended_metric"], "metrics.network_bytes_outbound")

  def test_route_peer_cohort_to_risk_metrics(self):
    """Peer cohort or department comparison must route to Risk Metrics."""
    prompt = "Compare this user against their departmental peer group cohort."
    rec = check_routing_recommendation(prompt)
    self.assertIsNotNone(rec)
    self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec["recommended_pipeline"], "dual_baseline_delta_z_3stage.yl2")

  def test_route_risk_score_to_risk_metrics(self):
    """Entity risk score or 360 health check must route to graph.risk_score."""
    prompt = "Run an omnibus 360 health check on entity risk score."
    rec = check_routing_recommendation(prompt)
    self.assertIsNotNone(rec)
    self.assertEqual(rec["target_skill"], "secops-risk-metrics-multistage")
    self.assertEqual(rec["recommended_metric"], "graph.risk_score")

  def test_retain_ad_hoc_statistical_hunter_tasks(self):
    """Raw ad-hoc statistical outlier hunting prompts must remain in statistical hunter (return None)."""
    raw_prompts = [
        "Hunt for C2 beaconing with jitter over the last 24 hours.",
        "Calculate inline MAD on DNS queries across the weekend.",
        "Find password sprays using Poisson burst clustering and Fano factor.",
        "Detect rare admin tool execution surges on quiet endpoints using Poisson deviance.",
        "Find single-stage rare user agents appearing on at most 2 machines.",
    ]
    for p in raw_prompts:
      rec = check_routing_recommendation(p)
      self.assertIsNone(rec, f"Prompt '{p}' should remain in statistical hunter, got routing: {rec}")

  def test_format_routing_handoff_card_content(self):
    """Handoff card must contain Markdown alert formatting and target skill action."""
    rec = {
        "should_route": True,
        "target_skill": "secops-risk-metrics-multistage",
        "recommended_metric": "metrics.http_queries_total",
        "recommended_pipeline": "hybrid_metric_fleet_prevalence_2stage.yl2",
        "target_dimension": "network.http.user_agent",
        "justification": "Web HTTP request volume across user-agent strings is pre-computed.",
    }
    card = format_routing_handoff_card(rec)
    self.assertIn("### 🔄 Skill Handoff Card — Skill Delegation: Route to `secops-risk-metrics-multistage`", card)
    self.assertIn("metrics.http_queries_total", card)
    self.assertIn("hybrid_metric_fleet_prevalence_2stage.yl2", card)
    self.assertIn("network.http.user_agent", card)
    self.assertIn("Delegation Action", card)


if __name__ == "__main__":
  unittest.main()
