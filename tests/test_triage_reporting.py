"""Unit tests for the 5-Section CommonMark Triage Report Formatter & Evidence Pillars."""

import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import format_triage_report


class TestTriageReporting(unittest.TestCase):

  def setUp(self):
    self.sample_stats_payload = {
        "stats": {
            "results": [
                {
                    "column": "host",
                    "values": [{"value": {"stringVal": "host-alpha-prod"}}]
                },
                {
                    "column": "TIME_BUCKET",
                    "values": [{"value": {"stringVal": "2026-08-24T08:00:00Z"}}]
                },
                {
                    "column": "observation_count",
                    "values": [{"value": {"int64Val": 850}}]
                },
                {
                    "column": "baseline_active_samples",
                    "values": [{"value": {"int64Val": 168}}]
                },
                {
                    "column": "baseline_mean",
                    "values": [{"value": {"doubleVal": 250.0}}]
                },
                {
                    "column": "baseline_dispersion",
                    "values": [{"value": {"doubleVal": 35.0}}]
                },
                {
                    "column": "fleet_prevalence",
                    "values": [{"value": {"int64Val": 1}}]
                },
                {
                    "column": "distinct_binaries",
                    "values": [{"value": {"int64Val": 42}}]
                },
                {
                    "column": "z_score",
                    "values": [{"value": {"doubleVal": 17.14}}]
                }
            ]
        }
    }

  def test_report_contains_all_five_sections(self):
    report = format_triage_report("Process Execution Surges", self.sample_stats_payload, fleet_size=5000)

    # Section 1: Executive Headline & Normal Envelope
    self.assertIn("### ⚡ Statistical Outlier Report: Process Execution Surges", report)
    self.assertIn("Normal Baseline Envelope", report)
    self.assertIn("Fleet Scaling / Multiple-Comparison Adjustment", report)

    # Section 2: Ranked Outlier Summary Table
    self.assertIn("#### 📊 Ranked Outlier Summary", report)
    self.assertIn("| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |", report)
    self.assertIn("`host-alpha-prod`", report)
    self.assertIn("🚨 **[CRITICAL OUTLIER]**", report)
    self.assertIn("[CRI: 100]", report)

    # Section 3: Top Outlier Spotlight with 6 Evidence Pillars
    self.assertIn("#### 🔍 Top Outlier Spotlight: `host-alpha-prod`", report)
    self.assertIn("Calibrated Risk Index", report)
    self.assertIn("##### 🗣️ What Happened & Why It Matters (In Plain English)", report)
    self.assertIn("##### 🏛️ Forensic Evidence Breakdown", report)
    self.assertIn("**1. Activity Spike**", report)
    self.assertIn("**2. Baseline History**", report)
    self.assertIn("**3. Typical Normal Level**", report)
    self.assertIn("**4. Normal Daily Spread**", report)
    self.assertIn("**5. Company-Wide Breadth**", report)
    self.assertIn("**6. Variety of Programs**", report)
    self.assertIn("🔴 Potential Attack Scenarios", report)
    self.assertIn("🟢 Legitimate Business Explanations", report)
    self.assertIn("🎯 Step-by-Step SOC Action Plan (No Math Required)", report)

    # Section 4: Chronicle UI Manual Pivot (Triage Reference Only)
    self.assertIn("#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)", report)
    self.assertIn("principal.hostname = \"host-alpha-prod\"", report)

    # Section 5: Collapsible Technical Appendix
    self.assertIn("<details>", report)
    self.assertIn("<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>", report)
    self.assertIn("##### 📐 Mathematical Model & Formulaic Derivations", report)
    self.assertIn("##### 🌐 Multiple-Comparison Fleet Correction", report)
    self.assertIn("##### 🛡️ Statistical Validity & Safeguard Verification", report)
    self.assertIn("</details>", report)

  def test_insufficient_baseline_evidence_handling(self):
    # Low active samples (N = 3) -> should trigger INSUFFICIENT BASELINE tier
    sparse_payload = dict(self.sample_stats_payload)
    sparse_payload["stats"]["results"][3]["values"][0]["value"]["int64Val"] = 3
    report = format_triage_report("Process Surges", sparse_payload)
    self.assertIn("⚪ **INSUFFICIENT BASELINE**", report)


if __name__ == "__main__":
  unittest.main()
