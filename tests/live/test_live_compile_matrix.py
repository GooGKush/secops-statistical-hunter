"""Unit and opt-in live tests for the WS0-03 Chronicle UDM Search compile harness."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from multistage_query_builder import QueryIntegrityGate  # pylint: disable=wrong-import-position
from tests.live.live_compile_harness import (  # pylint: disable=wrong-import-position
    DEFAULT_END_TIME,
    DEFAULT_START_TIME,
    ENTITY_TYPES,
    LiveCompileHarness,
    TIERS,
    main as harness_cli_main,
    make_adc_rest_search_fn,
    parse_udm_search_response,
)


class TestLiveCompileHarnessOffline(unittest.TestCase):
  """Offline unit tests for template discovery, matrix rendering, and result logging."""

  def setUp(self) -> None:
    self.harness = LiveCompileHarness(repo_root=REPO_ROOT)

  def test_discovers_all_24_pipelines_and_13_examples(self) -> None:
    pipelines = self.harness.discover_pipeline_templates()
    examples = self.harness.discover_example_files()

    self.assertEqual(len(pipelines), 24)
    self.assertEqual(len(examples), 13)
    self.assertEqual(len({arch for arch, _ in pipelines}), 24)
    self.assertEqual(len({fname for _, fname in pipelines}), 24)
    self.assertTrue(all(fname.endswith(".yl2") for _, fname in pipelines))
    self.assertTrue(all(ex.name.endswith(".yara") for ex in examples))

  def test_renders_full_matrix_cleanly(self) -> None:
    cases = self.harness.build_full_matrix(
        entity_types=ENTITY_TYPES,
        tiers=TIERS,
        window_hours=1.0,
        include_examples=True,
    )
    expected_total = 24 * len(ENTITY_TYPES) * len(TIERS) + 13
    self.assertEqual(len(cases), expected_total)

    unresolved_re = re.compile(r"\{\{[a-zA-Z0-9_]+\}\}")
    seen_case_ids = set()
    for case in cases:
      self.assertNotIn(case.case_id, seen_case_ids)
      seen_case_ids.add(case.case_id)
      self.assertTrue(case.query.strip(), f"Empty query in {case.case_id}")
      self.assertEqual(len(case.query_sha256), 64)
      self.assertEqual(
          unresolved_re.findall(case.query),
          [],
          f"Unresolved template placeholders in {case.case_id}",
      )
      qa = QueryIntegrityGate.verify_pre_dispatch(case.query)
      self.assertTrue(
          qa["valid"],
          f"Pre-dispatch QA failed for {case.case_id}: {qa['errors']}",
      )

  def test_smoke_matrix_covers_every_template_and_example(self) -> None:
    smoke = self.harness.build_smoke_matrix(tier="BALANCED", window_hours=1.0)
    self.assertEqual(len(smoke), 37)
    pipeline_cases = [c for c in smoke if c.source_kind == "pipeline"]
    example_cases = [c for c in smoke if c.source_kind == "example"]
    self.assertEqual(len(pipeline_cases), 24)
    self.assertEqual(len(example_cases), 13)

  def test_parse_udm_search_response_columnar_stats_and_errors(self) -> None:
    zero_row_stats = {
        "stats": {
            "results": [
                {"column": "entity"},
                {"column": "observation_count"},
                {"column": "z_score"},
            ],
            "hasJoin": True,
        }
    }
    self.assertEqual(parse_udm_search_response(zero_row_stats), (True, 0, None))

    three_row_stats = {
        "stats": {
            "results": [
                {
                    "column": "entity",
                    "values": [
                        {"value": {"stringVal": "h1"}},
                        {"value": {"stringVal": "h2"}},
                        {"value": {"stringVal": "h3"}},
                    ],
                },
                {
                    "column": "z_score",
                    "values": [
                        {"value": {"doubleVal": 5.1}},
                        {"value": {"doubleVal": 4.2}},
                        {"value": {"doubleVal": 3.3}},
                    ],
                },
            ],
            "hasJoin": True,
        }
    }
    self.assertEqual(parse_udm_search_response(three_row_stats), (True, 3, None))

    events_payload = {"events": [{"udm": {}}, {"udm": {}}]}
    self.assertEqual(parse_udm_search_response(events_payload), (True, 2, None))
    self.assertEqual(parse_udm_search_response({}), (True, 0, None))

    err_dict = {"error": {"code": 400, "message": "Request contains an invalid argument."}}
    ok, rows, err = parse_udm_search_response(err_dict)
    self.assertFalse(ok)
    self.assertEqual(rows, 0)
    self.assertIn("Request contains an invalid argument", err or "")

    err_str = "Encountered error in step execution: Request contains an invalid argument."
    ok2, rows2, err2 = parse_udm_search_response(err_str)
    self.assertFalse(ok2)
    self.assertEqual(rows2, 0)
    self.assertEqual(err2, err_str)

    ok3, rows3, err3 = parse_udm_search_response(RuntimeError("compiler timeout"))
    self.assertFalse(ok3)
    self.assertEqual(rows3, 0)
    self.assertEqual(err3, "compiler timeout")

  def test_run_cases_with_mock_search_fn_logs_compile_and_row_counts(self) -> None:
    smoke = self.harness.build_smoke_matrix(tier="BALANCED", window_hours=1.0)
    calls: List[Tuple[str, str]] = []

    def mock_search_fn(query: str, start_time: str, end_time: str) -> Dict[str, Any]:
      calls.append((start_time, end_time))
      if "$diversity_z <= -1.5" in query:
        return {"error": {"code": 400, "message": "Request contains an invalid argument."}}
      if "cast.as_int(metadata.event_timestamp.seconds / 86400)" in query:
        raise RuntimeError("Request contains an invalid argument.")
      if "fleet_zscore_process_outliers" in query or "$fleet_z = $diff / $safe_stddev" in query:
        return {
            "stats": {
                "results": [
                    {"column": "host", "values": [{"value": {"stringVal": "dev-win10-14.site.lan"}}]},
                ],
                "hasJoin": True,
            }
        }
      return {"stats": {"results": [{"column": "entity"}], "hasJoin": True}}

    results = self.harness.run_cases(
        smoke,
        search_fn=mock_search_fn,
        start_time=DEFAULT_START_TIME,
        end_time=DEFAULT_END_TIME,
    )
    self.assertEqual(len(calls), len(smoke))
    self.assertTrue(all(st == DEFAULT_START_TIME and et == DEFAULT_END_TIME for st, et in calls))

    summary = self.harness.summarize_results(results)
    self.assertEqual(summary["total_cases"], 37)
    self.assertEqual(summary["compile_failed_count"], 2)
    self.assertIn("pipeline:HYBRID_ENTROPY_CONCENTRATION:host:BALANCED", summary["failed_case_ids"])
    self.assertIn("example:rolling_ratio_spike.yara", summary["failed_case_ids"])

  def test_manifest_export_and_import_roundtrip(self) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp = Path(tmpdir)
      manifest_path = tmp / "manifest.json"
      raw_results_path = tmp / "raw_results.json"
      out_report_path = tmp / "report.json"

      rc_export = harness_cli_main(["--mode", "smoke", "--export-manifest", str(manifest_path)])
      self.assertEqual(rc_export, 0)
      manifest_items = json.loads(manifest_path.read_text(encoding="utf-8"))
      self.assertEqual(len(manifest_items), 37)

      synthetic_raw = [
          {
              "case_id": item["case_id"],
              "query_sha256": item["query_sha256"],
              "response": {"stats": {"results": [{"column": "entity"}]}},
          }
          for item in manifest_items
      ]
      raw_results_path.write_text(json.dumps(synthetic_raw), encoding="utf-8")

      rc_import = harness_cli_main([
          "--mode",
          "smoke",
          "--import-results",
          str(raw_results_path),
          "--output",
          str(out_report_path),
      ])
      self.assertEqual(rc_import, 0)
      saved_report = json.loads(out_report_path.read_text(encoding="utf-8"))
      self.assertEqual(saved_report["summary"]["total_cases"], 37)
      self.assertEqual(saved_report["summary"]["compile_ok_count"], 37)

  def test_recorded_baseline_gus_sdl_integrity(self) -> None:
    baseline_path = Path(__file__).resolve().parent / "baseline_gus_sdl.json"
    self.assertTrue(baseline_path.exists(), "Missing recorded tests/live/baseline_gus_sdl.json")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    self.assertEqual(baseline["metadata"]["project_id"], "gus-sdl")
    self.assertEqual(baseline["metadata"]["evidence_tag"], "V-live")
    self.assertEqual(baseline["summary"]["total_cases"], 37)
    self.assertEqual(baseline["summary"]["compile_ok_count"], 35)
    self.assertEqual(baseline["summary"]["compile_failed_count"], 2)
    self.assertEqual(
        sorted(baseline["summary"]["failed_case_ids"]),
        [
            "example:rolling_ratio_spike.yara",
            "pipeline:HYBRID_ENTROPY_CONCENTRATION:host:BALANCED",
        ],
    )
    self.assertEqual(len(baseline["compile_results"]), 37)

    sec8 = baseline["section_8_baselines"]
    self.assertIn("identifier_coverage_pf9_e4", sec8)
    self.assertIn("spray_dispersion_pf4_ws1_06", sec8)
    self.assertIn("ecg_and_whois_pf8_e6_ws1_08", sec8)
    dns_cov = sec8["identifier_coverage_pf9_e4"]["event_types"]["NETWORK_DNS"]
    self.assertEqual(dns_cov["total_events"], 582744)
    self.assertEqual(dns_cov["has_principal_ip"], 582585)
    self.assertEqual(dns_cov["has_principal_hostname"], 164)


@unittest.skipUnless(
    os.environ.get("SECOPS_LIVE_TESTS") == "1",
    "Opt-in live gus-sdl tests (set SECOPS_LIVE_TESTS=1 to enable).",
)
class TestLiveCompileMatrixGusSdl(unittest.TestCase):
  """Opt-in live Chronicle UDM Search compile verification against gus-sdl."""

  KNOWN_PRE_FIX_FAILURES = frozenset({
      "pipeline:HYBRID_ENTROPY_CONCENTRATION:host:BALANCED",
      "example:rolling_ratio_spike.yara",
  })

  def test_live_smoke_matrix_against_gus_sdl(self) -> None:
    harness = LiveCompileHarness(repo_root=REPO_ROOT)
    smoke_cases = harness.build_smoke_matrix(tier="BALANCED", window_hours=1.0)
    search_fn = make_adc_rest_search_fn(
        customer_id=os.environ.get("SECOPS_CUSTOMER_ID", "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"),
        project_id=os.environ.get("SECOPS_PROJECT_ID", "gus-sdl"),
        region=os.environ.get("SECOPS_REGION", "us"),
    )
    results = harness.run_cases(
        smoke_cases,
        search_fn=search_fn,
        start_time=DEFAULT_START_TIME,
        end_time=DEFAULT_END_TIME,
    )
    unexpected_failures = [
        f"{r.case_id}: {r.error}"
        for r in results
        if not r.compile_ok and r.case_id not in self.KNOWN_PRE_FIX_FAILURES
    ]
    self.assertEqual(unexpected_failures, [], f"Unexpected live compile failures: {unexpected_failures}")


if __name__ == "__main__":
  unittest.main()
