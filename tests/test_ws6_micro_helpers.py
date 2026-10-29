"""Unit and regression tests for WS6-02..04 vetted Python helpers and D6 Guardrails G1-G5.

Covers:
  - G1: Raw udm_search JSON payload input only (rejects raw floats, strings, arrays, or --scores flags).
  - G2: Fail-closed validation (missing/empty files, malformed JSON, NaN/Inf, API error payloads,
        events-only dumps, ragged column lengths, out-of-window buckets, invalid parameters,
        and <3 benign strings -> INSUFFICIENT_BENIGN_LENGTH_COHORT) with ValueError / exit code 2.
  - G3: Provenance Appendix with helper_version, query_sha256, and payload_sha256 in output and Markdown.
  - G4: 100% offline deterministic golden math tests for:
        * WS6-02 EWMA (dense T zero-fill, Roberts/Lucas-Saccucci UCL = mu_0 + L*sigma_0*sqrt(lambda/(2-lambda)),
          degenerate sigma_0 == 0 floor, sustained moderate shift +1.6 sigma detection, single-bucket blip smoothing).
        * WS6-03 Shannon Character Entropy (exact H(s) bits/char, Chronicle list.values wire format,
          length-matched [0.65*L, 1.5*L] benign prevalence cohort vs rare obfuscated/DGA token,
          entity-centric array shape, corpus-fallback warning, and <3 benign fail-closed error).
        * WS6-04 C2 Inter-Arrival Jitter (Chronicle list.values int64Val across hourly buckets,
          cross-hour delta_t stitching, periodic beacon +/-10% jitter vs exponential human traffic,
          25-element array_distinct cap truncation warning, and <min_intervals clean skip).
  - G5: Honest fallback when local script execution is unavailable (build_query(local_execution_available=False),
        CLI --no-local-scripts, and HandoffEndpoint.ingest({"local_execution_available": False})) failing closed
        with "this model needs a client that can run local scripts", while BURST_Z_SCREEN, LONG_STRING_SCREEN,
        and FLOW_GAP_RATIO_SCREEN succeed as stateless in-query screens.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import ueba_constants as uc  # pylint: disable=wrong-import-position
from multistage_query_builder import (  # pylint: disable=wrong-import-position
    HandoffEndpoint,
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    parse_columnar_stats,
)
try:
  import micro_python_helpers as mph  # pylint: disable=wrong-import-position
except ImportError:
  mph = None  # type: ignore[assignment]


def _make_chronicle_cell(val: Any) -> Dict[str, Any]:
  """Builds realistic Chronicle udmSearch stats cell JSON (including list.values for array_distinct)."""
  if isinstance(val, list):
    inner = []
    for item in val:
      if isinstance(item, int):
        inner.append({"int64Val": str(item)})
      elif isinstance(item, float):
        inner.append({"doubleVal": item})
      else:
        inner.append({"stringVal": str(item)})
    return {"list": {"values": inner}}
  if isinstance(val, bool):
    return {"value": {"boolVal": val}}
  if isinstance(val, int):
    return {"value": {"int64Val": str(val)}}
  if isinstance(val, float):
    return {"value": {"doubleVal": val}}
  return {"value": {"stringVal": str(val)}}


def _make_stats_payload(columns: Dict[str, Sequence[Any]]) -> Dict[str, Any]:
  """Builds a realistic columnar Chronicle udmSearch stats response."""
  results = []
  for col_name, values in columns.items():
    col_entry: Dict[str, Any] = {"column": col_name}
    if values:
      col_entry["values"] = [_make_chronicle_cell(v) for v in values]
    results.append(col_entry)
  return {"stats": {"results": results, "hasJoin": True}}


class TestParseColumnarStatsArrayDistinct(unittest.TestCase):
  """Verifies parse_columnar_stats handles live Chronicle array_distinct list.values cells."""

  def test_parse_columnar_stats_decodes_chronicle_list_values(self) -> None:
    payload = _make_stats_payload({
        "src_ip": ["10.42.0.15"],
        "dst_ip": ["198.51.100.77"],
        "event_timestamps": [[1761573600, 1761573900, 1761574200]],
        "sample_entities": [["wkstn-01", "wkstn-02"]],
        "total_conns": [30],
    })
    rows = parse_columnar_stats(payload)
    self.assertEqual(len(rows), 1)
    self.assertEqual(rows[0]["src_ip"], "10.42.0.15")
    self.assertEqual(rows[0]["dst_ip"], "198.51.100.77")
    self.assertEqual(rows[0]["event_timestamps"], [1761573600, 1761573900, 1761574200])
    self.assertEqual(rows[0]["sample_entities"], ["wkstn-01", "wkstn-02"])
    self.assertEqual(rows[0]["total_conns"], 30)


class TestWS6GuardrailsG1ToG3(unittest.TestCase):
  """Tests D6 Guardrails G1 (no typed scores), G2 (fail-closed exit 2 / ValueError), and G3 (SHA-256 provenance)."""

  SAMPLE_QUERY = "stage s1 {\n  metadata.event_type = \"PROCESS_LAUNCH\"\n  match: $e by 1h\n  outcome: $c = count(metadata.id)\n}\n"

  def setUp(self) -> None:
    self.assertIsNotNone(mph, "scripts/micro_python_helpers.py missing")

  def test_g1_rejects_non_dict_payloads_and_typed_score_flags(self) -> None:
    for bad_payload in ("[1, 2, 3]", "3.75", '"ewma_z=4.2"', "true"):
      with self.subTest(payload=bad_payload):
        with self.assertRaisesRegex(ValueError, "G1_RAW_UDM_PAYLOAD_REQUIRED"):
          mph.parse_strict_udm_stats_payload(bad_payload)

    helper_script = str(SCRIPTS_DIR / "micro_python_helpers.py")
    for subcmd in ("ewma", "shannon", "c2-jitter"):
      proc = subprocess.run(
          [sys.executable, helper_script, subcmd, "--scores", "host-a=4.5"],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc.returncode, 2, f"{subcmd} --scores must exit with code 2")

  def test_g2_fail_closed_on_malformed_events_ragged_nan_and_bad_params(self) -> None:
    # 1. Malformed JSON and NaN/Infinity tokens
    for bad_raw in ("{not-valid-json", '{"stats": {"results": [{"column": "x", "values": [{"value": {"doubleVal": NaN}}]}]}}'):
      with self.assertRaises(ValueError):
        mph.parse_strict_udm_stats_payload(bad_raw)

    # 2. Raw events dump without stats
    with self.assertRaisesRegex(ValueError, "G2_RAW_EVENTS_PAYLOAD_REJECTED"):
      mph.parse_strict_udm_stats_payload({"events": [{"udm": {}}]})

    # 3. Backend API error payload
    with self.assertRaisesRegex(ValueError, "G2_BACKEND_ERROR_PAYLOAD"):
      mph.parse_strict_udm_stats_payload({"error": {"code": 400, "message": "INVALID_ARGUMENT"}})

    # 4. Ragged column lengths
    ragged = {
        "stats": {
            "results": [
                {"column": "entity", "values": [{"value": {"stringVal": "h1"}}, {"value": {"stringVal": "h2"}}]},
                {"column": "window_events", "values": [{"value": {"int64Val": "10"}}]},
            ]
        }
    }
    with self.assertRaisesRegex(ValueError, "G2_RAGGED_COLUMN_LENGTHS"):
      mph.parse_strict_udm_stats_payload(ragged)

    # 5. Parameter validation on helpers
    empty_stats = {"stats": {"results": [{"column": "entity"}]}}
    with self.assertRaises(ValueError):
      mph.run_ewma_helper(
          empty_stats,
          query_text=self.SAMPLE_QUERY,
          start_time="2026-10-27T00:00:00Z",
          end_time="2026-10-28T00:00:00Z",
          lambda_weight=0.0,
      )
    with self.assertRaises(ValueError):
      mph.run_ewma_helper(
          empty_stats,
          query_text=self.SAMPLE_QUERY,
          start_time="2026-10-27T00:00:00Z",
          end_time="2026-10-28T00:00:00Z",
          control_l=-1.0,
      )
    with self.assertRaises(ValueError):
      mph.run_c2_jitter_helper(empty_stats, query_text=self.SAMPLE_QUERY, max_cv=0.50)
    with self.assertRaises(ValueError):
      mph.run_c2_jitter_helper(empty_stats, query_text=self.SAMPLE_QUERY, min_intervals=1)
    with self.assertRaises(ValueError):
      mph.run_shannon_helper(empty_stats, query_text=self.SAMPLE_QUERY, min_length=0)

  def test_g2_cli_exits_2_on_missing_empty_or_invalid_files(self) -> None:
    helper_script = str(SCRIPTS_DIR / "micro_python_helpers.py")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp = Path(tmpdir)
      q_path = tmp / "query.yl2"
      q_path.write_text(self.SAMPLE_QUERY, encoding="utf-8")

      # Missing payload file -> exit 2
      proc_missing = subprocess.run(
          [
              sys.executable,
              helper_script,
              "c2-jitter",
              "--query-file",
              str(q_path),
              "--payload-file",
              str(tmp / "does_not_exist.json"),
          ],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc_missing.returncode, 2)

      # Empty payload file -> exit 2
      empty_p = tmp / "empty.json"
      empty_p.write_text("", encoding="utf-8")
      proc_empty = subprocess.run(
          [
              sys.executable,
              helper_script,
              "shannon",
              "--query-file",
              str(q_path),
              "--payload-file",
              str(empty_p),
          ],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc_empty.returncode, 2)

      # Events-only payload file -> exit 2
      events_p = tmp / "events.json"
      events_p.write_text(json.dumps({"events": [{"udm": {}}]}), encoding="utf-8")
      proc_events = subprocess.run(
          [
              sys.executable,
              helper_script,
              "ewma",
              "--query-file",
              str(q_path),
              "--payload-file",
              str(events_p),
              "--start-time",
              "2026-10-27T00:00:00Z",
              "--end-time",
              "2026-10-28T00:00:00Z",
          ],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc_events.returncode, 2)

  def test_g3_provenance_sha256_in_result_and_markdown_appendix(self) -> None:
    helper_script = str(SCRIPTS_DIR / "micro_python_helpers.py")
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp = Path(tmpdir)
      q_bytes = self.SAMPLE_QUERY.encode("utf-8")
      p_obj = {"stats": {"results": [{"column": "src_ip"}, {"column": "dst_ip"}, {"column": "event_timestamps"}]}}
      p_bytes = json.dumps(p_obj, indent=2).encode("utf-8")

      q_path = tmp / "executed.yl2"
      p_path = tmp / "udm_response.json"
      out_json = tmp / "result.json"
      q_path.write_bytes(q_bytes)
      p_path.write_bytes(p_bytes)

      expected_q_sha = hashlib.sha256(q_bytes).hexdigest()
      expected_p_sha = hashlib.sha256(p_bytes).hexdigest()

      proc = subprocess.run(
          [
              sys.executable,
              helper_script,
              "c2-jitter",
              "--query-file",
              str(q_path),
              "--payload-file",
              str(p_path),
              "--output-json",
              str(out_json),
          ],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(proc.returncode, 0, f"Unexpected stderr: {proc.stderr}")
      saved = json.loads(out_json.read_text(encoding="utf-8"))
      self.assertEqual(saved["provenance"]["helper_version"], mph.HELPER_VERSION)
      self.assertEqual(saved["provenance"]["query_sha256"], expected_q_sha)
      self.assertEqual(saved["provenance"]["payload_sha256"], expected_p_sha)

      md = proc.stdout
      self.assertIn("Provenance Appendix", md)
      self.assertIn(mph.HELPER_VERSION, md)
      self.assertIn(expected_q_sha, md)
      self.assertIn(expected_p_sha, md)


class TestWS602EwmaHelperMath(unittest.TestCase):
  """Golden math tests for WS6-02 EWMA over dense zero-filled hourly grid."""

  QUERY_TEXT = "stage entity_hourly { metadata.event_type = \"PROCESS_LAUNCH\" match: $entity by 1h outcome: $window_events = count(metadata.id) }"

  def setUp(self) -> None:
    self.assertIsNotNone(mph, "scripts/micro_python_helpers.py missing")

  def test_ewma_dense_zero_fill_moderate_sustained_shift_and_blip_suppression(self) -> None:
    # 24-hour window [2026-10-27T00:00:00Z, 2026-10-28T00:00:00Z): T = 24 hourly buckets, B = 12 baseline buckets.
    start_epoch = 1793059200  # 2026-10-27T00:00:00Z
    # Entity "host-sustained":
    #   Baseline 12h: alternating 8 and 12 events -> mu_0 = 10.0, s_0 = sqrt(48/11) = 2.088931871468374.
    #    Wait: let's include two zero-event hours omitted from udm_search to prove dense T zero-fill!
    #   Suppose hours 0,2,4,6,8 have 20 events and hours 1,3,5,7,9,10,11 are OMITTED (0 events)!
    #   Wait: let's test dense zero-fill explicitly on "host-sparse" AND test exact moderate +1.6*sigma_0 shift on "host-shift"!
    entities: List[str] = []
    ws_list: List[int] = []
    counts: List[int] = []
    procs: List[int] = []
    peers: List[int] = []

    # 1. "host-shift": baseline hours 0..11 alternate 16 and 24 -> mu_0 = 20.0,
    #    sample variance = 12 * 16 / 11 = 17.454545..., s_0 = 4.177863743 (note > sqrt(20)=4.472? sqrt(20)=4.472135955!).
    #    Let's make baseline alternate 14 and 26 -> mu_0 = 20.0, sample s_0 = sqrt(12*36/11) = 6.266795614 > sqrt(20)!
    #    Then post-baseline hours 12..19 (8 consecutive hours) each have 30 events:
    #    single-hour Z = (30 - 20) / 6.266795614 = +1.5957σ (< 2.0σ on EVERY single hour!).
    #    Yet recursive EWMA (lambda=0.25, L=3.0) accumulates across the 8 hours to breach UCL!
    for h in range(12):
      entities.append("host-shift")
      ws_list.append(start_epoch + h * 3600)
      counts.append(14 if h % 2 == 0 else 26)
      procs.append(4)
      peers.append(18)
    for h in range(12, 20):
      entities.append("host-shift")
      ws_list.append(start_epoch + h * 3600)
      counts.append(30)
      procs.append(5)
      peers.append(18)
    for h in range(20, 24):
      entities.append("host-shift")
      ws_list.append(start_epoch + h * 3600)
      counts.append(20)
      procs.append(4)
      peers.append(18)

    # 2. "host-blip": identical baseline (hours 0..11 alternate 14 and 26, mu_0=20, sigma_0=6.266795614),
    #    ONE single-hour transient blip at hour 12 of 40 events (+3.19σ for 1 hour), then back to 20!
    #    EWMA with asymptotic UCL smooths single-bucket transient blips below 3.0σ!
    for h in range(12):
      entities.append("host-blip")
      ws_list.append(start_epoch + h * 3600)
      counts.append(14 if h % 2 == 0 else 26)
      procs.append(3)
      peers.append(18)
    entities.append("host-blip")
    ws_list.append(start_epoch + 12 * 3600)
    counts.append(40)
    procs.append(3)
    peers.append(18)
    for h in range(13, 24):
      entities.append("host-blip")
      ws_list.append(start_epoch + h * 3600)
      counts.append(20)
      procs.append(3)
      peers.append(18)

    # 3. "host-sparse": only active in hours 0 and 6 during baseline (12 events each; 10 baseline hours omitted -> zero-filled!),
    #    so true zero-inclusive baseline mean is 24 / 12 = 2.0 (NOT 12.0!). No post-baseline activity -> nominal.
    for h in (0, 6):
      entities.append("host-sparse")
      ws_list.append(start_epoch + h * 3600)
      counts.append(12)
      procs.append(2)
      peers.append(18)

    payload = _make_stats_payload({
        "entity": entities,
        "ws": ws_list,
        "window_events": counts,
        "distinct_binaries": procs,
        "fleet_prevalence": peers,
    })

    res = mph.run_ewma_helper(
        payload,
        query_text=self.QUERY_TEXT,
        start_time="2026-10-27T00:00:00Z",
        end_time="2026-10-28T00:00:00Z",
        lambda_weight=0.25,
        control_l=3.0,
        baseline_fraction=0.50,
    )

    by_entity = {r["entity"]: r for r in res["entity_results"]}
    shift_row = by_entity["host-shift"]
    blip_row = by_entity["host-blip"]
    sparse_row = by_entity["host-sparse"]

    expected_sigma0 = math.sqrt(12.0 * 36.0 / 11.0)
    expected_sigma_ewma = expected_sigma0 * math.sqrt(0.25 / 1.75)
    expected_ucl = 20.0 + 3.0 * expected_sigma_ewma

    self.assertAlmostEqual(shift_row["baseline_mean"], 20.0, places=6)
    self.assertAlmostEqual(shift_row["baseline_dispersion"], expected_sigma0, places=6)
    self.assertAlmostEqual(shift_row["sigma_ewma"], expected_sigma_ewma, places=6)
    self.assertAlmostEqual(shift_row["ucl"], expected_ucl, places=6)
    self.assertLess(shift_row["max_single_bucket_z"], 2.0)
    self.assertGreater(shift_row["ewma_z"], 3.0)
    self.assertEqual(shift_row["cri"], uc.cri_from_model_score("ewma_z", shift_row["ewma_z"], threshold_override=3.0))
    self.assertGreaterEqual(shift_row["cri"], 50)

    # Single-bucket blip is smoothed below 3.0 EWMA control limit
    self.assertLess(blip_row["ewma_z"], 3.0)

    # Sparse entity proves dense zero-fill: 24 events across 12 baseline hours => mu_0 == 2.0 (not 12.0!)
    self.assertAlmostEqual(sparse_row["baseline_mean"], 2.0, places=6)

    outlier_entities = [o["entity"] for o in res["outliers"]]
    self.assertEqual(outlier_entities, ["host-shift"])
    self.assertIn("host-shift", res["report_markdown"])
    self.assertIn("Provenance Appendix", res["report_markdown"])

  def test_ewma_degenerate_constant_baseline_uses_poisson_floor_and_rejects_out_of_window_ws(self) -> None:
    start_epoch = 1793059200  # 2026-10-27T00:00:00Z
    # Constant 4 events every baseline hour -> sample s_0 == 0.0 -> floor = sqrt(max(4.0, 1.0)) = 2.0
    ws_list = [start_epoch + h * 3600 for h in range(24)]
    counts = [4] * 12 + [12] * 12
    payload = _make_stats_payload({
        "entity": ["steady-srv"] * 24,
        "ws": ws_list,
        "window_events": counts,
    })
    res = mph.run_ewma_helper(
        payload,
        query_text=self.QUERY_TEXT,
        start_time="2026-10-27T00:00:00Z",
        end_time="2026-10-28T00:00:00Z",
        lambda_weight=0.25,
        control_l=3.0,
    )
    row = res["entity_results"][0]
    self.assertAlmostEqual(row["baseline_mean"], 4.0, places=6)
    self.assertAlmostEqual(row["baseline_dispersion"], 2.0, places=6)
    self.assertGreater(row["ewma_z"], 3.0)

    # Out-of-window timestamp -> fail-closed ValueError
    bad_payload = _make_stats_payload({
        "entity": ["steady-srv"],
        "ws": [start_epoch - 7200],
        "window_events": [5],
    })
    with self.assertRaisesRegex(ValueError, "G2_OUT_OF_WINDOW_BUCKET"):
      mph.run_ewma_helper(
          bad_payload,
          query_text=self.QUERY_TEXT,
          start_time="2026-10-27T00:00:00Z",
          end_time="2026-10-28T00:00:00Z",
      )


class TestWS603ShannonHelperMath(unittest.TestCase):
  """Golden math tests for WS6-03 per-character Shannon entropy & length-matched benign cohort scoring."""

  QUERY_TEXT = "stage token_stats { metadata.event_type = \"PROCESS_LAUNCH\" match: $token outcome: $raw_length = max(strings.length($token)) }"

  def setUp(self) -> None:
    self.assertIsNotNone(mph, "scripts/micro_python_helpers.py missing")

  def test_exact_shannon_entropy_bits_per_char(self) -> None:
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits(""), 0.0, places=6)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("aaaaaaaaaaaa"), 0.0, places=6)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("01" * 20), 1.0, places=6)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("0123456789abcdef" * 4), 4.0, places=6)

  def test_length_normalized_shannon_flags_obfuscated_token_and_ignores_long_repetitive_cli(self) -> None:
    # 6 benign enterprise command lines around length 55-80 (host_prevalence >= 3), moderate English/CLI entropy (~3.5-3.9 bits/char)
    benign_tokens = [
        "/usr/bin/python3 /opt/corp/agent/health_check.py --mode=status",
        "/usr/bin/python3 /opt/corp/agent/log_rotator.py --config=/etc/corp.conf",
        "/usr/bin/systemctl status corp-monitoring-daemon.service --no-pager",
        "/usr/sbin/logrotate /etc/logrotate.conf --state /var/lib/logrotate/status",
        "/usr/bin/git -C /opt/corp/deploy fetch --prune origin refs/heads/main",
        "/usr/bin/curl -sS https://internal-mirror.corp.local/healthz --max-time 5",
    ]
    # Rare candidate 1: high-entropy base64/random payload (64 unique printable chars -> 6.0 bits/char!), prevalence = 1
    high_entropy_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # Rare candidate 2: equally long 64-char repetitive benign path/padding -> low entropy (~1.5 bits/char), prevalence = 1
    low_entropy_long_token = "/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/bb/aa/"

    tokens = benign_tokens + [high_entropy_token, low_entropy_long_token]
    sample_entities = (
        [["srv-1", "srv-2", "srv-3", "srv-4"]] * len(benign_tokens)
        + [["wkstn-compromised-09"], ["wkstn-dev-02"]]
    )
    prevalences = [12, 10, 15, 9, 8, 11, 1, 1]
    events = [40, 35, 50, 30, 25, 45, 2, 3]
    lengths = [len(t) for t in tokens]
    procs = [1] * len(tokens)

    payload = _make_stats_payload({
        "token": tokens,
        "sample_entities": sample_entities,
        "host_prevalence": prevalences,
        "token_events": events,
        "raw_length": lengths,
        "distinct_binaries": procs,
    })

    res = mph.run_shannon_helper(
        payload,
        query_text=self.QUERY_TEXT,
        min_length=25,
        benign_min_prevalence=3,
        candidate_max_prevalence=2,
        z_threshold=3.0,
    )

    self.assertEqual(len(res["outliers"]), 1)
    top = res["outliers"][0]
    self.assertEqual(top["token"], high_entropy_token)
    self.assertEqual(top["entity"], "wkstn-compromised-09")
    self.assertAlmostEqual(top["entropy_bits"], 6.0, places=6)
    self.assertEqual(top["cohort_mode"], "length_matched")
    self.assertGreater(top["shannon_z"], 3.0)
    self.assertEqual(top["cri"], uc.cri_from_model_score("shannon_z", top["shannon_z"], threshold_override=3.0))
    self.assertGreaterEqual(top["cri"], 50)

    cand_by_token = {c["token"]: c for c in res["candidate_results"]}
    self.assertLess(cand_by_token[low_entropy_long_token]["shannon_z"], 0.0)
    self.assertEqual(cand_by_token[low_entropy_long_token]["cri"], 0)

  def test_shannon_corpus_fallback_warning_and_insufficient_benign_cohort_error(self) -> None:
    # 4 benign tokens around length 30, and 1 candidate token of length 120 (outside [0.65*120, 1.5*120]) -> corpus_fallback warning
    benign_short = [
        "cmd.exe /c echo corp_check_01",
        "cmd.exe /c echo corp_check_02",
        "cmd.exe /c echo corp_check_03",
        "cmd.exe /c echo corp_check_04",
    ]
    long_cand = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2)[:120]
    payload_fallback = _make_stats_payload({
        "token": benign_short + [long_cand],
        "sample_entities": [["h1", "h2", "h3"]] * 4 + [["h9"]],
        "host_prevalence": [5, 5, 5, 5, 1],
        "token_events": [10, 10, 10, 10, 1],
        "raw_length": [len(t) for t in benign_short] + [len(long_cand)],
    })
    res_fb = mph.run_shannon_helper(payload_fallback, query_text=self.QUERY_TEXT, min_length=25)
    self.assertEqual(res_fb["candidate_results"][0]["cohort_mode"], "corpus_fallback")
    self.assertTrue(any("corpus_fallback" in w or "length-matched" in w for w in res_fb["warnings"]))

    # Fewer than 3 benign strings when scoring candidates -> fail closed with INSUFFICIENT_BENIGN_LENGTH_COHORT
    payload_too_few = _make_stats_payload({
        "token": benign_short[:2] + [long_cand],
        "sample_entities": [["h1", "h2", "h3"]] * 2 + [["h9"]],
        "host_prevalence": [5, 5, 1],
        "token_events": [10, 10, 1],
        "raw_length": [len(benign_short[0]), len(benign_short[1]), len(long_cand)],
    })
    with self.assertRaisesRegex(ValueError, "INSUFFICIENT_BENIGN_LENGTH_COHORT"):
      mph.run_shannon_helper(payload_too_few, query_text=self.QUERY_TEXT, min_length=25)


class TestWS604C2JitterHelperMath(unittest.TestCase):
  """Golden math tests for WS6-04 C2 inter-arrival jitter, cross-hour stitching, and array_distinct cap warning."""

  QUERY_TEXT = "stage host_intervals { metadata.event_type = \"NETWORK_CONNECTION\" match: $src_ip, $dst_ip by 1h outcome: $conn_count = count(metadata.id) }"

  def setUp(self) -> None:
    self.assertIsNotNone(mph, "scripts/micro_python_helpers.py missing")

  def test_c2_jitter_periodic_beacon_vs_random_human_and_array_distinct_cap(self) -> None:
    base_ts = 1793059200  # 2026-10-27T00:00:00Z
    rng = random.Random(42)

    # Pair 1: Periodic 300s beacon across 3 consecutive hours with +/-8% uniform jitter
    beacon_ts: List[int] = []
    cur = base_ts + 45
    for _ in range(30):
      beacon_ts.append(cur)
      cur += 300 + rng.randint(-20, 20)

    # Split beacon_ts into hourly buckets just like Root match: $src_ip, $dst_ip, $ws
    beacon_buckets: Dict[str, List[int]] = {}
    for ts in beacon_ts:
      hr_key = f"hour_{(ts - base_ts) // 3600}"
      beacon_buckets.setdefault(hr_key, []).append(ts)

    # Pair 2: Random memoryless human browsing (exponential inter-arrival times, CV ~ 1.0)
    human_ts: List[int] = []
    cur_h = base_ts + 10
    for _ in range(30):
      human_ts.append(cur_h)
      cur_h += max(1, int(rng.expovariate(1.0 / 300.0)))
    human_buckets: Dict[str, List[int]] = {}
    for ts in human_ts:
      hr_key = f"hour_{(ts - base_ts) // 3600}"
      human_buckets.setdefault(hr_key, []).append(ts)

    # Pair 3: High-rate beacon hitting the 25-element array_distinct cap in one hour (25 timestamps in bucket, bucket_conns=40)
    capped_ts = [base_ts + i * 120 for i in range(25)]

    # Pair 4: Sparse pair with only 3 timestamps (2 intervals < min_intervals=4) -> cleanly skipped
    sparse_ts = [base_ts + 100, base_ts + 400, base_ts + 700]

    src_col: List[str] = []
    dst_col: List[str] = []
    ws_col: List[str] = []
    ts_col: List[List[int]] = []
    bconns_col: List[int] = []
    tconns_col: List[int] = []
    ahours_col: List[int] = []
    prev_col: List[int] = []
    procs_col: List[int] = []

    for ws_k, b_list in sorted(beacon_buckets.items()):
      src_col.append("10.10.5.21")
      dst_col.append("198.51.100.44")
      ws_col.append(ws_k)
      ts_col.append(b_list)
      bconns_col.append(len(b_list))
      tconns_col.append(len(beacon_ts))
      ahours_col.append(len(beacon_buckets))
      prev_col.append(1)
      procs_col.append(1)

    for ws_k, h_list in sorted(human_buckets.items()):
      src_col.append("10.10.5.99")
      dst_col.append("203.0.113.88")
      ws_col.append(ws_k)
      ts_col.append(h_list)
      bconns_col.append(len(h_list))
      tconns_col.append(len(human_ts))
      ahours_col.append(len(human_buckets))
      prev_col.append(2)
      procs_col.append(2)

    src_col.append("10.10.5.77")
    dst_col.append("192.0.2.55")
    ws_col.append("hour_0")
    ts_col.append(capped_ts)
    bconns_col.append(40)
    tconns_col.append(40)
    ahours_col.append(6)
    prev_col.append(1)
    procs_col.append(1)

    src_col.append("10.10.5.12")
    dst_col.append("198.51.100.99")
    ws_col.append("hour_0")
    ts_col.append(sparse_ts)
    bconns_col.append(3)
    tconns_col.append(3)
    ahours_col.append(1)
    prev_col.append(1)
    procs_col.append(1)

    payload = _make_stats_payload({
        "src_ip": src_col,
        "dst_ip": dst_col,
        "ws": ws_col,
        "event_timestamps": ts_col,
        "bucket_conns": bconns_col,
        "total_conns": tconns_col,
        "active_hours": ahours_col,
        "fleet_prevalence": prev_col,
        "distinct_binaries": procs_col,
    })

    res = mph.run_c2_jitter_helper(payload, query_text=self.QUERY_TEXT, max_cv=0.20, min_intervals=4)

    by_pair = {(r["src_ip"], r["dst_ip"]): r for r in res["pair_results"]}
    self.assertNotIn(("10.10.5.12", "198.51.100.99"), by_pair)
    self.assertEqual(len(res["skipped_insufficient_intervals"]), 1)

    beacon = by_pair[("10.10.5.21", "198.51.100.44")]
    human = by_pair[("10.10.5.99", "203.0.113.88")]
    capped = by_pair[("10.10.5.77", "192.0.2.55")]

    # Cross-hour stitching preserves all 30 timestamps -> 29 consecutive intervals
    self.assertEqual(beacon["interval_count"], 29)
    self.assertLess(beacon["cv"], 0.10)
    self.assertGreaterEqual(beacon["fraction_near_median"], 0.90)
    self.assertGreaterEqual(beacon["periodicity_score"], 0.90)
    self.assertFalse(beacon["array_distinct_cap_hit"])
    self.assertEqual(beacon["cri"], uc.cri_from_model_score("cv", beacon["cv"], threshold_override=0.20))
    self.assertGreaterEqual(beacon["cri"], 70)

    # Human traffic has high CV (> 0.60) and CRI == 0
    self.assertGreater(human["cv"], 0.60)
    self.assertEqual(human["cri"], 0)

    # Capped pair flags array_distinct_cap_hit and surfaces warning in report
    self.assertTrue(capped["array_distinct_cap_hit"])
    self.assertTrue(any("25" in w and "array_distinct" in w for w in res["warnings"]))
    self.assertIn("array_distinct", res["report_markdown"])

    outlier_pairs = [(o["src_ip"], o["dst_ip"]) for o in res["outliers"]]
    self.assertIn(("10.10.5.21", "198.51.100.44"), outlier_pairs)
    self.assertNotIn(("10.10.5.99", "203.0.113.88"), outlier_pairs)


class TestWS6GuardrailG5HonestFallback(unittest.TestCase):
  """Tests D6 Guardrail G5 fail-closed behavior without local script execution vs stateless in-query screens."""

  EXACT_G5_PHRASE = "this model needs a client that can run local scripts"

  def test_router_g5_blocks_helper_models_without_local_scripts_and_allows_screens(self) -> None:
    router = MultiStageTemplateRouter()
    for arch in (
        "EWMA_BURST_VELOCITY",
        "EWMA",
        "SHANNON_ENTROPY_CHARACTER",
        "SHANNON",
        "C2_BEACONING_JITTER",
        "JITTER",
    ):
      with self.subTest(archetype=arch):
        with self.assertRaises(ValueError) as ctx:
          router.build_query(arch, local_execution_available=False)
        self.assertIn(self.EXACT_G5_PHRASE, str(ctx.exception))

    # Stateless honest screen archetypes succeed even when local_execution_available=False!
    for screen_arch in (
        "BURST_Z_SCREEN",
        "BURST_Z",
        "LONG_STRING_SCREEN",
        "FLOW_GAP_RATIO_SCREEN",
        "FLOW_GAP_RATIO",
    ):
      with self.subTest(screen=screen_arch):
        q = router.build_query(screen_arch, local_execution_available=False)
        qa = QueryIntegrityGate.verify_pre_dispatch(q)
        self.assertTrue(qa["valid"], f"{screen_arch} failed pre-dispatch: {qa['errors']}")

  def test_cli_no_local_scripts_exits_nonzero_with_g5_message(self) -> None:
    builder_script = str(SCRIPTS_DIR / "multistage_query_builder.py")
    for arch in ("EWMA_BURST_VELOCITY", "SHANNON_ENTROPY_CHARACTER", "C2_BEACONING_JITTER"):
      proc = subprocess.run(
          [sys.executable, builder_script, "--build_query", "--archetype", arch, "--no-local-scripts"],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertNotEqual(proc.returncode, 0)
      self.assertIn(self.EXACT_G5_PHRASE, proc.stderr + proc.stdout)

    proc_screen = subprocess.run(
        [sys.executable, builder_script, "--build_query", "--archetype", "FLOW_GAP_RATIO_SCREEN", "--no-local-scripts"],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertEqual(proc_screen.returncode, 0, f"Unexpected stderr: {proc_screen.stderr}")
    self.assertIn("stage host_intervals", proc_screen.stdout)

  def test_handoff_endpoint_enforces_g5_when_local_execution_unavailable(self) -> None:
    payload = {
        "protocol": "secops-threat-hunt-handoff-v1",
        "request_id": "req-g5-01",
        "source_skill": "secops-risk-metrics-multistage",
        "target_skill": "secops-statistical-hunter",
        "intent": "SCHEDULED_EXFILTRATION_TIMING",
        "target_entity": {"type": "HOSTNAME", "value": "site-rev-proxy.lan"},
        "search_window": {"lookback": "24h"},
        "statistical_model": {"name": "C2_BEACONING_JITTER", "sensitivity": "BALANCED"},
        "local_execution_available": False,
        "justification": "Client without run_command attempting C2 jitter model.",
    }
    res_blocked = HandoffEndpoint.ingest(payload)
    self.assertEqual(res_blocked["status"], "HANDOFF_ACK_REJECTED")
    self.assertTrue(any(self.EXACT_G5_PHRASE in err for err in res_blocked["errors"]))

    payload_screen = dict(payload)
    payload_screen["intent"] = "FLOW_GAP_RATIO_SCREEN"
    payload_screen["statistical_model"] = {"name": "FLOW_GAP_RATIO_SCREEN", "sensitivity": "BALANCED"}
    res_ok = HandoffEndpoint.ingest(payload_screen)
    self.assertEqual(res_ok["status"], "HANDOFF_ACK_ACCEPTED")
    self.assertEqual(res_ok["model_routed"], "FLOW_GAP_RATIO_SCREEN")


if __name__ == "__main__":
  unittest.main()
