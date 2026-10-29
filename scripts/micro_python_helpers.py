#!/usr/bin/env python3
"""Vetted Python Helpers for Micro-Plane Statistical Hunting (WS6-02..04, D6 G1-G5).

Provides deterministic, offline-testable post-processing over compact, ungated
Google SecOps Chronicle `udm_search` aggregated `stats` payloads for the three
micro-plane models whose exact statistics cannot be expressed in stateless
single-bucket YARA-L 2.0:

  1. WS6-02 (`ewma` / `run_ewma_helper`):
     Zero-fills missing buckets onto the dense T-bucket grid and evaluates Roberts /
     Lucas-Saccucci recursive EWMA S_t = lambda*x_t + (1-lambda)*S_{t-1} against
     UCL = mu_0 + L * sigma_0 * sqrt(lambda / (2 - lambda)).
  2. WS6-03 (`shannon` / `run_shannon_helper`):
     Computes exact per-character Shannon entropy H(s) = -sum p(c) log2 p(c) (bits/char)
     and standardizes rare candidate strings against the empirical entropy distribution
     of length-matched [0.65*L, 1.50*L] multi-host benign strings for the same field.
  3. WS6-04 (`c2-jitter` / `run_c2_jitter_helper`):
     Stitches hourly `array_distinct(event_timestamp.seconds)` arrays per qualifying
     external `(src_ip, dst_ip)` pair, deduplicates and sorts timestamps across hour
     boundaries, flags the 25-element `array_distinct` cap when hit, and computes
     inter-arrival CV = sigma_dt / mu_dt plus periodicity diagnostics.

Enforces D6 Guardrails G1-G5:
  - G1: Accepts ONLY raw `udm_search` JSON response objects (never LLM-typed scores or `--scores`).
  - G2: Fails closed (ValueError in Python; exit code 2 on CLI) on missing/empty files,
        malformed JSON, NaN/Infinity cells, API error payloads, raw `events` dumps,
        ragged column lengths, out-of-window buckets, invalid parameters, or <3 benign strings.
  - G3: Emits a Provenance Appendix (`helper_version`, `query_sha256`, `payload_sha256`)
        in both the structured output dictionary and the 5-Section Markdown report.
  - G4: 100% deterministic offline math with zero network calls unless `--run-query` is passed.
  - G5: Paired with `MultiStageTemplateRouter(local_execution_available=False)` / `--no-local-scripts`
        fail-closed enforcement and stateless screen alternatives (`BURST_Z_SCREEN`,
        `LONG_STRING_SCREEN`, `FLOW_GAP_RATIO_SCREEN`).
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
from typing import Any, Collection, Dict, List, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import ueba_constants as uc  # pylint: disable=wrong-import-position

HELPER_VERSION = "1.0.0"
ARRAY_DISTINCT_CAP = 25

DEFAULT_CUSTOMER_ID = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
DEFAULT_PROJECT_ID = "gus-sdl"
DEFAULT_REGION = "us"


def compute_sha256_hex(data: Union[str, bytes]) -> str:
  """Computes lowercase hex SHA-256 digest of string or bytes."""
  raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
  return hashlib.sha256(raw).hexdigest()


def _serialize_canonical_payload_bytes(raw_payload: Union[str, bytes, Dict[str, Any]]) -> bytes:
  if isinstance(raw_payload, bytes):
    if not raw_payload.strip():
      raise ValueError("G2_EMPTY_PAYLOAD: raw udm_search payload is empty.")
    return raw_payload
  if isinstance(raw_payload, str):
    if not raw_payload.strip():
      raise ValueError("G2_EMPTY_PAYLOAD: raw udm_search payload string is empty.")
    return raw_payload.encode("utf-8")
  if isinstance(raw_payload, dict):
    return json.dumps(raw_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
  raise ValueError(
      "G1_RAW_UDM_PAYLOAD_REQUIRED: expected raw udm_search JSON object (dict/str/bytes), "
      f"got {type(raw_payload).__name__}."
  )


def build_provenance_block(
    query_text: str,
    raw_payload_bytes: Union[str, bytes],
    helper_name: str,
) -> Dict[str, str]:
  """Constructs D6 Guardrail G3 SHA-256 provenance metadata."""
  if not isinstance(query_text, str) or not query_text.strip():
    raise ValueError("G2_EMPTY_QUERY: executed YARA-L query text is required for G3 provenance.")
  payload_bytes = raw_payload_bytes.encode("utf-8") if isinstance(raw_payload_bytes, str) else bytes(raw_payload_bytes)
  if not payload_bytes.strip():
    raise ValueError("G2_EMPTY_PAYLOAD: raw udm_search payload is empty.")
  return {
      "helper_name": helper_name,
      "helper_version": HELPER_VERSION,
      "query_sha256": compute_sha256_hex(query_text),
      "payload_sha256": compute_sha256_hex(payload_bytes),
  }


def _reject_non_finite_constant(token: str) -> Any:
  raise ValueError(f"G2_NON_FINITE_NUMERIC: JSON constant {token!r} is forbidden in udm_search payloads.")


def _decode_scalar_value_dict(val_obj: Dict[str, Any], *, force_string: bool = False) -> Any:
  """Decodes a Chronicle stats cell value dict with strict finite validation."""
  if not val_obj:
    return None
  if "stringVal" in val_obj:
    return str(val_obj["stringVal"])
  if "timestampVal" in val_obj:
    return str(val_obj["timestampVal"])
  if "boolVal" in val_obj:
    return str(val_obj["boolVal"]) if force_string else bool(val_obj["boolVal"])
  if "int64Val" in val_obj:
    raw_i = val_obj["int64Val"]
    if force_string:
      return str(raw_i)
    try:
      return int(raw_i)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2_MALFORMED_INT64: invalid int64Val {raw_i!r}") from exc
  if "uint64Val" in val_obj:
    raw_u = val_obj["uint64Val"]
    if force_string:
      return str(raw_u)
    try:
      return int(raw_u)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2_MALFORMED_UINT64: invalid uint64Val {raw_u!r}") from exc
  if "doubleVal" in val_obj:
    raw_d = val_obj["doubleVal"]
    try:
      fval = float(raw_d)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2_MALFORMED_DOUBLE: invalid doubleVal {raw_d!r}") from exc
    if not math.isfinite(fval):
      raise ValueError(f"G2_NON_FINITE_NUMERIC: non-finite doubleVal {raw_d!r}")
    return str(raw_d) if force_string else fval
  return None


def _decode_chronicle_cell(cell: Any, *, force_string: bool = False) -> Any:
  """Decodes either scalar `{"value": ...}` or `array_distinct` `{"list": {"values": [...]}}` cells."""
  if not isinstance(cell, dict):
    if isinstance(cell, float) and not math.isfinite(cell):
      raise ValueError(f"G2_NON_FINITE_NUMERIC: non-finite cell {cell!r}")
    return str(cell) if (force_string and cell is not None) else cell

  # Chronicle array_distinct wire formats:
  #   {"list": {"values": [{"int64Val": "..."}, ...]}}
  #   {"listValue": {"values": [...]}}
  #   {"value": {"listVal": {"values": [...]}}}
  val_obj = cell.get("value")
  list_container = (
      cell.get("list")
      or cell.get("listValue")
      or (val_obj.get("listVal") if isinstance(val_obj, dict) else None)
      or (val_obj.get("listValue") if isinstance(val_obj, dict) else None)
  )
  if isinstance(list_container, dict):
    raw_items = list_container.get("values", [])
    if not isinstance(raw_items, list):
      raise ValueError("G2_MALFORMED_PAYLOAD: list.values must be a JSON array.")
    decoded_list: List[Any] = []
    for elem in raw_items:
      if isinstance(elem, dict):
        inner = elem.get("value") if isinstance(elem.get("value"), dict) else elem
        decoded_elem = _decode_scalar_value_dict(inner, force_string=force_string)
        if decoded_elem is not None:
          decoded_list.append(decoded_elem)
      else:
        if isinstance(elem, float) and not math.isfinite(elem):
          raise ValueError(f"G2_NON_FINITE_NUMERIC: non-finite list element {elem!r}")
        decoded_list.append(str(elem) if force_string else elem)
    return decoded_list

  if isinstance(val_obj, dict):
    return _decode_scalar_value_dict(val_obj, force_string=force_string)

  # Direct value dict without outer "value" wrapper
  for direct_key in ("stringVal", "int64Val", "uint64Val", "doubleVal", "boolVal", "timestampVal"):
    if direct_key in cell:
      return _decode_scalar_value_dict(cell, force_string=force_string)

  return None


def parse_strict_udm_stats_payload(
    raw_payload: Union[str, bytes, Dict[str, Any]],
    *,
    string_columns: Collection[str] = (),
) -> List[Dict[str, Any]]:
  """Strictly validates and parses a raw Chronicle `udm_search` aggregated `stats` payload (G1 & G2)."""
  if isinstance(raw_payload, (str, bytes)):
    raw_text = raw_payload.decode("utf-8") if isinstance(raw_payload, bytes) else raw_payload
    if not raw_text.strip():
      raise ValueError("G2_EMPTY_PAYLOAD: udm_search payload is empty.")
    try:
      data = json.loads(raw_text, parse_constant=_reject_non_finite_constant)
    except ValueError:
      raise
    except Exception as exc:
      raise ValueError(f"G2_MALFORMED_PAYLOAD: invalid JSON payload: {exc}") from exc
  elif isinstance(raw_payload, dict):
    # Re-serialize and parse with _reject_non_finite_constant to catch in-memory NaN/Inf floats
    try:
      canonical = json.dumps(raw_payload, allow_nan=False)
      data = json.loads(canonical)
    except (TypeError, ValueError) as exc:
      raise ValueError(f"G2_NON_FINITE_NUMERIC: payload contains non-finite or non-JSON values: {exc}") from exc
  else:
    raise ValueError(
        "G1_RAW_UDM_PAYLOAD_REQUIRED: helpers accept only raw udm_search JSON objects, "
        f"never pre-computed scalars or arrays (got {type(raw_payload).__name__})."
    )

  if not isinstance(data, dict):
    raise ValueError(
        "G1_RAW_UDM_PAYLOAD_REQUIRED: top-level JSON must be a raw udm_search response object, "
        f"got {type(data).__name__}."
    )

  if data.get("isError") is True or "error" in data:
    raise ValueError(f"G2_BACKEND_ERROR_PAYLOAD: udm_search returned an error payload: {data.get('error', data)}")

  if "events" in data and "stats" not in data:
    raise ValueError(
        "G2_RAW_EVENTS_PAYLOAD_REJECTED: expected aggregated multi-stage udm_search `stats` payload, "
        "got raw `events` dump."
    )

  if not data:
    return []

  if "stats" not in data:
    raise ValueError("G2_MISSING_STATS_BLOCK: payload must contain a `stats` block from udm_search.")

  stats_block = data["stats"]
  if stats_block in (None, {}, []):
    return []
  if not isinstance(stats_block, dict):
    raise ValueError(f"G2_MALFORMED_PAYLOAD: `stats` must be an object, got {type(stats_block).__name__}.")

  results = stats_block.get("results")
  if results in (None, []):
    return []
  if not isinstance(results, list):
    raise ValueError("G2_MALFORMED_PAYLOAD: `stats.results` must be a list of column objects.")

  string_col_set = {c.lstrip("$") for c in string_columns}
  parsed_columns: Dict[str, List[Any]] = {}
  observed_lengths: List[Tuple[str, int]] = []

  for col_entry in results:
    if not isinstance(col_entry, dict) or not isinstance(col_entry.get("column"), str) or not col_entry["column"].strip():
      raise ValueError(f"G2_MALFORMED_PAYLOAD: invalid column descriptor in stats.results: {col_entry!r}")
    col_name = col_entry["column"].lstrip("$")
    raw_vals = col_entry.get("values")
    if raw_vals is None:
      observed_lengths.append((col_name, 0))
      parsed_columns[col_name] = []
      continue
    if not isinstance(raw_vals, list):
      raise ValueError(f"G2_MALFORMED_PAYLOAD: `values` for column {col_name!r} must be a list.")
    observed_lengths.append((col_name, len(raw_vals)))
    force_str = col_name in string_col_set
    parsed_columns[col_name] = [_decode_chronicle_cell(cell, force_string=force_str) for cell in raw_vals]

  if not observed_lengths:
    return []

  distinct_lengths = {length for _, length in observed_lengths}
  if len(distinct_lengths) > 1:
    raise ValueError(f"G2_RAGGED_COLUMN_LENGTHS: inconsistent column lengths in stats.results: {observed_lengths}")

  num_rows = next(iter(distinct_lengths))
  if num_rows == 0:
    return []

  rows: List[Dict[str, Any]] = []
  for idx in range(num_rows):
    rows.append({col: vals[idx] for col, vals in parsed_columns.items()})
  return rows


def _parse_iso_utc_to_epoch(iso_str: str, label: str) -> int:
  if not isinstance(iso_str, str) or not iso_str.strip():
    raise ValueError(f"G2_INVALID_TIME: {label} must be a non-empty ISO-8601 timestamp.")
  txt = iso_str.strip()
  if txt.endswith("Z"):
    txt = txt[:-1] + "+00:00"
  try:
    dt = datetime.fromisoformat(txt)
  except ValueError as exc:
    raise ValueError(f"G2_INVALID_TIME: invalid ISO-8601 {label} {iso_str!r}: {exc}") from exc
  if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)
  return int(dt.astimezone(timezone.utc).timestamp())


def _parse_bucket_epoch(ws_val: Any) -> int:
  if isinstance(ws_val, bool) or ws_val is None:
    raise ValueError(f"G2_INVALID_BUCKET_TIMESTAMP: invalid bucket timestamp {ws_val!r}")
  if isinstance(ws_val, (int, float)):
    if not math.isfinite(ws_val):
      raise ValueError(f"G2_NON_FINITE_NUMERIC: bucket timestamp {ws_val!r}")
    return int(ws_val)
  s = str(ws_val).strip()
  if not s:
    raise ValueError("G2_INVALID_BUCKET_TIMESTAMP: empty bucket timestamp.")
  try:
    return int(s)
  except ValueError:
    return _parse_iso_utc_to_epoch(s, "ws")


def _epoch_to_iso_utc(epoch: int) -> str:
  return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_pivot_fields_from_query(
    query_text: Optional[str],
    *,
    default_entity_field: str = "principal.hostname",
    default_event_type: str = "PROCESS_LAUNCH",
) -> Tuple[str, str]:
  """Extracts (entity_field, event_type) from YARA-L query_text with safe defaults."""
  if not query_text:
    return default_entity_field, default_event_type

  ev_match = re.search(r'metadata\.event_type\s*=\s*"([^"]+)"', query_text)
  event_type = ev_match.group(1).strip() if ev_match else default_event_type

  ent_match = (
      re.search(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\s*=\s*\$entity\b", query_text)
      or re.search(r"\$entity\s*=\s*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\b", query_text)
      or re.search(r"strings\.coalesce\(\s*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)[^)]*\)\s*=\s*\$entity\b", query_text)
      or re.search(r"\$entity\s*=\s*strings\.coalesce\(\s*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)[^)]*\)", query_text)
  )
  entity_field = ent_match.group(1).strip() if ent_match else default_entity_field
  return entity_field, event_type


def _severity_badge_from_cri(cri: Optional[int], z_equiv: Optional[float], *, show_sigma: bool = True, raw_display: str = "") -> Tuple[str, str]:
  code, label, emoji = uc.get_cri_band_info(cri)
  cri_fmt, _ = uc.get_cri_badge(cri)
  sev = f"{emoji} **[{label.upper()}]**" if code != "N/A" else "⚪ **[N/A]**"

  if raw_display:
    sev = f"{sev} (`{raw_display}`)"
  elif show_sigma and z_equiv is not None:
    sev = f"{sev} (`{z_equiv:+.2f}σ`)"
  return sev, cri_fmt


def _visual_bar(cri: Optional[int]) -> str:
  c = max(0, min(100, 0 if cri is None else int(cri)))
  filled = max(1 if c > 0 else 0, round(c / 10))
  return "`" + ("█" * filled) + ("░" * (10 - filled)) + "`"


def _confidence_badge(active_samples: int) -> Tuple[str, str]:
  if active_samples >= 24:
    return "🟢 **HIGH CONFIDENCE**", f"Strong sample density (N = {active_samples} >= 24)."
  if active_samples >= 8:
    return "🟡 **MODERATE CONFIDENCE**", f"Moderate sample density (N = {active_samples})."
  return "🟠 **EARLY BASELINE**", f"Limited sample density (N = {active_samples})."


def _render_5section_helper_report(
    *,
    hunt_topic: str,
    model_title: str,
    formula_markdown: str,
    outliers: List[Dict[str, Any]],
    entity_universe_size: int,
    envelope_mu_str: str,
    envelope_sigma_str: str,
    pivot_filter: str,
    query_text: str,
    provenance: Dict[str, str],
    warnings: Sequence[str],
    show_sigma: bool,
) -> str:
  """Renders the canonical 5-Section Triage Report with D6 Guardrail G3 Provenance Appendix."""
  n_out = len(outliers)
  fleet_n = max(1, int(entity_universe_size))
  expected_max_z = round(math.sqrt(2.0 * math.log(max(2, fleet_n))), 2)

  lines: List[str] = [
      f"### ⚡ Statistical Outlier Report: {hunt_topic}",
      f"* **Outliers Detected**: {n_out} entities exceeded the anomaly threshold.",
      f"* **Normal Baseline Envelope**: Typical Average (μ) ≈ {envelope_mu_str} | Typical Variation (σ) ≈ ±{envelope_sigma_str}",
      f"* **Fleet Scaling**: Expected Gaussian maximum √(2 ln N) ≈ {expected_max_z:.2f}σ across N = {fleet_n} evaluated candidates.",
  ]
  for w in warnings:
    lines.append(f"* **Guardrail Notice**: ⚠️ {w}")

  lines.extend([
      "",
      "---",
      "#### 📊 Ranked Outlier Summary",
      "| Entity (Host / User / Pair) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |",
      "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
  ])

  if outliers:
    for row in outliers[:20]:
      conf_b, _ = _confidence_badge(int(row["baseline_active_samples"]))
      sev_b, cri_b = _severity_badge_from_cri(
          row["cri"],
          row.get("z_equiv"),
          show_sigma=show_sigma,
          raw_display=row["score_display"],
      )
      lines.append(
          f"| `{row['display_entity']}` | {row['window_label']} | **{row['observed_display']}** | "
          f"{row['baseline_display']} | {conf_b} | {sev_b} | {cri_b} | {_visual_bar(row['cri'])} |"
      )
  else:
    lines.append(
        "| `Nominal Baseline (0 Outliers)` | Full Window | **0 breaches** | "
        f"{envelope_mu_str} ± {envelope_sigma_str} | 🟢 **HIGH CONFIDENCE** | 🟢 **[NOMINAL]** (`0.00`) | 🟢 `[CRI: 0]` | `░░░░░░░░░░` |"
    )

  lines.extend(["", "---"])
  if outliers:
    top = outliers[0]
    conf_b, conf_desc = _confidence_badge(int(top["baseline_active_samples"]))
    sev_b, cri_b = _severity_badge_from_cri(
        top["cri"],
        top.get("z_equiv"),
        show_sigma=show_sigma,
        raw_display=top["score_display"],
    )
    prev_val = top.get("fleet_prevalence", -1)
    prev_str = "Unknown / N/A" if int(prev_val) < 0 else f"{int(prev_val)} peer(s)"
    lines.extend([
        f"#### 🔍 Top Outlier Spotlight: `{top['display_entity']}` — {sev_b} | {cri_b}",
        f"* **Data Confidence Level**: {conf_b} — {conf_desc}",
        "##### 🗣️ What Happened & Why It Matters (In Plain English)",
        top["narrative"],
        "##### 🏛️ Forensic Evidence Breakdown (6 Mandatory Evidence Pillars)",
        "| Evidence Pillar | Observed Value | What this Means for Your Investigation |",
        "| :--- | :--- | :--- |",
        f"| **1. Activity Spike** | `{top['observation_count']}` | Observed peak/score metric (`$observation_count`) |",
        f"| **2. Baseline History** | `{top['baseline_active_samples']}` | Historical active buckets/events evaluated (`$baseline_active_samples`) |",
        f"| **3. Typical Normal Level** | `{top['baseline_mean']:.4f}` | Expected baseline level (`$baseline_mean`) |",
        f"| **4. Normal Daily Spread** | `±{top['baseline_dispersion']:.4f}` | Empirical dispersion floor (`$baseline_dispersion`) |",
        f"| **5. Company-Wide Breadth** | `{prev_str}` | Enterprise-wide adoption/breadth (`$fleet_prevalence`) |",
        f"| **6. Variety of Programs** | `{top['distinct_binaries']} unique` | Distinct binaries/processes observed (`$distinct_binaries`) |",
    ])
  else:
    lines.extend([
        "#### 🔍 Top Outlier Spotlight: Nominal Baseline (0 Outliers Detected)",
        "* **Data Confidence Level**: 🟢 **NOMINAL** — Zero entities breached the control boundary.",
        "##### 🗣️ What Happened & Why It Matters (In Plain English)",
        f"Evaluated `{fleet_n}` candidate record(s) under **{model_title}** with zero threshold breaches (`CRI = 0`).",
        "##### 🏛️ Forensic Evidence Breakdown (6 Mandatory Evidence Pillars)",
        "| Evidence Pillar | Observed Value | What this Means for Your Investigation |",
        "| :--- | :--- | :--- |",
        "| **1. Activity Spike** | `0` | Zero anomalous breaches observed (`$observation_count`) |",
        f"| **2. Baseline History** | `{fleet_n}` | Evaluated cohort size (`$baseline_active_samples`) |",
        f"| **3. Typical Normal Level** | `{envelope_mu_str}` | Baseline mean (`$baseline_mean`) |",
        f"| **4. Normal Daily Spread** | `±{envelope_sigma_str}` | Baseline dispersion (`$baseline_dispersion`) |",
        "| **5. Company-Wide Breadth** | `Nominal` | Fleet-wide posture (`$fleet_prevalence`) |",
        "| **6. Variety of Programs** | `0 unique` | No anomalous binary spikes (`$distinct_binaries`) |",
    ])

  lines.extend([
      "",
      "---",
      "#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)",
      "*(Passive UDM filter for manual triage in Chronicle SIEM console. Use a ```text fence — NEVER ```yara.)*",
      "```text",
      pivot_filter,
      "```",
      "",
      "---",
      "<details>",
      "<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details & Provenance)</b></summary>",
      "",
      "##### 📐 Mathematical Model & Formulaic Derivations",
      f"* **Model**: {model_title}",
      f"* **Derivation**: {formula_markdown}",
      "",
      "##### 🎚️ Calibrated Risk Index (CRI) Sigmoid Normalization",
      "$$\\text{CRI}(Z_{\\text{eq}}) = \\begin{cases} 0 & Z_{\\text{eq}} \\le 0 \\\\ \\text{round}\\!\\left(\\frac{100}{1 + \\exp(-0.6 \\cdot (Z_{\\text{eq}} - 3.0))}\\right) & Z_{\\text{eq}} > 0 \\end{cases}$$",
      "",
      "##### 🔐 Provenance Appendix (D6 Guardrail G3)",
      f"* `helper_name`: `{provenance['helper_name']}`",
      f"* `helper_version`: `{provenance['helper_version']}`",
      f"* `query_sha256`: `{provenance['query_sha256']}`",
      f"* `payload_sha256`: `{provenance['payload_sha256']}`",
      "",
      "##### 📜 Verbatim Executed Multi-Stage YARA-L Query",
      "```yara",
      query_text.strip(),
      "```",
      "</details>",
  ])
  return "\n".join(lines) + "\n"


# ==============================================================================
# 1. WS6-02: EWMA Control Chart over Dense Zero-Filled Grid
# ==============================================================================
def run_ewma_helper(
    raw_payload: Union[str, bytes, Dict[str, Any]],
    *,
    query_text: str,
    start_time: str,
    end_time: str,
    lambda_weight: float = 0.25,
    control_l: float = 3.0,
    baseline_fraction: float = 0.50,
    min_baseline_buckets: int = 6,
    bucket_seconds: int = 3600,
    hunt_topic: str = "Intraday EWMA Rate Shift Hunt",
) -> Dict[str, Any]:
  """Evaluates Roberts/Lucas-Saccucci recursive EWMA over a dense zero-filled T-bucket grid (WS6-02)."""
  if not isinstance(lambda_weight, (int, float)) or not math.isfinite(lambda_weight) or not (0.0 < lambda_weight <= 1.0):
    raise ValueError(f"G2_INVALID_PARAM: lambda_weight must satisfy 0 < lambda <= 1, got {lambda_weight!r}")
  if not isinstance(control_l, (int, float)) or not math.isfinite(control_l) or control_l <= 0.0:
    raise ValueError(f"G2_INVALID_PARAM: control_l must be > 0, got {control_l!r}")
  if not isinstance(baseline_fraction, (int, float)) or not math.isfinite(baseline_fraction) or not (0.10 <= baseline_fraction < 1.0):
    raise ValueError(f"G2_INVALID_PARAM: baseline_fraction must be in [0.10, 1.0), got {baseline_fraction!r}")
  if int(min_baseline_buckets) < 2:
    raise ValueError(f"G2_INVALID_PARAM: min_baseline_buckets must be >= 2, got {min_baseline_buckets!r}")
  if int(bucket_seconds) < 60:
    raise ValueError(f"G2_INVALID_PARAM: bucket_seconds must be >= 60, got {bucket_seconds!r}")

  start_epoch = _parse_iso_utc_to_epoch(start_time, "start_time")
  end_epoch = _parse_iso_utc_to_epoch(end_time, "end_time")
  if end_epoch <= start_epoch:
    raise ValueError(f"G2_INVALID_TIME: end_time ({end_time}) must be strictly after start_time ({start_time}).")
  span = end_epoch - start_epoch
  if span % int(bucket_seconds) != 0:
    raise ValueError(
        f"G2_INVALID_TIME: window span ({span}s) is not an integer multiple of bucket_seconds ({bucket_seconds}s)."
    )
  total_buckets = span // int(bucket_seconds)
  if total_buckets < max(4, int(min_baseline_buckets) + 1):
    raise ValueError(
        f"G2_INVALID_TIME: window provides {total_buckets} buckets, need >= {max(4, int(min_baseline_buckets) + 1)}."
    )

  payload_bytes = _serialize_canonical_payload_bytes(raw_payload)
  provenance = build_provenance_block(query_text, payload_bytes, "ewma")
  rows = parse_strict_udm_stats_payload(raw_payload, string_columns={"entity", "host", "user", "src_ip"})

  baseline_buckets = max(int(min_baseline_buckets), min(total_buckets - 1, int(total_buckets * float(baseline_fraction))))
  per_entity_series: Dict[str, List[float]] = {}
  per_entity_procs: Dict[str, int] = {}
  per_entity_peers: Dict[str, int] = {}

  for r in rows:
    entity_val = r.get("entity") or r.get("host") or r.get("user") or r.get("src_ip")
    if entity_val is None or not str(entity_val).strip():
      raise ValueError(f"G2_MISSING_COLUMN: row missing non-empty entity column: {r!r}")
    ent = str(entity_val).strip()

    ws_raw = r.get("ws") if "ws" in r else r.get("window_start")
    if ws_raw is None:
      raise ValueError(f"G2_MISSING_COLUMN: row for {ent!r} missing `ws`/`window_start` bucket column.")
    ws_epoch = _parse_bucket_epoch(ws_raw)
    if ws_epoch < start_epoch or ws_epoch >= end_epoch:
      raise ValueError(
          f"G2_OUT_OF_WINDOW_BUCKET: bucket timestamp {ws_epoch} for {ent!r} falls outside [{start_epoch}, {end_epoch})."
      )
    idx = (ws_epoch - start_epoch) // int(bucket_seconds)

    cnt_raw = (
        r.get("window_events")
        if "window_events" in r
        else (r.get("observation_count") if "observation_count" in r else r.get("count"))
    )
    if cnt_raw is None:
      raise ValueError(f"G2_MISSING_COLUMN: row for {ent!r} missing `window_events`/`observation_count`.")
    cnt = float(cnt_raw)
    if not math.isfinite(cnt) or cnt < 0.0:
      raise ValueError(f"G2_INVALID_COUNT: negative or non-finite count {cnt_raw!r} for {ent!r}.")

    series = per_entity_series.setdefault(ent, [0.0] * total_buckets)
    series[idx] += cnt
    if r.get("distinct_binaries") is not None:
      per_entity_procs[ent] = max(per_entity_procs.get(ent, 0), int(float(r["distinct_binaries"])))
    if r.get("fleet_prevalence") is not None:
      per_entity_peers[ent] = max(per_entity_peers.get(ent, -1), int(float(r["fleet_prevalence"])))

  entity_results: List[Dict[str, Any]] = []
  asymp_factor = math.sqrt(float(lambda_weight) / (2.0 - float(lambda_weight)))

  for ent in sorted(per_entity_series.keys()):
    series = per_entity_series[ent]
    base_slice = series[:baseline_buckets]
    mu_0 = sum(base_slice) / float(baseline_buckets)
    if baseline_buckets > 1:
      var_0 = sum((v - mu_0) ** 2 for v in base_slice) / float(baseline_buckets - 1)
      s_0 = math.sqrt(max(0.0, var_0))
    else:
      s_0 = 0.0
    poisson_floor = max(math.sqrt(max(mu_0, 1.0)), 1.0)
    sigma_0 = max(s_0, poisson_floor)
    sigma_ewma = sigma_0 * asymp_factor
    ucl = mu_0 + float(control_l) * sigma_ewma

    s_prev = mu_0
    peak_ewma_z = -math.inf
    peak_ewma_val = mu_0
    peak_idx = baseline_buckets
    peak_obs = 0.0
    max_single_z = -math.inf
    ucl_exact_at_peak = ucl

    for idx in range(baseline_buckets, total_buckets):
      step_k = idx - baseline_buckets + 1
      x_t = series[idx]
      s_cur = float(lambda_weight) * x_t + (1.0 - float(lambda_weight)) * s_prev
      ewma_z_t = (s_cur - mu_0) / sigma_ewma
      single_z_t = (x_t - mu_0) / sigma_0
      if single_z_t > max_single_z:
        max_single_z = single_z_t
      if ewma_z_t > peak_ewma_z:
        peak_ewma_z = ewma_z_t
        peak_ewma_val = s_cur
        peak_idx = idx
        peak_obs = x_t
        step_sigma = sigma_0 * asymp_factor * math.sqrt(1.0 - (1.0 - float(lambda_weight)) ** (2 * step_k))
        ucl_exact_at_peak = mu_0 + float(control_l) * step_sigma
      s_prev = s_cur

    z_eq = uc.score_to_z_equivalent("ewma_z", peak_ewma_z, threshold_override=float(control_l))
    cri_val = uc.cri_from_model_score("ewma_z", peak_ewma_z, threshold_override=float(control_l))
    active_total = sum(1 for v in series if v > 0.0)
    peak_iso = _epoch_to_iso_utc(start_epoch + peak_idx * int(bucket_seconds))

    is_outlier = peak_ewma_z >= float(control_l)
    if is_outlier:
      ewma_narrative = (
          f"Entity `{ent}` sustained an elevated post-baseline trajectory reaching `EWMA = {peak_ewma_val:.2f}` "
          f"at `{peak_iso}`, breaching the Roberts/Lucas-Saccucci control limit `UCL = {ucl:.2f}` "
          f"(`ewma_z = {peak_ewma_z:+.2f}σ`, peak single-bucket Z `{max_single_z:+.2f}σ`, `CRI = {cri_val}`)."
      )
    else:
      ewma_narrative = (
          f"Entity `{ent}` remained within the Roberts/Lucas-Saccucci control limit `UCL = {ucl:.2f}`, "
          f"reaching peak `EWMA = {peak_ewma_val:.2f}` at `{peak_iso}` "
          f"(`ewma_z = {peak_ewma_z:+.2f}σ`, peak single-bucket Z `{max_single_z:+.2f}σ`, `CRI = {cri_val}`)."
      )

    rec = {
        "entity": ent,
        "display_entity": ent,
        "window_label": peak_iso,
        "ewma_z": round(peak_ewma_z, 6),
        "peak_ewma": round(peak_ewma_val, 6),
        "ucl": round(ucl, 6),
        "ucl_exact_step": round(ucl_exact_at_peak, 6),
        "sigma_ewma": round(sigma_ewma, 6),
        "max_single_bucket_z": round(max_single_z, 6),
        "z_equiv": round(z_eq, 6) if z_eq is not None else None,
        "cri": cri_val,
        "observation_count": int(round(peak_obs)),
        "baseline_active_samples": baseline_buckets,
        "active_buckets_observed": active_total,
        "total_grid_buckets": total_buckets,
        "baseline_mean": round(mu_0, 6),
        "baseline_dispersion": round(sigma_0, 6),
        "fleet_prevalence": per_entity_peers.get(ent, -1),
        "distinct_binaries": per_entity_procs.get(ent, 1),
        "observed_display": f"EWMA={peak_ewma_val:.2f} (obs={int(round(peak_obs))})",
        "baseline_display": f"{mu_0:.2f} ± {sigma_0:.2f} (UCL={ucl:.2f})",
        "score_display": f"{peak_ewma_z:+.2f}σ EWMA",
        "narrative": ewma_narrative,
    }
    entity_results.append(rec)

  outliers = sorted(
      [r for r in entity_results if r["ewma_z"] >= float(control_l)],
      key=lambda item: item["ewma_z"],
      reverse=True,
  )

  env_mu = f"{statistics.mean([r['baseline_mean'] for r in entity_results]):.2f}" if entity_results else "0.00"
  env_sd = f"{statistics.mean([r['baseline_dispersion'] for r in entity_results]):.2f}" if entity_results else "0.00"
  top_ent = outliers[0]["entity"] if outliers else "<entity>"
  pivot_entity_field, pivot_event_type = _extract_pivot_fields_from_query(query_text)
  report_md = _render_5section_helper_report(
      hunt_topic=hunt_topic,
      model_title=f"Exponentially Weighted Moving Average Control Chart (λ={lambda_weight}, L={control_l})",
      formula_markdown=(
          f"$S_t = \\lambda x_t + (1-\\lambda) S_{{t-1}}$, "
          f"$\\sigma_{{\\text{{EWMA}}}} = \\sigma_0 \\sqrt{{\\lambda/(2-\\lambda)}}$, "
          f"$\\text{{UCL}} = \\mu_0 + {control_l}\\,\\sigma_{{\\text{{EWMA}}}}$ over dense $T={total_buckets}$ grid"
      ),
      outliers=outliers,
      entity_universe_size=len(entity_results),
      envelope_mu_str=env_mu,
      envelope_sigma_str=env_sd,
      pivot_filter=f'{pivot_entity_field} = "{top_ent}" AND metadata.event_type = "{pivot_event_type}"',
      query_text=query_text,
      provenance=provenance,
      warnings=[],
      show_sigma=True,
  )

  return {
      "model": "EWMA_BURST_VELOCITY",
      "status": "OK" if entity_results else "NOMINAL_EMPTY_PAYLOAD",
      "parameters": {
          "start_time": start_time,
          "end_time": end_time,
          "lambda_weight": float(lambda_weight),
          "control_l": float(control_l),
          "total_grid_buckets": total_buckets,
          "baseline_buckets": baseline_buckets,
          "bucket_seconds": int(bucket_seconds),
      },
      "entity_results": entity_results,
      "outliers": outliers,
      "warnings": [],
      "provenance": provenance,
      "report_markdown": report_md,
  }


# ==============================================================================
# 2. WS6-03: Per-Character Shannon Entropy vs Length-Matched Benign Cohort
# ==============================================================================
def compute_shannon_entropy_bits(text: str) -> float:
  """Computes exact per-character Shannon entropy H(s) = -sum p(c) log2 p(c) in bits/char."""
  if not text:
    return 0.0
  n = len(text)
  counts = Counter(text)
  return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())


def run_shannon_helper(
    raw_payload: Union[str, bytes, Dict[str, Any]],
    *,
    query_text: str,
    min_length: int = 25,
    benign_min_prevalence: int = 3,
    candidate_max_prevalence: int = 2,
    z_threshold: float = 3.0,
    min_benign_peers: int = 5,
    length_band_low: float = 0.65,
    length_band_high: float = 1.50,
    entropy_sd_floor: float = 0.15,
    hunt_topic: str = "Length-Normalized Shannon Character Entropy Hunt",
) -> Dict[str, Any]:
  """Evaluates exact per-character Shannon entropy against length-matched benign strings (WS6-03)."""
  if int(min_length) < 1:
    raise ValueError(f"G2_INVALID_PARAM: min_length must be >= 1, got {min_length!r}")
  if int(benign_min_prevalence) < 2:
    raise ValueError(f"G2_INVALID_PARAM: benign_min_prevalence must be >= 2, got {benign_min_prevalence!r}")
  if int(candidate_max_prevalence) < 1 or int(candidate_max_prevalence) >= int(benign_min_prevalence):
    raise ValueError(
        f"G2_INVALID_PARAM: candidate_max_prevalence ({candidate_max_prevalence}) must satisfy "
        f"1 <= candidate_max_prevalence < benign_min_prevalence ({benign_min_prevalence})."
    )
  if not isinstance(z_threshold, (int, float)) or not math.isfinite(z_threshold) or z_threshold <= 0.0:
    raise ValueError(f"G2_INVALID_PARAM: z_threshold must be > 0, got {z_threshold!r}")
  if int(min_benign_peers) < 3:
    raise ValueError(f"G2_INVALID_PARAM: min_benign_peers must be >= 3, got {min_benign_peers!r}")
  if not (0.10 <= float(length_band_low) < 1.0 < float(length_band_high) <= 4.0):
    raise ValueError("G2_INVALID_PARAM: length_band must bracket 1.0 within [0.10, 4.0].")
  if not isinstance(entropy_sd_floor, (int, float)) or not math.isfinite(entropy_sd_floor) or entropy_sd_floor <= 0.0:
    raise ValueError(f"G2_INVALID_PARAM: entropy_sd_floor must be > 0, got {entropy_sd_floor!r}")

  payload_bytes = _serialize_canonical_payload_bytes(raw_payload)
  provenance = build_provenance_block(query_text, payload_bytes, "shannon")
  rows = parse_strict_udm_stats_payload(
      raw_payload,
      string_columns={"token", "entity", "host", "user", "sample_entities", "candidate_tokens"},
  )

  # Normalize both token-centric `(token, sample_entities, host_prevalence)` and
  # entity-centric `(entity, candidate_tokens, ...)` payload shapes.
  token_map: Dict[str, Dict[str, Any]] = {}
  for r in rows:
    if "token" in r and r["token"] is not None:
      tok = str(r["token"])
      if len(tok) < int(min_length):
        continue
      raw_ents = r.get("sample_entities")
      if isinstance(raw_ents, list):
        ents = [str(e) for e in raw_ents if str(e).strip()]
      elif r.get("entity") is not None:
        ents = [str(r["entity"])]
      else:
        ents = ["unknown"]
      prev_raw = r.get("host_prevalence") if "host_prevalence" in r else r.get("fleet_prevalence")
      prev = int(float(prev_raw)) if prev_raw is not None else max(1, len(set(ents)))
      ev_raw = r.get("token_events") if "token_events" in r else r.get("observation_count", 1)
      ev_cnt = max(1, int(float(ev_raw))) if ev_raw is not None else 1
      procs = max(1, int(float(r["distinct_binaries"]))) if r.get("distinct_binaries") is not None else 1

      entry = token_map.setdefault(
          tok,
          {"token": tok, "entities": [], "host_prevalence": 0, "token_events": 0, "distinct_binaries": 1},
      )
      for e in ents:
        if e not in entry["entities"]:
          entry["entities"].append(e)
      entry["host_prevalence"] = max(entry["host_prevalence"], prev)
      entry["token_events"] += ev_cnt
      entry["distinct_binaries"] = max(entry["distinct_binaries"], procs)
    elif "candidate_tokens" in r and isinstance(r["candidate_tokens"], list):
      ent_str = str(r.get("entity") or r.get("host") or "unknown")
      for raw_tok in r["candidate_tokens"]:
        tok = str(raw_tok)
        if len(tok) < int(min_length):
          continue
        entry = token_map.setdefault(
            tok,
            {"token": tok, "entities": [], "host_prevalence": 0, "token_events": 0, "distinct_binaries": 1},
        )
        if ent_str not in entry["entities"]:
          entry["entities"].append(ent_str)
        entry["host_prevalence"] = max(entry["host_prevalence"], len(entry["entities"]))
        entry["token_events"] += 1
    else:
      raise ValueError(f"G2_MISSING_COLUMN: row lacks `token` or `candidate_tokens` column: {r!r}")

  benign_records: List[Dict[str, Any]] = []
  raw_candidates: List[Dict[str, Any]] = []
  for tok, info in token_map.items():
    h_bits = compute_shannon_entropy_bits(tok)
    item = {
        "token": tok,
        "length": len(tok),
        "entropy_bits": h_bits,
        "entities": info["entities"],
        "entity": info["entities"][0] if info["entities"] else "unknown",
        "host_prevalence": info["host_prevalence"],
        "token_events": info["token_events"],
        "distinct_binaries": info["distinct_binaries"],
    }
    if info["host_prevalence"] >= int(benign_min_prevalence):
      benign_records.append(item)
    elif info["host_prevalence"] <= int(candidate_max_prevalence):
      raw_candidates.append(item)

  if raw_candidates and len(benign_records) < 3:
    raise ValueError(
        f"INSUFFICIENT_BENIGN_LENGTH_COHORT: found {len(benign_records)} benign strings "
        f"(host_prevalence >= {benign_min_prevalence}), need >= 3 to standardize {len(raw_candidates)} candidate(s)."
    )

  warnings: List[str] = []
  fallback_count = 0
  candidate_results: List[Dict[str, Any]] = []

  for cand in raw_candidates:
    tok_len = cand["length"]
    lo = float(length_band_low) * tok_len
    hi = float(length_band_high) * tok_len
    peers = [b for b in benign_records if lo <= b["length"] <= hi]
    if len(peers) >= int(min_benign_peers):
      cohort = peers
      cohort_mode = "length_matched"
    else:
      cohort = benign_records
      cohort_mode = "corpus_fallback"
      fallback_count += 1

    h_vals = [p["entropy_bits"] for p in cohort]
    mean_h = sum(h_vals) / float(len(h_vals))
    if len(h_vals) > 1:
      var_h = sum((v - mean_h) ** 2 for v in h_vals) / float(len(h_vals) - 1)
      sd_h = math.sqrt(max(0.0, var_h))
    else:
      sd_h = 0.0
    eff_sd = max(sd_h, float(entropy_sd_floor))
    shannon_z = (cand["entropy_bits"] - mean_h) / eff_sd

    z_eq = uc.score_to_z_equivalent("shannon_z", shannon_z, threshold_override=float(z_threshold))
    cri_val = uc.cri_from_model_score("shannon_z", shannon_z, threshold_override=float(z_threshold))
    preview_tok = cand["token"] if len(cand["token"]) <= 48 else cand["token"][:45] + "..."

    is_shannon_outlier = shannon_z >= float(z_threshold)
    threshold_clause = (
        f"exceeding the `{z_threshold:.2f}σ` threshold against"
        if is_shannon_outlier
        else f"within the `{z_threshold:.2f}σ` threshold against"
    )

    candidate_results.append({
        "entity": cand["entity"],
        "sample_entities": cand["entities"],
        "token": cand["token"],
        "display_entity": f"{cand['entity']} :: {preview_tok}",
        "window_label": f"len={tok_len}",
        "length": tok_len,
        "entropy_bits": round(cand["entropy_bits"], 6),
        "cohort_mode": cohort_mode,
        "cohort_size": len(cohort),
        "cohort_mean_entropy": round(mean_h, 6),
        "cohort_sd_entropy": round(eff_sd, 6),
        "shannon_z": round(shannon_z, 6),
        "z_equiv": round(z_eq, 6) if z_eq is not None else None,
        "cri": cri_val,
        "observation_count": tok_len,
        "baseline_active_samples": len(cohort),
        "baseline_mean": round(mean_h, 6),
        "baseline_dispersion": round(eff_sd, 6),
        "fleet_prevalence": cand["host_prevalence"],
        "distinct_binaries": cand["distinct_binaries"],
        "observed_display": f"{cand['entropy_bits']:.2f} bits/ch (len={tok_len})",
        "baseline_display": f"{mean_h:.2f} ± {eff_sd:.2f} bits/ch",
        "score_display": f"{shannon_z:+.2f}σ H",
        "narrative": (
            f"Rare string on `{cand['entity']}` (`host_prevalence = {cand['host_prevalence']}`, length `{tok_len}`) "
            f"measured `{cand['entropy_bits']:.2f}` bits/char, {threshold_clause} `{mean_h:.2f} ± {eff_sd:.2f}` bits/char "
            f"across `{len(cohort)}` `{cohort_mode}` benign reference strings (`shannon_z = {shannon_z:+.2f}σ`, `CRI = {cri_val}`)."
        ),
    })

  if fallback_count > 0:
    warnings.append(
        f"cohort_mode=corpus_fallback used for {fallback_count} candidate(s) with < {min_benign_peers} "
        f"length-matched benign peers in [{length_band_low:.2f}*L, {length_band_high:.2f}*L]."
    )

  candidate_results.sort(key=lambda item: item["shannon_z"], reverse=True)
  outliers = [c for c in candidate_results if c["shannon_z"] >= float(z_threshold)]

  env_mu = f"{statistics.mean([b['entropy_bits'] for b in benign_records]):.2f} bits/ch" if benign_records else "0.00 bits/ch"
  env_sd = (
      f"{max(statistics.stdev([b['entropy_bits'] for b in benign_records]) if len(benign_records) > 1 else 0.0, float(entropy_sd_floor)):.2f} bits/ch"
      if benign_records
      else "0.00 bits/ch"
  )
  top_ent = outliers[0]["entity"] if outliers else "<entity>"
  pivot_entity_field, pivot_event_type = _extract_pivot_fields_from_query(query_text)
  report_md = _render_5section_helper_report(
      hunt_topic=hunt_topic,
      model_title="Length-Normalized Per-Character Shannon Entropy (H bits/char)",
      formula_markdown=(
          "$H(s) = -\\sum_c p(c)\\log_2 p(c)$, "
          f"$Z_H = (H(s) - \\mu_{{H,\\text{{benign}}(L)}}) / \\max(\\sigma_{{H,\\text{{benign}}(L)}}, {entropy_sd_floor})$"
      ),
      outliers=outliers,
      entity_universe_size=max(1, len(candidate_results)),
      envelope_mu_str=env_mu,
      envelope_sigma_str=env_sd,
      pivot_filter=f'{pivot_entity_field} = "{top_ent}" AND metadata.event_type = "{pivot_event_type}"',
      query_text=query_text,
      provenance=provenance,
      warnings=warnings,
      show_sigma=True,
  )

  return {
      "model": "SHANNON_ENTROPY_CHARACTER",
      "status": "OK" if rows else "NOMINAL_EMPTY_PAYLOAD",
      "parameters": {
          "min_length": int(min_length),
          "benign_min_prevalence": int(benign_min_prevalence),
          "candidate_max_prevalence": int(candidate_max_prevalence),
          "z_threshold": float(z_threshold),
          "min_benign_peers": int(min_benign_peers),
      },
      "benign_cohort_count": len(benign_records),
      "candidate_results": candidate_results,
      "outliers": outliers,
      "warnings": warnings,
      "provenance": provenance,
      "report_markdown": report_md,
  }


# ==============================================================================
# 3. WS6-04: C2 Consecutive Inter-Arrival Jitter & Periodicity
# ==============================================================================
def run_c2_jitter_helper(
    raw_payload: Union[str, bytes, Dict[str, Any]],
    *,
    query_text: str,
    max_cv: float = 0.20,
    min_intervals: int = 4,
    near_median_tolerance: float = 0.25,
    hunt_topic: str = "C2 Inter-Arrival Jitter & Periodicity Hunt",
) -> Dict[str, Any]:
  """Computes consecutive inter-arrival CV and periodicity across stitched hourly timestamp arrays (WS6-04)."""
  # ueba_constants "cv" has inverted_ratio neutral = 0.50; max_cv must lie strictly inside (0, 0.50).
  if not isinstance(max_cv, (int, float)) or not math.isfinite(max_cv) or not (0.0 < float(max_cv) < 0.50):
    raise ValueError(f"G2_INVALID_PARAM: max_cv must satisfy 0.0 < max_cv < 0.50, got {max_cv!r}")
  if int(min_intervals) < 2:
    raise ValueError(f"G2_INVALID_PARAM: min_intervals must be >= 2, got {min_intervals!r}")
  if not isinstance(near_median_tolerance, (int, float)) or not (0.0 < float(near_median_tolerance) < 1.0):
    raise ValueError(f"G2_INVALID_PARAM: near_median_tolerance must be in (0, 1), got {near_median_tolerance!r}")

  payload_bytes = _serialize_canonical_payload_bytes(raw_payload)
  provenance = build_provenance_block(query_text, payload_bytes, "c2-jitter")
  rows = parse_strict_udm_stats_payload(raw_payload, string_columns={"src_ip", "dst_ip", "entity", "ws"})

  grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
  for r in rows:
    src = r.get("src_ip") or r.get("entity")
    dst = r.get("dst_ip")
    if src is None or dst is None or not str(src).strip() or not str(dst).strip():
      raise ValueError(f"G2_MISSING_COLUMN: row missing non-empty `src_ip`/`dst_ip`: {r!r}")
    pair_key = (str(src).strip(), str(dst).strip())

    raw_ts_list = r.get("event_timestamps")
    if not isinstance(raw_ts_list, list):
      raise ValueError(f"G2_MISSING_COLUMN: row for {pair_key} missing `event_timestamps` list column.")

    parsed_ts: List[float] = []
    for t in raw_ts_list:
      try:
        tf = float(t)
      except (TypeError, ValueError) as exc:
        raise ValueError(f"G2_MALFORMED_TIMESTAMP: invalid timestamp {t!r} for {pair_key}") from exc
      if not math.isfinite(tf) or tf <= 0.0:
        raise ValueError(f"G2_MALFORMED_TIMESTAMP: non-positive or non-finite timestamp {t!r} for {pair_key}")
      parsed_ts.append(tf)

    bucket_conns = int(float(r["bucket_conns"])) if r.get("bucket_conns") is not None else len(parsed_ts)
    hit_cap = len(parsed_ts) >= ARRAY_DISTINCT_CAP or (
        len(parsed_ts) >= ARRAY_DISTINCT_CAP and bucket_conns > len(parsed_ts)
    )

    g = grouped.setdefault(
        pair_key,
        {
            "timestamps": [],
            "cap_hit": False,
            "capped_buckets": 0,
            "total_conns": 0,
            "active_hours": 0,
            "fleet_prevalence": -1,
            "distinct_binaries": 1,
        },
    )
    g["timestamps"].extend(parsed_ts)
    if hit_cap:
      g["cap_hit"] = True
      g["capped_buckets"] += 1
    if r.get("total_conns") is not None:
      g["total_conns"] = max(g["total_conns"], int(float(r["total_conns"])))
    else:
      g["total_conns"] += bucket_conns
    if r.get("active_hours") is not None:
      g["active_hours"] = max(g["active_hours"], int(float(r["active_hours"])))
    else:
      g["active_hours"] += 1
    if r.get("fleet_prevalence") is not None:
      g["fleet_prevalence"] = max(g["fleet_prevalence"], int(float(r["fleet_prevalence"])))
    if r.get("distinct_binaries") is not None:
      g["distinct_binaries"] = max(g["distinct_binaries"], int(float(r["distinct_binaries"])))

  pair_results: List[Dict[str, Any]] = []
  skipped_insufficient: List[Dict[str, Any]] = []
  warnings: List[str] = []
  capped_pairs: List[str] = []

  for (src_ip, dst_ip), info in sorted(grouped.items()):
    ts_sorted = sorted(set(info["timestamps"]))
    if len(ts_sorted) - 1 < int(min_intervals):
      skipped_insufficient.append({
          "src_ip": src_ip,
          "dst_ip": dst_ip,
          "distinct_timestamps": len(ts_sorted),
          "intervals": max(0, len(ts_sorted) - 1),
      })
      continue

    deltas = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
    m_int = len(deltas)
    mean_dt = sum(deltas) / float(m_int)
    var_dt = sum((d - mean_dt) ** 2 for d in deltas) / float(m_int - 1)
    sd_dt = math.sqrt(max(0.0, var_dt))
    cv = sd_dt / mean_dt

    med_dt = float(statistics.median(deltas))
    mad_dt = float(statistics.median([abs(d - med_dt) for d in deltas]))
    robust_cv = (1.4826 * mad_dt) / med_dt if med_dt > 0.0 else cv

    tol = float(near_median_tolerance)
    near_cnt = sum(1 for d in deltas if (1.0 - tol) * med_dt <= d <= (1.0 + tol) * med_dt)
    frac_near_med = near_cnt / float(m_int)

    if m_int >= 3 and sd_dt > 0.0:
      num_ac = sum((deltas[i] - mean_dt) * (deltas[i + 1] - mean_dt) for i in range(m_int - 1))
      den_ac = sum((d - mean_dt) ** 2 for d in deltas)
      lag1_ac = max(-1.0, min(1.0, num_ac / den_ac)) if den_ac > 0.0 else 0.0
    else:
      lag1_ac = 0.0

    periodicity_score = max(0.0, min(1.0, 0.5 * (1.0 - min(cv, 1.0)) + 0.5 * frac_near_med))
    z_eq = uc.score_to_z_equivalent("cv", cv, threshold_override=float(max_cv))
    cri_val = uc.cri_from_model_score("cv", cv, threshold_override=float(max_cv))

    if info["cap_hit"]:
      capped_pairs.append(f"{src_ip} -> {dst_ip}")

    cap_note = " (⚠️ array_distinct 25-element bucket cap hit)" if info["cap_hit"] else ""
    is_c2_outlier = cv <= float(max_cv)
    if is_c2_outlier:
      c2_narrative = (
          f"External pair `{src_ip} -> {dst_ip}` exhibited clockwork callback regularity across `{m_int}` "
          f"consecutive intervals (`Δt = {mean_dt:.1f}s ± {sd_dt:.1f}s`, `CV = {cv:.3f} <= {max_cv:.2f}`, "
          f"`{frac_near_med * 100:.0f}%` within ±{int(tol * 100)}% of median `{med_dt:.1f}s`, `CRI = {cri_val}`){cap_note}."
      )
    else:
      c2_narrative = (
          f"External pair `{src_ip} -> {dst_ip}` remained irregular across `{m_int}` "
          f"consecutive intervals (`Δt = {mean_dt:.1f}s ± {sd_dt:.1f}s`, `CV = {cv:.3f} > {max_cv:.2f}`, "
          f"`{frac_near_med * 100:.0f}%` within ±{int(tol * 100)}% of median `{med_dt:.1f}s`, `CRI = {cri_val}`){cap_note}."
      )

    pair_results.append({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "display_entity": f"{src_ip} -> {dst_ip}",
        "window_label": f"{info['active_hours']}h active",
        "interval_count": m_int,
        "distinct_timestamps": len(ts_sorted),
        "mean_delta_seconds": round(mean_dt, 6),
        "sd_delta_seconds": round(sd_dt, 6),
        "median_delta_seconds": round(med_dt, 6),
        "cv": round(cv, 6),
        "robust_cv": round(robust_cv, 6),
        "fraction_near_median": round(frac_near_med, 6),
        "lag1_autocorr": round(lag1_ac, 6),
        "periodicity_score": round(periodicity_score, 6),
        "array_distinct_cap_hit": bool(info["cap_hit"]),
        "capped_buckets": int(info["capped_buckets"]),
        "z_equiv": round(z_eq, 6) if z_eq is not None else None,
        "cri": cri_val,
        "observation_count": max(info["total_conns"], len(ts_sorted)),
        "baseline_active_samples": info["active_hours"],
        "baseline_mean": round(mean_dt, 6),
        "baseline_dispersion": round(sd_dt, 6),
        "fleet_prevalence": info["fleet_prevalence"],
        "distinct_binaries": info["distinct_binaries"],
        "observed_display": f"CV={cv:.3f} (periodicity={periodicity_score:.2f})",
        "baseline_display": f"Δt={mean_dt:.1f}s ± {sd_dt:.1f}s",
        "score_display": f"CV={cv:.3f}",
        "narrative": c2_narrative,
    })

  if capped_pairs:
    warnings.append(
        f"Chronicle `array_distinct` {ARRAY_DISTINCT_CAP}-element per-bucket cap reached on "
        f"{len(capped_pairs)} pair(s) ({', '.join(capped_pairs[:5])}); sub-bucket intervals in saturated hours may be subsampled."
    )

  pair_results.sort(key=lambda item: item["cv"])
  outliers = [p for p in pair_results if p["cv"] <= float(max_cv)]

  env_mu = f"{statistics.mean([p['mean_delta_seconds'] for p in pair_results]):.1f}s" if pair_results else "0.0s"
  env_sd = f"{statistics.mean([p['sd_delta_seconds'] for p in pair_results]):.1f}s" if pair_results else "0.0s"
  _, c2_event_type = _extract_pivot_fields_from_query(query_text, default_event_type="NETWORK_CONNECTION")
  if outliers:
    pivot = (
        f'principal.ip = "{outliers[0]["src_ip"]}" AND target.ip = "{outliers[0]["dst_ip"]}" '
        f'AND metadata.event_type = "{c2_event_type}"'
    )
  else:
    pivot = f'metadata.event_type = "{c2_event_type}"'

  report_md = _render_5section_helper_report(
      hunt_topic=hunt_topic,
      model_title=f"Consecutive Inter-Arrival Jitter & Periodicity (CV <= {max_cv:.2f})",
      formula_markdown=(
          "$\\Delta t_i = t_{i+1} - t_i$, $\\text{CV} = \\sigma_{\\Delta t} / \\mu_{\\Delta t}$, "
          "$Z_{\\text{eq}} = 3.0 \\cdot (0.50 - \\text{CV}) / (0.50 - \\text{CV}_{\\text{thresh}})$"
      ),
      outliers=outliers,
      entity_universe_size=max(1, len(pair_results)),
      envelope_mu_str=env_mu,
      envelope_sigma_str=env_sd,
      pivot_filter=pivot,
      query_text=query_text,
      provenance=provenance,
      warnings=warnings,
      show_sigma=False,
  )

  return {
      "model": "C2_BEACONING_JITTER",
      "status": "OK" if rows else "NOMINAL_EMPTY_PAYLOAD",
      "parameters": {
          "max_cv": float(max_cv),
          "min_intervals": int(min_intervals),
          "near_median_tolerance": float(near_median_tolerance),
          "array_distinct_cap": ARRAY_DISTINCT_CAP,
      },
      "pair_results": pair_results,
      "skipped_insufficient_intervals": skipped_insufficient,
      "outliers": outliers,
      "warnings": warnings,
      "provenance": provenance,
      "report_markdown": report_md,
  }


# ==============================================================================
# Optional Live ADC Query Runner + CLI Entrypoint (Fail-Closed Exit Code 2)
# ==============================================================================
def _execute_udm_search_adc(
    query: str,
    start_time: str,
    end_time: str,
    *,
    customer_id: str = DEFAULT_CUSTOMER_ID,
    project_id: str = DEFAULT_PROJECT_ID,
    region: str = DEFAULT_REGION,
    limit: int = 1000,
) -> bytes:
  """Executes a single read-only Chronicle udmSearch REST request via gcloud ADC."""
  token_proc = subprocess.run(
      ["gcloud", "auth", "application-default", "print-access-token"],
      check=True,
      capture_output=True,
      text=True,
      timeout=15,
  )
  token = token_proc.stdout.strip()
  host = f"{region}-chronicle.googleapis.com" if region and region != "us" else "chronicle.googleapis.com"
  base_url = (
      f"https://{host}/v1alpha/projects/{project_id}/locations/{region}"
      f"/instances/{customer_id}:udmSearch"
  )
  params = urllib.parse.urlencode({
      "query": query,
      "timeRange.startTime": start_time,
      "timeRange.endTime": end_time,
      "limit": limit,
  })
  req = urllib.request.Request(
      f"{base_url}?{params}",
      headers={
          "Authorization": f"Bearer {token}",
          "x-goog-user-project": project_id,
          "Accept": "application/json",
      },
      method="GET",
  )
  try:
    with urllib.request.urlopen(req, timeout=90) as resp:
      return resp.read()
  except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    raise ValueError(f"G2_BACKEND_ERROR_PAYLOAD: HTTP {exc.code} from udmSearch: {body}") from exc


def _add_common_io_args(sub: argparse.ArgumentParser) -> None:
  sub.add_argument("--query-file", type=Path, required=True, help="Path to verbatim executed YARA-L 2.0 query file.")
  sub.add_argument("--payload-file", type=Path, default=None, help="Path to raw udm_search JSON response file.")
  sub.add_argument("--run-query", action="store_true", help="Execute --query-file via Chronicle ADC REST instead of reading --payload-file.")
  sub.add_argument("--save-payload", type=Path, default=None, help="Optional path to save raw udm_search JSON when --run-query is set.")
  sub.add_argument("--output-json", type=Path, default=None, help="Optional path to write full structured JSON output.")
  sub.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Stdout output format.")
  sub.add_argument("--customer-id", default=os.environ.get("SECOPS_CUSTOMER_ID", DEFAULT_CUSTOMER_ID))
  sub.add_argument("--project-id", default=os.environ.get("SECOPS_PROJECT_ID", DEFAULT_PROJECT_ID))
  sub.add_argument("--region", default=os.environ.get("SECOPS_REGION", DEFAULT_REGION))


def _load_query_and_payload(args: argparse.Namespace) -> Tuple[str, bytes]:
  if not args.query_file.exists():
    raise ValueError(f"G2_MISSING_QUERY_FILE: query file does not exist: {args.query_file}")
  query_text = args.query_file.read_text(encoding="utf-8")
  if not query_text.strip():
    raise ValueError(f"G2_EMPTY_QUERY: query file is empty: {args.query_file}")

  if args.run_query:
    st = getattr(args, "start_time", None)
    et = getattr(args, "end_time", None)
    if not st or not et:
      raise ValueError("G2_INVALID_TIME: --run-query requires both --start-time and --end-time.")
    payload_bytes = _execute_udm_search_adc(
        query_text,
        st,
        et,
        customer_id=args.customer_id,
        project_id=args.project_id,
        region=args.region,
    )
    if args.save_payload is not None:
      args.save_payload.parent.mkdir(parents=True, exist_ok=True)
      args.save_payload.write_bytes(payload_bytes)
    return query_text, payload_bytes

  if args.payload_file is None:
    raise ValueError("G2_MISSING_PAYLOAD_FILE: --payload-file is required unless --run-query is set.")
  if not args.payload_file.exists():
    raise ValueError(f"G2_MISSING_PAYLOAD_FILE: payload file does not exist: {args.payload_file}")
  payload_bytes = args.payload_file.read_bytes()
  if not payload_bytes.strip():
    raise ValueError(f"G2_EMPTY_PAYLOAD: payload file is empty: {args.payload_file}")
  return query_text, payload_bytes


def main(argv: Optional[Sequence[str]] = None) -> int:
  """CLI entrypoint enforcing D6 Guardrails G1-G3 with fail-closed exit code 2."""
  parser = argparse.ArgumentParser(
      prog="micro_python_helpers.py",
      description="Vetted micro-plane statistical helpers over raw Chronicle udm_search stats payloads (WS6-02..04).",
  )
  subparsers = parser.add_subparsers(dest="subcommand", required=True)

  p_ewma = subparsers.add_parser("ewma", help="WS6-02 recursive EWMA control chart over dense zero-filled hourly grid.")
  _add_common_io_args(p_ewma)
  p_ewma.add_argument("--start-time", required=True, help="Search window start ISO-8601 UTC timestamp.")
  p_ewma.add_argument("--end-time", required=True, help="Search window end ISO-8601 UTC timestamp.")
  p_ewma.add_argument("--lambda-weight", type=float, default=0.25)
  p_ewma.add_argument("--control-l", type=float, default=3.0)
  p_ewma.add_argument("--baseline-fraction", type=float, default=0.50)
  p_ewma.add_argument("--min-baseline-buckets", type=int, default=6)
  p_ewma.add_argument("--bucket-seconds", type=int, default=3600)
  p_ewma.add_argument("--topic", default="Intraday EWMA Rate Shift Hunt")

  p_shannon = subparsers.add_parser("shannon", help="WS6-03 length-normalized per-character Shannon entropy.")
  _add_common_io_args(p_shannon)
  p_shannon.add_argument("--start-time", default=None)
  p_shannon.add_argument("--end-time", default=None)
  p_shannon.add_argument("--min-length", type=int, default=25)
  p_shannon.add_argument("--benign-min-prevalence", type=int, default=3)
  p_shannon.add_argument("--candidate-max-prevalence", type=int, default=2)
  p_shannon.add_argument("--z-threshold", type=float, default=3.0)
  p_shannon.add_argument("--min-benign-peers", type=int, default=5)
  p_shannon.add_argument("--topic", default="Length-Normalized Shannon Character Entropy Hunt")

  p_c2 = subparsers.add_parser("c2-jitter", help="WS6-04 consecutive C2 inter-arrival jitter & periodicity.")
  _add_common_io_args(p_c2)
  p_c2.add_argument("--start-time", default=None)
  p_c2.add_argument("--end-time", default=None)
  p_c2.add_argument("--max-cv", type=float, default=0.20)
  p_c2.add_argument("--min-intervals", type=int, default=4)
  p_c2.add_argument("--near-median-tolerance", type=float, default=0.25)
  p_c2.add_argument("--topic", default="C2 Inter-Arrival Jitter & Periodicity Hunt")

  args = parser.parse_args(argv)
  try:
    query_text, payload_bytes = _load_query_and_payload(args)
    if args.subcommand == "ewma":
      result = run_ewma_helper(
          payload_bytes,
          query_text=query_text,
          start_time=args.start_time,
          end_time=args.end_time,
          lambda_weight=args.lambda_weight,
          control_l=args.control_l,
          baseline_fraction=args.baseline_fraction,
          min_baseline_buckets=args.min_baseline_buckets,
          bucket_seconds=args.bucket_seconds,
          hunt_topic=args.topic,
      )
    elif args.subcommand == "shannon":
      result = run_shannon_helper(
          payload_bytes,
          query_text=query_text,
          min_length=args.min_length,
          benign_min_prevalence=args.benign_min_prevalence,
          candidate_max_prevalence=args.candidate_max_prevalence,
          z_threshold=args.z_threshold,
          min_benign_peers=args.min_benign_peers,
          hunt_topic=args.topic,
      )
    elif args.subcommand == "c2-jitter":
      result = run_c2_jitter_helper(
          payload_bytes,
          query_text=query_text,
          max_cv=args.max_cv,
          min_intervals=args.min_intervals,
          near_median_tolerance=args.near_median_tolerance,
          hunt_topic=args.topic,
      )
    else:
      raise ValueError(f"Unknown subcommand: {args.subcommand}")

    if args.output_json is not None:
      args.output_json.parent.mkdir(parents=True, exist_ok=True)
      args.output_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    if args.format == "json":
      sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
      sys.stdout.write(result["report_markdown"])
    return 0
  except (ValueError, OSError, subprocess.CalledProcessError) as exc:
    sys.stderr.write(f"ERROR: {exc}\n")
    return 2


if __name__ == "__main__":
  sys.exit(main())
