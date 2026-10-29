#!/usr/bin/env python3
"""Opt-in live Chronicle UDM Search compile harness for secops-statistical-hunter (WS0-03).

Enumerates and renders every MultiStageTemplateRouter (archetype, entity_type, tier)
combination across templates/pipelines/*.yl2 plus examples/*.yara, and executes
sequential read-only udm_search compile checks over a bounded <= 1h window via an
injectable search_fn(query, start_time, end_time) -> dict (or manifest export/import).
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from multistage_query_builder import MultiStageTemplateRouter, QueryIntegrityGate  # pylint: disable=wrong-import-position

DEFAULT_CUSTOMER_ID = "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5"
DEFAULT_PROJECT_ID = "gus-sdl"
DEFAULT_REGION = "us"
DEFAULT_START_TIME = "2026-10-27T14:00:00Z"
DEFAULT_END_TIME = "2026-10-27T15:00:00Z"
DEFAULT_MAX_EVENTS = 20

ENTITY_TYPES: Tuple[str, ...] = ("host", "user", "ip")
TIERS: Tuple[str, ...] = ("CONSERVATIVE", "BALANCED", "AGGRESSIVE")

USER_CENTRIC_ARCHETYPES = frozenset({
    "BETA_BINOMIAL_FAILURE",
    "HOUR_OF_DAY_PROFILE",
    "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
    "POISSON_BURST_CLUSTERING",
    "PRIVILEGED_LATERAL_EXPANSION",
    "TWO_PART_HURDLE",
})

SearchFn = Callable[[str, str, str], Any]


@dataclass(frozen=True)
class CompileCase:
  """Single rendered YARA-L 2.0 compile check case."""

  index: int
  case_id: str
  source_kind: str  # "pipeline" | "example"
  template_file: str
  archetype: Optional[str]
  entity_type: Optional[str]
  tier: Optional[str]
  window_hours: Optional[float]
  query: str
  query_sha256: str


@dataclass(frozen=True)
class CompileResult:
  """Recorded outcome of running one CompileCase through udm_search."""

  case_id: str
  source_kind: str
  template_file: str
  archetype: Optional[str]
  entity_type: Optional[str]
  tier: Optional[str]
  window_hours: Optional[float]
  start_time: str
  end_time: str
  query_sha256: str
  compile_ok: bool
  row_count: int
  error: Optional[str] = None


def sha256_text(text: str) -> str:
  """Returns hex SHA-256 digest of UTF-8 text."""
  return hashlib.sha256(text.encode("utf-8")).hexdigest()


def default_entity_type_for_archetype(archetype: str) -> str:
  """Returns natural primary entity_type ('user' or 'host') for smoke checks."""
  if archetype.upper() in USER_CENTRIC_ARCHETYPES:
    return "user"
  return "host"


def parse_udm_search_response(raw_response: Any) -> Tuple[bool, int, Optional[str]]:
  """Parses a Chronicle udm_search payload or error into (compile_ok, row_count, error).

  Columnar multi-stage stats responses return `{"stats": {"results": [{"column": ...}]}}`
  even when 0 rows match; `row_count` is therefore the maximum length of `values` across
  returned columns, never `len(results)`.
  """
  if isinstance(raw_response, BaseException):
    return False, 0, str(raw_response)

  if raw_response is None:
    return False, 0, "Empty (None) response from search_fn."

  if isinstance(raw_response, str):
    stripped = raw_response.strip()
    if not stripped:
      return True, 0, None
    if stripped.startswith("{"):
      try:
        parsed = json.loads(stripped)
        return parse_udm_search_response(parsed)
      except json.JSONDecodeError:
        pass
    qa = QueryIntegrityGate.verify_backend_response(stripped)
    if not qa["valid"]:
      return False, 0, stripped
    if stripped.lower().startswith("error") or "encountered error" in stripped.lower():
      return False, 0, stripped
    return True, 0, None

  if isinstance(raw_response, dict):
    if raw_response.get("isError") is True:
      err_val = raw_response.get("error") or raw_response.get("message") or str(raw_response)
      return False, 0, str(err_val)

    if raw_response.get("error"):
      err_obj = raw_response["error"]
      if isinstance(err_obj, dict):
        msg = err_obj.get("message") or json.dumps(err_obj, sort_keys=True)
      else:
        msg = str(err_obj)
      return False, 0, msg

    qa = QueryIntegrityGate.verify_backend_response(raw_response)
    if not qa["valid"]:
      return False, 0, "; ".join(qa["errors"])

    stats_block = raw_response.get("stats")
    if isinstance(stats_block, dict):
      results = stats_block.get("results", [])
      if isinstance(results, list):
        row_count = max(
            (len(col.get("values", [])) for col in results if isinstance(col, dict)),
            default=0,
        )
        return True, row_count, None
      return True, 0, None

    events_block = raw_response.get("events")
    if isinstance(events_block, list):
      return True, len(events_block), None

    return True, 0, None

  return False, 0, f"Unsupported search_fn response type: {type(raw_response).__name__}"


class LiveCompileHarness:
  """Discovers templates/examples, builds compile matrices, and executes compile checks."""

  def __init__(
      self,
      repo_root: Optional[Path] = None,
      router: Optional[MultiStageTemplateRouter] = None,
  ):
    self.repo_root = Path(repo_root) if repo_root is not None else REPO_ROOT
    self.templates_dir = self.repo_root / "templates" / "pipelines"
    self.examples_dir = self.repo_root / "examples"
    self.router = router or MultiStageTemplateRouter(template_dir=self.templates_dir)

  def discover_pipeline_templates(self) -> List[Tuple[str, str]]:
    """Returns sorted (canonical_archetype, template_filename) pairs for all pipeline templates."""
    reverse_arch_map: Dict[str, str] = {}
    for arch_name, fname in self.router.ARCHETYPE_TEMPLATE_MAP.items():
      reverse_arch_map.setdefault(fname, arch_name)

    filenames = {p.name for p in self.templates_dir.glob("*.yl2")}
    filenames.update(self.router.INLINE_TEMPLATES.keys())

    discovered: List[Tuple[str, str]] = []
    for fname in sorted(filenames):
      archetype = self.router.TEMPLATE_TO_SENSITIVITY_KEY.get(fname)
      if not archetype:
        archetype = reverse_arch_map.get(fname)
      if not archetype:
        stem = fname[:-4] if fname.endswith(".yl2") else fname
        archetype = re.sub(r"_\d+stage$", "", stem).upper()
      discovered.append((archetype, fname))

    discovered.sort(key=lambda item: item[1])
    return discovered

  def discover_example_files(self) -> List[Path]:
    """Returns sorted list of examples/*.yara files."""
    if not self.examples_dir.exists():
      return []
    return sorted(self.examples_dir.glob("*.yara"))

  def build_full_matrix(
      self,
      entity_types: Sequence[str] = ENTITY_TYPES,
      tiers: Sequence[str] = TIERS,
      window_hours: float = 1.0,
      include_examples: bool = True,
  ) -> List[CompileCase]:
    """Builds the full (archetype x entity_type x tier) matrix plus examples/*.yara."""
    cases: List[CompileCase] = []
    idx = 1
    for archetype, fname in self.discover_pipeline_templates():
      for entity_type in entity_types:
        for tier in tiers:
          query = self.router.build_query(
              archetype=archetype,
              tier=tier,
              entity_type=entity_type,
              window_hours=window_hours,
          )
          cases.append(
              CompileCase(
                  index=idx,
                  case_id=f"pipeline:{archetype}:{entity_type}:{tier}",
                  source_kind="pipeline",
                  template_file=fname,
                  archetype=archetype,
                  entity_type=entity_type,
                  tier=tier,
                  window_hours=window_hours,
                  query=query,
                  query_sha256=sha256_text(query),
              )
          )
          idx += 1

    if include_examples:
      for ex_path in self.discover_example_files():
        query = ex_path.read_text(encoding="utf-8")
        cases.append(
            CompileCase(
                index=idx,
                case_id=f"example:{ex_path.name}",
                source_kind="example",
                template_file=ex_path.name,
                archetype=None,
                entity_type=None,
                tier=None,
                window_hours=None,
                query=query,
                query_sha256=sha256_text(query),
            )
        )
        idx += 1

    return cases

  def build_smoke_matrix(
      self,
      tier: str = "BALANCED",
      window_hours: float = 1.0,
      include_examples: bool = True,
  ) -> List[CompileCase]:
    """Builds 1 representative case per pipeline template plus all examples/*.yara."""
    cases: List[CompileCase] = []
    idx = 1
    tier_up = tier.upper()
    for archetype, fname in self.discover_pipeline_templates():
      entity_type = default_entity_type_for_archetype(archetype)
      query = self.router.build_query(
          archetype=archetype,
          tier=tier_up,
          entity_type=entity_type,
          window_hours=window_hours,
      )
      cases.append(
          CompileCase(
              index=idx,
              case_id=f"pipeline:{archetype}:{entity_type}:{tier_up}",
              source_kind="pipeline",
              template_file=fname,
              archetype=archetype,
              entity_type=entity_type,
              tier=tier_up,
              window_hours=window_hours,
              query=query,
              query_sha256=sha256_text(query),
          )
      )
      idx += 1

    if include_examples:
      for ex_path in self.discover_example_files():
        query = ex_path.read_text(encoding="utf-8")
        cases.append(
            CompileCase(
                index=idx,
                case_id=f"example:{ex_path.name}",
                source_kind="example",
                template_file=ex_path.name,
                archetype=None,
                entity_type=None,
                tier=None,
                window_hours=None,
                query=query,
                query_sha256=sha256_text(query),
            )
        )
        idx += 1

    return cases

  def run_cases(
      self,
      cases: Sequence[CompileCase],
      search_fn: SearchFn,
      start_time: str = DEFAULT_START_TIME,
      end_time: str = DEFAULT_END_TIME,
  ) -> List[CompileResult]:
    """Executes cases sequentially (one query at a time) through search_fn."""
    results: List[CompileResult] = []
    for case in cases:
      try:
        raw_resp = search_fn(case.query, start_time, end_time)
        compile_ok, row_count, error_msg = parse_udm_search_response(raw_resp)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        compile_ok, row_count, error_msg = False, 0, str(exc)

      results.append(
          CompileResult(
              case_id=case.case_id,
              source_kind=case.source_kind,
              template_file=case.template_file,
              archetype=case.archetype,
              entity_type=case.entity_type,
              tier=case.tier,
              window_hours=case.window_hours,
              start_time=start_time,
              end_time=end_time,
              query_sha256=case.query_sha256,
              compile_ok=compile_ok,
              row_count=row_count,
              error=error_msg,
          )
      )
    return results

  @staticmethod
  def summarize_results(results: Sequence[CompileResult]) -> Dict[str, Any]:
    """Summarizes compile pass/fail counts across pipelines and examples."""
    pipelines = [r for r in results if r.source_kind == "pipeline"]
    examples = [r for r in results if r.source_kind == "example"]
    return {
        "total_cases": len(results),
        "compile_ok_count": sum(1 for r in results if r.compile_ok),
        "compile_failed_count": sum(1 for r in results if not r.compile_ok),
        "pipeline_total": len(pipelines),
        "pipeline_compile_ok": sum(1 for r in pipelines if r.compile_ok),
        "pipeline_compile_failed": sum(1 for r in pipelines if not r.compile_ok),
        "example_total": len(examples),
        "example_compile_ok": sum(1 for r in examples if r.compile_ok),
        "example_compile_failed": sum(1 for r in examples if not r.compile_ok),
        "failed_case_ids": [r.case_id for r in results if not r.compile_ok],
        "nonzero_row_cases": [
            {"case_id": r.case_id, "row_count": r.row_count}
            for r in results
            if r.compile_ok and r.row_count > 0
        ],
    }

  @staticmethod
  def export_manifest(cases: Sequence[CompileCase], output_path: Path) -> None:
    """Writes rendered CompileCase list to a JSON manifest for external/MCP execution."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(c) for c in cases]
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

  @staticmethod
  def import_results(
      cases: Sequence[CompileCase],
      raw_results_path: Path,
      default_start_time: str = DEFAULT_START_TIME,
      default_end_time: str = DEFAULT_END_TIME,
  ) -> List[CompileResult]:
    """Joins a list of CompileCases with externally recorded MCP udm_search outputs."""
    raw_items = json.loads(raw_results_path.read_text(encoding="utf-8"))
    by_case_id: Dict[str, Dict[str, Any]] = {}
    by_sha: Dict[str, Dict[str, Any]] = {}
    for item in raw_items:
      if not isinstance(item, dict):
        continue
      if item.get("case_id"):
        by_case_id[str(item["case_id"])] = item
      if item.get("query_sha256"):
        by_sha[str(item["query_sha256"])] = item

    compiled: List[CompileResult] = []
    for case in cases:
      rec = by_case_id.get(case.case_id) or by_sha.get(case.query_sha256)
      if rec is None:
        raise KeyError(f"Missing result entry for {case.case_id} ({case.query_sha256})")
      if "compile_ok" in rec:
        compile_ok = bool(rec["compile_ok"])
        row_count = int(rec.get("row_count", 0))
        error_msg = rec.get("error")
      else:
        compile_ok, row_count, error_msg = parse_udm_search_response(rec.get("response"))
      compiled.append(
          CompileResult(
              case_id=case.case_id,
              source_kind=case.source_kind,
              template_file=case.template_file,
              archetype=case.archetype,
              entity_type=case.entity_type,
              tier=case.tier,
              window_hours=case.window_hours,
              start_time=str(rec.get("start_time") or default_start_time),
              end_time=str(rec.get("end_time") or default_end_time),
              query_sha256=case.query_sha256,
              compile_ok=compile_ok,
              row_count=row_count,
              error=error_msg,
          )
      )
    return compiled


def make_adc_rest_search_fn(
    customer_id: str = DEFAULT_CUSTOMER_ID,
    project_id: str = DEFAULT_PROJECT_ID,
    region: str = DEFAULT_REGION,
    max_events: int = DEFAULT_MAX_EVENTS,
    timeout_seconds: int = 60,
) -> SearchFn:
  """Builds a read-only Chronicle UDM Search REST transport using Google Cloud ADC.

  Used only when SECOPS_LIVE_TESTS=1 is enabled in standalone environments without MCP.
  """
  try:
    import google.auth  # type: ignore  # pylint: disable=import-outside-toplevel
    import google.auth.transport.requests  # type: ignore  # pylint: disable=import-outside-toplevel
  except ImportError as exc:
    raise RuntimeError(
        "google-auth is required for standalone ADC live udm_search execution; "
        "inject search_fn or use --export-manifest / --import-results with MCP."
    ) from exc

  credentials, _ = google.auth.default(
      scopes=["https://www.googleapis.com/auth/cloud-platform"]
  )
  auth_req = google.auth.transport.requests.Request()

  host = (
      "chronicle.googleapis.com"
      if region == "us"
      else f"{region}-chronicle.googleapis.com"
  )
  parent = f"projects/{project_id}/locations/{region}/instances/{customer_id}"
  base_url = f"https://{host}/v1alpha/{parent}:udmSearch"

  def _search(query: str, start_time: str, end_time: str) -> Dict[str, Any]:
    if not credentials.valid or credentials.expired or not credentials.token:
      credentials.refresh(auth_req)
    params = urllib.parse.urlencode({
        "query": query,
        "timeRange.startTime": start_time,
        "timeRange.endTime": end_time,
        "limit": max_events,
    })
    req = urllib.request.Request(
        f"{base_url}?{params}",
        method="GET",
        headers={
            "Authorization": f"Bearer {credentials.token}",
            "Accept": "application/json",
        },
    )
    try:
      with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as http_err:
      err_body = http_err.read().decode("utf-8", errors="replace")
      try:
        parsed_err = json.loads(err_body)
        if isinstance(parsed_err, dict) and "error" in parsed_err:
          return parsed_err
      except json.JSONDecodeError:
        pass
      return {"error": f"HTTP {http_err.code}: {err_body}"}

  return _search


def main(argv: Optional[Sequence[str]] = None) -> int:
  """CLI entrypoint for exporting manifests, importing MCP results, or running ADC checks."""
  parser = argparse.ArgumentParser(
      description="Opt-in live compile harness for secops-statistical-hunter."
  )
  parser.add_argument(
      "--mode",
      choices=("smoke", "full"),
      default="smoke",
      help="Matrix mode: 'smoke' (24 pipelines + 13 examples) or 'full' (24x3x3 + 13).",
  )
  parser.add_argument("--window-hours", type=float, default=1.0)
  parser.add_argument("--start-time", default=DEFAULT_START_TIME)
  parser.add_argument("--end-time", default=DEFAULT_END_TIME)
  parser.add_argument("--export-manifest", type=Path, default=None)
  parser.add_argument("--import-results", type=Path, default=None)
  parser.add_argument("--output", type=Path, default=None)
  parser.add_argument(
      "--run-live",
      action="store_true",
      help="Run live read-only udm_search via ADC (requires SECOPS_LIVE_TESTS=1).",
  )
  args = parser.parse_args(argv)

  harness = LiveCompileHarness()
  cases = (
      harness.build_full_matrix(window_hours=args.window_hours)
      if args.mode == "full"
      else harness.build_smoke_matrix(window_hours=args.window_hours)
  )

  if args.export_manifest is not None:
    harness.export_manifest(cases, args.export_manifest)

  results: Optional[List[CompileResult]] = None
  if args.import_results is not None:
    results = harness.import_results(
        cases,
        args.import_results,
        default_start_time=args.start_time,
        default_end_time=args.end_time,
    )
  elif args.run_live:
    if os.environ.get("SECOPS_LIVE_TESTS") != "1":
      raise SystemExit("Refusing --run-live without SECOPS_LIVE_TESTS=1.")
    search_fn = make_adc_rest_search_fn(
        customer_id=os.environ.get("SECOPS_CUSTOMER_ID", DEFAULT_CUSTOMER_ID),
        project_id=os.environ.get("SECOPS_PROJECT_ID", DEFAULT_PROJECT_ID),
        region=os.environ.get("SECOPS_REGION", DEFAULT_REGION),
    )
    results = harness.run_cases(
        cases,
        search_fn=search_fn,
        start_time=args.start_time,
        end_time=args.end_time,
    )

  if results is not None:
    report = {
        "summary": harness.summarize_results(results),
        "compile_results": [asdict(r) for r in results],
    }
    if args.output is not None:
      args.output.parent.mkdir(parents=True, exist_ok=True)
      args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    else:
      print(json.dumps(report["summary"], indent=2))

  return 0


if __name__ == "__main__":
  raise SystemExit(main())
