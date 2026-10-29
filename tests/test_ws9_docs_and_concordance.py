# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Tests for WS9-03 (27-pipeline slot matrix & generator sync) and WS9-04 (D6 G1-G5 SKILL.md guardrails)."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
  sys.path.insert(0, str(REPO_ROOT))
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.generate_references import (  # pylint: disable=wrong-import-position
    generate_dynamic_windowing_matrix,
    generate_statistical_taxonomy,
)
from scripts.multistage_query_builder import (  # pylint: disable=wrong-import-position
    MultiStageTemplateRouter,
    __version__ as builder_version,
)


def _extract_active_pipeline_rows(taxonomy_md: str) -> Dict[str, str]:
  r"""Extracts `| \`<template.yl2>\` | ... |` rows from Section 20 before Retired Dispositions."""
  sec20_idx = taxonomy_md.find("## 20.")
  if sec20_idx == -1:
    return {}
  sec20_tail = taxonomy_md[sec20_idx:]
  retired_idx = sec20_tail.find("### Retired Dispositions")
  next_sec_idx = sec20_tail.find("\n## 21.")
  cut_candidates = [i for i in (retired_idx, next_sec_idx) if i != -1]
  active_block = sec20_tail[: min(cut_candidates)] if cut_candidates else sec20_tail

  rows: Dict[str, str] = {}
  for line in active_block.splitlines():
    m = re.match(r"^\|\s*`([a-zA-Z0-9_]+\.yl2)`\s*\|", line.strip())
    if m:
      rows[m.group(1)] = line.strip()
  return rows


class TestWS9DocsAndConcordance(unittest.TestCase):
  """Verifies WS9-03 taxonomy 27-pipeline slot matrix & generator sync and WS9-04 D6 G1-G5 guardrails."""

  def test_ws9_03_taxonomy_covers_all_27_pipelines_and_100pct_of_slots(self) -> None:
    """Every active .yl2 pipeline and 100% of its {{slot}} placeholders appear in taxonomy §20."""
    pipelines_dir = REPO_ROOT / "templates" / "pipelines"
    yl2_files = sorted(pipelines_dir.glob("*.yl2"))
    self.assertEqual(len(yl2_files), 27)

    taxonomy_md = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    table_rows = _extract_active_pipeline_rows(taxonomy_md)
    self.assertEqual(set(table_rows.keys()), {p.name for p in yl2_files})

    helper_map = MultiStageTemplateRouter.PYTHON_HELPER_SCREEN_ALTERNATIVES
    screen_to_subcmd = {screen_arch: subcmd for subcmd, screen_arch in helper_map.values()}

    for p in yl2_files:
      with self.subTest(template=p.name):
        raw_yl2 = p.read_text(encoding="utf-8")
        code_only = re.sub(r"//[^\n]*", "", raw_yl2)
        code_only = re.sub(r"/\*.*?\*/", "", code_only, flags=re.DOTALL)

        slots = sorted(set(re.findall(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", raw_yl2)))
        self.assertGreater(len(slots), 0, f"{p.name} has zero {{slots}}")

        named_stages = re.findall(r"^\s*stage\s+([a-zA-Z0-9_]+)\s*\{", code_only, flags=re.MULTILINE)
        total_stages = len(named_stages) + 1
        sens_key = MultiStageTemplateRouter.TEMPLATE_TO_SENSITIVITY_KEY[p.name]
        root_matches = re.findall(r"^\s*match:\s*\n\s*([^\n]+)", code_only, flags=re.MULTILINE)
        root_orders = re.findall(r"^\s*order:\s*\n\s*([^\n]+)", code_only, flags=re.MULTILINE)
        self.assertTrue(root_matches, f"{p.name} missing match: block")
        self.assertTrue(root_orders, f"{p.name} missing order: block")

        root_match_str = root_matches[-1].strip()
        order_var = root_orders[-1].strip().split()[0]

        row_text = table_rows[p.name]
        self.assertIn(f"`{sens_key}`", row_text)
        self.assertIn(f"{total_stages} stages", row_text)
        self.assertIn(root_match_str, row_text)
        self.assertIn(f"`{order_var}`", row_text)

        if sens_key in helper_map:
          subcmd, _ = helper_map[sens_key]
          self.assertIn(f"micro_python_helpers.py {subcmd}", row_text)
        elif sens_key in screen_to_subcmd:
          self.assertIn("D6-G5", row_text)
        else:
          self.assertIn("In-query SIEM", row_text)

        for slot in slots:
          self.assertIn(
              f"`{{{{{slot}}}}}`",
              row_text,
              f"Taxonomy row for {p.name} is missing slot {{{{{slot}}}}}",
          )

  def test_ws9_03_reference_generators_match_disk_byte_for_byte(self) -> None:
    """generate_references.py outputs match references/*.md byte-for-byte with zero drift."""
    taxonomy_disk = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    windowing_disk = (REPO_ROOT / "references" / "dynamic-windowing-matrix.md").read_text(encoding="utf-8")
    self.assertEqual(generate_statistical_taxonomy(), taxonomy_disk)
    self.assertEqual(generate_dynamic_windowing_matrix(), windowing_disk)

  def test_ws9_03_retired_impossible_travel_documented_only_as_retired(self) -> None:
    """impossible_travel_geo_velocity_2stage.yl2 is retired (D1) in taxonomy, SKILL.md triggers, and README.md."""
    retired_tpl = REPO_ROOT / "templates" / "pipelines" / "impossible_travel_geo_velocity_2stage.yl2"
    self.assertFalse(retired_tpl.exists())

    taxonomy_md = (REPO_ROOT / "references" / "statistical-models-taxonomy.md").read_text(encoding="utf-8")
    active_rows = _extract_active_pipeline_rows(taxonomy_md)
    self.assertNotIn("impossible_travel_geo_velocity_2stage.yl2", active_rows)
    self.assertIn("### Retired Dispositions (`D1`)", taxonomy_md)
    retired_section = taxonomy_md.split("### Retired Dispositions (`D1`)", 1)[1].split("\n## 21.", 1)[0]
    self.assertIn("impossible_travel_geo_velocity_2stage.yl2", retired_section)
    self.assertIn("IMPOSSIBLE_TRAVEL_GEO_VELOCITY", retired_section)
    self.assertIn("HOUR_OF_DAY_PROFILE", retired_section)
    self.assertIn("hour_of_day_profile_3stage.yl2", retired_section)

    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    frontmatter = skill_md.split("---", 2)[1]
    self.assertNotIn("impossible travel", frontmatter.lower())
    self.assertIn("hour-of-day circadian profile", frontmatter.lower())

    readme_md = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    self.assertNotIn("├── impossible_travel_geo_velocity_2stage.yl2", readme_md)
    for p in sorted((REPO_ROOT / "templates" / "pipelines").glob("*.yl2")):
      self.assertIn(p.name, readme_md, f"README.md missing active template {p.name}")

  def test_ws9_04_skill_md_d6_helper_exemption_and_g1_through_g5_guardrails(self) -> None:
    """SKILL.md Tool Orchestration Protocol states explicit D6 exemptions and all G1-G5 guardrails within 28 KB."""
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertLessEqual(len(skill_md.encode("utf-8")), 28672)
    self.assertLessEqual(len(skill_md.splitlines()), 275)

    tool_proto_lines = [
        line for line in skill_md.splitlines() if "**Tool Orchestration Protocol**:" in line
    ]
    self.assertEqual(len(tool_proto_lines), 1)
    proto = tool_proto_lines[0]

    # Mandatory verbatim invariant
    self.assertIn("There is no blanket approval for `run_command`, only explicit exemptions.", proto)

    # Explicit vetted helper & subcommands
    self.assertIn("scripts/micro_python_helpers.py", proto)
    for subcmd in ("ewma", "shannon", "c2-jitter"):
      self.assertIn(subcmd, proto)

    # Explicit G1-G5 guardrails
    self.assertIn("`G1`", proto)
    self.assertIn("never LLM-typed numbers", proto)
    self.assertIn("`G2`", proto)
    self.assertIn("exit `2` fail-closed", proto)
    self.assertIn("missing/malformed input", proto)
    self.assertIn("`G3`", proto)
    self.assertIn("SHA-256", proto)
    self.assertIn("helper version", proto)
    self.assertIn("Provenance Appendix", proto)
    self.assertIn("`G4`", proto)
    self.assertIn("offline golden-tested", proto)
    self.assertIn("zero network calls", proto)
    self.assertIn("`G5`", proto)
    self.assertIn("this model needs a client that can run local scripts", proto)
    self.assertIn("never run an in-query approximation under the real model's name", proto)
    for screen_name in ("BURST_Z_SCREEN", "LONG_STRING_SCREEN", "FLOW_GAP_RATIO_SCREEN"):
      self.assertIn(screen_name, proto)

  def test_rule10_version_3_0_0_and_release_notes_remediation_changelog(self) -> None:
    """Rule 10: SKILL.md, builder __version__, README badge, and RELEASE_NOTES.md are synchronized at v3.0.0."""
    skill_md = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    frontmatter = skill_md.split("---", 2)[1]
    self.assertIn("version: 3.0.0", frontmatter)
    self.assertEqual(builder_version, "3.0.0")

    readme_md = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    self.assertIn("version-v3.0.0-blue.svg", readme_md)

    release_notes = (REPO_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    self.assertIn("## 📦 Version 3.0.0", release_notes)
    v300_section = release_notes.split("## 📦 Version 3.0.0", 1)[1].split("## 📦 Version 2.9.0", 1)[0]
    for required_token in (
        "WS1-06",
        "WS1-07",
        "WS1-08",
        "D1",
        "HOUR_OF_DAY_PROFILE",
        "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        "WS6-02",
        "WS6-03",
        "WS6-04",
        "micro_python_helpers.py",
        "WS7-01",
        "WS7-02",
        "WS7-03",
        "WS8-01",
        "WS8-02",
        "WS8-03",
        "WS8-04",
        "EXFILTRATION_IQR_OUTLIER",
        "WS9-03",
        "WS9-04",
    ):
      self.assertIn(required_token, v300_section, f"RELEASE_NOTES v3.0.0 entry missing {required_token}")

  def test_rule10_readme_cri_bands_and_final_test_counts(self) -> None:
    """Rule 10 / D5: README CRI bands match 26/46/70/90 and RELEASE_NOTES reflects final test count."""
    readme_md = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    self.assertNotIn("0–29", readme_md, "README.md still lists legacy CRI bands instead of D5 26/46/70/90")
    self.assertIn("26", readme_md)
    release_notes = (REPO_ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    v300_section = release_notes.split("## 📦 Version 3.0.0", 1)[1].split("## 📦 Version 2.9.0", 1)[0]
    self.assertIn("326 passed", v300_section)


if __name__ == "__main__":
  unittest.main()
