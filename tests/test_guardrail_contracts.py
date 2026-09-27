"""Unit tests asserting the presence and strict enforcement of the guardrail contracts,
compiler AST invariants, and truth-in-reporting policies in secops-statistical-hunter.

Author: Greg Kushmerek
"""

import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import (
    PostFlightExecutionAuditor,
    AuditStatus,
    MultiStageTemplateRouter,
    validate_multistage_syntax,
    check_scope_exclusions,
)
import multistage_query_builder


class TestGuardrailContracts(unittest.TestCase):

  def setUp(self):
    self.repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    self.skill_md_path = os.path.join(self.repo_dir, "SKILL.md")
    self.assertTrue(os.path.exists(self.skill_md_path), "SKILL.md must exist")
    with open(self.skill_md_path, "r", encoding="utf-8") as f:
      self.skill_content = f.read()

  def test_authorship_statement_present(self):
    """Author Greg Kushmerek must be declared across skill metadata and scripts."""
    self.assertIn("author: Greg Kushmerek", self.skill_content)
    self.assertEqual(multistage_query_builder.__author__, "Greg Kushmerek")

  def test_hard_stop_on_api_error_contract_present(self):
    """SKILL.md must explicitly contain the Transparent Error Surfacing contract."""
    self.assertIn(
        "Transparent Error Surfacing",
        self.skill_content,
        "SKILL.md must define the Transparent Error Surfacing contract."
    )
    self.assertIn(
        "surface the exact error response",
        self.skill_content,
        "SKILL.md must direct surfacing error responses."
    )

  def test_zero_python_simulation_contract_present(self):
    """SKILL.md must explicitly define the Native SIEM Engine Execution Guarantee."""
    self.assertIn(
        "Native SIEM Engine Execution Guarantee",
        self.skill_content,
        "SKILL.md must define the Native SIEM Engine Execution Guarantee."
    )
    self.assertIn(
        "natively within Google SecOps Chronicle SIEM",
        self.skill_content,
        "SKILL.md must direct executing calculations natively within SIEM."
    )

  def test_literal_query_display_mandate_present(self):
    """SKILL.md must enforce that Section 2 contains the literal query passed to udm_search."""
    self.assertIn(
        "Verbatim Query Provenance",
        self.skill_content,
        "SKILL.md must enforce verbatim query provenance."
    )

  def test_clean_handoff_contract_present(self):
    """SKILL.md must define the Clean Hand-Off (CH) protocol with Path A vs Path B distinction."""
    self.assertIn(
        "Clean Hand-Off (CH) Protocol",
        self.skill_content,
        "SKILL.md must define the Clean Hand-Off protocol."
    )
    self.assertIn(
        "Path A (Standard Escalation Default — Synthetic Event Ingestion)",
        self.skill_content,
        "SKILL.md must define Path A default synthetic event ingestion."
    )
    self.assertIn(
        "Path B (Explicit Active Case Attachment)",
        self.skill_content,
        "SKILL.md must define Path B active case comment exception."
    )

  def test_zero_code_handoff_invariant_present(self):
    """SKILL.md must enforce the Conceptual Handoff Contract prohibiting code emission during skill steering."""
    self.assertIn(
        "Conceptual Handoff Contract",
        self.skill_content,
        "SKILL.md must define the Conceptual Handoff Contract."
    )
    self.assertIn(
        "Zero-Code Handoff Invariant",
        self.skill_content,
        "SKILL.md must enforce Zero-Code Handoff Invariant."
    )

  def test_strict_nomenclature_mandate_present(self):
    """SKILL.md must enforce Query vs. Rule nomenclature mandate."""
    self.assertIn(
        "Search Query Nomenclature",
        self.skill_content,
        "SKILL.md must mandate search query nomenclature."
    )
    self.assertIn(
        "ad-hoc Multi-Stage Queries",
        self.skill_content,
        "SKILL.md must direct using ad-hoc Multi-Stage Queries."
    )

  def test_postflight_auditor_flags_raw_event_dump_and_remediates(self):
    """PostFlightExecutionAuditor must detect raw log dumps and recommend canonical query."""
    raw_event_payload = {
        "events": [{"name": f"ev-{i}", "udm": {"metadata": {"eventType": "USER_LOGIN"}}} for i in range(25)]
    }
    non_stats_query = "metadata.event_type = \"USER_LOGIN\" AND principal.user.userid = \"frank\""

    audit = PostFlightExecutionAuditor.audit_execution(
        executed_query=non_stats_query,
        api_response=raw_event_payload,
        expected_architecture="LOCAL_2STAGE",
        expected_model="Z_SCORE",
    )

    self.assertEqual(audit.status, AuditStatus.RETRY_REQUIRED.value)
    self.assertFalse(audit.is_valid)
    self.assertTrue(any("RAW_LOG_DUMP_DETECTED" in e for e in audit.errors))
    self.assertIsNotNone(audit.recommended_query)
    self.assertIn("stage host_hourly", audit.recommended_query)

  def test_compiler_ast_syntax_traps(self):
    """Validator must catch Common Compiler syntax violations."""
    # 1. Invalid stage variable syntax ($ after dot)
    bad_var_syntax = "stage s { match: $h by 1h outcome: $val = max(s.$var) }"
    errs_var = validate_multistage_syntax(bad_var_syntax)
    self.assertTrue(any("INVALID_STAGE_VARIABLE_SYNTAX" in e for e in errs_var))

    # 2. Non-existent sqrt function
    bad_sqrt = "stage s { match: $h by 1h outcome: $z = sqrt($val) }"
    errs_sqrt = validate_multistage_syntax(bad_sqrt)
    self.assertTrue(any("INVALID_SQRT_FUNCTION" in e for e in errs_sqrt))

    # 3. Exponent operator ^
    bad_exp = "stage s { match: $h by 1h outcome: $z2 = $z ^ 2 }"
    errs_exp = validate_multistage_syntax(bad_exp)
    self.assertTrue(any("INVALID_EXPONENT_OPERATOR" in e for e in errs_exp))

    # 4. Detection rule wrapper
    bad_rule = "rule my_rule { stage s { match: $h by 1h outcome: $c = count(metadata.id) } }"
    errs_rule = validate_multistage_syntax(bad_rule)
    self.assertTrue(any("INVALID_DETECTION_RULE_SYNTAX" in e for e in errs_rule))

    # 5. if() conditional with missing else clause
    bad_if_else = "stage s { match: $h by 1h outcome: $val = if($a > 0, 1.0) }"
    errs_if_else = validate_multistage_syntax(bad_if_else)
    self.assertTrue(any("INVALID_IF_CONDITIONAL" in e for e in errs_if_else))

    # 6. if() conditional with compound arithmetic in then-clause
    bad_if_compound = "stage s { match: $h by 1h outcome: $val = if($a > 0, $b / $c, 0.0) }"
    errs_if_compound = validate_multistage_syntax(bad_if_compound)
    self.assertTrue(any("INVALID_IF_CONDITIONAL" in e for e in errs_if_compound))

  def test_all_pipeline_templates_pass_validation(self):
    """All golden pipeline templates in templates/pipelines/ must pass grammar and scope validation."""
    pipeline_dir = os.path.join(self.repo_dir, "templates", "pipelines")
    self.assertTrue(os.path.exists(pipeline_dir), "templates/pipelines/ directory must exist")
    yl2_files = glob.glob(os.path.join(pipeline_dir, "*.yl2"))
    self.assertEqual(len(yl2_files), 17, f"Must have exactly 17 golden pipeline templates, found {len(yl2_files)}")

    router = MultiStageTemplateRouter(template_dir=pipeline_dir)
    for fpath in yl2_files:
      filename = os.path.basename(fpath)
      # Build query with defaults
      archetype = filename.replace("_2stage.yl2", "").replace("_3stage.yl2", "").replace("_4stage.yl2", "").upper()
      rendered_query = router.build_query(archetype=archetype, tier="BALANCED")

      violations = check_scope_exclusions(rendered_query)
      self.assertEqual(violations, [], f"Scope exclusions violated in {filename}")

      syntax_errors = validate_multistage_syntax(rendered_query)
      fatal_errors = [e for e in syntax_errors if not e.startswith("MISSING METHODOLOGY HEADER")]
      self.assertEqual(fatal_errors, [], f"Syntax errors in {filename}: {fatal_errors}")

  def test_dual_grounding_commandments_contract(self):
    """SKILL.md must strictly define the Dual Grounding Commandments."""
    self.assertIn("THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)", self.skill_content)
    self.assertIn("Invariant 1: Empirical Data Grounding (Zero Data Simulation)", self.skill_content)
    self.assertIn("Invariant 2: Verified Compiler Grammar (Zero Schema/Syntax Fantasy)", self.skill_content)
    self.assertIn("Truth Over Completion", self.skill_content)

  def test_three_state_active_hunt_lifecycle_contract(self):
    """SKILL.md must define the closed 3-state active hunt lifecycle."""
    self.assertIn("THE 3-STATE ACTIVE HUNT LIFECYCLE", self.skill_content)
    self.assertIn("State 1: Pre-Flight Clearance & Specification", self.skill_content)
    self.assertIn("State 2: Deterministic Multi-Stage Execution & 5-Section Triage Report", self.skill_content)
    self.assertIn("State 3: Iteration, Entity Shifts & Federated Bridge", self.skill_content)

  def test_active_hunt_session_lock_contract(self):
    """SKILL.md must define the Active Hunt Session Lock preventing cross-skill drift."""
    self.assertIn("Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)", self.skill_content)
    self.assertIn("RETAIN SESSION AFFINITY", self.skill_content)
    self.assertIn("re-enter State 1 for the new entity", self.skill_content)

  def test_cooperative_framework_contract(self):
    """SKILL.md must reference the bilateral cooperative framework and the file must exist."""
    self.assertIn("statistical-hunting-cooperative-framework.md", self.skill_content)
    framework_path = os.path.join(self.repo_dir, "references", "statistical-hunting-cooperative-framework.md")
    self.assertTrue(os.path.exists(framework_path), "Cooperative framework file must exist in references/")

  def test_pillar5_debaiting_contract(self):
    """SKILL.md and output schemas must de-bait Pillar 5 / Section 4 to prevent automated tool execution."""
    self.assertIn("#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)", self.skill_content)
    self.assertNotIn("Immediate Drill-Down Investigation Query", self.skill_content)


if __name__ == "__main__":
  unittest.main()
