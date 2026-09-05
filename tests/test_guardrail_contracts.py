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
    """SKILL.md must explicitly contain the Hard Stop on API Error contract."""
    self.assertIn(
        "Hard Stop on API Error (MANDATORY STOP — ZERO SILENT FALLBACK)",
        self.skill_content,
        "SKILL.md must define the Hard Stop on API Error contract."
    )
    self.assertIn(
        "STRICTLY PROHIBITED",
        self.skill_content,
        "SKILL.md must strictly prohibit silent local simulation."
    )

  def test_zero_python_simulation_contract_present(self):
    """SKILL.md must explicitly prohibit writing scratch Python scripts to simulate SIEM baselines."""
    self.assertIn(
        "Native Execution Guarantee (ZERO PYTHON SIMULATION SCRIPTING)",
        self.skill_content,
        "SKILL.md must define the Native Execution Guarantee prohibiting Python simulation."
    )
    self.assertIn(
        "CRITICAL COMPLIANCE VIOLATION",
        self.skill_content,
        "SKILL.md must define local arithmetic simulation as a critical compliance violation."
    )

  def test_literal_query_display_mandate_present(self):
    """SKILL.md must enforce that Section 2 contains the literal query passed to udm_search."""
    self.assertIn(
        "Literal Query Display Mandate (ZERO FAKED YARA-L QUERIES)",
        self.skill_content,
        "SKILL.md must enforce literal query display."
    )

  def test_clean_handoff_contract_present(self):
    """SKILL.md must define the Clean Hand-Off (CH) protocol with Path A vs Path B distinction."""
    self.assertIn(
        "Clean Hand-Off (CH) Protocol",
        self.skill_content,
        "SKILL.md must define the Clean Hand-Off protocol."
    )
    self.assertIn(
        "Path A (Mandatory Default — Synthetic Event Ingestion)",
        self.skill_content,
        "SKILL.md must define Path A default synthetic event ingestion."
    )
    self.assertIn(
        "Path B (Carved-Out Active Case Exception)",
        self.skill_content,
        "SKILL.md must define Path B active case comment exception."
    )

  def test_zero_code_handoff_invariant_present(self):
    """SKILL.md must enforce the Zero-Code Handoff Invariant prohibiting code emission during skill steering."""
    self.assertIn(
        "Zero-Code Handoff Invariant",
        self.skill_content,
        "SKILL.md must define the Zero-Code Handoff Invariant."
    )
    self.assertIn(
        "Tool-Precondition Code Block Embargo",
        self.skill_content,
        "SKILL.md must link zero-code handoffs to the Tool-Precondition Code Block Embargo."
    )

  def test_strict_nomenclature_mandate_present(self):
    """SKILL.md must enforce Query vs. Rule nomenclature mandate."""
    self.assertIn(
        "Strict Nomenclature Mandate (Query vs. Rule)",
        self.skill_content,
        "SKILL.md must mandate query vs rule nomenclature."
    )
    self.assertIn(
        "CRITICAL NOMENCLATURE & ARCHITECTURAL VIOLATION",
        self.skill_content,
        "SKILL.md must flag rule creation as a critical nomenclature violation."
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

  def test_all_pipeline_templates_pass_validation(self):
    """All golden pipeline templates in templates/pipelines/ must pass grammar and scope validation."""
    pipeline_dir = os.path.join(self.repo_dir, "templates", "pipelines")
    self.assertTrue(os.path.exists(pipeline_dir), "templates/pipelines/ directory must exist")
    yl2_files = glob.glob(os.path.join(pipeline_dir, "*.yl2"))
    self.assertEqual(len(yl2_files), 9, f"Must have exactly 9 golden pipeline templates, found {len(yl2_files)}")

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
    self.assertIn("Invariant 1: Zero Data Simulation (NEVER Fabricate Data)", self.skill_content)
    self.assertIn("Invariant 2: Zero Schema/Syntax Fantasy (NEVER Hallucinate UDM Fields or YARA-L Grammar)", self.skill_content)
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
