"""Unit tests for YARA-L Multi-Stage grammar, compiler AST rules, and scope exclusions."""

import os
import unittest
import glob
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import check_scope_exclusions, validate_multistage_syntax


class TestCompilerGrammar(unittest.TestCase):

  def test_all_examples_pass_validation(self):
    examples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples"))
    yara_files = glob.glob(os.path.join(examples_dir, "*.yara"))
    self.assertGreater(len(yara_files), 5, "Should find multiple example YARA-L files")

    for fpath in yara_files:
      with open(fpath, "r") as f:
        query_text = f.read()
      
      violations = check_scope_exclusions(query_text)
      self.assertEqual(violations, [], f"Scope exclusions violated in {os.path.basename(fpath)}")

      syntax_errors = validate_multistage_syntax(query_text)
      fatal_errors = [e for e in syntax_errors if not e.startswith("MISSING METHODOLOGY HEADER")]
      self.assertEqual(fatal_errors, [], f"Syntax errors found in {os.path.basename(fpath)}: {fatal_errors}")

  def test_reject_intra_stage_variable_reuse(self):
    bad_query = """
    stage host_s {
      metadata.event_type = "PROCESS_LAUNCH"
      match: $host by 1h
      outcome:
        $diff = $a - $b
        $z = $diff / $c
    }
    $host = $host_s.host
    match: $host by 1h
    outcome:
      $out = max($host_s.diff)
    condition:
      $out > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("INTRA-STAGE RACE CONDITION" in e for e in errors), "Should detect intra-stage variable chaining")

  def test_reject_excessive_outcome_variables(self):
    vars_block = "\n".join([f"        $var_{i} = max($e.id)" for i in range(25)])
    bad_query = f"""
    stage s1 {{
      metadata.event_type = "PROCESS_LAUNCH"
      match: $host by 1h
      outcome:
{vars_block}
    }}
    $host = $s1.host
    match: $host by 1h
    outcome:
      $val = max($s1.var_0)
    condition:
      $val > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("OutcomeLimit = 20" in e for e in errors), "Should enforce 20 variable outcome limit")

  def test_reject_scope_exclusions(self):
    query_with_metrics = "stage s { $x = metrics.auth_attempts_fail(window: 30d) }"
    violations = check_scope_exclusions(query_with_metrics)
    self.assertTrue(len(violations) > 0, "Should detect metrics.* exclusion")
    self.assertIn("metrics.", violations[0])

    query_with_risk = "stage s { $r = graph.risk_score }"
    violations_risk = check_scope_exclusions(query_with_risk)
    self.assertTrue(len(violations_risk) > 0, "Should detect risk_score exclusion")

  def test_reject_exponent_operator(self):
    bad_query = "stage s { match: $h by 1h outcome: $z2 = $z ^ 2 }"
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("'^' is invalid" in e for e in errors), "Should reject '^' exponent operator")

  def test_reject_tuple_in_syntax(self):
    bad_query = "stage s { $e.metadata.event_type in (\"A\", \"B\") match: $h by 1h outcome: $c = count($e.metadata.id) }"
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("'in (\"A\", \"B\")'" in e for e in errors), "Should reject Python/SQL tuple syntax")

  def test_reject_by_24h_window(self):
    bad_query = "stage s { metadata.event_type = \"PROCESS_LAUNCH\" match: $h by 24h outcome: $c = count(metadata.id) }"
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("'by 24h' is invalid" in e for e in errors), "Should reject 'by 24h' in favor of 'by 1d'")

  def test_reject_dollar_stage_prefix(self):
    bad_query = "stage $bad_stage { metadata.event_type = \"PROCESS_LAUNCH\" match: $h by 1h outcome: $c = count(metadata.id) }"
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("must not have a '$' prefix" in e for e in errors), "Should reject '$' prefix in stage declarations")

  def test_reject_multivector_cramming(self):
    bad_query = """
    stage crammed_stage {
      $p.metadata.event_type = "PROCESS_LAUNCH"
      $a.metadata.event_type = "USER_LOGIN"
      match: $host by 1h
      outcome:
        $c = count($p.metadata.id)
    }
    $host = $crammed_stage.host
    match: $host by 1h
    outcome:
      $out = max($crammed_stage.c)
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("MULTI-VECTOR CRAMMING" in e for e in errors), "Should detect multi-vector event cramming in single stage")

  def test_reject_ecg_limit_exceeded(self):
    bad_query = """
    stage multi_ecg {
      $dns.metadata.event_type = "NETWORK_DNS"
      $g1.graph.entity.domain.prevalence.day_count = 10
      $g2.graph.entity.ip.prevalence.day_count = 5
      match: $host by 1h
      outcome:
        $c = count($dns.metadata.id)
    }
    $host = $multi_ecg.host
    match: $host by 1h
    outcome:
      $out = max($multi_ecg.c)
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("ECG LIMIT EXCEEDED" in e for e in errors), "Should enforce max 1 ECG lookup per stage")

  def test_reject_event_section_arithmetic(self):
    bad_stage_query = """
    // Methodology: Z_SCORE
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      $diff = $a - $b
      match: $host by 1h
      outcome: $c = count(metadata.id)
    }
    $host = $s1.host
    match: $host by 1h
    outcome: $out = max($s1.c)
    condition: $out > 0
    """
    errors = validate_multistage_syntax(bad_stage_query)
    self.assertTrue(any("ARITHMETIC_IN_EVENT_SECTION" in e for e in errors), "Should reject arithmetic above match: in named stage")

    bad_root_query = """
    // Methodology: Z_SCORE
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome: $c = count(metadata.id)
    }
    $host = $s1.host
    $diff = $s1.c - 10
    match: $host by 1h
    outcome: $out = max($s1.c)
    condition: $out > 0
    """
    errors = validate_multistage_syntax(bad_root_query)
    self.assertTrue(any("ARITHMETIC_IN_EVENT_SECTION" in e for e in errors), "Should reject arithmetic above match: in root stage")

  def test_reject_unbound_match_placeholder(self):
    bad_query = """
    // Methodology: Z_SCORE
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host, $unbound_var by 1h
      outcome: $c = count(metadata.id)
    }
    $host = $s1.host
    match: $host by 1h
    outcome: $out = max($s1.c)
    condition: $out > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("UNBOUND_MATCH_VARIABLE" in e for e in errors), "Should reject unbound match placeholder")

  def test_allow_outcome_arithmetic(self):
    valid_query = """
    // Methodology: Z_SCORE
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome:
        $obs = count(metadata.id)
    }
    stage s2 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome:
        $avg = avg(metadata.id)
        $std = stddev(metadata.id)
    }
    $host = $s1.host
    $host = $s2.host
    match: $host by 1h
    outcome:
      $diff = max($s1.obs) - max($s2.avg)
      $z = (max($s1.obs) - max($s2.avg)) / max($s2.std)
      $scaled = (max($s1.obs) * 1.5) + 2.0
    condition:
      $z > 3.0
    """
    errors = validate_multistage_syntax(valid_query)
    fatal_errors = [e for e in errors if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(fatal_errors, [], f"Expected zero errors for valid outcome arithmetic: {fatal_errors}")


  def test_service_account_repository_origin_intent_and_triggers(self):
    """SKILL.md and scope exclusions must document service account origin rarity and operational triggers."""
    skill_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    skill_path = os.path.join(skill_dir, "SKILL.md")
    scope_path = os.path.join(skill_dir, "references", "scope-exclusions-guardrail.md")
    with open(skill_path, "r", encoding="utf-8") as f:
      s_content = f.read()
    with open(scope_path, "r", encoding="utf-8") as f:
      sc_content = f.read()

    self.assertIn("service account out of normal behavioral scope", s_content)
    self.assertIn("POISSON_ORIGIN_RARITY", s_content)
    self.assertIn("The Train on a New Track", s_content)
    self.assertIn("Service Account Repository Access & Origin Scope Anomalies", sc_content)


if __name__ == "__main__":
  unittest.main()

