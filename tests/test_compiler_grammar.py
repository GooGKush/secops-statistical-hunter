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


if __name__ == "__main__":
  unittest.main()
