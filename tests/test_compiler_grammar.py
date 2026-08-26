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


if __name__ == "__main__":
  unittest.main()
