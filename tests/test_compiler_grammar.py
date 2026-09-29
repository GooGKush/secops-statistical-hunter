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

  def test_reject_bare_scalar_if_in_stage_outcome(self):
    """AST validator must reject bare scalar if() conditionals in intermediate stage outcomes."""
    bad_query = """
    stage s1 {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.asset.ip = $src_ip
      match: $src_ip by 1h
      outcome:
        $avg_gap = if(count(metadata.id) > 1, 10.0, 0.0)
    }
    $src_ip = $s1.src_ip
    match: $src_ip
    outcome:
      $val = max($s1.avg_gap)
    condition:
      $val > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("Bare scalar if() in intermediate stage outcome" in e for e in errors),
                    f"Expected bare scalar if rejection, got: {errors}")

  def test_c2_beaconing_jitter_template_passes_cleanly(self):
    """The rendered C2 beaconing jitter pipeline must pass syntax validation with zero fatal errors."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("C2_BEACONING_JITTER")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered C2 beaconing jitter pipeline had errors: {errors}")

  def test_reject_events_section_in_root_stage(self):
    """Root stage of a multi-stage query must not contain an events: block header."""
    bad_query = """
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome: $c = count(metadata.id)
    }
    events:
      $host = $s1.host
    match: $host by 1h
    outcome: $out = max($s1.c)
    condition: $out > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("INVALID_EVENTS_SECTION_IN_ROOT" in e for e in errors),
                    f"Expected INVALID_EVENTS_SECTION_IN_ROOT rejection, got: {errors}")

  def test_reject_member_dot_notation_in_match(self):
    """Match section must not contain member dot notation ($e.principal.hostname)."""
    bad_query = """
    metadata.event_type = "PROCESS_LAUNCH"
    match: $e.principal.hostname by 1h
    outcome: $c = count(metadata.id)
    condition: $c > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("INVALID_MATCH_DOT_NOTATION" in e for e in errors),
                    f"Expected INVALID_MATCH_DOT_NOTATION rejection, got: {errors}")

  def test_hybrid_entropy_concentration_template_passes_cleanly(self):
    """Rendered hybrid entropy concentration template must pass syntax validation cleanly."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("DIVERSITY_DEFICIT")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered hybrid entropy concentration had errors: {errors}")

  def test_markov_2gram_transition_rarity_template_passes_cleanly(self):
    """Rendered Markov 2-Gram transition rarity template must pass syntax validation cleanly."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("MARKOV_2GRAM_TRANSITION_RARITY")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered Markov 2-Gram pipeline had errors: {errors}")

  def test_shannon_entropy_character_template_passes_cleanly(self):
    """Rendered Shannon character entropy template must pass syntax validation cleanly."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("SHANNON_ENTROPY_CHARACTER")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered Shannon character entropy pipeline had errors: {errors}")

  def test_zipfian_process_rarity_template_passes_cleanly(self):
    """Rendered Zipfian process rarity template must pass syntax validation cleanly."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("ZIPFIAN_PROCESS_RARITY")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered Zipfian process rarity pipeline had errors: {errors}")

  def test_ewma_burst_velocity_template_passes_cleanly(self):
    """Rendered EWMA burst velocity template must pass syntax validation cleanly."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("EWMA_BURST_VELOCITY")
    errors = validate_multistage_syntax(query)
    self.assertEqual(errors, [], f"Rendered EWMA burst velocity pipeline had errors: {errors}")

  def test_root_stage_sequential_derivations_and_if_logic(self):
    """Terminal Root stage permits sequential derived assignments and safe if() logic."""
    good_query = """
    // Goal: Test sequential derivations and conditional logic in root stage
    // Statistical Model: Z-Score with safe denominator
    stage host_s {
      metadata.event_type = "PROCESS_LAUNCH"
      $entity = principal.hostname
      match: $entity by 1h
      outcome:
        $hourly_count = count(metadata.id)
    }
    stage host_stats {
      $entity = $host_s.entity
      match: $entity
      outcome:
        $host_mean = avg($host_s.hourly_count)
        $host_stddev = stddev($host_s.hourly_count)
    }
    $entity = $host_s.entity
    $entity = $host_stats.entity
    $window_start = $host_s.window_start
    match: $entity, $window_start by 1h
    outcome:
      $obs = max($host_s.hourly_count)
      $mean = max($host_stats.host_mean)
      $stddev = max($host_stats.host_stddev)
      $diff = $obs - $mean
      $safe_stddev = if($stddev > 0, $stddev, 1.0)
      $z_score = $diff / $safe_stddev
    condition:
      $z_score >= 3.0
    order:
      $z_score desc
    """
    errors = validate_multistage_syntax(good_query)
    self.assertEqual(errors, [], f"Root stage derivations should pass cleanly: {errors}")

  def test_reject_excessive_named_stages(self):
    """Rejects queries with > 3 named stages (allowance is strictly 1-3 named stages + root)."""
    four_named_stages = """
    // Goal: Test stage limit rejection
    // Statistical Model: Excessive stages
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      $u = principal.user.userid
      match: $u by 1h
      outcome: $c1 = count(metadata.id)
    }
    stage s2 {
      $u = $s1.u
      match: $u by 1h
      outcome: $c2 = max($s1.c1)
    }
    stage s3 {
      $u = $s2.u
      match: $u by 1h
      outcome: $c3 = max($s2.c2)
    }
    stage s4 {
      $u = $s3.u
      match: $u by 1h
      outcome: $c4 = max($s3.c3)
    }
    $u = $s4.u
    match: $u by 1h
    outcome:
      $final = max($s4.c4)
    condition:
      $final >= 1
    """
    errors = validate_multistage_syntax(four_named_stages)
    self.assertTrue(any("STAGE COUNT LIMIT EXCEEDED" in e for e in errors),
                    f"Expected STAGE COUNT LIMIT EXCEEDED rejection for 4 named stages, got: {errors}")

  def test_reject_cartesian_dummy_join(self):
    """Cartesian joins via $dummy = 1 or match: $dummy must be rejected."""
    bad_query = """
    stage ua_counts {
      metadata.event_type = "NETWORK_HTTP"
      network.http.user_agent = $ua
      principal.ip = $ip
      match: $ua by 1h
      outcome: $devs = count_distinct(principal.ip)
    }
    stage fleet_stats {
      $ua = $ua_counts.ua
      $dummy = 1
      match: $dummy
      outcome: $avg = avg($ua_counts.devs)
    }
    $ua = $ua_counts.ua
    $dummy = 1
    $dummy = $fleet_stats.dummy
    match: $ua by 1h
    outcome:
      $out = max($ua_counts.devs)
    condition:
      $out > 0
    """
    errors = validate_multistage_syntax(bad_query)
    self.assertTrue(any("CARTESIAN_DUMMY_JOIN" in e for e in errors),
                    f"Expected CARTESIAN_DUMMY_JOIN error, got: {errors}")

  def test_golden_rare_user_agent_prevalence_passes(self):
    """Golden example rare_user_agent_prevalence.yara must pass grammar and scope validation."""
    golden_path = os.path.join(os.path.dirname(__file__), "..", "examples", "rare_user_agent_prevalence.yara")
    self.assertTrue(os.path.exists(golden_path), f"Golden file must exist: {golden_path}")
    with open(golden_path, "r", encoding="utf-8") as f:
      content = f.read()
    violations = check_scope_exclusions(content)
    self.assertEqual(violations, [], f"Scope exclusions violated in rare_user_agent_prevalence.yara: {violations}")
    syntax_errors = validate_multistage_syntax(content)
    fatal_errors = [e for e in syntax_errors if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(fatal_errors, [], f"Syntax errors in rare_user_agent_prevalence.yara: {fatal_errors}")

  def test_function_factory_math_builtins_permitted(self):
    """Namespaced math.* built-ins (math.sqrt, math.log, math.exp, math.min, math.max) must pass syntax validation."""
    query = """
    stage s1 {
      metadata.event_type = "NETWORK_CONNECTION"
      principal.hostname = $host
      match: $host by 1h
      outcome:
        $bytes = sum(network.sent_bytes)
    }
    $host = $s1.host
    match: $host by 1h
    outcome:
      $log_b = math.log(max($s1.bytes) + 1.0)
      $dist = math.sqrt($log_b * $log_b)
      $clamped = math.min(math.max($dist, 0.0), 100.0)
      $calibrated = 100.0 / (1.0 + math.exp(-0.5 * ($clamped - 3.0)))
    condition:
      $calibrated >= 50.0
    """
    errors = validate_multistage_syntax(query)
    fatal_errors = [e for e in errors if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(fatal_errors, [], f"Unexpected syntax errors for math built-ins: {fatal_errors}")

  def test_bare_sqrt_rejected_but_math_sqrt_allowed(self):
    """Bare sqrt(...) must be rejected while math.sqrt(...) is permitted."""
    bare_sqrt_query = """
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome: $cnt = count(metadata.id)
    }
    $host = $s1.host
    match: $host by 1h
    outcome:
      $val = sqrt(max($s1.cnt))
    condition:
      $val > 0
    """
    errors = validate_multistage_syntax(bare_sqrt_query)
    self.assertTrue(any("INVALID_SQRT_FUNCTION" in e for e in errors), f"Must flag bare sqrt() as invalid, got: {errors}")

    math_sqrt_query = """
    stage s1 {
      metadata.event_type = "PROCESS_LAUNCH"
      principal.hostname = $host
      match: $host by 1h
      outcome: $cnt = count(metadata.id)
    }
    $host = $s1.host
    match: $host by 1h
    outcome:
      $val = math.sqrt(max($s1.cnt))
    condition:
      $val > 0
    """
    errors_valid = validate_multistage_syntax(math_sqrt_query)
    fatal_valid = [e for e in errors_valid if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(fatal_valid, [], f"math.sqrt() must be accepted, got: {fatal_valid}")

  def test_nested_if_conditionals_with_aggregations_pass(self):
    """if() conditionals containing nested aggregation calls (e.g. max(...)) must balance cleanly."""
    nested_if_query = """
    stage s1 {
      metadata.event_type = "USER_LOGIN"
      target.user.userid = $user
      match: $user by 1d
      outcome: $fails = count(metadata.id)
    }
    stage s2 {
      $user = $s1.user
      match: $user
      outcome: $sd = stddev($s1.fails)
    }
    $user = $s1.user
    $user = $s2.user
    match: $user by 1d
    outcome:
      $safe_sd = if(max($s2.sd) > 0, max($s2.sd), 1.0)
      $z = max($s1.fails) / $safe_sd
    condition:
      $z >= 3.0
    """
    errors = validate_multistage_syntax(nested_if_query)
    fatal_errors = [e for e in errors if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(fatal_errors, [], f"Nested if() with aggregations should pass cleanly, got: {fatal_errors}")


if __name__ == "__main__":
  unittest.main()



