"""Unit tests for statistical models, Bayesian updating, and threshold scaling."""

import math
import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import calculate_fleet_adjusted_threshold, SENSITIVITY_MAP


class TestMathModels(unittest.TestCase):

  def test_bonferroni_fleet_scaling(self):
    # Base threshold: 3.0
    # For N=1, should remain base threshold 3.0
    self.assertEqual(calculate_fleet_adjusted_threshold(3.0, 1), 3.0)

    # For N=50, Z_adj ~ sqrt(2 * ln(50)) = sqrt(2 * 3.912) = sqrt(7.824) = 2.80 -> base 3.0
    z_50 = calculate_fleet_adjusted_threshold(3.0, 50)
    self.assertGreaterEqual(z_50, 3.0)

    # For N=5000, sqrt(2 * ln(5000)) = sqrt(2 * 8.517) = sqrt(17.034) = 4.13
    z_5000 = calculate_fleet_adjusted_threshold(3.0, 5000)
    self.assertAlmostEqual(z_5000, 4.13, places=2)

    # For N=50000, sqrt(2 * ln(50000)) = sqrt(2 * 10.82) = 4.65
    z_50000 = calculate_fleet_adjusted_threshold(3.0, 50000)
    self.assertAlmostEqual(z_50000, 4.65, places=2)

  def test_poisson_gamma_bayesian_shrinkage(self):
    """WS5 / WS0-01: Empirical-Bayes leave-one-out Gamma-Poisson shrinkage & excess overdispersion predictive Z."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("BAYESIAN_GAMMA_SHRINKAGE", tier="BALANCED", window_hours=168.0, bucket_size="1h")
    self.assertIn("$alpha_prior = 2.0 + $prior_sum", query)
    self.assertIn("$beta_prior = 2.0 + 167", query)
    self.assertIn("$raw_excess_var =", query)
    self.assertIn("$bayesian_z = ($observation_count - $baseline_mean) / $baseline_dispersion", query)

    # Evaluate exact bayesian_gamma_shrinkage_4stage.yl2 equations (alpha_0=2.0, beta_0=2.0):
    alpha_0, beta_0 = 2.0, 2.0
    # 1. Sparse host (T_prior = 10 buckets, prior_sum = 100) shrinks more toward prior rate (1.0)
    #    than dense host (T_prior = 167 buckets, prior_sum = 1670) at the same empirical rate (10.0/hr):
    sparse_mean = (alpha_0 + 100.0) / (beta_0 + 10.0)
    dense_mean = (alpha_0 + 1670.0) / (beta_0 + 167.0)
    self.assertLess(abs(sparse_mean - 1.0), abs(dense_mean - 1.0))

    # 2. Predictable host (167 prior hours at steady 10/hr -> sum_x=1670, sum_x2=16700, excess_var=0)
    #    hit with k=45 spike fires strongly ($bayesian_z >= 3.0):
    t_prior = 167.0
    prior_sum, prior_sum_sq = 1670.0, 16700.0
    alpha_p = alpha_0 + prior_sum
    beta_p = beta_0 + t_prior
    base_mean = alpha_p / beta_p
    emp_mean = prior_sum / t_prior
    excess_var_steady = max(0.0, (prior_sum_sq / t_prior) - (emp_mean ** 2) - emp_mean)
    self.assertEqual(excess_var_steady, 0.0)
    pred_sd_steady = math.sqrt(max(1.0, (base_mean * (beta_p + 1.0) / beta_p) + excess_var_steady))
    z_steady = (45.0 - base_mean) / pred_sd_steady
    self.assertGreater(z_steady, 10.0)

    # 3. Chronically bursty host with same mean (prior_sum=1670) but high prior sum_x2=90000 is dampened:
    excess_var_bursty = max(0.0, (90000.0 / t_prior) - (emp_mean ** 2) - emp_mean)
    pred_sd_bursty = math.sqrt(max(1.0, (base_mean * (beta_p + 1.0) / beta_p) + excess_var_bursty))
    z_bursty = (45.0 - base_mean) / pred_sd_bursty
    self.assertLess(z_bursty, 2.0)

  def test_beta_binomial_failure_shrinkage(self):
    """WS5 / WS0-01: Leave-one-out conjugate Beta(1, 19) prior & Beta-Binomial predictive failure Z."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("BETA_BINOMIAL_FAILURE", tier="BALANCED", window_hours=168.0, bucket_size="1h")
    self.assertIn("$alpha_prior = 1.0 + $prior_fails", query)
    self.assertIn("$beta_prior = 19.0 + $prior_succ", query)
    self.assertIn("$fail_z = ($observation_count - ($safe_trials * $baseline_mean)) / $baseline_dispersion", query)

    # Evaluate exact beta_binomial_failure_4stage.yl2 equations with clean prior history (200 successes, 4 failures):
    alpha_0, beta_0 = 1.0, 19.0
    prior_fails, prior_succ = 4.0, 196.0
    alpha_p = alpha_0 + prior_fails   # 5.0
    beta_p = beta_0 + prior_succ      # 215.0
    prior_total = alpha_p + beta_p    # 220.0
    p0 = alpha_p / prior_total        # ~2.27%

    # Case 1: 1 attempt, 1 failure (raw rate = 100%) shrinks to posterior ~2.71% and does NOT alert (fail_z < 3.0)
    n1, f1 = 1.0, 1.0
    post_prob_1 = (alpha_p + f1) / (prior_total + n1)
    pred_var_1 = max(0.25, n1 * p0 * (1.0 - p0) * ((prior_total + n1) / (prior_total + 1.0)))
    fail_z_1 = (f1 - n1 * p0) / math.sqrt(pred_var_1)
    self.assertLess(post_prob_1, 0.05)
    self.assertLess(fail_z_1, 3.0)

    # Case 2: 30 attempts, 25 failures (credential-stuffing / spray wave) alerts strongly (fail_z >> 3.5)
    n2, f2 = 30.0, 25.0
    pred_var_2 = max(0.25, n2 * p0 * (1.0 - p0) * ((prior_total + n2) / (prior_total + 1.0)))
    fail_z_2 = (f2 - n2 * p0) / math.sqrt(pred_var_2)
    self.assertGreater(fail_z_2, 15.0)

  def test_fano_factor_physics(self):
    """WS1-06 / PF-4: Zero-inclusive Fano dispersion reconstructs missing zero buckets across T."""
    from multistage_query_builder import MultiStageTemplateRouter, compute_total_window_buckets
    router = MultiStageTemplateRouter()
    t_buckets = compute_total_window_buckets(168.0, "1h")
    self.assertEqual(t_buckets, 168)
    query = router.build_query("POISSON_BURST_CLUSTERING", tier="BALANCED", window_hours=168.0, bucket_size="1h")
    self.assertIn("$zero_incl_mean = 1.0 * $sum_x / 168", query)
    self.assertIn("$mean_sq = 1.0 * $sum_x2 / 168", query)

    # Pure Poisson arrival: variance == mean -> F = 1.0
    mean_p = 10.0
    var_p = 10.0
    self.assertEqual(var_p / mean_p, 1.0)

    # Concentrated spray: 5 hours with 60 failures each, 163 silent zero hours (active-only variance = 0!)
    sum_x = 5.0 * 60.0
    sum_x2 = 5.0 * (60.0 ** 2)
    zero_incl_mean = sum_x / t_buckets
    zero_incl_var = (sum_x2 / t_buckets) - (zero_incl_mean ** 2)
    fano_burst = zero_incl_var / zero_incl_mean
    self.assertAlmostEqual(fano_burst, 58.2143, places=3)
    self.assertGreater(fano_burst, 4.0, "Zero-inclusive Fano factor must flag concentrated spray bursts")

  def test_dynamic_threshold_condition_band(self):
    """Router must inject sensitivity band ($score >= min and $score < max) into root condition."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    q = router.build_query("ZSCORE_PROCESS_SURGE", min_threshold=2.0, max_threshold=3.0)
    self.assertIn("condition:", q)
    self.assertIn("$z_score >= 2.0 and $z_score < 3.0", q)

  def test_dynamic_condition_expression_override(self):
    """Router must inject custom compound condition expression into root condition."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    custom_expr = "$z_score >= 3.5 and $observation_count >= 50"
    q = router.build_query("ZSCORE_PROCESS_SURGE", condition_expression=custom_expr)
    self.assertIn("condition:", q)
    self.assertIn(custom_expr, q)

  def test_6_hybrid_mathematical_archetypes_compile_cleanly(self):
    """All 6 hybrid mathematical models must route and compile into valid YARA-L."""
    from multistage_query_builder import MultiStageTemplateRouter, check_scope_exclusions, validate_multistage_syntax
    router = MultiStageTemplateRouter()
    hybrid_models = [
        "DIVERSITY_DEFICIT",
        "ELEPHANT_FLOW_CONCENTRATION",
        "ORTHOGONAL_THREAT_SPACE",
        "BAYESIAN_JOINT_ODDS",
        "TWO_PART_HURDLE",
        "FLEET_PREVALENCE_NORMALIZATION",
    ]
    for model in hybrid_models:
      query = router.build_query(model, tier="BALANCED")
      self.assertEqual(check_scope_exclusions(query), [], f"Scope exclusion failed for {model}")
      errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
      self.assertEqual(errs, [], f"Syntax validation failed for {model}: {errs}")

  def test_log_normal_volume_model_compiles_cleanly(self):
    """LOG_NORMAL_VOLUME_SURGE model must compile cleanly with math.log and math.pow (without math.exp)."""
    from multistage_query_builder import MultiStageTemplateRouter, check_scope_exclusions, validate_multistage_syntax
    router = MultiStageTemplateRouter()
    query = router.build_query("LOG_NORMAL_VOLUME_SURGE", tier="BALANCED")
    self.assertEqual(check_scope_exclusions(query), [])
    errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(errs, [], f"Syntax validation failed for LOG_NORMAL_VOLUME_SURGE: {errs}")
    self.assertIn("math.log(", query)
    self.assertNotIn("math.exp(", query)
    self.assertIn("math.pow(", query)
    self.assertIn("$z_log", query)

  def test_euclidean_threat_distance_uses_math_sqrt(self):
    """MULTI_SECTOR_THREAT_FUSION and ORTHOGONAL_THREAT_SPACE must use math.sqrt for true distance."""
    from multistage_query_builder import MultiStageTemplateRouter, check_scope_exclusions, validate_multistage_syntax
    router = MultiStageTemplateRouter()
    query = router.build_query("MULTI_SECTOR_THREAT_FUSION", tier="BALANCED")
    self.assertEqual(check_scope_exclusions(query), [])
    errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(errs, [], f"Syntax validation failed for MULTI_SECTOR_THREAT_FUSION: {errs}")
    self.assertIn("math.sqrt(", query)
    self.assertIn("$threat_distance", query)

  def test_markov_2gram_surprisal_math(self):
    """WS5 / WS0-01: Whole-window Laplace-smoothed Markov 2-Gram surprisal ln((N_parent + V)/(N_pair + 1)) without step cliff."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("MARKOV_2GRAM_TRANSITION_RARITY", tier="BALANCED")
    self.assertNotIn("rare_multiplier", query)
    self.assertIn("$markov_threat_score = math.log(($window_parent_launches + 100.0) / ($window_pair_launches + 1.0))", query)

    parent_count = 100.0
    vocab_smooth = 100.0
    s1 = math.log((parent_count + vocab_smooth) / (1.0 + 1.0))  # ln(200 / 2) = ln(100)
    s2 = math.log((parent_count + vocab_smooth) / (2.0 + 1.0))  # ln(200 / 3)
    s3 = math.log((parent_count + vocab_smooth) / (3.0 + 1.0))  # ln(200 / 4)
    self.assertAlmostEqual(s1, 4.6052, places=3)
    self.assertGreater(s1, s2)
    self.assertGreater(s2, s3)
    # Continuous transition from 2nd to 3rd execution (ln(4/3) ~ 0.2877, never a 2x step drop)
    self.assertAlmostEqual(s2 - s3, math.log(4.0 / 3.0), places=6)

  def test_shannon_entropy_character_math(self):
    """WS6-03 / WS0-01: Per-character Shannon entropy H(s) = -sum p(c) log2 p(c) replaces log(length) proxy."""
    from micro_python_helpers import compute_shannon_entropy_bits
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("SHANNON_ENTROPY_CHARACTER", tier="BALANCED")
    self.assertIn("$sample_entities = array_distinct($entity)", query)
    self.assertNotIn("math.log(", query)

    # Identical length (48 chars), completely different true character entropy:
    low_entropy_str = "a" * 48
    high_entropy_hex = "0123456789abcdef" * 3
    self.assertEqual(compute_shannon_entropy_bits(low_entropy_str), 0.0)
    self.assertAlmostEqual(compute_shannon_entropy_bits(high_entropy_hex), 4.0, places=6)

  def test_zipfian_long_tail_rarity_math(self):
    """WS5 / WS0-01: Pure host-prevalence IDF rarity ln(N_fleet_hosts / N_adopter_hosts) avoids event-volume mixing."""
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("ZIPFIAN_PROCESS_RARITY", tier="BALANCED")
    self.assertIn("$zipf_rarity_score = math.log(1.0 * $safe_fleet_hosts / $safe_hosts)", query)

    safe_fleet_hosts = 1000.0
    single_host_rarity = math.log(safe_fleet_hosts / 1.0)
    broad_daemon_rarity = math.log(safe_fleet_hosts / 500.0)
    self.assertAlmostEqual(single_host_rarity, 6.9078, places=3)
    self.assertAlmostEqual(broad_daemon_rarity, math.log(2.0), places=6)
    self.assertGreater(single_host_rarity, 2.5)
    self.assertLess(broad_daemon_rarity, 2.5)

  def test_ewma_burst_velocity_math(self):
    """WS6-02 / WS0-01: True recursive EWMA S_t = lambda*x_t + (1-lambda)*S_{t-1} via micro_python_helpers."""
    from micro_python_helpers import run_ewma_helper
    from multistage_query_builder import MultiStageTemplateRouter
    router = MultiStageTemplateRouter()
    query = router.build_query("EWMA_BURST_VELOCITY", tier="BALANCED", window_hours=24.0)

    # 24-hour window [0..23]: hours 0..11 alternate 8 and 12 (mu_0=10, s_0=sqrt(12*4/11)=2.08893),
    # hours 12..23 jump to 20 -> sustained shift breaches asymptotic UCL = mu_0 + 3*sigma_0*sqrt(lambda/(2-lambda)).
    base_epoch = 1761523200  # 2025-10-27T00:00:00Z
    ws_vals = [str(base_epoch + h * 3600) for h in range(24)]
    cnt_vals = [str(8 if h % 2 == 0 else 12) if h < 12 else "20" for h in range(24)]
    payload = {
        "stats": {
            "results": [
                {"column": "entity", "values": [{"value": {"stringVal": "srv-ewma-01"}} for _ in range(24)]},
                {"column": "ws", "values": [{"value": {"int64Val": w}} for w in ws_vals]},
                {"column": "window_events", "values": [{"value": {"int64Val": c}} for c in cnt_vals]},
            ]
        }
    }
    res = run_ewma_helper(
        payload,
        query_text=query,
        start_time="2025-10-27T00:00:00Z",
        end_time="2025-10-28T00:00:00Z",
        lambda_weight=0.25,
        control_l=3.0,
    )
    self.assertEqual(len(res["outliers"]), 1)
    rec = res["outliers"][0]
    expected_asymp = math.sqrt(0.25 / 1.75)
    self.assertAlmostEqual(rec["sigma_ewma"] / rec["baseline_dispersion"], expected_asymp, places=5)
    self.assertGreater(rec["ewma_z"], 3.0)

  def test_new_analytical_models_compile_across_all_tiers(self):
    """All 4 new models must route and compile across CONSERVATIVE, BALANCED, and AGGRESSIVE tiers."""
    from multistage_query_builder import MultiStageTemplateRouter, check_scope_exclusions, validate_multistage_syntax
    router = MultiStageTemplateRouter()
    new_models = [
        "MARKOV_2GRAM_TRANSITION_RARITY",
        "SHANNON_ENTROPY_CHARACTER",
        "ZIPFIAN_PROCESS_RARITY",
        "EWMA_BURST_VELOCITY",
        "IQR_TUKEY_SKEW_FENCES",
    ]
    tiers = ["CONSERVATIVE", "BALANCED", "AGGRESSIVE"]
    for model in new_models:
      for tier in tiers:
        query = router.build_query(model, tier=tier)
        self.assertEqual(check_scope_exclusions(query), [], f"Scope exclusion failed for {model} [{tier}]")
        errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
        self.assertEqual(errs, [], f"Syntax validation failed for {model} [{tier}]: {errs}")

  def test_iqr_tukey_skew_fences_and_bowley_math(self):
    """1-Stage Quantile envelope, Bowley skewness, tail-heaviness ratio, and Hubert-Vandervieren fence evaluate accurately."""
    from multistage_query_builder import MultiStageTemplateRouter, validate_multistage_syntax
    router = MultiStageTemplateRouter()
    query = router.build_query("IQR_TUKEY_SKEW_FENCES", tier="BALANCED")
    self.assertIn("window.percentile($daily_stats.daily_value, 10)", query)
    self.assertIn("window.percentile($daily_stats.daily_value, 25)", query)
    self.assertIn("window.percentile($daily_stats.daily_value, 50)", query)
    self.assertIn("window.percentile($daily_stats.daily_value, 75)", query)
    self.assertIn("window.percentile($daily_stats.daily_value, 90)", query)
    self.assertIn("$bowley_skew", query)
    self.assertIn("$tail_heaviness", query)
    self.assertIn("$adj_upper_fence", query)
    self.assertIn("$fence_z", query)
    self.assertIn("order:\n  $fence_z desc", query)
    self.assertIn("stage fleet_breadth", query)
    errs = [e for e in validate_multistage_syntax(query) if not e.startswith("MISSING METHODOLOGY HEADER")]
    self.assertEqual(errs, [])

    # Verify Bowley skewness & recalibrated Hubert-Vandervieren fence math (1.35 * B_skew)
    q25, q50, q75 = 111.0, 112.0, 114.0
    iqr = q75 - q25
    bowley_skew = (q75 + q25 - 2.0 * q50) / iqr
    self.assertAlmostEqual(bowley_skew, 1.0 / 3.0, places=4)
    pos_skew = max(0.0, bowley_skew)
    adj_fence = q75 + 1.5 * math.pow(2.718281828, 1.35 * pos_skew) * iqr
    self.assertAlmostEqual(adj_fence, 121.0574, places=3)
    robust_scale = iqr / 1.349
    fence_z = (130.0 - adj_fence) / robust_scale
    self.assertAlmostEqual(fence_z, 4.0212, places=3)


if __name__ == "__main__":
  unittest.main()

