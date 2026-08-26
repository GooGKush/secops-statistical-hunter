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
    # Host A: Highly predictable historical mean = 10, stddev = 1.0 (var = 1.0)
    # Gamma prior: beta_0 = 10 / 1 = 10; alpha_0 = 10 * 10 = 100
    # Observed spike: k = 30 events in 1h window (t = 1)
    # Posterior: alpha_post = 100 + 30 = 130; beta_post = 10 + 1 = 11
    # Posterior mean = 130 / 11 = 11.82
    # Prior weight = 10 / 11 = 90.9%; Evidence weight = 1 / 11 = 9.1%
    mu_a, sd_a = 10.0, 1.0
    var_a = sd_a ** 2
    beta_a = mu_a / var_a
    alpha_a = mu_a * beta_a

    obs_a = 30.0
    alpha_post_a = alpha_a + obs_a
    beta_post_a = beta_a + 1.0
    post_mean_a = alpha_post_a / beta_post_a

    self.assertAlmostEqual(post_mean_a, 11.82, places=2)
    self.assertAlmostEqual(beta_a / beta_post_a, 0.909, places=2)

  def test_beta_binomial_failure_shrinkage(self):
    # Prior: alpha_0 = 1.0, beta_0 = 9.0 (10% normal corporate failure rate, prior weight = 10 trials)
    # Case 1: 1 attempt, 1 failure (raw rate = 100%)
    # Posterior: alpha_post = 1 + 1 = 2; beta_post = 9 + 0 = 9; total = 11
    # Posterior fail prob = 2 / 11 = 18.2% (Shrinks 100% false alarm down to 18%)
    alpha_0, beta_0 = 1.0, 9.0
    fails_1, successes_1 = 1, 0
    post_prob_1 = (alpha_0 + fails_1) / (alpha_0 + beta_0 + fails_1 + successes_1)
    self.assertAlmostEqual(post_prob_1, 0.1818, places=3)

    # Case 2: 100 attempts, 90 failures (sustained attack)
    # Posterior: alpha_post = 1 + 90 = 91; beta_post = 9 + 10 = 19; total = 110
    # Posterior fail prob = 91 / 110 = 82.7% (Confirmed high-confidence attack)
    fails_2, successes_2 = 90, 10
    post_prob_2 = (alpha_0 + fails_2) / (alpha_0 + beta_0 + fails_2 + successes_2)
    self.assertAlmostEqual(post_prob_2, 0.8272, places=3)

  def test_fano_factor_physics(self):
    # Pure Poisson arrival: variance == mean -> F = 1.0
    mean_p = 10.0
    var_p = 10.0
    fano_p = var_p / mean_p
    self.assertEqual(fano_p, 1.0)

    # Attack burst clustering: mean = 10, variance = 100 -> F = 10.0
    var_burst = 100.0
    fano_burst = var_burst / mean_p
    self.assertEqual(fano_burst, 10.0)
    self.assertGreater(fano_burst, 4.0, "Fano factor should flag burst clustering threshold")


if __name__ == "__main__":
  unittest.main()
