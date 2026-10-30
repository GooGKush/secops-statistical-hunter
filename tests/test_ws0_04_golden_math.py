# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""WS0-04: Synthetic Golden-Math & Offline D6-G4 Helper Verification Suite.

Deterministic mathematical verification suite for `secops-statistical-hunter` covering:
  1. Zero-Inclusive Fano Dispersion (PF-4, WS1-06):
     - Active-only variance blind spot (F_active = 0.0) vs zero-inclusive T=168 reconstruction
       (F = 58.214285714... matching statistics.pvariance / statistics.fmean to 1e-9).
     - Seeded pure Poisson traffic (lambda=5.0, random.Random(42), T=1000) within +/-20% of F=1.0.
  2. Learned 24-Bin Hour-of-Day Profile (WS5-HOD, D1):
     - 14-day series (D_base=13 pre-scoring days + day 14 scored out-of-sample) verifying routine
       business-hour login (Z_hod = 0.0, hour_profile_mass = 1/9), sporadic zero-day reconstruction,
       and 03:00 UTC out-of-profile anomaly (Z_hod = +10.0 >= 3.0, hour_profile_mass = 0.0).
  3. Sample-SD Samuelson Cap (N-1)/sqrt(N), MAD Constants (0.6745 / 1.253314), and
     Recalibrated 1.35 Bowley-Tukey Fence Excess Z:
     - Exact Samuelson bound across N in {2, 7, 10, 11, 30} proving N=10 < 3.0 < N=11.
     - Normal consistency constants Phi^-1(0.75) = 0.67448975 and sqrt(pi/2) = 1.253314137 plus
       MAD=0 -> meanAD*1.253314 fallback.
     - Bounded Bowley skewness B in [-1, 1] and recalibrated exp(1.35 * max(0, B)) excess Z.
  4. Empirical-Bayes Gamma Shrinkage & Leave-One-Out Beta-Binomial Failure (WS5):
     - Sparse vs dense shrinkage monotonicity, +10 sigma spike firing on predictable host, and
       excess overdispersion dampening on chronically bursty host.
     - Leave-one-out Beta-Binomial: 1/1 failure suppressed (Z_fail < 3.0), 25/30 failure surge
       alerts strongly (Z_fail > 3.5), chronic failing service account dampened.
  5. Offline D6-G4 Verification of `scripts/micro_python_helpers.py` (WS6-02..04):
     - `socket.socket`, `socket.create_connection`, and `urllib.request.urlopen` monkeypatched
       to raise AssertionError("Network call forbidden by D6-G4").
     - EWMA (lambda=0.25, missing zero buckets filled, sqrt(lambda/(2-lambda)) = sqrt(1/7),
       sustained +1.8 sigma 4-hour shift triggers EWMA while single-hour Z stays < 3.0).
     - Shannon entropy exact bits/char (0.0, 1.0, 2.0, 4.0) and length-matched cohort Z.
     - C2 jitter clockwork 60s periodic arrivals across stitched hourly buckets (CV = 0.0000),
       seeded exponential arrivals (>= 200 events, CV ~ 1.0 +/- 20%), and exclusion of multicast
       (224.0.0.251), link-local (169.254.169.254), and internal RFC1918 destinations.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import random
import socket
import statistics
import sys
import tempfile
import unittest
from unittest import mock
import urllib.request
from typing import Any, Dict, List, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

import micro_python_helpers as mph  # pylint: disable=wrong-import-position
from multistage_query_builder import (  # pylint: disable=wrong-import-position
    MultiStageTemplateRouter,
    QueryIntegrityGate,
    compute_hod_window_slots,
    compute_total_window_buckets,
)


def _knuth_poisson(rng: random.Random, lam: float) -> int:
  """Exact Knuth inverse-transform Poisson variate generator using deterministic stdlib Random."""
  threshold = math.exp(-lam)
  k = 0
  prod = 1.0
  while True:
    k += 1
    prod *= rng.random()
    if prod <= threshold:
      return k - 1


def _make_chronicle_cell(val: Any) -> Dict[str, Any]:
  """Builds realistic Chronicle udmSearch stats cell JSON (including list.values for array_distinct)."""
  if isinstance(val, list):
    inner = []
    for item in val:
      if isinstance(item, int):
        inner.append({"int64Val": str(item)})
      elif isinstance(item, float):
        inner.append({"doubleVal": item})
      else:
        inner.append({"stringVal": str(item)})
    return {"list": {"values": inner}}
  if isinstance(val, bool):
    return {"value": {"boolVal": val}}
  if isinstance(val, int):
    return {"value": {"int64Val": str(val)}}
  if isinstance(val, float):
    return {"value": {"doubleVal": val}}
  return {"value": {"stringVal": str(val)}}


def _make_stats_payload(columns: Dict[str, Sequence[Any]]) -> Dict[str, Any]:
  """Builds a realistic columnar Chronicle udmSearch stats response."""
  results = []
  for col_name, values in columns.items():
    col_entry: Dict[str, Any] = {"column": col_name}
    if values:
      col_entry["values"] = [_make_chronicle_cell(v) for v in values]
    results.append(col_entry)
  return {"stats": {"results": results, "hasJoin": True}}


def _eval_poisson_burst_fano(sum_x: float, sum_x2: float, total_buckets: int) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `poisson_burst_clustering_2stage.yl2`."""
  zero_incl_mean = 1.0 * sum_x / float(total_buckets)
  mean_sq = 1.0 * sum_x2 / float(total_buckets)
  raw_var = mean_sq - (zero_incl_mean * zero_incl_mean)
  zero_incl_var = raw_var if raw_var > 0.0 else 0.0
  zero_incl_sd = math.sqrt(zero_incl_var)
  safe_mean = zero_incl_mean if zero_incl_mean > 0.0 else 1.0
  raw_fano = zero_incl_var / safe_mean
  fano_factor = raw_fano if zero_incl_mean > 0.0 else 0.0
  return {
      "zero_incl_mean": zero_incl_mean,
      "zero_incl_var": zero_incl_var,
      "zero_incl_sd": zero_incl_sd,
      "fano_factor": fano_factor,
  }


def _eval_hod_profile_bucket(
    observed: float,
    sum_x_hod: float,
    sum_x2_hod: float,
    baseline_days: int,
    entity_base_total: float,
) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `hour_of_day_profile_3stage.yl2`."""
  mu_hod = 1.0 * sum_x_hod / float(baseline_days)
  raw_var_hod = (1.0 * sum_x2_hod / float(baseline_days)) - (mu_hod * mu_hod)
  var_hod = raw_var_hod if raw_var_hod > 0.0 else 0.0
  sd_hod = math.sqrt(var_hod)
  floor_arg = mu_hod if mu_hod > 1.0 else 1.0
  floor_hod = math.sqrt(floor_arg)
  safe_sd_hod = sd_hod if sd_hod > floor_hod else floor_hod
  safe_entity_total = entity_base_total if entity_base_total > 0.0 else 1.0
  hour_profile_mass = sum_x_hod / safe_entity_total
  hod_z_score = (observed - mu_hod) / safe_sd_hod
  return {
      "mu_hod": mu_hod,
      "var_hod": var_hod,
      "sd_hod": sd_hod,
      "safe_sd_hod": safe_sd_hod,
      "hour_profile_mass": hour_profile_mass,
      "hod_z_score": hod_z_score,
  }


def _eval_mad_modified_z(series: Sequence[float], observed: float, dispersion_floor: float = 1.0) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `mad_modified_z_4stage.yl2`."""
  baseline_median = float(statistics.median(series))
  abs_devs = [abs(x - baseline_median) for x in series]
  baseline_dispersion = float(statistics.median(abs_devs))
  baseline_mean_abs_dev = float(sum(abs_devs) / len(abs_devs))
  scale_from_mad = baseline_dispersion / 0.6745
  scale_from_meanad = baseline_mean_abs_dev * 1.253314
  robust_scale = scale_from_mad if baseline_dispersion > 0.0 else scale_from_meanad
  safe_robust_scale = robust_scale if robust_scale > 0.0 else dispersion_floor
  m_z_score = (observed - baseline_median) / safe_robust_scale
  return {
      "baseline_median": baseline_median,
      "mad": baseline_dispersion,
      "mean_ad": baseline_mean_abs_dev,
      "safe_robust_scale": safe_robust_scale,
      "m_z_score": m_z_score,
  }


def _eval_bowley_tukey_fence(
    q25_val: float,
    q50_val: float,
    q75_val: float,
    observed: float,
    p10_val: float = 0.0,
    p90_val: float = 0.0,
) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `iqr_tukey_skew_fences_3stage.yl2`."""
  baseline_dispersion = q75_val - q25_val
  rel_floor = 0.01 * q50_val
  iqr_floor = rel_floor if rel_floor > 1.0 else 1.0
  safe_iqr = baseline_dispersion if baseline_dispersion > iqr_floor else iqr_floor
  bowley_skew = (q75_val + q25_val - (2.0 * q50_val)) / safe_iqr
  tail_heaviness = (p90_val - p10_val) / safe_iqr
  pos_skew = bowley_skew if bowley_skew > 0.0 else 0.0
  skew_exp = math.pow(2.718281828, 1.35 * pos_skew)
  adj_upper_fence = q75_val + (1.5 * skew_exp * safe_iqr)
  fence_z = (observed - adj_upper_fence) / (safe_iqr / 1.349)
  return {
      "safe_iqr": safe_iqr,
      "bowley_skew": bowley_skew,
      "tail_heaviness": tail_heaviness,
      "adj_upper_fence": adj_upper_fence,
      "fence_z": fence_z,
  }


def _eval_bayesian_gamma_shrinkage(
    observed: float,
    total_sum_x: float,
    total_sum_x2: float,
    prior_window_buckets: int,
    prior_alpha0: float = 2.0,
    prior_beta0: float = 2.0,
) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `bayesian_gamma_shrinkage_4stage.yl2`."""
  raw_prior_sum = total_sum_x - observed
  prior_sum = raw_prior_sum if raw_prior_sum > 0.0 else 0.0
  raw_prior_sum_sq = total_sum_x2 - (1.0 * observed * observed)
  prior_sum_sq = raw_prior_sum_sq if raw_prior_sum_sq > 0.0 else 0.0
  alpha_prior = prior_alpha0 + prior_sum
  beta_prior = prior_beta0 + float(prior_window_buckets)
  baseline_mean = alpha_prior / beta_prior
  posterior_arrival_rate = (alpha_prior + observed) / (beta_prior + 1.0)
  prior_emp_mean = 1.0 * prior_sum / float(prior_window_buckets)
  raw_excess_var = (
      (1.0 * prior_sum_sq / float(prior_window_buckets))
      - (prior_emp_mean * prior_emp_mean)
      - prior_emp_mean
  )
  excess_var = raw_excess_var if raw_excess_var > 0.0 else 0.0
  raw_pred_var = (baseline_mean * (beta_prior + 1.0) / beta_prior) + excess_var
  safe_pred_var = raw_pred_var if raw_pred_var > 1.0 else 1.0
  baseline_dispersion = math.sqrt(safe_pred_var)
  bayesian_z = (observed - baseline_mean) / baseline_dispersion
  return {
      "baseline_mean": baseline_mean,
      "posterior_arrival_rate": posterior_arrival_rate,
      "excess_var": excess_var,
      "baseline_dispersion": baseline_dispersion,
      "bayesian_z": bayesian_z,
  }


def _eval_beta_binomial_failure(
    obs_fails: float,
    obs_trials: float,
    total_hist_fails: float,
    total_hist_events: float,
    prior_alpha0: float = 1.0,
    prior_beta0: float = 19.0,
) -> Dict[str, float]:
  """Evaluates exact Root outcome math of `beta_binomial_failure_4stage.yl2`."""
  safe_trials = obs_trials if obs_trials > 0.0 else 1.0
  raw_prior_fails = total_hist_fails - obs_fails
  prior_fails = raw_prior_fails if raw_prior_fails > 0.0 else 0.0
  raw_prior_events = total_hist_events - obs_trials
  prior_events = raw_prior_events if raw_prior_events > prior_fails else prior_fails
  prior_succ = prior_events - prior_fails
  alpha_prior = prior_alpha0 + prior_fails
  beta_prior = prior_beta0 + prior_succ
  prior_total = alpha_prior + beta_prior
  baseline_mean = alpha_prior / prior_total
  posterior_fail_prob = (alpha_prior + obs_fails) / (prior_total + safe_trials)
  pred_var = (
      safe_trials
      * baseline_mean
      * (1.0 - baseline_mean)
      * ((prior_total + safe_trials) / (prior_total + 1.0))
  )
  safe_pred_var = pred_var if pred_var > 0.25 else 0.25
  baseline_dispersion = math.sqrt(safe_pred_var)
  fail_z = (obs_fails - (safe_trials * baseline_mean)) / baseline_dispersion
  return {
      "baseline_mean": baseline_mean,
      "posterior_fail_prob": posterior_fail_prob,
      "baseline_dispersion": baseline_dispersion,
      "fail_z": fail_z,
  }


class TestWS004ZeroInclusiveFanoGolden(unittest.TestCase):
  """1. Zero-Inclusive Fano Dispersion (PF-4, WS1-06) golden math verification."""

  def test_concentrated_spray_168h_vs_active_only_blind_spot(self) -> None:
    router = MultiStageTemplateRouter()
    t_buckets = compute_total_window_buckets(168.0, "1h")
    self.assertEqual(t_buckets, 168)

    rendered = router.build_query(
        "POISSON_BURST_CLUSTERING",
        tier="BALANCED",
        window_hours=168.0,
        bucket_size="1h",
    )
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(rendered)["valid"])
    self.assertIn("$zero_incl_mean = 1.0 * $sum_x / 168", rendered)
    self.assertIn("$mean_sq = 1.0 * $sum_x2 / 168", rendered)

    # Synthetic 168-hour series: 60 failures in each of 5 hours, 0 in remaining 163 hours
    active_only_vec = [60.0] * 5
    full_168_vec = [60.0] * 5 + [0.0] * 163
    self.assertEqual(len(full_168_vec), 168)

    # Active-only variance (pre-WS1-06 bug) collapses to 0.0!
    fano_active_only = statistics.pvariance(active_only_vec) / statistics.fmean(active_only_vec)
    self.assertEqual(fano_active_only, 0.0)

    # Zero-inclusive template formula matches exact population variance / mean to < 1e-9
    sum_x = sum(active_only_vec)               # 300.0
    sum_x2 = sum(x * x for x in active_only_vec)  # 18000.0
    self.assertEqual(sum_x, 300.0)
    self.assertEqual(sum_x2, 18000.0)

    res = _eval_poisson_burst_fano(sum_x, sum_x2, total_buckets=168)
    expected_mu = statistics.fmean(full_168_vec)
    expected_var = statistics.pvariance(full_168_vec)
    expected_fano = expected_var / expected_mu

    self.assertAlmostEqual(res["zero_incl_mean"], 300.0 / 168.0, delta=1e-9)
    self.assertAlmostEqual(res["zero_incl_var"], expected_var, delta=1e-9)
    self.assertAlmostEqual(res["fano_factor"], expected_fano, delta=1e-9)
    self.assertAlmostEqual(res["fano_factor"], 58.214285714, delta=1e-6)
    self.assertGreater(res["fano_factor"], 4.0)

  def test_seeded_poisson_traffic_yields_unit_fano_within_20_percent(self) -> None:
    rng = random.Random(42)
    t_buckets = 1000
    lam = 5.0
    poisson_vec = [_knuth_poisson(rng, lam) for _ in range(t_buckets)]
    sum_x = float(sum(poisson_vec))
    sum_x2 = float(sum(x * x for x in poisson_vec))

    res = _eval_poisson_burst_fano(sum_x, sum_x2, total_buckets=t_buckets)
    ref_fano = statistics.pvariance(poisson_vec) / statistics.fmean(poisson_vec)
    self.assertAlmostEqual(res["fano_factor"], ref_fano, delta=1e-9)
    self.assertGreaterEqual(res["fano_factor"], 0.80)
    self.assertLessEqual(res["fano_factor"], 1.20)


class TestWS004HourOfDayProfileGolden(unittest.TestCase):
  """2. Learned 24-Bin Hour-of-Day Profile (WS5-HOD, D1) golden math verification."""

  def test_14d_circadian_profile_routine_vs_03utc_out_of_profile_and_zero_day_reconstruction(self) -> None:
    start_iso = "2026-10-14T00:00:00Z"
    end_iso = "2026-10-28T00:00:00Z"
    slots = compute_hod_window_slots(start_time_iso=start_iso, end_time_iso=end_iso)
    self.assertEqual(slots["baseline_days"], 13)

    router = MultiStageTemplateRouter()
    rendered = router.build_query(
        "HOUR_OF_DAY_PROFILE",
        tier="BALANCED",
        start_time=start_iso,
        end_time=end_iso,
        tenant_tz="UTC",
    )
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(rendered)["valid"])
    self.assertIn("$mu_hod = 1.0 * max($hod_baseline.sum_x_hod) / 13", rendered)

    # Synthetic 13-day pre-scoring profile:
    # - Hours 10..17 UTC: steady 10 events/hr on all 13 prior days (sum_x = 130, sum_x2 = 1300)
    # - Hour 09 UTC: 10 events/hr on 10 prior days and 0 events on 3 quiet PTO days (sum_x = 100, sum_x2 = 1000)
    # - Hours 00..08, 18..23 UTC: 0 events/hr on all 13 prior days (sum_x = 0, sum_x2 = 0)
    d_base = 13
    entity_base_total = (8 * 13 * 10.0) + (10 * 10.0)  # 1040 + 100 = 1140

    # (a) Pure uniform 9-hour schedule check (13 days * 9 hours * 10 events = 1170):
    routine_10utc_uniform = _eval_hod_profile_bucket(
        observed=10.0,
        sum_x_hod=130.0,
        sum_x2_hod=1300.0,
        baseline_days=d_base,
        entity_base_total=1170.0,
    )
    self.assertAlmostEqual(routine_10utc_uniform["hod_z_score"], 0.0, delta=1e-9)
    self.assertAlmostEqual(routine_10utc_uniform["hour_profile_mass"], 1.0 / 9.0, delta=1e-9)

    # (b) Sporadic quiet-day hour (09:00 UTC active 10/13 days): zero-inclusive variance matches full 13-day vector
    full_09utc_vec = [10.0] * 10 + [0.0] * 3
    routine_09utc = _eval_hod_profile_bucket(
        observed=10.0,
        sum_x_hod=sum(full_09utc_vec),
        sum_x2_hod=sum(x * x for x in full_09utc_vec),
        baseline_days=d_base,
        entity_base_total=entity_base_total,
    )
    self.assertAlmostEqual(routine_09utc["mu_hod"], statistics.fmean(full_09utc_vec), delta=1e-9)
    self.assertAlmostEqual(routine_09utc["var_hod"], statistics.pvariance(full_09utc_vec), delta=1e-9)
    self.assertLess(routine_09utc["hod_z_score"], 1.0)

    # (c) Out-of-profile 03:00 UTC login burst (10 events on day 14 against 0 prior events at hour 03):
    #     Scored out-of-sample so day-14 spike does NOT contaminate mu_hod or sd_hod!
    anomaly_03utc = _eval_hod_profile_bucket(
        observed=10.0,
        sum_x_hod=0.0,
        sum_x2_hod=0.0,
        baseline_days=d_base,
        entity_base_total=entity_base_total,
    )
    self.assertEqual(anomaly_03utc["mu_hod"], 0.0)
    self.assertEqual(anomaly_03utc["safe_sd_hod"], 1.0)
    self.assertAlmostEqual(anomaly_03utc["hod_z_score"], 10.0, delta=1e-9)
    self.assertGreaterEqual(anomaly_03utc["hod_z_score"], 3.0)
    self.assertEqual(anomaly_03utc["hour_profile_mass"], 0.0)


class TestWS004SamuelsonMadTukeyGolden(unittest.TestCase):
  """3. Sample-SD Samuelson Cap, MAD Constants, and Recalibrated Bowley-Tukey Excess Z."""

  def test_sample_sd_samuelson_cap_exact_across_sample_sizes(self) -> None:
    caps: Dict[int, float] = {}
    for n in (2, 7, 10, 11, 30):
      with self.subTest(n=n):
        extremal = [1000.0] + [0.0] * (n - 1)
        mean_x = statistics.fmean(extremal)
        sample_sd = statistics.stdev(extremal)  # N - 1 degrees of freedom (PF-2)
        achieved_max_z = (extremal[0] - mean_x) / sample_sd
        expected_cap = (n - 1) / math.sqrt(float(n))
        caps[n] = expected_cap
        self.assertAlmostEqual(achieved_max_z, expected_cap, delta=1e-12)

    # Verify PF-2 / WS1-09 boundary: 3.0 sigma is unreachable at N <= 10 and first reachable at N = 11
    self.assertLess(caps[2], 1.0)
    self.assertLess(caps[7], 2.5)
    self.assertLess(caps[10], 3.0)
    self.assertGreater(caps[11], 3.0)
    self.assertAlmostEqual(caps[30], 29.0 / math.sqrt(30.0), delta=1e-12)

  def test_mad_gaussian_consistency_constants_and_zero_mad_meanad_fallback(self) -> None:
    # Exact Gaussian 75th percentile Phi^-1(0.75) = 0.6744897501960817; half-normal sqrt(pi/2) = 1.2533141373
    phi_inv_75 = statistics.NormalDist(0.0, 1.0).inv_cdf(0.75)
    sqrt_half_pi = math.sqrt(math.pi / 2.0)
    self.assertAlmostEqual(phi_inv_75, 0.67448975, delta=1e-8)
    self.assertAlmostEqual(0.6745, phi_inv_75, delta=1.1e-5)
    self.assertAlmostEqual(1.253314, sqrt_half_pi, delta=1.5e-7)

    # Case A: Positive MAD series -> uses MAD / 0.6745
    pos_mad_series = [90.0, 95.0, 98.0, 100.0, 102.0, 105.0, 110.0]
    res_pos = _eval_mad_modified_z(pos_mad_series, observed=140.0)
    self.assertEqual(res_pos["mad"], 5.0)
    self.assertAlmostEqual(res_pos["safe_robust_scale"], 5.0 / 0.6745, delta=1e-9)
    self.assertAlmostEqual(res_pos["m_z_score"], (140.0 - 100.0) / (5.0 / 0.6745), delta=1e-9)

    # Case B: Majority-tie series (>50% identical -> MAD == 0, meanAD == 5.0) -> switches to meanAD * 1.253314
    zero_mad_series = [100.0] * 8 + [80.0, 90.0, 110.0, 120.0]
    res_fallback = _eval_mad_modified_z(zero_mad_series, observed=130.0)
    self.assertEqual(res_fallback["mad"], 0.0)
    self.assertAlmostEqual(res_fallback["mean_ad"], 5.0, delta=1e-9)
    self.assertAlmostEqual(res_fallback["safe_robust_scale"], 5.0 * 1.253314, delta=1e-9)
    self.assertAlmostEqual(res_fallback["m_z_score"], (130.0 - 100.0) / (5.0 * 1.253314), delta=1e-9)

    # Case C: Completely constant series (MAD == 0 and meanAD == 0) -> uses dispersion_floor
    const_series = [100.0] * 10
    res_const = _eval_mad_modified_z(const_series, observed=102.0, dispersion_floor=2.5)
    self.assertEqual(res_const["safe_robust_scale"], 2.5)
    self.assertAlmostEqual(res_const["m_z_score"], 0.8, delta=1e-9)

  def test_bowley_tukey_skew_fences_bounds_and_excess_z(self) -> None:
    # Normal IQR = 2 * Phi^-1(0.75) = 1.3489795 ~ 1.349
    normal_iqr = 2.0 * statistics.NormalDist(0.0, 1.0).inv_cdf(0.75)
    self.assertAlmostEqual(normal_iqr, 1.349, delta=2.1e-5)

    # 1. Left-skewed (Q1=80, Q2=95, Q3=100 -> B = -0.5 < 0 -> pos_skew = 0 -> standard Q3 + 1.5*IQR)
    left = _eval_bowley_tukey_fence(80.0, 95.0, 100.0, observed=160.0, p10_val=60.0, p90_val=110.0)
    self.assertAlmostEqual(left["bowley_skew"], -0.5, delta=1e-9)
    self.assertAlmostEqual(left["adj_upper_fence"], 100.0 + 1.5 * 20.0, delta=1e-9)
    self.assertAlmostEqual(left["fence_z"], (160.0 - 130.0) / (20.0 / 1.349), delta=1e-9)

    # 2. Symmetric (Q1=90, Q2=100, Q3=110 -> B = 0.0 -> Q3 + 1.5*IQR = 140)
    sym = _eval_bowley_tukey_fence(90.0, 100.0, 110.0, observed=140.0)
    self.assertAlmostEqual(sym["bowley_skew"], 0.0, delta=1e-9)
    self.assertAlmostEqual(sym["adj_upper_fence"], 140.0, delta=1e-9)
    self.assertAlmostEqual(sym["fence_z"], 0.0, delta=1e-9)

    # 3. Maximally right-skewed (Q1=100, Q2=100, Q3=120 -> B = +1.0 -> recalibrated exp(1.35) ~ 3.857426)
    right = _eval_bowley_tukey_fence(100.0, 100.0, 120.0, observed=300.0)
    self.assertAlmostEqual(right["bowley_skew"], 1.0, delta=1e-9)
    expected_fence = 120.0 + 1.5 * math.pow(2.718281828, 1.35) * 20.0
    self.assertAlmostEqual(right["adj_upper_fence"], expected_fence, delta=1e-6)
    self.assertGreater(right["fence_z"], 3.5)


class TestWS004EmpiricalBayesAndBetaBinomialGolden(unittest.TestCase):
  """4. Empirical-Bayes Gamma Shrinkage & Leave-One-Out Beta-Binomial Failure (WS5)."""

  def test_empirical_bayes_gamma_shrinkage_direction_and_overdispersion_dampening(self) -> None:
    # Prior Gamma(2.0, 2.0) has prior mean rate = 1.0/hr.
    # Two entities both observed at empirical prior rate 12.0/hr over T_prior=6 vs T_prior=167:
    sparse = _eval_bayesian_gamma_shrinkage(
        observed=12.0,
        total_sum_x=6 * 12.0 + 12.0,
        total_sum_x2=6 * 144.0 + 144.0,
        prior_window_buckets=6,
    )
    dense = _eval_bayesian_gamma_shrinkage(
        observed=12.0,
        total_sum_x=167 * 12.0 + 12.0,
        total_sum_x2=167 * 144.0 + 144.0,
        prior_window_buckets=167,
    )
    # Sparse entity shrinks much more strongly toward prior mean 1.0 than dense entity
    self.assertLess(sparse["baseline_mean"], dense["baseline_mean"])
    self.assertAlmostEqual(sparse["baseline_mean"], (2.0 + 72.0) / (2.0 + 6.0), delta=1e-9)   # 9.25
    self.assertAlmostEqual(dense["baseline_mean"], (2.0 + 2004.0) / (2.0 + 167.0), delta=1e-9)  # 11.8698

    # +10 sigma Poisson spike (obs = 16 + 10*4 = 56) on stable host (167h at steady 16/hr, excess_var = 0) fires:
    stable_spike = _eval_bayesian_gamma_shrinkage(
        observed=56.0,
        total_sum_x=167 * 16.0 + 56.0,
        total_sum_x2=167 * 256.0 + (56.0 ** 2),
        prior_window_buckets=167,
    )
    self.assertEqual(stable_spike["excess_var"], 0.0)
    self.assertGreater(stable_spike["bayesian_z"], 9.5)
    self.assertGreaterEqual(stable_spike["bayesian_z"], 3.0)

    # Chronically bursty server with same prior mean (16/hr) but high variance (half 0, half 32 -> E[X^2]=512,
    # Var=256, excess_var = 256 - 16 = 240) dampens obs=56 below 3.0 sigma!
    bursty_prior_sum = 83 * 32.0 + 84 * 0.0  # ~15.90/hr across 167 buckets
    bursty_prior_sum_sq = 83 * (32.0 ** 2)
    bursty_spike = _eval_bayesian_gamma_shrinkage(
        observed=56.0,
        total_sum_x=bursty_prior_sum + 56.0,
        total_sum_x2=bursty_prior_sum_sq + (56.0 ** 2),
        prior_window_buckets=167,
    )
    self.assertGreater(bursty_spike["excess_var"], 200.0)
    self.assertLess(bursty_spike["bayesian_z"], 3.0)

  def test_beta_binomial_1_of_1_suppressed_and_real_surge_alerts(self) -> None:
    # 1. Cold-start 1 failure out of 1 attempt: shrinks to 2/21 (~9.5%) and fail_z = 0.95 / 0.50 = 1.90 < 3.0
    cold_1of1 = _eval_beta_binomial_failure(
        obs_fails=1.0,
        obs_trials=1.0,
        total_hist_fails=1.0,
        total_hist_events=1.0,
    )
    self.assertAlmostEqual(cold_1of1["posterior_fail_prob"], 2.0 / 21.0, delta=1e-9)
    self.assertLess(cold_1of1["fail_z"], 3.0)

    # 2. Mature clean user (4 prior fails in 200 prior attempts) with 1 failure out of 1 attempt: does NOT alert
    mature_1of1 = _eval_beta_binomial_failure(
        obs_fails=1.0,
        obs_trials=1.0,
        total_hist_fails=5.0,
        total_hist_events=201.0,
    )
    self.assertLess(mature_1of1["fail_z"], 3.0)

    # 3. Real failure surge (25 fails out of 30 attempts) against clean history (4 fails in 200 attempts): alerts strongly
    real_surge = _eval_beta_binomial_failure(
        obs_fails=25.0,
        obs_trials=30.0,
        total_hist_fails=29.0,
        total_hist_events=230.0,
    )
    self.assertGreater(real_surge["fail_z"], 3.5)
    self.assertGreater(real_surge["fail_z"], 15.0)

    # 4. Chronically failing service account (160 prior fails in 200 prior attempts) at 22/30 fails: dampened (< 3.0)
    noisy_svc = _eval_beta_binomial_failure(
        obs_fails=22.0,
        obs_trials=30.0,
        total_hist_fails=182.0,
        total_hist_events=230.0,
    )
    self.assertLess(abs(noisy_svc["fail_z"]), 1.0)


class TestWS004OfflineMicroHelpersGolden(unittest.TestCase):
  """5. Offline Golden-Math Verification of `scripts/micro_python_helpers.py` (WS6-02..04, D6-G4)."""

  def _forbid_network(self, *args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Network call forbidden by D6-G4")

  def setUp(self) -> None:
    self._patchers = [
        mock.patch.object(socket, "socket", side_effect=self._forbid_network),
        mock.patch.object(socket, "create_connection", side_effect=self._forbid_network),
        mock.patch.object(urllib.request, "urlopen", side_effect=self._forbid_network),
    ]
    for p in self._patchers:
      p.start()

  def tearDown(self) -> None:
    for p in reversed(self._patchers):
      p.stop()

  def test_d6_g4_socket_guard_is_active(self) -> None:
    with self.assertRaisesRegex(AssertionError, "Network call forbidden by D6-G4"):
      socket.socket()

  def test_ewma_exact_recursion_zero_fill_and_sustained_1_8_sigma_shift(self) -> None:
    router = MultiStageTemplateRouter()
    query = router.build_query("EWMA_BURST_VELOCITY", tier="BALANCED", window_hours=24.0)

    # 24-hour grid [2026-10-27T00:00:00Z .. 2026-10-28T00:00:00Z):
    # Baseline slice = first 12 hours [0..11]:
    #   Hours 0, 2, 4, 6, 8, 10 are OMITTED from payload (0 events -> reconstructed by dense zero-fill!)
    #   Hours 1, 3, 5, 7, 9, 11 each have 20 events -> dense baseline = [0, 20, 0, 20, 0, 20, 0, 20, 0, 20, 0, 20]
    #   Exact mu_0 = 10.0, sample var_0 = 12 * 100 / 11 = 1200 / 11, sigma_0 = sqrt(1200 / 11) = 10.4446593573 > sqrt(10)
    start_epoch = 1793059200  # 2026-10-27T00:00:00Z
    mu_0 = 10.0
    sigma_0 = math.sqrt(1200.0 / 11.0)
    lam = 0.25
    expected_asymp = math.sqrt(lam / (2.0 - lam))  # sqrt(1/7) = 0.3779644730092272
    self.assertAlmostEqual(expected_asymp, math.sqrt(1.0 / 7.0), delta=1e-12)

    # Sustained moderate +1.8 * sigma_0 shift for 4 hours (hours 12, 13, 14, 15), then back to mu_0=10:
    # Single-bucket Z never exceeds +1.80 (< 3.0), while recursive EWMA reaches:
    #   ewma_z_4 = 1.8 * (1 - 0.75^4) / sqrt(1/7) = 3.25551178 >= 3.0!
    shifted_val = mu_0 + 1.8 * sigma_0
    ws_col: List[int] = []
    cnt_col: List[float] = []
    full_expected_series = [0.0] * 24

    for h in range(12):
      if h % 2 == 1:
        ws_col.append(start_epoch + h * 3600)
        cnt_col.append(20.0)
        full_expected_series[h] = 20.0

    for h in range(12, 24):
      val = shifted_val if 12 <= h < 16 else mu_0
      ws_col.append(start_epoch + h * 3600)
      cnt_col.append(val)
      full_expected_series[h] = val

    payload = _make_stats_payload({
        "entity": ["host-ewma-golden"] * len(ws_col),
        "ws": ws_col,
        "window_events": cnt_col,
        "distinct_binaries": [3] * len(ws_col),
        "fleet_prevalence": [1] * len(ws_col),
    })

    res = mph.run_ewma_helper(
        payload,
        query_text=query,
        start_time="2026-10-27T00:00:00Z",
        end_time="2026-10-28T00:00:00Z",
        lambda_weight=lam,
        control_l=3.0,
    )

    self.assertEqual(len(res["outliers"]), 1)
    rec = res["outliers"][0]

    # Hand-verify exact EWMA recursion over hours 12..23
    s_cur = mu_0
    hand_peak = -math.inf
    for h in range(12, 24):
      s_cur = lam * full_expected_series[h] + (1.0 - lam) * s_cur
      hand_peak = max(hand_peak, s_cur)

    sigma_ewma = sigma_0 * expected_asymp
    expected_ucl = mu_0 + 3.0 * sigma_ewma
    expected_ewma_z = (hand_peak - mu_0) / sigma_ewma

    self.assertAlmostEqual(rec["baseline_mean"], mu_0, delta=1e-6)
    self.assertAlmostEqual(rec["baseline_dispersion"], sigma_0, delta=1e-5)
    self.assertAlmostEqual(rec["sigma_ewma"], sigma_ewma, delta=1e-5)
    self.assertAlmostEqual(rec["ucl"], expected_ucl, delta=1e-5)
    self.assertAlmostEqual(rec["peak_ewma"], hand_peak, delta=1e-5)
    self.assertAlmostEqual(rec["ewma_z"], expected_ewma_z, delta=1e-5)
    self.assertAlmostEqual(rec["ewma_z"], 1.8 * (1.0 - (0.75 ** 4)) / expected_asymp, delta=1e-5)
    self.assertLess(rec["max_single_bucket_z"], 3.0)
    self.assertAlmostEqual(rec["max_single_bucket_z"], 1.8, delta=1e-5)
    self.assertGreaterEqual(rec["ewma_z"], 3.0)
    self.assertGreater(rec["peak_ewma"], rec["ucl_exact_step"])

  def test_shannon_exact_entropy_identities_and_length_matched_standardization(self) -> None:
    # Closed-form bit-entropy identities
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("a" * 32), 0.0, delta=1e-9)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("01" * 16), 1.0, delta=1e-9)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("ACGT" * 8), 2.0, delta=1e-9)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits("0123456789abcdef" * 2), 4.0, delta=1e-9)

    router = MultiStageTemplateRouter()
    query = router.build_query("SHANNON_ENTROPY_CHARACTER", tier="BALANCED")

    # 6 benign length-matched (~32-char) structured CLI strings (host_prevalence >= 5, ~2.5-3.0 bits/char)
    benign_tokens = [
        "/usr/bin/systemd-resolve --status",
        "/usr/sbin/logrotate /etc/logrot1",
        "/usr/sbin/logrotate /etc/logrot2",
        "/opt/corp/agent/bin/healthcheck1",
        "/opt/corp/agent/bin/healthcheck2",
        "/usr/local/bin/backup-sync --run",
    ]
    # High-entropy 32-char rare token (32 distinct base64 symbols -> exact log2(32) = 5.000000 bits/char)
    high_entropy_cand = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    self.assertEqual(len(high_entropy_cand), 32)
    self.assertAlmostEqual(mph.compute_shannon_entropy_bits(high_entropy_cand), 5.0, delta=1e-9)

    # Equally long (32-char) low-entropy rare token ("a" * 32 -> 0.000000 bits/char)
    low_entropy_cand = "a" * 32

    all_tokens = benign_tokens + [high_entropy_cand, low_entropy_cand]
    sample_ents = [["h1", "h2", "h3", "h4", "h5"]] * len(benign_tokens) + [["victim-host-01"], ["quiet-host-02"]]
    prevs = [6] * len(benign_tokens) + [1, 1]
    events = [20] * len(benign_tokens) + [1, 1]

    payload = _make_stats_payload({
        "token": all_tokens,
        "sample_entities": sample_ents,
        "host_prevalence": prevs,
        "token_events": events,
        "distinct_binaries": [1] * len(all_tokens),
    })

    res = mph.run_shannon_helper(payload, query_text=query, min_length=25, z_threshold=3.0)
    by_tok = {c["token"]: c for c in res["candidate_results"]}

    hi_rec = by_tok[high_entropy_cand]
    lo_rec = by_tok[low_entropy_cand]
    self.assertEqual(hi_rec["cohort_mode"], "length_matched")
    self.assertEqual(hi_rec["cohort_size"], 6)
    self.assertAlmostEqual(hi_rec["entropy_bits"], 5.0, delta=1e-6)
    self.assertGreaterEqual(hi_rec["shannon_z"], 3.0)

    self.assertEqual(lo_rec["cohort_mode"], "length_matched")
    self.assertAlmostEqual(lo_rec["entropy_bits"], 0.0, delta=1e-6)
    self.assertLessEqual(lo_rec["shannon_z"], 0.0)

    outlier_tokens = [o["token"] for o in res["outliers"]]
    self.assertIn(high_entropy_cand, outlier_tokens)
    self.assertNotIn(low_entropy_cand, outlier_tokens)

  def test_c2_jitter_clockwork_60s_seeded_poisson_and_non_external_exclusions(self) -> None:
    router = MultiStageTemplateRouter()
    query = router.build_query("C2_BEACONING_JITTER", tier="BALANCED", window_hours=24.0)
    self.assertTrue(QueryIntegrityGate.verify_pre_dispatch(query)["valid"])

    # Verify YARA-L template excludes RFC1918, multicast, link-local, loopback, broadcast
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "169.254.0.0/16", "127.0.0.0/8"):
      self.assertIn(f'not net.ip_in_range_cidr($dst_ip, "{cidr}")', query)

    base_ts = 1793059200  # 2026-10-27T00:00:00Z

    # 1. Clockwork 60s periodic C2 beacon to external IP (93.184.216.34) stitched across 2 hourly buckets:
    #    20 timestamps spanning hour_0 and hour_1 (<= 10/bucket < 25/hr cap), exact delta_t = 60s -> CV = 0.0000
    clockwork_60s_cross_hr = [base_ts + 3000 + i * 60 for i in range(20)]
    cw_buckets: Dict[str, List[int]] = {}
    for ts in clockwork_60s_cross_hr:
      cw_buckets.setdefault(f"hr_{(ts - base_ts) // 3600}", []).append(ts)
    self.assertEqual(len(cw_buckets), 2)

    # 2. Seeded Poisson exponential inter-arrivals (random.Random(42), 240 arrivals >= 200 across ~20 hours):
    rng = random.Random(42)
    exp_ts: List[int] = []
    cur_t = base_ts + 5
    for _ in range(240):
      exp_ts.append(cur_t)
      # Mean delta = 300s (~12 arrivals/hr, well below 25/hr array_distinct cap), continuous float/int seconds
      cur_t += max(1, int(round(rng.expovariate(1.0 / 300.0))))
    exp_buckets: Dict[str, List[int]] = {}
    for ts in exp_ts:
      exp_buckets.setdefault(f"hr_{(ts - base_ts) // 3600}", []).append(ts)

    # 3. Non-external destinations with clockwork 60s arrivals that MUST be excluded by defense-in-depth:
    excluded_destinations = [
        "224.0.0.251",      # IPv4 multicast (mDNS)
        "ff02::fb",         # IPv6 multicast
        "169.254.169.254",  # IPv4 link-local (cloud metadata / APIPA)
        "fe80::1",          # IPv6 link-local
        "10.0.0.5",         # RFC1918 10/8
        "172.16.3.50",      # RFC1918 172.16/12
        "192.168.1.10",     # RFC1918 192.168/16
        "127.0.0.1",        # Loopback
        "255.255.255.255",  # Broadcast
    ]

    src_col: List[str] = []
    dst_col: List[str] = []
    ws_col: List[str] = []
    ts_col: List[List[int]] = []

    for ws_k, b_ts in sorted(cw_buckets.items()):
      src_col.append("10.42.1.10")
      dst_col.append("93.184.216.34")
      ws_col.append(ws_k)
      ts_col.append(b_ts)

    for ws_k, e_ts in sorted(exp_buckets.items()):
      src_col.append("10.42.1.20")
      dst_col.append("198.51.100.200")
      ws_col.append(ws_k)
      ts_col.append(e_ts)

    for bad_dst in excluded_destinations:
      src_col.append("10.42.1.99")
      dst_col.append(bad_dst)
      ws_col.append("hr_0")
      ts_col.append([base_ts + i * 60 for i in range(12)])

    payload = _make_stats_payload({
        "src_ip": src_col,
        "dst_ip": dst_col,
        "ws": ws_col,
        "event_timestamps": ts_col,
    })

    # Verify CLI offline path under D6-G4 socket ban as well
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp = Path(tmpdir)
      q_file = tmp / "c2.yl2"
      p_file = tmp / "payload.json"
      out_file = tmp / "out.json"
      q_file.write_text(query, encoding="utf-8")
      p_file.write_text(json.dumps(payload), encoding="utf-8")
      rc = mph.main([
          "c2-jitter",
          "--query-file", str(q_file),
          "--payload-file", str(p_file),
          "--output-json", str(out_file),
          "--format", "json",
      ])
      self.assertEqual(rc, 0)
      res = json.loads(out_file.read_text(encoding="utf-8"))

    by_pair = {(r["src_ip"], r["dst_ip"]): r for r in res["pair_results"]}

    # Clockwork 60s external pair: exact CV = 0.0, periodicity = 1.0, alerts strongly
    cw_rec = by_pair[("10.42.1.10", "93.184.216.34")]
    self.assertEqual(cw_rec["interval_count"], 19)
    self.assertAlmostEqual(cw_rec["mean_delta_seconds"], 60.0, delta=1e-9)
    self.assertAlmostEqual(cw_rec["cv"], 0.0, delta=1e-9)
    self.assertAlmostEqual(cw_rec["robust_cv"], 0.0, delta=1e-9)
    self.assertAlmostEqual(cw_rec["periodicity_score"], 1.0, delta=1e-9)
    self.assertAlmostEqual(cw_rec["z_equiv"], 5.0, delta=1e-6)
    self.assertEqual(cw_rec["cri"], 77)
    self.assertGreaterEqual(cw_rec["cri"], 70)

    # Seeded Poisson exponential external pair (>= 200 arrivals): CV ~ 1.0 within +/-20%, does NOT alert
    exp_rec = by_pair[("10.42.1.20", "198.51.100.200")]
    self.assertGreaterEqual(exp_rec["distinct_timestamps"], 200)
    self.assertGreaterEqual(exp_rec["cv"], 0.80)
    self.assertLessEqual(exp_rec["cv"], 1.20)
    self.assertEqual(exp_rec["cri"], 0)

    # Multicast, link-local, loopback, broadcast, and internal RFC1918 destinations are excluded
    for bad_dst in excluded_destinations:
      self.assertNotIn(("10.42.1.99", bad_dst), by_pair, f"Non-external destination {bad_dst} was not excluded")

    outlier_pairs = [(o["src_ip"], o["dst_ip"]) for o in res["outliers"]]
    self.assertEqual(outlier_pairs, [("10.42.1.10", "93.184.216.34")])


if __name__ == "__main__":
  unittest.main()
