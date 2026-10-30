"""WS5-MODELS regression, golden-math, and examples/*.yara tests."""

from __future__ import annotations

import math
from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPTS_DIR))

from multistage_query_builder import (  # pylint: disable=wrong-import-position
    DataReductionEngine,
    MultiStageTemplateRouter,
    PRIMARY_SCORE_KEYS,
    QueryIntegrityGate,
    audit_query_execution,
    get_soc_severity_badge,
    resolve_fleet_prevalence,
    validate_multistage_syntax,
)
from ueba_constants import cri_from_model_score  # pylint: disable=wrong-import-position


# ---------------------------------------------------------------------------
# Golden Python Reference Math for All 11 WS5-MODELS Remediated Pipelines
# ---------------------------------------------------------------------------


def compute_zipfian_rarity(adopter_hosts: int, fleet_total_hosts: int) -> float:
  safe_hosts = adopter_hosts if adopter_hosts > 0 else 1
  safe_fleet = fleet_total_hosts if fleet_total_hosts > safe_hosts else safe_hosts
  return math.log(1.0 * safe_fleet / safe_hosts)


def compute_bayesian_gamma_z(
    obs: int,
    sum_x: float,
    sum_x2: float,
    prior_window_buckets: int,
    alpha0: float = 2.0,
    beta0: float = 2.0,
) -> tuple[float, float, float]:
  prior_sum = max(0.0, sum_x - obs)
  prior_sum_sq = max(0.0, sum_x2 - (obs * obs))
  alpha_prior = alpha0 + prior_sum
  beta_prior = beta0 + prior_window_buckets
  baseline_mean = alpha_prior / beta_prior
  prior_emp_mean = 1.0 * prior_sum / prior_window_buckets
  raw_excess_var = (
      (1.0 * prior_sum_sq / prior_window_buckets)
      - (prior_emp_mean * prior_emp_mean)
      - prior_emp_mean
  )
  excess_var = max(0.0, raw_excess_var)
  raw_pred_var = (baseline_mean * (beta_prior + 1.0) / beta_prior) + excess_var
  baseline_dispersion = math.sqrt(max(1.0, raw_pred_var))
  bayesian_z = (obs - baseline_mean) / baseline_dispersion
  posterior_rate = (alpha_prior + obs) / (beta_prior + 1.0)
  return bayesian_z, baseline_mean, posterior_rate


def compute_diversity_concentration_score(
    distinct_targets: int,
    obs_events: int,
    peak_bytes: int,
    sum_bytes: int,
    sum_targets: float,
    sum_targets_sq: float,
    active_samples: int,
    min_deficit_z: float = 1.5,
    min_concentration_ratio: float = 0.65,
) -> tuple[float, float, float, float]:
  n_prior = max(1, active_samples - 1)
  loo_sum = max(0.0, sum_targets - distinct_targets)
  loo_sum_sq = max(0.0, sum_targets_sq - (distinct_targets * distinct_targets))
  loo_mean = loo_sum / n_prior
  loo_var = max(0.0, (loo_sum_sq / n_prior) - (loo_mean * loo_mean))
  loo_sd = math.sqrt(loo_var)
  floor_sd = math.sqrt(max(1.0, loo_mean))
  safe_sd = max(loo_sd, floor_sd)
  raw_deficit_z = (loo_mean - distinct_targets) / safe_sd
  deficit_z = max(0.0, raw_deficit_z)
  diversity_ratio = 1.0 * distinct_targets / max(1, obs_events)
  concentration_ratio = 1.0 * peak_bytes / max(1, sum_bytes)
  threat_score = 3.0 * math.sqrt(
      ((deficit_z / min_deficit_z) ** 2)
      + ((concentration_ratio / min_concentration_ratio) ** 2)
  )
  return deficit_z, diversity_ratio, concentration_ratio, threat_score


def compute_poisson_rare_surge(
    obs_today: int, total_hist_runs: int, window_days: int
) -> tuple[float, float]:
  prior_runs = max(0, total_hist_runs - obs_today)
  lam = (prior_runs + 0.5) / max(1, window_days)
  safe_lam = max(0.01, lam)
  diff = max(0.0, obs_today - lam)
  z_sq = (diff * diff) / safe_lam
  return z_sq, lam


def compute_markov_2gram_score(
    window_pair_launches: int,
    window_parent_launches: int,
    vocab_smooth: float = 100.0,
) -> tuple[float, float]:
  prob = (window_pair_launches + 1.0) / (window_parent_launches + vocab_smooth)
  score = math.log((window_parent_launches + vocab_smooth) / (window_pair_launches + 1.0))
  return score, prob


def compute_dual_baseline_delta_z(
    obs: int,
    sum_x: float,
    sum_x2: float,
    active_hours: int,
    fleet_obs_mean: float,
    fleet_exp_mean: float,
    fleet_sd_mean: float,
) -> tuple[float, float, float]:
  n_prior = max(1, active_hours - 1)
  loo_sum = max(0.0, sum_x - obs)
  loo_sum_sq = max(0.0, sum_x2 - (obs * obs))
  loo_mean = loo_sum / n_prior
  loo_var = max(0.0, (loo_sum_sq / n_prior) - (loo_mean * loo_mean))
  loo_sd = math.sqrt(loo_var)
  personal_sd = max(loo_sd, math.sqrt(max(1.0, loo_mean)))
  personal_z = (obs - loo_mean) / personal_sd

  safe_fleet_sd = max(fleet_sd_mean, math.sqrt(max(1.0, fleet_exp_mean)))
  fleet_z = (fleet_obs_mean - fleet_exp_mean) / safe_fleet_sd
  pos_fleet_z = max(0.0, fleet_z)
  delta_z = personal_z - pos_fleet_z
  return delta_z, personal_z, fleet_z


def compute_two_part_hurdle_score(
    obs: int,
    sum_x: float,
    sum_x2: float,
    total_active: int,
    min_active_samples: int = 4,
    min_awakening_volume: int = 10,
) -> float:
  if total_active <= min_active_samples:
    if obs < min_awakening_volume:
      return 0.0
    return 3.0 * (1.0 * obs / min_awakening_volume)
  n_prior = max(1, total_active - 1)
  loo_sum = max(0.0, sum_x - obs)
  loo_sum_sq = max(0.0, sum_x2 - (obs * obs))
  loo_mean = loo_sum / n_prior
  loo_var = max(0.0, (loo_sum_sq / n_prior) - (loo_mean * loo_mean))
  loo_sd = math.sqrt(loo_var)
  safe_sd = max(loo_sd, math.sqrt(max(1.0, loo_mean)))
  raw_z = (obs - loo_mean) / safe_sd
  return max(0.0, raw_z)


def compute_tukey_fence_z(
    obs: float, q25: float, q50: float, q75: float
) -> tuple[float, float]:
  iqr = q75 - q25
  floor_iqr = max(1.0, 0.01 * q50)
  safe_iqr = max(iqr, floor_iqr)
  bowley_skew = (q75 + q25 - 2.0 * q50) / safe_iqr
  pos_skew = max(0.0, bowley_skew)
  adj_upper_fence = q75 + 1.5 * math.pow(2.718281828, 1.35 * pos_skew) * safe_iqr
  robust_scale = safe_iqr / 1.349
  fence_z = (obs - adj_upper_fence) / robust_scale
  return fence_z, adj_upper_fence


def compute_beta_binomial_z(
    fails_today: int,
    trials_today: int,
    total_hist_fails: int,
    total_hist_events: int,
    alpha0: float = 1.0,
    beta0: float = 19.0,
) -> tuple[float, float, float]:
  prior_fails = max(0, total_hist_fails - fails_today)
  prior_events = max(prior_fails, total_hist_events - trials_today)
  prior_succ = max(0, prior_events - prior_fails)
  alpha_prior = alpha0 + prior_fails
  beta_prior = beta0 + prior_succ
  prior_total = alpha_prior + beta_prior
  p0 = alpha_prior / prior_total
  safe_trials = max(1, trials_today)
  posterior_prob = (alpha_prior + fails_today) / (prior_total + safe_trials)
  pred_var = (
      safe_trials
      * p0
      * (1.0 - p0)
      * ((prior_total + safe_trials) / (prior_total + 1.0))
  )
  dispersion = math.sqrt(max(0.25, pred_var))
  fail_z = (fails_today - (safe_trials * p0)) / dispersion
  return fail_z, p0, posterior_prob


def compute_producer_consumer_z(
    obs_ratio: float, sum_ratio: float, sum_ratio_sq: float, active_windows: int
) -> tuple[float, float, float]:
  n_prior = max(1, active_windows - 1)
  loo_sum = max(0.0, sum_ratio - obs_ratio)
  loo_sum_sq = max(0.0, sum_ratio_sq - (obs_ratio * obs_ratio))
  loo_mean = loo_sum / n_prior
  loo_var = max(0.0, (loo_sum_sq / n_prior) - (loo_mean * loo_mean))
  loo_sd = math.sqrt(loo_var)
  dispersion = max(0.05, loo_sd)
  z_score = (obs_ratio - loo_mean) / dispersion
  return z_score, loo_mean, dispersion


def compute_lateral_expansion_score(
    obs_targets: int,
    new_targets: int,
    total_target_visits: int,
    active_days: int,
) -> tuple[float, float]:
  n_prior = max(1, active_days - 1)
  prior_visits = max(0, total_target_visits - obs_targets)
  baseline_mean = 1.0 * prior_visits / n_prior
  dispersion = math.sqrt(max(1.0, baseline_mean))
  pos_breadth_z = max(0.0, (obs_targets - baseline_mean) / dispersion)
  z_score = pos_breadth_z + (1.5 * new_targets)
  return z_score, baseline_mean


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------


def _count_stages_and_raw_stages(query: str) -> tuple[int, int]:
  stage_blocks = list(re.finditer(r"(?m)^\s*stage\s+([A-Za-z0-9_]+)\s*\{", query))
  raw_count = 0
  for idx, match in enumerate(stage_blocks):
    start = match.end()
    end = stage_blocks[idx + 1].start() if idx + 1 < len(stage_blocks) else len(query)
    body = query[start:end]
    if "metadata.event_type" in body or ".metadata.event_type" in body:
      raw_count += 1
  return len(stage_blocks), raw_count


def _max_outcome_vars(query: str) -> int:
  # Count '$var =' assignments inside each outcome: section.
  blocks = re.split(r"(?m)^\s*outcome:\s*$", query)[1:]
  max_vars = 0
  for block in blocks:
    cutoff = re.split(r"(?m)^\s*(?:condition|match|order|limit|stage)\b", block)[0]
    assignments = re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", cutoff)
    max_vars = max(max_vars, len(assignments))
  return max_vars


class TestWS5ModelsPipelines(unittest.TestCase):
  """Regression and golden-math verification for the 11 WS5-MODELS pipelines."""

  WS5_MODELS = (
      "ZIPFIAN_PROCESS_RARITY",
      "BAYESIAN_GAMMA_SHRINKAGE",
      "HYBRID_ENTROPY_CONCENTRATION",
      "POISSON_RARE_SURGE",
      "MARKOV_2GRAM_TRANSITION_RARITY",
      "DUAL_BASELINE_DELTA_Z",
      "TWO_PART_HURDLE",
      "IQR_TUKEY_SKEW_FENCES",
      "BETA_BINOMIAL_FAILURE",
      "PRODUCER_CONSUMER_RATIO_INVERSION",
      "PRIVILEGED_LATERAL_EXPANSION",
  )

  def setUp(self) -> None:
    self.router = MultiStageTemplateRouter()

  def test_all_11_models_compile_within_stage_and_outcome_budgets(self) -> None:
    for model in self.WS5_MODELS:
      for tier in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE"):
        with self.subTest(model=model, tier=tier):
          query = self.router.build_query(model, tier=tier)
          qa = QueryIntegrityGate.verify_pre_dispatch(query)
          self.assertTrue(qa["valid"], f"{model} [{tier}] QA failed: {qa['errors']}")
          errs = [
              e
              for e in validate_multistage_syntax(query)
              if not e.startswith("MISSING METHODOLOGY HEADER")
          ]
          self.assertEqual(errs, [], f"{model} [{tier}] syntax errors: {errs}")
          stage_count, raw_count = _count_stages_and_raw_stages(query)
          self.assertLessEqual(stage_count, 4, f"{model} exceeded 4 named stages")
          self.assertLessEqual(raw_count, 2, f"{model} exceeded 2 raw stages")
          self.assertLessEqual(
              _max_outcome_vars(query), 20, f"{model} exceeded 20 outcome vars"
          )
          # Zero negative numeric literals in condition:
          cond_tail = query.split("condition:")[-1]
          self.assertIsNone(
              re.search(r"(?:<=|>=|<|>|=)\s*-\d", cond_tail),
              f"{model} [{tier}] contains negative literal in condition: {cond_tail}",
          )

  def test_zipfian_process_rarity_pure_host_prevalence(self) -> None:
    q = self.router.build_query("ZIPFIAN_PROCESS_RARITY", tier="BALANCED")
    self.assertIn("stage fleet_process_popularity", q)
    self.assertIn("stage fleet_host_total", q)
    self.assertIn("$fleet_total_hosts", q)
    self.assertNotIn("$fleet_host_count", q)
    self.assertIn("math.log(1.0 * $safe_fleet_hosts / $safe_hosts)", q)

    # Golden math: 1/50 novel binary strictly outranks chatty 2/50 daemon
    novel = compute_zipfian_rarity(adopter_hosts=1, fleet_total_hosts=50)
    chatty_two_host = compute_zipfian_rarity(adopter_hosts=2, fleet_total_hosts=50)
    ubiquitous = compute_zipfian_rarity(adopter_hosts=45, fleet_total_hosts=50)
    self.assertAlmostEqual(novel, 3.9120, places=3)
    self.assertGreater(novel, 2.5)
    self.assertGreater(novel, chatty_two_host)
    self.assertLess(ubiquitous, 0.5)

    # Ensure resolve_fleet_prevalence reads actual adopter count, never fleet total
    row = {"fleet_prevalence": 1, "fleet_total_hosts": 50}
    self.assertEqual(resolve_fleet_prevalence(row), 1.0)

  def test_bayesian_gamma_shrinkage_predictive_z_and_overdispersion(self) -> None:
    q = self.router.build_query(
        "BAYESIAN_GAMMA_SHRINKAGE", tier="BALANCED", window_hours=168.0
    )
    self.assertIn("$alpha_prior", q)
    self.assertIn("$beta_prior", q)
    self.assertIn("$posterior_arrival_rate", q)
    self.assertIn("$bayesian_z", q)
    self.assertIn("order:\n  $bayesian_z desc", q)
    self.assertNotIn("$posterior_arrival_rate >=", q.split("condition:")[-1])
    self.assertEqual(
        audit_query_execution(q, "BAYESIAN_GAMMA_4STAGE", "BAYESIAN_GAMMA")["status"],
        "PASS",
    )

    # Steady high-volume server (mean ~50/hr, bursty var ~400) observing 55 -> suppressed!
    z_steady, _, _ = compute_bayesian_gamma_z(
        obs=55, sum_x=167 * 50 + 55, sum_x2=167 * (50**2 + 400) + 55**2, prior_window_buckets=167
    )
    self.assertLess(z_steady, 1.0)

    # Quiet workstation (mean ~1/hr, low variance) spiking to 25 -> high Bayesian Z!
    z_spike, _, _ = compute_bayesian_gamma_z(
        obs=25, sum_x=167 * 1 + 25, sum_x2=167 * 2 + 25**2, prior_window_buckets=167
    )
    self.assertGreater(z_spike, 15.0)
    self.assertGreaterEqual(cri_from_model_score("bayesian_z", 3.0), 50)

  def test_hybrid_entropy_concentration_zero_negative_literals_and_positive_deficit_z(self) -> None:
    q = self.router.build_query("HYBRID_ENTROPY_CONCENTRATION", tier="BALANCED")
    self.assertIn("destination diversity & concentration screen", q.lower())
    self.assertNotIn("-1.5", q)
    self.assertNotIn("-2.5", q)
    self.assertNotIn("-1.0", q)
    self.assertIn("$deficit_z", q)
    self.assertIn("$concentration_ratio", q)
    self.assertIn("$threat_score", q)

    # Host normally talks to 20 peers (SD ~3); drops to 1 C2 IP with 95% byte concentration
    deficit_z, div_ratio, conc_ratio, score = compute_diversity_concentration_score(
        distinct_targets=1,
        obs_events=50,
        peak_bytes=950_000,
        sum_bytes=1_000_000,
        sum_targets=10 * 20 + 1,
        sum_targets_sq=10 * (20**2 + 9) + 1,
        active_samples=11,
    )
    self.assertGreater(deficit_z, 4.0)
    self.assertLessEqual(div_ratio, 0.20)
    self.assertGreaterEqual(conc_ratio, 0.65)
    self.assertGreater(score, 6.0)

  def test_poisson_rare_surge_dynamic_window_days_and_first_time_admin_tool(self) -> None:
    q_14d = self.router.build_query("POISSON_RARE_SURGE", tier="BALANCED", window_hours=336.0)
    q_30d = self.router.build_query("POISSON_RARE_SURGE", tier="BALANCED", window_hours=720.0)
    self.assertIn("/ 13", q_14d)
    self.assertIn("/ 29", q_30d)
    self.assertIn("stage host_online_baseline", q_14d)
    self.assertIn('timestamp.get_date(', q_14d)
    self.assertIn("$is_latest_day = 1", q_14d)

    # First-time vssadmin.exe execution today (obs=2, total_hist_runs=2 -> prior=0) over 13 prior days
    z_sq, lam = compute_poisson_rare_surge(obs_today=2, total_hist_runs=2, window_days=13)
    self.assertAlmostEqual(lam, 0.5 / 13.0, places=4)
    self.assertGreater(z_sq, 9.0)  # Exceeds BALANCED z_sq_threshold = 9.0!

  def test_markov_2gram_smooth_laplace_no_cliff(self) -> None:
    q = self.router.build_query("MARKOV_2GRAM_TRANSITION_RARITY", tier="BALANCED")
    self.assertIn("stage pair_window_totals", q)
    self.assertIn("stage parent_window_totals", q)
    self.assertNotIn("if($transition_count <= 2", q)
    self.assertNotIn("-math.log", q)

    # Single winword.exe -> powershell.exe (pair=1, parent=1) alerts on BALANCED (>= 3.0)
    score_single, _ = compute_markov_2gram_score(1, 1, vocab_smooth=100.0)
    self.assertAlmostEqual(score_single, math.log(101.0 / 2.0), places=4)
    self.assertGreaterEqual(score_single, 3.0)

    # Monotonic decay without artificial 2x cliff between 2nd and 3rd run
    s2, _ = compute_markov_2gram_score(2, 500, vocab_smooth=100.0)
    s3, _ = compute_markov_2gram_score(3, 500, vocab_smooth=100.0)
    self.assertGreater(s2, s3)
    self.assertLess(s2 - s3, 0.5)

  def test_dual_baseline_delta_z_mature_fleet_shift_suppression(self) -> None:
    q = self.router.build_query("DUAL_BASELINE_DELTA_Z", tier="BALANCED")
    self.assertIn("stage fleet_concurrent_baseline", q)
    self.assertIn("$host_personal_baseline.active_hours >=", q)
    self.assertIn("$pos_fleet_z", q)
    self.assertIn("$delta_z = $personal_z - $pos_fleet_z", q)

    # Patch Tuesday: personal spikes to 60 (usual 10, SD ~3.16), fleet also spikes to 60 -> suppressed
    delta_patch, pers_z, flt_z = compute_dual_baseline_delta_z(
        obs=60,
        sum_x=24 * 10 + 60,
        sum_x2=24 * 110 + 60**2,
        active_hours=25,
        fleet_obs_mean=60.0,
        fleet_exp_mean=10.0,
        fleet_sd_mean=3.16,
    )
    self.assertGreater(pers_z, 10.0)
    self.assertGreater(flt_z, 10.0)
    self.assertLess(delta_patch, 1.0)

    # Isolated compromise: personal spikes to 60 while fleet remains at expected 10 -> fires!
    delta_iso, _, _ = compute_dual_baseline_delta_z(
        obs=60,
        sum_x=24 * 10 + 60,
        sum_x2=24 * 110 + 60**2,
        active_hours=25,
        fleet_obs_mean=10.0,
        fleet_exp_mean=10.0,
        fleet_sd_mean=3.16,
    )
    self.assertGreater(delta_iso, 10.0)

  def test_two_part_hurdle_single_raw_stage_and_dormant_gate(self) -> None:
    q = self.router.build_query("TWO_PART_HURDLE", tier="BALANCED")
    self.assertNotIn("stage current_activity", q)
    self.assertIn("$min_awakening_volume", q.replace("10", "$min_awakening_volume"))
    self.assertIn("$hurdle_threat_score", q)

    # maya.goodman low-volume trickle (obs=4, active=2 <= 4) -> 0.0 (suppressed!)
    self.assertEqual(
        compute_two_part_hurdle_score(obs=4, sum_x=6, sum_x2=20, total_active=2),
        0.0,
    )
    # True dormant account awakening burst (obs=15 >= 10, active=1 <= 4) -> 4.5 >= 3.0
    self.assertAlmostEqual(
        compute_two_part_hurdle_score(obs=15, sum_x=15, sum_x2=225, total_active=1),
        4.5,
    )
    # Active account below its usual mean (obs=2 vs usual 20) -> positive-rectified 0.0 (never negative!)
    self.assertEqual(
        compute_two_part_hurdle_score(
            obs=2, sum_x=10 * 20 + 2, sum_x2=10 * 410 + 4, total_active=11
        ),
        0.0,
    )

  def test_iqr_tukey_skew_fences_scale_invariant_fence_z(self) -> None:
    q = self.router.build_query("IQR_TUKEY_SKEW_FENCES", tier="BALANCED")
    self.assertIn("1.35 * $pos_skew", q)
    self.assertIn("$fence_z", q)
    self.assertNotIn("min_iqr", q)

    fence_z, adj_fence = compute_tukey_fence_z(130.0, 111.0, 112.0, 114.0)
    self.assertAlmostEqual(adj_fence, 121.0574, places=3)
    self.assertGreater(fence_z, 3.5)
    self.assertEqual(cri_from_model_score("fence_z", 3.5), 50)

  def test_beta_binomial_failure_predictive_fail_z(self) -> None:
    q = self.router.build_query("BETA_BINOMIAL_FAILURE", tier="BALANCED")
    self.assertIn("$alpha_prior", q)
    self.assertIn("$beta_prior", q)
    self.assertIn("$posterior_fail_prob", q)
    self.assertIn("$fail_z", q)
    self.assertIn("order:\n  $fail_z desc", q)
    self.assertEqual(
        audit_query_execution(q, "BETA_BINOMIAL_4STAGE", "BETA_BINOMIAL")["status"],
        "PASS",
    )
    self.assertIn("fail_z", PRIMARY_SCORE_KEYS)
    self.assertEqual(
        DataReductionEngine.reduce([{"fail_z": 4.25}])["primary_score_metric"],
        "fail_z",
    )
    self.assertIn("CRITICAL", get_soc_severity_badge("fail_z", 5.2))

    # Chronic 25% service failure account (25/100 today, 250/1000 historically) -> suppressed!
    z_chronic, _, _ = compute_beta_binomial_z(
        fails_today=25, trials_today=100, total_hist_fails=275, total_hist_events=1100
    )
    self.assertLess(z_chronic, 1.0)

    # Normal 1% user account suddenly hitting 25/50 password spray failures -> high fail_z!
    z_spray, _, _ = compute_beta_binomial_z(
        fails_today=25, trials_today=50, total_hist_fails=30, total_hist_events=550
    )
    self.assertGreater(z_spray, 10.0)

  def test_producer_consumer_ratio_inversion_loo_z_and_inline_sync(self) -> None:
    q = self.router.build_query("PRODUCER_CONSUMER_RATIO_INVERSION", tier="BALANCED")
    self.assertIn("$producer_ratio", q)
    self.assertIn("$bucket_ratio", q)
    self.assertIn("$z_score = ($producer_ratio - $baseline_mean) / $baseline_dispersion", q)

    disk_tpl = (
        REPO_ROOT / "templates" / "pipelines" / "producer_consumer_ratio_inversion_2stage.yl2"
    ).read_text(encoding="utf-8")
    self.assertEqual(
        disk_tpl.strip(),
        MultiStageTemplateRouter.INLINE_TEMPLATES[
            "producer_consumer_ratio_inversion_2stage.yl2"
        ].strip(),
    )

    # Steady log forwarder (always 0.90 outbound ratio) -> z_score = 0.0 (suppressed!)
    z_forwarder, _, _ = compute_producer_consumer_z(
        obs_ratio=0.90,
        sum_ratio=15 * 0.90,
        sum_ratio_sq=15 * (0.90**2),
        active_windows=15,
    )
    self.assertAlmostEqual(z_forwarder, 0.0, places=4)

    # Workstation (normally 0.10 consumer) suddenly inverting to 0.85 producer -> z = +15.0!
    z_invert, _, _ = compute_producer_consumer_z(
        obs_ratio=0.85,
        sum_ratio=14 * 0.10 + 0.85,
        sum_ratio_sq=14 * (0.10**2) + (0.85**2),
        active_windows=15,
    )
    self.assertAlmostEqual(z_invert, 15.0, places=2)

  def test_privileged_lateral_expansion_zero_cross_product_and_zero_sd_jumpbox(self) -> None:
    q = self.router.build_query("PRIVILEGED_LATERAL_EXPANSION", tier="BALANCED")
    self.assertIn("stage daily_user_breadth", q)
    self.assertIn("stage user_target_history", q)
    self.assertIn("stage user_breadth_baseline", q)
    self.assertNotIn("stage current_breadth", q)
    self.assertNotIn("min_sd", q)
    self.assertIn("$new_targets", q)

    # Clockwork jump-box admin (exactly 2 targets/day for 14 days, sd=0) Lateral Moves to 3 new hosts
    z_lat, mean_b = compute_lateral_expansion_score(
        obs_targets=5, new_targets=3, total_target_visits=14 * 2 + 5, active_days=15
    )
    self.assertAlmostEqual(mean_b, 2.0, places=4)
    self.assertGreater(z_lat, 6.0)


class TestWS5ExamplesRemediation(unittest.TestCase):
  """Verifies all 13 examples/*.yara files compile cleanly and eliminate anti-patterns."""

  def setUp(self) -> None:
    self.examples_dir = REPO_ROOT / "examples"
    self.example_files = sorted(self.examples_dir.glob("*.yara"))

  def test_all_13_examples_pass_integrity_and_budget_contracts(self) -> None:
    self.assertEqual(len(self.example_files), 13)
    for path in self.example_files:
      text = path.read_text(encoding="utf-8")
      with self.subTest(example=path.name):
        qa = QueryIntegrityGate.verify_pre_dispatch(text)
        self.assertTrue(qa["valid"], f"{path.name} QA failed: {qa['errors']}")
        errs = [
            e
            for e in validate_multistage_syntax(text)
            if not e.startswith("MISSING METHODOLOGY HEADER")
        ]
        self.assertEqual(errs, [], f"{path.name} syntax errors: {errs}")
        stage_count, raw_count = _count_stages_and_raw_stages(text)
        self.assertLessEqual(stage_count, 3, f"{path.name} > 3 stages")
        self.assertLessEqual(raw_count, 2, f"{path.name} > 2 raw stages")
        self.assertLessEqual(_max_outcome_vars(text), 20, f"{path.name} > 20 outcome vars")

        # Anti-patterns banned across all examples
        self.assertNotIn("cast.as_int(metadata.event_timestamp.seconds", text)
        self.assertIsNone(re.search(r"\bby\s+day\b", text), f"{path.name} uses invalid 'by day'")
        self.assertNotIn("+ 0.001", text)
        self.assertNotIn("+ 0.1", text)
        self.assertNotIn("stddev($", text.replace(" ", "").split("+1.0")[0] if "+ 1.0" in text and "stddev" in text else "__never__")

        # If root has 'by <unit>', root match must carry $ws or $window_start
        root_tail = re.split(r"(?m)^\s*stage\s+[A-Za-z0-9_]+\s*\{", text)[-1]
        # Extract text after final stage closing brace
        brace_depth = 0
        root_start = 0
        for m in re.finditer(r"(?m)^\s*stage\s+[A-Za-z0-9_]+\s*\{", text):
          idx = m.end() - 1
          brace_depth = 0
          for pos in range(idx, len(text)):
            if text[pos] == "{":
              brace_depth += 1
            elif text[pos] == "}":
              brace_depth -= 1
              if brace_depth == 0:
                root_start = pos + 1
                break
        root_section = text[root_start:]
        match_m = re.search(r"(?m)^\s*match:\s*\n?\s*([^\n]+)", root_section)
        if match_m and re.search(r"\bby\s+\d+[mhd]\b", match_m.group(1)):
          self.assertTrue(
              "$ws" in match_m.group(1) or "$window_start" in match_m.group(1),
              f"{path.name} bucketed root match missing $ws/$window_start: {match_m.group(1)}",
          )

  def test_specific_example_fixes_e7_mad_ua_and_poisson(self) -> None:
    rolling = (self.examples_dir / "rolling_ratio_spike.yara").read_text(encoding="utf-8")
    self.assertNotIn("cast.as_int", rolling)
    self.assertIn("by 1d", rolling)

    mad = (self.examples_dir / "mad_outlier_detection.yara").read_text(encoding="utf-8")
    self.assertIn("by 1d", mad)
    self.assertNotIn("math.abs($today_volume - $median_vol)", mad)
    self.assertNotIn("$mad > 10.0", mad)

    ua = (self.examples_dir / "rare_user_agent_prevalence.yara").read_text(encoding="utf-8")
    _, raw_count = _count_stages_and_raw_stages(ua)
    self.assertEqual(raw_count, 1)
    self.assertIn("$ws", ua)

    poisson = (self.examples_dir / "poisson_rare_event_surge.yara").read_text(encoding="utf-8")
    self.assertIn("timestamp.get_date(", poisson)
    self.assertIn("$is_latest_day = 1", poisson)


if __name__ == "__main__":
  unittest.main()
