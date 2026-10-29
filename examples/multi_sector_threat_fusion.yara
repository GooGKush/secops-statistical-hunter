// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for coordinated multi-stage intrusions across Auth, Endpoint, and Network (Multi-Sector Threat Fusion)
// Target Telemetry: UDM_EVENTS (USER_LOGIN + PROCESS_LAUNCH + NETWORK_CONNECTION)
// Statistical Model: Leave-One-Out Multi-Sector Fusion & Positive-Rectified Euclidean Vector Norm (D = sqrt(pos_Z1^2 + pos_Z2^2 + pos_Z3^2))
// Topology: ONE raw stage with coalesced entity & per-sector conditional sums -> whole-window sums -> LOO sector moments -> root fusion.
// Operational Analogy: "The Combined Arms Threat Radar"
// Mathematical Rationale:
//   - Coalesces principal.hostname / principal.asset.hostname / principal.ip so all three telemetry families align
//     onto the same endpoint key, and counts both "BLOCK" and "FAIL" auth actions.
//   - Computes leave-one-out (n - 1) means and sample variances per sector with a continuous Poisson floor
//     sqrt(max(mean, 1.0)) per sector, eliminating sub-unit SD blowups on sparse sectors.
// Sensitivity Boundary: BALANCED (Composite Threat Distance D >= 3.0σ, Min Events >= 5, Min Prior Active Samples >= 7)
// ============================================================================

// --- STAGE 1: Bucketed per-host activity and squared counts in each sector ---
stage sector_counts {
  $entity = strings.coalesce($e.principal.hostname, $e.principal.asset.hostname, $e.principal.ip)
  $entity != ""
  (
    $e.metadata.event_type = "USER_LOGIN"
    or $e.metadata.event_type = "PROCESS_LAUNCH"
    or $e.metadata.event_type = "NETWORK_CONNECTION"
  )

  match:
    $entity by 1h

  outcome:
    $auth_fails = sum(if($e.metadata.event_type = "USER_LOGIN" and ($e.security_result.action = "BLOCK" or $e.security_result.action = "FAIL"), 1, 0))
    $auth_fails_sq = 1.0 * sum(if($e.metadata.event_type = "USER_LOGIN" and ($e.security_result.action = "BLOCK" or $e.security_result.action = "FAIL"), 1, 0)) * sum(if($e.metadata.event_type = "USER_LOGIN" and ($e.security_result.action = "BLOCK" or $e.security_result.action = "FAIL"), 1, 0))
    $proc_launches = sum(if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $proc_launches_sq = 1.0 * sum(if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0)) * sum(if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $net_flows = sum(if($e.metadata.event_type = "NETWORK_CONNECTION", 1, 0))
    $net_flows_sq = 1.0 * sum(if($e.metadata.event_type = "NETWORK_CONNECTION", 1, 0)) * sum(if($e.metadata.event_type = "NETWORK_CONNECTION", 1, 0))
}

// --- STAGE 2: Per-entity whole-window sufficient statistics across all sectors ---
stage host_sector_baseline {
  $entity = $sector_counts.entity

  match:
    $entity

  outcome:
    $sum_auth = sum($sector_counts.auth_fails)
    $sum_auth2 = sum($sector_counts.auth_fails_sq)
    $sum_proc = sum($sector_counts.proc_launches)
    $sum_proc2 = sum($sector_counts.proc_launches_sq)
    $sum_net = sum($sector_counts.net_flows)
    $sum_net2 = sum($sector_counts.net_flows_sq)
    $active_hours = count($sector_counts.window_start)
}

// --- STAGE 3: Leave-one-out (n - 1) per-(entity, bucket) sector means and sample variances ---
stage sector_loo {
  $entity = $sector_counts.entity
  $entity = $host_sector_baseline.entity
  $ws = $sector_counts.window_start

  match:
    $entity, $ws by 1h

  outcome:
    $obs_total = max($sector_counts.auth_fails) + max($sector_counts.proc_launches) + max($sector_counts.net_flows)
    $auth_obs = max($sector_counts.auth_fails)
    $proc_obs = max($sector_counts.proc_launches)
    $net_obs = max($sector_counts.net_flows)
    $n_prior = max($host_sector_baseline.active_hours) - 1
    $auth_mean = 1.0 * (max($host_sector_baseline.sum_auth) - max($sector_counts.auth_fails)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1)
    $auth_var = ((max($host_sector_baseline.sum_auth2) - max($sector_counts.auth_fails_sq)) - (1.0 * (max($host_sector_baseline.sum_auth) - max($sector_counts.auth_fails)) * (max($host_sector_baseline.sum_auth) - max($sector_counts.auth_fails)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1))) / (max(if($host_sector_baseline.active_hours > 3, $host_sector_baseline.active_hours, 3)) - 2)
    $proc_mean = 1.0 * (max($host_sector_baseline.sum_proc) - max($sector_counts.proc_launches)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1)
    $proc_var = ((max($host_sector_baseline.sum_proc2) - max($sector_counts.proc_launches_sq)) - (1.0 * (max($host_sector_baseline.sum_proc) - max($sector_counts.proc_launches)) * (max($host_sector_baseline.sum_proc) - max($sector_counts.proc_launches)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1))) / (max(if($host_sector_baseline.active_hours > 3, $host_sector_baseline.active_hours, 3)) - 2)
    $net_mean = 1.0 * (max($host_sector_baseline.sum_net) - max($sector_counts.net_flows)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1)
    $net_var = ((max($host_sector_baseline.sum_net2) - max($sector_counts.net_flows_sq)) - (1.0 * (max($host_sector_baseline.sum_net) - max($sector_counts.net_flows)) * (max($host_sector_baseline.sum_net) - max($sector_counts.net_flows)) / (max(if($host_sector_baseline.active_hours > 2, $host_sector_baseline.active_hours, 2)) - 1))) / (max(if($host_sector_baseline.active_hours > 3, $host_sector_baseline.active_hours, 3)) - 2)
}

// --- ROOT STAGE: Continuous Poisson Sector Floors, Positive Rectification & Euclidean Norm ---
$entity = $sector_loo.entity
$ws = $sector_loo.ws

match:
  $entity, $ws by 1h

outcome:
  $auth_fl = if(max($sector_loo.auth_mean) > 1.0, max($sector_loo.auth_mean), 1.0)
  $auth_sv = if(max($sector_loo.auth_var) > $auth_fl, max($sector_loo.auth_var), $auth_fl)
  $z1 = (max($sector_loo.auth_obs) - max($sector_loo.auth_mean)) / math.sqrt($auth_sv)
  $pos_z1 = if($z1 > 0.0, $z1, 0.0)

  $proc_fl = if(max($sector_loo.proc_mean) > 1.0, max($sector_loo.proc_mean), 1.0)
  $proc_sv = if(max($sector_loo.proc_var) > $proc_fl, max($sector_loo.proc_var), $proc_fl)
  $z2 = (max($sector_loo.proc_obs) - max($sector_loo.proc_mean)) / math.sqrt($proc_sv)
  $pos_z2 = if($z2 > 0.0, $z2, 0.0)

  $net_fl = if(max($sector_loo.net_mean) > 1.0, max($sector_loo.net_mean), 1.0)
  $net_sv = if(max($sector_loo.net_var) > $net_fl, max($sector_loo.net_var), $net_fl)
  $z3 = (max($sector_loo.net_obs) - max($sector_loo.net_mean)) / math.sqrt($net_sv)
  $pos_z3 = if($z3 > 0.0, $z3, 0.0)

  // 6 Standardized Evidence Pillars
  $observation_count = max($sector_loo.obs_total)
  $baseline_active_samples = max($sector_loo.n_prior)
  $baseline_mean = max($sector_loo.auth_mean) + max($sector_loo.proc_mean) + max($sector_loo.net_mean)
  $baseline_dispersion = math.sqrt($auth_sv + $proc_sv + $net_sv)
  $fleet_prevalence = 0 - 1
  $distinct_binaries = max($sector_loo.proc_obs)
  $threat_distance = math.sqrt(($pos_z1 * $pos_z1) + ($pos_z2 * $pos_z2) + ($pos_z3 * $pos_z3))

condition:
  $baseline_active_samples >= 7
  and $observation_count >= 5
  and $threat_distance >= 3.0

order:
  $threat_distance desc
