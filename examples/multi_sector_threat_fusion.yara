// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for coordinated multi-stage intrusions across Auth, Endpoint, and Network (Multi-Sector Threat Fusion)
// Target Telemetry: UDM_EVENTS (USER_LOGIN + PROCESS_LAUNCH + NETWORK_CONNECTION)
// Statistical Model: Multi-Sector Fusion & Euclidean Vector Norm (D^2 = Z_auth^2 + Z_proc^2 + Z_net^2)
// Topology: ONE raw stage with per-sector conditional sums -> per-host sector baselines -> root fusion.
//   Three independent raw sector stages joined at the root are rejected by the compiler
//   (verified: any two compile, all three do not). Conditional sums keep one scan and one join.
// Operational Analogy: "The Combined Arms Threat Radar"
// Mathematical Rationale:
//   Adversaries execute multi-stage kill chains with low-and-slow tactics in each silo.
//   Single-domain detectors miss these events because each vector is only mildly elevated (Z ~ 2.0σ).
//   Multi-Sector Fusion computes the orthogonal Euclidean distance across Authentication,
//   Process Execution, and Network Egress into a unified multi-domain threat norm D >= 3.0σ (D^2 >= 9.0).
// Sensitivity Boundary: BALANCED (Composite Threat Distance D >= 3.0σ [D^2 >= 9.0], Min Events >= 1 in each active sector)
// ============================================================================

// --- STAGE 1: Hourly per-host activity in each sector via conditional sums ---
stage sector_counts {
  $host = $e.principal.hostname
  $host != ""
  (
    $e.metadata.event_type = "USER_LOGIN"
    or $e.metadata.event_type = "PROCESS_LAUNCH"
    or $e.metadata.event_type = "NETWORK_CONNECTION"
  )

  match:
    $host by 1h

  outcome:
    $auth_fails = sum(if($e.metadata.event_type = "USER_LOGIN" and $e.security_result.action = "BLOCK", 1, 0))
    $proc_launches = sum(if($e.metadata.event_type = "PROCESS_LAUNCH", 1, 0))
    $net_flows = sum(if($e.metadata.event_type = "NETWORK_CONNECTION", 1, 0))
}

// --- STAGE 2: Per-host historical baseline (mean, stddev) for each sector ---
stage host_sector_baseline {
  $host = $sector_counts.host

  match:
    $host

  outcome:
    $auth_mean = avg($sector_counts.auth_fails)
    $auth_sd = stddev($sector_counts.auth_fails)
    $proc_mean = avg($sector_counts.proc_launches)
    $proc_sd = stddev($sector_counts.proc_launches)
    $net_mean = avg($sector_counts.net_flows)
    $net_sd = stddev($sector_counts.net_flows)
    $active_hours = count($sector_counts.window_start)
}

// --- ROOT STAGE: Orthogonal Threat-Space Fusion (squared Euclidean norm; no sqrt in YARA-L) ---
$host = $sector_counts.host
$host = $host_sector_baseline.host
$ws = $sector_counts.window_start

match:
  $host, $ws by 1h

outcome:
  // Evidence pillars
  $auth_event_count = max($sector_counts.auth_fails)
  $proc_event_count = max($sector_counts.proc_launches)
  $net_event_count = max($sector_counts.net_flows)
  $baseline_active_samples = max($host_sector_baseline.active_hours)
  $observation_count = max($sector_counts.auth_fails) + max($sector_counts.proc_launches) + max($sector_counts.net_flows)

  // Per-sector Z with +1.0 additive dispersion floor
  $sector_z_auth = (max($sector_counts.auth_fails) - max($host_sector_baseline.auth_mean)) / (max($host_sector_baseline.auth_sd) + 1.0)
  $sector_z_proc = (max($sector_counts.proc_launches) - max($host_sector_baseline.proc_mean)) / (max($host_sector_baseline.proc_sd) + 1.0)
  $sector_z_net = (max($sector_counts.net_flows) - max($host_sector_baseline.net_mean)) / (max($host_sector_baseline.net_sd) + 1.0)

  // D^2 = Z_auth^2 + Z_proc^2 + Z_net^2 ; sort by D^2 (monotone in D)
  $threat_vector_norm_sq = $sector_z_auth * $sector_z_auth + $sector_z_proc * $sector_z_proc + $sector_z_net * $sector_z_net

condition:
  $baseline_active_samples >= 60
  and $threat_vector_norm_sq >= 9.0

order:
  $threat_vector_norm_sq desc
