// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Hunt for coordinated multi-stage intrusions across Auth, Endpoint, and Network (Multi-Sector Threat Fusion)
// Target Telemetry: UDM_EVENTS (USER_LOGIN + PROCESS_LAUNCH + NETWORK_CONNECTION)
// Statistical Model: 4-Stage Multi-Sector Fusion & Euclidean Vector Norm (D = sqrt(Z_auth^2 + Z_proc^2 + Z_net^2))
// Operational Analogy: "The Combined Arms Threat Radar"
// Mathematical Rationale:
//   Adversaries execute multi-stage kill chains with low-and-slow tactics in each silo.
//   Single-domain detectors miss these events because each vector is only mildly elevated (Z ~ 2.0σ).
//   Multi-Sector Fusion computes the orthogonal Euclidean distance across Authentication,
//   Process Execution, and Network Egress into a unified multi-domain threat norm D >= 3.0σ (D^2 >= 9.0).
// Sensitivity Boundary: Composite Threat Distance D >= 3.0σ (D^2 >= 9.0), Min Events >= 1 in each active sector
// ============================================================================

// --- STAGE 1: Sector 1 - Authentication / Credential Access Anomalies ---
stage auth_sector {
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "BLOCK"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $auth_fails = count($e.metadata.id)
    $auth_distinct_users = count_distinct($e.target.user.userid)
}

// --- STAGE 2: Sector 2 - Endpoint / Suspicious Process Execution Anomalies ---
stage proc_sector {
  $e.metadata.event_type = "PROCESS_LAUNCH"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $proc_launches = count($e.metadata.id)
    $proc_distinct_files = count_distinct($e.target.process.file.full_path)
}

// --- STAGE 3: Sector 3 - Network / Egress Data Anomalies ---
stage net_sector {
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $host = $e.principal.hostname
  $host != ""

  match:
    $host by 1h

  outcome:
    $net_flows = count($e.metadata.id)
    $net_distinct_ports = count_distinct($e.target.port)
}

// --- STAGE 4 (ROOT STAGE): Multi-Sector Fusion & Vector Threat Norm ---
$host = $auth_sector.host
$host = $proc_sector.host
$host = $net_sector.host

$ws = $auth_sector.window_start
$ws = $proc_sector.window_start
$ws = $net_sector.window_start

$a_obs = $auth_sector.auth_fails
$p_obs = $proc_sector.proc_launches
$n_obs = $net_sector.net_flows

// Normalize against standard operational thresholds (e.g. sigma scaling)
$z_auth = $a_obs / 5.0
$z_proc = $p_obs / 10.0
$z_net = $n_obs / 20.0

// Euclidean Vector Threat Norm D^2 = Z_auth^2 + Z_proc^2 + Z_net^2
$z_auth_sq = $z_auth * $z_auth
$z_proc_sq = $z_proc * $z_proc
$z_net_sq = $z_net * $z_net
$composite_threat_norm_sq = $z_auth_sq + $z_proc_sq + $z_net_sq

match:
  $host, $ws by 1h

outcome:
  // Sector Breakdown
  $auth_event_count = max($a_obs)
  $proc_event_count = max($p_obs)
  $net_event_count = max($n_obs)

  $sector_z_auth = max($z_auth)
  $sector_z_proc = max($z_proc)
  $sector_z_net = max($z_net)

  // Composite Distance Metric
  $threat_vector_norm_sq = max($composite_threat_norm_sq)

condition:
  ($a_obs > 0 or $p_obs > 0 or $n_obs > 0)
  and $threat_vector_norm_sq >= 9.0 // Composite Threat Distance D >= 3.0 sigma
