// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect outlier browser user-agent strings across enterprise devices by pure host-prevalence inverse document frequency.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP)
// Statistical Model: Host-Prevalence Inverse Document Frequency Rarity (ln(N_fleet_hosts / N_adopter_hosts))
// Mathematical Rationale:
//   - Single Raw Scan: Extracts host-day user-agent activity once in Stage 1, then derives fleetwide user-agent
//     adopter breadth (Stage 2) and total active fleet hosts (Stage 3) with zero redundant raw telemetry scans.
//   - Pure Host Prevalence: Scores ln(safe_fleet_hosts / safe_adopter_hosts) so chatty multi-host user-agents
//     cannot outrank genuinely rare single-host scripts or implants.
// Sensitivity Boundary: BALANCED (Host Prevalence <= 2, Min Host Requests >= 5, Min Fleet Hosts >= 5, Rarity Score >= 1.5)
// ============================================================================

// Stage 1: Individual host activity per user-agent string (single raw scan)
stage host_ua_activity {
    metadata.event_type = "NETWORK_HTTP"
    $etype = metadata.event_type
    network.http.user_agent = $user_agent
    $user_agent != ""
    principal.asset.hostname = $host
    $host != ""

  match:
    $etype, $host, $user_agent by 1d

  outcome:
    $host_events = count(metadata.id)
    $sample_uris = array_distinct(target.url)
}

// Stage 2: Enterprise-wide fleet adoption per user-agent string across the search window
stage fleet_ua_prevalence {
    $etype = $host_ua_activity.etype
    $user_agent = $host_ua_activity.user_agent

  match:
    $etype, $user_agent

  outcome:
    $fleet_adopters = count_distinct($host_ua_activity.host)
    $total_fleet_events = sum($host_ua_activity.host_events)
}

// Stage 3: Total active HTTP client host population across the search window
stage fleet_host_total {
    $etype = $host_ua_activity.etype

  match:
    $etype

  outcome:
    $total_hosts = count_distinct($host_ua_activity.host)
}

// Root Stage: Join host-day activity with fleet adoption and total fleet size
$etype = $host_ua_activity.etype
$etype = $fleet_ua_prevalence.etype
$etype = $fleet_host_total.etype
$host = $host_ua_activity.host
$user_agent = $host_ua_activity.user_agent
$user_agent = $fleet_ua_prevalence.user_agent
$ws = $host_ua_activity.window_start

match:
  $host, $user_agent, $ws by 1d

outcome:
  $adopter_hosts = max($fleet_ua_prevalence.fleet_adopters)
  $fleet_total_hosts = max($fleet_host_total.total_hosts)
  $local_events = max($host_ua_activity.host_events)
  $safe_hosts = if($adopter_hosts > 0, $adopter_hosts, 1)
  $safe_fleet_hosts = if($fleet_total_hosts > $safe_hosts, $fleet_total_hosts, $safe_hosts)
  $rarity_score = math.log(1.0 * $safe_fleet_hosts / $safe_hosts)

  // 6 Core Evidence Pillars
  $observation_count = $local_events
  $baseline_active_samples = $safe_fleet_hosts
  $baseline_mean = 1.0 * $adopter_hosts / $safe_fleet_hosts
  $baseline_dispersion = $rarity_score
  $fleet_prevalence = $adopter_hosts
  $distinct_binaries = 1
  $sample_commands = array_distinct($host_ua_activity.sample_uris)

condition:
  $safe_fleet_hosts >= 5
  and $fleet_prevalence <= 2
  and $observation_count >= 5
  and $rarity_score >= 1.5

order:
  $rarity_score desc
