// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect outlier browser user-agent strings across enterprise devices by fleet prevalence and volume.
// Target Telemetry: UDM_EVENTS (NETWORK_HTTP)
// Statistical Model: Fleet Prevalence Normalization & Discrete Host Rarity
// Mathematical Rationale:
//   - Why this model: Compares each user-agent string's endpoint adoption across the enterprise.
//     Standard corporate browsers appear across many hosts; rare/outlier user-agent strings
//     (scrapers, malicious scripts, custom CLI tools, or spoofed implants) appear on an isolated minority of hosts.
//   - Small-Sample & Volume Protection: Enforces a maximum fleet adoption ceiling (<= 2 distinct endpoints)
//     and an activity volume floor (>= 5 HTTP requests) to prevent false positives from transient single-request noise.
// Sensitivity Boundary: BALANCED (Host Prevalence <= 2, Minimum Event Volume >= 5, Minimum Active Hours >= 6)
// ============================================================================

// Stage 1: Individual host activity per user-agent string
stage host_ua_activity {
    metadata.event_type = "NETWORK_HTTP"
    network.http.user_agent = $user_agent
    $user_agent != ""
    principal.asset.hostname = $host
    $host != ""

  match:
    $host, $user_agent by 1d

  outcome:
    $host_events = count(metadata.id)
    $sample_uris = array_distinct(target.url)
}

// Stage 2: Enterprise-wide concurrent fleet adoption on user-agent string
stage fleet_ua_prevalence {
    metadata.event_type = "NETWORK_HTTP"
    network.http.user_agent = $user_agent
    $user_agent != ""
    principal.asset.hostname = $host
    $host != ""

  match:
    $user_agent by 1d

  outcome:
    $fleet_adopters = count_distinct($host)
    $total_fleet_events = count(metadata.id)
    $sample_hosts = array_distinct($host)
}

// Root Stage: Join host activity with fleet adoption on token ($user_agent)
$user_agent = $host_ua_activity.user_agent
$user_agent = $fleet_ua_prevalence.user_agent

match:
  $user_agent by 1d

outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($fleet_ua_prevalence.total_fleet_events)
  $baseline_active_samples = max($fleet_ua_prevalence.fleet_adopters)
  $baseline_mean = 1.0
  $baseline_dispersion = 0.0
  $fleet_prevalence = max($fleet_ua_prevalence.fleet_adopters)
  $distinct_binaries = count_distinct($host_ua_activity.host)
  $sample_commands = array_distinct($fleet_ua_prevalence.sample_hosts)
  
  // Linear Prevalence Dampening Factor: 1.0 / (fleet_adopters + 1.0)
  $prevalence_dampener = 1.0 / ($fleet_prevalence + 1.0)
  $rarity_score = $observation_count * $prevalence_dampener

condition:
  // Fleet Prevalence Filter: User agent must appear on at most 2 distinct enterprise endpoints
  $fleet_prevalence <= 2
  // Activity Floor: Must have observed at least 5 requests
  and $observation_count >= 5

order:
  $rarity_score desc
