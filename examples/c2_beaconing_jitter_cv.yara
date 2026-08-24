// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect persistent Command & Control (C2) beaconing to low-prevalence external infrastructure with random sleep jitter.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ) & Fleet Prevalence Filter
// Mathematical Rationale:
//   - Why this model: Automated implants (Cobalt Strike, Sliver) sleep between callbacks with a configured jitter percentage (typically 15-20%).
//     This produces a low Coefficient of Variation (CV <= 0.20), whereas human browsing exhibits wide, random time variance (CV > 0.50).
//   - Noise protection: Enforces a volume floor of >= 25 connections over the window, a sample density floor (>= 6 active hours),
//     and restricts destination IP prevalence to <= 2 internal hosts to eliminate widespread cloud infrastructure (CDNs, NTP, OS updates).
// Sensitivity Boundary: BALANCED (CV <= 0.20, Total Conns >= 25, Prevalence <= 2 hosts, Active Hours >= 6)
// ============================================================================

// Stage 1: Measure hourly timing stamps per (src_ip, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    principal.asset.ip = $src_ip
    // Exclude internal RFC 1918 subnets for destination
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    $ts = metadata.event_timestamp.seconds

  match:
    $src_ip, $dst_ip by 1h
  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
}

// Stage 2: Calculate hourly gap interval and aggregate historical timing stats across the window
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip
    
    // Linear event-level gap interval computation across stage 1 outputs
    $time_span = $host_intervals.last_seen - $host_intervals.first_seen
    $intervals = $host_intervals.conn_count - 1
    $avg_gap = $time_span / $intervals

  match:
    $src_ip, $dst_ip
  outcome:
    $mean_gap = avg($avg_gap)
    $stddev_gap = stddev($avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $active_hours = count($host_intervals.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of the destination IP
stage fleet_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip
  outcome:
    // How many distinct internal hosts communicated with this external IP?
    $prevalence = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute CV, and emit standardized 6 Evidence Pillars
$src_ip = $timing_stats.src_ip
$dst_ip = $timing_stats.dst_ip
$dst_ip = $fleet_prevalence.dst_ip

// Linear event-level CV calculation (eliminates intra-stage outcome race conditions)
$cv_ratio = $timing_stats.stddev_gap / $timing_stats.mean_gap

match:
  $src_ip, $dst_ip
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($fleet_prevalence.prevalence)
  $distinct_binaries = max($timing_stats.total_conns)
  
  // Aggregate Coefficient of Variation
  $cv = max($cv_ratio)

condition:
  // Small-Sample Protection: Require at least 6 active hourly beaconing buckets
  $baseline_active_samples >= 6
  // Volume Floor: at least 25 connections over window
  and $observation_count >= 25
  // Prevalence Constraint: rare external destination (<= 2 hosts in enterprise)
  and $fleet_prevalence <= 2
  // Timing Constraint: beacon interval between 30s and 3600s (1h)
  and $baseline_mean >= 30.0 and $baseline_mean <= 3600.0
  // Sensitivity Tier: BALANCED (CV <= 0.20 tolerates up to 20% random sleep jitter)
  and $cv <= 0.20

order:
  $cv asc

