// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Detect persistent Command & Control (C2) beaconing to low-prevalence external infrastructure with random sleep jitter.
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Inter-Arrival Jitter via Coefficient of Variation (CV = σ / μ) & Fleet Prevalence Filter
// Mathematical Rationale:
//   - Why this model: Automated implants (Cobalt Strike, Sliver) sleep between callbacks with a configured jitter percentage (typically 15-20%).
//     This produces a low Coefficient of Variation (CV <= 0.20), whereas human browsing exhibits wide, random time variance (CV > 0.50).
//   - Noise protection: Enforces a volume floor of >= 25 connections over the window to prevent small-sample division noise, and restricts
//     destination IP prevalence to <= 2 internal hosts to eliminate widespread cloud infrastructure (CDNs, NTP, OS updates).
// Sensitivity Boundary: BALANCED (CV <= 0.20, Total Conns >= 25, Prevalence <= 2 hosts)
// ============================================================================

// Stage 1: Measure hourly timing intervals per (host, destination_ip) pair
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
    // Inter-arrival average interval (in seconds) within the hour
    $avg_gap = ($last_seen - $first_seen) / ($conn_count - 1)
}

// Stage 2: Aggregate historical timing stats across the full window
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip

  match:
    $src_ip, $dst_ip
  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
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

// Root Stage: Combine timing stats, compute CV, and enforce anomaly boundaries
$src_ip = $timing_stats.src_ip
$dst_ip = $timing_stats.dst_ip
$dst_ip = $fleet_prevalence.dst_ip

match:
  $src_ip, $dst_ip
outcome:
  $mean_interval = max($timing_stats.mean_gap)
  $stddev_interval = max($timing_stats.stddev_gap)
  $total_connections = max($timing_stats.total_conns)
  $hosts_contacting = max($fleet_prevalence.prevalence)
  // Coefficient of Variation: smaller CV = higher periodicity / less randomness
  $cv = $stddev_interval / $mean_interval

condition:
  // Volume Floor: at least 25 connections over window to prevent small-sample division noise
  $total_connections >= 25
  // Prevalence Constraint: rare external destination (<= 2 hosts in the enterprise)
  and $hosts_contacting <= 2
  // Timing Constraint: beacon interval between 30s and 3600s (1h)
  and $mean_interval >= 30.0 and $mean_interval <= 3600.0
  // Sensitivity Tier: BALANCED (CV <= 0.20 tolerates up to 20% random sleep jitter)
  and $cv <= 0.20

order:
  $cv asc
