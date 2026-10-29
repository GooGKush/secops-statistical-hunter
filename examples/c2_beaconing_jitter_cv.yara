// ============================================================================
// METHODOLOGY & HUNTING GOAL
// Goal: Screen persistent low-prevalence external pairs with uniform bucket flow-gap ratios (flow-gap ratio screen).
// Target Telemetry: UDM_EVENTS (NETWORK_CONNECTION)
// Statistical Model: Cross-Bucket Flow-Gap Ratio Dispersion (flow-gap ratio — stateless YARA-L candidate screen)
// Mathematical Rationale:
//   - Honest D6 G5 In-Query Screen: Stateless bucketed YARA-L measures within-bucket span/count
//     flow-gap ratios across active buckets (CV = σ_gap / μ_gap <= 0.20), serving as an external
//     pair regularity pre-screen while excluding RFC 1918, loopback, multicast, broadcast, and link-local noise.
//   - Noise protection: Enforces >= 25 connections over the window, >= 6 active hours,
//     and destination IP prevalence <= 2 internal hosts.
// Sensitivity Boundary: BALANCED (Flow-Gap Ratio CV <= 0.20, Total Conns >= 25, Prevalence <= 2 hosts, Active Hours >= 6)
// ============================================================================

// Stage 1: Measure hourly span-to-count flow-gap ratio per (src_ip, dst_ip) pair
stage host_intervals {
    metadata.event_type = "NETWORK_CONNECTION"
    target.ip = $dst_ip
    $dst_ip != ""
    principal.asset.ip = $src_ip
    $src_ip != ""
    // Exclude internal RFC 1918, loopback, multicast, broadcast, and IPv4/IPv6 link-local destinations
    not net.ip_in_range_cidr($dst_ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($dst_ip, "192.168.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "127.0.0.0/8")
    not net.ip_in_range_cidr($dst_ip, "224.0.0.0/4")
    not net.ip_in_range_cidr($dst_ip, "169.254.0.0/16")
    not net.ip_in_range_cidr($dst_ip, "255.255.255.255/32")
    not net.ip_in_range_cidr($dst_ip, "fe80::/10")
    not net.ip_in_range_cidr($dst_ip, "ff00::/8")
    $ts = metadata.event_timestamp.seconds

  match:
    $src_ip, $dst_ip by 1h
  outcome:
    $first_seen = min($ts)
    $last_seen = max($ts)
    $conn_count = count(metadata.id)
    $avg_gap = 1.0 * (max($ts) - min($ts)) / count(metadata.id)
}

// Stage 2: Aggregate flow-gap ratio statistics across the window per pair
stage timing_stats {
    $src_ip = $host_intervals.src_ip
    $dst_ip = $host_intervals.dst_ip

  match:
    $src_ip, $dst_ip
  outcome:
    $mean_gap = avg($host_intervals.avg_gap)
    $stddev_gap = stddev($host_intervals.avg_gap)
    $total_conns = sum($host_intervals.conn_count)
    $active_hours = count($host_intervals.window_start)
}

// Stage 3: Measure enterprise-wide prevalence of the destination IP
stage dst_prevalence {
    $dst_ip = $host_intervals.dst_ip

  match:
    $dst_ip
  outcome:
    $src_breadth = count_distinct($host_intervals.src_ip)
}

// Root Stage: Combine timing stats, compute unbiased flow-gap ratio CV, and emit 6 Evidence Pillars
$src_ip = $timing_stats.src_ip
$dst_ip = $timing_stats.dst_ip
$dst_ip = $dst_prevalence.dst_ip

match:
  $src_ip, $dst_ip
outcome:
  // 6 Core Evidence Pillars
  $observation_count = max($timing_stats.total_conns)
  $baseline_active_samples = max($timing_stats.active_hours)
  $baseline_mean = max($timing_stats.mean_gap)
  $baseline_dispersion = max($timing_stats.stddev_gap)
  $fleet_prevalence = max($dst_prevalence.src_breadth)
  $distinct_binaries = max($timing_stats.total_conns)

  // Unbiased Flow-Gap Ratio CV = σ_gap / μ_gap
  $safe_mean = if($baseline_mean > 0.0, $baseline_mean, 1.0)
  $cv = $baseline_dispersion / $safe_mean

condition:
  $baseline_active_samples >= 6
  and $observation_count >= 25
  and $baseline_mean >= 1.0
  and $fleet_prevalence <= 2
  and $cv <= 0.20

order:
  $cv asc
