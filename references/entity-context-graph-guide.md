# Chronicle Entity Context Graph (ECG) & Global Context Guide

This reference provides the structural syntax, field catalog, and compiler invariants for integrating Chronicle's **Entity Context Graph (ECG)** — specifically `GLOBAL_CONTEXT` (threat intelligence) and `DERIVED_CONTEXT` (persistent first seen, last seen, and enterprise prevalence) — into multi-stage statistical threat hunting pipelines.

---

## 1. Architectural Foundations: Graph Context in Statistical Hunting

In standard raw telemetry hunting, calculations are bounded strictly by the ad-hoc query horizon (e.g. 24h, 7d, 14d). While this is ideal for detecting sudden burst velocity and timing jitter, it suffers from two major limitations:
1. **The Cold-Start Blindspot**: An ad-hoc query cannot definitively tell whether a binary, domain, or host is truly brand-new across the entire enterprise history or simply had zero events within the query's bounded time window.
2. **External Threat Agnosticism**: A statistical burst to an external destination carries vastly different risk if the target is a long-standing internal service versus a domain registered 48 hours ago or an executable never previously seen on any endpoint in the enterprise.

Chronicle SIEM bridges this gap via the **Entity Context Graph (`$alias.graph.*`)**, storing persistent entity metadata and enterprise prevalence that can be joined directly inside multi-stage DAGs.

---

## 2. Graph Source Types & UDM Field Catalog

### A. `GLOBAL_CONTEXT` (Curated Threat Intelligence)
Represents global intelligence feeds continuously updated by Google Cloud:

| Provider / Feed | UDM Source & Filter Syntax | Key Fields Available |
| :--- | :--- | :--- |
| **Google Cloud Threat Intelligence (GCTI)** | `$gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"` | `$gcti.graph.metadata.threat.threat_feed_name` (e.g. `"Tor Exit Nodes"`, `"Remote Access Tools"`, `"Command and Control Servers"`)<br>`$gcti.graph.entity.hostname`, `$gcti.graph.entity.ip` |
| **WHOIS Domain Registration** | `$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$whois.graph.metadata.vendor_name = "WHOIS"` | `$whois.graph.entity.domain.creation_time.seconds`<br>`$whois.graph.entity.domain.expiration_time.seconds`<br>`$whois.graph.entity.domain.name` |
| **Google Safe Browsing** | `$safebrowse.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$safebrowse.graph.metadata.product_name = "Google Safe Browsing"` | `$safebrowse.graph.entity.file.sha256`<br>`$safebrowse.graph.entity.url` |
| **Benign Binaries / Known Good** | `$benign.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$benign.graph.metadata.threat.threat_feed_name = "Benign Binaries"` | `$benign.graph.entity.file.sha256`<br>`$benign.graph.metadata.threat.threat_feed_name` |

### B. `DERIVED_CONTEXT` (Chronicle Persistent Entity History & Prevalence)
Represents Chronicle's enterprise-wide persistent tracking across months and years of ingested telemetry:

| Entity Type | UDM Source & Filter Syntax | Key Fields Available |
| :--- | :--- | :--- |
| **File / Binary (`FILE`)** | `$file.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$file.graph.metadata.entity_type = "FILE"`<br>`$file.graph.entity.file.sha256 = $sha256` | `$file.graph.entity.file.prevalence.day_count` (integer: total calendar days observed enterprise-wide)<br>`$file.graph.entity.file.prevalence.rolling_max` (integer: rolling peak host count)<br>`$file.graph.entity.file.first_seen_time.seconds`<br>`$file.graph.entity.file.last_seen_time.seconds` |
| **Domain Name (`DOMAIN_NAME`)** | `$dom.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$dom.graph.metadata.entity_type = "DOMAIN_NAME"`<br>`$dom.graph.entity.domain.name = $domain` | `$dom.graph.entity.domain.prevalence.day_count` (integer: total calendar days contacted enterprise-wide)<br>`$dom.graph.entity.domain.prevalence.rolling_max` (integer: rolling peak host count)<br>`$dom.graph.entity.domain.first_seen_time.seconds`<br>`$dom.graph.entity.domain.last_seen_time.seconds` |
| **Asset / Host History (`ASSET`)** | `$asset.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$asset.graph.metadata.entity_type = "ASSET"`<br>`$asset.graph.entity.asset.hostname = $host` | `$asset.graph.entity.asset.first_seen_time.seconds`<br>`$asset.graph.entity.asset.last_seen_time.seconds`<br>`$asset.graph.entity.asset.hostname` |
| **User Account History (`USER`)** | `$user.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$user.graph.metadata.entity_type = "USER"`<br>`$user.graph.entity.user.userid = $user` | `$user.graph.entity.user.first_seen_time.seconds`<br>`$user.graph.entity.user.last_seen_time.seconds`<br>`$user.graph.entity.user.userid` |

---

## 3. The 4 Hard Compiler & Memory Invariants for ECG

When authoring multi-stage queries with Entity Context Graph joins, the following rules are mandatory:

### Rule 1: Maximum 1 ECG Alias Per Named Stage (`ECG_LIMIT = 1`)
Chronicle's F1 distributed memory engine isolates graph traversal. Declaring more than one graph alias (`$alias.graph.*`) inside a single stage block causes memory exhaustion.
* ❌ **Invalid (Multiple Graph Aliases in One Stage)**:
  ```yara
  stage bad_stage {
    $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
    $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT" // FAILS: 2 ECG aliases in one stage
  }
  ```
* ✅ **Valid (Decoupled across DAG Stages)**:
  Place each graph lookup in its own named stage, or select the primary intelligence source for that stage.

### Rule 2: Strict Allowance of 1–3 Named Stages Plus Root
Because Malachite queries permit at most **3 named intermediate stages plus 1 unwrapped root stage (4 stages total)**, an ECG pipeline must budget its stages cleanly:
* **Stage 1**: Event-Plane Extraction & Binning (Raw telemetry)
* **Stage 2**: Entity Context Graph Enrichment (Max 1 ECG lookup)
* **Stage 3**: Historical Parameter Estimation (Mean, Standard Deviation, Active Intervals)
* **Root Stage**: Multi-Stage Join, Safe-Divisor Arithmetic & Threat Scoring

### Rule 3: Zero Event-Section Arithmetic Above `match:`
Graph timestamp calculations must **never** perform binary arithmetic (`-`, `+`) in the event filter section:
* ❌ **Invalid**:
  ```yara
  $age_seconds = timestamp.current_seconds() - $whois.graph.entity.domain.creation_time.seconds // FAILS
  ```
* ✅ **Valid (Direct Placeholder Assignment & Outcome Calculation)**:
  ```yara
  // In event filter:
  $created_ts = $whois.graph.entity.domain.creation_time.seconds

  // In outcome block:
  $age_days = (timestamp.current_seconds() - max($created_ts)) / 86400.0
  ```

### Rule 4: Inner-Join Awareness & Safe Left-Join Emulation
In YARA-L 2.0, multi-stage joins across stages in the root stage are inner joins on the match keys.
* If Stage 2 filters on an external threat feed (`threat_feed_name != ""`), clean entities produce zero records in Stage 2 and are omitted from root.
* For **Derived Context Prevalence** (`FILE`, `DOMAIN_NAME`, `ASSET`): Chronicle maintains continuous graph state for ingested entities. In root outcomes, apply safe evaluation to handle boundary conditions:
  ```yara
  $enterprise_day_count = min($file_derived_context.day_count)
  // Low-prevalence indicator: Day count <= 3 enterprise-wide
  $is_rare_binary = if($enterprise_day_count <= 3 and $enterprise_day_count >= 0, 1.0, 0.0)
  $multiplier = if($is_rare_binary = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $multiplier
  ```

---

## 4. Canonical Multi-Stage Pipeline Patterns

### Pattern 1: Global Context Threat Intel Enrichment (`global_threat_intel_enrichment_3stage.yl2`)
```yara
// Goal: Hunt for high-volume network exfiltration targeting newly registered domains or GCTI threats
// Statistical Model: Z-Score with Global Threat Intel (ECG) Enrichment

// --- STAGE 1: Event-Plane Traffic Extraction ---
stage raw_traffic {
  $net.metadata.event_type = "NETWORK_CONNECTION"
  $host = $net.principal.asset.hostname
  $domain = $net.target.hostname
  $domain != ""
  $host != ""

  match:
    $host, $domain by 1h

  outcome:
    $hourly_bytes = sum($net.network.sent_bytes)
    $conn_count = count($net.metadata.id)
}

// --- STAGE 2: Global Context Graph Lookup (Max 1 ECG Alias) ---
stage global_threat_intel {
  $whois.graph.entity.domain.name = $domain
  $whois.graph.metadata.entity_type = "DOMAIN_NAME"
  $whois.graph.metadata.vendor_name = "WHOIS"
  $whois.graph.metadata.source_type = "GLOBAL_CONTEXT"
  $domain != ""

  match:
    $domain

  outcome:
    $creation_ts = max($whois.graph.entity.domain.creation_time.seconds)
}

// --- STAGE 3: Baseline Parameter Estimation ---
stage host_baseline {
  $host = $raw_traffic.host

  match:
    $host

  outcome:
    $hist_mean_bytes = avg($raw_traffic.hourly_bytes)
    $hist_sd_bytes = stddev($raw_traffic.hourly_bytes)
    $active_hours = count($raw_traffic.window_start)
}

// --- ROOT STAGE (UNWRAPPED): Joint Statistical & Threat Fusion ---
$host = $raw_traffic.host
$domain = $raw_traffic.domain
$domain = $global_threat_intel.domain
$host = $host_baseline.host

match:
  $host, $domain by 1h

outcome:
  $obs_bytes = max($raw_traffic.hourly_bytes)
  $mean_bytes = max($host_baseline.hist_mean_bytes)
  $sd_bytes = max($host_baseline.hist_sd_bytes)
  $safe_sd = if($sd_bytes > 0, $sd_bytes, 1.0)
  $z_score = ($obs_bytes - $mean_bytes) / ($safe_sd + 1.0)

  $created = max($global_threat_intel.creation_ts)
  $domain_age_days = (timestamp.current_seconds() - $created) / 86400.0
  $is_nrd = if($domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)

  // Context-Boosted Threat Score: Apply 2.5x multiplier for newly registered domains
  $threat_score = if($is_nrd = 1.0, $z_score * 2.5, $z_score)

  // 6 Standardized Evidence Pillars
  $observation_count = $obs_bytes
  $baseline_active_samples = max($host_baseline.active_hours)
  $baseline_mean = $mean_bytes
  $baseline_dispersion = $sd_bytes
  $fleet_prevalence = 1
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 12
  and $threat_score >= 3.0

order:
  $threat_score desc
```

### Pattern 2: Derived Context File Prevalence Pipeline (`derived_context_file_prevalence_3stage.yl2`)
```yara
// Goal: Hunt for anomalous execution bursts of rare or enterprise-unseen binaries using Derived Context prevalence
// Statistical Model: Z-Score with Derived Context (Binary Day Count & Age) Prevalence Multiplier

// --- STAGE 1: Event-Plane Process Execution Extraction ---
stage raw_execution {
  $proc.metadata.event_type = "PROCESS_LAUNCH"
  $host = $proc.principal.asset.hostname
  $sha256 = $proc.target.process.file.sha256
  $host != ""
  $sha256 != ""

  match:
    $host, $sha256 by 1h

  outcome:
    $hourly_executions = count($proc.metadata.id)
}

// --- STAGE 2: Chronicle Derived Context Graph Lookup (Binary Prevalence & Age) ---
stage file_derived_context {
  $file.graph.entity.file.sha256 = $sha256
  $file.graph.metadata.entity_type = "FILE"
  $file.graph.metadata.source_type = "DERIVED_CONTEXT"
  $sha256 != ""

  match:
    $sha256

  outcome:
    $day_count = min($file.graph.entity.file.prevalence.day_count)
    $rolling_max = max($file.graph.entity.file.prevalence.rolling_max)
    $first_seen_ts = min($file.graph.entity.file.first_seen_time.seconds)
}

// --- STAGE 3: Host Execution Baseline Parameter Estimation ---
stage host_baseline {
  $host = $raw_execution.host

  match:
    $host

  outcome:
    $hist_mean_execs = avg($raw_execution.hourly_executions)
    $hist_sd_execs = stddev($raw_execution.hourly_executions)
    $active_hours = count($raw_execution.window_start)
}

// --- ROOT STAGE (UNWRAPPED): Joint Execution & Enterprise Prevalence Fusion ---
$host = $raw_execution.host
$sha256 = $raw_execution.sha256
$sha256 = $file_derived_context.sha256
$host = $host_baseline.host

match:
  $host, $sha256 by 1h

outcome:
  $obs_execs = max($raw_execution.hourly_executions)
  $mean_execs = max($host_baseline.hist_mean_execs)
  $sd_execs = max($host_baseline.hist_sd_execs)
  $safe_sd = if($sd_execs > 0, $sd_execs, 1.0)
  $z_score = ($obs_execs - $mean_execs) / ($safe_sd + 1.0)

  $enterprise_day_count = min($file_derived_context.day_count)
  $enterprise_first_seen = min($file_derived_context.first_seen_ts)
  $file_age_days = (timestamp.current_seconds() - $enterprise_first_seen) / 86400.0

  // Rare Binary Multiplier: 2.5x threat score boost for binaries seen enterprise-wide on <= 3 days
  $is_rare_binary = if($enterprise_day_count <= 3 and $enterprise_day_count >= 0, 1.0, 0.0)
  $multiplier = if($is_rare_binary = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $multiplier

  // 6 Standardized Evidence Pillars
  $observation_count = $obs_execs
  $baseline_active_samples = max($host_baseline.active_hours)
  $baseline_mean = $mean_execs
  $baseline_dispersion = $sd_execs
  $fleet_prevalence = max($file_derived_context.rolling_max)
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 12
  and $threat_score >= 2.5

order:
  $threat_score desc
```

### Pattern 3: Derived Context Domain Prevalence Pipeline (`derived_context_domain_prevalence_3stage.yl2`)
```yara
// Goal: Hunt for anomalous network egress bursts to enterprise-unseen or low-prevalence domains using Derived Context
// Statistical Model: Z-Score with Derived Context (Domain Day Count & First Seen) Prevalence Multiplier

// --- STAGE 1: Event-Plane Network Egress Extraction ---
stage raw_network {
  $net.metadata.event_type = "NETWORK_CONNECTION"
  $host = $net.principal.asset.hostname
  $domain = $net.target.hostname
  $host != ""
  $domain != ""

  match:
    $host, $domain by 1h

  outcome:
    $hourly_bytes = sum($net.network.sent_bytes)
    $conn_count = count($net.metadata.id)
}

// --- STAGE 2: Chronicle Derived Context Graph Lookup (Domain Prevalence & Age) ---
stage domain_derived_context {
  $dom.graph.entity.domain.name = $domain
  $dom.graph.metadata.entity_type = "DOMAIN_NAME"
  $dom.graph.metadata.source_type = "DERIVED_CONTEXT"
  $domain != ""

  match:
    $domain

  outcome:
    $day_count = min($dom.graph.entity.domain.prevalence.day_count)
    $rolling_max = max($dom.graph.entity.domain.prevalence.rolling_max)
    $first_seen_ts = min($dom.graph.entity.domain.first_seen_time.seconds)
}

// --- STAGE 3: Host Egress Baseline Parameter Estimation ---
stage host_baseline {
  $host = $raw_network.host

  match:
    $host

  outcome:
    $hist_mean_bytes = avg($raw_network.hourly_bytes)
    $hist_sd_bytes = stddev($raw_network.hourly_bytes)
    $active_hours = count($raw_network.window_start)
}

// --- ROOT STAGE (UNWRAPPED): Joint Egress & Enterprise Domain Prevalence Fusion ---
$host = $raw_network.host
$domain = $raw_network.domain
$domain = $domain_derived_context.domain
$host = $host_baseline.host

match:
  $host, $domain by 1h

outcome:
  $obs_bytes = max($raw_network.hourly_bytes)
  $mean_bytes = max($host_baseline.hist_mean_bytes)
  $sd_bytes = max($host_baseline.hist_sd_bytes)
  $safe_sd = if($sd_bytes > 0, $sd_bytes, 1.0)
  $z_score = ($obs_bytes - $mean_bytes) / ($safe_sd + 1.0)

  $enterprise_day_count = min($domain_derived_context.day_count)
  $enterprise_first_seen = min($domain_derived_context.first_seen_ts)
  $domain_age_days = (timestamp.current_seconds() - $enterprise_first_seen) / 86400.0

  // Rare Domain Multiplier: 2.5x threat score boost for domains observed enterprise-wide on <= 3 days
  $is_rare_domain = if($enterprise_day_count <= 3 and $enterprise_day_count >= 0, 1.0, 0.0)
  $multiplier = if($is_rare_domain = 1.0, 2.5, 1.0)
  $threat_score = $z_score * $multiplier

  // 6 Standardized Evidence Pillars
  $observation_count = $obs_bytes
  $baseline_active_samples = max($host_baseline.active_hours)
  $baseline_mean = $mean_bytes
  $baseline_dispersion = $sd_bytes
  $fleet_prevalence = max($domain_derived_context.rolling_max)
  $distinct_binaries = 1

condition:
  $baseline_active_samples >= 12
  and $threat_score >= 2.5

order:
  $threat_score desc
```
