# Chronicle Entity Context Graph (ECG) & Global Context Guide

This reference provides the structural syntax, field catalog, and compiler invariants for integrating Chronicle's **Entity Context Graph (ECG)** — specifically `GLOBAL_CONTEXT` (threat intelligence) and `DERIVED_CONTEXT` (persistent first seen, last seen, and enterprise prevalence) — into multi-stage statistical threat hunting pipelines.

---

## 1. Architectural Foundations: Graph Context in Statistical Hunting

In standard raw telemetry hunting, calculations are bounded strictly by the ad-hoc query horizon (e.g. 24h, 7d, 30d). While this is ideal for detecting sudden burst velocity and timing jitter, it suffers from two major limitations:
1. **The Cold-Start Blindspot**: An ad-hoc query cannot definitively tell whether a host or domain is truly brand-new across the entire enterprise history or simply had zero events within the query's time window.
2. **External Threat Agnosticism**: A statistical burst to an external IP or domain carries different risk if the destination is a known CDN versus a domain registered 48 hours ago or flagged in Google Cloud Threat Intelligence (GCTI).

Chronicle SIEM bridges this gap via the **Entity Context Graph (`$alias.graph.*`)**, storing persistent entity metadata that can be joined directly inside multi-stage DAGs.

---

## 2. Graph Source Types & UDM Field Catalog

### A. `GLOBAL_CONTEXT` (Curated Threat Intelligence)
Represents global intelligence feeds continuously updated by Google Cloud:

| Provider / Feed | UDM Source & Filter Syntax | Key Fields Available |
| :--- | :--- | :--- |
| **Google Cloud Threat Intelligence (GCTI)** | `$gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"` | `$gcti.graph.metadata.threat.threat_feed_name` (e.g. `"Tor Exit Nodes"`, `"Remote Access Tools"`, `"Command and Control Servers"`)<br>`$gcti.graph.entity.hostname`, `$gcti.graph.entity.ip` |
| **WHOIS Domain Registration** | `$whois.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$whois.graph.metadata.vendor_name = "WHOIS"` | `$whois.graph.entity.domain.creation_time.seconds`<br>`$whois.graph.entity.domain.expiration_time.seconds`<br>`$whois.graph.entity.domain.name` |
| **Google Safe Browsing** | `$safebrowse.graph.metadata.source_type = "GLOBAL_CONTEXT"`<br>`$safebrowse.graph.metadata.product_name = "Google Safe Browsing"` | `$safebrowse.graph.entity.file.sha256`<br>`$safebrowse.graph.entity.url` |

### B. `DERIVED_CONTEXT` (Chronicle Persistent Entity History)
Represents Chronicle's enterprise-wide persistent tracking across months/years of ingested data:

| Entity Type | UDM Source & Filter Syntax | Key Fields Available |
| :--- | :--- | :--- |
| **Asset / Host History** | `$asset.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$asset.graph.metadata.entity_type = "ASSET"` | `$asset.graph.entity.asset.first_seen_time.seconds`<br>`$asset.graph.entity.asset.last_seen_time.seconds`<br>`$asset.graph.entity.asset.hostname` |
| **User Account History** | `$user.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$user.graph.metadata.entity_type = "USER"` | `$user.graph.entity.user.first_seen_time.seconds`<br>`$user.graph.entity.user.last_seen_time.seconds`<br>`$user.graph.entity.user.userid` |
| **Artifact / Domain Prevalence** | `$dom.graph.metadata.source_type = "DERIVED_CONTEXT"`<br>`$dom.graph.metadata.entity_type = "DOMAIN_NAME"` | `$dom.graph.entity.domain.first_seen_time.seconds`<br>`$dom.graph.entity.domain.last_seen_time.seconds` |

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
In YARA-L 2.0, multi-stage joins across stages in the root stage are inner joins on the match keys. If Stage 2 filters on an external threat feed (`threat_feed_name != ""`), entities with clean reputations will produce **zero records in Stage 2 and be completely omitted from the root stage**.
* To use ECG as an **enrichment multiplier** on general statistical outliers:
  Match on the entity/domain and evaluate threat flags via boolean indicators (`$is_threat = if($gcti_match > 0, 1.0, 0.0)`).
* To use ECG as a **hard qualification gate**:
  Use the inner join intentionally (e.g. hunting specifically for statistical bursts targeting known GCTI IOCs).

---

## 4. Canonical 3-Stage + Root Pipeline Pattern

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
  $z_score = ($obs_bytes - $mean_bytes) / $safe_sd

  $created = max($global_threat_intel.creation_ts)
  $domain_age_days = (timestamp.current_seconds() - $created) / 86400.0
  $is_nrd = if($domain_age_days <= 30.0 and $domain_age_days >= 0.0, 1.0, 0.0)

  // Context-Boosted Threat Score: Apply 2.5x multiplier for newly registered domains
  $threat_score = if($is_nrd == 1.0, $z_score * 2.5, $z_score)

condition:
  $host_baseline.active_hours >= 12
  and $threat_score >= 3.0

order:
  $threat_score desc
```
