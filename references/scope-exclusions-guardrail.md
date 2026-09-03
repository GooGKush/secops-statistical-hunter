# Scope Exclusions & Engine Boundaries

A critical engineering boundary in Google SecOps is understanding what each backend engine supports:

---

## 1. Search Engine vs. Detection Rules Engine Separation (CRITICAL)

### The Fundamental Architectural Difference
* **Search / Stats Engine (`parser.MultiStageQuery`)**:
  * Operates on ad-hoc queries with named stages (`stage stage1 { ... } stage stage2 { ... } outcome: ...`).
  * Evaluated across the data plane using F1/Query Engine as a directed acyclic graph (DAG) of intermediate joins and aggregations.
  * Supported in **UDM Search API (`udm_search`)**, **SearchService (LRO)**, and **Native Dashboards (`ExecuteDashboardQuery`)**.
* **Detection Rules Engine (`parser.YL2Rule`)**:
  * Operates on continuous, real-time event streams evaluating incoming logs against sliding match windows.
  * Strictly requires standard YARA-L 2.0 Rule syntax (`rule <name> { events: ... match: ... condition: ... outcome: ... }`).
  * **Does NOT support multi-stage DAG execution or `stage` blocks.**

### Prohibited Agent Actions
* ❌ **NEVER** offer to convert a multi-stage search query into a real-time YARA-L detection rule.
* ❌ **NEVER** attempt to submit a multi-stage query to `create_rule` or `validate_rule`.

### Permitted Operational Paths
* ✓ **Ad-hoc Execution**: Run the query directly via `udm_search` across Gus-SDL or the customer instance.
* ✓ **Native Dashboard Widget**: Add the multi-stage query to a Native SecOps Dashboard chart (Scatterplot, Bar, Table).
* ✓ **Scheduled Hunting Search**: Configure a recurring automation / sidecar job that executes the search on a daily/weekly schedule and summarizes new outliers for the SOC team.

---

## 2. UEBA / Risk Analytics (`metrics.*`) vs. Ad-Hoc Multi-Stage Telemetry

| Dimension | `secops-risk-metrics-multistage` (UEBA Metrics) | `secops-statistical-hunter` (This Skill) |
| :--- | :--- | :--- |
| **Data Plane** | Pre-computed daily/hourly summary tables (`metrics.*`) | Raw telemetry (`UDM_EVENTS`) & alerts (`RULE_DETECTIONS`) |
| **Lookback Horizon** | **Fixed Rolling 30-Day Windows** (`window: 30d`, `period: 1d`) with $O(1)$ lookups. | **Arbitrary Time Slices**: Can query any timestamp window (`2026-08-01T00:00:00Z` to `2026-08-15T00:00:00Z`). |
| **Join Restrictions** | Must match exact pre-indexed dimension combinations (e.g. `target.user.userid` + `country`). | Can group by any combination of UDM fields (`principal.hostname`, `target.ip`, `dns.questions.name`). |
| **Primary Use Case** | Baseline alerting when an entity deviates from their 30-day pre-computed posture or peer cohort. | Interactive threat hunting across un-baselined TTPs (C2 beaconing, DGA, timing jitter, bursts). |

### Shared Multi-Stage Model Disambiguation
Both skills execute ad-hoc Multi-Stage YARA-L DAG queries (`stage ... { }` + unwrapped Root Stage) via Chronicle UDM Search (`udm_search`). When an analyst inquiry uses shared mathematical terms, apply this routing matrix:

1. **Dual-Baseline Delta-$Z$**:
   * **In `secops-statistical-hunter` (This Skill)**: The *Patch Tuesday Shield*—compares an entity's raw log surge today against the concurrent enterprise fleet shift ($\Delta Z = Z_{\text{personal}} - Z_{\text{fleet}}$) to suppress company-wide updates.
   * **In `secops-risk-metrics-multistage`**: Compares an entity's 30-day personal baseline (`metrics.auth_attempts_*`) against a pre-computed peer department/cohort baseline.
2. **Multi-Sector Threat Fusion**:
   * **In `secops-statistical-hunter` (This Skill)**: The *Combined Arms Radar*—fuses raw event counts across orthogonal silos (Auth + Process + Network) in a single historical search window.
   * **In `secops-risk-metrics-multistage`**: Fuses decoupled 30-day baseline deviations ($D = \sqrt{\sum Z_i^2}$) across UEBA tables (Auth, Cloud CRUD, Workspace Exfil, Network Egress, Endpoint Tools).
3. **Timing Jitter ($CV \le 0.20$) & Inter-Arrival Analysis ($\Delta t$)**:
   * **Exclusive to `secops-statistical-hunter`**: Pre-computed UEBA tables aggregate daily event sums and cannot compute packet/connection inter-arrival intervals ($\Delta t_i = t_i - t_{i-1}$). Timing jitter and robotic beaconing MUST be evaluated over raw UDM telemetry.
4. **30-Day Baselines, Peer Cohorts & 360° Health Checks**:
   * **Exclusive to `secops-risk-metrics-multistage`**: Requires pre-computed behavioral baselines. Route all requests targeting `metrics.*` or 30-day UEBA envelopes to `secops-risk-metrics-multistage`.
5. **Service Account Repository Access & Origin Scope Anomalies**:
   * **In `secops-risk-metrics-multistage`**: When monitoring cloud data stores (GCS buckets, BigQuery datasets, AWS S3 buckets) backed by `GCP_CLOUDAUDIT`, `AWS_CLOUDTRAIL`, or `AZURE_ACTIVITY`. Uses 30-day pre-computed baselines (`metrics.resource_read_*`, `metrics.resource_written_*`) filtering directly by `principal.user.userid` and caller IP `principal.ip`.
   * **In `secops-statistical-hunter` (This Skill)**: When monitoring source code repositories (GitHub, GitLab, Bitbucket) or custom file servers whose telemetry logs as `metadata.event_type = "USER_RESOURCE_ACCESS"`. Evaluates empirical origin rarity ($k \ge 1$ from unobserved origin $\lambda \to 0$) or volume MAD over raw UDM telemetry.

---

## 3. Mandatory Pre-Dispatch Linter Check

All queries generated by this skill must pass through `scripts/multistage_query_builder.py` to assert that zero `metrics.*` or `graph.risk_score` patterns leak into the YARA-L string:

```python
EXCLUDED_PATTERNS = [
    (r"\bmetrics\.", "UEBA metric functions (metrics.*) are excluded from ad-hoc searches. Use secops-risk-metrics-multistage."),
    (r"\brisk_score\b", "Entity Risk Score fields (risk_score) are excluded. Use secops-risk-metrics-multistage."),
    (r"\bgraph\.risk_score", "Entity Risk Graph tables are excluded. Use secops-risk-metrics-multistage."),
    (r"UEBA_EVENTS", "UEBA_EVENTS source dataset is excluded. Use raw UDM_EVENTS or RULE_DETECTIONS."),
    (r"^\s*rule\s+[a-zA-Z0-9_]+\s*\{", "Multi-stage queries cannot be wrapped in rule blocks. They are Search-only."),
]
```

---

## 4. Search Window Ceilings: Single-Stage (90 Days) vs. Multi-Stage (30 Days)

Google SecOps enforces strict backend execution limits depending on query topology:

| Query Architecture | Maximum Window Ceiling | Underlying Reason | Recommended Hunting Use Case |
| :--- | :--- | :--- | :--- |
| **Single-Stage Macro Stats Search**<br>(`match: $host outcome: ...`) | **90 Consecutive Days**<br>(7,776,000 seconds / 2,160 hours) | Single map-reduce aggregation pass without cross-stage shuffle buffers. | Historical host averages, 90-day entity profile summaries, total volume baselines. |
| **Multi-Stage DAG Outlier Hunt**<br>(`stage s1 { ... } stage s2 { ... }`) | **30 Consecutive Days**<br>(2,592,000 seconds / 720 hours) | Intermediate stage joins and shuffle states are buffered in distributed F1 worker memory. Queries $>30\text{d}$ exceed join buffer quotas. | Hourly 3-Sigma $Z$-scores, MAD outlier detection, Poisson burst clustering (Fano factor). |

### Prescriptive Agent Interception
* If an analyst asks for a **Multi-Stage Hunt** $>30\text{ days}$:
  1. Advise that multi-stage queries have a 30-day maximum limit due to distributed join state buffers.
  2. Run the multi-stage hunt over the maximum 30-day window (720 hourly points are statistically optimal for 3-Sigma).
  3. Offer a 90-day single-stage macro search if they specifically need longer historical averages.
* If an analyst asks for any search $>90\text{ days}$:
  1. Advise that the absolute Chronicle Search API ceiling is 90 days.
  2. Scope the search to the 90-day maximum window.
