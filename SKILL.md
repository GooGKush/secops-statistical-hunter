---
name: secops-statistical-hunter
author: Greg Kushmerek
version: 2.7.1
description: |
  Guides and executes multi-stage statistical anomaly detection, Bayesian credibility updating,
  outlier hunting, and Entity Context Graph (GLOBAL_CONTEXT and DERIVED_CONTEXT) enrichment in Google Security
  Operations (SecOps) over raw UDM telemetry across custom time slices.
  Supports Z-Score, Poisson Dispersion (Fano Factor), Discrete Poisson Rarity, Median Absolute Deviation (MAD),
  Coefficient of Variation (CV), Poisson-Gamma Bayesian Shrinkage, Beta-Binomial Ratio Regularization,
  Dual-Baseline Delta-Z (Patch Tuesday Shield), Multi-Sector Threat Fusion, and 6 Hybrid Mathematical Models
  (Diversity Deficit, Elephant Flow Concentration, Orthogonal Threat Space, Bayesian Joint Odds, Two-Part Hurdle,
  and Fleet Prevalence Normalization). Supports dynamic root-stage condition filtering and noise level steering.
  Enforces strict 5-Section CommonMark Triage Reporting (with 6 standardized forensic evidence pillars,
  Calibrated Risk Index [0-100] normalization, Unicode visual bars, and 1-click drilldowns),
  strict visual axis-type isolation, and post-query intent and stage degradation auditing.
  Triggers: "hunt for beaconing with jitter", "inline C2 timing regularity", "calculate MAD on DNS",
  "Tukey fence anomaly", "impossible travel velocity", "rolling volume ratio", "pre-flight boundary probe",
  "poisson burst clustering", "fano factor password spray", "rare admin tool surge",
  "bayesian gamma prior updating", "beta-binomial failure rate shrinkage", "dual-baseline delta-z",
  "patch tuesday immunity", "multi-sector threat fusion", "4-stage killchain hunter",
  "service account out of normal behavioral scope", "unexpected host origin or abnormal access patterns",
  "unusual data repository access", "service account origin rarity", "source code repository anomaly",
    "diversity deficit", "elephant flow concentration", "orthogonal threat space", "two-part hurdle", "privileged lateral expansion", "unseen endpoint login", "admin destination breadth",
    "global threat intel enrichment", "gcti threat match", "whois newly registered domain surge", "derived context asset age", "unfamiliar machine login",
    "derived context file prevalence", "enterprise unseen binary burst", "derived context domain prevalence", "first seen domain egress", "binary enterprise prevalence".
compatibility: Requires access to a Google SecOps SIEM instance with the SecOps GUS MCP server (udm_search, get_operation) or Chronicle API.
---

# SecOps Statistical Hunter (`secops-statistical-hunter`)

This skill empowers an LLM agent and SOC analyst to execute **ad-hoc multi-stage statistical outlier hunting** in Google SecOps over raw UDM telemetry without requiring pre-computed machine-learning pipelines or UEBA batch metrics.

> [!IMPORTANT]
> ### 🚨 Telemetry Scope & Mandatory Pre-Flight Delegation Gate
> This skill executes **ad-hoc multi-stage statistical anomaly detection strictly over raw in-flight event telemetry** (`UDM_EVENTS`).
> **Skill Delegation Boundary (Immediate Yield):**
> If an analyst prompt references `"UEBA"`, `"30-day baseline"`, `"30d baseline"`, `"risk metric"`, `"risk score"`, `"peer cohort"`, or asks for a behavioral risk review across 30 days:
> **Emit the Skill Delegation Card below and yield the turn (0 tool calls), reserving query formulation and execution strictly for the designated destination skill:**
>
> ### 🔄 Skill Handoff Card — Skill Delegation: Route to `secops-risk-metrics-multistage`
>
> > [!NOTE]
> > **Architectural Boundary Demarcation: Ad-Hoc Raw Telemetry ──► Pre-Computed Behavioral Metrics**
> > • **Routing Rationale**: Rolling 30-day behavioral baselines and UEBA metric functions are pre-computed in Google SecOps and exclusively maintained in secops-risk-metrics-multistage.
> > • **Target Skill**: `secops-risk-metrics-multistage`
> > • **Recommended Metric / Function**: `metrics.*`
> > • **Target Dimension**: `[target user, host, or metric]`
>
> > [!IMPORTANT]
> > **Delegation Action**: Handing off to `secops-risk-metrics-multistage` to construct the behavioral baseline query.
> > *Please switch to the `secops-risk-metrics-multistage` skill to execute this behavioral baseline hunt.*

---

## 🎯 Non-Statistician Intent & Trigger Catalog

When interacting with a cybersecurity analyst, **match their operational hypothesis to the optimal statistical model** and explain the choice using plain-English physical analogies:

| Analyst Operational Question | Statistical Model | Plain-English Concept & Analogy |
| :--- | :--- | :--- |
| *"Find password sprays or brute force pulsing in intermittent waves to evade rate limits."* | **`POISSON_BURST_CLUSTERING`** ($F = \sigma^2 / \mu > 4.0$) | **Rainfall downpour vs. steady trickle**: Normal login mistakes trickle in steadily; automated attack waves arrive in synchronized, clumpy bursts. |
| *"Detect sensitive admin commands (`vssadmin`, `whoami`) surging on quiet servers without division-by-zero."* | **`POISSON_RARE_SURGE`** (Poisson $Z > 3.5$) | **Mathematical rarity on quiet baselines**: Evaluates the improbability of seeing $N$ events today given a near-zero historical arrival rate. |
| *"Hunt for C2 beaconing where the implant uses randomized sleep delays to avoid fixed-interval alerts."* | **`C2_BEACONING_JITTER`** ($\text{CV} \le 0.20$) | **Robotic timing regularity**: Automated implants exhibit low timing variance ($\text{CV} \le 0.20$), while human browsing is chaotic ($\text{CV} > 0.50$). |
| *"Find sudden surges on volatile hosts while ignoring false alarms on erratic machines."* | **`BAYESIAN_GAMMA_SHRINKAGE`** ($\text{Shift} \ge 3.0$) | **The Seasoned SOC Detective**: Gamma prior weights host stability against current evidence; stable machines alert on small shifts. |
| *"Hunt for password spray / error ratios without false alarms from single-trial mistakes (1 fail / 1 try)."* | **`BETA_BINOMIAL_REGULARIZATION`** ($P_{\text{fail}} \ge 0.70$) | **Small-Sample Ratio Regularizer**: Beta-Binomial conjugate updating regularizes single-trial mistakes toward population error baselines. |
| *"Isolate targeted endpoint spikes from company-wide software deployments or Patch Tuesday."* | **`DUAL_BASELINE_DELTA_Z`** ($\Delta Z \ge 3.0\sigma$) | **The Patch Tuesday Immunity Shield**: Subtracts concurrent fleet shift from personal surge ($\Delta Z = Z_p - Z_f$), ignoring company-wide updates. |
| *"Detect coordinated low-and-slow kill chains across Auth, Endpoint, and Network silos."* | **`MULTI_SECTOR_FUSION`** ($D = \sqrt{\sum Z_i^2} \ge 3.0\sigma$) | **The Combined Arms Radar**: Computes orthogonal Euclidean distance across domains, catching multi-vector attacks where point detectors miss. |
| *"Find service accounts accessing source code or data repositories (GitHub, GitLab, internal shares) from unexpected host origins or out of normal scope."* | **`POISSON_ORIGIN_RARITY`** (Poisson $Z > 3.5$) | **The Train on a New Track**: Service accounts operate like trains on fixed rails (fixed CI runners, deterministic IPs). Accessing a repository from an unseen host has a near-zero historical arrival rate ($\lambda \to 0$), triggering an acute statistical rarity alert over raw `USER_RESOURCE_ACCESS`. |
| *"Find automated scripted exfiltration where an entity touches many destinations with minimal vocabulary entropy or elephant flows."* | **`DIVERSITY_DEFICIT`** ($k/(N+1) \le 0.20$) & **`ELEPHANT_FLOW_CONCENTRATION`** ($\text{Peak}/\text{Sum} \ge 0.70$) | **The High-Speed Conveyor**: Attackers scripting data exfiltration generate repetitive, low-entropy transfers with high volume concentration. |
| *"Detect privileged or administrative accounts logging into unseen endpoints or expanding their machine radius."* | **`PRIVILEGED_LATERAL_EXPANSION`** ($Z_{\text{breadth}} \ge 2.0\sigma$) | **The Explorer off the Beaten Path**: Admins routinely touch a small, bounded cluster of machines; a sudden surge in unique target workstations/servers reveals lateral traversal. |
| *"Detect dormant accounts or service accounts suddenly awakening with unusual activity."* | **`TWO_PART_HURDLE`** ($H \ge 2.5$) | **The Sleeper Awakening**: Historically dormant accounts incur a discrete activation penalty; active accounts are evaluated on continuous baseline deviation with exact conditional zero-dispersion protection. |
| *"Hunt for network exfiltration targeting newly registered domains or Google Cloud Threat Intelligence (GCTI) indicators."* | **`GLOBAL_THREAT_INTEL`** ($Z_{\text{threat}} \ge 3.0$) | **The Flash in the Dark**: Combines raw network burst velocity with Chronicle's persistent Entity Context Graph (WHOIS NRD age $< 30$d or GCTI feed matches) to boost threat severity on suspicious destinations. |
| *"Find anomalous logins targeting brand-new, rare, or recently commissioned assets."* | **`DERIVED_CONTEXT_PREVALENCE`** ($Z_{\text{auth}} \ge 2.5$) | **The Unfamiliar Machine**: Uses Chronicle's persistent Entity Context Graph (`DERIVED_CONTEXT`) to verify true enterprise first-seen age, separating routine logins from first-contact connections to unestablished endpoints. |
| *"Hunt for anomalous execution bursts of rare or enterprise-unseen binaries."* | **`DERIVED_CONTEXT_FILE_PREVALENCE`** ($Z_{\text{threat}} \ge 2.5$) | **The Unprecedented Binary**: Uses Chronicle's persistent Entity Context Graph (`DERIVED_CONTEXT`) to evaluate enterprise-wide file prevalence (`day_count <= 3`), applying a 2.5x threat score multiplier for rare binaries executing on local endpoints. |
| *"Detect high-volume network egress bursts to enterprise-unseen or newly contacted domains."* | **`DERIVED_CONTEXT_DOMAIN_PREVALENCE`** ($Z_{\text{threat}} \ge 2.5$) | **The First-Contact Outbound Flow**: Employs Chronicle's persistent Entity Context Graph (`DERIVED_CONTEXT`) to cross-reference domain history (`day_count <= 3`), prioritizing network surges targeting domains never previously accessed across the fleet. |

---

## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE

### 🚦 State 1: Pre-Flight Clearance & Specification (Interactive Verification Gate)

When an analyst initiates a threat hunt or selects an archetype, proceed through the interactive pre-flight gate:
0. **Pre-Flight Routing Interceptor (Risk Metrics Delegation Gate - Strict Precedence)**:
   Always evaluate this routing interceptor first. When this interceptor matches, routing handoff takes absolute precedence over consultative discovery or specification.
   When the analyst request matches any pre-computed baseline or UEBA indicators below, immediately present the Markdown **Skill Delegation Card** and conclude your response (0 tool calls):
   - **Explicit UEBA / 30-Day Baselines / Risk Metrics**: Any request containing the terms `"UEBA"`, `"30-day baseline"`, `"30d baseline"`, `"risk metric"`, or `"risk score"`, or asking for a behavioral risk review across 30 days. Statistical Hunter operates over short-horizon raw telemetry (typically 1h to 7d); rolling 30-day baselines belong to `secops-risk-metrics-multistage`.
   - **Web / HTTP Traffic**: Requests asking to baseline or compare HTTP request volume across browser user-agent strings, hosts, or users (`metrics.http_queries_total`, `metrics.http_queries_success`, `metrics.http_queries_fail`).
   - **Authentication Volume**: Requests comparing logins/failures to an entity's 30-day normal/typical baseline (`metrics.auth_attempts_*`).
   - **Network Bytes/Flows**: Outbound/inbound data transfer baselines (`metrics.network_bytes_*`, `metrics.network_flows_*`).
   - **DNS Queries**: DNS resolution volume or payload bytes over 30 days (`metrics.dns_*`).
   - **File Executions**: Process execution baselines (`metrics.file_executions_*`).
   - **Workspace / Cloud Activity**: Administrative settings changes, file downloads, email volume (`metrics.workspace_*`).
   - **Peer Cohorts & Entity Risk Scores**: Inquiries comparing an entity to their department/role peer group, or referencing omnibus entity risk scores (`graph.risk_score`) / 360° health checks.

   **Affirmative Delegation Output**:
   When any indicator above matches, output the canonical delegation card directly in Markdown and yield the turn:
   ```markdown
   ### 🔄 Skill Handoff Card — Skill Delegation: Route to `secops-risk-metrics-multistage`

   > [!NOTE]
   > **Architectural Boundary Demarcation: Ad-Hoc Raw Telemetry ──► Pre-Computed Behavioral Metrics**
   > • **Routing Rationale**: Rolling 30-day behavioral baselines and UEBA metric functions are pre-computed in Google SecOps and exclusively maintained in secops-risk-metrics-multistage.
   > • **Target Skill**: `secops-risk-metrics-multistage`
   > • **Recommended Metric / Function**: `metrics.*`
   > • **Target Dimension**: `[target user, host, or metric]`

   > [!IMPORTANT]
   > **Delegation Action**: Handing off to `secops-risk-metrics-multistage` to construct the behavioral baseline query.
   > *Please switch to the `secops-risk-metrics-multistage` skill to execute this behavioral baseline hunt.*
   ```
1. **Universal Pre-Flight Gate & Interactive Scoping Protocol**:
   All analytical, investigative, and statistical inquiries (including direct operational requests such as *"Hunt for..."*, *"Check our servers for..."*, *"Evaluate spikes on server X and show the evidence pillars"*, or *"Detect anomalies..."*) enter State 1: Pre-Flight Clearance & Specification.
   Turn 1 is reserved for formulating the hunting methodology: presenting the approach overview, operational analogy, structured pre-flight specification card, candidate query preview, and soliciting execution clearance. Tool execution on Turn 1 evaluates exclusively simple single-event filters via at most ONE 1-shot schema validation probe (`udm_search(..., maxEvents=1)`). Candidate queries remain strictly Markdown previews (` ```yara `) on Turn 1; historical telemetry analysis and multi-stage query execution take place on Turn 2 upon receiving user clearance.
2. **Consultative Support & Expert Bypass Rule**:
   * *Consultative Discovery*: For open-ended requests that remain within raw telemetry scope after clearing Step 0, inspect `references/consultative-worksheet.md` to classify the objective across the 6 Raw Behavioral Telemetry Deformations and 6 Raw Hunting Domains, presenting 2–3 targeted Summary View options.
   * *Enterprise-Grounded Hunt Consultative Pattern*: When an analyst explores endpoint or network anomalies (such as process execution spikes, data egress, or authentication bursts), offer the two-tier scoping choice:
     - **Tier A (Pure Local Baseline)**: Evaluates statistical volume deviations strictly against that endpoint's local historical mean and standard deviation.
     - **Tier B (Enterprise-Grounded Hunt)**: Joins Chronicle `DERIVED_CONTEXT` enterprise prevalence to correlate local spikes with enterprise-wide day counts (`day_count <= 3`), applying a 2.5x threat score boost for unseen binaries or domains while suppressing ubiquitous corporate software.
   * *Expert Bypass Rule*: If the analyst specifies both the target telemetry (e.g. `PROCESS_LAUNCH`) and statistical model (e.g. `MAD` or `Z-score`), proceed directly to emitting the Pre-Flight Card.
3. **Plain-English Operational Analogy**: Explain the detection mechanics in 1-2 intuitive sentences.
4. **Structured Pre-Flight Hunting Specification Card & Candidate Query Preview**:
   * *Template-First Formulation Directive*: Before formulating a candidate query, inspect the matching canonical pipeline template using `view_file` on `templates/pipelines/<model_name>.yl2` (or consult `references/multi-stage-query-guide.md` via `view_file`) to adopt verified variable bindings, match keys, and outcome formulas:
     - `MAD_EXFILTRATION` / `MAD`: `templates/pipelines/mad_exfiltration_2stage.yl2`
     - `POISSON_BURST_CLUSTERING`: `templates/pipelines/poisson_burst_clustering_2stage.yl2`
     - `POISSON_RARE_SURGE` / `POISSON_ORIGIN_RARITY`: `templates/pipelines/poisson_rare_surge_2stage.yl2`
     - `C2_BEACONING_JITTER`: `templates/pipelines/c2_beaconing_jitter_2stage.yl2`
     - `BAYESIAN_GAMMA_SHRINKAGE`: `templates/pipelines/bayesian_gamma_shrinkage_4stage.yl2`
     - `BETA_BINOMIAL_FAILURE`: `templates/pipelines/beta_binomial_failure_4stage.yl2`
     - `DUAL_BASELINE_DELTA_Z`: `templates/pipelines/dual_baseline_delta_z_3stage.yl2`
     - `MULTI_SECTOR_THREAT_FUSION`: `templates/pipelines/multi_sector_threat_fusion_4stage.yl2`
     - `PRIVILEGED_LATERAL_EXPANSION`: `templates/pipelines/privileged_lateral_expansion_2stage.yl2`
     - `TWO_PART_HURDLE`: `templates/pipelines/two_part_hurdle_2stage.yl2`
     - `HYBRID_ENTROPY_CONCENTRATION` / `DIVERSITY_DEFICIT`: `templates/pipelines/hybrid_entropy_concentration_2stage.yl2`
     - `GLOBAL_THREAT_INTEL_ENRICHMENT` / `GLOBAL_CONTEXT`: `templates/pipelines/global_threat_intel_enrichment_3stage.yl2`
     - `DERIVED_CONTEXT_PREVALENCE` / `DERIVED_CONTEXT`: `templates/pipelines/derived_context_prevalence_3stage.yl2`
     - `DERIVED_CONTEXT_FILE_PREVALENCE` / `FILE_PREVALENCE`: `templates/pipelines/derived_context_file_prevalence_3stage.yl2`
     - `DERIVED_CONTEXT_DOMAIN_PREVALENCE` / `DOMAIN_PREVALENCE`: `templates/pipelines/derived_context_domain_prevalence_3stage.yl2`
     - `ZSCORE_PROCESS_SURGE` / `Z_SCORE`: `templates/pipelines/zscore_process_surge_2stage.yl2`
   * *Canonical Pre-Flight Specification Card Structure*: Present the hunting plan using the standard pre-flight specification card layout:
     ```markdown
     PRE-FLIGHT HUNTING SPECIFICATION:
     • Target Entity / Scope:  `[Entity]` ([Entity Type])
     • Threat Hypothesis:      [1-sentence specific threat hypothesis]
     • Baseline Horizon Spine: Raw UDM Telemetry (`[EVENT_TYPE]`, 14-day horizon via `startTime`/`endTime`, canonical `by 1h`/`by 1d` buckets)
     • Statistical Model:      [Canonical Mathematical Model Name]
     • Significance Threshold: [Model-specific statistical threshold] | CRI >= 50
     • Compiler Probe:         1-shot `udm_search(maxEvents=1)` over a 10-minute ISO 8601 window — schema verified.

     ### Candidate Multi-Stage YARA-L Query Preview
     ```
   * *6 Mandatory Root Outcome Variables Protocol*:
     Every candidate multi-stage YARA-L query emits the 6 standardized root outcome variables:
     - `$observation_count` (observed window count, e.g. `max($host_hourly.hourly_count)`)
     - `$baseline_active_samples` (active sample depth, e.g. `max($host_stats.active_samples)`)
     - `$baseline_mean` (baseline central tendency, e.g. `max($host_stats.host_mean)`)
     - `$baseline_dispersion` (baseline spread / deviation, e.g. `max($host_stats.host_stddev)`)
     - `$fleet_prevalence` (fleet breadth active in window, e.g. `max($fleet_breadth.fleet_hosts)`)
     - `$distinct_binaries` (distinct programs or destination targets, e.g. `max($host_hourly.distinct_procs)` for process activity or `max($host_hourly.distinct_destinations)` for network traffic)
     Retain these 6 exact outcome variable names across all telemetry types (process launches, network connections, authentication, DNS, file events).
   * *Target Entity Scoping & Bare Identifier Match Binding*:
     When scoping to a specific entity (such as host `dev-ub22-1` or user `frank.kolzig`), filter directly in the primary stage predicates and bind the entity variable for matching:
     ```yara
     stage host_hourly {
         metadata.event_type = "NETWORK_CONNECTION"
         principal.hostname = "dev-ub22-1"
         principal.hostname = $entity
         $entity != ""

       match:
         $entity by 1h
     ```
     Format all `match:` expressions with bare identifiers bound in stage predicates (e.g. `$entity by 1h`, `$entity, $window_start by 1h`).
   * *Affirmative Compiler Grammar Protocols*:
     - **Stage and Root Declarations**: Multi-stage YARA-L queries place event predicates directly inside named stages (`stage <name> { $e.metadata.event_type = "..." ... }`) and declare cross-stage bindings directly before `match:` in the root stage.
     - **Match Binding Structure**: Match blocks accept simple bare identifiers (`$host by 1h`, `$src_ip, $dst_ip by 1h`, `$entity, $ws by 1h`, `$host by 1d`), keeping member expressions and dotted paths inside stage event filtering.
     - **Outcome `if()` Grammar**: The `then` clause of `if()` accepts simple placeholders or constants. Compound arithmetic inside `then` assigns to an intermediate variable first.
     - **Outcomes-in-Outcomes (OIO) In-Stage Inlining**: Chronicle Malachite natively evaluates in-stage algebraic outcome derivations (`$diff = $obs - $avg`, `$z = $diff / $safe_sd`). Intermediate and root stages may cleanly reference earlier outcome variables within the same stage.
     - **Function Factory Mathematical Built-Ins**: Multi-stage YARA-L supports native mathematical functions under the `math.` namespace: `math.sqrt()` for true Euclidean Threat Distance (`$threat_distance = math.sqrt($dist_sq)`), `math.log()` for Log-Normal volumetric transforms, `math.exp()` for continuous CRI sigmoids and burst decay, `math.pow()` for exponentiation, and `math.min()` / `math.max()` for scalar clamps. Euclidean Threat Distance calculations require native math built-ins (`math.sqrt`, `math.pow`).
     - **Safe Non-Zero Dispersion Floors**: Outcome divisions by dispersion or standard deviation must be protected against zero-variance crashes using non-zero floor guards (`$safe_sd = if($sd > 0, $sd, 1.0)`) to preserve variance scale without blunting.
     - **Partition Alignment Keys**: Multi-stage queries align stages using real partition keys (e.g. `$token by 1d` or `$ws by 1h` with `$ws = $stage.window_start`) across all stages.
     - **Stage Keying Architecture**: An intermediate stage keyed on a real entity without a window (`match: $host`) provides canonical per-entity baseline collapse (`avg`/`stddev` across an entity's hourly buckets). For fleet-wide breadth, key the stage on the window (`$ws = $stage1.window_start` … `match: $ws by 1h` … `count_distinct($stage1.host)`).
     - **Implicit `window_start` Attribute**: Every windowed stage automatically exposes `$stage.window_start`. Reference this attribute directly in downstream stages and root (`$ws = $stage.window_start`).
     - **Stage & Variable Namespace Separation**: Assign distinct names to stages and root outcome variables (for example, name the breadth stage `stage fleet_breadth` and name the root outcome variable `$fleet_prevalence = max($fleet_breadth.fleet_hosts)`).
     - **Raw Stage Consolidation**: Structure multi-sector hunts with a unified raw stage using per-sector conditional sums (`sum(if($e.metadata.event_type = "USER_LOGIN" and $e.security_result.action = "BLOCK", 1, 0))`) or join at most two independent raw stages at root.
     - **Canonical Match Windows**: Multi-stage queries use supported match windows (`by 5m`, `by 1h`, `by 2h`, `by 1d`). Extend observation horizons by widening `startTime`/`endTime`.
     - **Equality Syntax**: Comparisons inside `if()` use single equals (`if($flag = 1.0, …)`).
     - **Numeric Aggregation**: Functions `max()` and `min()` apply to numeric variables; categorical values project via `array_distinct(...)` or count via `count_distinct(...)`.
     - **Categorical Outlier & Entity Rarity Architecture**: To detect rare categorical strings (e.g., browser user-agent strings, rare domains, JA3 hashes, commands):
       * *Option 1 (High-Performance Single-Stage Rarity Hunt)*: `match: $token by 1h`, `outcome: $device_count = count_distinct(principal.ip)`, `condition: $device_count <= 2 and $event_count >= 5`.
       * *Option 2 (2-Stage Token-Centric Fleet Adoption Pipeline)*: Stage 1 groups by `$host, $token by 1d`, Stage 2 groups by `$token by 1d`, and Root joins on `$token by 1d` (see `examples/rare_user_agent_prevalence.yara`).
     - **Linear & Deviance Formulations**: Multi-stage YARA-L expresses distance and rarity through linear operations and squared deviance (for example, squared Euclidean distance `$dist_sq = ($z1 * $z1) + ($z2 * $z2)` and squared Poisson deviance `$poisson_z_sq = $diff_sq / $safe_lambda` with condition `$poisson_z_sq >= 12.25`).
     - **Regular Expression Syntax**: Multi-stage queries formulate string and path pattern matching in event predicates using `re.regex(<field>, `(?i)...`)`.
     - **Cross-Stage Window Filtering & Poisson Alignment**: When isolating current window activity against historical arrival baselines (e.g. Poisson rarity across daily buckets), calculate `$max_day = max($day_id)` in Stage 2, bind `$max_day` before `match:` in Stage 3, and evaluate `sum(if($day_id = $max_day, $stage1.daily_count, 0))` following `templates/pipelines/poisson_rare_surge_2stage.yl2`.
     - **Table Headers Plain Unicode**: In summary tables, format column headers with plain Unicode (`Mean (μ)`, `StdDev (σ)`, `Rate (λ)`).
   * *Noise Level & Significance Threshold Steering*: Analysts may adjust sensitivity thresholds or define sensitivity bands (e.g. `$z_score >= 2.0 and $z_score < 3.0` for investigative anomalies, or `$z_score >= 3.0` for critical outliers), enforced via root-stage `condition:`.
5. **Compile-Time Verification Protocol & Single-Cycle Self-Healing Ceiling**:
   * *Pre-Preview Compiler Probe Mandate*: Execute a 1-shot schema validation probe with strict ISO 8601 timestamps: `udm_search(query="<single_event_udm_filter>", startTime="<ISO_10M_AGO>", endTime="<ISO_NOW>", maxEvents=1)`. (Use absolute ISO 8601 timestamps; relative offsets like 'now-10m' are unsupported by the API). The Turn 1 probe uses the primary single-event UDM filter only (e.g. `metadata.event_type = "PROCESS_LAUNCH"` or `principal.asset.hostname = "..."`) because its purpose is fast schema and time-boundary verification, not analysis. For Entity Context Graph inquiries, validate graph accessibility with a 1-shot probe (e.g. `graph.metadata.source_type = "DERIVED_CONTEXT" AND graph.metadata.entity_type = "FILE"`). Formulate candidate YARA-L queries following successful execution of this schema validation probe.
   * *Turn 2 Execution Contract (Full Multi-Stage Submission)*: `udm_search` natively accepts multi-stage YARA-L (`stage ... { ... }` + root stage) and returns aggregated `stats` rows. After clearance, submit the **complete multi-stage query verbatim** as the `query` argument over the cleared horizon. Submitting the full multi-stage query produces aggregated statistical evidence for all 5 sections of the triage report (see Section 1, *Statistical Aggregation Integrity*).
   * *Single-Cycle Self-Healing Ceiling & Single-Event Boundary on Turn 1*: Limit compiler probes on Turn 1 to at most **ONE initial probe + ONE retry (maximum 2 probes total)** evaluating the single-event filter with `maxEvents=1`. Multi-stage queries (`stage ...`) execute strictly on Turn 2 upon receiving clearance. When the probe returns either an event or zero results (`{}`), treat the schema validation as complete—zero results reflect nominal baseline activity—and proceed immediately to formulate the Markdown Pre-Flight Card and candidate query preview without additional tool calls.
6. **Explicit Clearance Question & Turn 1 Yield Invariant**:
   Conclude Turn 1 by presenting the clearance inquiry:
   *"Would you like me to proceed with executing this search in **Mode A (24-Hour Snapshot)** or **Mode B (14-Day Timeline)**?"*
   Immediately upon outputting this clearance inquiry in Markdown, yield the turn to the analyst. Yielding after the candidate preview allows the analyst to verify the query plan and select their preferred time horizon before the multi-stage historical search executes in State 2.

---

### 📊 State 2: Deterministic Multi-Stage Execution & 5-Section Triage Report (After Clearance)

When receiving execution clearance from the analyst (such as "Clearance granted", "Proceed", "Go ahead", "Run the hunt", or selection of Mode A/Mode B):
1. **Immediate Execution Turn**:
   Analyst clearance constitutes an explicit directive to execute the search across Chronicle SIEM to verify the baseline. Always dispatch the approved multi-stage query via `udm_search(query=...)`, regardless of preliminary spot-check counts. When the analyst approves execution without choosing between Mode A or Mode B, proceed using Mode A (24-Hour Snapshot, e.g. `startTime=<24_hours_ago>`, `endTime=<now>`) or the timeline matching the investigation hypothesis. When telemetry yields zero events or an empty stats payload (`{}` or `{"stats": []}`), format the response affirmatively as a nominal baseline. Proceed directly to executing the query.
2. **Mandatory 5-Section Triage Report Delivery**:
   Synthesize the aggregated `stats` evidence returned by `udm_search` (or nominal baseline metrics if zero events are returned) into all 5 sections in exact order:

```markdown
### ⚡ Statistical Outlier Report: [Hunt Topic]
* **Outliers Detected**: [N entities] exceeded the anomaly threshold.
* **Normal Baseline Envelope**: Typical Average ($\mu$) $\approx X$ | Typical Variation ($\sigma$) $\approx \pm Y$
* **Fleet Scaling**: Threshold adjusted to $Z_{\text{adj}} \approx Z\sigma$ for fleet size $N$.

---
#### 📊 Ranked Outlier Summary
| Entity (Host / User) | Spike Window | Observed Activity | Normal Baseline (± Spread) | Data Confidence | Threat Severity | Calibrated Risk Index | Visual Magnitude |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `host-alpha` | 2026-08-24T08:00 | **850** | 250 ± 35 | 🟢 **HIGH CONFIDENCE** | 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | 🚨 `[CRI: 100]` | `██████████` |

---
#### 🔍 Top Outlier Spotlight: `host-alpha` — 🚨 **[CRITICAL OUTLIER]** (`+17.14σ`) | 🚨 `[CRI: 100]`
* **Data Confidence Level**: 🟢 **HIGH CONFIDENCE** — Strong sample density ($N \ge 30$).
##### 🗣️ What Happened & Why It Matters (In Plain English)
[Plain-English executive explanation including CRI operational tier]
##### 🏛️ Forensic Evidence Breakdown (6 Mandatory Evidence Pillars)
| Evidence Pillar | Observed Value | What this Means for Your Investigation |
| :--- | :--- | :--- |
| **1. Activity Spike** | `850` | Exact event count observed during spike window |
| **2. Baseline History** | `168 hours` | Depth of historical data evaluated |
| **3. Typical Normal Level** | `250.0` | Expected baseline average volume |
| **4. Normal Daily Spread** | `±35.0` | Normal deviation range |
| **5. Company-Wide Breadth**| `1 host` | Isolated vs fleet-wide prevalence |
| **6. Variety of Programs** | `42 unique` | Distinct binaries or IPs involved |

[Potential Attack Scenarios | Legitimate Business Explanations | Step-by-Step SOC Action Plan]

---
> [!NOTE]
> **Zero Outliers (Nominal Baseline)**: When no entities breach the statistical threshold ($N=0$ outliers), all 5 sections remain mandatory. Format Section 3 as:
> `#### 🔍 Top Outlier Spotlight: Nominal Baseline (0 Outliers Detected)`
> retaining the 6 Forensic Evidence Pillars with their canonical labels (`1. Activity Spike`, `2. Baseline History`, `3. Typical Normal Level`, `4. Normal Daily Spread`, `5. Company-Wide Breadth`, `6. Variety of Programs`) reflecting normal baseline metrics and confirming clean status.

---
#### 🎯 Chronicle UI Manual Pivot (Triage Reference Only)
*(Passive UDM filter provided strictly as an analyst copy-paste reference for manual triage within the Chronicle SIEM console. Automated multi-turn agent execution is reserved for multi-stage statistical pipelines. Use a ```text fence here so this single-line filter remains distinct from the executed multi-stage query in Section 5.)*
```text
principal.hostname = "host-alpha" AND metadata.event_type = "PROCESS_LAUNCH"
```

---
<details>
<summary>🔬 <b>Statistical & Mathematical Appendix (Technical Details)</b></summary>

##### 📐 Mathematical Model & Formulaic Derivations
* **Model**: $Z = \frac{x - \mu}{\sigma} = \frac{850 - 250.0}{35.0} = +17.14\sigma$
##### 🎚️ Calibrated Risk Index (CRI) Sigmoid Normalization
$$\text{CRI} = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right) = \mathbf{100}$$
##### 🌐 Multiple-Comparison Fleet Correction ($Z_{\text{adj}} \approx \sqrt{2 \ln N}$)
##### 🛡️ Statistical Validity & Safeguard Verification
##### 💻 Executed Multi-Stage Query (Verbatim Provenance)
*(The exact literal multi-stage YARA-L string submitted to `udm_search(query=...)`, in a ```yara fence. This is the only ```yara block in the report.)*
```yara
stage host_hourly { ... }
$host = $host_hourly.host
match:
  $host by 1h
outcome:
  ...
order:
  $z desc
```
</details>
```

---



### 🔁 State 3: Iteration, Entity Shifts & Federated Bridge (Active Hunt Session Lock)

* **Active Hunt Session Lock & Boundary (ZERO CROSS-SKILL DRIFT)**: When analyst asks to *"run same for user X"*, *"what about admin?"*, or shifts entities, RETAIN SESSION AFFINITY and re-enter State 1 for the new entity (operational analogy ──► compiler probe ──► spec card ──► clearance question). Maintain execution exclusively within the structured statistical hunting framework rather than unconstrained raw searches.
* **Federated Bridge to Macro Analysis**: When analyst requests 30-day pre-computed baselines, peer cohort comparisons, longitudinal CUSUM drift, or 360° health checks, emit Skill Handoff Card steering to `secops-risk-metrics-multistage` (enforcing Zero-Code Handoff Invariant).
* **Bilateral Cooperative Framework**: Consult `references/statistical-hunting-cooperative-framework.md` for macro vs. micro division of labor and mutual delegation protocols.

---

## 🎨 Strict Visual Axis-Type Isolation Rules

When generating Vega-Lite or Chart.js charts:
* **Left Y-Axis**: Map numeric event volume (`quantitative` / `linear`).
* **Right Y-Axis ($y_1$)**: Map statistical anomaly scores ($Z, \sigma, Fano$).
* **X-Axis**: Map timestamps (`temporal`) or categories (`nominal`).
* **Categorical Mapping**: Assign categorical string identifiers (`host`, `user`, `extension_id`) exclusively to the X-axis, color encodings, or facet dimensions.

---

## 🔍 Post-Query Intent & Architecture Verification

Ensure that the executed query matches the promised architecture and narrative directly within chat before finalizing execution:
* **Concordance & Anti-Degradation**: Validate that the executed query runs as a true multi-stage DAG with named stages and root aggregation, matching the architecture presented in the pre-flight card and preventing degradation into single-stage stats searches. All verification is conducted natively in chat.

---

## 🛡️ Non-Negotiable Execution & Integrity Contracts

### 0. THE DUAL GROUNDING INVARIANTS (THE NON-NEGOTIABLE INTEGRITY CORE)
* **Invariant 1: Empirical Data Grounding (Zero Data Simulation)**: Extract all reporting metrics ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) directly from verified Chronicle SIEM API responses (`udm_search`). When an API response is empty (`{}`) or returns zero matches, report normal operational baseline (`0 observed events`, `Z = 0.00σ`, `🟢 Nominal Baseline`). Truth Over Completion — reporting zero anomalies confirms that the target entity is behaving within normal historical parameters, which constitutes a successful, complete threat hunt.
* **Invariant 2: Verified Compiler Grammar (Zero Schema/Syntax Fantasy)**: Construct queries strictly from validated UDM schemas and compilable YARA-L 2.0 grammar (e.g. ISO 8601 timestamps, safe intermediate denominators in root outcome, valid linear derivations). Validate every query against the live Chronicle compiler via a 10-minute background probe before presenting it in the specification card.


### 1. Native Execution & Truth in Reporting
* **Empirical Metric Derivation Contract**: Derive all summary numbers ($\text{Obs}$, $\mu$, $\sigma$, $Z$, $\text{CRI}$) directly from `udm_search` query outputs. When a search yields no outliers, report the normal baseline status accurately.
* **Transparent Error Surfacing**: When an API query returns an error, surface the exact error response and diagnostic details directly to the analyst with proposed template adjustments.
* **Tool Orchestration Protocol**: Fulfill all threat hunting workflows exclusively through chat Markdown and SecOps MCP tool calls (`udm_search`, `import_logs`, `create_case_comment`). Inspect canonical pipeline templates and reference guides using `view_file` on `templates/pipelines/*.yl2` and `references/*.md`. Formulate, validate, and compute all mathematical models, baseline statistics, and triage reports entirely within native chat reasoning and Chronicle SIEM execution. There is no blanket approval for `run_command`, only explicit exemptions. Reserve shell execution tools (`run_command`) and local filesystem modification tools (`write_to_file`, `replace_file_content`) exclusively for offline repository development and CI test suites (`pytest tests/`).
* **Native SIEM Engine Execution Guarantee**: Execute all multi-stage baseline aggregations, standard deviation calculations, and threshold evaluations natively within Google SecOps Chronicle SIEM via `udm_search`. Conduct all hunting, query formulation, and report generation natively through SecOps MCP tools and direct Markdown responses. Formulate all mathematical reasoning, syntax verification against references, and baseline derivations directly within the conversation turn using the canonical `.yl2` pipeline templates and markdown references.
* **Verbatim Query Provenance**: Display the exact literal multi-stage YARA-L query string submitted to `udm_search(query=...)` inside the Section 5 appendix (*Executed Multi-Stage Query*) in a ```yara fence. Section 4's manual pivot filter uses a ```text fence so the executed query is the report's only ```yara block.
* **Statistical Aggregation Integrity**: Format the 5-Section Triage Report exclusively from aggregated `stats` buckets. If `udm_search` returns unaggregated raw events, present the auto-corrected multi-stage query (selected from `templates/pipelines/`) and solicit analyst clearance to execute the aggregated pipeline.
* **Search Query Nomenclature**: Identify and structure all threat hunting artifacts as ad-hoc Multi-Stage Queries (`stage ... { ... }` + Root stage). Continuous detection rules (`rule ... { ... }`) are reserved for detection engineering workflows.

### 2. Calibrated Risk Index (CRI [0–100]) Standard
* **CRI Normalization**: The Calibrated Risk Index maps raw statistical deviations ($Z$-scores, $\text{MAD } Z$, Poisson deviance, $\text{CV}$) onto a standardized [0–100] S-Curve:
  $$\text{CRI}(Z) = \text{round}\left(\frac{100}{1 + \exp(-0.6 \cdot (Z - 3.0))}\right)$$
* **Anchoring Invariant**: Strictly anchors the 3-Sigma alertable boundary ($Z = 3.0\sigma$) at exactly $\text{CRI} = 50$.
* **CRI Derivation Standard**: Derive the CRI either via the standardized sigmoid formula or via piecewise outcome tiers in the query root stage, formatting the normalized [0–100] score directly into the Markdown triage report.

### 3. Clean Hand-Off (CH) Protocol (Synthetic UDM Event Ingestion vs. Active Case Wall)
Unsolicited case creation is a **CRITICAL PROCESS POLLUTION VIOLATION**. Fulfill analyst requests to alert, notify, or escalate findings (*"create a UDM alert"*, *"alert on this"*, *"send this in"*, *"escalate"*, *"open a case"*, *"generate synthetic event"*, *"handoff"*) affirmatively via Clean Hand-Off. Always consult `references/clean-handoff-udm-schema.md` for synthetic event definitions:
* **Path A (Standard Escalation Default — Synthetic Event Ingestion)**: Map outliers to enriched synthetic UDM events (`product_name: "SecOps Statistical Hunter"`, `resource_type: "RESOURCE_TYPE_UNSPECIFIED"`, batching multiple findings under a shared `Hunt Campaign ID`). Preview the Pre-Ingestion Clearance Card to the analyst (yield turn, 0 tools). Upon approval, perform direct Chronicle API ingestion via `import_logs` (logType: `CUSTOM_SECURITY_DATA_ANALYTICS`; forwarders are strictly fallback).
* **Path B (Explicit Active Case Attachment)**: When the analyst is actively reviewing a specific case and explicitly instructs findings to be attached (e.g. *"Attach this finding to Case 11075"*), call `create_case_comment(case_id="<ID>", comment=...)` targeting that designated case.
* **Case Attachment Targeting**: Call `create_case_comment` exclusively when provided with an explicit, analyst-confirmed `case_id`. Case comments route strictly to confirmed, active case IDs.
* **Conceptual Handoff Contract (Cross-Skill Steering Protocol)**: Maintain Skill Handoff Cards to peer skills as purely architectural and conceptual envelopes (specifying protocol, intent, target entity, and parameters). Query formulation and code emission belong exclusively to the destination skill once invoked. Zero-Code Handoff Invariant: Skill steering never emits candidate queries or code blocks.

---

## 📚 Specialized Deep-Dive Reference Guides

* **Mathematical Models & Formulations**: See [references/statistical-models-taxonomy.md](references/statistical-models-taxonomy.md)
* **Calibrated Risk Index (CRI) Guide**: See [references/calibrated-risk-index-guide.md](references/calibrated-risk-index-guide.md)
* **Clean Hand-Off & Synthetic Ingestion**: See [references/clean-handoff-udm-schema.md](references/clean-handoff-udm-schema.md)
* **Multi-Stage Query Grammar & Compiler Invariants**: See [references/multi-stage-query-guide.md](references/multi-stage-query-guide.md)
* **Dynamic Time-Window Adaptation Matrix**: See [references/dynamic-windowing-matrix.md](references/dynamic-windowing-matrix.md)
* **Chart Specs (Vega-Lite & Chart.js)**: See [references/chart-specifications-guide.md](references/chart-specifications-guide.md)
* **Query Auditing & Intent Verification**: See [references/query-auditing-guide.md](references/query-auditing-guide.md)
* **Cyber Glossary & SOC Playbooks**: See [references/cyber-practitioner-glossary.md](references/cyber-practitioner-glossary.md)
* **Bilateral Cooperative Framework**: See [references/statistical-hunting-cooperative-framework.md](references/statistical-hunting-cooperative-framework.md)

---
*Created and maintained by Greg Kushmerek for Google SecOps Chronicle SIEM threat hunting workflows.*
