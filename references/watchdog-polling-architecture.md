# Asynchronous LRO Watchdog & Polling Architecture

Because 30-day multi-stage YARA-L queries over raw UDM telemetry can run for several minutes, **synchronous blocking loops (`while not done: sleep(15)`) are strictly prohibited** in tool implementations. Blocking loops tie up the LLM agent's context window, consume idle compute, and frequently trigger RPC tool timeouts.

---

## 1. Non-Blocking Reactive Wakeup Pattern

Agents implementing `secops-statistical-hunter` must use Jetski's **`schedule`** tool to monitor long-running operations (`projects/.../operations/s-...`).

### Sequence Diagram

```
[Agent]                        [udm_search Tool]            [schedule Tool]
   │                                   │                           │
   │ 1. udm_search(query, async=True)  │                           │
   ├──────────────────────────────────►│                           │
   │ 2. Returns operation_id           │                           │
   │◄──────────────────────────────────┤                           │
   │                                   │                           │
   │ 3. schedule(DurationSeconds=30, Prompt="Check s-12345")       │
   ├──────────────────────────────────────────────────────────────►│
   │ 4. Agent stops calling tools (Turn Ends / Zero Compute)       │
   │                                                               │
   │ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 30 SECONDS ELAPSE ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ │
   │                                                               │
   │ 5. Reactive Wakeup Message: "Check s-12345"                   │
   │◄──────────────────────────────────────────────────────────────┤
   │ 6. get_operation(name="operations/s-12345")                   │
   ├──────────────────────────────────►│                           │
   │ 7. Returns status (RUNNING vs DONE)                           │
   │◄──────────────────────────────────┤                           │
```

---

## 2. Stall Diagnosis & Health Watchdog

When `get_operation` returns `done == false`, the watchdog inspects the operation metadata to detect whether the query is making progress or wedged:

### A. Frozen Progress Delta
* Most Chronicle search operations return progress counters (`events_searched`).
* **Watchdog Rule**: Compare `events_searched` at Poll $T_k$ against Poll $T_{k-1}$.
* If `events_searched` is $> 0$ and increasing, the query is healthy.
* If `events_searched` remains frozen across two polls separated by $\ge 60$ seconds, the query is **STALLED**.

### B. Concurrency Starvation (`CONCURRENT_SEARCHES` Quota)
* If status indicates `QUEUED` for $> 120$ seconds, the customer's instance has reached its concurrent heavy-search limit.
* Prompt the analyst to either wait or cancel an older search.

---

## 3. Prescriptive Query Refactoring Advice (When Stalled)

If a query stalls or times out after 10 minutes, the agent must offer concrete SQL/F1 optimization advice:

1. **Split the Window**: Reduce `30 DAY` to two `15 DAY` chunks.
2. **Remove Leading Wildcard Regexes**: Avoid `re.regex($field, r".*beacon.*")` inside stage 1. Use exact string matches or prefix filters (`strings.starts_with`).
3. **Add High-Selectivity Pre-Filters**: Always constrain `metadata.event_type` and `principal.asset.ip` before performing `group(...)` or multi-stage joins.
