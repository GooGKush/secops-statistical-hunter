# Malachite Function Factory Compiler Reference Matrix

**Skill:** `secops-statistical-hunter`  
**Target:** Google SecOps Malachite Common Compiler (YARA-L 2.0 / Stats Search over Raw `UDM_EVENTS`)

---

## 1. Overview & Compiler Governance

The Chronicle Malachite Common Compiler features a standard library ("Function Factory") of built-in scalar, mathematical, and window aggregation functions.
Understanding section boundaries (`events:` vs `outcome:`), function signatures, and Outcomes-in-Outcomes (OIO) is essential for writing high-performance, valid multi-stage statistical hunting queries over raw UDM event telemetry.

---

## 2. Function Support & Section Validity Matrix

| Function Namespace | Function Signature | Valid in `events:` | Valid in `outcome:` | Notes / Invariants |
| :--- | :--- | :---: | :---: | :--- |
| **`math.sqrt`** | `math.sqrt(number)` | ❌ | ✅ | Computes $\sqrt{x}$. Bare `sqrt()` is strictly rejected. Ideal for true Euclidean Threat Distance ($D$). |
| **`math.pow`** | `math.pow(base, exp)` | ❌ | ✅ | Native exponentiation ($x^y$). Use `math.pow(2.718281828, x)` for $e^x$. The `^` operator is invalid in YARA-L. |
| **`math.abs`** | `math.abs(number)` | ✅ | ✅ | Computes absolute value $\|x\|$. Essential for symmetric distance and deviation metrics. |
| **`math.log`** | `math.log(number)` | ✅ | ✅ | Computes natural logarithm $\ln(x)$. Requires $x > 0$. Unlocks Log-Normal volumetric surge detection. |
| **`math.floor`** | `math.floor(number)` | ❌ | ✅ | Floor function $\lfloor x \rfloor$. |
| **`math.ceil`** | `math.ceil(number)` | ❌ | ✅ | Ceiling function $\lceil x \rceil$. |
| **`math.round`** | `math.round(number, [scale])` | ❌ | ✅ | 1-arg rounds to integer; 2-arg rounds to specified decimal scale (e.g. `math.round($z, 2)`). |
| **`math.geo_distance`** | `math.geo_distance(lon1, lat1, lon2, lat2)` | ✅ | ✅ | Computes Haversine geodesic distance in meters between coordinate pairs. |
| **`window.variance`**| `window.variance(event_field)` | ❌ | ✅ | Computes sample variance across matched window events. Bare `variance()` is rejected. |
| **`cast.as_int`** | `cast.as_int(number\|string)` | ✅ | ✅ | Casts numeric float or string timestamp to integer (e.g. `cast.as_int(ts / 86400)`). |
| **`cast.as_float`** | `cast.as_float(string)` | ✅ | ✅ | Parses string representation into float. Expects type `string` (fails if passed `int`). |

### Unsupported / Forbidden Function Hallucinations

| Forbidden Syntax | Compiler Status | Valid YARA-L 2.0 Replacement |
| :--- | :---: | :--- |
| **`math.exp(x)`** | ❌ Rejected (`invalid function`) | Use `math.pow(2.718281828, x)` |
| **`math.min(a, b)`** | ❌ Rejected (`invalid function`) | Use 3-arg conditional `if($a < $b, $a, $b)` |
| **`math.max(a, b)`** | ❌ Rejected (`invalid function`) | Use 3-arg conditional `if($a > $b, $a, $b)` |
| **`arrays.max([...])` / `arrays.min([...])`** | ❌ Rejected (`syntax error`) | Literal array notation `[...]` in `outcome:` causes compiler syntax error; use `if($a > $b, $a, $b)` |

---

## 3. Outcomes-in-Outcomes (OIO) In-Stage Dependency Rules

Chronicle Malachite natively supports `UsesOutcomesInOutcomes` via compile-time **AST Expression Inlining** (`substituteOutcomeVarsInAssignments`). Intermediate and root stages may cleanly reference earlier outcome variables within the same stage:

```yara
outcome:
  $obs = count(metadata.id)
  $mean = avg($stage1.hourly_count)
  $raw_sd = stddev($stage1.hourly_count)
  $safe_sd = if($raw_sd > 0, $raw_sd, 1.0)

  // Clean OIO in-stage derivation (replaces verbose repeated formulas):
  $diff = $obs - $mean
  $z_score = $diff / $safe_sd
  $threat_norm_sq = $z_score * $z_score
  $threat_distance = math.sqrt($threat_norm_sq)
```

### OIO Safety Invariants
1. **Definition-Before-Reference**: An outcome variable must be defined on an earlier line before it is referenced.
2. **Acyclic Dependency Graph**: Cyclical dependencies between outcomes cause compiler rejection.
3. **No Nested Aggregations on Outcomes**: Aggregations like `max($z_score)` within the same stage are prohibited; aggregations operate only on event attributes or upstream stage variables.

---

## 4. Section Boundary Constraints

### A. Event Sections (Above `match:`)
* **Allowed**:
  * Bound scalar functions:
    ```yara
    $day_id = cast.as_int(metadata.event_timestamp.seconds / 86400)
    ```
  * Mathematical functions valid in `events:`: `math.abs()`, `math.log()`, `math.geo_distance()`.
  * String functions: `strings.to_lower()`, `strings.concat()`, `re.regex()`.
  * IP range functions: `net.ip_in_range_cidr()`.
* **Prohibited**:
  * Binary variable-to-variable arithmetic (`$a - $b`, `$a / $b`) above `match:`. All placeholder arithmetic must occur in `outcome:`.
  * Aggregation functions (`count`, `max`, `sum`, `avg`, `window.variance`).

### B. Outcome Section (`outcome:`)
* **Allowed**:
  * Variable-to-variable arithmetic, subtraction, multiplication, and division.
  * Function Factory mathematical operations (`math.pow`, `math.sqrt`, `math.abs`, `math.log`, `math.floor`, `math.ceil`, `math.round`, `math.geo_distance`).
  * In-stage Outcomes-in-Outcomes derivations.
  * Conditional assignments: `if(condition, then_val, else_val)` (use 3-arg `if($a > $b, $a, $b)` instead of non-existent `math.max` / `math.min`, and `math.pow(2.718281828, $x)` instead of non-existent `math.exp`).
* **Prohibited**:
  * **Non-Existent Math Functions**: `math.exp()`, `math.min()`, `math.max()` are rejected by the Malachite compiler.
  * **Literal Array Notation**: `arrays.max([0.0, $val])` or any `[...]` literal syntax in `outcome:` fails compiler parsing.
  * **Compound Arithmetic in `then` Clause**: `if(cond, $a - $b, 0)` is invalid; must compute `$diff = $a - $b` and use `if(cond, $diff, 0)`.
  * **Unaggregated Event Attributes in Match Windows**: When a match window is declared (`by 1h`, `by 1d`), all raw event attributes in `outcome:` must use an aggregation function (`max()`, `min()`, `array_distinct()`, `count()`).

---

## 5. Dual Temporal Spines Architecture

`secops-statistical-hunter` supports two complementary temporal spines for grouping events:

### 1. Daily Temporal Spine (`by 1d`)
* **Horizon**: 7 days to 30 days (`startTime` / `endTime`).
* **Match Key**: `$host by 1d` or `$user, $ws by 1d`.
* **Benefits**:
  - **1:1 Reconciliation with `secops-risk-metrics-multistage`**: Daily raw sums match macro 30-day baseline daily metrics.
  - **24× Row Reduction**: Compresses 720 hourly buckets down to 30 daily buckets, eliminating timeouts and memory exhaustion on high-volume logs (`NETWORK_CONNECTION`).

### 2. Micro Temporal Spine (`by 5m`, `by 1h`, `by 2h`)
* **Horizon**: 6 hours to 72 hours.
* **Match Key**: `$src_ip, $dst_ip by 5m` or `$host by 1h`.
* **Benefits**:
  - Uncovers sub-daily timing variance, C2 sleep jitter ($CV \le 0.20$), and clustered Poisson brute force waves ($F > 4.0$).
