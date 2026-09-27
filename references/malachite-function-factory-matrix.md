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
| **`math.pow`** | `math.pow(base, exp)` | ❌ | ✅ | Native exponentiation ($x^y$). Replaces manual `$stddev * $stddev`. The `^` operator is invalid in YARA-L. |
| **`math.abs`** | `math.abs(number)` | ❌ | ✅ | Computes absolute value $\|x\|$. Essential for symmetric distance and deviation metrics. |
| **`math.log`** | `math.log(number)` | ❌ | ✅ | Computes natural logarithm $\ln(x)$. Requires $x > 0$. Unlocks Log-Normal volumetric surge detection. |
| **`math.exp`** | `math.exp(number)` | ❌ | ✅ | Computes $e^x$. Enables continuous sigmoid CRI normalization and exponential burst decay. |
| **`math.floor`** | `math.floor(number)` | ❌ | ✅ | Floor function $\lfloor x \rfloor$. |
| **`math.ceil`** | `math.ceil(number)` | ❌ | ✅ | Ceiling function $\lceil x \rceil$. |
| **`math.round`** | `math.round(number, [scale])` | ❌ | ✅ | 1-arg rounds to integer; 2-arg rounds to specified decimal scale (e.g. `math.round($z, 2)`). |
| **`math.min`** | `math.min(num1, num2)` | ❌ | ✅ | 2-arg scalar min. Clamps values to upper boundaries. |
| **`math.max`** | `math.max(num1, num2)` | ❌ | ✅ | 2-arg scalar max. Clamps values to lower boundaries. |
| **`window.variance`**| `window.variance(event_field)` | ❌ | ✅ | Computes sample variance across matched window events. Bare `variance()` is rejected. |
| **`cast.as_int`** | `cast.as_int(number\|string)` | ✅ | ✅ | Casts numeric float or string timestamp to integer (e.g. `cast.as_int(ts / 86400)`). |
| **`cast.as_float`** | `cast.as_float(string)` | ✅ | ✅ | Parses string representation into float. Expects type `string` (fails if passed `int`). |
| **`arrays.max/min`**| `arrays.max(array)` | ❌ | ❌ (Literals) | Literal array notation `[...]` in `outcome:` causes compiler syntax error. |

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
  * String functions: `strings.to_lower()`, `strings.concat()`, `re.regex()`.
  * IP range functions: `net.ip_in_range_cidr()`.
* **Prohibited**:
  * Binary variable-to-variable arithmetic (`$a - $b`, `$a / $b`) above `match:`. All placeholder arithmetic must occur in `outcome:`.
  * Aggregation functions (`count`, `max`, `sum`, `avg`, `window.variance`).

### B. Outcome Section (`outcome:`)
* **Allowed**:
  * Variable-to-variable arithmetic, subtraction, multiplication, and division.
  * Function Factory mathematical operations (`math.pow`, `math.sqrt`, `math.abs`, `math.log`, `math.exp`, `math.floor`, `math.ceil`, `math.round`, `math.min`, `math.max`).
  * In-stage Outcomes-in-Outcomes derivations.
  * Conditional assignments: `if(condition, then_val, else_val)`.
* **Prohibited**:
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

### 2. Micro Temporal Spine (`10m`, `15m`, `1h`)
* **Horizon**: 6 hours to 72 hours.
* **Match Key**: `$src_ip, $dst_ip by 10m` or `$host by 1h`.
* **Benefits**:
  - Uncovers sub-daily timing variance, C2 sleep jitter ($CV \le 0.20$), and clustered Poisson brute force waves ($F > 4.0$).
