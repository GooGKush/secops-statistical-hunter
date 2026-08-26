# Dynamic Time-Window Protocol & Adaptive Granularity Matrix

This reference documents the adaptive bucket sizing and proportional sample density formulas used to configure YARA-L statistical hunts across varying search window durations.

---

## 1. Adaptive Granularity Matrix

| Search Window Duration | Recommended Bucket Size | Total Available Buckets ($K$) | Sample Floor ($N_{\min}$) | Model Fitness / Cautions |
| :--- | :---: | :---: | :---: | :--- |
| **$\le 12$ Hours** | `by 10m` | 72 intervals | $\ge 12$ intervals | Perfect for intraday burst/clustering hunts. |
| **$12$ to $24$ Hours** | `by 15m` | 48–96 intervals | $\ge 24$ intervals | Standard single-day anomaly hunting baseline. |
| **$24$ to $48$ Hours** | `by 1h` | 24–48 intervals | $\ge 12$ intervals | Short multi-day surge hunts. |
| **$3$ to $7$ Days** | `by 1h` | 72–168 intervals | $\ge 42$ intervals | Multi-day historical standardization ($Z$-Score). |
| **$7$ to $30$ Days** | `by 1h` or `by 1d` | 168–720 intervals | $\ge 60$ intervals | Max supported duration for multi-stage pipelines. |
| **$> 30$ to $90$ Days** | `match: $entity` | Single window | Unwindowed | **Single-Stage Macro Searches Only** (no `stage` blocks). |

---

## 2. Window-Sample Mismatch Safeguards

```
Search Window (Hours) < Sample Floor ($baseline_active_samples) ===> AUTOMATIC QUERY FAILURE (0 Results)
```

The pre-execution compiler checks that:
$$\text{Sample Floor Condition} \le \text{Total Available Time Intervals in Window}$$
