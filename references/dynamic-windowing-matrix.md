<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->

# Dynamic Windowing & Adaptation Matrix

This matrix defines adaptive bucket granularity and proportional sample floors across search durations.

| Duration | Bucket Size | Minimum Sample Floor | Proportional Horizon |
| :--- | :--- | :--- | :--- |
| **6 Hours (Near-Real-Time)** | `10m` | `9` samples | `6h` |
| **12 Hours (Half-Day Shift)** | `10m` | `18` samples | `12h` |
| **24 Hours (Daily Rolling)** | `15m` | `24` samples | `24h` |
| **72 Hours (Weekend Burst)** | `1h` | `18` samples | `72h` |
| **7 Days (Weekly Horizon)** | `1h` | `42` samples | `168h` |
| **14 Days (Bi-Weekly Horizon)** | `1h` | `60` samples | `336h` |
| **30 Days (Monthly Baseline)** | `1h` | `60` samples | `720h` |

---
*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*
