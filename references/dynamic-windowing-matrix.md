<!-- AUTO-GENERATED FROM scripts/multistage_query_builder.py. DO NOT EDIT MANUALLY. -->

# Dynamic Windowing & Adaptation Matrix

This matrix defines adaptive bucket granularity and proportional sample floors across search durations, supporting both the **Micro Temporal Spine** (`10m`, `15m`, `1h`) and the **Daily Macro Spine** (`1d`).

### 1. Dual Temporal Spines Architecture
| Horizon | Target Use Case | Recommended Bucket | Sample Floor | Temporal Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Short Horizon (6h – 72h)** | Intra-day bursts, C2 beaconing jitter, password sprays | `10m`, `15m`, `1h` | 9 to 24 samples | Micro-analysis of sub-daily timing variance |
| **Multi-Day Horizon (7d – 30d)** | Multi-sector threat fusion, volume surges, dormant awakening | `1d` | 3 to 12 samples | **1:1 reconciliation with `secops-risk-metrics-multistage`** |
| **High-Frequency Multi-Day (7d – 14d)** | Multi-day beaconing persistence with sleep jitter | `1h` | 42 to 60 samples | Preserves hourly resolution across weeks |

### 2. Proportional Duration Matrix
| Duration | Micro Bucket | Daily Macro Bucket | Proportional Sample Floor | Total Horizon |
| :--- | :--- | :--- | :--- | :--- |
| **6 Hours (Near-Real-Time)** | `10m` | *N/A (Intra-day)* | `7` samples | `6h` |
| **12 Hours (Half-Day Shift)** | `10m` | *N/A (Intra-day)* | `7` samples | `12h` |
| **24 Hours (Daily Rolling)** | `15m` | *N/A (Intra-day)* | `7` samples | `24h` |
| **72 Hours (Weekend Burst)** | `1h` | *N/A (Intra-day)* | `7` samples | `72h` |
| **7 Days (Weekly Horizon)** | `1h` | `1d` | `3` samples | `168h` |
| **14 Days (Bi-Weekly Horizon)** | `1h` | `1d` | `5` samples | `336h` |
| **30 Days (Monthly Baseline)** | `1h` | `1d` | `7` samples | `720h` |

---
*Maintained by Greg Kushmerek. Single source of truth: `scripts/multistage_query_builder.py`.*
