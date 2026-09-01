# Post-Query Intent & Execution Audit Guide

This guide describes how to verify that executed YARA-L threat hunting queries match the architectural intent promised to the user.

---

## 1. Intent vs. Architecture Mapping

| Planned Investigation Type | Required Architecture | Intermediate Stages | Total Stages |
| :--- | :--- | :---: | :---: |
| **Macro Volume Baseline (30–90d)** | `SINGLE_STAGE_MACRO` | 0 | 1 |
| **Intraday Local Outlier Hunt (12–48h)** | `LOCAL_2STAGE` | 1 | 2 |
| **Historical Baseline Standardization** | `3STAGE_DAG` | 2 | 3 |
| **Dual-Baseline Delta-$Z$ (Patch Tuesday)** | `DUAL_BASELINE_3STAGE` / `4STAGE_DAG` | 2–3 | 3–4 |
| **Poisson-Gamma Bayesian Shrinkage** | `BAYESIAN_GAMMA_4STAGE` | 3 | 4 |
| **Beta-Binomial Ratio Regularization** | `BETA_BINOMIAL_4STAGE` | 3 | 4 |
| **Multi-Sector Threat Fusion** | `MULTI_SECTOR_FUSION_4STAGE` | 3 | 4 |

---

## 2. Automated CLI Verification

To audit a query file against promised architecture:

```bash
python3 scripts/multistage_query_builder.py \
  --query_file hunt_query.yara \
  --audit_intent DUAL_BASELINE_3STAGE \
  --audit_model DELTA_Z
```

### Output Status Codes:
* `PASS`: Query AST topology, variable operations, and condition safeguards fully match.
* `MISMATCH`: Query executed wrong stage depth or omitted required mathematical signatures.
* `GUARDRAIL_VIOLATION`: Query lacks small-sample floor ($N \ge 12$) or non-zero dispersion gating ($\sigma > 0$).

---

## 3. Post-Flight API Response Payload Auditing

To ensure that the SecOps backend executed the mathematical aggregation on the cluster and did not emit an un-aggregated raw log dump:

```bash
python3 scripts/multistage_query_builder.py \
  --query_file hunt_query.yara \
  --audit_response api_response.json \
  --audit_intent MULTI_SECTOR_FUSION_4STAGE \
  --audit_model FUSION
```

### Invariant Checks:
1. **`RAW_LOG_DUMP_DETECTED`**: Emits violation if the API returned `"events"` instead of compiled `"stats"`. All multi-stage math must run inside Chronicle's F1 engine.
2. **Multi-Vector Isolation**: Flags any attempt to cram cross-domain telemetry silos (Auth + Process + Network) into a single unseparated stage.
3. **ECG Limit Invariant**: Enforces a maximum of 1 Entity Context Graph lookup per stage to prevent F1 memory exhaustion.
4. **Token-Level Math Traps**: Rejects invalid YARA-L tokens such as `^` (exponent), `by 24h` (requires `by 1d`), `in ("A", "B")` (requires disjunctions), and `stage $name` (`$` prefix).
