# Strict UI Charting & Axis Isolation Specifications

This guide establishes the mandatory visual design patterns, data schemas, and axis-type isolation rules for statistical threat hunting reports across both Vega-Lite and Chart.js environments.

---

## 1. Strict Axis-Type Isolation Invariants

To avoid rendering errors where categorical strings collide with numeric quantities:
* **Left Y-Axis**: Reserved strictly for linear event volume (`quantitative` in Vega-Lite / `type: "linear"` in Chart.js).
* **Right Y-Axis ($y_1$)**: Reserved strictly for statistical anomaly scores ($\sigma$, $Z$, Fano factor, Delta-$Z$, Bayesian ratio).
* **X-Axis**: Strictly temporal timestamps (`temporal` / `type: "time"`) or categorical entities (`nominal` / `type: "category"`).
* **Rule**: NEVER place string identifiers (`host`, `user`, `extension_id`, `process_path`) on any Y-axis.

---

## 2. Copy-Pasteable Vega-Lite Dual-Y Template

```json
{
  "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
  "description": "Dual-Y Statistical Outlier Hunt (Volume vs Anomaly Score)",
  "data": {
    "values": [
      {"time": "2026-08-24T00:00:00Z", "volume": 120, "score": 1.2},
      {"time": "2026-08-24T01:00:00Z", "volume": 850, "score": 8.4}
    ]
  },
  "resolve": {"scale": {"y": "independent"}},
  "layer": [
    {
      "mark": {"type": "bar", "color": "#76c0f8", "opacity": 0.65},
      "encoding": {
        "x": {"field": "time", "type": "temporal", "title": "Time (UTC)"},
        "y": {"field": "volume", "type": "quantitative", "title": "Observed Volume"}
      }
    },
    {
      "mark": {"type": "line", "color": "#d93025", "size": 2.5},
      "encoding": {
        "x": {"field": "time", "type": "temporal"},
        "y": {
          "field": "score",
          "type": "quantitative",
          "title": "Anomaly Score (Z-Score σ)",
          "axis": {"orient": "right"}
        }
      }
    },
    {
      "mark": {"type": "rule", "color": "#d93025", "strokeDash": [4, 4]},
      "encoding": {
        "y": {"datum": 3.0, "type": "quantitative", "axis": {"orient": "right"}}
      }
    }
  ]
}
```

---

## 3. Copy-Pasteable Chart.js Template

```json
{
  "type": "bar",
  "data": {
    "labels": ["2026-08-24T00:00", "2026-08-24T01:00"],
    "datasets": [
      {
        "type": "bar",
        "label": "Event Volume",
        "data": [120, 850],
        "yAxisID": "y",
        "backgroundColor": "rgba(118, 192, 248, 0.65)"
      },
      {
        "type": "line",
        "label": "Statistical Score (Z)",
        "data": [1.2, 8.4],
        "yAxisID": "y1",
        "borderColor": "rgba(217, 48, 37, 1.0)",
        "tension": 0.1
      }
    ]
  },
  "options": {
    "responsive": true,
    "scales": {
      "x": {"title": {"display": true, "text": "Time Window (UTC)"}},
      "y": {"type": "linear", "position": "left", "title": {"display": true, "text": "Event Volume"}},
      "y1": {"type": "linear", "position": "right", "grid": {"drawOnChartArea": false}, "title": {"display": true, "text": "Anomaly Score (σ)"}}
    }
  }
}
```
