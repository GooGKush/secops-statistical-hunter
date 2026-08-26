"""Unit tests for UI Charting & Strict Axis-Type Isolation."""

import os
import unittest
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from multistage_query_builder import generate_chart_spec, generate_chartjs_spec


class TestChartSpecifications(unittest.TestCase):

  def setUp(self):
    self.sample_payload = {
        "stats": {
            "results": [
                {
                    "column": "host",
                    "values": [{"value": {"stringVal": "172.16.2.6"}}, {"value": {"stringVal": "172.16.5.82"}}]
                },
                {
                    "column": "TIME_BUCKET",
                    "values": [{"value": {"stringVal": "2026-08-24T16:00:00Z"}}, {"value": {"stringVal": "2026-08-24T16:00:00Z"}}]
                },
                {
                    "column": "observation_count",
                    "values": [{"value": {"int64Val": 99}}, {"value": {"int64Val": 30}}]
                },
                {
                    "column": "z_score",
                    "values": [{"value": {"doubleVal": 6.10}}, {"value": {"doubleVal": 1.41}}]
                }
            ]
        }
    }

  def test_dual_y_timeseries_spec(self):
    vega_spec = generate_chart_spec(self.sample_payload, plot_type="DUAL_Y_TIMESERIES")

    self.assertEqual(vega_spec["resolve"]["scale"]["y"], "independent", "Must resolve independent Y scales")
    self.assertEqual(len(vega_spec["layer"]), 3, "Should have Volume bar, Z-score line, and Threshold rule")

    # Layer 0: Bar Mark (Volume)
    bar_layer = vega_spec["layer"][0]
    self.assertEqual(bar_layer["encoding"]["x"]["type"], "temporal")
    self.assertEqual(bar_layer["encoding"]["y"]["type"], "quantitative")

    # Layer 1: Line Mark (Z-Score)
    line_layer = vega_spec["layer"][1]
    self.assertEqual(line_layer["encoding"]["y"]["axis"]["orient"], "right", "Z-Score must be oriented on right axis")
    self.assertEqual(line_layer["encoding"]["y"]["type"], "quantitative")

  def test_categorical_bar_spec_axis_isolation(self):
    cat_payload = {
        "stats": {
            "results": [
                {
                    "column": "extension_id",
                    "values": [{"value": {"stringVal": "mmfbcljfglbok..."}}, {"value": {"stringVal": "cnbggqchhmkk..."}}]
                },
                {
                    "column": "event_count",
                    "values": [{"value": {"int64Val": 14}}, {"value": {"int64Val": 10}}]
                }
            ]
        }
    }
    # Vega-Lite Bar Chart
    vega_cat = generate_chart_spec(cat_payload, plot_type="CATEGORICAL_BAR")
    self.assertEqual(vega_cat["encoding"]["x"]["type"], "nominal", "Entity identifier must be on X-axis (nominal)")
    self.assertEqual(vega_cat["encoding"]["y"]["type"], "quantitative", "Y-axis must be purely quantitative")

    # Chart.js Bar Chart
    chartjs_cat = generate_chartjs_spec(cat_payload, plot_type="CATEGORICAL_BAR")
    self.assertEqual(chartjs_cat["type"], "bar")
    self.assertEqual(chartjs_cat["data"]["labels"], ["mmfbcljfglbok...", "cnbggqchhmkk..."])
    self.assertEqual(chartjs_cat["data"]["datasets"][0]["data"], [14.0, 10.0])
    self.assertEqual(chartjs_cat["options"]["scales"]["y"]["type"], "linear", "Chart.js Y-axis must be linear numeric")


if __name__ == "__main__":
  unittest.main()
