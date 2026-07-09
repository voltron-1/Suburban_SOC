#!/usr/bin/env python3
"""
SLO metrics — measurement-error visibility tests (audit #165 / NIST SI-11).

slo_metrics.py must distinguish "ES/Kibana unreachable" from "genuinely no
data this window": a down dependency must always surface as an error/breach,
never silently collapse into a healthy-looking None/0 reading.

Run:  python tests/ai_agent/test_slo_metrics.py     (or: pytest tests/ai_agent)
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

# ES_PASS is read at import time; must be truthy or main() exits(1) immediately.
os.environ["ES_PASS"] = "unit_test_pass"

AGENT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "setup" / "ai_agent"
sys.path.insert(0, str(AGENT_DIR))

import slo_metrics  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class MetricFunctionTests(unittest.TestCase):
    """Each metric must raise MetricUnavailable on a real failure, but still
    return the same legitimate value (None/0) as before on genuine no-data."""

    def test_count_raises_on_request_exception(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._count("logstash-security-*", {"match_all": {}})

    def test_count_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._count("logstash-security-*", {"match_all": {}})

    def test_count_returns_real_zero_when_es_is_healthy(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics._count("logstash-security-*", {"match_all": {}}), 0)

    def test_mttd_raises_on_request_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=TimeoutError("timed out")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_mttd()

    def test_mttd_returns_none_on_genuinely_empty_window(self):
        # Regression guard: a healthy ES with zero alerts must NOT be treated
        # as a measurement error — that would be a false alarm.
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertIsNone(slo_metrics.metric_mttd())

    def test_mttr_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(500)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_mttr()

    def test_mttr_returns_none_on_empty_aggregation(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"aggregations": {"avg_lat": {}}})):
            self.assertIsNone(slo_metrics.metric_mttr())

    def test_coverage_raises_on_missing_file(self):
        with mock.patch.object(slo_metrics, "REPO", Path("/nonexistent-path-for-test")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_coverage()

    def test_false_positive_pct_raises_on_kibana_failure(self):
        with mock.patch.object(slo_metrics, "kb", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_false_positive_pct()

    def test_ingest_lag_raises_on_request_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_ingest_lag_seconds()

    def test_ingest_lag_returns_none_when_no_docs_yet(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertIsNone(slo_metrics.metric_ingest_lag_seconds())

    def test_parse_error_pct_propagates_count_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_parse_error_pct()


class MainExitCodeTests(unittest.TestCase):
    """End-to-end: main() must exit 3 (not the routine breach code 2) when a
    metric could not be measured, and must still behave exactly as before for
    a genuinely healthy, quiet system."""

    def _run_main_capturing_exit(self):
        try:
            slo_metrics.main()
        except SystemExit as e:
            return e.code
        return None

    def test_total_es_outage_exits_3_not_2(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")), \
             mock.patch.object(slo_metrics, "kb", side_effect=ConnectionError("refused")), \
             mock.patch.object(slo_metrics, "metric_coverage",
                               side_effect=slo_metrics.MetricUnavailable("no file")), \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)

    def test_healthy_quiet_system_exits_0(self):
        # Fresh ingest doc (healthy pipeline) but otherwise empty windows —
        # the pre-#165 baseline behavior for a quiet, working SOC.
        import datetime as _dt
        now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")

        def fake_es(method, path, body=None):
            if path == "/logstash-security-*/_search":
                return _FakeResponse(200, {"hits": {"hits": [{"_source": {"@timestamp": now_iso}}]}})
            return _FakeResponse(200, {"hits": {"hits": []}, "aggregations": {"avg_lat": {}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es), \
             mock.patch.object(slo_metrics, "kb", return_value=_FakeResponse(200, {"total": 0})), \
             mock.patch.object(slo_metrics, "metric_coverage", return_value=12.0), \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
