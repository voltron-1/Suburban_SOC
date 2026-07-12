#!/usr/bin/env python3
"""
Audit-write failure visibility tests (issue #184).

write_audit()'s ES write failures must never propagate (auditing must not break
alert handling) — but a failure now also writes a best-effort marker doc to
soc-agent-health-<tenant> so a SUSTAINED run of failures is dashboard-visible
(via slo_metrics.py's metric_audit_write_failures()), not just a log line.

Run:  pytest tests/ai_agent/test_audit_write_health.py
"""

import os
import sys
import types
import unittest
from unittest import mock

os.environ["SOC_AGENT_HMAC_SECRET"] = "unit_test_secret"

_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}  # type: ignore[attr-defined]
sys.modules["weekly_ciso_report"] = _stub

import agent_app  # noqa: E402


class WriteAuditHealthMarkerTests(unittest.TestCase):
    def test_health_marker_written_on_audit_write_failure(self):
        with mock.patch.object(agent_app.requests, "post",
                               side_effect=ConnectionError("refused")) as m:
            agent_app.write_audit("quarantine_mac", "system", "acme-corp",
                                   outcome="success", target="AA:BB:CC:DD:EE:FF")
        # Two POST attempts: the original audit write, then the health marker.
        self.assertEqual(m.call_count, 2)
        marker_args, marker_kwargs = m.call_args_list[1]
        self.assertEqual(marker_args[0],
                         f"{agent_app.ES_HOST}/soc-agent-health-acme-corp/_bulk")
        self.assertIn('"event.action": "audit_write_failed"', marker_kwargs["data"])
        self.assertIn('"target_action": "quarantine_mac"', marker_kwargs["data"])
        self.assertIn('"tenant.id": "acme-corp"', marker_kwargs["data"])

    def test_write_audit_never_raises_even_if_health_marker_also_fails(self):
        # Core acceptance criterion: BOTH writes failing must not raise.
        with mock.patch.object(agent_app.requests, "post",
                               side_effect=ConnectionError("refused")):
            try:
                agent_app.write_audit("quarantine_mac", "system", "acme-corp")
            except Exception as e:
                self.fail(f"write_audit() raised unexpectedly: {e}")

    def test_health_marker_not_written_on_audit_write_success(self):
        with mock.patch.object(agent_app.requests, "post") as m:
            agent_app.write_audit("quarantine_mac", "system", "acme-corp")
        # Only the original audit write — no marker needed when it succeeds.
        self.assertEqual(m.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
