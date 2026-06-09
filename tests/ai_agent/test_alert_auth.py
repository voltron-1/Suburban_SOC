#!/usr/bin/env python3
"""
WS0.2 — webhook authentication & input-validation tests for the SOC AI agent.

Asserts that the /alert endpoint:
  * rejects requests with a missing or invalid HMAC signature (401) and never
    invokes isolate.sh;
  * quarantines only when a valid signature AND a format-valid MAC are present;
  * never passes an invalid/malicious MAC to the isolate.sh subprocess.

Run:  python tests/ai_agent/test_alert_auth.py     (or: pytest tests/ai_agent)
"""

import os
import sys
import json
import types
import hmac
import hashlib
import unittest
from pathlib import Path
from unittest import mock

# The shared secret must be set BEFORE importing agent_app (it is read at import).
SECRET = "unit_test_secret"
os.environ["SOC_AGENT_HMAC_SECRET"] = SECRET

# agent_app imports its sibling reporting module at load time; stub it so this
# unit test doesn't pull in PDF/LLM dependencies.
_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}
sys.modules["weekly_ciso_report"] = _stub

AGENT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "setup" / "ai_agent"
sys.path.insert(0, str(AGENT_DIR))

import agent_app  # noqa: E402


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


class AlertAuthTests(unittest.TestCase):
    def setUp(self):
        agent_app.app.testing = True
        self.client = agent_app.app.test_client()
        # Neutralize every outbound side-effect so the test is hermetic.
        self.mock_run = mock.patch.object(agent_app.subprocess, "run").start()
        for fn in ("analyze_alert_with_ai", "send_soc_alert",
                   "send_discord_alert", "log_soar_action"):
            mock.patch.object(agent_app, fn, return_value="stub").start()
        self.addCleanup(mock.patch.stopall)

    def _post(self, payload, sign=True, tamper=False):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if sign:
            sig = _sign(body)
            if tamper:
                sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
            headers["x-elastic-signature"] = sig
        return self.client.post("/alert", data=body, headers=headers)

    def test_missing_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": "AA:BB:CC:DD:EE:FF"}, sign=False)
        self.assertEqual(r.status_code, 401)
        self.mock_run.assert_not_called()

    def test_invalid_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": "AA:BB:CC:DD:EE:FF"}, tamper=True)
        self.assertEqual(r.status_code, 401)
        self.mock_run.assert_not_called()

    def test_valid_signature_valid_mac_quarantines(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": "AA:BB:CC:DD:EE:FF"})
        self.assertEqual(r.status_code, 200)
        self.mock_run.assert_called_once()
        passed_args = self.mock_run.call_args[0][0]
        self.assertIn("AA:BB:CC:DD:EE:FF", passed_args)

    def test_valid_signature_malicious_mac_never_reaches_subprocess(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": "x; rm -rf / #"})
        self.assertEqual(r.status_code, 200)         # handled (escalated to review)
        self.mock_run.assert_not_called()            # but NEVER quarantined


if __name__ == "__main__":
    unittest.main(verbosity=2)
