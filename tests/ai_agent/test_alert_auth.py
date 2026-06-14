#!/usr/bin/env python3
"""
SOC AI agent — webhook auth, input validation, and SOAR response-model tests.

Covers WS0.2 (HMAC auth + MAC validation) and the CDP §12.3/§12.4 response model:

  * /alert rejects missing/invalid HMAC signatures (401) and never executes;
  * autonomous containment is OFF by default — a critical alert with a valid MAC
    is DRAFTED for human approval, NOT auto-executed (the industry-standard
    human-in-the-loop posture for a destructive, irreversible action);
  * autonomous execution happens ONLY when an operator opts in
    (AUTONOMOUS_ISOLATION=true);
  * a malicious/invalid MAC never reaches the response path;
  * §12.4 protected assets are never isolated and never even drafted;
  * a drafted action can be listed (/pending) and executed by a human (/approve);
  * execution routes containment to the hive-mind-broker over HMAC (#109) — the
    slim agent never shells out to isolate.sh.

Run:  python tests/ai_agent/test_alert_auth.py     (or: pytest tests/ai_agent)
"""

import os
import sys
import json
import time
import types
import hmac
import hashlib
import tempfile
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

# An IP guaranteed to be on the permanent exclusion list (governance/exclusion_list.txt).
EXCLUDED_IP = "192.168.1.1"
GOOD_MAC = "AA:BB:CC:DD:EE:FF"


def _sign(body: bytes, ts=None):
    """Return (timestamp, 'sha256=<hmac>') for the replay-protected scheme: the HMAC
    is over '<timestamp>.' + body (audit P1-1)."""
    ts = ts or str(int(time.time()))
    sig = "sha256=" + hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, sig


class AlertResponseTests(unittest.TestCase):
    def setUp(self):
        agent_app.app.testing = True
        self.client = agent_app.app.test_client()
        # The replay/nonce cache is module-level (audit P1-1); isolate it per test so
        # identical signed requests across tests don't trip replay rejection.
        agent_app._seen_sigs.clear()

        # Isolate the approval queue to a throwaway file per test.
        self._qfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
        self._qfile.close()
        self._qpatch = mock.patch.object(agent_app, "APPROVAL_QUEUE", self._qfile.name)
        self._qpatch.start()

        # Neutralize outbound side-effects. The broker dispatch is mocked to report
        # a successful block, so the autonomous/approve paths see containment succeed
        # without any real HTTP/SSH. Default return: (ok, detail).
        self.mock_dispatch = mock.patch.object(
            agent_app, "dispatch_block_via_broker",
            return_value=(True, "IP blocked on 1/1 router(s)")).start()
        for fn in ("analyze_alert_with_ai", "send_soc_alert",
                   "send_discord_alert", "log_soar_action"):
            mock.patch.object(agent_app, fn, return_value="stub").start()
        # WS2.3: stub Kibana Cases — create returns a fake id; comment/close are
        # tracked so tests can assert the case lifecycle without a live Kibana.
        self.mock_create_case = mock.patch.object(
            agent_app, "create_case", return_value="case-abc123").start()
        self.mock_case_comment = mock.patch.object(agent_app, "add_case_comment").start()
        self.mock_close_case = mock.patch.object(agent_app, "close_case").start()
        # WS3.3: audit writes go to ES — stub them out for unit tests.
        self.mock_audit = mock.patch.object(agent_app, "write_audit").start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: os.unlink(self._qfile.name))

    def _post(self, payload, sign=True, tamper=False, path="/alert", ts=None):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if sign:
            tstamp, sig = _sign(body, ts)
            if tamper:
                sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
            headers["x-elastic-signature"] = sig
            headers["x-elastic-timestamp"] = tstamp
        return self.client.post(path, data=body, headers=headers)

    def _get_pending(self, sign=True):
        """GET /pending is HMAC-gated; sign the (empty) body like an operator would."""
        headers = {}
        if sign:
            tstamp, sig = _sign(b"")
            headers["x-elastic-signature"] = sig
            headers["x-elastic-timestamp"] = tstamp
        return self.client.get("/pending", headers=headers)

    # --- WS0.2 authentication ------------------------------------------------
    def test_missing_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, sign=False)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_invalid_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, tamper=True)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    # --- privileged-endpoint authentication (audit P0-2) ---------------------
    def test_approve_unsigned_rejected_and_never_executes(self):
        # First draft a real action (signed) so a valid target exists to approve.
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        # An UNSIGNED /approve for that action must be refused and never dispatch.
        r = self._post({"id": draft["action_id"], "approver": "attacker"},
                       sign=False, path="/approve")
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_approve_invalid_signature_rejected(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "attacker"},
                       tamper=True, path="/approve")
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_pending_unsigned_rejected(self):
        r = self._get_pending(sign=False)
        self.assertEqual(r.status_code, 401)

    # --- replay protection (audit P1-1) --------------------------------------
    def test_replayed_alert_rejected(self):
        # A valid signed /alert is accepted once; replaying the EXACT same body +
        # timestamp + signature is refused (nonce already seen).
        payload = {"severity": "critical", "source_ip": "1.2.3.4", "source_mac": GOOD_MAC}
        ts = str(int(time.time()))
        first = self._post(payload, ts=ts)
        self.assertEqual(first.status_code, 200)
        replay = self._post(payload, ts=ts)              # identical -> identical signature
        self.assertEqual(replay.status_code, 401)

    def test_stale_timestamp_rejected(self):
        # A correctly-signed request with a timestamp outside the window is refused.
        old = str(int(time.time()) - (agent_app.HMAC_REPLAY_WINDOW + 60))
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, ts=old)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_missing_timestamp_rejected(self):
        # A valid signature with NO timestamp header is refused (can't prove freshness).
        body = json.dumps({"severity": "critical"}).encode()
        _, sig = _sign(body)
        r = self.client.post("/alert", data=body,
                             headers={"Content-Type": "application/json",
                                      "x-elastic-signature": sig})  # no timestamp
        self.assertEqual(r.status_code, 401)

    def test_weekly_report_unsigned_rejected(self):
        r = self._post({}, sign=False, path="/weekly-report")
        self.assertEqual(r.status_code, 401)

    # --- §12.3 draft-by-default (autonomous OFF) -----------------------------
    def test_critical_valid_mac_drafts_not_executes_by_default(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "drafted")
        self.mock_dispatch.assert_not_called()     # NEVER auto-dispatches by default
        # The drafted action is queued for approval.
        pending = self._get_pending().get_json()["pending"]
        self.assertTrue(any(a["target_mac"] == GOOD_MAC for a in pending))

    def test_malicious_mac_never_dispatches(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": "x; rm -rf / #"})
        self.assertEqual(r.status_code, 200)
        self.mock_dispatch.assert_not_called()

    # --- §12.3 autonomous path (opt-in) --------------------------------------
    def test_autonomous_flag_dispatches_to_broker(self):
        with mock.patch.object(agent_app, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "auto_isolated")
        self.mock_dispatch.assert_called_once()
        # The broker blocks by IP — the attacker IP is the first positional arg.
        self.assertEqual(self.mock_dispatch.call_args[0][0], "1.2.3.4")

    def test_autonomous_flag_still_blocks_invalid_mac(self):
        with mock.patch.object(agent_app, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": "not-a-mac"})
        self.assertEqual(r.status_code, 200)
        self.mock_dispatch.assert_not_called()     # no valid MAC -> never dispatches

    # --- §12.4 exclusion list ------------------------------------------------
    def test_excluded_asset_never_acted_on(self):
        with mock.patch.object(agent_app, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": EXCLUDED_IP,
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "no_action_protected_asset")
        self.mock_dispatch.assert_not_called()     # protected asset, even with flag on
        # And nothing was drafted for it either.
        pending = self._get_pending().get_json()["pending"]
        self.assertFalse(any(a["target_ip"] == EXCLUDED_IP for a in pending))

    # --- approval flow: human executes a drafted action ----------------------
    def test_pending_then_approve_dispatches(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        action_id = draft["action_id"]
        self.mock_dispatch.assert_not_called()     # still not executed at draft time

        r = self._post({"id": action_id, "approver": "analyst1"}, path="/approve")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "executed")
        self.mock_dispatch.assert_called_once()    # the human approval dispatches it
        self.assertEqual(self.mock_dispatch.call_args[0][0], "1.2.3.4")

    def test_approve_twice_does_not_double_execute(self):
        # audit P2-9: re-approving an already-resolved id must NOT dispatch again.
        action_id = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                                "source_mac": GOOD_MAC}).get_json()["action_id"]
        self.assertEqual(self._post({"id": action_id, "approver": "a1"},
                                    path="/approve").status_code, 200)
        self.mock_dispatch.assert_called_once()
        # Second approval of the same id (different approver -> distinct signature, so
        # it passes replay/auth and reaches the dedup): now resolved -> 404, no
        # second dispatch.
        second = self._post({"id": action_id, "approver": "a2"}, path="/approve")
        self.assertEqual(second.status_code, 404)
        self.mock_dispatch.assert_called_once()    # still exactly one dispatch

    # --- WS0.3 tenant-scoped routing (the broker owns router resolution) ------
    def test_named_tenant_passed_to_broker_on_autonomous(self):
        # The agent forwards the tenant; the broker maps it to that tenant's routers.
        with mock.patch.object(agent_app, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC, "tenant_id": "home-smith"})
        self.assertEqual(r.get_json()["status"], "auto_isolated")
        self.mock_dispatch.assert_called_once()
        # dispatch_block_via_broker(attacker_ip, tenant, source_mac=...)
        self.assertEqual(self.mock_dispatch.call_args[0][1], "home-smith")

    # --- WS2.3 alert triage & case tracking ----------------------------------
    def test_alert_opens_tracked_case(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": GOOD_MAC, "tenant_id": "home-smith"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["case_id"], "case-abc123")
        self.mock_create_case.assert_called_once()
        # the SOAR decision is appended to the case timeline
        self.assertTrue(self.mock_case_comment.called)

    def test_approve_closes_case_with_disposition(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "analyst1"}, path="/approve")
        self.assertEqual(r.get_json()["status"], "executed")
        self.assertEqual(r.get_json()["case_id"], "case-abc123")
        # approval closes the case with a disposition
        self.mock_close_case.assert_called_with("unassigned", "case-abc123",
                                                "true_positive_contained")

    def test_broker_refusal_surfaces_as_isolation_failed(self):
        # When the broker reports no routers for the tenant (it owns inventory),
        # the agent reports isolation_failed — never a silent success.
        self.mock_dispatch.return_value = (False, "no routers for tenant 'neighbor-jones'")
        with mock.patch.object(agent_app, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC, "tenant_id": "neighbor-jones"})
        self.assertEqual(r.get_json()["status"], "isolation_failed")
        self.mock_dispatch.assert_called_once()


class TenantResolverTests(unittest.TestCase):
    """WS0.3 helper unit tests (no Flask client)."""

    def test_safe_tenant(self):
        self.assertEqual(agent_app.safe_tenant("Home-Smith"), "home-smith")
        self.assertEqual(agent_app.safe_tenant("bad slug!"), "unassigned")
        self.assertEqual(agent_app.safe_tenant(None), "unassigned")

    def test_ip_excluded_cidr_and_ipv6(self):
        # audit P2-7: exclusion entries may be CIDR or IPv6, not just exact IPv4.
        entries = {"10.0.0.0/24", "2001:db8::/32", "8.8.8.8"}
        self.assertTrue(agent_app._ip_excluded("10.0.0.5", entries))    # in /24
        self.assertFalse(agent_app._ip_excluded("10.0.1.5", entries))   # outside
        self.assertTrue(agent_app._ip_excluded("2001:db8::1", entries)) # IPv6 in /32
        self.assertTrue(agent_app._ip_excluded("8.8.8.8", entries))     # exact
        self.assertFalse(agent_app._ip_excluded("nonsense", entries))

    def test_dispatch_fails_closed_without_secret(self):
        # #109: no HIVE_MIND_SECRET => the agent never dispatches (fails closed).
        with mock.patch.object(agent_app, "HIVE_MIND_SECRET", b""):
            ok, detail = agent_app.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertFalse(ok)
        self.assertIn("HIVE_MIND_SECRET", detail)

    def test_hosted_llm_egress_disabled_degrades_gracefully(self):
        # WS1.1 regression: LLM_ALLOW_HOSTED was referenced but never defined, so
        # analyze_alert_with_ai raised NameError -> /alert 500 on every intel hit.
        # With hosted egress disabled it must return a string, never raise.
        with mock.patch.object(agent_app, "LLM_ALLOW_HOSTED", False), \
             mock.patch.object(agent_app, "LLM_API_URL",
                               "https://api.openai.com/v1/chat/completions"):
            out = agent_app.analyze_alert_with_ai("alert: conn to known-bad IP")
        self.assertIsInstance(out, str)
        self.assertIn("skipped", out.lower())

    def test_notify_resolution_prefers_tenant_then_global(self):
        with mock.patch.dict(os.environ, {"NTFY_TOPIC_HOME_SMITH": "tenant-topic"}):
            self.assertEqual(agent_app.ntfy_topic_for("home-smith"), "tenant-topic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
