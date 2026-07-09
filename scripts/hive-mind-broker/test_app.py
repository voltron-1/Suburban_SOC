import pytest
from fastapi.testclient import TestClient
from unittest import mock
from unittest.mock import AsyncMock
import hmac
import hashlib
import json
import os
import time

# Set the HMAC secret before importing app (read at import).
os.environ["HIVE_MIND_SECRET"] = "test_secret"

import app as broker_app
from app import app, HMAC_SECRET

client = TestClient(app)

# A tenant + its router count, per the local inventory.yaml.
TENANT = "home-smith"
EXCLUDED_IP = "192.168.1.1"


def _sign(body: bytes, ts=None):
    """Return (timestamp, 'sha256=<hmac>') for the replay-protected scheme: HMAC over
    '<timestamp>.' + body (audit P1-1)."""
    ts = ts or str(int(time.time()))
    sig = "sha256=" + hmac.new(HMAC_SECRET, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, sig


def _signed_headers(body, sign=True, tamper=False, ts=None):
    headers = {}
    if sign:
        tstamp, sig = _sign(body, ts)
        if tamper:
            sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        headers["x-elastic-signature"] = sig
        headers["x-elastic-timestamp"] = tstamp
    return headers


def _post(payload, sign=True, tamper=False, ts=None):
    body = json.dumps(payload).encode("utf-8")
    return client.post("/webhook/alert", data=body,
                       headers=_signed_headers(body, sign, tamper, ts))


def _get_pending(sign=True):
    """GET /pending is HMAC-gated; sign the (empty) body like an operator would."""
    return client.get("/pending", headers=_signed_headers(b"", sign))


def _approve(payload, sign=True, tamper=False):
    """POST /approve is HMAC-gated; sign the request body."""
    body = json.dumps(payload).encode("utf-8")
    return client.post("/approve", data=body, headers=_signed_headers(body, sign, tamper))


@pytest.fixture(autouse=True)
def _no_real_ssh():
    """Keep the dispatcher from making real SSH calls; reset the queue per test."""
    broker_app._append_action  # touch to ensure import
    broker_app._seen_sigs.clear()   # isolate the replay/nonce cache per test (P1-1)
    if os.path.exists(broker_app.APPROVAL_QUEUE):
        os.remove(broker_app.APPROVAL_QUEUE)
    with mock.patch.object(broker_app, "dispatch_block_to_all",
                           new=AsyncMock(return_value=1)) as m:
        yield m
    if os.path.exists(broker_app.APPROVAL_QUEUE):
        os.remove(broker_app.APPROVAL_QUEUE)


def test_missing_signature():
    assert client.post("/webhook/alert", json={"attacker_ip": "1.2.3.4"}).status_code == 401


def test_invalid_signature():
    assert _post({"attacker_ip": "1.2.3.4"}, tamper=True).status_code == 401


def test_missing_ip():
    r = _post({"tenant_id": TENANT})
    assert r.status_code == 400


def test_alert_with_tenant_drafts_for_approval(_no_real_ssh):
    r = _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    assert r.status_code == 200
    assert "approval" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()              # draft does NOT dispatch
    pending = _get_pending().json()["pending"]
    drafted = [a for a in pending if a["attacker_ip"] == "9.9.9.9"]
    assert drafted and drafted[0]["tenant"] == TENANT and drafted[0]["router_count"] >= 1


def test_unknown_tenant_is_no_op(_no_real_ssh):
    r = _post({"attacker_ip": "9.9.9.9", "tenant_id": "ghost-tenant"})
    assert r.status_code == 200
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()
    assert _get_pending().json()["count"] == 0   # nothing drafted


def test_missing_tenant_is_no_op(_no_real_ssh):
    # No tenant_id => 'unassigned', which owns no routers => no broadcast.
    r = _post({"attacker_ip": "9.9.9.9"})
    assert r.status_code == 200
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


def test_excluded_ip_refused(_no_real_ssh):
    r = _post({"attacker_ip": EXCLUDED_IP, "tenant_id": TENANT})
    assert r.status_code == 200
    assert "exclusion list" in r.json()["message"].lower()
    assert _get_pending().json()["count"] == 0


# --- audit #164: attacker_ip must be a valid IP before it reaches nft/SSH ------
def test_alert_injection_string_rejected(_no_real_ssh):
    r = _post({"attacker_ip": "1.1.1.1 drop; reboot #", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()
    assert _get_pending().json()["count"] == 0


def test_alert_hostname_rejected(_no_real_ssh):
    r = _post({"attacker_ip": "not-an-ip.example.com", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def _post_dispatch(payload, sign=True, tamper=False, ts=None):
    body = json.dumps(payload).encode("utf-8")
    return client.post("/webhook/dispatch", data=body,
                       headers=_signed_headers(body, sign, tamper, ts))


# --- #109: /webhook/dispatch — immediate, pre-approved block -------------------
def test_dispatch_missing_signature():
    assert client.post("/webhook/dispatch", json={"attacker_ip": "9.9.9.9"}).status_code == 401


def test_dispatch_invalid_signature():
    assert _post_dispatch({"attacker_ip": "9.9.9.9"}, tamper=True).status_code == 401


def test_dispatch_missing_ip():
    assert _post_dispatch({"tenant_id": TENANT}).status_code == 400


def test_dispatch_executes_to_tenant_routers(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    assert r.status_code == 200
    body = r.json()
    assert body["executed"] is True and body["status"] == "executed"
    _no_real_ssh.assert_awaited_once()                 # actually dispatched, no draft
    routers_arg = _no_real_ssh.await_args[0][0]
    assert routers_arg and all(rt.get("tenant") == TENANT for rt in routers_arg)
    # Recorded as executed (not left pending).
    assert _get_pending().json()["count"] == 0


def test_dispatch_excluded_ip_refused(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": EXCLUDED_IP, "tenant_id": TENANT})
    assert r.status_code == 200
    assert r.json()["executed"] is False
    assert "exclusion list" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


# --- audit #164: attacker_ip must be a valid IP before it reaches nft/SSH ------
def test_dispatch_injection_string_rejected(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "1.1.1.1 drop; reboot #", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def test_dispatch_hostname_rejected(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "not-an-ip.example.com", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def test_dispatch_valid_ipv6_still_dispatches(_no_real_ssh):
    # Regression guard: the #164 validation must not break legitimate IPv6 input.
    r = _post_dispatch({"attacker_ip": "2001:db8::dead:beef", "tenant_id": TENANT})
    assert r.status_code == 200
    assert r.json()["executed"] is True
    _no_real_ssh.assert_awaited_once()


def test_dispatch_unknown_tenant_is_no_op(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": "ghost-tenant"})
    assert r.status_code == 200
    assert r.json()["executed"] is False
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


def test_approve_dispatches_only_to_tenant_routers(_no_real_ssh):
    draft = _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}).json()
    # pull the drafted id
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]

    r = _approve({"id": action_id, "approver": "analyst1"})
    assert r.status_code == 200
    assert r.json()["status"] == "executed"
    _no_real_ssh.assert_awaited_once()
    routers_arg = _no_real_ssh.await_args[0][0]
    assert routers_arg and all(rt.get("tenant") == TENANT for rt in routers_arg)


# --- audit P0-2: /approve and /pending must be authenticated ------------------
def test_approve_unsigned_rejected_and_never_dispatches(_no_real_ssh):
    # Draft a real action (signed), then attempt to approve it UNSIGNED.
    _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]
    r = _approve({"id": action_id, "approver": "attacker"}, sign=False)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()          # never executed the block


def test_approve_invalid_signature_rejected(_no_real_ssh):
    _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]
    r = _approve({"id": action_id, "approver": "attacker"}, tamper=True)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()


# --- audit #164: a corrupted queue entry must not crash /approve --------------
def test_approve_corrupted_queue_entry_rejected(_no_real_ssh):
    # Simulate a drafted action whose attacker_ip was never validated (e.g. a
    # manually-edited or pre-#164 queue file) rather than relying on _post,
    # which now validates at draft time and could never produce this state.
    broker_app._append_action({
        "id": "deadbeef0001", "ts": time.time(), "status": "pending",
        "tenant": TENANT, "attacker_ip": "not-an-ip", "router_count": 1,
    })
    r = _approve({"id": "deadbeef0001", "approver": "analyst1"})
    assert r.status_code == 422
    _no_real_ssh.assert_not_awaited()


def test_pending_unsigned_rejected():
    assert client.get("/pending").status_code == 401


# --- audit P1-3: SSH host-key verification is strict by default -----------------
def test_known_hosts_strict_by_default():
    import dispatcher
    with mock.patch.object(dispatcher, "INSECURE_SSH", False):
        # Returns the known_hosts PATH (asyncssh then verifies), never None.
        assert dispatcher._resolve_known_hosts() == dispatcher.KNOWN_HOSTS
        assert dispatcher._resolve_known_hosts() is not None


def test_known_hosts_insecure_opt_out_returns_none():
    import dispatcher
    with mock.patch.object(dispatcher, "INSECURE_SSH", True):
        assert dispatcher._resolve_known_hosts() is None


# --- audit P1-1: replay protection on the dispatch path ------------------------
def test_replayed_dispatch_rejected(_no_real_ssh):
    # An immediate dispatch is accepted once; replaying the EXACT same body +
    # timestamp + signature is refused (nonce already seen).
    payload = {"attacker_ip": "9.9.9.9", "tenant_id": TENANT}
    ts = str(int(time.time()))
    first = _post_dispatch(payload, ts=ts)
    assert first.status_code == 200 and first.json()["executed"] is True
    replay = _post_dispatch(payload, ts=ts)
    assert replay.status_code == 401
    _no_real_ssh.assert_awaited_once()          # the replay never reaches dispatch


def test_stale_timestamp_rejected(_no_real_ssh):
    old = str(int(time.time()) - (broker_app.HMAC_REPLAY_WINDOW + 60))
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}, ts=old)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()


def test_missing_timestamp_rejected():
    # A valid signature with no timestamp header is refused.
    body = json.dumps({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}).encode("utf-8")
    _, sig = _sign(body)
    r = client.post("/webhook/dispatch", data=body,
                    headers={"x-elastic-signature": sig})  # no timestamp
    assert r.status_code == 401


# --- audit P2-7: exclusion list supports CIDR + IPv6 --------------------------
def test_exclusion_supports_cidr_and_ipv6():
    import dispatcher
    with mock.patch.object(dispatcher, "load_excluded_ips",
                           return_value={"10.0.0.0/24", "2001:db8::/32"}):
        assert dispatcher.is_excluded_ip("10.0.0.5") is True      # inside the /24
        assert dispatcher.is_excluded_ip("10.0.1.5") is False     # outside it
        assert dispatcher.is_excluded_ip("2001:db8::1") is True   # IPv6 in the /32
        assert dispatcher.is_excluded_ip("2001:dead::1") is False
        # audit #164: a malformed address must be REJECTED, not silently
        # treated as "not excluded" (which previously let it flow on to
        # build_nft_command / an SSH-executed command).
        with pytest.raises(ValueError):
            dispatcher.is_excluded_ip("not-an-ip")
