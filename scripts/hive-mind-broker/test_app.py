import pytest
from fastapi.testclient import TestClient
from unittest import mock
from unittest.mock import AsyncMock
import hmac
import hashlib
import json
import os

# Set the HMAC secret before importing app (read at import).
os.environ["HIVE_MIND_SECRET"] = "test_secret"

import app as broker_app
from app import app, HMAC_SECRET

client = TestClient(app)

# A tenant + its router count, per the local inventory.yaml.
TENANT = "home-smith"
EXCLUDED_IP = "192.168.1.1"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()


def _post(payload, sign=True, tamper=False):
    body = json.dumps(payload).encode("utf-8")
    headers = {}
    if sign:
        sig = _sign(body)
        if tamper:
            sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        headers["x-elastic-signature"] = sig
    return client.post("/webhook/alert", data=body, headers=headers)


@pytest.fixture(autouse=True)
def _no_real_ssh():
    """Keep the dispatcher from making real SSH calls; reset the queue per test."""
    broker_app._append_action  # touch to ensure import
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
    pending = client.get("/pending").json()["pending"]
    drafted = [a for a in pending if a["attacker_ip"] == "9.9.9.9"]
    assert drafted and drafted[0]["tenant"] == TENANT and drafted[0]["router_count"] >= 1


def test_unknown_tenant_is_no_op(_no_real_ssh):
    r = _post({"attacker_ip": "9.9.9.9", "tenant_id": "ghost-tenant"})
    assert r.status_code == 200
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()
    assert client.get("/pending").json()["count"] == 0   # nothing drafted


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
    assert client.get("/pending").json()["count"] == 0


def test_approve_dispatches_only_to_tenant_routers(_no_real_ssh):
    draft = _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}).json()
    # pull the drafted id
    action_id = [a for a in client.get("/pending").json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]

    r = client.post("/approve", json={"id": action_id, "approver": "analyst1"})
    assert r.status_code == 200
    assert r.json()["status"] == "executed"
    _no_real_ssh.assert_awaited_once()
    routers_arg = _no_real_ssh.await_args[0][0]
    assert routers_arg and all(rt.get("tenant") == TENANT for rt in routers_arg)
