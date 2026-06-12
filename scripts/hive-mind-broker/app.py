from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
import uvicorn
import hmac
import hashlib
import json
import time
import uuid
import os
import re
import threading

from inventory import Inventory
from dispatcher import dispatch_block_to_all, is_excluded_ip

app = FastAPI(title="Hive-Mind Broker")

# Load the router inventory on startup
inv = Inventory("inventory.yaml")

# The secret used for HMAC validation. Loaded from the environment with NO
# insecure default (WS0.4) — if unset, the endpoint fails closed (503).
HMAC_SECRET = os.getenv("HIVE_MIND_SECRET", "").encode("utf-8")

# CDP §12.3: autonomous containment is Deferred Scope. By default the broker
# DRAFTS a block and queues it for a human-of-record; it does not push it.
# Set AUTONOMOUS_BLOCK_ENABLED=true to restore legacy auto-dispatch.
AUTONOMOUS_BLOCK_ENABLED = os.getenv("AUTONOMOUS_BLOCK_ENABLED", "false").lower() == "true"

APPROVAL_QUEUE = os.getenv("APPROVAL_QUEUE", "approval_queue.jsonl")
_queue_lock = threading.Lock()

# Tenant slug (WS0.3) — same grammar as agent_app/logstash/provision_tenant.sh.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}$")


def safe_tenant(value):
    """Return a validated lowercase tenant slug, or 'unassigned' if invalid."""
    v = str(value or "").strip().lower()
    return v if _TENANT_RE.match(v) else "unassigned"


def _append_action(action: dict) -> None:
    with _queue_lock:
        with open(APPROVAL_QUEUE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(action) + "\n")


def _read_queue():
    try:
        with open(APPROVAL_QUEUE, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except OSError:
        return []


async def _verify_and_parse(request: Request) -> dict:
    """Fail-closed HMAC gate shared by every block-producing endpoint.

    Verifies the x-elastic-signature HMAC over the RAW body (same scheme as the AI
    agent), then returns the parsed JSON. Raises the appropriate HTTPException on
    any failure so callers never see an unauthenticated or malformed payload.
    """
    # Fail closed if no secret is configured — never accept unauthenticated blocks.
    if not HMAC_SECRET:
        raise HTTPException(status_code=503, detail="Broker secret not configured")

    signature_header = request.headers.get("x-elastic-signature")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")

    # The raw body is what was signed — verify before parsing.
    body = await request.body()
    expected_mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        return json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")


@app.post("/webhook/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Receives webhook payloads from Kibana when a critical alert fires.
    """
    payload = await _verify_and_parse(request)

    # Extract the attacker IP from the Kibana alert payload
    # Payload structure depends on the specific Kibana Watcher/Alert action
    # For this MVP, we assume {"attacker_ip": "x.x.x.x"} is sent by the webhook
    attacker_ip = payload.get("attacker_ip")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="Payload missing attacker_ip")

    # §12.4: refuse to act against protected infrastructure, signed or not.
    if is_excluded_ip(attacker_ip):
        print(f"[!] REFUSED: {attacker_ip} is on the permanent exclusion list.")
        return {"status": "success",
                "message": f"IP {attacker_ip} is on the exclusion list — no block drafted."}

    # WS0.3: scope the block to the alert's tenant — only that tenant's routers
    # are ever touched; the broker never broadcasts across tenants. An unknown
    # tenant (or one with no routers) is a no-op, not a fall-back-to-all.
    tenant = safe_tenant(payload.get("tenant_id"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        print(f"[!] No routers for tenant '{tenant}' — refusing to act on {attacker_ip}.")
        return {"status": "success",
                "message": f"No routers configured for tenant '{tenant}' — nothing to block."}

    if AUTONOMOUS_BLOCK_ENABLED:
        # Legacy, out-of-scope behaviour, retained only behind an explicit flag.
        background_tasks.add_task(dispatch_block_to_all, routers, attacker_ip)
        print(f"[*] Auto-block dispatched for {attacker_ip} on tenant '{tenant}' (flag enabled).")
        return {"status": "success",
                "message": f"IP {attacker_ip} dispatched for block across {len(routers)} "
                           f"router(s) for tenant '{tenant}'."}

    # Default: §12.3 — draft the block and queue it for human approval.
    action = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "status": "pending",
        "tenant": tenant,
        "attacker_ip": attacker_ip,
        "router_count": len(routers),
    }
    _append_action(action)
    print(f"[*] Drafted block for {attacker_ip} (action {action['id']}) — awaiting approval.")
    return {"status": "success",
            "message": f"IP {attacker_ip} drafted for human approval (action {action['id']})."}


@app.post("/webhook/dispatch")
async def dispatch_block(request: Request):
    """Authenticated IMMEDIATE dispatch for an already-approved block (#109).

    The AI agent can't run isolate.sh from its slim container (no ssh/sudo), so it
    routes containment here. The agent performs the CDP §12.3 human-of-record gate
    upstream (autonomous opt-in OR a human /approve), so — unlike /webhook/alert —
    this endpoint does NOT re-queue for approval; it dispatches now.

    Still defence-in-depth: §12.4 exclusion and WS0.3 tenant scoping are re-checked
    here, and the dispatch is recorded to the approval queue as an audit line.
    Authentication is the same HMAC scheme; only a holder of HIVE_MIND_SECRET (the
    agent) can reach it.
    """
    payload = await _verify_and_parse(request)

    attacker_ip = payload.get("attacker_ip")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="Payload missing attacker_ip")
    approver = str(payload.get("approver", "soc-ai-agent"))

    # §12.4: refuse protected infrastructure, signed or not.
    if is_excluded_ip(attacker_ip):
        print(f"[!] REFUSED dispatch: {attacker_ip} is on the exclusion list.")
        return {"status": "refused", "executed": False,
                "message": f"IP {attacker_ip} is on the exclusion list — no block dispatched."}

    # WS0.3: only this tenant's routers are ever touched; unknown tenant => no-op.
    tenant = safe_tenant(payload.get("tenant_id"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        print(f"[!] No routers for tenant '{tenant}' — refusing to dispatch {attacker_ip}.")
        return {"status": "no_routers", "executed": False,
                "message": f"No routers configured for tenant '{tenant}' — nothing to block."}

    count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action({
        "id": uuid.uuid4().hex[:12], "ts": time.time(), "status": "executed",
        "approver": approver, "tenant": tenant, "attacker_ip": attacker_ip,
        "result": f"{count}/{len(routers)} routers",
    })
    print(f"[*] Dispatched block for {attacker_ip} on tenant '{tenant}' "
          f"({count}/{len(routers)} routers) — approver={approver}.")
    return {"status": "executed", "executed": True, "tenant": tenant,
            "router_count": len(routers), "success_count": count,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                       f"router(s) for tenant '{tenant}'."}


@app.get("/pending")
async def list_pending():
    """List drafted blocks awaiting a human-of-record."""
    resolved = {a["id"] for a in _read_queue() if a.get("status") in ("approved", "denied")}
    pending = [a for a in _read_queue()
               if a.get("status") == "pending" and a["id"] not in resolved]
    return {"pending": pending, "count": len(pending)}


@app.post("/approve")
async def approve(request: Request):
    """Human-of-record approves a drafted block, which then dispatches."""
    body = await request.json()
    action_id = body.get("id")
    approver = body.get("approver", "unknown")
    if not action_id:
        raise HTTPException(status_code=400, detail="missing 'id'")

    resolved = {a["id"] for a in _read_queue() if a.get("status") in ("approved", "denied")}
    pending = {a["id"]: a for a in _read_queue()
               if a.get("status") == "pending" and a["id"] not in resolved}
    action = pending.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"no pending action {action_id}")

    attacker_ip = action["attacker_ip"]
    if is_excluded_ip(attacker_ip):  # re-check at execution time
        _append_action({"id": action_id, "ts": time.time(), "status": "denied",
                        "approver": approver, "result": "exclusion list"})
        raise HTTPException(status_code=422, detail=f"{attacker_ip} is excluded")

    # WS0.3: dispatch only to the drafted action's tenant routers — never all.
    tenant = safe_tenant(action.get("tenant"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        _append_action({"id": action_id, "ts": time.time(), "status": "denied",
                        "approver": approver, "result": f"no routers for tenant {tenant}"})
        raise HTTPException(status_code=422, detail=f"no routers for tenant '{tenant}'")

    count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action({"id": action_id, "ts": time.time(), "status": "approved",
                    "approver": approver, "tenant": tenant,
                    "result": f"{count}/{len(routers)} routers"})
    return {"status": "executed", "approver": approver,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                       f"router(s) for tenant '{tenant}'."}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
