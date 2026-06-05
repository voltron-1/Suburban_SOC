from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
import uvicorn
import hmac
import hashlib
import json
import time
import uuid
import os
import threading

from inventory import Inventory
from dispatcher import dispatch_block_to_all, is_excluded_ip

app = FastAPI(title="Hive-Mind Broker")

# Load the router inventory on startup
inv = Inventory("inventory.yaml")

# The secret used for HMAC validation. In production, load from environment variable.
HMAC_SECRET = os.getenv("HIVE_MIND_SECRET", "default_dev_secret").encode('utf-8')

# CDP §12.3: autonomous containment is Deferred Scope. By default the broker
# DRAFTS a block and queues it for a human-of-record; it does not push it.
# Set AUTONOMOUS_BLOCK_ENABLED=true to restore legacy auto-dispatch.
AUTONOMOUS_BLOCK_ENABLED = os.getenv("AUTONOMOUS_BLOCK_ENABLED", "false").lower() == "true"

APPROVAL_QUEUE = os.getenv("APPROVAL_QUEUE", "approval_queue.jsonl")
_queue_lock = threading.Lock()


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

@app.post("/webhook/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Receives webhook payloads from Kibana when a critical alert fires.
    """
    # Verify HMAC signature
    signature_header = request.headers.get("x-elastic-signature")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")
    
    # Read the raw body for HMAC verification
    body = await request.body()
    
    # Calculate expected signature
    expected_mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    
    # Use hmac.compare_digest to prevent timing attacks
    if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

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

    routers = inv.get_routers()

    if AUTONOMOUS_BLOCK_ENABLED:
        # Legacy, out-of-scope behaviour, retained only behind an explicit flag.
        background_tasks.add_task(dispatch_block_to_all, routers, attacker_ip)
        print(f"[*] Auto-block dispatched for {attacker_ip} (flag enabled).")
        return {"status": "success",
                "message": f"IP {attacker_ip} dispatched for block across {len(routers)} routers."}

    # Default: §12.3 — draft the block and queue it for human approval.
    action = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "status": "pending",
        "attacker_ip": attacker_ip,
        "router_count": len(routers),
    }
    _append_action(action)
    print(f"[*] Drafted block for {attacker_ip} (action {action['id']}) — awaiting approval.")
    return {"status": "success",
            "message": f"IP {attacker_ip} drafted for human approval (action {action['id']})."}


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

    routers = inv.get_routers()
    count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action({"id": action_id, "ts": time.time(), "status": "approved",
                    "approver": approver, "result": f"{count}/{len(routers)} routers"})
    return {"status": "executed", "approver": approver,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} routers."}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
