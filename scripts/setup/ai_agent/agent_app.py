import os
import re
import hmac
import hashlib
import ipaddress
import threading
import requests
import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, jsonify

# Import the CISO reporting pipeline (Task 4.1-4.5, Issue #51)
from weekly_ciso_report import run_reporting_pipeline

app = Flask(__name__)
logger = logging.getLogger(__name__)

# --- Configuration ---
# Secrets/config come from the environment (set in scripts/setup/.env, passed
# through by docker-compose). No real secret is hardcoded as a default (WS0.4):
# unset secrets degrade gracefully (notifications skipped, AI triage falls back).
NTFY_TOPIC         = os.environ.get("NTFY_TOPIC",         "")
LLM_API_KEY        = os.environ.get("LLM_API_KEY",        "")
LLM_API_URL        = os.environ.get("LLM_API_URL",        "https://api.openai.com/v1/chat/completions")
LLM_MODEL          = os.environ.get("LLM_MODEL",          "gpt-4")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
# Elasticsearch endpoint for the SOAR feedback loop (Executive Dashboard metrics).
# Defaults to the Docker-network service name used by docker-compose.yml.
# Security is enabled (WS0.1): connect over HTTPS with a least-privilege user and
# verify TLS against the stack CA.
ES_HOST            = os.environ.get("ES_HOST",            "https://elasticsearch:9200")
ES_USER            = os.environ.get("ES_USER",            "logstash_internal")
ES_PASS            = os.environ.get("ES_PASS",            "")
ES_CA              = os.environ.get("ES_CA",              "/certs/ca/ca.crt")
# requests `verify` arg: path to the CA bundle if present, else fall back to False
# (self-signed cert on the internal docker network). Never disable for public ES.
ES_VERIFY          = ES_CA if (ES_CA and Path(ES_CA).is_file()) else False

# Absolute path to isolate.sh — resolved at import time so subprocess.run works
# regardless of Flask's current working directory.
ISOLATE_SCRIPT = str((Path(__file__).resolve().parent.parent / "isolate.sh"))

# --- Webhook authentication (WS0.2) ------------------------------------------
# /alert triggers device isolation, so it MUST be authenticated. Callers sign the
# raw request body with HMAC-SHA256 and send it in the `x-elastic-signature`
# header as "sha256=<hexdigest>" (same scheme as the hive-mind-broker). The shared
# secret comes from the SOC_AGENT_HMAC_SECRET env var — if it is unset the endpoint
# fails CLOSED (503), never open.
HMAC_HEADER = "x-elastic-signature"
HMAC_SECRET = os.environ.get("SOC_AGENT_HMAC_SECRET", "").encode("utf-8")

# Validation patterns for anything that reaches the isolate.sh subprocess.
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def verify_signature(raw_body: bytes, signature_header: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification of the raw request body."""
    if not HMAC_SECRET:
        app.logger.critical("SOC_AGENT_HMAC_SECRET is not set — refusing all /alert requests.")
        return False
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(HMAC_SECRET, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def is_valid_mac(value: str) -> bool:
    return bool(value) and bool(_MAC_RE.match(value))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# =============================================================================
# 1. AI ANALYST — Level 1 SOC triage
# =============================================================================
def analyze_alert_with_ai(raw_log_data):
    """
    Acts as the Level 1 SOC Analyst. Takes the raw JSON log from Kibana
    and asks the LLM to summarize the threat and map it to MITRE ATT&CK.
    """
    system_prompt = (
        "You are an expert SOC Analyst. Analyze the following SIEM alert JSON data. "
        "Provide a 2-sentence summary of the attack, identify the likely MITRE ATT&CK tactic, "
        "and recommend a specific remediation step. Be concise."
    )
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":    LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": str(raw_log_data)},
        ],
        "temperature": 0.2,
    }
    try:
        response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        return "AI Analysis failed. Manual review required."
    except Exception as e:
        app.logger.error("AI integration failed during alert analysis: %s", e)
        return "AI Analysis failed. Manual review required."

# =============================================================================
# 2. NOTIFICATION ENGINE — ntfy push
# =============================================================================
def send_soc_alert(title, message, priority=3, tags="rotating_light"):
    """Pushes formatted alerts to the analyst's mobile device via ntfy."""
    if not NTFY_TOPIC:
        app.logger.warning("NTFY_TOPIC not set — skipping ntfy push.")
        return
    url = f"https://ntfy.sh/{NTFY_TOPIC}"
    headers = {
        "Title":    title,
        "Priority": str(priority),
        "Tags":     tags,
    }
    try:
        requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=10)
    except Exception as e:
        app.logger.error("ntfy delivery failed: %s", e)


# =============================================================================
# 3. DISCORD NOTIFICATION — SOC channel alert
# =============================================================================
def send_discord_alert(device_ip: str, device_mac: str, ai_summary: str):
    """
    Posts a rich quarantine notification to the SOC Discord channel.
    Requires DISCORD_WEBHOOK_URL environment variable to be set.
    """
    if not DISCORD_WEBHOOK_URL:
        app.logger.warning("DISCORD_WEBHOOK_URL not set — skipping Discord notification.")
        return

    payload = {
        "embeds": [{
            "title": "\ud83d\udd12 Device Automatically Quarantined",
            "color": 15158332,  # Red
            "fields": [
                {"name": "Device IP",    "value": device_ip,  "inline": True},
                {"name": "MAC Address",  "value": device_mac, "inline": True},
                {"name": "Reason",       "value": "High-Confidence IOC — Ransomware/C2 domain communication detected", "inline": False},
                {"name": "AI Analysis",  "value": ai_summary[:1024], "inline": False},
            ],
            "footer": {"text": "Suburban-SOC | Automated SOAR Response"}
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
    except Exception as e:
        app.logger.error("Discord notification failed: %s", e)


# =============================================================================
# 3.5 SOAR FEEDBACK LOOP — index response actions back to Elasticsearch
# =============================================================================
def log_soar_action(action_type, target_ip, target_mac, ai_summary, severity):
    """
    Indexes SOAR response actions back to Elasticsearch so the Executive
    Dashboard can track automated response metrics (devices quarantined,
    AI recommendations, automated-vs-manual ratio, response latency).

    Writes to a daily `soar-actions-YYYY.MM.dd` index. Failures are logged
    but never raised — dashboard telemetry must not break alert handling.

    Args:
        action_type: e.g. "quarantine_mac", "quarantine_ip", "analyst_review".
        target_ip:   offending device IP.
        target_mac:  offending device MAC (may be empty).
        ai_summary:  the LLM triage summary text.
        severity:    alert severity ("critical", "medium", ...).
    """
    doc = {
        "@timestamp":     datetime.now(timezone.utc).isoformat(),
        "action.type":    action_type,
        "source.ip":      target_ip,
        "source.mac":     target_mac or "N/A",
        "ai.summary":     ai_summary,
        "event.severity": severity,
        # Whether a human still needs to act. Drives the automated-vs-manual pie.
        "response.automated": action_type != "analyst_review",
    }
    index = "soar-actions-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
    try:
        requests.post(
            f"{ES_HOST}/{index}/_doc",
            json=doc,
            headers={"Content-Type": "application/json"},
            auth=(ES_USER, ES_PASS),
            verify=ES_VERIFY,
            timeout=5,
        )
    except Exception as e:
        app.logger.error("Failed to index SOAR action: %s", e)


# =============================================================================
# 4. WEBHOOK LISTENER — real-time alert triage
# =============================================================================
@app.route("/alert", methods=["POST"])
def handle_kibana_webhook():
    """Receives a signed alert payload and orchestrates AI triage + response."""
    # Step 0: authenticate the request BEFORE doing anything else. The raw body is
    # what was signed, so verify it before parsing.
    raw_body = request.get_data()
    if not verify_signature(raw_body, request.headers.get(HMAC_HEADER)):
        app.logger.warning("Rejected /alert: missing or invalid HMAC signature.")
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    severity    = data.get("severity",   "medium")
    target_ip   = str(data.get("source_ip",  "")).strip()
    target_mac  = str(data.get("source_mac", "")).strip()
    raw_details = data.get("raw_log",    "No log data provided")

    # Validate anything that could reach the OS / isolate.sh. Invalid values are
    # blanked (never passed through) so the subprocess only ever sees a clean MAC.
    valid_mac = target_mac if is_valid_mac(target_mac) else ""
    safe_ip   = target_ip if is_valid_ip(target_ip) else "unknown"

    # Step 1: AI triage
    ai_summary = analyze_alert_with_ai(raw_details)

    # Step 2: Automated response
    if severity == "critical" and valid_mac:
        # Quarantine by MAC address (persists across IP/DHCP changes). Only a
        # format-validated MAC ever reaches the subprocess. Wrapped so a failed
        # isolate.sh invocation (e.g. missing ssh/sudo, unreachable router) is
        # logged rather than crashing the handler into a 500.
        try:
            subprocess.run(["sudo", ISOLATE_SCRIPT, valid_mac], check=False)
        except Exception as exc:  # noqa: BLE001 - never let response handling crash
            app.logger.error("isolate.sh invocation failed: %s", exc)
        target_ip = safe_ip

        # ntfy mobile push
        alert_body = (
            f"NODE ISOLATED\nIP: {target_ip} | MAC: {valid_mac}\n\n"
            f"AI Analysis:\n{ai_summary}"
        )
        send_soc_alert(
            title="CRITICAL: Autonomous Isolation",
            message=alert_body,
            priority=5,
            tags="skull,lock,robot",
        )

        # Discord SOC channel notification
        send_discord_alert(
            device_ip=target_ip,
            device_mac=valid_mac,
            ai_summary=ai_summary,
        )

        # SOAR feedback loop — record the automated quarantine for the dashboard
        log_soar_action(
            action_type="quarantine_mac",
            target_ip=target_ip,
            target_mac=valid_mac,
            ai_summary=ai_summary,
            severity=severity,
        )
    else:
        # Either a medium alert, or a critical one we cannot auto-contain because
        # no valid MAC was supplied (isolate.sh is MAC-only — we never feed it an
        # IP). Both escalate to a human instead of taking an OS action.
        if severity == "critical":
            title = "CRITICAL: Manual Isolation Required (no valid MAC)"
            priority = 5
            note = "Auto-isolation skipped — supply a valid source_mac to quarantine."
        else:
            title = "MEDIUM: Analyst Review Requested"
            priority = 3
            note = "Review required for isolation."
        alert_body = (
            f"Suspicious Activity from {safe_ip}\n\n"
            f"AI Analysis:\n{ai_summary}\n\n{note}"
        )
        send_soc_alert(
            title=title,
            message=alert_body,
            priority=priority,
            tags="warning,mag,robot",
        )

        # SOAR feedback loop — record the manual-review path (not automated)
        log_soar_action(
            action_type="analyst_review",
            target_ip=safe_ip,
            target_mac=valid_mac,
            ai_summary=ai_summary,
            severity=severity,
        )

    return jsonify({"status": "Alert Processed", "ai_analysis": ai_summary}), 200


# =============================================================================
# 5. WEEKLY CISO REPORT ENDPOINT  (Issue #51 — wired from weekly_ciso_report.py)
# =============================================================================
@app.route("/weekly-report", methods=["POST"])
def trigger_weekly_report():
    """
    Triggers the full CISO reporting pipeline asynchronously.
    Responds immediately with 202 Accepted; the PDF is generated and
    delivered to Slack + ntfy in the background thread.

    Invoke manually:
        curl -s -X POST http://localhost:5000/weekly-report
    Or schedule via cron:
        0 8 * * 1  curl -s -X POST http://localhost:5000/weekly-report
    """
    def _run():
        try:
            result = run_reporting_pipeline()
            app.logger.info("CISO report pipeline finished: %s", result)
        except Exception as exc:
            app.logger.error("CISO report pipeline error: %s", exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({
        "status":  "accepted",
        "message": "Weekly CISO report pipeline started in background. "
                   "PDF will be delivered to Slack and ntfy when ready.",
    }), 202


@app.route("/weekly-report/status", methods=["GET"])
def report_status():
    """Health check — confirms the report endpoint is reachable."""
    return jsonify({"status": "ready", "endpoint": "POST /weekly-report"}), 200


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # Binds to 0.0.0.0 so Kibana can reach it across the Docker network
    app.run(host="0.0.0.0", port=5000, debug=False)
