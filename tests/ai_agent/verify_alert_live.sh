#!/usr/bin/env bash
# =============================================================================
# verify_alert_live.sh — WS0.2 live-path check against the RUNNING AI agent.
#
# Proves, against the real container (not a mock):
#   1. an unsigned POST to /alert is rejected (401), no quarantine;
#   2. a tampered-signature POST is rejected (401), no quarantine;
#   3. a correctly-signed request using the EXACT body + HMAC scheme that
#      configs/logstash.conf produces is accepted (200). This uses an empty MAC
#      so it exercises auth + the signing format WITHOUT triggering a real
#      router SSH/quarantine.
#
# Optional (RUN_QUARANTINE=1): a signed critical alert WITH a valid MAC. By
#   default (autonomous OFF) the agent DRAFTS the action for approval (200) — no
#   router is touched. With AUTONOMOUS_ISOLATION=true the agent dispatches the block
#   to the hive-mind-broker over HMAC (#109); it never shells out to isolate.sh.
#
# Usage:
#   cd ~/projects/Suburban-SOC/scripts/setup      # for .env
#   ../../tests/ai_agent/verify_alert_live.sh
# =============================================================================
set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:5000}"

# Load the shared HMAC secret the agent + Logstash use.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../../scripts/setup/.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a; . "$ENV_FILE"; set +a
fi
SECRET="${SOC_AGENT_HMAC_SECRET:-}"
if [[ -z "$SECRET" ]]; then
  echo "[ERR] SOC_AGENT_HMAC_SECRET not found (looked in $ENV_FILE). Set it or export it." >&2
  exit 2
fi

pass=0; fail=0
# Replay-protected scheme (audit P1-1): HMAC over "<timestamp>.<body>".
sign() { printf '%s' "${1}.${2}" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}'; }

# $1=label  $2=expected_code  $3=body  $4=signature-header ("" to omit)  $5=timestamp ("" to omit)
check() {
  local label="$1" want="$2" body="$3" sig="${4:-}" ts="${5:-}"
  local hdr=(-H "Content-Type: application/json")
  [[ -n "$sig" ]] && hdr+=(-H "x-elastic-signature: $sig")
  [[ -n "$ts" ]]  && hdr+=(-H "x-elastic-timestamp: $ts")
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' "${hdr[@]}" \
         --data-binary "$body" "$AGENT_URL/alert" || echo "000")
  if [[ "$code" == "$want" ]]; then
    echo "  [PASS] $label -> HTTP $code (expected $want)"; pass=$((pass+1))
  else
    echo "  [FAIL] $label -> HTTP $code (expected $want)"; fail=$((fail+1))
  fi
}

echo "[*] Agent: $AGENT_URL"

# 1. Unsigned -> 401
check "unsigned request rejected" 401 \
  '{"severity":"critical","source_ip":"203.0.113.5","source_mac":""}' ""

# 2. Tampered signature (valid timestamp) -> 401
BODY='{"severity":"critical","source_ip":"203.0.113.5","source_mac":""}'
check "tampered signature rejected" 401 "$BODY" "sha256=deadbeef" "$(date +%s)"

# 3. Correctly-signed, Logstash-exact body, EMPTY mac -> 200 (no quarantine).
#    This is byte-for-byte what configs/logstash.conf's ruby filter emits:
#    {"severity":"critical","source_ip":"<ip>","source_mac":"<mac>"}, signed over
#    "<timestamp>.<body>" with the freshness timestamp sent alongside (audit P1-1).
LS_BODY='{"severity":"critical","source_ip":"203.0.113.5","source_mac":""}'
LS_TS=$(date +%s)
check "valid signature accepted (Logstash scheme)" 200 "$LS_BODY" "sha256=$(sign "$LS_TS" "$LS_BODY")" "$LS_TS"

# 4. OPTIONAL: signed + valid MAC -> 200. By default this is DRAFTED for approval
#    (no router action). With AUTONOMOUS_ISOLATION=true the agent dispatches the
#    block to the hive-mind-broker over HMAC (#109) — never isolate.sh.
if [[ "${RUN_QUARANTINE:-0}" == "1" ]]; then
  echo "[!] RUN_QUARANTINE=1 — critical+MAC alert. Drafts by default; with"
  echo "    AUTONOMOUS_ISOLATION=true it dispatches to the hive-mind-broker."
  Q_BODY='{"severity":"critical","source_ip":"203.0.113.5","source_mac":"AA:BB:CC:DD:EE:FF"}'
  Q_TS=$(date +%s)
  check "valid signature + valid MAC accepted" 200 "$Q_BODY" "sha256=$(sign "$Q_TS" "$Q_BODY")" "$Q_TS"
fi

echo
echo "[=] Results: $pass passed, $fail failed."
[[ "$fail" -eq 0 ]]
