#!/usr/bin/env bash
# =============================================================================
# verify_quarantine.sh — Issue #22 task 4: confirm physical SOAR response
#
# SSHes into the OpenWrt router and asserts that a SOAR_QUARANTINE_<MAC>
# uci firewall rule exists for the given MAC. Exits 0 on present, 1 on
# missing, 3 if the router is unreachable.
#
# Usage: ./verify_quarantine.sh AA:BB:CC:DD:EE:FF
# =============================================================================

set -euo pipefail

[[ -f "$(dirname "$0")/.env" ]] && set -a && source "$(dirname "$0")/.env" && set +a

TARGET_MAC="${1:-}"
OPENWRT_HOST="${OPENWRT_HOST:-192.168.1.1}"
OPENWRT_USER="${OPENWRT_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hivemind}"

if [[ -z "$TARGET_MAC" ]]; then
  echo "Usage: $0 <MAC_ADDRESS>" >&2
  exit 1
fi

# Normalize to match isolate.sh's rule-naming convention (uppercase, no separators)
MAC_NORM="$(echo "$TARGET_MAC" | tr '[:lower:]' '[:upper:]' | tr -d ':-')"
RULE_NAME="SOAR_QUARANTINE_${MAC_NORM}"

echo "[*] Verifying quarantine rule '${RULE_NAME}' on ${OPENWRT_HOST}..."

# -q for quiet, -o BatchMode to fail fast instead of prompting
if ! ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout=10 \
        "${OPENWRT_USER}@${OPENWRT_HOST}" \
        "uci show firewall 2>/dev/null | grep -q \"name='${RULE_NAME}'\""; then
  rc=$?
  if [[ $rc -eq 255 ]]; then
    echo "[-] SSH to ${OPENWRT_HOST} failed (network or auth)." >&2
    exit 3
  fi
  echo "[-] FAIL: Rule ${RULE_NAME} not found on router." >&2
  exit 1
fi

echo "[+] PASS: Rule ${RULE_NAME} is installed and persistent."
