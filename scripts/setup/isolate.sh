#!/bin/bash
# =============================================================================
# isolate.sh — Suburban-SOC SOAR Quarantine Script
# Phase C: OpenWrt uci MAC-based device isolation
#
# Usage:
#   ./isolate.sh <MAC_ADDRESS>
#   Example: ./isolate.sh AA:BB:CC:DD:EE:FF
#
# This script connects to the OpenWrt router via SSH and injects a
# permanent firewall DROP rule targeting the specified MAC address.
# The rule persists across reboots via uci commit.
#
# Prerequisites:
#   - SSH key ~/.ssh/id_ed25519_hivemind must be authorized on the router
#   - OPENWRT_HOST env var set to router IP (default: 192.168.1.1)
#   - OPENWRT_USER env var set (default: root)
# =============================================================================

set -euo pipefail

TARGET_MAC="${1:-}"
OPENWRT_HOST="${OPENWRT_HOST:-192.168.1.1}"
OPENWRT_USER="${OPENWRT_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hivemind}"

# --- Validate input ---
if [[ -z "$TARGET_MAC" ]]; then
  echo "[ERROR] No MAC address provided." >&2
  echo "Usage: $0 <MAC_ADDRESS>" >&2
  exit 1
fi

# Basic MAC format validation (accepts both XX:XX:XX:XX:XX:XX and XX-XX-XX-XX-XX-XX)
if ! echo "$TARGET_MAC" | grep -qE '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'; then
  echo "[ERROR] Invalid MAC address format: $TARGET_MAC" >&2
  exit 1
fi

# Normalize: uppercase + colon delimiter (OpenWrt uci expects XX:XX:XX:XX:XX:XX)
TARGET_MAC="$(echo "$TARGET_MAC" | tr '[:lower:]' '[:upper:]' | tr '-' ':')"
RULE_NAME="SOAR_QUARANTINE_${TARGET_MAC//:/}"

# --- Exclusion list enforcement (CDP §12.4) ---
# Refuse to quarantine any asset on the permanent exclusion list. Compared with
# delimiters stripped + uppercased so AA:BB.. and aa-bb.. match the same entry.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXCLUSION_LIST="${EXCLUSION_LIST:-$SCRIPT_DIR/../../governance/exclusion_list.txt}"
TARGET_MAC_NORM="$(echo "$TARGET_MAC" | tr -d ':-')"
if [[ -f "$EXCLUSION_LIST" ]]; then
  while IFS= read -r line; do
    entry="${line%%#*}"                     # strip inline comments
    entry="$(echo "$entry" | tr -d '[:space:]')"
    [[ -z "$entry" ]] && continue
    entry_norm="$(echo "$entry" | tr '[:lower:]' '[:upper:]' | tr -d ':-')"
    if [[ "$entry_norm" == "$TARGET_MAC_NORM" ]]; then
      echo "[REFUSED] $TARGET_MAC is on the permanent exclusion list ($EXCLUSION_LIST). Aborting." >&2
      exit 3
    fi
  done < "$EXCLUSION_LIST"
else
  echo "[WARN] Exclusion list not found at $EXCLUSION_LIST — proceeding without infra protection." >&2
fi

echo "[*] Initiating quarantine for device: $TARGET_MAC"
echo "[*] Connecting to OpenWrt router at $OPENWRT_HOST..."

# --- Execute uci firewall rule injection via SSH (idempotent) ---
# If a SOAR_QUARANTINE rule with the same name already exists, skip the
# add+restart cycle. Avoids accumulating duplicate uci rules on re-fires.
ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${OPENWRT_USER}@${OPENWRT_HOST}" \
    "if uci show firewall | grep -q \"name='${RULE_NAME}'\"; then \
       echo '[=] Rule ${RULE_NAME} already present — no-op.'; \
       exit 0; \
     fi && \
     uci add firewall rule && \
     uci set firewall.@rule[-1].name='${RULE_NAME}' && \
     uci set firewall.@rule[-1].src='lan' && \
     uci set firewall.@rule[-1].src_mac='${TARGET_MAC}' && \
     uci set firewall.@rule[-1].target='DROP' && \
     uci set firewall.@rule[-1].enabled='1' && \
     uci commit firewall && \
     /etc/init.d/firewall restart"

echo "[+] SUCCESS: Device $TARGET_MAC has been quarantined on $OPENWRT_HOST"
