#!/usr/bin/env bash
# =============================================================================
# isolate.sh — Suburban-SOC MAC-based device isolation (STANDALONE / MANUAL TOOL)
# Phase C: OpenWrt uci MAC-based device isolation
#
# NOTE (#109): this script is NO LONGER on the automated response path. The AI
# agent runs in a slim container with no ssh/sudo, so it now routes containment to
# the hive-mind-broker (scripts/hive-mind-broker/), which blocks by IP via nftables.
# This script is kept as a STANDALONE operator tool for MAC-level quarantine — a
# capability the broker's IP-block does not provide. Run it by hand on a host that
# has SSH access to the router; nothing invokes it automatically.
#
# Usage:
#   ./isolate.sh <MAC_ADDRESS> [ROUTER_HOST] [ROUTER_USER] [SSH_KEY]
#   Example: ./isolate.sh AA:BB:CC:DD:EE:FF 192.168.1.1 root /keys/id_ed25519
#
# This script connects to the OpenWrt router via SSH and injects a
# permanent firewall DROP rule targeting the specified MAC address.
# The rule persists across reboots via uci commit.
#
# Prerequisites:
#   - SSH key ~/.ssh/id_ed25519_hivemind must be authorized on the router
#   - OPENWRT_HOST env var set to router IP (default: 192.168.1.1)
#   - OPENWRT_USER env var set (default: root)
#   - The router's host key must be pinned in ISOLATE_KNOWN_HOSTS (default
#     ~/.ssh/known_hosts) — one-time bootstrap:
#       ssh-keyscan -t ed25519 "$OPENWRT_HOST" >> ~/.ssh/known_hosts
#     ISOLATE_INSECURE_SSH=true skips this for a lab/first-run only (#177).
#   - The §12.4 exclusion list (governance/exclusion_list.txt by default) must be
#     readable — this script fails closed (refuses to act) if it isn't, matching
#     the agent/broker's posture. ISOLATE_ALLOW_NO_EXCLUSIONS=true opts back into
#     proceeding without it for a lab/first-run only.
# =============================================================================

set -euo pipefail

# WS0.3 tenant-scoped isolation: optional positional args 2-4 (router host/user/
# key) override the env, which falls back to the built-in defaults. agent_app.py
# passes the resolved tenant's router this way (positional args survive `sudo`,
# which strips the environment); an empty arg is treated as unset.
TARGET_MAC="${1:-}"
OPENWRT_HOST="${2:-${OPENWRT_HOST:-192.168.1.1}}"
OPENWRT_USER="${3:-${OPENWRT_USER:-root}}"
SSH_KEY="${4:-${SSH_KEY:-$HOME/.ssh/id_ed25519_hivemind}}"

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
elif [[ "${ISOLATE_ALLOW_NO_EXCLUSIONS:-false}" == "true" ]]; then
  echo "[WARN] ISOLATE_ALLOW_NO_EXCLUSIONS=true — exclusion list not found at $EXCLUSION_LIST; proceeding WITHOUT infra protection (lab/first-run only; do not use in production)." >&2
else
  # Fail CLOSED (mirrors the agent's EXCLUSION_UNVERIFIABLE / broker handling): an
  # unreadable list must never silently widen what this script is willing to
  # quarantine. ISOLATE_ALLOW_NO_EXCLUSIONS=true opts back into the old
  # proceed-anyway behavior for a lab/first-run only.
  echo "[ERROR] Exclusion list not found at $EXCLUSION_LIST — refusing to act without it." >&2
  echo "        Restore the list, or set ISOLATE_ALLOW_NO_EXCLUSIONS=true to proceed without it (lab/first-run only)." >&2
  exit 4
fi

echo "[*] Initiating quarantine for device: $TARGET_MAC"
echo "[*] Connecting to OpenWrt router at $OPENWRT_HOST..."

# --- SSH host-key verification (#177, mirrors dispatcher.py's BROKER_KNOWN_HOSTS/
# BROKER_INSECURE_SSH). This was always StrictHostKeyChecking=no, so a MITM on the
# router path could capture this root SSH session. Strict by default; the router's
# host key must be pinned first (see the Prerequisites comment above).
# ISOLATE_INSECURE_SSH=true restores the old no-verification behaviour for a
# lab/first-run only — it logs loudly.
ISOLATE_KNOWN_HOSTS="${ISOLATE_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
ISOLATE_INSECURE_SSH="${ISOLATE_INSECURE_SSH:-false}"
if [[ "$ISOLATE_INSECURE_SSH" == "true" ]]; then
  echo "[WARN] ISOLATE_INSECURE_SSH=true — SSH host-key verification is DISABLED (lab/first-run only; do not use in production)." >&2
  SSH_HOST_KEY_OPTS=(-o StrictHostKeyChecking=no)
else
  SSH_HOST_KEY_OPTS=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=${ISOLATE_KNOWN_HOSTS}")
fi

# --- Execute uci firewall rule injection via SSH (idempotent) ---
# If a SOAR_QUARANTINE rule with the same name already exists, skip the
# add+restart cycle. Avoids accumulating duplicate uci rules on re-fires.
ssh -i "$SSH_KEY" \
    "${SSH_HOST_KEY_OPTS[@]}" \
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
