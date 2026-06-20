#!/bin/bash
# Install a systemd drop-in that sets TENANT_ID for the host Filebeat service.
# Run with: sudo bash scripts/setup/install_filebeat_tenant_dropin.sh [<tenant-slug>]
#
# Why this exists:
#   The host Filebeat unit (/usr/lib/systemd/system/filebeat.service) only exports
#   GODEBUG/BEAT_* — it never sets TENANT_ID. configs/network/filebeat.yml stamps
#   every event with [tenant][id] = "${TENANT_ID:unassigned}", so without this
#   drop-in all telemetry ships unattributed and lands in the
#   .ds-logstash-security-UNASSIGNED-* data stream. This drop-in makes Filebeat
#   stamp the real tenant so events route to .ds-logstash-security-<slug>-* and
#   issue #147 Section C ("Tenant attribution correct") can be evidenced.
#
# Idempotent: re-running overwrites the drop-in and restarts Filebeat.

set -euo pipefail

# Default to the canonical home tenant the stack + soar-tests assert against.
TENANT_ID="${1:-home-smith}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] must run as root (sudo)." >&2
  exit 1
fi

# Reject anything that isn't a lowercase slug — the data-stream name is derived
# from it, and Logstash/ES expect [a-z0-9-].
if ! printf '%s' "$TENANT_ID" | grep -qE '^[a-z0-9][a-z0-9-]*$'; then
  echo "[ERROR] tenant slug '$TENANT_ID' must be a lowercase [a-z0-9-] slug." >&2
  exit 1
fi

DROPIN_DIR="/etc/systemd/system/filebeat.service.d"
DROPIN="${DROPIN_DIR}/10-tenant.conf"

echo "[INFO] Writing ${DROPIN} (TENANT_ID=${TENANT_ID})"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
# Managed by scripts/setup/install_filebeat_tenant_dropin.sh
# Stamps [tenant][id] on every shipped event (configs/network/filebeat.yml).
[Service]
Environment="TENANT_ID=${TENANT_ID}"
EOF
chmod 0644 "$DROPIN"

echo "[INFO] Reloading systemd + restarting filebeat"
systemctl daemon-reload
systemctl restart filebeat

echo "[PASS] Drop-in installed. New events will carry tenant.id=${TENANT_ID}"
echo "[INFO] Verify:  systemctl show filebeat -p Environment | tr ' ' '\\n' | grep TENANT_ID"
echo "[INFO] Verify routing: new docs should land in .ds-logstash-security-${TENANT_ID}-*"
