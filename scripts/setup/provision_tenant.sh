#!/usr/bin/env bash
# =============================================================================
# provision_tenant.sh — WS0.3 per-tenant isolation provisioner.
#
# For a given tenant slug, creates:
#   * a Kibana Space            (UI isolation)
#   * a space-scoped data view  (logstash-security-<tenant>-*)
#   * a least-privilege role    (read ONLY that tenant's indices + that space)
#   * a tenant viewer user      (mapped to the role; random password printed once)
#
# Tenant data is physically separated by index (logstash-security-<tenant>-*,
# written by configs/logstash.conf). This script grants access to exactly one
# tenant's slice, so a tenant user can never read another tenant's data.
#
# Usage:
#   cd ~/projects/Suburban-SOC/scripts/setup
#   ./provision_tenant.sh <tenant-slug>          # e.g. home-smith
#
# Env (auto-loaded from ./.env):
#   ES_URL (default https://localhost:9200), KIBANA_URL (default http://localhost:5601)
#   ES_USER/ES_PASS (default elastic / $ELASTIC_PASSWORD), ES_CA (optional)
# =============================================================================
set -euo pipefail

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

TENANT="${1:-}"
if [[ -z "$TENANT" ]]; then
  red "Usage: $0 <tenant-slug>   (lowercase letters, digits, hyphens)"; exit 1
fi
if ! [[ "$TENANT" =~ ^[a-z0-9][a-z0-9-]{1,38}$ ]]; then
  red "ERROR: tenant slug must be lowercase [a-z0-9-], 2-39 chars (got '$TENANT')."; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/.env" ]] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }

ES_URL="${ES_URL:-https://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
[[ -z "$ES_PASS" ]] && { red "ERROR: ES_PASS / ELASTIC_PASSWORD required."; exit 1; }

AUTH=(-u "${ES_USER}:${ES_PASS}")
if [[ -n "${ES_CA:-}" && -f "${ES_CA}" ]]; then TLS=(--cacert "${ES_CA}"); else TLS=(-k); fi

ROLE="tenant_${TENANT//-/_}_viewer"
USER="tenant_${TENANT//-/_}"
TENANT_PW="${TENANT_PW:-$(openssl rand -base64 18)}"
KARGS=(-s -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "${AUTH[@]}")

blue "==> [1/4] Creating Kibana space '${TENANT}'"
curl "${KARGS[@]}" -o /dev/null -w '    space -> HTTP %{http_code}\n' \
  -X POST "${KIBANA_URL}/api/spaces/space" \
  -d "{\"id\":\"${TENANT}\",\"name\":\"${TENANT}\"}" || true

blue "==> [2/4] Creating space-scoped data view (logstash-security-${TENANT}-*)"
curl "${KARGS[@]}" -o /dev/null -w '    data view -> HTTP %{http_code}\n' \
  -X POST "${KIBANA_URL}/s/${TENANT}/api/data_views/data_view" \
  -d "{\"override\":true,\"data_view\":{\"id\":\"logstash-${TENANT}\",\"name\":\"logstash-security-${TENANT}-*\",\"title\":\"logstash-security-${TENANT}-*\",\"timeFieldName\":\"@timestamp\"}}" || true

blue "==> [3/4] Creating least-privilege role '${ROLE}'"
# Kibana role API sets BOTH the ES index privileges and the space-scoped feature
# access in one object — the role can read only this tenant's indices + space.
curl "${KARGS[@]}" -o /dev/null -w '    role -> HTTP %{http_code}\n' \
  -X PUT "${KIBANA_URL}/api/security/role/${ROLE}" \
  -d "{
        \"elasticsearch\": {
          \"indices\": [
            {\"names\": [\"logstash-security-${TENANT}-*\", \"soar-actions-${TENANT}-*\"],
             \"privileges\": [\"read\", \"view_index_metadata\"]}
          ]
        },
        \"kibana\": [ {\"spaces\": [\"${TENANT}\"], \"base\": [\"read\"]} ]
      }" || true

blue "==> [4/4] Creating tenant user '${USER}'"
code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "${TLS[@]}" \
  -X PUT "${ES_URL}/_security/user/${USER}" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${TENANT_PW}\",\"roles\":[\"${ROLE}\"],\"full_name\":\"Tenant viewer: ${TENANT}\"}" || true)
echo "    user -> HTTP ${code}"

echo
green "=================== TENANT PROVISIONED ==================="
printf '  Tenant     : %s\n' "$TENANT"
printf '  Space      : %s/s/%s\n' "$KIBANA_URL" "$TENANT"
printf '  Indices    : logstash-security-%s-* , soar-actions-%s-*\n' "$TENANT" "$TENANT"
printf '  Login      : %s  /  %s\n' "$USER" "$TENANT_PW"
red    "  ^ Record this password now — it is shown only once."
green "========================================================="
