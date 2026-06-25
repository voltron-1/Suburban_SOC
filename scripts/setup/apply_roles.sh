#!/usr/bin/env bash
# =============================================================================
# apply_roles.sh — WS3.2: install the least-privilege RBAC roles.
#
# Applies every role in configs/elasticsearch/roles/*.json to Elasticsearch so the
# role definitions are version-controlled (not ad-hoc). Humans use soc_analyst /
# soc_detection_engineer / soc_admin; services use logstash_writer / soc_agent_cases.
# No human or service uses the `elastic` superuser in normal operation.
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./apply_roles.sh
# Env: ES_URL (https://localhost:9200), ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
# Shared ES creds + TLS + es helpers (issue #156).
source "$HERE/lib/es_common.sh"

for f in "$REPO_ROOT"/configs/elasticsearch/roles/*.json; do
  role="$(basename "$f" .json)"
  code=$(es_code -X PUT "$ES_URL/_security/role/$role" \
    -H 'Content-Type: application/json' --data-binary "@$f")
  printf '    role %-26s -> HTTP %s\n' "$role" "$code"
done
echo "Done. RBAC roles installed."
