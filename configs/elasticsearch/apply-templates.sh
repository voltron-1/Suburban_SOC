#!/usr/bin/env bash
# =============================================================================
# apply-templates.sh — install the Suburban-SOC index templates.
#
# Pins ECS fields in logstash-security-* and soar-actions-* to keyword/ip/date
# so cross-index aggregations and Kibana dashboards are consistent. Without
# these, Elasticsearch dynamically maps strings to `text` (fielddata disabled),
# which silently fails shard-level aggregations and produces data-view conflicts.
#
# Templates apply to indices created AFTER they are installed. To fix existing
# indices, reindex them (see reindex-existing.sh) — field types cannot be
# changed in place.
#
# Usage (from repo root or anywhere):
#   ES_URL=https://localhost:9200 ES_USER=elastic ES_PASS=... ./apply-templates.sh
# Env (auto-loaded from scripts/setup/.env if present):
#   ES_URL (default https://localhost:9200), ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD
#   ES_CA (default /certs/ca/ca.crt) — FAILS CLOSED if unreadable; set
#   ES_INSECURE=true to explicitly skip TLS verification (lab only).
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

# Shared ES creds + TLS + es() (issue #156; audit #166 — no local -k downgrade).
source "$HERE/../../scripts/setup/lib/es_common.sh"

echo "==> Installing logstash-security-template"
esj -o /dev/null -w '    -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/_index_template/logstash-security-template" \
  --data-binary "@$HERE/logstash-security-template.json"

echo "==> Installing soar-actions-template"
esj -o /dev/null -w '    -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/_index_template/soar-actions-template" \
  --data-binary "@$HERE/soar-actions-template.json"

echo "==> Dropping replicas to 0 on existing indices (single-node -> clears yellow)"
esj -o /dev/null -w '    logstash-security-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/logstash-security-*/_settings" -d '{"index":{"number_of_replicas":0}}'
esj -o /dev/null -w '    soar-actions-*      -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/soar-actions-*/_settings" -d '{"index":{"number_of_replicas":0}}'

echo "Done."
