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
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
[[ -z "$ES_PASS" ]] && { echo "ERROR: set ES_PASS or ELASTIC_PASSWORD"; exit 1; }

curl_es() { curl -sk -u "${ES_USER}:${ES_PASS}" -H 'Content-Type: application/json' "$@"; }

echo "==> Installing logstash-security-template"
curl_es -o /dev/null -w '    -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/_index_template/logstash-security-template" \
  --data-binary "@$HERE/logstash-security-template.json"

echo "==> Installing soar-actions-template"
curl_es -o /dev/null -w '    -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/_index_template/soar-actions-template" \
  --data-binary "@$HERE/soar-actions-template.json"

echo "==> Dropping replicas to 0 on existing indices (single-node -> clears yellow)"
curl_es -o /dev/null -w '    logstash-security-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/logstash-security-*/_settings" -d '{"index":{"number_of_replicas":0}}'
curl_es -o /dev/null -w '    soar-actions-*      -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/soar-actions-*/_settings" -d '{"index":{"number_of_replicas":0}}'

echo "Done."
