#!/usr/bin/env bash
# =============================================================================
# stack_health.sh — WS2.5: the SOC monitors its own components.
#
# A SOC that can't see its own outages is blind. This checks every component
# (Elasticsearch, Kibana, Logstash, AI agent, Hive-Mind broker), indexes the result
# to soc-health, and raises an ntfy alert if anything is DOWN — so the SOC detects
# its own outages. Run on a schedule (cron).
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./stack_health.sh
# Env: ES_URL, KIBANA_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, NTFY_TOPIC.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
NTFY_TOPIC="${NTFY_TOPIC:-}"
# Shared ES creds + TLS + es helpers (issue #156). Soft mode: a health monitor must
# keep checking other components even when ES creds are absent, so don't fail-fast.
# shellcheck disable=SC2034  # read by the sourced es_common.sh, not directly in this file
ES_REQUIRE_CREDS=0
# shellcheck source=lib/es_common.sh
source "$HERE/lib/es_common.sh"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

declare -a DOWN=()
report() { printf '  %-16s %s\n' "$1" "$2"; }

# Container running? (best-effort; works when docker is on PATH)
container_up() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

check() {  # $1=name  $2=ok(0/1)  $3=detail
  if [[ "$2" -eq 0 ]]; then report "$1" "UP   ($3)"; else report "$1" "DOWN ($3)"; DOWN+=("$1"); fi
}

echo "==> SOC stack health $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Elasticsearch — cluster health (red counts as down).
es_status="$(es -m 6 "$ES_URL/_cluster/health" | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)"
[[ "$es_status" == "green" || "$es_status" == "yellow" ]] && check elasticsearch 0 "$es_status" || check elasticsearch 1 "${es_status:-unreachable}"

# Kibana — overall status level. #177: Kibana is TLS-only now (same stack CA as ES),
# so es()'s ES_TLS flags (-k/--cacert) are load-bearing here too, not a no-op.
kb_level="$(es -m 6 "$KIBANA_URL/api/status" | grep -o '"level":"[a-z]*"' | head -1 | cut -d'"' -f4)"
[[ "$kb_level" == "available" ]] && check kibana 0 "$kb_level" || check kibana 1 "${kb_level:-unreachable}"

# Logstash — node stats (:9600) if reachable, else container state.
if curl -s -m 5 "http://localhost:9600/_node/stats/pipelines" 2>/dev/null | grep -q '"pipelines"'; then
  check logstash 0 "pipeline ok"
elif container_up logstash; then
  check logstash 0 "container up"
else
  check logstash 1 "no :9600 + container down"
fi

# AI agent + broker — container state (not LAN-exposed; HMAC-gated).
container_up soc_ai_agent && check ai_agent 0 "container up" || check ai_agent 1 "container down"
container_up hive_mind_broker && check broker 0 "container up" || check broker 1 "container down"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status="$([[ ${#DOWN[@]} -eq 0 ]] && echo healthy || echo degraded)"
# Record to soc-health for the dashboard (best-effort; needs ES up).
esj -m 6 -o /dev/null -X POST "$ES_URL/soc-health/_doc" \
  -d "{\"@timestamp\":\"$now\",\"status\":\"$status\",\"down_count\":${#DOWN[@]},\"down\":[$(printf '"%s",' "${DOWN[@]}" | sed 's/,$//')]}" 2>/dev/null

echo
if [[ ${#DOWN[@]} -eq 0 ]]; then
  green "=== All components healthy. ==="
  exit 0
else
  red "=== DOWN: ${DOWN[*]} ==="
  if [[ -n "$NTFY_TOPIC" ]]; then
    curl -s -m 6 -o /dev/null "https://ntfy.sh/${NTFY_TOPIC}" \
      -H "Title: Suburban-SOC component DOWN" -H "Priority: urgent" -H "Tags: rotating_light,skull" \
      -d "SOC components DOWN: ${DOWN[*]}" 2>/dev/null
  fi
  exit 2
fi
