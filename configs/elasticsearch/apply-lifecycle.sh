#!/usr/bin/env bash
# =============================================================================
# apply-lifecycle.sh — install the Suburban-SOC data lifecycle (WS0.5).
#
# Bounds storage and makes the evidence window explicit by installing, in order:
#   1. an fs snapshot repository  (suburban-soc-snapshots)         — needs path.repo
#   2. an SLM policy              (suburban-soc-daily-snapshots)   — daily snapshots
#   3. two ILM policies           (logstash-security-ilm 30d,
#                                  soar-actions-ilm 365d)          — hot/warm/delete
#   4. the data-stream index templates (via apply-templates.sh)    — data_stream:{}
#
# The ILM delete phase is snapshot-gated (wait_for_snapshot), so an index is only
# deleted once the SLM policy has captured it — "snapshot before delete".
#
# Idempotent: every PUT is an upsert. Safe to re-run.
#
# Usage (from anywhere; env auto-loaded from scripts/setup/.env):
#   ES_URL=https://localhost:9200 ES_USER=elastic ES_PASS=... ./apply-lifecycle.sh
#   ./apply-lifecycle.sh --snapshot-now   # also trigger an immediate SLM snapshot
# Env: ES_URL (default https://localhost:9200), ES_USER (elastic),
#      ES_PASS / ELASTIC_PASSWORD, ES_CA (default /certs/ca/ca.crt — FAILS
#      CLOSED if unreadable; set ES_INSECURE=true to skip verification, lab only).
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

# Shared ES creds + TLS + es() (issue #156; audit #166 — no local -k downgrade).
source "$HERE/../../scripts/setup/lib/es_common.sh"

SNAPSHOT_NOW=0
for arg in "$@"; do
  case "$arg" in
    --snapshot-now) SNAPSHOT_NOW=1 ;;
    --*) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

REPO="suburban-soc-snapshots"
SLM="suburban-soc-daily-snapshots"

put() {  # $1=label  $2=path  $3=json-file
  esj -o /dev/null -w "    ${1} -> HTTP %{http_code}\n" -X PUT \
    "$ES_URL$2" --data-binary "@$3"
}

echo "==> [1/4] Registering snapshot repository '${REPO}' (fs, path.repo)"
# Fails with 500 'path.repo not registered' if docker-compose's path.repo +
# snapshots volume are not in place — that's the actionable signal to redeploy.
put "repo" "/_snapshot/${REPO}" "$HERE/ilm/snapshot-repository.json"

echo "==> [2/4] Installing SLM policy '${SLM}'"
put "slm" "/_slm/policy/${SLM}" "$HERE/ilm/slm-policy.json"

echo "==> [3/4] Installing ILM policies"
put "logstash-security-ilm" "/_ilm/policy/logstash-security-ilm" "$HERE/ilm/logstash-security.ilm.json"
put "soar-actions-ilm"      "/_ilm/policy/soar-actions-ilm"      "$HERE/ilm/soar-actions.ilm.json"

echo "==> [4/4] Installing data-stream index templates"
# Templates carry data_stream:{} + index.lifecycle.name, so they must go in after
# the ILM policies they reference exist. Invoke via `bash` so it works even when
# the script is mounted read-only without the executable bit (the compose
# `lifecycle` one-shot mounts configs/elasticsearch :ro).
bash "$HERE/apply-templates.sh"

if [[ $SNAPSHOT_NOW -eq 1 ]]; then
  echo "==> Triggering an immediate snapshot via SLM '${SLM}'"
  esj -o /dev/null -w '    execute -> HTTP %{http_code}\n' -X POST "$ES_URL/_slm/policy/${SLM}/_execute"
fi

echo "Done. Data lifecycle installed (ILM + snapshots + data-stream templates)."
