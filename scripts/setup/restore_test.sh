#!/usr/bin/env bash
# =============================================================================
# restore_test.sh — WS2.5: prove backups are RESTORABLE (not just taken).
#
# A backup you have never restored is not a backup. This snapshots a deterministic
# canary index, restores it under a scratch name, verifies the doc count matches,
# and cleans up — failing loudly if the round-trip doesn't reproduce the data.
# Run on a schedule alongside the SLM snapshots; a failure means the evidence chain
# is broken and must be investigated.
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./restore_test.sh                 # canary round-trip (default)
#   ./restore_test.sh <real-index>    # restore-test a real index into a scratch copy
# Env: ES_URL (https://localhost:9200), ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD,
#      REPO (suburban-soc-snapshots).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
REPO="${REPO:-suburban-soc-snapshots}"
[[ -z "$ES_PASS" ]] && { echo "ERROR: ES_PASS / ELASTIC_PASSWORD required"; exit 1; }

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
es() { curl -sk -u "${ES_USER}:${ES_PASS}" -H 'Content-Type: application/json' "$@"; }
# python-free count (works on minimal images): pull "count":N from the JSON.
count() { es "$ES_URL/$1/_count" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2; }

SRC="${1:-soc-restore-canary}"
SNAP="restoretest-$(es "$ES_URL/_nodes/_local/name" >/dev/null 2>&1; date -u +%s 2>/dev/null || echo run)"
SCRATCH="${SRC}-restoretest"

cleanup() {
  es -o /dev/null -X DELETE "$ES_URL/$SCRATCH" >/dev/null 2>&1
  es -o /dev/null -X DELETE "$ES_URL/_snapshot/$REPO/$SNAP" >/dev/null 2>&1
  [[ "$SRC" == "soc-restore-canary" ]] && es -o /dev/null -X DELETE "$ES_URL/$SRC" >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> Restore test: source=$SRC repo=$REPO"

# 1. Seed the canary (deterministic) if using the default.
if [[ "$SRC" == "soc-restore-canary" ]]; then
  es -o /dev/null -X DELETE "$ES_URL/$SRC" >/dev/null 2>&1
  bulk=""
  for i in $(seq 1 25); do
    bulk+='{"index":{}}\n{"@timestamp":"2026-01-01T00:00:00Z","canary":'"$i"'}\n'
  done
  # Dedicated curl with ONLY the ndjson content-type (es() hardcodes json; two
  # Content-Type headers => ES rejects the bulk).
  printf "$bulk" | curl -sk -u "${ES_USER}:${ES_PASS}" -o /dev/null -X POST \
    "$ES_URL/$SRC/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-
  es -o /dev/null -X POST "$ES_URL/$SRC/_refresh"
fi
SRC_N="$(count "$SRC")"
[[ "${SRC_N:-0}" -gt 0 ]] || { red "FAIL: source index $SRC has 0 docs"; exit 1; }
echo "    source docs: $SRC_N"

# 2. Snapshot just this index (wait for completion).
code=$(es -o /dev/null -w '%{http_code}' -X PUT "$ES_URL/_snapshot/$REPO/$SNAP?wait_for_completion=true" \
  -d "{\"indices\":\"$SRC\",\"include_global_state\":false}")
[[ "$code" == "200" ]] || { red "FAIL: snapshot HTTP $code (is the repo registered? run apply-lifecycle.sh)"; exit 1; }
echo "    snapshot $SNAP created."

# 3. Restore under a scratch name (rename), wait, verify.
es -o /dev/null -X DELETE "$ES_URL/$SCRATCH" >/dev/null 2>&1
code=$(es -o /dev/null -w '%{http_code}' -X POST "$ES_URL/_snapshot/$REPO/$SNAP/_restore?wait_for_completion=true" \
  -d "{\"indices\":\"$SRC\",\"rename_pattern\":\"(.+)\",\"rename_replacement\":\"\$1-restoretest\",\"include_global_state\":false,\"index_settings\":{\"index.number_of_replicas\":0}}")
[[ "$code" == "200" ]] || { red "FAIL: restore HTTP $code"; exit 1; }
es -o /dev/null -X POST "$ES_URL/$SCRATCH/_refresh"
DST_N="$(count "$SCRATCH")"

echo "    restored docs: $DST_N (expected $SRC_N)"
if [[ "${DST_N:-0}" -eq "${SRC_N:-0}" && "${SRC_N:-0}" -gt 0 ]]; then
  green "PASS: snapshot round-trip verified — $DST_N/$SRC_N docs restored from $REPO."
  exit 0
else
  red "FAIL: restored $DST_N but expected $SRC_N — backups are NOT reliably restorable."
  exit 2
fi
