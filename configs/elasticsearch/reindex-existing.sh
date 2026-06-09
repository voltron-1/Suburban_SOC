#!/usr/bin/env bash
# =============================================================================
# reindex-existing.sh — migrate legacy indices onto the corrected ECS mappings.
#
# WHY: indices created before configs/elasticsearch/*-template.json were applied
# have ECS fields dynamically mapped as `text` (fielddata disabled), so
# aggregations silently fail and Kibana shows data-view conflicts. Field types
# cannot be changed in place — the data must be reindexed into a new index that
# inherits the corrected template.
#
# WHAT: for each source index `X` this reindexes into `X-ecs`, which matches the
# same `logstash-security-*` / `soar-actions-*` data-view pattern and therefore
# inherits the priority-200 templates (keyword/ip/date + replicas:0). It then
# verifies the document count before touching the original.
#
# SAFETY: non-destructive by default — originals are LEFT in place and you end up
# with both `X` (old) and `X-ecs` (new). Re-run with --replace to delete each
# original ONLY after its `-ecs` copy verifies (equal doc count AND zero reindex
# failures). Any mismatch leaves both indices untouched for inspection.
#
# NOTE: the new `source.ip` (ip) / `*.ip` mappings are stricter than the old
# `text`. If a legacy doc holds a non-IP string in an ip-typed field, reindex
# reports it under `failures` and that index is skipped from --replace. Inspect,
# then fix the source data or the template before retrying.
#
# Usage (from anywhere; env auto-loaded from scripts/setup/.env):
#   ./reindex-existing.sh                 # dry-run-ish: reindex legacy -> *-ecs, keep originals
#   ./reindex-existing.sh --replace       # also delete each original after verify
#   ./reindex-existing.sh --include-mock  # also migrate *-mock / *-dynamic test indices
#   ./reindex-existing.sh --dry-run       # only list what WOULD be migrated, with counts
#   ./reindex-existing.sh logstash-security-2026.06.08   # explicit index/pattern(s)
# Env: ES_URL (default https://localhost:9200), ES_USER (elastic),
#      ES_PASS / ELASTIC_PASSWORD.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
[[ -z "$ES_PASS" ]] && { echo "ERROR: set ES_PASS or ELASTIC_PASSWORD"; exit 1; }

REPLACE=0; INCLUDE_MOCK=0; DRY_RUN=0; EXPLICIT=()
for arg in "$@"; do
  case "$arg" in
    --replace)      REPLACE=1 ;;
    --include-mock) INCLUDE_MOCK=1 ;;
    --dry-run)      DRY_RUN=1 ;;
    --*) echo "Unknown flag: $arg"; exit 1 ;;
    *) EXPLICIT+=("$arg") ;;
  esac
done

es() { curl -sk --max-time 600 -u "${ES_USER}:${ES_PASS}" -H 'Content-Type: application/json' "$@"; }
# Count docs in an index/pattern; prints an integer (0 if absent). The `tr -d` strips
# any CR — some python builds (e.g. Windows python on WSL) emit CRLF, which would
# otherwise contaminate string comparisons below.
count() { local n; n=$(es "$ES_URL/$1/_count" | python3 -c "import sys,json;print(json.load(sys.stdin).get('count',0))" 2>/dev/null | tr -d '\r'); echo "${n:-0}"; }

# ---- Resolve the source index list -----------------------------------------
if [[ ${#EXPLICIT[@]} -gt 0 ]]; then
  PATTERN="$(IFS=,; echo "${EXPLICIT[*]}")"
else
  # Legacy daily indices only. The date-prefixed glob excludes per-tenant indices
  # (logstash-security-<tenant>-*) and the already-correct ones.
  PATTERN="logstash-security-2026.*,soar-actions-2026.*"
fi

mapfile -t SOURCES < <(
  es "$ES_URL/_cat/indices/$PATTERN?h=index" 2>/dev/null \
    | tr -d ' ' | grep -v '^$' \
    | grep -v -- '-ecs$' \
    | { if [[ $INCLUDE_MOCK -eq 0 ]]; then grep -viE 'mock|dynamic'; else cat; fi; } \
    | sort
)
# With --include-mock, fold in the test indices that the date glob misses.
if [[ $INCLUDE_MOCK -eq 1 && ${#EXPLICIT[@]} -eq 0 ]]; then
  mapfile -t EXTRA < <(es "$ES_URL/_cat/indices/logstash-security-mock,soar-actions-mock,soar-actions-dynamic-2026?h=index" 2>/dev/null | tr -d ' ' | grep -v '^$' | sort)
  SOURCES+=("${EXTRA[@]:-}")
fi

if [[ ${#SOURCES[@]} -eq 0 || -z "${SOURCES[0]:-}" ]]; then
  echo "No source indices matched '$PATTERN'. Nothing to do."; exit 0
fi

echo "Source indices to migrate (${#SOURCES[@]}):"
for s in "${SOURCES[@]}"; do [[ -n "$s" ]] && printf '  %-44s %s docs\n' "$s" "$(count "$s")"; done
echo "Mode: $([[ $REPLACE -eq 1 ]] && echo 'REPLACE (delete originals after verify)' || echo 'copy-only (originals kept)')"
[[ $DRY_RUN -eq 1 ]] && { echo "(dry run — no changes made)"; exit 0; }
echo "============================================================"

OK=0; SKIP=0
for SRC in "${SOURCES[@]}"; do
  [[ -z "$SRC" ]] && continue
  TGT="${SRC}-ecs"
  SRC_N="$(count "$SRC")"
  echo "==> $SRC ($SRC_N docs) -> $TGT"

  # Fresh target each run (idempotent re-runs).
  es -o /dev/null -X DELETE "$ES_URL/$TGT" >/dev/null 2>&1 || true

  RESP="$(es -X POST "$ES_URL/_reindex?wait_for_completion=true&refresh=true" -d "{
    \"conflicts\":\"proceed\",
    \"source\":{\"index\":\"$SRC\",\"size\":2000},
    \"dest\":{\"index\":\"$TGT\",\"op_type\":\"create\"}
  }")"
  read -r CREATED FAILS < <(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('created',0), len(d.get('failures',[])))
" 2>/dev/null | tr -d '\r' || echo "0 -1")
  CREATED=${CREATED:-0}; FAILS=${FAILS:--1}

  TGT_N="$(count "$TGT")"
  if [[ "$FAILS" == "0" && "$TGT_N" -eq "$SRC_N" ]]; then
    echo "    OK: reindexed $CREATED docs, target count $TGT_N matches."
    if [[ $REPLACE -eq 1 ]]; then
      es -o /dev/null -w '    deleted original -> HTTP %{http_code}\n' -X DELETE "$ES_URL/$SRC"
    fi
    OK=$((OK+1))
  else
    echo "    SKIP: failures=$FAILS, src=$SRC_N tgt=$TGT_N (original kept; inspect $TGT)."
    echo "$RESP" | python3 -c "
import sys,json
try: d=json.load(sys.stdin)
except Exception: sys.exit()
for f in d.get('failures',[])[:3]:
    c=f.get('cause',{})
    print('      failure:',f.get('index'),c.get('type'),'-',str(c.get('reason'))[:140])
" 2>/dev/null || true
    SKIP=$((SKIP+1))
  fi
done

echo "============================================================"
echo "Done. migrated_ok=$OK  skipped=$SKIP"
[[ $REPLACE -eq 0 ]] && echo "Originals kept. Verify the *-ecs indices, then re-run with --replace to swap."
