# shellcheck shell=bash
# =============================================================================
# es_common.sh — single source of truth for Elasticsearch credentials + the
# `es()` curl helpers. Source this instead of re-deriving ES_PASS and
# redefining es() in every script. Eliminates the duplication behind
# intermittent HTTP 401s (issue #156, runbook §11.5: unset creds / multiple
# conflicting es() definitions).
#
# Usage — source AFTER the caller has loaded its own .env (this lib reads creds
# from the current environment; it does not load .env, so each script keeps its
# correct .env location):
#
#   source "<repo>/scripts/setup/lib/es_common.sh"
#   es      "$ES_URL/_cluster/health"                         # auth + TLS, no Content-Type
#   esj  -X POST "$ES_URL/idx/_doc" -d "$json"                # + application/json
#   es_bulk -X POST "$ES_URL/idx/_bulk" --data-binary @-      # + application/x-ndjson
#   es_code "$ES_URL/_ilm/policy/foo"                         # prints HTTP status code only
#
# Credentials (resolved once, here):
#   ES_URL   default https://localhost:9200
#   ES_USER  default elastic
#   ES_PASS  from $ES_PASS, else $ELASTIC_PASSWORD
#   ES_CA    if set AND the file exists -> curl --cacert <ca>; else -> curl -k
#
# Fails fast (exit 1) when no password resolves, instead of emitting an
# unauthenticated request that returns a confusing 401.
# =============================================================================

ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

if [[ -z "${ES_PASS:-}" ]]; then
  echo "ERROR: ES_PASS / ELASTIC_PASSWORD is not set." >&2
  echo "       Set it in scripts/setup/.env or export it, then retry." >&2
  # exit (not return): this must abort the sourcing SCRIPT. `return` would only end
  # the source and let the script run on credential-less, defeating the fail-fast.
  exit 1
fi

# Auth + TLS built once. Prefer verifying against the stack CA; fall back to -k
# only when no readable CA is available (preserves existing localhost behavior).
ES_AUTH=(-u "${ES_USER}:${ES_PASS}")
if [[ -n "${ES_CA:-}" && -f "${ES_CA}" ]]; then
  ES_TLS=(--cacert "${ES_CA}")
else
  ES_TLS=(-k)
fi

# Base helper: auth + TLS, NO Content-Type — callers add -H as needed so json
# (doc) and x-ndjson (bulk) calls never collide into two Content-Type headers
# (which Elasticsearch rejects).
es()      { curl -s "${ES_AUTH[@]}" "${ES_TLS[@]}" "$@"; }
# Convenience wrappers for the common content types.
esj()     { es -H 'Content-Type: application/json' "$@"; }
es_bulk() { es -H 'Content-Type: application/x-ndjson' "$@"; }
# Status-code only (replaces the per-script code()/codeof() helpers).
es_code() { curl -s -o /dev/null -w '%{http_code}' "${ES_AUTH[@]}" "${ES_TLS[@]}" "$@"; }
