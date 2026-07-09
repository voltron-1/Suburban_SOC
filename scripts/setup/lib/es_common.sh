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
#   ES_CA    default /certs/ca/ca.crt; if readable -> curl --cacert <ca>.
#            FAIL CLOSED (audit #166 / NIST SC-8): if no readable CA and
#            ES_INSECURE isn't "true", this script exits rather than
#            silently falling back to curl -k.
#   ES_CURL_TIMEOUT  default 60 (seconds). es()/es_code() now always set
#            --max-time (audit #170 — no consumer previously had a hard
#            ceiling on a hung/stalled ES connection). Curl honors the LAST
#            --max-time/-m it sees, and ours is added before "$@", so any
#            caller that needs a longer ceiling (e.g. a bulk reindex) can
#            still override it by passing its own -m/--max-time as normal.
#
# Fails fast (exit 1) when no password resolves, instead of emitting an
# unauthenticated request that returns a confusing 401. Set ES_REQUIRE_CREDS=0
# before sourcing to downgrade that to a warning (for health monitors that must
# keep checking other components when ES is down / creds are absent).
# =============================================================================

# Idempotent: if already sourced in this shell, skip re-resolving creds.
[[ -n "${_ES_COMMON_LOADED:-}" ]] && return 0
_ES_COMMON_LOADED=1

ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

# Fail fast on missing creds by default. Health monitors that must keep checking
# other components when ES is down / creds are absent can set ES_REQUIRE_CREDS=0 to
# downgrade this to a warning (es() then goes out unauthenticated and surfaces 401).
if [[ -z "${ES_PASS:-}" ]]; then
  if [[ "${ES_REQUIRE_CREDS:-1}" == "0" ]]; then
    echo "WARNING: ES_PASS / ELASTIC_PASSWORD not set — ES calls will be unauthenticated." >&2
  else
    echo "ERROR: ES_PASS / ELASTIC_PASSWORD is not set." >&2
    echo "       Set it in scripts/setup/.env or export it, then retry." >&2
    # exit (not return): this must abort the sourcing SCRIPT. `return` would only end
    # the source and let the script run credential-less, defeating the fail-fast.
    exit 1
  fi
fi

# Auth + TLS built once. Prefer verifying against the stack CA. FAIL CLOSED
# (audit #166 / NIST SC-8): a missing/unreadable CA no longer silently
# downgrades to -k — set ES_INSECURE=true to explicitly opt out (lab/
# first-run only), mirroring dispatcher.py's BROKER_INSECURE_SSH pattern.
ES_AUTH=(-u "${ES_USER}:${ES_PASS}")
ES_CA="${ES_CA:-/certs/ca/ca.crt}"
if [[ -f "${ES_CA}" ]]; then
  ES_TLS=(--cacert "${ES_CA}")
elif [[ "${ES_INSECURE:-false}" == "true" ]]; then
  echo "WARNING: ES_INSECURE=true and no readable CA at ES_CA=${ES_CA} — TLS verification is DISABLED for ES calls (lab/first-run only; do not use in production)." >&2
  ES_TLS=(-k)
else
  echo "ERROR: no readable CA at ES_CA=${ES_CA} — refusing to skip TLS verification." >&2
  echo "       Set ES_CA to the stack CA path, or ES_INSECURE=true to explicitly accept unverified TLS (lab only)." >&2
  exit 1
fi

# audit #170: every curl invocation gets a hard ceiling — no consumer of this
# shared helper previously had one, so a stalled ES connection could hang a
# caller indefinitely. Overridable per-deployment via ES_CURL_TIMEOUT; a
# caller can still raise it for a specific call by passing its own
# -m/--max-time (curl honors the last one seen — see header note above).
ES_CURL_TIMEOUT="${ES_CURL_TIMEOUT:-60}"

# Base helper: auth + TLS, NO Content-Type — callers add -H as needed so json
# (doc) and x-ndjson (bulk) calls never collide into two Content-Type headers
# (which Elasticsearch rejects).
es()      { curl -s --max-time "${ES_CURL_TIMEOUT}" "${ES_AUTH[@]}" "${ES_TLS[@]}" "$@"; }
# Convenience wrappers for the common content types.
esj()     { es -H 'Content-Type: application/json' "$@"; }
es_bulk() { es -H 'Content-Type: application/x-ndjson' "$@"; }
# Status-code only (replaces the per-script code()/codeof() helpers).
es_code() { curl -s --max-time "${ES_CURL_TIMEOUT}" -o /dev/null -w '%{http_code}' "${ES_AUTH[@]}" "${ES_TLS[@]}" "$@"; }
