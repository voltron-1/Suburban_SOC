#!/usr/bin/env bash
# =============================================================================
# test_rbac.sh — WS3.2 negative tests: each account can do its job, and ONLY its job.
#
# Creates throwaway users for the key roles and asserts the allowed operations
# succeed and the forbidden ones are denied (403) — proving least privilege.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$HERE/../../scripts/setup/.env"
[[ -f "$ENVF" ]] && { set -a; . "$ENVF"; set +a; }
ES_URL="${ES_URL:-https://localhost:9200}"; ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
[[ -z "$ES_PASS" ]] && { echo "ERR: ES_PASS required" >&2; exit 2; }

PW="RbacTest123!"; fails=0
admin() { curl -sk -u "${ES_USER}:${ES_PASS}" "$@"; }
as() { local u="$1"; shift; curl -sk -o /dev/null -w '%{http_code}' -u "$u:$PW" "$@"; }
mkuser() { admin -o /dev/null -X PUT "$ES_URL/_security/user/$1" -H 'Content-Type: application/json' -d "{\"password\":\"$PW\",\"roles\":[\"$2\"]}"; }
rmuser() { admin -o /dev/null -X DELETE "$ES_URL/_security/user/$1"; }
expect() { # $1=label $2=actual $3=expected
  if [[ "$2" == "$3" ]]; then echo "  [PASS] $1 -> $2"; else echo "  [FAIL] $1 -> $2 (expected $3)"; fails=$((fails+1)); fi
}

admin -o /dev/null -X POST "$ES_URL/logstash-security-rbactest/_doc?refresh=true" -H 'Content-Type: application/json' -d '{"x":1}'
mkuser t_analyst soc_analyst
mkuser t_logstash logstash_writer

echo "== soc_analyst: read-only on SOC data, no admin =="
expect "analyst reads logstash-*"           "$(as t_analyst "$ES_URL/logstash-security-*/_search?size=0")" 200
expect "analyst CANNOT delete an index"     "$(as t_analyst -X DELETE "$ES_URL/logstash-security-rbactest")" 403
expect "analyst CANNOT create a role"       "$(as t_analyst -X PUT "$ES_URL/_security/role/evil" -H 'Content-Type: application/json' -d '{}')" 403

echo "== logstash_writer: write SOC indices only, no alerts read, no security mgmt =="
# Write to asset-inventory-* (a regular index the role covers; logstash-security-* is
# a WS0.5 data stream whose _doc auto-id returns 400 regardless of privilege).
expect "logstash_writer writes asset-inventory-*" "$(as t_logstash -X POST "$ES_URL/asset-inventory-rbactest/_doc" -H 'Content-Type: application/json' -d '{"y":2}')" 201
expect "logstash_writer CANNOT read alerts" "$(as t_logstash "$ES_URL/.alerts-security.alerts-default/_search?size=0")" 403
expect "logstash_writer CANNOT create user" "$(as t_logstash -X PUT "$ES_URL/_security/user/evil" -H 'Content-Type: application/json' -d "{\"password\":\"$PW\",\"roles\":[]}")" 403

rmuser t_analyst; rmuser t_logstash
admin -o /dev/null -X DELETE "$ES_URL/logstash-security-rbactest"
admin -o /dev/null -X DELETE "$ES_URL/asset-inventory-rbactest"
echo
if [[ $fails -eq 0 ]]; then echo "[=] RBAC least-privilege verified."; exit 0; else echo "[=] $fails RBAC check(s) FAILED."; exit 1; fi
