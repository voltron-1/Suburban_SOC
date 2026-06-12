#!/usr/bin/env bash
# =============================================================================
# collect_control_evidence.sh — WS3.7 continuous control monitoring (CCM).
#
# Runs every SOC 2 technical control built in M10 against the LIVE stack, writes
# one status doc per control per run to the `soc-controls` time series, and pushes
# an ntfy alert if any control has REGRESSED (status=fail). This is the control
# that watches the other controls — point a cron/systemd timer at it.
#
#   bash scripts/setup/collect_control_evidence.sh          # collect + alert on fail
#   CCM_NO_ALERT=1 bash scripts/setup/collect_control_evidence.sh   # collect only
#
# Exit 0 if all controls pass/no_data; 1 if any control failed (so the scheduler
# surfaces the regression). Evidence is queryable in Kibana via the WS3.7 dashboard
# (configs/server/control_status_dashboard.ndjson). See docs/SOP-013-ccm.md.
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$SCRIPT_DIR/.env" ]] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }
ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
NTFY_TOPIC="${NTFY_TOPIC:-subsoc-alerts}"
[[ -z "$ES_PASS" ]] && { echo "ERR: ES_PASS / ELASTIC_PASSWORD required" >&2; exit 2; }
AUTH=(-u "${ES_USER}:${ES_PASS}")
if [[ -n "${ES_CA:-}" && -f "${ES_CA}" ]]; then TLS=(--cacert "${ES_CA}"); else TLS=(-k); fi
es()   { curl -s "${AUTH[@]}" "${TLS[@]}" "$@"; }
codeof(){ curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "${TLS[@]}" "$@"; }

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BULK=""; fails=0; failed_ctrls=""
record() { # id  name  status(pass|fail|no_data)  detail
  local id="$1" name="$2" status="$3" detail="$4"
  printf -v line '{"create":{}}\n{"@timestamp":"%s","control.id":"%s","control.name":"%s","control.status":"%s","control.detail":"%s","soc2.tsc":"%s"}\n' \
    "$TS" "$id" "$name" "$status" "$detail" "${5:-Security}"
  BULK+="$line"
  printf '  [%s] %-22s %s\n' "$( [[ $status == pass ]] && echo PASS || { [[ $status == fail ]] && echo FAIL || echo ----; } )" "$id" "$detail"
  if [[ "$status" == "fail" ]]; then fails=$((fails+1)); failed_ctrls+="${id} "; fi
}

echo "== WS3.7 continuous control monitoring @ ${TS} =="

# C1 — Encryption in transit (WS3.1): http + transport TLS both enabled.
s=$(es "${ES_URL}/_nodes/settings?filter_path=nodes.*.settings.xpack.security" 2>/dev/null)
if echo "$s" | grep -q '"http":{"ssl":{"enabled":"true"' && echo "$s" | grep -q '"transport":{"ssl":{"enabled":"true"'; then
  record "C1-encryption-transit" "Encryption in transit" pass "http+transport TLS enabled" "Confidentiality"
else
  record "C1-encryption-transit" "Encryption in transit" fail "http/transport TLS not both enabled" "Confidentiality"
fi

# C2 — RBAC least privilege (WS3.2): all expected roles present.
missing=""; for r in soc_analyst soc_detection_engineer soc_admin logstash_writer soc_agent_cases soc_audit_appender; do
  [[ "$(codeof "${ES_URL}/_security/role/${r}")" == "200" ]] || missing+="${r} "
done
[[ -z "$missing" ]] && record "C2-rbac" "RBAC least privilege" pass "6/6 roles present" \
                     || record "C2-rbac" "RBAC least privilege" fail "missing roles: ${missing}"

# C3 — Audit trail append-only (WS3.3): appender role grants ONLY create / create_index.
ap=$(es "${ES_URL}/_security/role/soc_audit_appender" 2>/dev/null)
if echo "$ap" | grep -qE '"privileges":\["create_index","create"\]|"privileges":\["create","create_index"\]' \
   && ! echo "$ap" | grep -qE '"(write|index|delete|delete_index|all|manage)"'; then
  record "C3-audit-append-only" "Audit trail append-only" pass "appender = create-only (tamper-evident)"
else
  record "C3-audit-append-only" "Audit trail append-only" fail "appender role not create-only — tamper risk"
fi

# C4 — Retention / ILM (WS0.5): the security data-stream ILM policy exists.
[[ "$(codeof "${ES_URL}/_ilm/policy/logstash-security-ilm")" == "200" ]] \
  && record "C4-retention-ilm" "Retention (ILM)" pass "logstash-security-ilm present" \
  || record "C4-retention-ilm" "Retention (ILM)" fail "logstash-security-ilm missing"

# C5 — Backup / SLM (WS2.5): policy exists AND has a successful snapshot, with no
#      failure newer than the last success.
sl=$(es "${ES_URL}/_slm/policy/suburban-soc-daily-snapshots" 2>/dev/null)
ls_succ=$(echo "$sl" | grep -oE '"last_success":\{[^}]*"time":[0-9]+' | grep -oE '"time":[0-9]+$' | grep -oE '[0-9]+' | tail -1)
ls_fail=$(echo "$sl" | grep -oE '"last_failure":\{[^}]*"time":[0-9]+' | grep -oE '"time":[0-9]+$' | grep -oE '[0-9]+' | tail -1)
if [[ -n "$ls_succ" ]] && { [[ -z "$ls_fail" ]] || [[ "$ls_succ" -ge "$ls_fail" ]]; }; then
  record "C5-backup-slm" "Backups (SLM snapshots)" pass "last snapshot succeeded" "Availability"
elif [[ -z "$(echo "$sl" | grep -o last_success)" ]]; then
  record "C5-backup-slm" "Backups (SLM snapshots)" no_data "policy present, no snapshot yet" "Availability"
else
  record "C5-backup-slm" "Backups (SLM snapshots)" fail "last snapshot FAILED (failure newer than success)" "Availability"
fi

# C6 — Vulnerability scanning (WS3.6): the scan workflow is present in the repo.
[[ -f "${REPO_ROOT}/.github/workflows/security-scan.yml" ]] \
  && record "C6-vuln-scanning" "Vulnerability scanning" pass "security-scan.yml present (CI gate)" \
  || record "C6-vuln-scanning" "Vulnerability scanning" fail "security-scan.yml missing"

# C7 — Change management (WS3.5): deploys are being recorded to soc-deploys.
dc=$(codeof "${ES_URL}/soc-deploys")
if [[ "$dc" == "200" ]]; then record "C7-change-mgmt" "Change management" pass "soc-deploys index present"
else record "C7-change-mgmt" "Change management" no_data "no deploys recorded yet (soc-deploys absent)"; fi

# Persist the evidence (append-only-friendly: each run is new create docs).
echo "$BULK" | es -X POST "${ES_URL}/soc-controls/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @- >/dev/null \
  && echo "  -> evidence written to soc-controls" || echo "  -> WARN: failed to write soc-controls"

echo
if [[ $fails -gt 0 ]]; then
  echo "[=] CONTROL REGRESSION: ${fails} control(s) failed -> ${failed_ctrls}"
  if [[ -z "${CCM_NO_ALERT:-}" ]]; then
    curl -s -o /dev/null -m 8 -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
      -H "Title: Suburban-SOC control regression" -H "Priority: high" -H "Tags: rotating_light" \
      -d "SOC 2 control regression: ${failed_ctrls}(see soc-controls / control-status dashboard)" \
      && echo "  -> ntfy regression alert sent to ${NTFY_TOPIC}"
  fi
  exit 1
fi
echo "[=] All controls pass — SOC 2 technical posture verified @ ${TS}"
exit 0
