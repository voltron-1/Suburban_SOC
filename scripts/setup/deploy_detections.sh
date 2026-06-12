#!/usr/bin/env bash
# =============================================================================
# deploy_detections.sh — WS1.2 detection-as-code (#93).
#
# Converts the version-controlled Sigma rules (rules/sigma/*.yml) into Elastic
# Security detection rules with pySigma + the elasticsearch backend, then imports
# them into the Kibana Detection Engine. Detection LOGIC lives in the Sigma rule,
# not in inline logstash.conf regex.
#
# Flow:  sigma convert (lucene/siem_rule_ndjson, suburban-soc-ecs pipeline)
#        -> set index to logstash-* per rule
#        -> POST /api/detection_engine/rules/_import?overwrite=true  (idempotent;
#           stable rule_id comes from each Sigma rule's `id`).
#
# The toolchain (sigma-cli + pysigma-backend-elasticsearch) is set up in a local
# venv if `sigma` is not already on PATH. Use --no-build to require it on PATH.
#
# Usage (from anywhere; env auto-loaded from scripts/setup/.env):
#   ./scripts/setup/deploy_detections.sh            # convert + import (+ enable)
#   ./scripts/setup/deploy_detections.sh --no-enable # import disabled rules
#   DETECTION_INDEX='logstash-*' ./deploy_detections.sh
# Env: KIBANA_URL (http://localhost:5601), ES_USER (elastic),
#      ES_PASS/ELASTIC_PASSWORD, DETECTION_INDEX (logstash-*).
# =============================================================================
set -euo pipefail

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$SCRIPT_DIR/.env" ]] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"
DETECTION_INDEX="${DETECTION_INDEX:-logstash-*}"
RULES_DIR="$REPO_ROOT/rules/sigma"
PIPELINE="$REPO_ROOT/configs/detections/suburban-soc-ecs.yml"
[[ -z "$ES_PASS" ]] && { red "ERROR: ES_PASS / ELASTIC_PASSWORD required."; exit 1; }

NO_BUILD=0; ENABLE=1
for a in "$@"; do case "$a" in
  --no-build)  NO_BUILD=1 ;;
  --no-enable) ENABLE=0 ;;
  --include-experimental) INCLUDE_EXPERIMENTAL=1 ;;
  *) red "Unknown flag: $a"; exit 1 ;;
esac; done
INCLUDE_EXPERIMENTAL="${INCLUDE_EXPERIMENTAL:-0}"

# --- 1. Ensure the Sigma toolchain -------------------------------------------
SIGMA="$(command -v sigma || true)"
if [[ -z "$SIGMA" ]]; then
  [[ $NO_BUILD -eq 1 ]] && { red "ERROR: 'sigma' not on PATH and --no-build set."; exit 1; }
  VENV="$REPO_ROOT/.venv-detections"
  SIGMA="$VENV/bin/sigma"; [[ -x "$SIGMA" ]] || SIGMA="$VENV/Scripts/sigma.exe"
  if [[ ! -x "$SIGMA" ]]; then
    blue "==> Setting up Sigma toolchain venv ($VENV)"
    python3 -m venv "$VENV"
    PY="$VENV/bin/python"; [[ -x "$PY" ]] || PY="$VENV/Scripts/python.exe"
    "$PY" -m pip install -q --disable-pip-version-check sigma-cli pysigma-backend-elasticsearch
    SIGMA="$VENV/bin/sigma"; [[ -x "$SIGMA" ]] || SIGMA="$VENV/Scripts/sigma.exe"
  fi
fi
green "    sigma: $("$SIGMA" version 2>/dev/null | tail -1)"

# --- 2. Select rules by promotion status, then convert -----------------------
# WS2.1 promotion gate: only deploy rules that have passed the test/stable gate
# (tests/detections/). `experimental` rules are excluded unless --include-experimental.
RULES=()
for f in "$RULES_DIR"/*.yml; do
  st="$(grep -m1 '^status:' "$f" | awk '{print $2}' | tr -d '[:space:]')"
  if [[ "$st" == "stable" || "$st" == "test" || "$INCLUDE_EXPERIMENTAL" == "1" ]]; then
    RULES+=("$f")
  fi
done
[[ ${#RULES[@]} -gt 0 ]] || { red "ERROR: no rules selected (all experimental? use --include-experimental)."; exit 1; }
blue "==> Converting ${#RULES[@]} Sigma rule(s) [status test/stable$([[ $INCLUDE_EXPERIMENTAL == 1 ]] && echo '+experimental')] -> Elastic detection rules"
RAW="$(mktemp)"; NDJSON="$(mktemp)"; ERR="$(mktemp)"
trap 'rm -f "$RAW" "$NDJSON" "$ERR"' EXIT
# sigma convert is all-or-nothing: ONE invalid rule fails the whole batch, so we
# surface its stderr rather than swallowing it. JSON rule lines start with '{';
# the "Parsing Sigma rules" progress lines do not.
"$SIGMA" convert -t lucene -f siem_rule_ndjson -p "$PIPELINE" "${RULES[@]}" 2>"$ERR" \
  | grep '^{' > "$RAW" || true
count=$(wc -l < "$RAW" | tr -d ' ')
if [[ "${count:-0}" -eq 0 ]]; then
  red "ERROR: conversion produced 0 rules. sigma reported:"
  grep -iE 'error|unknown|invalid' "$ERR" | head -10 | sed 's/^/    /'
  exit 1
fi

# --- 3. Point each rule at our data index (logstash-*) + honour --no-enable ---
# Read stdin / write stdout (bash handles the redirections) so no temp path is
# passed to the interpreter — portable across shells.
ENABLE="$ENABLE" DETECTION_INDEX="$DETECTION_INDEX" python3 - < "$RAW" > "$NDJSON" <<'PY'
import json, os, sys
idx = os.environ["DETECTION_INDEX"].split(",")
enable = os.environ["ENABLE"] == "1"
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    r["index"] = idx
    r["enabled"] = enable
    print(json.dumps(r))
PY
green "    converted $count rules (index=$DETECTION_INDEX, enabled=$([[ $ENABLE -eq 1 ]] && echo true || echo false))"

# --- 4. Import into the Kibana Detection Engine (idempotent) -----------------
blue "==> Importing detection rules into the Kibana Detection Engine"
# Ensure the signals/alerts index exists first (no-op if already created).
curl -s -o /dev/null -u "${ES_USER}:${ES_PASS}" -X POST \
  "${KIBANA_URL}/api/detection_engine/index" -H 'kbn-xsrf: true' || true
resp=$(curl -s -u "${ES_USER}:${ES_PASS}" -X POST \
  "${KIBANA_URL}/api/detection_engine/rules/_import?overwrite=true" \
  -H 'kbn-xsrf: true' --form "file=@${NDJSON};type=application/ndjson" || true)

echo "$resp" | python3 -c "
import sys, json
try: d = json.load(sys.stdin)
except Exception: print('    RAW:', sys.stdin.read()[:300]); sys.exit(1)
ok = d.get('success')
print(f\"    success={ok}  imported={d.get('success_count')}  errors={len(d.get('errors',[]))}\")
for e in d.get('errors', [])[:5]:
    print('      error:', e.get('rule_id'), '-', str(e.get('error',{}).get('message'))[:160])
sys.exit(0 if ok else 2)
"
rc=$?

echo
if [[ $rc -eq 0 ]]; then
  green "=== Detection rules deployed. View/triage in Kibana → Security → Rules / Alerts. ==="
else
  red   "=== Detection rule import reported errors (see above). ==="
fi
exit $rc
