#!/usr/bin/env bash
# =============================================================================
# deploy_changelog.sh — WS3.5: record every deploy (change management evidence).
#
# Appends a timestamped, git-pinned entry to docs/deploy-changelog.md and (if ES is
# reachable) indexes it to the immutable `soc-deploys` index — so every change that
# reaches prod is recorded with what/when/who/commit (SOC 2 change management).
#
# Called by the deploy scripts:  ./deploy_changelog.sh "<component>" "<summary>"
# Env (auto-loaded from scripts/setup/.env): ES_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD.
# =============================================================================
set -uo pipefail
COMPONENT="${1:-unknown}"
SUMMARY="${2:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GITREV="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
ACTOR="$(git -C "$REPO_ROOT" config user.name 2>/dev/null || echo "${USER:-unknown}")"
LOG="$REPO_ROOT/docs/deploy-changelog.md"

# 1. Markdown changelog (created with a header on first run).
if [[ ! -f "$LOG" ]]; then
  printf '# Deployment Changelog (WS3.5)\n\nEvery deploy is recorded here (auto-appended by deploy_changelog.sh).\n\n| UTC time | component | commit | actor | summary |\n|---|---|---|---|---|\n' > "$LOG"
fi
printf '| %s | %s | `%s` | %s | %s |\n' "$TS" "$COMPONENT" "$GITREV" "$ACTOR" "$SUMMARY" >> "$LOG"
echo "    changelog: recorded $COMPONENT @ $GITREV"

# 2. Immutable ES record (best-effort).
if [[ -n "$ES_PASS" && -f "$HERE/lib/es_common.sh" ]]; then
  # Shared ES creds + TLS + es helpers (issue #156); sourced inside the if so the
  # markdown changelog still writes without ES creds (and without the lib present).
  source "$HERE/lib/es_common.sh"
  esj -m 6 -o /dev/null -X POST "$ES_URL/soc-deploys/_doc" \
    -d "{\"@timestamp\":\"$TS\",\"component\":\"$COMPONENT\",\"commit\":\"$GITREV\",\"actor\":\"$ACTOR\",\"summary\":\"$SUMMARY\"}" 2>/dev/null || true
fi
