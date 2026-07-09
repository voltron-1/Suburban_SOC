#!/usr/bin/env bash
# =============================================================================
# refresh_intel.sh — auto-refresh the Zeek threat-intel feed (WS1.3).
#
# Replaces the 2 static intel.dat entries with a LIVE, keyless feed (abuse.ch
# Feodo Tracker botnet-C2 IPs by default) merged with the curated seed
# (intel.seed.dat — always includes the WS1.1 test indicators). Writes the Zeek
# Intel framework format, and indexes both the indicators and a freshness/heartbeat
# doc into Elasticsearch so the dashboard can show feed age and alert when stale.
#
# Fail-safe: a fetch failure NEVER empties the feed — the seed (and the previous
# intel.dat) are preserved — but the run records status=stale and exits non-zero so
# cron/monitoring catches it.
#
# Schedule (cron, every 6h):
#   0 */6 * * * /home/<you>/projects/Suburban-SOC/configs/intel/refresh_intel.sh >> /var/log/suburban-soc-intel.log 2>&1
#
# Env (auto-loaded from scripts/setup/.env): ES_URL (https://localhost:9200),
#   ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD. Feeds overridable via FEODO_URL.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

# These serve the no-ES path: the if-block below only indexes when ES_PASS is set,
# and es_common.sh (sourced inside that block) re-resolves the same three vars.
ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

FEODO_URL="${FEODO_URL:-https://feodotracker.abuse.ch/downloads/ipblocklist.txt}"
SEED="$HERE/intel.seed.dat"
OUT="$HERE/intel.dat"
# If the live capture's bind-mount path exists, refresh it too so running Zeek
# picks up the new feed on its next read without a manual re-sync.
LIVE_DIR="/storage/PCAP/intel"

IPV4_RE='^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '[intel] %s %s\n' "$(ts)" "$*"; }

tmp="$(mktemp)"; tmp_ips="$(mktemp)"
trap 'rm -f "$tmp" "$tmp_ips"' EXIT

# --- 1. Fetch the live feed (fail-safe) --------------------------------------
# Capture to stdout (portable across curl flavors) rather than -o <file>.
status="ok"; feodo_count=0
if raw="$(curl -fsS --max-time 30 "$FEODO_URL" 2>/dev/null)" && [[ -n "$raw" ]]; then
  # Keep only valid IPv4 lines (strip comments/blanks/CRs).
  printf '%s\n' "$raw" | grep -vE '^\s*#|^\s*$' | tr -d '\r' | awk '{print $1}' \
    | grep -E "$IPV4_RE" | sort -u > "$tmp_ips" || true
  # tmp_ips now holds only clean unique IPs, so wc -l is the count (grep -c both
  # prints AND exits non-zero on empty, which would corrupt the value).
  feodo_count=$(wc -l < "$tmp_ips" | tr -d ' ')
  log "fetched $feodo_count IPs from Feodo Tracker"
else
  status="stale"
  : > "$tmp_ips"
  log "WARN: Feodo fetch failed/empty ($FEODO_URL) — keeping seed + previous feed only"
fi

# --- 2. Build the Zeek Intel .dat (seed + live), atomically ------------------
{
  printf '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n'
  # Curated seed (skip its header/comment lines).
  grep -vE '^\s*#|^\s*$' "$SEED"
  # Live Feodo IPs as Intel::ADDR.
  while IFS= read -r ip; do
    [[ -n "$ip" ]] && printf '%s\tIntel::ADDR\tabuse.ch/Feodo\tBotnet C2 IP (auto)\n' "$ip"
  done < "$tmp_ips"
} > "$tmp"

# De-dupe on the indicator column while preserving the header.
{ head -1 "$tmp"; tail -n +2 "$tmp" | sort -u -t$'\t' -k1,1; } > "${tmp}.dedup"
mv "${tmp}.dedup" "$tmp"

total=$(($(grep -cvE '^\s*#' "$tmp") ))
mv "$tmp" "$OUT"
log "wrote $OUT ($total indicators: $feodo_count live + seed)"
if [[ -d "$LIVE_DIR" ]]; then
  cp "$OUT" "$LIVE_DIR/intel.dat" 2>/dev/null && log "synced live feed -> $LIVE_DIR/intel.dat" \
    || log "NOTE: could not write $LIVE_DIR (permissions?) — re-run the capture sync"
fi

# --- 3. Index indicators + a freshness heartbeat into Elasticsearch ----------
if [[ -n "$ES_PASS" ]]; then
  # No hardcoded Content-Type — each call sets its own (bulk=x-ndjson, doc=json),
  # so we never send two Content-Type headers (ES rejects that).
  # Shared ES creds + TLS + es()/es_bulk() (issue #156). Sourced inside the
  # `if [[ -n "$ES_PASS" ]]` block so the feed refresh still runs without ES creds.
  # shellcheck source=../../scripts/setup/lib/es_common.sh
  source "$HERE/../../scripts/setup/lib/es_common.sh"
  # 3a. Upsert each indicator (_id = indicator) into threat-intel-indicators so
  #     re-runs don't duplicate; ECS threat.indicator.* + threat.feed.name.
  bulk="$(mktemp)"
  now="$(ts)"
  # No python/jq dependency: indicators are validated IPv4/domains and the type/feed
  # are fixed strings, so they embed in JSON safely without escaping.
  grep -vE '^\s*#|^\s*$' "$OUT" | while IFS=$'\t' read -r ind itype isrc _; do
    [[ -z "$ind" ]] && continue
    if [[ "$itype" == "Intel::ADDR" ]]; then field="ip"; else field="domain"; fi
    printf '{"index":{"_index":"threat-intel-indicators","_id":"%s"}}\n' "$ind"
    printf '{"@timestamp":"%s","threat":{"indicator":{"%s":"%s","type":"%s"},"feed":{"name":"%s"}}}\n' \
      "$now" "$field" "$ind" "$itype" "$isrc"
  done > "$bulk"
  if [[ -s "$bulk" ]]; then
    # Pipe via stdin (@-) rather than @file for portability across curl flavors.
    es -X POST "$ES_URL/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @- -o /dev/null -w '' < "$bulk" 2>/dev/null
    log "indexed $total indicators into threat-intel-indicators"
  fi
  rm -f "$bulk"
  # 3b. Heartbeat doc for the freshness panel / stale-feed alert.
  es -X POST "$ES_URL/threat-intel-meta/_doc" -H 'Content-Type: application/json' -o /dev/null -w '' \
    -d "{\"@timestamp\":\"$now\",\"feed\":{\"name\":\"abuse.ch/Feodo\"},\"indicator_count\":$total,\"live_count\":$feodo_count,\"status\":\"$status\"}" 2>/dev/null
  log "recorded freshness heartbeat (status=$status)"
else
  log "NOTE: ES_PASS unset — skipped ES indexing (feed file still updated)"
fi

[[ "$status" == "ok" ]] && exit 0 || exit 2
