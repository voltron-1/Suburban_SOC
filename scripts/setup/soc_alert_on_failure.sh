#!/usr/bin/env bash
# =============================================================================
# soc_alert_on_failure.sh — OnFailure= alert dispatcher for the SOC self-health
# lane (#554).
#
# Wired via `OnFailure=soc-alert-on-failure@%n.service` on slo-metrics.service
# and zeek-host-capture.service (see
# configs/systemd/soc-alert-on-failure@.service) so a unit that fails before
# its own body ever runs — e.g. an ExecStartPre credential check or CA-pin
# mismatch — still produces something off the host, not just a journal line
# nobody is watching.
#
# Deliberately depends on neither Docker nor Elasticsearch: those are exactly
# what slo-metrics.service and zeek-host-capture.service report on, and a
# delivery path sharing their dependency would go dark in the same outage it
# exists to report.
#
# Rate limit (#567): OnFailure= fires on every restart cycle, not once when a unit
# gives up, so this script governs its own output. One push per failed unit per
# SOC_ALERT_COOLDOWN_SECONDS (default 3600 = at most 24/day per unit, however fast the
# unit restarts). Failures inside the cooldown are counted, not dropped: the next
# push says how many were suppressed. State is one small file per unit under
# $STATE_DIRECTORY (set by the template unit's StateDirectory=). Any state-dir problem
# fails OPEN -- the alert is sent unthrottled rather than lost.
#
# Usage: soc_alert_on_failure.sh <failed-unit-name>
#   (systemd supplies this via the "@%n.service" instance name on the
#   OnFailure= directive, which the template unit passes through as %i.)
# =============================================================================
set -uo pipefail

FAILED_UNIT="${1:?usage: soc_alert_on_failure.sh <failed-unit-name>}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
NTFY_TOPIC="${NTFY_TOPIC:-}"

if [[ -z "$NTFY_TOPIC" ]]; then
  # #554: an unset sink must be visible, not a silently-successful no-op. Exit 0
  # rather than failing this unit itself, though — slo_metrics.py's own startup
  # warning (also #554) already flags the missing topic on every 15-minute run;
  # a second alarm for the same root cause from the dispatcher that can't reach
  # ntfy in the first place would just be noise layered on the same gap.
  echo "soc_alert_on_failure: NTFY_TOPIC is unset -- cannot deliver alert for ${FAILED_UNIT}" >&2
  exit 0
fi

COOLDOWN="${SOC_ALERT_COOLDOWN_SECONDS:-3600}"
[[ "$COOLDOWN" =~ ^[0-9]+$ ]] || COOLDOWN=3600
STATE_DIR="${STATE_DIRECTORY:-${SOC_ALERT_STATE_DIR:-}}"
STATE_DIR="${STATE_DIR%%:*}"   # systemd joins multiple StateDirectory= entries with ':'

STATE_FILE=""
SUPPRESSED=0
if [[ -n "$STATE_DIR" ]] && mkdir -p "$STATE_DIR" 2>/dev/null && [[ -w "$STATE_DIR" ]]; then
  # Per-unit key, so two failing units never share a cooldown. Sanitised: the unit
  # name comes from systemd, but it ends up in a path.
  STATE_FILE="$STATE_DIR/$(printf '%s' "$FAILED_UNIT" | tr -c 'A-Za-z0-9_.@-' '_').state"
  # Serialise concurrent instances of the same unit (read-decide-write must be atomic).
  exec 9>"$STATE_FILE.lock" && command -v flock >/dev/null 2>&1 && flock -w 5 9 || true

  NOW="$(date +%s)"
  LAST=0
  if [[ -r "$STATE_FILE" ]]; then
    read -r LAST SUPPRESSED < "$STATE_FILE" || true
  fi
  [[ "$LAST" =~ ^[0-9]+$ ]] || LAST=0
  [[ "$SUPPRESSED" =~ ^[0-9]+$ ]] || SUPPRESSED=0

  if (( NOW - LAST < COOLDOWN )); then
    SUPPRESSED=$((SUPPRESSED + 1))
    printf '%s %s\n' "$LAST" "$SUPPRESSED" > "$STATE_FILE" 2>/dev/null || true
    echo "soc_alert_on_failure: ${FAILED_UNIT} failed again inside the ${COOLDOWN}s cooldown -- suppressed (${SUPPRESSED} so far)" >&2
    exit 0
  fi
else
  echo "soc_alert_on_failure: no writable state directory -- sending ${FAILED_UNIT} alert without rate limiting" >&2
fi

BODY="SOC unit failed: ${FAILED_UNIT} -- journalctl -u ${FAILED_UNIT}"
if (( SUPPRESSED > 0 )); then
  BODY="${BODY} (${SUPPRESSED} further failure(s) suppressed since the last alert)"
fi

# Same call shape as stack_health.sh's own ntfy push: -s/-m bound the call, the
# push itself is best-effort (a dead network path here must not turn one failed
# unit into two).
if curl -s -m 10 -o /dev/null "https://ntfy.sh/${NTFY_TOPIC}" \
     -H "Title: Suburban-SOC unit failure" -H "Priority: high" -H "Tags: rotating_light" \
     -d "$BODY" 2>/dev/null; then
  # Start the cooldown only after a push actually left the host; a failed push is
  # retried by the next failure instead of being silenced for an hour.
  [[ -n "$STATE_FILE" ]] && { printf '%s 0\n' "$(date +%s)" > "$STATE_FILE" 2>/dev/null || true; }
fi
exit 0
