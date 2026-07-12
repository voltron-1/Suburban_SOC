# Audit-Write Failure Visibility — Design Spec

**Issue:** [#184](https://github.com/voltron-1/Suburban_SOC/issues/184) (follow-up to #165)
**Date:** 2026-07-12
**Status:** Approved, ready for implementation plan

## Problem

`write_audit()` in `scripts/setup/ai_agent/agent_app.py` appends a tamper-evident record to
`soc-audit-<tenant>` for every privileged decision the SOC agent makes. It has a correct,
intentional "never raise" contract — auditing must not break alert handling — so ES write
failures are caught and logged, never propagated. But today that's *all* that happens: a log
line at `ERROR` level, with no counter, metric, or dashboard signal. Nothing distinguishes "one
audit write failed transiently" from "the compliance audit trail has been silently blank for six
hours." An operator would only discover a sustained failure by grepping raw logs.

## Goals

- Make a *sustained* run of audit-write failures visible outside raw logs (dashboard/alert), without
  paging on a single transient blip.
- Preserve `write_audit()`'s "never raise" contract exactly as-is.
- Reuse existing architecture and conventions rather than introducing a new subsystem.

## Non-goals

- Solving total-ES-outage visibility — already covered by `stack_health.sh`'s ES healthcheck and
  `slo_metrics.py`'s `ingest_lag_seconds` (`BREACH_IF_NA`).
- A new authenticated/unauthenticated HTTP endpoint on the agent. Considered and rejected — see
  Alternatives.
- Retention/ILM policy for the new index. Expected volume is low (failures should be rare); revisit
  only if that assumption breaks.

## Design

### 1. Failure-marker write in `write_audit()`

`write_audit()`'s existing `except` block gains one addition: a best-effort write of a minimal
marker doc to a new per-tenant index, `soc-agent-health-<tenant>`, mirroring `soc-audit-<tenant>`'s
own naming and `_bulk`-with-`create`-op shape (same tenant scoping the function already has).

Doc shape:

```json
{
  "@timestamp": "<now, UTC ISO8601>",
  "tenant.id": "<tenant>",
  "event.action": "audit_write_failed",
  "target_action": "<the action write_audit was originally called for>",
  "error": "<str(exception)>"
}
```

This write is wrapped in its **own** nested `try/except`. If it also fails (e.g. total ES outage),
log at `WARNING` (the primary failure is already logged at `ERROR`; this is a secondary, expected-
possible event) and return — no retry chain, no further fallback.

### 2. ES role change

The agent authenticates as `logstash_internal` (role `logstash_writer`) for all its ES writes,
including the existing `soar-actions-<tenant>` stream. `logstash_writer`'s `indices` grant in
`docker-compose.yml`'s `provision` service gets `"soc-agent-health-*"` added alongside the existing
`"logstash-*"`/`"soar-actions-*"` patterns. No new user, role, or password — this data isn't
sensitive/tamper-critical the way the audit trail itself is (that's exactly why it's fine to share
the less-restrictive `create+write` role rather than get its own `soc_audit_appender`-style
create-only role).

### 3. New SLO metric

`slo_metrics.py` gains `metric_audit_write_failures()`, using the existing `_count()` helper against
`soc-agent-health-*` with a `match_all` query over the existing `WINDOW` (`now-7d` default) — nothing
else ever writes to that index, so every doc in it *is* a failure, no extra filter needed. A
wildcard `_count` against zero matching indices (the common case — no failures ever) returns `0`
successfully; it does not error the way an exact non-existent index name would.

Wired in exactly like the other five metrics:

- `TARGETS["audit_write_failures"] = float(os.environ.get("SLO_AUDIT_WRITE_FAIL_MAX", "3"))`
- `LOWER_BETTER["audit_write_failures"] = True`
- **Not** added to `BREACH_IF_NA` — an unmeasurable *query failure* still raises `MetricUnavailable`
  via `_count()`'s existing exception handling (same as every other metric), but a genuine zero-count
  result is a legitimate "good" value, not an unmeasurable one.
- Added to the `metric_fns` dict in `main()`.

That's the entire dashboard/alerting integration: `main()` already handles breach evaluation,
indexing to `soc-slo-metrics`, and the ntfy alert generically for anything in `metric_fns`. Target
of `3` means a single transient failure doesn't breach; three or more within the rolling window
does — resolves the "transient vs. sustained" distinction from the issue directly.

## Testing

New file `tests/ai_agent/test_audit_write_health.py` (no existing file tests `write_audit()`'s own
behavior — it's only ever mocked away as a no-op dependency in other tests):

- Simulate an ES write failure (mock `requests.post` to raise) and assert the health-marker write
  is attempted with the expected shape.
- Simulate **both** writes failing and assert the function still returns normally (doesn't raise) —
  the core acceptance criterion.
- `metric_audit_write_failures()`: mirrors the existing `MetricFunctionTests` pattern in
  `test_slo_metrics.py` — raises `MetricUnavailable` on a query failure, returns the correct count
  on success.
- A breach-threshold test: 2 failures in the window does not breach; 3 does (matches
  `SLO_AUDIT_WRITE_FAIL_MAX` default).

## Alternatives considered

**In-process counter + new `/health` endpoint polled by `slo_metrics.py`.** Simpler code-wise (no
new ES role/index), and the issue's own suggested remediation. Rejected as the primary approach:
the counter resets to zero on every container restart/redeploy — for a compliance-audit-trail
visibility feature, a redeploy silently masking a sustained failure run is a worse failure mode than
the one being fixed. Also introduces a new inter-service HTTP dependency (`slo_metrics.py` → agent
`:5000`) that doesn't exist today, whereas every existing SLO metric already queries ES directly.

**Dedicated least-privilege ES user/role** (mirroring `hive_mind_broker`/`slo_metrics` in #167/#171).
More consistent with this project's least-privilege philosophy in the abstract, but adds a new
password env var and provisioning block for a low-sensitivity liveness signal. Rejected in favor of
extending the existing `logstash_writer` grant — the agent already holds broader write access than
this new index needs, so a new role buys no real isolation here.

## Files touched (expected)

- `scripts/setup/ai_agent/agent_app.py` — `write_audit()` addition
- `scripts/setup/ai_agent/slo_metrics.py` — new metric function + wiring
- `scripts/setup/docker-compose.yml` — `logstash_writer` role index grant
- `tests/ai_agent/test_slo_metrics.py` — new metric tests
- `tests/ai_agent/test_audit_write_health.py` (new) — `write_audit()` dual-failure behavior
