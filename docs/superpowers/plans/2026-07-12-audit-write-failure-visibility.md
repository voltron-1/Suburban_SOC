# Audit-Write Failure Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a *sustained* run of SOC-agent audit-write failures visible on the SLO dashboard without changing `write_audit()`'s "never raise" contract.

**Architecture:** `write_audit()`'s existing `except` block gains a call to a new helper that best-effort-writes a failure-marker doc to a new per-tenant ES index (`soc-agent-health-<tenant>`). `slo_metrics.py` gains a new metric that counts those docs over its existing rolling window and plugs into its existing generic breach/alert/dashboard-index machinery — no new endpoint, no new dashboard code.

**Tech Stack:** Python 3.12 (Flask agent), Elasticsearch 9.3.2, pytest/unittest, Docker Compose.

## Global Constraints

- `write_audit()`'s "never raise" contract must hold under **any** combination of failures (spec, Goals section).
- The new index write reuses the agent's existing `logstash_internal` ES credential — no new user/role/password (spec, Design §2 + user's explicit choice during brainstorming).
- Breach threshold: 1-2 failures in the rolling window tolerated, 3+ breaches, overridable via `SLO_AUDIT_WRITE_FAIL_MAX` (spec, Design §3 + user's explicit choice during brainstorming). **Note:** Task 3 below originally specified a target default of `"3"`, which — combined with `main()`'s existing strict `val > target` comparator — would actually have meant "breach only above 3" (4+), not "3+". This was caught during implementation (see Task 3's fix-round commits) and corrected to a target default of `"2"`, which combined with the same comparator correctly means "3+ breaches." The shipped code uses `"2"`; treat the `"3"` appearing in Task 3's original step-by-step text below as superseded.
- No new dashboard panel, endpoint, or ILM policy — out of scope (spec, Non-goals).
- Reference spec: `docs/superpowers/specs/2026-07-12-audit-write-failure-visibility-design.md`.

---

### Task 1: Audit-write failure marker in `agent_app.py`

**Files:**
- Modify: `scripts/setup/ai_agent/agent_app.py:784-808` (`write_audit`)
- Create: `tests/ai_agent/test_audit_write_health.py`

**Interfaces:**
- Consumes: existing module globals `ES_HOST`, `ES_USER`, `ES_PASS`, `ES_VERIFY` (all defined at `agent_app.py:75-85`); existing `app.logger`; existing `requests`, `json`, `datetime`/`timezone` imports.
- Produces: new function `_write_audit_health_marker(action: str, tenant: str, error: Exception) -> None` — no return value, never raises. Later tasks do not depend on this (it's only called internally by `write_audit`).

- [ ] **Step 1: Write the failing tests**

Create `tests/ai_agent/test_audit_write_health.py`:

```python
#!/usr/bin/env python3
"""
Audit-write failure visibility tests (issue #184).

write_audit()'s ES write failures must never propagate (auditing must not break
alert handling) — but a failure now also writes a best-effort marker doc to
soc-agent-health-<tenant> so a SUSTAINED run of failures is dashboard-visible
(via slo_metrics.py's metric_audit_write_failures()), not just a log line.

Run:  pytest tests/ai_agent/test_audit_write_health.py
"""

import os
import sys
import types
import unittest
from unittest import mock

os.environ["SOC_AGENT_HMAC_SECRET"] = "unit_test_secret"

_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}  # type: ignore[attr-defined]
sys.modules["weekly_ciso_report"] = _stub

import agent_app  # noqa: E402


class WriteAuditHealthMarkerTests(unittest.TestCase):
    def test_health_marker_written_on_audit_write_failure(self):
        with mock.patch.object(agent_app.requests, "post",
                               side_effect=ConnectionError("refused")) as m:
            agent_app.write_audit("quarantine_mac", "system", "acme-corp",
                                   outcome="success", target="AA:BB:CC:DD:EE:FF")
        # Two POST attempts: the original audit write, then the health marker.
        self.assertEqual(m.call_count, 2)
        marker_args, marker_kwargs = m.call_args_list[1]
        self.assertEqual(marker_args[0],
                         f"{agent_app.ES_HOST}/soc-agent-health-acme-corp/_bulk")
        self.assertIn('"event.action": "audit_write_failed"', marker_kwargs["data"])
        self.assertIn('"target_action": "quarantine_mac"', marker_kwargs["data"])
        self.assertIn('"tenant.id": "acme-corp"', marker_kwargs["data"])

    def test_write_audit_never_raises_even_if_health_marker_also_fails(self):
        # Core acceptance criterion: BOTH writes failing must not raise.
        with mock.patch.object(agent_app.requests, "post",
                               side_effect=ConnectionError("refused")):
            try:
                agent_app.write_audit("quarantine_mac", "system", "acme-corp")
            except Exception as e:
                self.fail(f"write_audit() raised unexpectedly: {e}")

    def test_health_marker_not_written_on_audit_write_success(self):
        with mock.patch.object(agent_app.requests, "post") as m:
            agent_app.write_audit("quarantine_mac", "system", "acme-corp")
        # Only the original audit write — no marker needed when it succeeds.
        self.assertEqual(m.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ai_agent/test_audit_write_health.py -v`
Expected: FAIL — `test_health_marker_written_on_audit_write_failure` and `test_health_marker_not_written_on_audit_write_success` fail on `self.assertEqual(m.call_count, 2)` / `1` (currently always 1, no marker logic exists yet). `test_write_audit_never_raises_even_if_health_marker_also_fails` passes already (existing code already doesn't raise) — that's fine, it's a regression guard for the change about to be made.

- [ ] **Step 3: Implement the marker-write helper and wire it into `write_audit()`**

Replace `scripts/setup/ai_agent/agent_app.py:784-808` (the current `write_audit` function) with:

```python
def write_audit(action, actor, tenant, outcome="", target="", detail=""):
    """Append a tamper-evident audit record (who/what/when/tenant) to soc-audit-<tenant>.

    The agent's ES account holds the append-only `soc_audit_appender` role (create
    privilege only — no update/delete), so it can ADD audit records but never modify
    or remove them. Every quarantine/response decision is recorded. Failures are
    logged, never raised — auditing must not break alert handling.
    """
    doc = {
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
        "event.action":  action,
        "actor":         actor,
        "tenant.id":     tenant,
        "event.outcome": outcome,
        "target":        target,
        "detail":        detail,
    }
    # op_type=create (append-only) via the bulk create form.
    ndjson = '{"create":{}}\n' + json.dumps(doc) + "\n"
    try:
        requests.post(f"{ES_HOST}/soc-audit-{tenant}/_bulk", data=ndjson,
                      headers={"Content-Type": "application/x-ndjson"},
                      auth=(ES_USER, ES_PASS), verify=ES_VERIFY, timeout=5)
    except Exception as e:  # noqa: BLE001
        app.logger.error("Failed to write audit record: %s", e)
        _write_audit_health_marker(action, tenant, e)


def _write_audit_health_marker(action, tenant, error):
    """Best-effort dashboard-visible signal for a failed audit write (#184).

    A single failure doc in soc-agent-health-<tenant>; slo_metrics.py counts these
    over its rolling window so a SUSTAINED run of failures breaches an SLO (and
    alerts), while a one-off transient blip does not. Must never raise itself — if
    this ALSO fails (e.g. total ES outage), that's already caught by
    stack_health.sh / the ingest-lag SLO, not this function's job to escalate further.
    """
    doc = {
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
        "tenant.id":     tenant,
        "event.action":  "audit_write_failed",
        "target_action": action,
        "error":         str(error),
    }
    ndjson = '{"create":{}}\n' + json.dumps(doc) + "\n"
    try:
        requests.post(f"{ES_HOST}/soc-agent-health-{tenant}/_bulk", data=ndjson,
                      headers={"Content-Type": "application/x-ndjson"},
                      auth=(ES_USER, ES_PASS), verify=ES_VERIFY, timeout=5)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("Failed to write audit-write-failure health marker: %s", e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ai_agent/test_audit_write_health.py -v`
Expected: PASS (3/3)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ -q`
Expected: all tests pass (145 existing + 3 new = 148). `test_alert_auth.py`/`test_notify_masking.py` mock `write_audit` entirely, so they're unaffected by this change.

- [ ] **Step 6: Commit**

```bash
cd /home/tjlam/projects/Suburban-SOC
git add scripts/setup/ai_agent/agent_app.py tests/ai_agent/test_audit_write_health.py
git commit -m "feat(#184): write a health-marker doc when write_audit() fails

write_audit()'s 'never raise' contract is unchanged — the new marker write
is itself wrapped in its own try/except. Lays the groundwork for a
dashboard-visible SLO metric (next commit) rather than a log-grep-only signal."
```

---

### Task 2: Grant the agent's ES role write access to the new index

**Files:**
- Modify: `configs/elasticsearch/roles/logstash_writer.json`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: ES role grant that Task 4's live verification and Task 3's metric queries both depend on being applied to the running stack.

- [ ] **Step 1: Edit the role definition**

Current content of `configs/elasticsearch/roles/logstash_writer.json`:

```json
{
  "cluster": ["monitor","manage_index_templates","manage_ilm"],
  "indices": [
    {"names": ["logstash-*","soar-actions-*","asset-inventory-*"],
     "privileges": ["create_index","create","write","manage"]}
  ]
}
```

Replace with:

```json
{
  "cluster": ["monitor","manage_index_templates","manage_ilm"],
  "indices": [
    {"names": ["logstash-*","soar-actions-*","asset-inventory-*","soc-agent-health-*"],
     "privileges": ["create_index","create","write","manage"]}
  ]
}
```

Note: this file — not the inline bootstrap JSON in `docker-compose.yml`'s `provision` service (line 171) — is the actual source of truth. The `roles` service (`docker-compose.yml`, applies `configs/elasticsearch/roles/*.json` after `provision` runs) overwrites whatever the inline bootstrap created; the two are documented as already having drifted (`docker-compose.yml:356-361`), and this project's convention is to only maintain the `roles/*.json` files going forward, not re-sync the inline bootstrap. Do not edit `docker-compose.yml:171`.

- [ ] **Step 2: Verify the JSON is valid**

Run: `cd /home/tjlam/projects/Suburban-SOC && python3 -c "import json; json.load(open('configs/elasticsearch/roles/logstash_writer.json'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
cd /home/tjlam/projects/Suburban-SOC
git add configs/elasticsearch/roles/logstash_writer.json
git commit -m "feat(#184): grant logstash_writer role write access to soc-agent-health-*

Reuses the agent's existing logstash_internal credential rather than a new
dedicated user — this data isn't sensitive/tamper-critical like the audit
trail itself. Applied to the running stack in the live-verification task."
```

---

### Task 3: `metric_audit_write_failures()` in `slo_metrics.py`

**Files:**
- Modify: `scripts/setup/ai_agent/slo_metrics.py:50-68` (`TARGETS`/`LOWER_BETTER`/`BREACH_IF_NA`), and after `metric_parse_error_pct` (~line 199), and `main()`'s `metric_fns` dict (~line 207)
- Modify: `tests/ai_agent/test_slo_metrics.py`

**Interfaces:**
- Consumes: existing `_count(index, query)` helper (`slo_metrics.py:104-112`), existing `WINDOW` global (`slo_metrics.py:48`).
- Produces: `metric_audit_write_failures() -> float` — raises `MetricUnavailable` on a real query failure (same contract as every other `metric_*` function); not consumed by any later task in this plan.

- [ ] **Step 1: Write the failing tests**

In `tests/ai_agent/test_slo_metrics.py`, add to `MetricFunctionTests` as the last three methods in the class — after `test_parse_error_pct_propagates_count_failure` (the class's last existing method, ending at line 149) and before the blank line/`class EsKbWrapperTests` boundary at line 152:

```python
    def test_audit_write_failures_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_audit_write_failures()

    def test_audit_write_failures_returns_count_on_success(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 5})):
            self.assertEqual(slo_metrics.metric_audit_write_failures(), 5)

    def test_audit_write_failures_returns_zero_when_healthy(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics.metric_audit_write_failures(), 0)
```

Then update `MainExitCodeTests._mock_all_metrics` to accept and mock the new metric (existing default of `0.0` preserves every current caller's behavior unchanged):

```python
    def _mock_all_metrics(self, mttd=0.0, mttr=0.0, coverage=12.0, fp_pct=0.0,
                           ingest_lag=10.0, parse_err=0.0, audit_write_failures=0.0):
        return [
            mock.patch.object(slo_metrics, "metric_mttd", return_value=mttd),
            mock.patch.object(slo_metrics, "metric_mttr", return_value=mttr),
            mock.patch.object(slo_metrics, "metric_coverage", return_value=coverage),
            mock.patch.object(slo_metrics, "metric_false_positive_pct", return_value=fp_pct),
            mock.patch.object(slo_metrics, "metric_ingest_lag_seconds", return_value=ingest_lag),
            mock.patch.object(slo_metrics, "metric_parse_error_pct", return_value=parse_err),
            mock.patch.object(slo_metrics, "metric_audit_write_failures",
                               return_value=audit_write_failures),
            mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(200, {})),
        ]
```

Add a new test to `MainExitCodeTests` (after `test_breach_detected_exits_2_and_sends_ntfy`) for the breach threshold itself:

```python
    def test_audit_write_failures_below_threshold_does_not_breach(self):
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(audit_write_failures=2.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_audit_write_failures_at_threshold_breaches(self):
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(audit_write_failures=3.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        self.assertIn("audit_write_failures", ntfy_post.call_args.kwargs["data"].decode())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ai_agent/test_slo_metrics.py -v`
Expected: FAIL — `metric_audit_write_failures` doesn't exist yet (`AttributeError`), so every new test fails, and `_mock_all_metrics`'s new `mock.patch.object(slo_metrics, "metric_audit_write_failures", ...)` also fails to resolve the attribute.

- [ ] **Step 3: Implement the metric and wire it in**

In `scripts/setup/ai_agent/slo_metrics.py`, change `TARGETS` (currently lines 50-57) to add one line:

```python
TARGETS = {
    "mttd_minutes":        float(os.environ.get("SLO_MTTD_MAX_MIN", "30")),
    "mttr_minutes":        float(os.environ.get("SLO_MTTR_MAX_MIN", "5")),
    "coverage_techniques": float(os.environ.get("SLO_COVERAGE_MIN", "10")),
    "false_positive_pct":  float(os.environ.get("SLO_FP_MAX_PCT", "10")),
    "ingest_lag_seconds":  float(os.environ.get("SLO_INGEST_LAG_MAX_S", "300")),
    "parse_error_pct":     float(os.environ.get("SLO_PARSE_ERR_MAX_PCT", "1")),
    "audit_write_failures": float(os.environ.get("SLO_AUDIT_WRITE_FAIL_MAX", "3")),
}
```

Change `LOWER_BETTER` (currently lines 59-62) to add one entry:

```python
LOWER_BETTER = {
    "mttd_minutes": True, "mttr_minutes": True, "coverage_techniques": False,
    "false_positive_pct": True, "ingest_lag_seconds": True, "parse_error_pct": True,
    "audit_write_failures": True,
}
```

Leave `BREACH_IF_NA` (line 68) unchanged — `audit_write_failures` is never unmeasurable-as-None; `_count()` either returns a real number or raises `MetricUnavailable` (handled generically by `main()` already), matching the spec's explicit decision not to add it there.

Add the new function directly after `metric_parse_error_pct` (currently ending around line 199):

```python
def metric_audit_write_failures():
    """Count of write_audit() failures in the window (#184).

    Every doc in soc-agent-health-* IS a failure marker — nothing else writes
    there — so a plain count over the window is the metric, no extra filter.
    """
    return _count("soc-agent-health-*", {"match_all": {}})
```

In `main()`, add one line to the `metric_fns` dict (currently lines 207-213):

```python
    metric_fns = {
        "mttd_minutes": metric_mttd,
        "mttr_minutes": metric_mttr,
        "coverage_techniques": metric_coverage,
        "false_positive_pct": metric_false_positive_pct,
        "ingest_lag_seconds": metric_ingest_lag_seconds,
        "parse_error_pct": metric_parse_error_pct,
        "audit_write_failures": metric_audit_write_failures,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ai_agent/test_slo_metrics.py -v`
Expected: PASS (all tests, including the 5 new ones)

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ -q`
Expected: all tests pass (148 from Task 1 + 5 new = 153)

- [ ] **Step 6: Commit**

```bash
cd /home/tjlam/projects/Suburban-SOC
git add scripts/setup/ai_agent/slo_metrics.py tests/ai_agent/test_slo_metrics.py
git commit -m "feat(#184): add audit_write_failures SLO metric

Wired into the existing generic breach/alert/soc-slo-metrics-index machinery
in main() — no new dashboard code needed. Default threshold 3 (override via
SLO_AUDIT_WRITE_FAIL_MAX) distinguishes a transient blip from a sustained
failure run, per the issue's own framing of the problem."
```

---

### Task 4: Live verification and PR

**Files:** none (verification only)

**Interfaces:**
- Consumes: Task 1's `_write_audit_health_marker`, Task 2's role grant, Task 3's `metric_audit_write_failures`.
- Produces: merged/PR'd feature, nothing further consumes this.

- [ ] **Step 1: Apply the updated role to the running stack**

The `roles` one-shot service already re-applies every file in `configs/elasticsearch/roles/` on `docker compose up`. Re-run it directly rather than restarting the whole stack:

Run: `cd /home/tjlam/projects/Suburban-SOC/scripts/setup && docker compose up roles 2>&1 | tail -10`
Expected: a line like `role logstash_writer -> HTTP 200`

- [ ] **Step 2: Confirm the role grant took effect**

Run:
```bash
cd /home/tjlam/projects/Suburban-SOC/scripts/setup
set -a; source .env; set +a
curl -s --cacert /certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
  https://localhost:9200/_security/role/logstash_writer | python3 -m json.tool
```
Expected: the `indices[0].names` array includes `"soc-agent-health-*"`.

(If `/certs/ca/ca.crt` isn't readable from the host in this environment, run the same `curl` inside the `elasticsearch` container instead: `docker exec elasticsearch curl -s --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" https://localhost:9200/_security/role/logstash_writer`.)

- [ ] **Step 3: Rebuild and redeploy the agent with the new code**

Run:
```bash
cd /home/tjlam/projects/Suburban-SOC/scripts/setup
docker compose build ai-agent
docker compose up -d ai-agent
```
Expected: `Container soc_ai_agent` reaches `healthy` within ~30s (poll `docker inspect --format='{{.State.Health.Status}}' soc_ai_agent` if needed).

- [ ] **Step 4: Trigger a real audit-write failure and confirm the marker doc lands**

Exec into the already-running agent container and call `write_audit()` directly, monkey-patching `ES_HOST` in-process to an unreachable address so the write genuinely fails (no need to touch the container's real environment or the live ES service):

```bash
cd /home/tjlam/projects/Suburban-SOC/scripts/setup
docker compose exec -T ai-agent python3 -c "
import agent_app
agent_app.ES_HOST = 'https://elasticsearch:9999'  # force a connection failure
agent_app.write_audit('quarantine_mac', 'system', 'unassigned', outcome='success', target='AA:BB:CC:DD:EE:FF')
print('write_audit() returned without raising')
"
```
Expected: prints `write_audit() returned without raising` (confirms the never-raise contract live, not just in mocked tests).

Then confirm the marker doc actually landed in ES (using the real, correct `ES_HOST` this time):
```bash
set -a; source .env; set +a
curl -s --cacert /certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
  "https://localhost:9200/soc-agent-health-unassigned/_search?pretty" \
  -H 'Content-Type: application/json' -d '{"sort":[{"@timestamp":"desc"}],"size":1}'
```
Expected: one hit with `"event.action": "audit_write_failed"` and `"target_action": "quarantine_mac"`.

- [ ] **Step 5: Confirm slo_metrics.py picks up the new metric**

```bash
cd /home/tjlam/projects/Suburban-SOC
set -a; source scripts/setup/.env; set +a
.venv/bin/python3 scripts/setup/ai_agent/slo_metrics.py 2>&1 | tail -12
```

Expected: the printed metrics table includes an `audit_write_failures` row with a value of at least `1` (from Step 4) against a target of `<=3.0`, status `ok` (below threshold from a single test doc).

- [ ] **Step 6: Run the full test suite one more time**

Run: `cd /home/tjlam/projects/Suburban-SOC && .venv/bin/python3 -m pytest tests/ -q`
Expected: all 153 tests pass.

- [ ] **Step 7: Push and open the PR**

```bash
cd /home/tjlam/projects/Suburban-SOC
git push -u origin remediation/p3-issue-184-audit-write-visibility
gh pr create --title "feat(#184): dashboard-visible metric for SOC agent audit-write failures" --body "$(cat <<'EOF'
## Summary
Closes #184 — a sustained run of write_audit() failures (the tamper-evident
audit trail write) is now visible on the SLO dashboard, not just a log line.

- write_audit()'s existing except block now also best-effort-writes a failure
  marker to a new soc-agent-health-<tenant> index (its own nested try/except —
  the "never raise" contract is unchanged and covered by a dedicated test).
- logstash_writer's ES role grant extended to that new index pattern — reuses
  the agent's existing credential, no new user/password.
- New metric_audit_write_failures() in slo_metrics.py, wired into the existing
  generic breach/alert/soc-slo-metrics machinery. Default breach threshold is
  3 failures in the rolling window (SLO_AUDIT_WRITE_FAIL_MAX) — tolerates a
  one-off transient blip, alerts on a sustained pattern, per the issue's own
  framing of the problem.

Design spec: docs/superpowers/specs/2026-07-12-audit-write-failure-visibility-design.md

## Test plan
- [x] New tests/ai_agent/test_audit_write_health.py — never-raise contract
      verified under single AND double write failure
- [x] New tests in tests/ai_agent/test_slo_metrics.py — metric function +
      breach-threshold behavior (2 does not breach, 3 does)
- [x] Full suite passing
- [x] Live-verified against the running stack: role grant applied and
      confirmed, a real write_audit() failure produced a real marker doc in
      ES, slo_metrics.py's own output shows the new metric row

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
EOF is here; PR body needs no further edits.
