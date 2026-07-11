# #171 — broker structured logging + persisted denial records (AU-2/3/12)

## Scope (from issue acceptance criteria)

1. 0 bare `print()` calls remain in broker or agent runtime code paths.
2. A new test asserts a rejected-HMAC or replayed request produces a persisted
   denial record (not just an HTTP response).
3. Agent INFO-level log lines are visible in `docker logs` after adding
   `basicConfig`.
4. Broker denial records are queryable the same way the agent's
   `soc-audit-<tenant>` records are.

## Findings from investigation

- `agent_app.py` already uses `logging`/`app.logger` throughout (0 bare
  `print()`) — its only gap is no `logging.basicConfig()`, so its own
  INFO-level lines fall under Flask's default WARNING floor. Narrow fix: add
  `logging.basicConfig(level=logging.INFO, ...)` near the top.
- The broker (`app.py`, `dispatcher.py`, `inventory.py`) is the actual
  bare-`print()` offender (18 call sites). `uvicorn app:app` is the Dockerfile
  CMD (no `__main__` block runs), so a module-level `logging.basicConfig()`
  in `app.py` executes at import time regardless of launch method. Uvicorn's
  own `dictConfig` only touches `uvicorn`/`uvicorn.error`/`uvicorn.access`
  loggers and leaves root alone, so this doesn't conflict.
- `inventory.py`'s `if __name__ == "__main__":` block is an interactive
  smoke-test entry point, not a runtime path — left as `print()`.
- No persisted record exists today for `_verify()`'s failure branches
  (missing/invalid signature, invalid/stale timestamp, replayed signature,
  unconfigured secret) — this is the actual AU-2/3/12 gap. Business-logic
  refusals (exclusion list, no-routers) are a separate, already-partially-
  handled concern (`/approve` already appends `status: denied` to
  `approval_queue.jsonl`) — out of scope here to avoid scope creep.
- Precedent to mirror: `agent_app.py:write_audit()` — async-POSTs an
  `op_type=create` doc to `soc-audit-<tenant>` via the append-only
  `soc_audit_appender` role (create-only, no update/delete). `httpx==0.28.1`
  is already a broker dependency — use `httpx.AsyncClient` (not `requests`,
  which would block the FastAPI event loop).
- `soc-audit-unassigned` is an already-established convention (see
  `docs/SOP-012-privacy-data-handling.md`) for audit events with no real
  tenant. `_verify()` fires before the JSON body is trusted/parsed in most
  failure branches, so denial records use `tenant="unassigned"` uniformly —
  simplest correct choice, no new index-naming scheme needed.
- Per #167's precedent (dedicated `slo_metrics` user instead of reusing a
  shared account), give the broker its own ES user (`hive_mind_broker`)
  rather than reusing `logstash_internal`. Reuses the *existing*
  `soc_audit_appender` role as-is (create-only on `soc-audit-*` already
  matches the need exactly) — no new ES role required.
- `soc-audit-*` has no explicit index template (dynamic mapping, same as
  today) and is already covered by the SLM snapshot policy wildcard. No
  dashboard panel exists today for the agent's own audit trail either
  (grepped repo-wide) — SOPs treat it as Discover/KQL-queryable evidence, not
  a dedicated panel. "Queryable the same way" is satisfied by writing to
  `soc-audit-*` and live-verifying a KQL query — no new panel required.
- Gated like `SLO_METRICS_PASSWORD`: unset `BROKER_AUDIT_PASSWORD` skips
  provisioning the user, and the broker degrades gracefully (denial write
  fails closed on the *write*, logged, never blocking the 401/503 response).

## File changes

- `scripts/hive-mind-broker/app.py` — `logging.basicConfig` + module logger;
  convert 7 `print()` sites; add `ES_HOST/ES_USER/ES_PASS/ES_CA` config +
  async `write_denial()`; call it from every `_verify()` failure branch.
- `scripts/hive-mind-broker/dispatcher.py` — module logger; convert 8
  `print()` sites (levels: info for success, warning for refusals, error for
  SSH/exec failures).
- `scripts/hive-mind-broker/inventory.py` — module logger; convert the 2
  runtime-path `print()` sites (leave the `__main__` smoke-test block as-is).
- `scripts/hive-mind-broker/test_app.py` — new tests asserting denial records
  are persisted for invalid-signature / replayed / missing-signature cases
  (mock the ES POST; assert call was made with the right doc shape), plus a
  test that a write failure doesn't turn into a 500.
- `scripts/setup/ai_agent/agent_app.py` — add `logging.basicConfig()`.
- `scripts/setup/docker-compose.yml` — gated `hive_mind_broker` ES user
  provisioning (reusing `soc_audit_appender`); wire
  `ES_HOST/ES_USER/ES_PASS/ES_CA` + `certs:/certs:ro` mount into the broker
  service; `depends_on: provision` for startup ordering.
- `scripts/setup/.env.example` — document `BROKER_AUDIT_PASSWORD`.

## Verification

- `pytest scripts/hive-mind-broker/test_app.py` — new + existing tests green.
- Live: set `BROKER_AUDIT_PASSWORD`, re-run provisioning, restart the broker
  container, send an invalid-signature request, confirm a `soc-audit-
  unassigned` doc lands via a live ES query. Confirm `docker logs
  hive_mind_broker` shows structured log lines instead of `print()` output.
- Confirm `docker logs soc_ai_agent` now surfaces INFO-level lines.
