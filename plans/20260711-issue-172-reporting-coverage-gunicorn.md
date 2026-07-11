# #172 — reporting-plane test coverage + gunicorn (SA-11, SC-5)

## Scope (from issue acceptance criteria)

1. pytest-cov line coverage ≥70% on `slo_metrics.py`, `run_hunts.py`,
   `weekly_ciso_report.py`, gated in CI.
2. Agent container runs under `gunicorn` instead of the Werkzeug dev server.
3. Container healthcheck passes under the new WSGI server.
4. `tests/ai_agent/test_alert_auth.py` stays green after the server swap.

## Findings from investigation

- The issue's evidence is partly stale: `tests/ai_agent/test_slo_metrics.py`
  (13 tests) and `tests/hunts/test_run_hunts.py` (6 tests) already exist —
  added by #165's fix (PR #179) — but both have real coverage gaps (only
  failure-path branches of several metrics/helpers are tested, not the
  happy-path branches; `es()`/`kb()`/`main()`'s breach/NTFY paths are
  untested). Neither test file is wired into ANY CI workflow at all —
  `soar-tests.yml` only runs `test_alert_auth.py`. `weekly_ciso_report.py`
  has zero direct tests — `test_alert_auth.py` stubs it out entirely via
  `sys.modules` injection so `agent_app.py` can import without pulling in
  weasyprint/elasticsearch/jinja2.
- Gunicorn's `-w 2` (multi-process) suggested in the issue text would be a
  **security regression**: `agent_app.py` keeps `_seen_sigs` (HMAC replay
  nonce cache) and `_queue_lock`-guarded approval-queue writes as in-process
  state guarded by `threading.Lock` — thread-safe, not process-safe. Two
  worker *processes* each get an independent `_seen_sigs` dict, so a
  replayed signature has a real chance of landing on the worker that never
  saw the original, silently defeating replay protection. Using
  `--worker-class gthread --workers 1 --threads 4` instead keeps a single
  process (existing locks stay correct) while still moving off the raw dev
  server for SC-5/production-readiness. Documenting this deviation clearly
  since it contradicts the issue's literal suggestion.
- Importing `weasyprint` requires its native libs (pango/cairo/gdk-pixbuf) to
  be *loadable*, not just present at render time — so any CI job that
  imports `weekly_ciso_report.py` needs the same `apt-get install` list as
  `scripts/setup/ai_agent/Dockerfile`. `soar-tests.yml` deliberately avoids
  this weight (its own header comment says so) — adding it there would
  contradict that file's stated design. New dedicated workflow instead:
  `.github/workflows/reporting-coverage.yml`.
- No existing healthcheck for the `ai-agent` compose service. All its routes
  need a signed body or return JSON requiring auth — rather than add a new
  unauthenticated `/health` route (out of scope) or fight curl's `-f`
  semantics against an auth-gated route, use a plain TCP-connect check
  (stdlib `socket`, no new binary/dependency needed in the slim image):
  confirms gunicorn is bound and accepting connections without touching HTTP
  auth semantics at all.

## File changes

- `tests/ai_agent/test_slo_metrics.py` — add happy-path tests for
  `metric_coverage`/`metric_false_positive_pct`/`metric_parse_error_pct`
  (including the zero-total no-division-by-zero branch), a test that
  exercises the real `es()`/`kb()` wrappers (mocking `SESSION` instead of
  the wrapper), and `main()`'s breach-detected (exit 2) + NTFY-sent +
  NTFY-failure-swallowed paths.
- `tests/hunts/test_run_hunts.py` — add: no-hunts-found (exit 1),
  missing-ES_PASS (exit 1, via monkeypatching the module global before
  calling `main()` directly), and a hunt whose count meets its threshold
  (finding=True branch).
- `tests/ai_agent/test_weekly_ciso_report.py` — new file: `_tag_to_nist`
  (valid/case-variant/malformed tags), `fetch_and_calculate_metrics`
  (mocked `Elasticsearch` happy path with MTTD+NIST calc, and the
  connection-failure demo-fallback path), `generate_executive_summary`
  (hosted-LLM-blocked, local-LLM success, LLM-failure), `create_pdf_report`
  (real weasyprint render to a temp path — libs are already confirmed
  working on this host from #183's verification), `send_to_slack`
  (no-creds, full 3-step happy path, and a failure at each step),
  `send_ntfy_notification` (success + swallowed-failure), and a
  `run_reporting_pipeline` wiring test with all sub-functions mocked.
- `.github/workflows/reporting-coverage.yml` — new workflow: apt-get the
  weasyprint native libs, `pip install -r scripts/setup/ai_agent/requirements.txt
  pyyaml pytest pytest-cov`, run pytest-cov against the three target files
  with `--cov-fail-under=70`.
- `scripts/setup/ai_agent/requirements.txt` — add `gunicorn`.
- `scripts/setup/ai_agent/Dockerfile` — CMD →
  `gunicorn --worker-class gthread --workers 1 --threads 4 --bind 0.0.0.0:5000
  --access-logfile - --error-logfile - agent_app:app`.
- `scripts/setup/docker-compose.yml` — add a TCP-connect healthcheck to the
  `ai-agent` service.

## Verification

- `pytest --cov=... --cov-report=term-missing` locally against all three
  files, confirm ≥70% each before pushing.
- `pytest tests/ai_agent/test_alert_auth.py` stays green (acceptance
  criterion — the stub pattern shouldn't be touched).
- Live: rebuild `soc_ai_agent`, confirm gunicorn starts (check `docker logs`
  for the gunicorn banner, not the Werkzeug dev-server warning), confirm the
  new healthcheck reports healthy, send a real signed `/alert` webhook
  end-to-end to confirm nothing broke under gunicorn.
