# soc_pipeline.sh health-check fix — independent validation (2026-09-15)

## Claimed behavior
Health checks in `scripts/setup/soc_pipeline.sh` used
`curl -s ... &>/dev/null`, which exits 0 for ANY completed HTTP exchange
(including 401/403/503), so a wrong Elasticsearch password produced
`[PASS] Elasticsearch is reachable`. The fix adds two helpers —
`http_code()` (returns the HTTP status code, or `000` if no HTTP response
was obtained at all) and `es_health_code()` (calls `http_code` against
`/_cluster/health` with session creds) — and switches all 5 call sites
(2 in `run_prereq_checks`, 3 in `run_sop_005` Steps 2-4) to branch on the
status code instead of curl's exit status.

## Environment
- Live stack confirmed up read-only: `docker ps` showed
  `elasticsearch: Up 5 hours (healthy)`, `kibana: Up 5 hours (healthy)`,
  `logstash: Up 5 hours`.
- Stack CA confirmed readable: `/etc/filebeat/certs/ca.crt` (root-owned,
  0644).
- Credentials loaded from `scripts/setup/.env` (`ELASTIC_PASSWORD`) via
  `set -a; . scripts/setup/.env; set +a` in a subshell; the value was never
  echoed or written to any file — each test that used it was followed by a
  `grep -qF "$ELASTIC_PASSWORD" <output-file>` check that reported the
  password was NOT present in the captured output.
- No file under `scripts/setup/soc_pipeline.sh` was modified. All testing
  was done against a stripped copy (`sed '$d' soc_pipeline.sh > lib.sh`,
  removing only the trailing unconditional `main_menu` call at EOF) sourced
  in disposable `bash -c` subshells, plus a second harness
  (`steps234.sh`) built by extracting **lines 593-636 of the real file
  verbatim** (diff-confirmed identical) and wrapping them in a function, to
  test Steps 2-4 of `run_sop_005` without reaching Step 5
  (`sudo systemctl start filebeat`) or Step 6 (live capture mode select).
  No container, systemd unit, or repo file was started, stopped, or
  reconfigured.

---

## Test A — Wrong/empty ES_PASS via `run_prereq_checks`

```
Command: run_prereq_checks with ES_USER=elastic ES_PASS=wrong-password-xyz
         (SSH-setup prompt answered "n" via stdin; ROUTER_IP set to an
         unreachable IP so the SSH check fails fast and deterministically)
Exit code: 0 (function itself doesn't propagate a failure exit code;
           correctness is judged on printed PASS/FAIL/summary text, per
           the task's own acceptance criteria)
Result: PASS
```

Evidence (ANSI color codes stripped for readability; content unchanged):
```

>>> SOP Prerequisite Checks
--------------------------------------------
  [PASS] Docker is running
  [PASS] tcpdump is installed
  [WARN] SSH to router (127.0.0.255) requires a password or is unreachable.
  Would you like to configure passwordless SSH now? [y/N]:   [WARN] Remote capture scripts will not work without passwordless SSH.
  [PASS] Log directory exists: /storage/PCAP/zeek_logs
  [PASS] Filebeat is running
  [INFO] Stack CA: /etc/filebeat/certs/ca.crt (SOP-003)
  [FAIL] Elasticsearch REJECTED the credentials (HTTP 401) - wrong password for user 'elastic'
  [PASS] Kibana is reachable (port 5601, HTTP 302)

  Some checks failed. Review warnings above before proceeding.
EXIT_CODE_OF_FUNCTION:0
```

**What this proves:** the Elasticsearch line reads
`[FAIL] Elasticsearch REJECTED the credentials (HTTP 401) - wrong password
for user 'elastic'`, and the summary reads `Some checks failed. Review
warnings above before proceeding.` — matching the required "FAIL + HTTP 401
+ Some checks failed" combination. This is the exact regression the old
`&>/dev/null` code produced a false PASS for; here the wrong password is
correctly reported as a hard failure, and `all_pass=false` correctly
suppressed the "All critical checks passed" banner.

---

## Test B — Correct ES_PASS via `run_prereq_checks`

```
Command: run_prereq_checks with ES_USER=elastic, ES_PASS=<real value from .env>
Exit code: 0
Result: PASS
```

Evidence:
```

>>> SOP Prerequisite Checks
--------------------------------------------
  [PASS] Docker is running
  [PASS] tcpdump is installed
  [WARN] SSH to router (127.0.0.255) requires a password or is unreachable.
  Would you like to configure passwordless SSH now? [y/N]:   [WARN] Remote capture scripts will not work without passwordless SSH.
  [PASS] Log directory exists: /storage/PCAP/zeek_logs
  [PASS] Filebeat is running
  [INFO] Stack CA: /etc/filebeat/certs/ca.crt (SOP-003)
  [PASS] Elasticsearch is reachable and authenticated (port 9200, HTTP 200)
  [PASS] Kibana is reachable (port 5601, HTTP 302)

  All critical checks passed.
EXIT_CODE_OF_FUNCTION:0
```

**What this proves:** with the real password, Elasticsearch reports
`[PASS] Elasticsearch is reachable and authenticated (port 9200, HTTP 200)`
and the run ends with `All critical checks passed.` — the fix does not
introduce a false negative on a correct credential; HTTP 200 still reads
as full success. Confirmed no password leakage: a post-hoc
`grep -qF "$ELASTIC_PASSWORD"` against this captured output returned no
match.

---

## Test C — `http_code` against a closed port

```
Command: http_code https://localhost:9299/   (port 9299 has nothing listening)
Exit code: 0 (function call)
Result: PASS
```

Evidence:
```
RETURNED: [000]
TEST C: PASS (exactly 000)
```

Independently confirmed the underlying curl mechanics (not just the `:-000`
bash fallback) produce this:
```
$ curl -s -o /dev/null -w 'exit_via_curl: %{http_code}\n' --connect-timeout 3 --max-time 5 https://localhost:9299/
exit_via_curl: 000
curl exit code: 7

$ ss -ltn | grep 9299
(no output — port 9299 is not listening)
```

**What this proves:** `http_code` returns exactly `000` for a
connection-refused target, both via the wrapper and via curl's own
`%{http_code}` write-out (curl exit 7, "couldn't connect"). The `000`
comes from curl itself, not merely the function's `${code:-000}` fallback
masking an empty string — i.e., the "no HTTP response at all" case is
correctly distinguished from the "got an HTTP response, didn't like it"
case (401/403/etc.) that Tests A and D exercise.

---

## Test D — `run_sop_005` Steps 2-4 in isolation

Driving the full `run_sop_005` was avoided by design: Step 5
unconditionally runs `sudo systemctl start filebeat` if Filebeat is not
active, and Step 6 offers live capture mode selection — both out of scope
for a read-only validation. Per the task's own fallback instruction,
Steps 2-4 (lines 593-636 of `soc_pipeline.sh`, verbatim, diff-confirmed)
were extracted into a `steps_2_4()` function and sourced alongside the
real `lib.sh` (which supplies the real `http_code`/`es_health_code`/
`pass`/`fail`/`warn`/`resolve_es_ca`).

### D1 — Wrong ES_PASS

```
Command: steps_2_4 with ES_USER=elastic ES_PASS=wrong-password-xyz
         (empty line fed to stdin for the Step 2 "Press Enter..." prompt)
Exit code: 0
Result: PASS
```

Evidence:
```

Step 2: ELK Stack
  [INFO] Stack CA: /etc/filebeat/certs/ca.crt (SOP-003)
  [WARN] Elasticsearch not up and authenticated. Start your ELK stack (docker compose up -d)
  Press Enter once ELK is running...  [INFO] Stack CA: /etc/filebeat/certs/ca.crt (SOP-003)

Step 3: Verify Elasticsearch
  [FAIL] Elasticsearch REJECTED the credentials (HTTP 401) - wrong password for user 'elastic'

Step 4: Verify Kibana
  [PASS] Kibana reachable at https://localhost:5601 (HTTP 302)
```

**What this proves:** Step 2 no longer claims "Elasticsearch already up"
on bad creds — it correctly falls to the `warn` branch. Step 3 prints
`[FAIL] Elasticsearch REJECTED the credentials (HTTP 401) - wrong password
for user 'elastic'` and does **not** attempt to parse a `status` field out
of what would have been an empty/auth-error body. Step 4 (Kibana) is
correctly unaffected by the bad ES credential and still passes on HTTP 302.

### D2 — Correct ES_PASS

```
Command: steps_2_4 with ES_USER=elastic, ES_PASS=<real value from .env>
         (stdin explicitly closed via </dev/null since a correct password
         should not hit the "Press Enter" prompt at all)
Exit code: 0
Result: PASS
```

Evidence:
```

Step 2: ELK Stack
  [INFO] Stack CA: /etc/filebeat/certs/ca.crt (SOP-003)
  [PASS] Elasticsearch already up

Step 3: Verify Elasticsearch
  [PASS] Elasticsearch: "status":"yellow"

Step 4: Verify Kibana
  [PASS] Kibana reachable at https://localhost:5601 (HTTP 302)
```

**What this proves:** with real creds, Step 2 passes immediately without
prompting (`es_health_code` = 200 on the first try, so the `read -r` line
is never reached — confirmed by the run completing cleanly even with
`</dev/null`, which would have made a bad script hang or error on a stray
prompt). Step 3's `ES_STATUS` parse against the real 200 response still
works, printing the cluster's actual status
(`"status":"yellow"` — quoted verbatim from curl's live response body).
Step 4 (Kibana) passes on HTTP 302. Confirmed no password leakage via the
same post-hoc `grep -qF` check (no match).

---

## Test E — `bash -n` and `shellcheck -S warning`

```
Command: bash -n scripts/setup/soc_pipeline.sh
Exit code: 0
Result: PASS (no syntax errors, no output)

Command: shellcheck -S warning scripts/setup/soc_pipeline.sh
Exit code: 0
Result: PASS (zero findings at warning severity or above — shellcheck 0.9.0)
```

**What this proves:** the diff introduces no shell syntax errors and no
shellcheck warnings/errors (e.g., no unquoted expansions, no unused
variables) in the new `http_code`/`es_health_code` helpers or their 5 call
sites.

---

## Test F — Existing repo tests

```
Command: ls tests/setup/
Result: test_build_attack_coverage.py, test_docker_compose_ports.py,
        test_env_loader.py, test_es_client.py,
        test_provision_error_handling.py, test_provision_no_cleartext_argv.py,
        test_role_compose_sync.py, test_setup_branch_protection.py,
        test_soc_admin_role_scope.py, test_systemd_environment_no_expansion.py
```

Grepped every test file for `soc_pipeline` and for dynamic globbing over
`scripts/setup/*.sh` — no test references `soc_pipeline.sh` by name, and
the one test that globs a directory (`test_systemd_environment_no_expansion.py`)
only globs `*.service` files under a systemd unit directory, unrelated to
this script.

```
Command: python3 -m pytest tests/setup/ -q
Exit code: 0
Result: PASS
```
Evidence:
```
147 passed, 10 subtests passed in 1.01s
```

**What this proves:** no existing automated test currently covers
`soc_pipeline.sh`'s health-check logic (a coverage gap, not something this
diff caused), and the full `tests/setup` suite is unaffected by this
uncommitted change — no regression.

---

## Summary Table

| Test | Description | Result |
|------|-------------|--------|
| A | Wrong ES_PASS → `run_prereq_checks` | PASS |
| B | Correct ES_PASS → `run_prereq_checks` | PASS |
| C | `http_code` on closed port → `000` | PASS |
| D1 | `run_sop_005` Steps 2-4, wrong creds | PASS |
| D2 | `run_sop_005` Steps 2-4, correct creds | PASS |
| E | `bash -n` / `shellcheck -S warning` | PASS (clean) |
| F | Existing `tests/setup` suite | PASS (no regression; no direct coverage exists) |

## Remaining Unknowns / Gaps Not Tested
- **No automated test exists for this script's health-check behavior.**
  Tests A-D above were run manually and are not preserved as a regression
  test; a future wrong-password regression would not be caught by CI.
  Recommend a `tests/setup/test_soc_pipeline_healthcheck.py` (fake `curl`
  binary on `PATH` returning canned status codes, same idiom as this repo's
  other faked-CLI tests) as a follow-up.
- **The 000/`ES_CA` unreadable path** (`resolve_es_ca`'s failure branch,
  which falls back to the nonexistent `/certs/ca/ca.crt`) was not
  independently exercised end-to-end in Steps 2-4 — Test C covers `000`
  from a closed port, not from a bad/missing CA file specifically, though
  the code path (`curl --cacert <bad-path>` → curl exit 77 → empty
  `%{http_code}` → `${code:-000}`) is the same fallback mechanism.
- **Kibana's 503 branch** (container "up but still initialising") was not
  exercised — the live Kibana container is healthy and returns 302, so
  there was no way to reach that branch without degrading the live stack,
  which was out of scope (read-only constraint).
- Steps 5+ of `run_sop_005` (Filebeat start, live capture mode selection)
  were deliberately not run, per the read-only/no-service-changes
  constraint — this is a scoping choice, not a finding.

## Verdict
**Validated.** All 6 requested checks (A-F) reproduce independently and
confirm the fix: `run_prereq_checks` and `run_sop_005` Steps 2-4 now
correctly report `[FAIL]`/HTTP 401 on a wrong Elasticsearch password
(previously a false `[PASS]`), still report success correctly on HTTP
200/302, and `http_code` correctly distinguishes "no HTTP response at all"
(`000`) from "got a response, rejected" (401/403). No regressions found in
`bash -n`, `shellcheck -S warning`, or the existing `tests/setup` suite.
The only gap is the absence of an automated regression test for this
behavior (pre-existing, not introduced by this diff).
