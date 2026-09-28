# Code review: uncommitted diff — scripts/setup/soc_pipeline.sh (health-check HTTP status fix)
Reviewer: code-reviewer sub-agent, 2026-09-15
Scope: `git diff scripts/setup/soc_pipeline.sh` (working tree, uncommitted). Two new
helpers (`http_code`, `es_health_code`) after `resolve_es_ca()`; 5 call sites rewritten
(2 in `run_prereq_checks`, 3 in `run_sop_005`).

Verified empirically (not just read): ran `curl -s -o /dev/null -w '%{http_code}'`
against a bad `--cacert` path (exit 77), a closed port (exit 7, connection refused),
and an unresolvable hostname (exit 6, DNS failure) — all three print `000` from curl's
own `-w` substitution, before this script's `${code:-000}` fallback ever engages. Also
confirmed with a standalone `bash -c` repro that a `local es_code` variable and a
same-named `es_code()` *function* (as defined in `scripts/setup/lib/es_common.sh`) do
not collide — command-position lookup resolves the function, `$es_code` resolves the
variable, independent of `local`. Confirmed via `grep` that `soc_pipeline.sh` has no
`set -e`/`set -u`/`pipefail` and does not `source` `es_common.sh` today.

---

## Must Fix
None. The core fix is correct: every rewritten call site now switches on the HTTP
status code rather than curl's exit status, which is exactly what the stated bug
(HTTP 401 silently reported as PASS) required.

## Should Fix

1. **[scripts/setup/soc_pipeline.sh:638-643] Same bug class survives, unfixed, one function down.**
   `run_sop_005` Step 5 still does:
   ```
   if ! systemctl is-active --quiet filebeat 2>/dev/null; then
       sudo systemctl start filebeat
       pass "Filebeat started"
   ```
   `pass "Filebeat started"` prints unconditionally — it never checks whether
   `sudo systemctl start filebeat` actually succeeded (e.g., a broken config would
   make the start fail, and the operator still sees green). This is the identical
   "claims success without verifying the result" bug class the rest of the diff was
   written to eliminate. Same pattern exists at line 547
   (`pass "Filebeat enabled and started"`, in the SOP-002 install function, after an
   unchecked `sudo systemctl start filebeat`) and line 571
   (`pass "Logs cleared: $LOG_DIR"`, after an unchecked
   `sudo "${SCRIPT_DIR}/clear_logs.sh"`). None of these are touched by this diff, so
   they are not a regression it introduces — but since the diff's whole premise is
   "don't report PASS without checking," leaving three sibling instances in place
   means the fix is incomplete for the file as a whole. Suggest a fast follow-up:
   `systemctl is-active --quiet filebeat && pass ... || fail ...` after each start,
   and check `clear_logs.sh`'s exit code before printing pass.

2. **[scripts/setup/soc_pipeline.sh:335-337] Comment overstates scope.**
   ```
   # Reachable but the credential was rejected. This is a hard failure:
   # SOP-005 Step 3 parses the health JSON and every ES query below
   # would silently return nothing.
   ```
   "every ES query below" implies plural downstream ES calls in this script; there is
   exactly one (`run_sop_005` Step 3's `_cluster/health` parse, line 615-616). Not
   wrong in spirit (bad creds do break everything downstream that depends on ES), but
   worded more broadly than what's actually in the file — tighten to something like
   "and the one ES query below (Step 3) would silently return nothing" to keep the
   comment falsifiable against the code it sits next to.

## Consider

1. **[scripts/setup/soc_pipeline.sh:329-330, 613] `es_code` naming echoes a real library function name.**
   `run_prereq_checks` declares `local es_code` and `run_sop_005` uses a global
   `ES_CODE`. `scripts/setup/lib/es_common.sh:124` defines a *function* `es_code()`.
   Confirmed via a live repro (`bash -c` test above) that a local/global variable and
   a same-named function do not collide in bash — different namespaces, and the
   script never calls bare `es_code` as a command. So there is no bug today, and none
   would appear even if `soc_pipeline.sh` later sourced `es_common.sh`, provided
   nothing calls bare `es_code` expecting the library function. Still, deliberately
   naming a local variable identically to a lib function the same comment block
   name-checks (line ~172: "the same status-code idiom as es_common.sh's es_code()")
   invites a future reader to assume a relationship that isn't there. A distinct name
   (e.g. `es_status`) would remove the ambiguity for zero cost.

2. **[scripts/setup/soc_pipeline.sh:630 vs. old line 628] Kibana connect-timeout silently tightened from 5s to 3s.**
   The old `run_sop_005` Step 4 check used `--connect-timeout 5`. The new shared
   `http_code` helper hardcodes `--connect-timeout 3`. Likely harmless (this is only
   the TCP+TLS handshake timeout, not overall readiness), and arguably an
   improvement for consistency with the other 4 call sites, but it's an
   unannounced behavior change bundled into what's framed as a status-code fix —
   worth a one-line mention in the commit message if this file gets committed.

3. **[scripts/setup/soc_pipeline.sh:613, 630] `ES_CODE`/`KB_CODE` stay unlocalized globals.**
   Consistent with this function's pre-existing style (`ES_STATUS` at line 615 and
   `LOG_COUNT` at line 665 are also unlocalized globals) — not a regression the diff
   introduces, and no observed collision risk since nothing else in the file reads
   those names. Still a good candidate for a `local` pass across all four the next
   time this function is touched.

## Looks Good

- **`http_code`'s `000`-on-failure behavior is correct and well-layered.** curl's own
  `-w '%{http_code}'` already substitutes `000` for a bad CA file, connection
  refused, and DNS failure (confirmed by direct reproduction, not assumed) — the
  function's `${code:-000}` fallback is not redundant, it's the correct defensive
  backstop for the one case curl *doesn't* cover itself: no stdout captured at all
  (e.g. `curl` missing from PATH, killed by signal). No `set -e`/`pipefail` in the
  file, so a non-zero curl exit never aborts the script here either way.
- **No whitespace/comparison hazard.** `-w '%{http_code}'` always yields a clean
  3-digit token; no `-L` is used anywhere so there's no multi-code concatenation to
  worry about; and the `local code; code=$(...)` split-assignment idiom is used
  correctly (avoids the classic bug where `local x=$(cmd)` masks `cmd`'s exit status
  in `$?` — moot here since exit status is intentionally never consulted, but still
  the right habit).
- **Severity vocabulary is reused correctly.** `fail()` + `all_pass=false` for the
  ES 401/403 branch matches the script's existing convention (`fail()` was already
  used for "Docker not running", a genuine hard blocker) rather than inventing a new
  severity tier. `all_pass` only ever changes the closing banner text
  ("All critical checks passed" vs. "Some checks failed") — it is never returned,
  checked, or used to gate `main_menu`'s subsequent calls — so escalating 401/403 to
  a hard failure is a purely informational, non-breaking change.
- **Sound severity split between "not up yet" and "up but wrong creds."** Treating
  HTTP `000`/non-200 (stack not started) as `warn` (expected at this point in the
  flow — SOP-005 Step 2 explicitly waits for the user to start it) while treating
  401/403 (stack up, credentials wrong) as `fail` is the right distinction: the
  former is self-resolving via the next step, the latter is a config error nothing
  downstream will fix on its own.
- **Incidental hardening beyond the stated fix.** `run_sop_005` Step 3's
  `ES_STATUS` curl call (line 615) now carries `--max-time 10`, which it never had
  before (previously fully unbounded) — closes a latent hang risk that wasn't part
  of the bug being fixed but is a welcome side effect.

## Answers to the specific review questions

1. Yes — `http_code` yields `000` correctly. Confirmed empirically that curl's own
   `-w` output already substitutes `000` for connect-refused, DNS failure, and a bad
   `--cacert` path (exit 77); `${code:-000}` is the correct additional backstop for
   the "curl produced literally no stdout" case.
2. No hazard found — command substitution + `echo` always yields a clean digit-only
   token, and no `-L`/retry flags exist to produce multi-code output.
3. No collision, verified with a live bash reproduction (function vs. variable
   namespaces are independent). Naming is a readability nit only (see Consider #1).
4. Consistent with the function's pre-existing global-variable style (`ES_STATUS`,
   `LOG_COUNT`) — not a new problem, just not fully idiomatic either.
5. Correct and safe — `all_pass` is cosmetic-only (final banner text), never used
   for control flow. No other branch obviously needs the same escalation beyond the
   pre-existing ones (Docker) already doing it.
6. Yes — three unfixed instances of the same bug class remain: lines 547, 571, and
   640 (`pass` printed unconditionally after an unchecked `sudo systemctl start
   filebeat` / unchecked `clear_logs.sh` invocation). See Should Fix #1.
7. Yes, with one overstatement (Should Fix #2: "every ES query below" when there is
   exactly one).

## Verdict
✅ **Approve** — no Must Fix items; the diff correctly fixes the reported bug and is
verified sound end to end (curl behavior, quoting, comparison logic, control flow).
The two Should Fix items are pre-existing/adjacent to this diff's blast radius, not
regressions it introduces, and can be a fast follow-up rather than a blocker.
