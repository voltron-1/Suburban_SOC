# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: Structural Health Review Remediation — Priority 1 (Critical) COMPLETE.
Priority 2: #164-#171 merged; #172 not yet started.**
Source: repo-wide structural/NIST-CSF-2.0/SP-800-53-Rev.5-aligned review,
2026-07-08 — 14 issues filed (#164-#177), 5 more filed since (#182-#183,
#185, #189-#190), all linked to
[Project Board #17](https://github.com/users/voltron-1/projects/17).

Next unstarted item: **#172** — zero test coverage on the SOC reporting plane;
agent runs on Flask dev server, not prod WSGI.

- [x] **#171** — broker security events logged via bare `print()`, no
  persisted record of denied/replayed/invalid-signature attempts (AU-2/3/12).
  All `print()` converted to `logging`; new `write_denial()` persists every
  `_verify()` auth-failure to `soc-audit-unassigned` via a new dedicated
  least-privilege `hive_mind_broker` ES user (reuses the existing
  `soc_audit_appender` role, no new role). 37 tests passing; `security-auditor`
  (no exploitable issues) + `code-reviewer` (one should-fix, resolved) both
  ran. Live-verified against the running stack: real invalid-signature
  request → 401 + matching ES doc; confirmed the account is create-only (403
  on search/delete); confirmed agent's `basicConfig` fix against a control
  case. [PR #194](https://github.com/voltron-1/Suburban_SOC/pull/194) merged
  (rebased cleanly onto #183's fix first); issue closed.
- [x] **#183** — `weasyprint==68.0` CVE (CVE-2026-49452, CSS injection via
  presentational hints), surfaced by `pip-audit` failing on #171's PR (that
  job scans the whole `requirements.txt`, not just the diff — the failure was
  pre-existing, unrelated to #171 itself). Verified per-release against
  PyPI's advisory data that 68.1 *still* carries the CVE — only 69.0 is
  clear; confirmed no breaking-API impact on `weekly_ciso_report.py`'s only
  call site. Live-verified: rendered a real PDF via a fresh venv and again
  inside the rebuilt `soc_ai_agent` container.
  [PR #195](https://github.com/voltron-1/Suburban_SOC/pull/195) merged;
  issue closed.

- [x] **#192** (unplanned, detection-engineering coverage review, filed
  2026-07-09 — separate from the #164-#190 structural review) — collected
  Windows Security/System events had no alert rules (4625/4648/4672/4732),
  and key channels weren't collected at all (Security 1102, System 104/7040/
  7045, WMI-Activity 5861, PowerShell 4103/4104). Added 12 new Sigma rules +
  3 Elastic threshold-rule companions (count/cardinality logic the Sigma
  fixture evaluator and lucene conversion can't express), new logsource-
  conditioned ECS field mappings, `winlogbeat.yml` channel collection,
  `test_threshold_rules.py`, coverage matrix regenerated (24 → 36 rows).
  [PR #193](https://github.com/voltron-1/Suburban_SOC/pull/193) merged;
  issue closed.

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (SI-10/PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178) merged; issue closed.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  merged; issue closed. 20 new tests, all passing. Deferred `agent_app.py:696`
  (audit-write visibility) to a follow-up — filed as #184.
- [x] **#166** — Bash admin tooling skipped TLS verification (`curl -k`) while
  sending ES credentials (SC-8). [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180) merged; issue closed.
  Operator note: host scripts relying on the old implicit `-k` fallback now
  need `ES_CA=<path>` or `ES_INSECURE=true`.
- [x] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7). [PR #181](https://github.com/voltron-1/Suburban_SOC/pull/181)
  merged; issue closed. New least-privilege `slo_metrics_reader` ES role +
  `slo_metrics` user, live-created and verified end-to-end — holding.
  `zeek-host-capture.service` sandboxing was deployed, broke live capture in
  production (crash-loop), and was reverted same-day — root cause was the
  WSL2 `eth0` interface being administratively down, unrelated to the
  hardening itself, but the unit currently runs unsandboxed. Follow-up #182
  covers re-attempting it safely. `es_common.sh`'s shared `elastic` default
  deliberately left alone (~15 other legitimate admin-tooling consumers
  depend on it).
- [x] **#185** (unplanned, discovered this session) — `deploy_detections.sh`
  silently no-op'd on every run since its introduction (#93, 2026-06-12):
  competing `< "$RAW"` / `<<'PY'` stdin redirects meant the transformed rule
  payload was always empty, and Kibana's import API returns `success:true`
  for an empty file — a silent false-positive (CM-3, SI-11). Surfaced while
  investigating shellcheck findings for #168. Fixed via `RAW_PATH` env var +
  explicit `open()`; verified with synthetic + realistic-data transform
  tests. [PR #186](https://github.com/voltron-1/Suburban_SOC/pull/186)
  merged; issue closed.
- [x] **#168** — CI had no linter and functional tests were path-filtered
  (SA-11/CM-3). New always-on `.github/workflows/lint.yml` (shellcheck, ruff,
  mypy, yamllint); `soar-tests.yml`/`detections.yml` path filters removed
  entirely. Fixed all findings surfaced (2 real shellcheck unused-vars, 3
  ruff, 8 mypy — 2 of which were genuine latent type-signature/behavior
  mismatches, not just stub pickiness) rather than suppressing. Along the way
  found a real shellcheck directive-scoping gotcha (a `disable=` comment
  before a `cmd1; cmd2; cmd3` chain only covers `cmd1`). Explicitly deferred:
  required branch-protection status checks (repo-settings change, needs
  separate explicit sign-off). Real CI confirmed: ruff/mypy/yamllint pass;
  `soar-tests`/`detections` now actually run and pass (previously would have
  been skipped). Branch `remediation/p2-issue-168-nist` (commit `1e7c0f4`).
  [PR #187](https://github.com/voltron-1/Suburban_SOC/pull/187) merged;
  issue closed.
- [x] **#169** — Logstash pipeline had no dead-letter queue and no grok
  parse-failure test coverage (SC-24). New `configs/logstash.yml`
  (`queue.type: persisted`, `dead_letter_queue.enable: true`), output split
  routing parse failures to a `logstash-security-quarantine-*` index, new
  `dq-quarantine` dashboard panel, 14 new grok/JSON parse-failure tests.
  Branch `remediation/p2-issue-169-nist`.
  [PR #188](https://github.com/voltron-1/Suburban_SOC/pull/188) merged;
  issue closed.
- [x] **#170** — ES client/credential consolidation (#156/#157) incomplete; no
  connection reuse or retry (CM-2). Branch `remediation/p2-issue-170-nist`.
  New `scripts/setup/lib/es_client.py` (`requests.Session` + `urllib3.Retry`;
  `read=0` deliberately — never auto-retry a write after a read-timeout, only
  pre-send connection failures and explicit 502/503/504);
  `slo_metrics.py`/`run_hunts.py` migrated onto it. `weekly_ciso_report.py`/
  `verify_detections.py` (elasticsearch-py, not raw requests — one uses
  `api_key` auth) got `retry_on_timeout=True, max_retries=3` added natively
  instead. `es_common.sh`'s `es()`/`es_code()` now set `--max-time
  "${ES_CURL_TIMEOUT:-60}"` (previously unset on all 19 sourcing scripts).
  Live-verified against the running stack: `slo_metrics.py`, `run_hunts.py`,
  `refresh_intel.sh` (bulk index under the new 60s cap), `stack_health.sh`
  (its own `-m 6` override still wins). 26 unit tests, all green. Several
  items in the original issue evidence turned out stale on fresh inspection
  and were deliberately left untouched — see the PR description for the
  full list (redundant-looking `ES_PASS` derivation in
  `refresh_intel.sh`/`deploy_changelog.sh` is an intentional best-effort-ES
  gate, not a bug; the `logstash_writer` role "duplication" in
  `docker-compose.yml` is a documented two-phase bootstrap, not drift).
  Two new findings surfaced and filed separately rather than folded in:
  [#189](https://github.com/voltron-1/Suburban_SOC/issues/189)
  (`soc_pipeline.sh` health checks probe `http://` against the TLS-only
  stack — always fail) and
  [#190](https://github.com/voltron-1/Suburban_SOC/issues/190)
  (`reindex-existing.sh`'s local `es()` override recurses infinitely
  through `esj()` — script is currently non-functional).
  [PR #191](https://github.com/voltron-1/Suburban_SOC/pull/191) merged;
  issue closed.

P2 remaining (#172) and P3 (backlog, #173-#177) are tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17); working
sequentially in descending priority order per the remediation protocol, one
item at a time with explicit approval before each file change.

---

## LAST SESSION — 2026-07-11

- **#171** implemented, reviewed (`security-auditor` + `code-reviewer` in
  parallel), live-verified, and merged — see NEXT UP for detail.
  [PR #194](https://github.com/voltron-1/Suburban_SOC/pull/194).
- **#183** (weasyprint CVE, filed 2026-07-08) fixed and merged same-session
  after its `pip-audit` failure surfaced on #171's PR — turned out to be
  pre-existing and unrelated to #171 itself, not a regression.
  [PR #195](https://github.com/voltron-1/Suburban_SOC/pull/195), merged
  first, #194 rebased cleanly onto it (disjoint files, no conflicts).
- Process note: reported #194 as fully done before actually checking
  `gh pr checks` against the real CI run — local verification (pytest/ruff/
  mypy) is not a substitute for confirming the actual PR checks. Caught when
  the user reported a CI failure; corrected by checking `gh pr checks` /
  the check-runs API before any future "done" claim on a PR.

## LAST SESSION — 2026-07-10

- Detection-engineering coverage review (unplanned, separate track from the
  #164-#190 structural review): filed and closed #192 same-session. 12 new
  Sigma rules + 3 Elastic threshold companions covering Windows Security/
  System/WMI/PowerShell event IDs that were either collected-but-unalerted
  or not collected at all. [PR #193](https://github.com/voltron-1/Suburban_SOC/pull/193)
  merged; branch `detections/issue-192-coverage-gaps` deleted post-merge
  (squash merge — local branch cleaned up separately since git didn't
  recognize it as an ancestor of `main`).

## LAST SESSION — 2026-07-08

- Principal-engineer structural health review of the full repo (architecture map,
  robustness/access-control gap analysis mapped to NIST CSF 2.0 + SP 800-53
  Rev.5, sustainability/test/resource-management lenses). Filed 14 issues
  (#164-#177: P1 critical ×4, P2 medium ×5, P3 low ×5) with evidence, control
  mappings, and acceptance criteria; labeled by priority/nist-compliance/
  tech-debt/security; linked to [Project Board #17](https://github.com/users/voltron-1/projects/17).
- **All four P1 (critical) items fixed, tested, PR'd, and merged this
  session**: #164 (PR #178, SI-10), #165 (PR #179, SI-11), #166 (PR #180,
  SC-8), #167 (PR #181, AC-6/CM-7). Each PR includes end-to-end verification
  against the live running stack where no CI path existed to lean on instead.
- Two follow-up issues filed: #182 (zeek-host-capture.service capability
  scoping — needs live-tested sudo access) and #183 (weasyprint CVE
  unrelated to the P1 work, surfaced while investigating pip-audit CI
  failures on the four PRs).
- #160/#161: shipped pipeline ECS fixes + HIGH source.ip-spoof hardening (parallel
  code-reviewer + security-auditor); **PR #162 merged, both issues closed.** Live investigation
  found two extra root causes the issues missed: (1) panels bucket on `.keyword` subfields
  absent on the keyword-mapped real data (fixed net-sni/net-cipher, like be95698); (2) #161 is
  ~entirely mock-data-driven. Backfilled tls.* (5,711 real docs, via approved ILM write-block
  lift+restore) and mock `country_name` (800 docs); redeployed the Network dashboard; both
  panels verified rendering via live aggregations. Logstash restarted → pipeline config live.

Prior session (per merged PR history):

- [x] #159 — ingest-lag SLO recovery + end-to-end dashboard validation
- [x] #158 — ingest-lag SLO recovery + #147 telemetry evidence
- [x] #157 — consolidate es() helpers + ES credential loading (#156)
- [x] #153 — restore + harden ingest pipeline after restart-induced SLO breach (WS2.4)
- [x] #152 — fix small-detection-log ingestion + A.1/A.2 evidence (SOP-147)
- [x] #151 — Path A/B evidence-generation chain + Beats mTLS (SOP-147)
- [x] #150 — evidence validation runbook + flag suspect evidence (SOP-147)
- [x] #149 — emulation→telemetry map + validator, Zeek rules, CI gate

---

## DEFERRED

- [ ] Follow-up issue (to file) — #161 coverage/robustness leftovers surfaced in review:
  standalone `Invalid user <x> from <ip>` sshd line (no verb) not parsed; numeric captures
  (`source.port`, `process.pid`) land as keyword not `long`; add `tls.*`/`process.pid` to
  the index template; `::ffff:` IPv4-mapped-IPv6 gap + 3×-duplicated geoip guard regex.
  Reason: non-blocking enhancements; core acceptance is met by the current fix.
- [ ] Real-telemetry gap ticket (to file) — "Failed SSH by Country" + TLS panels currently
  demo on mock/recent data; live SSH brute-force telemetry is ~absent (2 real failure docs).
  If these must reflect real attacks, the auth.log Filebeat→pipeline shipping path needs to
  actually deliver events. Separate from the ECS fix.
- [x] Activate the PR #162 pipeline config on the running Logstash — done 2026-07-08
  (`docker restart logstash`); container came up stable, so config parsed; forward enrichment
  of new docs active.
