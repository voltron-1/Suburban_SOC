# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: Structural Health Review Remediation — Priority 1 (Critical) COMPLETE.
Priority 2: #164-#167, #170 fixed; #168/#169 fixed pending merge (PRs
#187/#188); #171-#172 not yet started.**
Source: repo-wide structural/NIST-CSF-2.0/SP-800-53-Rev.5-aligned review,
2026-07-08 — 14 issues filed (#164-#177), 5 more filed since (#182-#183,
#185, #189-#190), all linked to
[Project Board #17](https://github.com/users/voltron-1/projects/17).

Next unstarted item: **#171** — broker security events logged via bare
`print()`, no persisted record of denied/replayed/invalid-signature attempts
(AU-2/3/12). Open PRs #185/#186 (deploy_detections.sh fix), #187 (#168 — CI
lint gate), #188 (#169 — Logstash DLQ) still awaiting a batch-merge decision
from the owner.

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (NIST SP 800-53 Rev.5 SI-10 / CSF 2.0 PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178)
  merged; issue closed. Broker suite 23→29 tests, all passing.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  merged; issue closed. 20 new tests, all passing (real CI confirmed via
  `soar-tests.yml` for the slo_metrics half — `run_hunts.py` has no CI path yet,
  tracked under #168). Deferred `agent_app.py:696` (audit-write visibility) to a
  follow-up — no metrics/health surface to hook a counter into yet.
- [x] **#166** — Bash admin tooling skipped TLS verification (`curl -k`) while
  sending ES credentials (SC-8). [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180)
  merged; issue closed. Also fixed the `lifecycle` compose one-shot, which had no
  CA mounted and would have broken stack startup once the fail-closed default
  landed. Operator note: any host script relying on the old implicit `-k`
  fallback now needs `ES_CA=<path>` or `ES_INSECURE=true`.
- [x] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7). [PR #181](https://github.com/voltron-1/Suburban_SOC/pull/181)
  merged; issue closed. New least-privilege `slo_metrics_reader` ES role +
  `slo_metrics` user, live-created and verified end-to-end against the running
  stack. `zeek-host-capture.service` hardened conservatively only (no
  capability/`User=` changes — actively capturing real traffic, no safe way to
  live-test a narrower capability set this session; does not reach the ≤6.0
  target). `es_common.sh`'s shared `elastic` default deliberately left alone
  (~15 other legitimate admin-tooling consumers depend on it). **Template-only
  change — operator must redeploy both systemd units to apply**
  (`sudo cp configs/systemd/{slo-metrics,zeek-host-capture}.service
  /etc/systemd/system/ && sudo systemctl daemon-reload`, then restart each;
  see redeploy runbook). Follow-up filed: #182 (zeek-host-capture.service
  capability scoping).
- [x] **#170** — ES client/credential consolidation (#156/#157) incomplete; no
  connection reuse or retry (CM-2). Branch `remediation/p2-issue-170-nist`,
  PR pending. New `scripts/setup/lib/es_client.py` (`requests.Session` +
  `urllib3.Retry`; `read=0` deliberately — never auto-retry a write after a
  read-timeout, only pre-send connection failures and explicit 502/503/504);
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

P2 remaining (#168, #169 open as PRs #187/#188; #171-#172) and P3 (backlog,
#173-#177) are tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17).

Also filed this session (unrelated to the P1 fixes themselves, surfaced while
investigating CI failures): #183 — `weasyprint==68.0` pinned in
`scripts/setup/ai_agent/requirements.txt` has a disclosed CVE (CVE-2026-49452,
CSS injection/SSRF via `presentational_hints`); a fix is available upstream
(69.0/68.1), not yet bumped.

---

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
