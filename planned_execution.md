# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: Structural Health Review Remediation — Priority 1 (Critical).**
Source: repo-wide structural/NIST-CSF-2.0/SP-800-53-Rev.5-aligned review,
2026-07-08 — 14 issues filed (#164-#177) and linked to
[Project Board #17](https://github.com/users/voltron-1/projects/17).

Next unstarted item: **#166** — Bash admin tooling skips TLS verification
(`curl -k`) while sending ES credentials (SC-8).

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (NIST SP 800-53 Rev.5 SI-10 / CSF 2.0 PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178)
  merged; issue closed. Broker suite 23→29 tests, all passing.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  merged; issue closed. 20 new tests, all passing (real CI confirmed via
  `soar-tests.yml` for the slo_metrics half — `run_hunts.py` has no CI path yet,
  tracked under #168). Deferred `agent_app.py:696` (audit-write visibility) to a
  follow-up — no metrics/health surface to hook a counter into yet.
- [ ] **#166** — Bash admin tooling skips TLS verification (`curl -k`) while
  sending ES credentials (SC-8). [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180)
  open, verified end-to-end against the live stack — awaiting merge.
- [ ] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7). [PR #181](https://github.com/voltron-1/Suburban_SOC/pull/181)
  open, verified end-to-end against the live stack — awaiting merge. Template-only;
  operator must redeploy both systemd units to apply. Follow-up filed: #182
  (zeek-host-capture.service capability scoping, deferred — needs live-tested sudo
  access not available this session).

P2 (next sprint, #168-#172) and P3 (backlog, #173-#177) are tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17); not
individually sequenced here until the remaining two P1 PRs (#180, #181) merge.

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
- **#164 merged** (PR #178): unvalidated `attacker_ip` in hive-mind-broker
  reaching the `nft`/SSH sink — SI-10/PR.PS-06.
- **#165 merged** (PR #179): SLO metrics/threat hunts silent ES-failure
  swallowing — SI-11.
- #166, #167 fixed and PR'd (#180, #181), verified end-to-end against the live
  stack, not yet merged. Two follow-up issues filed: #182 (zeek-host-capture
  capability scoping) and #183 (weasyprint CVE).
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
