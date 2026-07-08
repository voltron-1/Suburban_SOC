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

Next unstarted item: **#167** — Unhardened systemd units + `elastic` superuser
default in host automation (AC-6, CM-7).

- [~] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (NIST SP 800-53 Rev.5 SI-10 / CSF 2.0 PR.PS-06). Fixed + tested on branch
  `remediation/issue-164-nist` (commit `beaac0b`); broker suite 23→29 tests, all
  passing. [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178) opened
  — awaiting review/merge.
- [~] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). Fixed + tested on branch `remediation/issue-165-nist`
  (commit `46b81cb`); 20 new tests, all passing (real CI confirmed via
  `soar-tests.yml` for the slo_metrics half — `run_hunts.py` has no CI path yet,
  tracked under #168). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  opened — awaiting review/merge. Deferred `agent_app.py:696` (audit-write
  visibility) to a follow-up — no metrics/health surface to hook a counter into yet.
- [~] **#166** — Bash admin tooling skipped TLS verification (`curl -k`) while
  sending ES credentials (SC-8). Fixed + verified end-to-end against the live
  running stack (no CI path for these scripts) on branch
  `remediation/issue-166-nist` (commit `70245a9`); also fixed the `lifecycle`
  compose one-shot, which had no CA mounted and would have broken stack startup
  once the fail-closed default landed. [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180)
  opened — awaiting review/merge. Operator note: any host script relying on the
  old implicit `-k` fallback now needs `ES_CA=<path>` or `ES_INSECURE=true`.
- [ ] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7).

P2 (next sprint, #168-#172) and P3 (backlog, #173-#177) are tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17); not
individually sequenced here until the P1 critical items above clear.

Note: #164, #165, and #166 are on independent branches off the same
`origin/main` commit, each with its own `planned_execution.md` edit — expect
trivial merge conflicts in this file as each PR merges; resolve by keeping all
items' status lines.

---

## LAST SESSION — 2026-07-08

- Principal-engineer structural health review of the full repo (architecture map,
  robustness/access-control gap analysis mapped to NIST CSF 2.0 + SP 800-53
  Rev.5, sustainability/test/resource-management lenses). Filed 14 issues
  (#164-#177: P1 critical ×4, P2 medium ×5, P3 low ×5) with evidence, control
  mappings, and acceptance criteria; labeled by priority/nist-compliance/
  tech-debt/security; linked to [Project Board #17](https://github.com/users/voltron-1/projects/17).
- Remediation in progress: **#164** (unvalidated `attacker_ip` in hive-mind-broker
  reaching the `nft`/SSH sink — SI-10/PR.PS-06), branch `remediation/issue-164-nist`,
  [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178). **#165** (SLO
  metrics/threat hunts silent ES-failure swallowing — SI-11), branch
  `remediation/issue-165-nist`, [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179).
  **#166** (bash tooling `curl -k` TLS skip — SC-8, plus a `lifecycle` compose
  fix), branch `remediation/issue-166-nist`, [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180).
  None merged yet.
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
