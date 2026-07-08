# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: SOP-147 dashboard validation — final panel fixes (data-quality cleanup)**

- [~] **#160** — zeek.ssl SNI/Cipher panels. Pipeline fix + dashboard `.keyword` fix in
  **PR #162**; historical backfill done live (**5,711 docs** carry `tls.*`); Network
  dashboard redeployed — SNI/Cipher panels render live. **Blockers to close:** merge #162;
  activate pipeline on running Logstash (needs restart to reload config).
- [~] **#161** — Failed SSH by Country. Pipeline geoip/grok fix (+ HIGH spoof hardening) in
  **PR #162**; mock `country_name` backfilled (**800 docs**) — panel renders China/NK/Russia
  live. **Blocker to close:** merge #162.

After #162 merges the open-issue backlog is empty — next phase TBD (define with owner).
PR: https://github.com/voltron-1/Suburban_SOC/pull/162 ·
Evidence: `findings/20260707-160-161-logstash-ecs-geoip.md`.

---

## LAST SESSION — 2026-07-08

- #160/#161: shipped pipeline ECS fixes + HIGH source.ip-spoof hardening (parallel
  code-reviewer + security-auditor) in PR #162 off fresh branch. Live investigation found two
  extra root causes the issues missed: (1) panels bucket on `.keyword` subfields absent on the
  keyword-mapped real data (fixed net-sni/net-cipher, like be95698); (2) #161 is ~entirely
  mock-data-driven. Backfilled tls.* (5,711 real docs, via approved ILM write-block
  lift+restore) and mock `country_name` (800 docs); redeployed the Network dashboard. Both
  panels verified rendering via live aggregations. Pipeline config not yet reloaded on running
  Logstash (needs restart / host docker access).

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
- [!] Activate the PR #162 pipeline config on the **running Logstash** — needs a Logstash
  restart to reload bind-mounted `configs/logstash.conf` (host docker access; not reachable
  from this WSL distro). Until then, forward enrichment of *new* docs is inactive; historical
  docs already backfilled.
