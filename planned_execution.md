# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: SOP-147 dashboard validation — final panel fixes (data-quality cleanup)**

Next unstarted item: none after the two below. Once #160/#161 merge, the open-issue
backlog is empty — next phase is TBD (define with owner).

- [~] **#160** — zeek.ssl SNI/cipher ECS-normalized (`tls.*`) — fix applied, in review,
  live verification pending stack.
- [~] **#161** — auth.log source geoip + grok ECS fix (Failed SSH by Country) — fix applied
  (incl. HIGH source.ip-spoof hardening from review), in review, live verification pending.

Both land in one branch off `main` (currently on stale merged `fix/ingest-lag-slo-recovery`).
Evidence: `findings/20260707-160-161-logstash-ecs-geoip.md`.

---

## LAST SESSION — 2026-07-07

- Opened work on #160 + #161 (last two open issues, both SOP-147 leftovers).
- Applied ECS normalization (#160) and source-geoip + grok hardening (#161) to
  `configs/logstash.conf`; parallel code-reviewer + security-auditor pass; fixed a HIGH
  source.ip-spoof regression + MEDIUM backtracking/PII findings. Not yet committed
  (awaiting approval) or live-verified (stack down).

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
- [ ] Live verification + historical reindex/rollover for #160/#161 — **blocked on stack up**
  (ES down locally; needs sudo restart per the ingest-pipeline-restart runbook).
