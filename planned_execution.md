# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Phase: Structural Health Review Remediation — Priority 1 (Critical) COMPLETE.
Priority 2 in progress.**
Source: repo-wide structural/NIST-CSF-2.0/SP-800-53-Rev.5-aligned review,
2026-07-08 — 14 issues filed (#164-#177) and linked to
[Project Board #17](https://github.com/users/voltron-1/projects/17). Plus
follow-ups #182-#185 filed during remediation itself.

Next unstarted item: **#170** — ES client/credential consolidation
(#156/#157) incomplete; no connection reuse or retry.

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (SI-10/PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178) merged; issue closed.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179) merged; issue closed.
  Deferred `agent_app.py:696` (audit-write visibility) — filed as #184.
- [x] **#166** — Bash admin tooling skipped TLS verification (`curl -k`) while
  sending ES credentials (SC-8). [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180) merged; issue closed.
  Operator note: host scripts relying on the old implicit `-k` fallback now
  need `ES_CA=<path>` or `ES_INSECURE=true`.
- [x] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7). [PR #181](https://github.com/voltron-1/Suburban_SOC/pull/181) merged; issue closed.
  New least-privilege `slo_metrics_reader` ES role/user — holding.
  `zeek-host-capture.service` sandboxing was deployed, broke live capture
  (root cause: WSL2 `eth0` down, unrelated to the hardening), reverted
  same-day — unit currently runs unsandboxed. Follow-up: #182.
- [x] **#185** (unplanned) — `deploy_detections.sh` silently no-op'd on every
  run since introduction (#93): competing stdin redirects meant the
  transformed rule payload was always empty, Kibana's import API returns
  `success:true` for an empty file (CM-3, SI-11). [PR #186](https://github.com/voltron-1/Suburban_SOC/pull/186) open.
- [x] **#168** — CI had no linter and functional tests were path-filtered
  (SA-11/CM-3). New always-on `lint.yml` (shellcheck/ruff/mypy/yamllint);
  `soar-tests.yml`/`detections.yml` path filters removed. Real CI confirmed
  working. [PR #187](https://github.com/voltron-1/Suburban_SOC/pull/187) open.
- [x] **#169** — Logstash had no dead-letter queue/persisted queue, and grok/
  JSON parse failures were tagged but still written to the main index
  (SC-24, CP-10). New `configs/logstash.yml` (persisted queue + DLQ) +
  durable named volume; `logstash.conf` output split to route
  `pipeline.error:true` events to a `logstash-security-quarantine-*` index;
  14 new golden-file grok/JSON tests (includes the #161 DEFERRED
  standalone-"Invalid user" gap); new "Quarantined Events" Kibana panel.
  **Live end-to-end verified**: real malformed/well-formed events posted
  through the running pipeline, confirmed routing to quarantine vs. main
  index respectively. **Found and fixed a real #166 regression along the
  way**: the `lifecycle` Docker one-shot was failing outright
  ("No such file or directory") because that PR's `es_common.sh` sourcing
  assumed a full repo checkout, but the `lifecycle` compose service only
  ever mounted `configs/elasticsearch/` — this was actively blocking
  Logstash from starting mid-session; fixed by mounting `scripts/setup/lib`
  into the container. Branch `remediation/p2-issue-169-nist` (commit
  `041b709`). [PR #188](https://github.com/voltron-1/Suburban_SOC/pull/188) open.
- [ ] **#170** — ES client/credential consolidation (#156/#157) incomplete;
  no connection reuse or retry. Next up.

P2 remaining (#171, #172, #182, #183) and P3 (#173-#177, #184) tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17); working
sequentially in descending priority order per the remediation protocol, one
item at a time with explicit approval before each file change.

Operator note: PRs #178-#181 (P1) are the only ones merged so far; #186-#188
(P2, plus the unplanned #185) are open, awaiting a batch merge decision —
same pattern as the P1 phase. Each independently verified (tests + live
stack where applicable) but not yet on `main`.

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
