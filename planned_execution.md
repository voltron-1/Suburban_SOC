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
follow-ups #182-#185 filed during remediation itself (see below).

Next unstarted item: **#168** — CI has no linter and functional tests are
path-filtered (SA-11/CM-3).

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (NIST SP 800-53 Rev.5 SI-10 / CSF 2.0 PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178)
  merged; issue closed. Broker suite 23→29 tests, all passing.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  merged; issue closed. 20 new tests, all passing (real CI confirmed via
  `soar-tests.yml` for the slo_metrics half — `run_hunts.py` has no CI path yet,
  tracked under #168). Deferred `agent_app.py:696` (audit-write visibility) to a
  follow-up — filed as #184.
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
  stack — this part is holding. `slo-metrics.service` sandboxing (empty
  CapabilityBoundingSet, ProtectSystem=strict, etc.) deployed and confirmed
  working. **`zeek-host-capture.service` sandboxing was deployed, broke live
  capture in production (crash-loop), and was reverted same-day** — root cause
  turned out to be the WSL2 `eth0` interface being administratively down
  (unrelated to the hardening directives, confirmed via journalctl), but the
  unhardened unit file is what's currently live. Follow-up #182 (capability
  scoping) now also covers re-attempting sandboxing safely. `es_common.sh`'s
  shared `elastic` default deliberately left alone (~15 other legitimate
  admin-tooling consumers depend on it).
- [x] **#185** (unplanned, discovered this session) — `deploy_detections.sh`
  silently no-op'd on every run since its introduction (#93, 2026-06-12):
  competing `< "$RAW"` / `<<'PY'` stdin redirects meant the heredoc always won,
  so the transformed rule payload was always empty, and Kibana's import API
  returns `success:true` for an empty file — a silent false-positive matching
  the SI-11 pattern (CM-3, SI-11). Surfaced while investigating shellcheck
  findings for #168. Fixed via `RAW_PATH` env var + explicit `open()` instead of
  `sys.stdin`; verified with synthetic + realistic-data transform tests (20
  real rules exported from live Kibana, all transformed correctly). Live
  end-to-end import round-trip intentionally deferred (would mutate production
  rules without further sign-off). Branch `remediation/p1-issue-185-nist`
  (commit `add02c9`). [PR #186](https://github.com/voltron-1/Suburban_SOC/pull/186)
  open — awaiting merge.
- [ ] **#168** — CI has no linter and functional tests are path-filtered,
  leaving bash/reporting code ungated (SA-11/CM-3). Next up.

P2 remaining (#169-#172, #182, #183) and P3 (#173-#177, #184) tracked on
[Project Board #17](https://github.com/users/voltron-1/projects/17); working
sequentially in descending priority order per the remediation protocol, one
item at a time with explicit approval before each file change.

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
