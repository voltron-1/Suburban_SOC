# 2026-10-17 — Re-verification of the 2026-08-31 repo audit (Phase 0, read-only)

Source audit: artifact "Suburban-SOC Repo Audit" (claude.ai/artifact/5AzQC8fZaSZ4bAtd2jgpdT), audited 2026-08-31.
Checkout: `chore/audit-remediation` at `cc1448f` (= `origin/main`). No files edited in Phase 0 other than this one.

**Headline:** the audit was already turned into milestone **M25 – Repo Audit Remediation (#508–#523, +#539)**,
17/17 closed 2026-09-03 via PRs #525/#526 (+#543/#544). Most items no longer hold.

## Baseline gates (before any edit)

| Gate | Command | Result |
|---|---|---|
| pytest | `uv run --python 3.11 … python -m pytest tests/detections -q` (CI pins 3.11; system 3.12 lacks `smtpd`) | 91 passed, 24 skipped, **2 failed** — both `test_zeek_mime_detection.py` live-fire tests: `sudo: a password is required` for tcpdump (environmental, pre-existing) |
| ruff | `ruff check .` (0.15.15, CI pin) | pass |
| mypy | `.venv/bin/python -m mypy` over `git ls-files '*.py'` | pass (89 files). `~/.local/bin/mypy` reports 1 error at `scripts/setup/ai_agent/agent.py:590` — different mypy install, not the baseline |
| shellcheck | `git ls-files '*.sh' \| xargs shellcheck -S warning` | pass |
| yamllint | `yamllint -c .yamllint configs/` | pass |

Host note: `docker-desktop` WSL distro is **Stopped**; `zeek-host-capture.service` is `failed`; `suricata`/`filebeat` active.

## Per-item status

| # | Item | Status now | Evidence |
|---|---|---|---|
| 1 | Cert `O=UIW-SOC` | **Already fixed (#508)** | `generate_certs.sh:61,68` use `O=Suburban-SOC`. `grep UIW` still hits `:54`, an intentional operator advisory about pre-fix CAs. No re-mint needed: the stack's certs come from the compose `setup` service (Elastic certutil), not this script, which refuses to run without `ALLOW_STANDALONE_CERTS=1`; no standalone CA exists at `scripts/setup/certs/ca/ca.crt`. |
| 2 | `enforce_admins` | **Already fixed (#509/#539)** | Live: `enforce_admins: true`, strict, 14 required checks, no review gate, force-push/deletion off. Script `:10` documents both owner decisions. |
| 3 | Project board | **Readable now** | `gh project item-list 17`: 294 items (289 issues, 5 PRs) — 283 Done, 11 Backlog. Zero status/state mismatches. **5 issues not on board:** #192 (closed), #570 (open), #573 (open), #576 (closed), #577 (open). The 2026-08-29 Home.md narrative is superseded by #510's 2026-09-03 re-sync. |
| 4 | README M18 count | **Already fixed** | `README.md:83` "16/19 closed (updated 2026-09-04)"; live milestone 23: open=3 closed=16. |
| 5 | README M23/M24 rows | **Already fixed** | `README.md:88–89`; live M23 1/4, M24 5/5. |
| 6 | planned_execution M23 merge line | **Already fixed** | `planned_execution.md:339` says both merged; PR #506/#507 `MERGED` 2026-08-30. `:536` "still open/unmerged at the time" is historical narrative, correct. |
| 7 | CLAUDE.md M23/M24 note | **Already fixed (#513)** | Note removed; tracking pointer to README/planned_execution instead. |
| 8 | CLAUDE.md auto-close note | **Already fixed (#515)** | `CLAUDE.md:10` gives the real reasons (unreliable multi-close, negation ignored — #265). |
| 9 | SOP-147 runbook Watcher line | **Already fixed (#514)** | `docs/SOP-147-evidence-validation-runbook.md:30` now cites HMAC Logstash trigger + approval queue + #267. |
| 10 | M23 open issues | **Report** | #443, #444, #446 open; #445 closed. See "M23 report" below. |
| 11 | Canonical troubleshooting doc | **Done differently (#516)** | Canonical = `docs/master_pipeline_guide.md:436` "Troubleshooting Quick Reference"; SOP-001:76 and Zeek_ELK_Pipeline.md:5–8 point to it. No `docs/troubleshooting.md`. |
| 12 | 4 new entries | **Already present** | master_pipeline_guide.md:449–452 (ES red, Logstash crash-loop, Zeek silent death, detections CI). |
| 13 | "No data in Kibana" combined | **Already cross-referenced** | master_pipeline_guide.md:447 ↔ SOP-001:74. |
| 14 | 10 playbook entries + CI check | **Entries done (#517); CI check NOT present** | All 10 anchored in `IR_Sigma_Playbook.md`. No test enforces rule→entry coverage. Corpus is now **122** rules; **2 lack entries**: `system_lnx_ca_fingerprint_mismatch`, `system_lnx_self_health_unit_failed` (added by PR #564, M26). A check would fail today at 120/122. |
| 15 | SOP-001 SOAR section | **Already fixed (#518)** | `docs/SOP-001-pipeline-operations.md:55–61`. |
| 16 | Playbook templates | **Resolved the other way (#519)** | `docs/Playbook-Structure.md` is canonical; `governance/playbook_template.md:1` carries a "Superseded" banner. Refs: `README.md:403`, `docs/playbook-migration-inventory.md:26–28,97`, `docs/playbook-migration-report.md:203`. Reversing would contradict #519 and those docs. |
| 17 | implementation_plan.md:384 | Bullet is now at `:390` ("Troubleshooting blank panels…") in a dashboard-SOP spec. **Annotated 2026-10-17 (commit 7e64bdc):** points to the Troubleshooting Quick Reference in `docs/master_pipeline_guide.md`. |
| 18 | Suricata worklist | **Premise stale** | 80/100 enabled with TP/TN pcaps (165 fixture files), 20 disabled. The 20 are already categorized in `docs/detections/suricata-starter-set.md` (14 detection_filter, 2 placeholders 9000013/9000099, 2 DLP sign-off, 2 dead 9000063/9000064). Disabled SIDs: 9000001 2 5 8 9 10 13 46 60 62 63 64 65 66 73 80 82 83 99 100. |
| 19 | automate-infra-board.yml | **Already deleted (#520, commit bdc42ab)** | — |
| 20 | UIW branding | **Already fixed (#521)** | `.agyrules` clean; reports renamed `Suburban_SOC_*.html`; transcript kept with banner + redaction (`docs/AI_conversation_transcript.md:3–23`). Remaining `grep -rIil uiw` hits are all historical/intentional: README.md:90 & planned_execution.md:341/4351 (M25 narrative), logs/session-20260901.md:10, generate_certs.sh:54 (advisory), transcript paths, and a base64 false positive in `configs/server/suburban_soc_dashboards_bundle_final.ndjson`. **Owner decision 2026-10-17:** keep the transcript as-is and accept these hits as the intended residue (deleting it from HEAD would not purge history; the credential was already rotated). |
| 21–25 | Wiki pages | **Mostly fixed (#522/#523, wiki HEAD a364b4b 2026-09-04)** | Watcher mentions remaining are all retirement notes; SOP-Pipeline-Operations uses SOP-001-A…E/002/— (no collision, no sterlinggarnett link); Commit-Approach rewritten 2026-09-03; Sprint-Notes has a 2026-09-01 historical banner. **Gaps:** Final-Report has an inline SOAR correction but no top-of-page "academic snapshot / superseded" banner (#23). |
| 26 | Wiki Playbook-Structure | **Not done** | Wiki page is byte-identical to repo `docs/Playbook-Structure.md` (full blank template, not a pointer). |
| G | Audit report errors | **Still apply** (artifact not edited) | See corrections below. |

### New drift found (not in the audit)

- `README.md:451` — Usage → Architecture Flow still reads `**Response:** Kibana Watcher ➔ SOC AI Agent …`. Missed by the #267/#514 sweeps.

## M23 report (#443–#446) — for manual close decisions

| Issue | State | "Done when" (verbatim) | Evidence today |
|---|---|---|---|
| #443 | OPEN | "Suricata runs on the capture path next to Zeek, writes `eve.json` with real alerts from live traffic, survives a host reboot, and its death is visible." | `suricata.service` active (NRestarts=0, since 2026-10-17 10:46 CDT); `/var/log/suricata/eve.json` 50 MB but `grep -c '"event_type":"alert"'` = 0. Real-alert criterion not shown. Keep open. |
| #444 | OPEN | "A live Suricata alert lands in Elasticsearch, tenant-stamped, with populated `rule.*` fields, visible in Kibana, and covered by `pytest tests/pipeline`." | ES/Kibana down (Docker Desktop stopped); no live alert exists to land. Keep open. |
| #445 | CLOSED 2026-08-30 | — | — |
| #446 | OPEN | "`rules/suricata/` exists, CI is green across all 100 rules, and the enabled subset is exactly the rules with resolved placeholders and passing pcap fixtures." | 80 enabled, each with TP/TN pcap; 20 disabled with documented reasons; `test_suricata_rules.py` is a required CI gate. Reads as **met on its own wording** — candidate to close, owner's call. |

## Group G — corrections to the audit artifact

1. **§05.1 closed split.** "249 closed (248 completed, one not_planned trio)" doesn't sum. Recount from `gh api repos/voltron-1/Suburban_SOC/issues?state=all` (PRs excluded), taking the 263 issues created before the audit's own #508–#523 batch and `closed_at ≤ 2026-08-31`: **249 closed = 244 completed + 5 not_planned (#66, #67, #68, #223, #289)**. Caveat: `closed_at` reflects the latest close, so an issue closed then and reopened later is not counted.
2. **§07 plan item 09** calls the Logstash crash-loop "a documented incident". The documented incident (§02.3, `planned_execution.md` ~3215/3298/4122/4898) is the **`zeek-host-capture.service` crash-loop**. The Logstash crash-loop was a plausible but undocumented failure mode.
3. **§08 Methodology** lists "M5 count discrepancy" as a round-2 verification topic. No finding in §01–§07 mentions M5 — either drop it or add the finding it refers to.
4. **"13 SOPs" vs "13 SOP pages"** are different sets. Repo `docs/`: **13 distinct SOP numbers in 15 files**: 001, 003, 004, 005, 007–013, 022, 147, with 022 and 147 each split into a top-level file and a procedure/runbook file. Wiki: **14 `SOP-*` pages**: SOP-001, 003, 004, 005, 007–013, 022, 147, plus the separate `SOP-Pipeline-Operations` page. The report's "003–013 + 022 + 147" is 12 pages, since 002 and 006 don't exist. Label them "13 repo SOP numbers (docs/)" and "14 wiki SOP pages" and list each set.
