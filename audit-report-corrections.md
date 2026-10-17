# Corrections to the 2026-08-31 "Suburban-SOC Repo Audit" report

Report: <https://claude.ai/artifact/5AzQC8fZaSZ4bAtd2jgpdT> (not edited; corrections listed here).
Prepared 2026-10-17. Each item quotes the report, then gives the correction and how it was checked.

## 1. §05.1 — closed-issue split doesn't sum

**Report:** "263 issues all-time · 14 currently open · 249 closed (248 `completed`, one `not_planned` trio: #66/#67/#68)". 248 + 3 = 251, not 249.

**Correction:** **249 closed = 244 `completed` + 5 `not_planned`** — #66, #67, #68, #223, #289.

**Method:** `gh api --paginate 'repos/voltron-1/Suburban_SOC/issues?state=all&per_page=100'`, pull requests excluded. Took the issues created on or before 2026-08-31 minus the audit's own batch (#508–#523, created that day) = 263, and counted `state_reason` for those with `closed_at ≤ 2026-08-31T23:59:59Z`. Caveat: `closed_at` reflects an issue's latest close, so an issue closed at audit time and later reopened is not in this count.

## 2. §07, plan item 09 — wrong incident named

**Report:** "Logstash crash-loop (a documented incident with no runbook entry)".

**Correction:** the documented incident is the **`zeek-host-capture.service` crash-loop** (§02.3, narrated in `planned_execution.md` around lines 3215, 3298, 4122 and 4898). The Logstash pipeline crash-loop was listed in §02.3 as one of three *plausible but undocumented* failure modes.

## 3. §08 — orphan "M5 count discrepancy"

**Report:** §08's round-2 row lists "M5 count discrepancy" among the GitHub verification topics.

**Correction:** no finding in §00–§07 mentions an M5 discrepancy. Either remove it from §08 or add the finding it refers to.

## 4. "13 SOPs" (repo) vs "13 SOP pages" (wiki) — different sets

**Report:** §00/§02.1 "13 SOPs" in `docs/`; §04 "13 SOP pages (003–013 + 022 + 147)".

**Correction:** label and list them separately:

- **Repo, `docs/`:** 13 distinct SOP numbers in 15 files — 001, 003, 004, 005, 007, 008, 009, 010, 011, 012, 013, 022, 147 (022 and 147 each have a top-level file plus a procedure/runbook file).
- **Wiki:** 14 `SOP-*` pages — SOP-001, 003, 004, 005, 007–013, 022, 147, plus the separate `SOP-Pipeline-Operations` page. The report's "003–013 + 022 + 147" describes 12 pages (there is no 002 or 006).
