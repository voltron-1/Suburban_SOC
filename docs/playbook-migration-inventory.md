# Playbook Migration Inventory

Generated as part of the dynamic-HTML playbook migration. Source document:
`docs/playbooks/IR_Sigma_Playbook.md`.

## Scope finding

Unlike the original migration brief's assumption (a set of separate
operational `.md` files, e.g. `zeek-triage.md`, `host-quarantine.md`), this
repository's playbook content is **one single Markdown document**
(`docs/playbooks/IR_Sigma_Playbook.md`, ~560KB) that already contains a
per-rule "playbook" entry for most Sigma detection rules, organized by rule
family. Each entry follows a fixed 5-subsection shape:

1. Rule Summary & MITRE Mapping
2. Automated Extraction Fields
3. Enrichment Criteria
4. Containment Decision Flow
5. Remediation & Evidence Preservation

The migration unit is therefore **one structured playbook record per rule**,
not per file. `playbooks/migration/split_ir_sigma_playbook.py` parses the
source document by its `<a id="...">` anchors (which match rule filename
stems exactly) and emits one JSON record per rule to `playbooks/data/`.

`docs/Playbook-Structure.md` (the blank template referenced by `README.md`)
and `governance/playbook_template.md` (marked superseded by
`docs/Playbook-Structure.md`) are documentation/authoring aids, not
operational content, and are **not** migrated — they remain Markdown per
Phase 1's classification rules (keep as Markdown: developer/authoring docs).

## Coverage

| Metric | Count |
|---|---|
| Sigma rule files (`rules/sigma/*.yml`) | 122 |
| Suricata rule files (`rules/suricata/*.rules`) | 11 |
| Total rule files | 133 |
| Playbook entries found in source document | 120 |
| Rules with a migrated structured playbook | 120 |
| Rules with **no** playbook entry (gap — see below) | 13 |

## By category (of the 120 migrated)

| Category | Count |
|---|---|
| Windows Process Creation | 54 |
| Zeek Network Telemetry | 23 |
| Windows Security Log - Authentication & Identity | 16 |
| PowerShell Script Block Logging | 8 |
| Windows System Log - Service Control Manager & Event Log Service | 6 |
| Linux Authentication | 5 |
| Linux Process Creation | 5 |
| Sysmon Specialized Events | 2 |
| WMI Activity | 1 |

## By severity (of the 120 migrated)

| Severity | Count |
|---|---|
| medium | 50 |
| high | 48 |
| low | 13 |
| critical | 9 |

## Known gap: 13 rules with no playbook entry

Per the audit fix requiring the migration to halt/flag rather than silently
mark itself complete over a content gap, these are **not** migrated because
no corresponding content exists in the source document — nothing was
discarded:

**All 11 Suricata rule files have no playbook entry at all** (the source
document is titled "IR Sigma Playbook" and appears to have been scoped to
Sigma rules only):

- `auth_sso_abuse`
- `exfiltration_dlp`
- `iot_lab_research`
- `local`
- `phishing_email`
- `ransomware_c2`
- `recon_scanning`
- `remote_access_abuse`
- `residential_policy_violations`
- `web_lms_attacks`
- `web_shell_compromise`

**2 Sigma rules are newer than the playbook document** (both added via PR
#564, merged 2026-09-07, per `CLAUDE.md`'s session notes — after
`IR_Sigma_Playbook.md` was last restructured):

- `system_lnx_ca_fingerprint_mismatch`
- `system_lnx_self_health_unit_failed`

**Recommendation:** these 13 rules need playbook content authored (using
`docs/Playbook-Structure.md`'s structure, extended to match the 5-subsection
shape used elsewhere for consistency) before they can be migrated. This is a
content-authoring task, not a migration-tooling task — the parser and
renderer already support them the moment matching content exists; re-running
`playbooks/migration/split_ir_sigma_playbook.py` after IR_Sigma_Playbook.md
is extended will pick them up automatically.

## Per-rule detail

Full per-rule detail (filename, purpose, complexity, formatting) is not
duplicated here — it is preserved directly in each structured record; see
`playbooks/data/<rule_id>.json`. All 120 include: multiple heading levels,
numbered/tabular procedures, MITRE tactic/technique mapping, an "Automated
Extraction Fields" table, enrichment/TI criteria, a containment decision
flow (including KQL queries and, where relevant, auto-containment tiers),
and evidence-preservation steps citing `docs/SOP-147-evidence-validation-runbook.md`.
None reference OpenWrt commands directly by name in the sampled entries —
containment for these rules is EDR/AD/IdP-level (isolation, account
disable, credential revocation) rather than the OpenWrt MAC-quarantine path
shown in the architecture diagram, which is a separate containment
mechanism reached through `scripts/hive-mind-broker/` for network-layer
(Zeek/Suricata-sourced) findings. See the migration report for the full
architecture note.
