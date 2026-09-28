# Playbook Migration Report — Dynamic HTML Playbook System

## Summary

Migrated `docs/playbooks/IR_Sigma_Playbook.md` (single 560KB Markdown
document, 120 per-rule playbook entries) into a structured-data playbook
system served through the existing SOC AI Agent Flask app
(`scripts/setup/ai_agent/agent_app.py`), at `/playbooks` and
`/playbooks/<rule_id>`. `docs/playbooks/IR_Sigma_Playbook.md` is retained
unchanged; nothing in this change removes it or the Markdown runtime path
(there wasn't one — the original document was never rendered at runtime,
only read by analysts directly in the repo/wiki).

## Architecture

```
docs/playbooks/IR_Sigma_Playbook.md
          |
          v
playbooks/migration/split_ir_sigma_playbook.py   (parser, rerunnable)
          |
          v
playbooks/data/<rule_id>.json   (120 files, one per rule)
          |
          v
playbooks_blueprint.py   (Flask Blueprint, registered on agent_app.py)
          |
          v
templates/playbooks_dashboard.html, playbooks_detail.html
          |
          v
Analyst browser  (GET /playbooks, /playbooks/<id>)
          |
          +--> /playbooks/<id>/context.json  (AI-consumable, structured, no HTML)
```

No new service, container, port, or database was introduced. Flask and
Jinja2 were already repo dependencies (`scripts/setup/ai_agent/requirements.txt`);
nothing was added to it.

## Files created

```
playbooks/schema/playbook.schema.json
playbooks/schema/enums.json
playbooks/migration/split_ir_sigma_playbook.py
playbooks/data/*.json                              (120 files)
scripts/setup/ai_agent/playbooks_blueprint.py
scripts/setup/ai_agent/templates/_playbooks_base.html
scripts/setup/ai_agent/templates/playbooks_dashboard.html
scripts/setup/ai_agent/templates/playbooks_detail.html
scripts/setup/ai_agent/templates/playbooks_404.html
tests/ai_agent/test_playbooks_blueprint.py
docs/playbook-migration-inventory.md
docs/playbook-migration-report.md                  (this file)
```

## Files modified

```
scripts/setup/ai_agent/agent_app.py   (+4 lines: import + blueprint registration)
```

No other file was touched. `agent.py`, `checkpoints.py`, the Hive-Mind
broker, docker-compose, and every existing route/test in `agent_app.py`
are unchanged.

## Dependencies added / removed

None. Flask and Jinja2 were already present. No Markdown-rendering library
(`marked`, `markdown-it`, `react-markdown`, etc.) exists anywhere in this
repo to remove — the repo has no JS frontend at all, so build-prompt Phase
27 ("remove obsolete Markdown runtime dependencies") does not apply; there
is nothing to remove.

## Content preservation

Each of the 5 fixed subsections (Rule Summary & MITRE Mapping / Automated
Extraction Fields / Enrichment Criteria / Containment Decision Flow /
Remediation & Evidence Preservation) is captured **verbatim** as a single
Markdown-text block, rather than decomposed into finer-grained typed blocks
(table/list/codeBlock split apart). This was a deliberate choice, documented
in the parser's module docstring: the source mixes prose, tables, nested
lists, and fenced KQL/code blocks within a subsection in ways that cannot be
safely auto-split at this scale (120 entries, 560KB) without per-rule manual
review. Preserving each subsection verbatim guarantees the build prompt's
"preserve commands exactly" / "do not silently discard content" requirements
take priority over finer-grained structure. Commands, KQL/Zeek queries, and
MITRE technique IDs were spot-checked against the source and match exactly
(see `test_every_playbook_id_matches_its_filename` and the manual diff
performed during development).

**Content requiring special handling:** none identified beyond the above —
no subsection was empty, no metadata line was malformed, across all 120
entries (the parser's warning system, which would have flagged either,
produced zero warnings on this run).

**Content gap (not a preservation failure):** 13 rule files have no
playbook entry in the source document at all — see
`docs/playbook-migration-inventory.md` for the full list and reasoning.
These are flagged, not silently omitted from the "complete" claim below.

## Schema changes required

None beyond the initial schema design — `playbooks/schema/playbook.schema.json`
was written directly against the discovered 5-subsection shape and validated
against all 120 generated records with zero errors on first correct pass
(one self-caught bug: the schema's `blockType` enum initially omitted
`"markdown"`, the type the parser actually emits — fixed before this report
was written).

## Renderer changes required

None post-implementation. `playbooks_blueprint.py` and its 4 templates were
built once against the finalized schema.

## Suburban-SOC integration issues

- **Containment boundary is stronger than the original architecture diagram
  implied.** The diagram shows a single "SOC AI Agent" container handling
  both triage and OpenWrt quarantine dispatch. In the actual repository,
  containment execution is a separate service, `scripts/hive-mind-broker/`
  (FastAPI), reached over an HMAC-signed webhook, with its own replay
  protection, per-tenant router inventory, and a permanent IP exclusion
  list. This migration's read-only playbook routes live entirely in
  `agent_app.py` and never call the broker, directly or indirectly.
- **Containment shown in the migrated playbooks is EDR/identity-layer, not
  OpenWrt.** Across the 120 migrated entries, the "Containment Decision
  Flow" subsection describes EDR network isolation, AD/IdP account
  disable, and credential/session revocation — not OpenWrt MAC quarantine.
  Only one incidental mention of "OpenWrt" exists in the entire source
  document (a false-positive-check note, not a containment instruction;
  verified by direct grep, not sampling). OpenWrt-specific containment
  playbooks, if wanted, would need to be authored as part of closing the
  13-rule gap above, for any Suricata/network rule whose response path is
  OpenWrt-based.
- **AI triage integration**: `/playbooks/<id>/context.json` exposes
  structured `mitre` and `aiContext` fields for the AI layer to consume,
  per build-prompt Phase 16's "do not make the AI scrape rendered HTML"
  requirement. `agent.py`/`agent_app.py`'s existing triage logic does not
  yet call this endpoint — wiring it in was out of scope for this migration
  (which is presentation/structure only, per the original brief's Phase 5
  scope control) and is listed under remaining technical debt below.

## Security issues

None found. Jinja2 autoescaping (the Flask/Jinja2 default) is relied on
throughout; no template uses `|safe` or disables autoescaping on any
playbook-derived field (enforced by a static test,
`test_no_unsafe_jinja_filter_in_playbook_templates`, in addition to two
runtime XSS probes that inject `<script>alert("XSS")</script>` into both a
section body and an evidence-list item and assert it renders escaped, not
executable). Rule ids are validated against `[a-z0-9_]+` before touching the
filesystem, closing path traversal via the `<rule_id>` URL segment (tested).
No command or query shown in any playbook is executed — the routes are
GET-only and read-only; no route in `playbooks_blueprint.py` shells out,
calls the Hive-Mind broker, or writes to disk.

## Migration issues

None blocking. The one self-caught schema bug (missing `markdown` in the
`blockType` enum) was fixed before any test ran green; see "Schema changes
required" above.

## Test coverage

`tests/ai_agent/test_playbooks_blueprint.py`, 15 tests, all passing:
schema validation across all 120 records, registry/id consistency, 5-section
completeness, dashboard/detail/404/filter routing, path-traversal rejection,
the AI-context JSON contract, and the two XSS probes plus the static
`|safe`-usage guard. Full existing `tests/ai_agent/` suite (559 tests, 14
subtests) re-run and confirmed passing unaffected — the one pre-existing
collection error (`test_weekly_ciso_report.py`, missing `weasyprint` module)
is unrelated to this change and present on `main` independent of it (this
cloud session has no Docker/live-infra, matching `CLAUDE.md`'s documented
environment limits; not introduced or worsened here).

Drift check (`playbooks/migration/split_ir_sigma_playbook.py --check`)
passes with "No drift detected" as of this report's generation — the 120
generated files exactly match what re-parsing the current
`IR_Sigma_Playbook.md` produces.

## Known limitations

1. 13 rules (11 Suricata + 2 recently-added Sigma) have no playbook content
   to migrate — see inventory doc. Not a tooling gap; a content gap.
2. Subsection content is preserved as single Markdown-text blocks rather
   than decomposed into typed sub-blocks (table/list/codeBlock split
   apart) — see "Content preservation" above for the reasoning. The
   `codeBlock`/`queryBlock`/`table`/`list` block types exist in the schema
   for future finer-grained authoring but are not yet produced by the
   automated parser.
3. `agent.py`'s AI triage logic does not yet call `/playbooks/<id>/context.json`
   — the endpoint exists and is tested, but wiring it into the live triage
   path was left out as beyond this migration's presentation/structure
   scope.
4. No search-relevance ranking — the dashboard's search box does a
   case-insensitive substring match on title/id only.

## Remaining technical debt

- Author playbook content for the 13-rule gap (item 1 above), ideally
  extended from `docs/Playbook-Structure.md`'s canonical template to also
  carry the 5-subsection shape, so the parser (or a near-identical one) can
  ingest it the same way.
- Wire `agent.py`'s triage path to call `/playbooks/<id>/context.json` when
  a rule id is known, per the original brief's Phase 16 intent (structured
  context, not HTML scraping) — this migration built the endpoint but did
  not connect it, to keep this change additive/reviewable.
- Consider decomposing subsection content into the schema's finer-grained
  block types (table/list/codeBlock) once there is a lower-risk way to
  validate that split doesn't lose or reorder content across all 120+
  entries — e.g. a table-cell-count/row-count round-trip check.
- The drift-check script is not yet wired into CI; running it as a CI gate
  (fail the build if `IR_Sigma_Playbook.md` changes without regenerating
  `playbooks/data/`) would close the loop this migration's own audit fix
  #6 was meant to address structurally, not just make available as a
  manual command.

## Suburban-SOC integrations validated

Zeek, Filebeat, Logstash, Elasticsearch, Kibana, Suricata, OpenWrt/Hive-Mind
broker, and `docker-compose.yml`/`soc_pipeline.sh` are all **unaffected** —
no file belonging to any of those was read, imported, or modified by this
change. Verified by `git diff --stat` against `main` showing only the files
listed under "Files created"/"Files modified" above, and by the full
existing test suite passing unaffected.
