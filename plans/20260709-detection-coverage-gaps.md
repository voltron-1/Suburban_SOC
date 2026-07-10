# Plan — Windows detection coverage gaps (Security/System/WMI/PowerShell)

Status: in progress. Full design rationale already captured in the GitHub issue
this branch closes (see issue link below once opened).

## Sequence
1. Open GitHub issue (coverage gap description + rule table) + plan comment.
2. Branch: `detections/issue-<N>-coverage-gaps` off `main`.
3. Implement, in order:
   - `configs/detections/suburban-soc-ecs.yml` — logsource-conditioned pySigma
     pipeline additions (Security/System/WMI/PowerShell channels keep raw
     `winlog.event_data.*`; only add mappings actually needed by the new rules).
   - 11 new Sigma rules (rules 1a–7) + fixtures.json entries. Rule 8
     (PowerShell script-block) only if 1–7 land clean.
   - Elastic threshold-rule companions (`rules/elastic/threshold/*.ndjson`) for
     1a/1b, plus `tests/detections/test_threshold_rules.py`.
   - `deploy_detections.sh` — import step for the threshold ndjson companions.
   - `configs/endpoint/winlogbeat.yml` — approved diff (1102, 4728, 4756, 104,
     7040, 7045, WMI-Activity 5861, +4103/4104 if rule 8 lands).
   - `scripts/setup/build_attack_coverage.py` — stop hardcoding data-source
     column; read `logsource:` per rule.
   - Regenerate `docs/detections/attack-coverage.{md,json}`,
     `docs/detections/SIEM_KQL_Documentation.md` (via build_kql_docs.py),
     `coverage_checklist.md`, README rule count, stale-count refs in
     docs/SOC-maturity-roadmap.md / docs/implementation_plan.md / SOP docs.
4. Local gate run (mirrors CI): test_framework_enrichment.py,
   test_sigma_detections.py, test_threshold_rules.py, sigma convert gate,
   build_attack_coverage.py --check, build_kql_docs.py --check.
5. Parallel delegation: `security-auditor` + `code-reviewer` on the full diff.
6. Delegation: `tester-debugger` to run the full detections/pipeline test
   suite and confirm the fixture+conversion gates hold.
7. Address findings, commit, push, open PR closing the issue.

## Key constraints from recon (do not violate)
- `tests/detections/sigma_eval.py` has no correlation/aggregation support and
  the CI Lucene conversion can't express counts — 1a/1b ship as
  `status: experimental` Sigma (logic-of-record, excluded from
  deploy_detections.sh's query-rule import) + hand-authored Elastic threshold
  rules.
- `test_framework_enrichment.py` forbids the substring `sigma_` anywhere in
  `configs/logstash.conf` and requires 1:1 threat.technique/tactic/nist
  add_field counts — do not touch logstash.conf for this work.
- `sigma_eval.py` only supports modifiers: contains, endswith, startswith,
  all, cased. No regex/base64/cidr/windash — keep new rules within that set.
- Every new rule needs an `id`, `status`, `detection`+`condition`, and an
  `attack.tXXXX` tag (`test_every_rule_is_valid_detection_as_code`).
- `build_attack_coverage.py --check` and `build_kql_docs.py --check` are CI
  drift gates — must regenerate and commit outputs, not just source.
