# PR #571 — gitleaks allowlist: detection-coverage audit (security-auditor)

Read-only audit (no Bash in that agent session), persisted here by the main
session. Cross-check the empirical half against
`findings/20260914-pr571-testplan-verification.md`, which ran the scans.

## HIGH — whole-file `paths` exclusion disables every rule, including the repo's own P0 rule

`.gitleaks.toml:53` exempts `configs/server/suburban_soc_dashboards_bundle_final.ndjson`
from all 10 saved objects in the bundle, for every rule — including this repo's
`elastic-inline-basic-auth` (`:11`), which exists because audit P0-1 found an
`elastic:<password>` literal committed in a hand-authored HTML deliverable.

No compensating control: no `.pre-commit-config.yaml`, no `.githooks/`. CI
gitleaks is the only secret-scanning layer and is the control cited for NIST
RA-5 in `docs/COMPLIANCE_MATRIX.md:23`. Failure mode is *fewer findings*, which
nothing alerts on.

The PR's justification ("a wholesale Kibana export, not hand-edited prose") is
contradicted by the file: line 2 is a hand-authored markdown panel with inline
HTML (`<div style=...>`, a `<marquee>`), and lines 3-5 are three more. ATT&CK:
T1552.001; the change itself is a preventive-control impairment,
T1562.001-analogous in the CI supply chain.

Also in tension with `.gitattributes:64-66` (`*.ndjson text eol=lf`, audit
P2-16), which exists so this content is diffable and scannable. P2-16 and P0-1
now disagree on this path.

## MEDIUM — what the exclusion blinds in this file today

Grep-verified across the 10 objects (line 1 index-pattern, 2-8 visualization,
9-10 dashboard):

- `fieldFormatMap` -> `urlTemplate` (line 1):
  `https://talosintelligence.com/reputation_center/lookup?search={{value}}`.
  Clean today. Canonical field for keyed enrichment links (VT/Shodan/
  AbuseIPDB/GreyNoise take the key as a query param) — highest-likelihood
  future leak in the file.
- 4 markdown panels (lines 2-5, three with inline `<img src="data:image/j...`).
  Free text + HTML: a pasted Slack webhook, ntfy topic URL (#554 leaves
  `NTFY_TOPIC` unprovisioned) or presigned URL would normally hit stock rules.
- 10 `searchSourceJSON` blocks, all `kuery`. A saved hunt filtering on a
  captured `Bearer eyJ...` would normally hit the JWT/generic-api-key rules.
- Base map tile URL (line 6) — benign.
- 3 `data:image/jpeg;base64,` payloads; exactly one AWS-key-shaped run,
  `AIDAQAAAAAAAQIRIQMSM` on line 4. The `AAAAAAA` run is characteristic of
  JPEG base64 padding — the false-positive claim checks out.

Verified ABSENT today (0 hits, case-insensitive):
`password|passwd|api[_-]?key|secret|token|bearer|authorization|credential|basic `;
Vega specs; `enhancements`/`dynamicActions`/`urlDrilldown`; saved objects of
type `url`; `-----BEGIN`; long base64 runs other than the 3 images.
`xpack.*` is not applicable — it lives in `kibana.yml`, never in a saved-object
export.

Forward-looking: a Kibana connector/action or alerting-rule object added to
this bundle would be the highest secret-density class (webhook URLs, auth
headers, `apiKeyOwner`) landing in a pre-blinded file with no re-review trigger.

## MEDIUM — the narrower alternatives, and what gitleaks actually supports

(a) **Per-rule allowlist on `aws-access-token`** — supported (`[rules.allowlist]`,
already used at `:20-26`), but with `[extend] useDefault = true` you must
redeclare `[[rules]] id = "aws-access-token"`, which overrides the upstream
rule wholesale and forfeits upstream improvements. A legitimate objection, but
strictly narrower than what shipped.

(b) **Global `regexes` anchored on `data:image/...;base64,`** — supported but
*worse* here. `[allowlist] regexes` matches the finding's secret by default; to
anchor on context you need `regexTarget = "line"`, and in NDJSON one line is
one whole saved object, so it blinds nearly as much *and* applies repo-wide to
any file with a base64 image on a line. Rejecting it is correct; the PR rejects
it for the wrong reason (never mentions `regexTarget`).

(c) **`[allowlist] commits` / fingerprints** — correctly dismissed. The content
is in the working tree, so `--no-git` scans re-report it; fingerprint
suppression is `--baseline-path`, a CLI flag `gitleaks-action@v2` does not
expose.

(d) **De-inline the three JPEGs** — the actual root-cause fix. Removes the FP
and most of the file's bulk (serving P2-16's diffability goal). Costs: panels
need a reachable image URL (breaks offline import), and the edit must be made
in Kibana and re-exported or the next export reverts it. Reasonable to defer —
as a milestoned follow-up, not silently.

## MEDIUM — unanchored path regex; the new test does not check anchoring

`.gitleaks.toml:53` has no `^`/`$`. gitleaks matches `[allowlist] paths`
unanchored against the file path, so `...ndjson.bak` / `.orig` / `.rej` /
`.tmp` / `.example` / `.j2`, or a copy under any other root
(`evidence/2026-09/configs/server/...`, `backup/...`, an extracted tarball
dir), is also exempt. `.gitignore` does not ignore `*.bak`/`*.orig`/`*.tmp`, so
such a file is committable.

No live exposure: the only repo paths containing the string are
`.gitleaks.toml`, `tests/pipeline/test_gitleaks_allowlist.py`, and a prose
reference at `evidence/README.md:72`. The sibling
`configs/server/suburban_soc_dashboards_bundle.ndjson` correctly does not
match. Same weakness pre-exists at `:31` (`AUDIT_REPORT\.md` also matches
`notes_AUDIT_REPORT.md.bak`) — not introduced here.

`tests/pipeline/test_gitleaks_allowlist.py:44-58` claims to keep the entry
scoped, but all three decoys are non-matching under any plausible pattern and
nothing asserts anchoring — the test would still pass with the regex broadened
to a directory. Add `...ndjson.bak` and `backup/configs/server/...ndjson` as
decoys.

## LOW — CI does load this config, but by implicit discovery with nothing pinned

`.github/workflows/secret-scan.yml:18-21` sets no `--config` and no
`GITLEAKS_CONFIG`; the binary auto-discovers `.gitleaks.toml` at the scan-source
root. The PR's claim holds (confirmed in the run 34835114335 job log:
`DBG using existing gitleaks config .gitleaks.toml from '(--source)/.gitleaks.toml'`).

Two residual gaps: (i) nothing asserts the config was loaded — a rename or a
discovery change silently reverts CI to the stock ruleset, symptom "fewer
findings"; (ii) the workflow sets no `GITLEAKS_VERSION`, so only the action SHA
is pinned, not the scanner. **This is the gap that produced the phantom
defect** — see `findings/20260914-pr571-testplan-verification.md` §V2: the run
resolved 8.24.3, whose `aws-access-token` rule no longer carries the `AIDA`
prefix, so the finding this PR suppresses does not fire at all.

Fix: add `GITLEAKS_CONFIG: .gitleaks.toml` and an explicit `GITLEAKS_VERSION`
to that step's `env:`.

## LOW — the exclusion is retroactive across git history

A `paths` allowlist applies to every commit's version of that path, including
versions predating a rename. Verified separately (see the test-plan findings
file): a real full-history scan of 550 commits returns one finding, and it is
NOT in this file — it is `curl-auth-user` at
`docs/SOP-022-anomaly-validation.md:41`, commit `f642e1b3`.

## INFO — what the PR gets right; keep these in any revision

- `detections.yml:6-12` has no path filter and `:76` runs
  `python -m pytest tests/pipeline -q` as a directory glob, so the guard test
  genuinely runs on every PR.
- `test_dashboard_bundle_still_contains_the_documented_images` (`:66-71`) and
  `test_useDefault_still_extends_the_stock_ruleset` (`:73-78`) are well-chosen
  tripwires on the exclusion's premises.
- The comment block at `.gitleaks.toml:33-52` is unusually honest about the
  tradeoff. The disagreement is with the decision, not the disclosure.

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |
