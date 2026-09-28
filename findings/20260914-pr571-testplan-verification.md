# PR #571 / issue #570 — test-plan verification (main session)

Scope: independently re-run PR #571's stated verification against the *pinned CI
gitleaks version* on the local WSL host (which is the capture host and has the
full 652-commit clone), not the cloud sandbox the PR was authored in.

Tooling: gitleaks **8.24.3**, downloaded to the scratchpad to match exactly what
`gitleaks/gitleaks-action@v2` installs in CI (job log, run 34835114335:
`gitleaks version: 8.24.3`).

## V1 — CI `gitleaks` green on this PR's head: TRUE but VACUOUS

Job log, run 34835114335, step "Run gitleaks":

    gitleaks cmd: gitleaks detect --redact -v --exit-code=2 --report-format=sarif \
      --report-path=results.sarif --log-level=debug --log-opts=--no-merges \
      --first-parent 67563c57a31e5474442e2c259c0e0cc76d3ffcfe^..67563c57a31e5474442e2c259c0e0cc76d3ffcfe
    INF 1 commits scanned.
    INF scanned ~5437 bytes (5.44 KB) in 148ms
    INF no leaks found

The action scans **only the PR's own commit range** on a `pull_request` event —
1 commit, 5.44 KB. `configs/server/suburban_soc_dashboards_bundle_final.ndjson`
is not in that diff and was never scanned. The check would be green with or
without the allowlist entry, so it is not evidence the fix works.

Corollary (pre-existing, out of scope for this PR): `.github/workflows/
secret-scan.yml` has `push` / `pull_request` / `workflow_dispatch` triggers and
no `schedule:`. `fetch-depth: 0` (line 17) is therefore unused — nothing in CI
ever performs a full-history scan automatically.

Config pickup DOES work, per the same log:
`DBG using existing gitleaks config .gitleaks.toml from '(--source)/.gitleaks.toml'`
followed by `DBG extending config with default config`.

## V2 — "was 1 before this change": DOES NOT REPRODUCE. The fix is a no-op.

Worktree at PR head (`67563c57`), gitleaks 8.24.3:

| scan | with allowlist entry | with entry removed |
|---|---|---|
| `--no-git` (working tree) | no leaks found | no leaks found |
| `--log-opts="--all"` (550 commits) | leaks found: 1 | leaks found: 1 |

Identical both ways. The `aws-access-token` false positive the PR exists to
suppress **does not occur on the gitleaks version CI runs**.

Mechanism, confirmed by probe (two scratch files, default ruleset, `--no-git`):

- `AKIA` + 16 uppercase-alnum → flagged, `RuleID: aws-access-token`
- `AIDA` + 16 uppercase-alnum → NOT flagged

and in the target file:

    grep -coE '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}' \
      configs/server/suburban_soc_dashboards_bundle_final.ndjson
    1      # the single hit is AIDA-prefixed; zero AKIA-prefixed

8.24.3's stock `aws-access-token` rule no longer carries the `AIDA`/`AROA`/
`AGPA`/... prefixes that older gitleaks releases did. *Inference, not verified
here:* the cloud session that authored the PR ran an older gitleaks whose rule
still matched `AIDA`. What is verified is the observable: on 8.24.3 the entry
changes nothing.

## V3 — "61 commits — this repo's entire history": FALSE

    git rev-list origin/main --count   -> 614
    git rev-list --all --count         -> 652
    gitleaks --log-opts=--all          -> 550 commits scanned

The cloud session scanned a 61-commit shallow clone. Every "exactly one finding
across the full history" claim in both the PR body and issue #570 rests on that
partial scan.

## V4 — a real finding the partial scan missed (NEW)

A genuine full-history scan (550 commits, 19.29 MB) returns one finding, and it
is not the base64 image:

    RuleID:      curl-auth-user
    File:        docs/SOP-022-anomaly-validation.md
    Line:        41
    Commit:      f642e1b3166ad6f700dc6235ecd8641a234b7655
    Date:        2026-05-26T22:11:25Z
    Fingerprint: f642e1b3166ad6f700dc6235ecd8641a234b7655:docs/SOP-022-anomaly-validation.md:curl-auth-user:41

Present in **history only** — the working-tree scan is clean, so the line has
since been scrubbed. It is *not* suppressed by this config's
`SuburbanSOC2026!` stopword, which means the literal is a **different** value
from the one audit P0-1 recorded as rotated/burned. Needs owner triage:
confirm whether that credential was also rotated, then either add it to
`stopwords` (same precedent as P0-1) or rotate it. The value itself is
deliberately not recorded here, per this repo's "do not persist sensitive data
in findings files" convention.

## V5 — test-suite claims

- `pytest tests/pipeline/test_gitleaks_allowlist.py` -> **5 passed, 3 subtests
  passed**. Matches the PR's claim.
- `pytest tests/pipeline` -> **511 passed, 1 skipped, 0 failed** on this host.
  The PR claimed "505 passed, 4 failed (pre-existing/environment-specific)";
  the 4 failures are cloud-sandbox artifacts and do not reproduce here. CI's
  `detections` job (`.github/workflows/detections.yml:76`,
  `python -m pytest tests/pipeline -q`, no path filter, every PR) passed.
- The new test DOES run in CI, and `tomllib` is satisfied:
  `detections.yml:24` uses `python-version-file: .python-version` = 3.11.

## Bottom line

The PR's own test plan does not test the PR. Item 1 is vacuous by construction,
and the defect it claims to fix is not reproducible on the pinned toolchain —
so the change is a pure detection-coverage reduction (whole-file exclusion of an
86 KB Kibana export from every rule) bought for nothing.
