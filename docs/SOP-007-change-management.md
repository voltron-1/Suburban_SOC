# SOP-007 — Change Management on Detections & Config (WS3.5)

**Status:** Active · **Milestone:** M10 · **Workstream:** WS3.5 · **SOC 2:** Security (change mgmt)

## Purpose
Nothing that affects detection or response reaches production without a **reviewed,
CI-passed, recorded** change.

## Controls
1. **Pull-request review (enforced).** `main` is branch-protected: every change lands
   via PR with ≥1 approval; stale reviews are dismissed; no force-push/deletion.
   Enable once (repo admin): `./scripts/setup/setup_branch_protection.sh`.
   `.github/CODEOWNERS` routes review of `rules/`, `configs/`, `hunts/`, the agent,
   and the broker to code owners.
2. **CI gates (required checks).** The `detections` workflow (WS1.2/1.5/2.1/2.2) and
   `gitleaks` must pass before merge — a broken rule, a drifted ATT&CK matrix, a
   malformed hunt, or a leaked secret blocks the change.
3. **Recorded deploys (evidence).** Every deploy is logged by
   `scripts/setup/deploy_changelog.sh` to `docs/deploy-changelog.md` and the immutable
   `soc-deploys` index (what / when / actor / commit). `deploy_detections.sh` and
   `deploy_dashboards.sh` call it automatically.

## Acceptance (#106)
- [x] PR review + branch protection on rules/configs/response code (script + CODEOWNERS)
- [x] CI gates required to pass (detections + gitleaks)
- [x] Deploy changelog emitted (markdown + immutable ES index)
