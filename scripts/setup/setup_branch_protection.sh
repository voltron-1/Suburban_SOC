#!/usr/bin/env bash
# =============================================================================
# setup_branch_protection.sh — WS3.5: enforce change management on main.
#
# Requires a repo ADMIN token (gh auth login as an admin). Enforces, on `main`:
#   * PR review required (>=1 approval; stale reviews dismissed)
#   * CI must pass: detections + gitleaks + CodeQL + SOAR tests + pip-audit (audit P2-14)
#   * branch up to date before merge; no force-push / deletion
# Idempotent — re-run to update.
# =============================================================================
set -euo pipefail
BRANCH="${1:-main}"
echo "==> Enforcing branch protection on '$BRANCH' (requires admin)"
gh api -X PUT "repos/:owner/:repo/branches/$BRANCH/protection" \
  -H 'Accept: application/vnd.github+json' --input - <<JSON
{
  "required_status_checks": { "strict": true, "contexts": ["detections", "gitleaks", "CodeQL", "SOAR auth / exclusion / approval / tenant-scoping", "Python dependency audit (pip-audit)"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 1, "dismiss_stale_reviews": true },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo "==> Done. 'main' now requires a reviewed, CI-passed PR."
