# SOP-008 — Vulnerability Management of the SOC Stack (WS3.6)

**Status:** Active · **Milestone:** M10 · **Workstream:** WS3.6 · **SOC 2:** Security

## Purpose
The SOC platform must not be the weak link. Its own container images and Python
dependencies are pinned, scanned, and patched on a defined cadence.

## Controls
1. **Pinned dependencies.** `scripts/setup/ai_agent/requirements.txt` and
   `scripts/hive-mind-broker/requirements.txt` pin exact versions (reproducible
   builds + auditable). Test-only deps (pytest) are kept out of the production images.
2. **Image scanning (enforced gate).** The `Security Scan` CI workflow builds the
   agent + broker images and runs **Trivy** with `severity: CRITICAL, exit-code: 1` —
   a critical CVE (OS or library) **blocks the merge**.
3. **Dependency auditing.** CI runs **pip-audit** on both requirements files; it fails
   on any known vulnerability, with documented, tracked exceptions only.
4. **Patch cadence.** The workflow runs weekly (Mondays 06:00 UTC) in addition to per-PR.
   Each week: review findings, bump fix versions, re-run the suites.

## Tracked exceptions
| Advisory | Package | Reason | Review |
|---|---|---|---|
| PYSEC-2026-161 | starlette | Fix is 1.0.1; FastAPI caps starlette `< 0.50`, so the fix isn't installable until FastAPI supports starlette 1.0. Medium severity. | Re-check weekly; remove the `--ignore-vuln` once FastAPI supports starlette ≥ 1.0. |

## Acceptance (#107)
- [x] Pin + scan container images (Trivy) — CI blocks a critical CVE
- [x] Scan Python deps (pip-audit on both requirements.txt)
- [x] Patch cadence documented (weekly) + a known CVE is gated
