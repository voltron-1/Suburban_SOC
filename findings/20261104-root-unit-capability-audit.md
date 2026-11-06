# Root systemd units vs. the 750 home directory (audit, 2026-11-04)

Scope: all 9 `configs/systemd/*.service`. Evidence is from this capture host (read-only commands) unless marked UNVERIFIED.

## Finding
`/home/tjlam` is `drwxr-x--- tjlam:tjlam`. A root service with no `CAP_DAC_OVERRIDE` is neither owner nor group, so it cannot traverse into `/home/tjlam/projects/Suburban-SOC` (EACCES).
`zeek-capture-liveness.service` (`User=root`, `CapabilityBoundingSet=` empty) hit this on every timer run: `bash: .../zeek_capture_liveness.sh: Permission denied`, status 126.
Journal count since boot: **336** `permission denied` lines for that unit. Detection of the #549 wedge class was therefore dead while the alert path (`OnFailure=`) fired into an unset `NTFY_TOPIC`.
ATT&CK: none evidenced (a reliability defect, not an adversary action). Attacker view: a silently dead liveness check is a free blind spot for anything that stalls capture (T1562.001 would be the mapping only if tampering were shown; it was not).

## Per-unit matrix
| Unit | Runs as | Caps | Reads home checkout | Status |
|---|---|---|---|---|
| zeek-capture-liveness | root | none | yes (literal path) | **Defective**, fixed here: `SupplementaryGroups=tjlam` |
| zeek-host-capture | root | NET_RAW/ADMIN/CHOWN/SETUID/SETGID | yes | OK: `SupplementaryGroups=tjlam` (live: process `Groups: 1000`) |
| suricata-host-capture | root | NET_RAW/ADMIN | yes | OK in text; disabled on host, so never exercised (UNVERIFIED live) |
| intel-refresh, slo-metrics, stack-health, soc-alert-on-failure@ | tjlam | none | yes | Not affected: the user owns the home; 0 denials since boot |
| checkpoints-compact, threat-intel-compact | tjlam | none | yes | Not affected by this bug; **not installed** on this host (no unit files, no timers) |

Installed copies of intel-refresh, slo-metrics, soc-alert-on-failure@, stack-health, suricata-host-capture, zeek-capture-liveness, zeek-host-capture matched the repo (whitespace-trimmed diff) before the fix.

## Fix and why not a capability
First commit `0317ee2` used `CAP_DAC_READ_SEARCH`. It worked live (script ran), but `tests/pipeline/test_capture_unit_repo_access.py` already forbids DAC capabilities for this class (filesystem-wide read) and mandates `SupplementaryGroups=tjlam`. The test missed the unit because `CAPTURE_UNITS` was hard-coded to two units and keyed on `${SOC_REPO}`, while the liveness unit uses a literal path.
Now: `SupplementaryGroups=tjlam`, empty capability set, plus a test that discovers every root service reading `/home/` or `${SOC_REPO}`. Verified the test fails on `07c151c` and on `0317ee2` and passes on the new unit.

**UNVERIFIED on the host:** the group-based unit has not been deployed. Open question: does `systemctl restart` from a root unit with an empty capability set still work? (The original author's header already flagged the sandbox as unverified.) The `CAP_DAC_READ_SEARCH` version is the one proven live.

## Test results
`pytest tests/pipeline` on a clean checkout of `07c151c`: 530 passed. With these changes and no `.env`: 532 passed. In the live tree: 14 failures, all fake-`curl` tests in `test_soc_alert_on_failure.py` (13) and `test_zeek_capture_liveness.py` (1). They appear only when `scripts/setup/.env` exists (a one-line dummy gives 5); the cause inside the scripts' `.env` sourcing is not yet isolated. Not caused by this change.

## Other observations
1. `zeek-host-capture` still logs `could not refresh intel.dat ... Permission denied`. Different cause: `configs/intel/data/intel.dat` is mode 600 (written under `UMask=0077`), unreadable by group. Non-fatal (the intel-refresh timer and seed file cover it).
2. `scripts/setup/.env` is mode **644** and holds password/HMAC/webhook variables (names only inspected). Gitignored, and shielded by the 750 home, but not least-privilege. Use 640 (`tjlam:tjlam`), not 600: the liveness unit now reads it through group membership.
3. `NTFY_TOPIC` is still empty: restarts by the liveness check are not reported to anyone (claim C2 unproven).
