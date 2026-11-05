# Session handoff — 2026-11-04 (local session on the capture host)

**Read this first.** It supersedes parts of `plans/20261024-session-handoff.md` (several of that file's "DONE" items had regressed). Then read `planned_execution.md` (LAST SESSION — 2026-11-04).
Facts come from read-only commands run on the host and from output the owner pasted. **UNVERIFIED** means not run or not checked. Times are CST (container timestamps are UTC).

## 1. Goal behind the work
The owner has a funding walkthrough with military reviewers and wants every claim about Suburban-SOC *proven*, framed as a forward-operating-base edge sensing node. Scope chosen: close the gaps, no presentation yet.
`plans/20261104-claims-to-evidence-remediation.md` holds the claims register (C1–C13) and Phases P0–P5 with exit gates; `findings/20261104-plan-claim-verification.md` holds the verbatim evidence. Rules from those files: one phase at a time, wait for the owner's go-ahead between phases; never say "production-ready", "ruggedized", "SOC 2 Type II", "SOC-CMM L3", "autonomous response" (auto-isolation is off by default) or "zero vulnerabilities"; only 28 of 122 Sigma rules (+12 threshold) are deployed and 8 are live-fired.

## 2. State of the host now (observed 2026-11-04 ~17:15)

| Item | State |
|---|---|
| Zeek capture | **Running on `eth0`** since the owner set `CAPTURE_IFACE=eth0` and restarted at 17:06. `conn.log` has fresh records. `eth0` is the WSL NAT (`172.21.123.120/20`): this PC's traffic only. The pin in `/etc/default/zeek-host-capture` is a manual edit and **breaks again after a WSL restart** (14 boots 2026-10-26..11-03). |
| `zeek-capture-liveness` | Installed copy is the **first** fix (`CAP_DAC_READ_SEARCH`, copied 17:06:25; verified by reading `/etc/systemd/system/`). The repo now has the group-based unit; **not deployed (UNVERIFIED)**. |
| Docker stack | Up since ~16:40 because someone ran `docker compose up -d` (earlier session + owner), **not** automatically. Lives in Docker Desktop's engine. |
| Alerts | **`NTFY_TOPIC` is empty** in `scripts/setup/.env` (checked presence only, not value). Nothing reaches a human. Claim C2 unproven. |
| Router `10.18.81.1` | **Unreachable from this host** (`No route to host`; WSL NAT gateway `172.21.112.1`). The owner is not on that network. `ROUTER_IP`/`ROUTER_USER` unset. |
| Suricata | `suricata.service` active, no `eve.json` reaches ES (#587). `suricata_ingest_lag_seconds` SLO breach stands. |

## 3. Done this session (branch `plan/claims-to-evidence-remediation`, PR open; nothing merged)

| Commit | What | How verified |
|---|---|---|
| `0317ee2` | `CAP_DAC_READ_SEARCH` on the liveness unit | **Live**: the script ran, no `Permission denied`, reported `STALE` and restarted capture. Superseded (see next row). |
| `6d34caf` | Liveness unit → `SupplementaryGroups=tjlam`, empty caps; new test over **every root unit** reading `/home/` or `${SOC_REPO}` | Test fails on `07c151c` and on `0317ee2`, passes now. **Unit not run on the host.** |
| `4a90b29` | `findings/20261104-docker-engine-split.md` | Read-only evidence; decision recorded |
| `6bc4fe0` | `suburban-soc-stack.service`, `scripts/setup/start_stack.sh`, redeploy line, `tests/pipeline/test_stack_start.py` | 10 tests incl. real script vs fake `docker`; engine guard mutation-tested; shellcheck clean. **Not run under real systemd/Docker Desktop.** |
| `ccf824a` | SOP-005 section "Starting the stack at boot: one Docker engine (Option B)" | Docs |

Also in the PR: `findings/20261104-root-unit-capability-audit.md`, the plan and claim-verification files, README row, `planned_execution.md` LAST SESSION entry, this file.

## 4. Open work, in order
1. **Owner steps (need sudo; the agent shell has no TTY for it).**
   a. Read-only check of the native engine: `sudo sh -c 'ls /var/lib/docker/containers | wc -l'` and `sudo grep -ho '"Name":"[^"]*"' /var/lib/docker/containers/*/config.v2.json`.
   b. Docker Desktop > Settings > General > start at sign-in.
   c. Deploy both units: `sudo cp configs/systemd/{zeek-capture-liveness,suburban-soc-stack}.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable suburban-soc-stack.service`; then `sudo systemctl start zeek-capture-liveness.service` and read `journalctl -u zeek-capture-liveness -n 6`. **If the group-based liveness unit fails (e.g. `systemctl restart` denied with empty caps), revert to the `CAP_DAC_READ_SEARCH` version and say so.**
   d. `sudo systemctl disable --now docker.service docker.socket` (only after 1a). Then prove it: `wsl.exe --shutdown`, start Docker Desktop, confirm the stack comes up with no manual `compose up` (SOP-005 "Done when").
2. **`NTFY_TOPIC`.** The owner generates and writes it into `scripts/setup/.env` themselves so the value never enters a transcript. Then induce a failure and show one push (P0 exit gate).
3. **Durable Zeek interface (P0.0).** `eth1` pin dies on every WSL restart. Needs stable selection (e.g. default-route interface) or a topic/alert that survives; sudo to deploy.
4. **Sensor placement (#593)** — owner decision. A host NIC never sees other hosts in any WSL mode. Needs the OpenWrt router path (`ROUTER_IP`, `ROUTER_USER`, reachable network) or a mirror port, or the single-host scope documented.
5. **`zeek-host-capture` ordering against the engine.** It calls `docker` with no ordering; deliberately not changed (its header records a sandbox change that once broke production). Separate, careful change.
6. **P0.6 tenant-trust gap:** Logstash trusts the shipper's own `[tenant][id]` (#265 leftover).
7. **P0.7:** `slo_metrics.py` pushes every 15 min while the Suricata breach stands (once `NTFY_TOPIC` is set).
8. **Smaller:** `.env` is mode 644 holding secrets → use **640**, not 600 (the liveness unit reads it via group); `intel.dat` is mode 600 so the Zeek unit's refresh logs `Permission denied` (non-fatal); `soc_pipeline.sh` hardcodes `https://localhost:5601` (lines ~349, 645, 695); extend `build_attack_coverage.py` with `Deployed`/`Proof` columns (P1.2); `checkpoints-compact`/`threat-intel-compact` are not installed on this host.
9. **Test environment issue:** 14 `tests/pipeline` tests fail only when a real `scripts/setup/.env` exists (13 in `test_soc_alert_on_failure.py`, 1 in `test_zeek_capture_liveness.py`). Clean checkout `07c151c`: 530 passed. With a one-line dummy `.env`: 5 fail. Cause in the scripts' `.env` sourcing not isolated. Run CI-equivalent checks in a worktree without `.env`.
10. **Dated:** PR #607 (zeek pin 9.0.0 → 9.0.1, CVE exception to 2026-11-30) awaits owner review; the 164-pcap golden diff was not run; Debian lists nodejs deb13u3 as still vulnerable to CVE-2026-111497, which conflicts with the commit message (unresolved). The older CVE exception expires **2026-11-25** (#577).

## 5. Decisions only the owner can make
- Sensor placement (#593) and how this host reaches `10.18.81.1` (mirrored/bridged WSL networking, a box on that LAN, or router path with user/key).
- Option A (native dockerd, headless) vs staying on B: **B chosen now, A kept as target.** Revisit for real hardware or a reboot-without-sign-in requirement.
- Target hardware, local LLM size, peak load figure (plan section 3).
- Whether to merge `0317ee2`'s history as is (it was superseded by `6d34caf`; squash is the owner's call).

## 6. Lessons from this session (do not repeat)
- **My first liveness fix broke repo policy.** `test_capture_unit_repo_access.py` already forbade DAC capabilities and mandated `SupplementaryGroups=tjlam`; I added `CAP_DAC_READ_SEARCH` without searching for precedent. Search the tests and sibling units before inventing a fix.
- **The test that should have caught it was keyed on two hard-coded units.** Generalise guards over a glob of the directory.
- **"Passed" was not "healthy".** The liveness check ran, then reported `STALE` and restarted capture. Read the output, not the exit code.
- **A silent unfixed grep is not evidence.** I treated an empty Docker events history as nothing; it only meant the buffer was gone.
- **Baseline before blaming.** 14 failures looked like mine; a worktree at `07c151c` (530 passed) and a worktree with my changes (532 passed) showed they came from the host `.env`. Use `git worktree add --detach <scratch> <rev>`, not stash.
- **I asked for an IP and then could not reach it.** Check reachability (`ip route get`, one `ssh -o BatchMode`) when the owner supplies an address; say so at once if it is off-network.
- **`sudo` has no TTY in the agent shell.** Prepare exact commands; the owner runs them (`! <command>` also works).
- **Never print `.env` values.** Inspect key names or presence only; the file holds passwords, HMAC secrets and a webhook.
- **Two worktrees (`ss-pyparsing`, `pr571`) predate this session.** Leave them alone.

## 7. Repo rules that apply
- Branch + PR always; PRs touching `configs/`, `rules/`, agent, broker or `.github/` need code-owner review; **only the owner merges**.
- **Never write a closing keyword before an issue number**, even negated; write "leaves #N open". Close issues by hand after merge and verify.
- Every merge: row in `README.md` and a `LAST SESSION` entry in `planned_execution.md` in the same PR (done for this PR).
- Before pushing: `git fetch` and bring in the latest `main`; report conflicts. Never `reset --hard`, `checkout .` or `stash drop` without confirmation.
- Findings in `findings/`, plans/handoffs in `plans/`. Sourcing `scripts/setup/.env` exports secrets: run `exec bash` afterwards.

## 8. Paste this to start the next session

> Read `plans/20261104-session-handoff.md`, then the LAST SESSION — 2026-11-04 section of `planned_execution.md`. Re-check host state with read-only commands (`systemctl is-active zeek-host-capture`, `docker info --format '{{.Name}}'`, `docker compose ps`) before trusting section 2. Ask me before any change that needs sudo or touches live services. Start by asking whether I have run the owner steps in section 4.1, and do not open further PRs unless I ask.
