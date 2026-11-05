# Session handoff — 2026-11-05 (local session on the capture host)

**Read this first.** It updates `plans/20261104-session-handoff.md` (still the source for the claims register, rules and lessons); then read `planned_execution.md` (LAST SESSION — 2026-11-04, which carries this session's entries).
**UNVERIFIED** = not run or not checked. Times CST. No secret values were read or printed; `.env` was inspected by key name or presence only.

## 0. Owner steps: do these FIRST (everything below waits on them)
All need sudo (the agent shell has no TTY), so the owner runs them. Run from `~/projects/Suburban-SOC`. After each step read the output; do not trust "no error" as "worked".

1. **Read-only look at the native engine** (before touching it):
   ```bash
   sudo sh -c 'ls /var/lib/docker/containers | wc -l'
   sudo grep -ho '"Name":"[^"]*"' /var/lib/docker/containers/*/config.v2.json
   ```
   If it lists SOC stack containers or data worth keeping, stop before step 5 and tell the agent.
2. **Docker Desktop:** Settings > General > "Start Docker Desktop when you sign in" (UI, no command).
3. **Install both units:**
   ```bash
   sudo cp configs/systemd/zeek-capture-liveness.service configs/systemd/suburban-soc-stack.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable suburban-soc-stack.service
   ```
4. **Test the group-based liveness unit:**
   ```bash
   sudo systemctl start zeek-capture-liveness.service
   journalctl -u zeek-capture-liveness -n 6 --no-pager
   ```
   Healthy: `OK -- zeek-host-capture.service active, conn.log age Ns <= 1800s`. If it fails, revert to the capability version and tell the agent:
   `git show 0317ee2:configs/systemd/zeek-capture-liveness.service | sudo tee /etc/systemd/system/zeek-capture-liveness.service >/dev/null && sudo systemctl daemon-reload`
5. **Disable the native engine (only after step 1 looks safe):**
   ```bash
   sudo systemctl disable --now docker.service docker.socket
   ```
6. **Prove the boot start.** In Windows PowerShell: `wsl.exe --shutdown`. Start Docker Desktop, reopen WSL, then:
   ```bash
   systemctl is-enabled suburban-soc-stack.service
   journalctl -u suburban-soc-stack.service -n 20 --no-pager
   docker compose -f scripts/setup/docker-compose.yml ps -a
   ```
   Pass (SOP-005 "Done when"): the stack is up with no manual `compose up`. `CAPTURE_IFACE=eth0` may break again after the restart (known pin issue); check `systemctl is-active zeek-host-capture`.
7. **`NTFY_TOPIC` (owner only):** add `NTFY_TOPIC=<long random topic>` to `scripts/setup/.env` yourself so the value never enters a transcript. Tell the agent; it will induce a failure and show one push (P0 exit gate).

Status at 11:42 on 2026-11-05: none of steps 1-7 confirmed done (units not installed, native docker active, `NTFY_TOPIC` empty). Re-check read-only before assuming either way.

## 1. State of the host (read-only, 2026-11-05 11:42)

| Item | State |
|---|---|
| Owner steps 4.1c-d (unit deploy, disable native docker) | **Not done.** `/etc/systemd/system/suburban-soc-stack.service` does not exist (`enabled=not-found`). The installed `zeek-capture-liveness.service` is the 2026-11-04 17:06 copy (the `CAP_DAC_READ_SEARCH` version, repo state at that time); the repo's group-based unit (`6d34caf`) came later and has not been copied. Native `docker.service` and `docker.socket` are `active` and `enabled`. |
| Docker engine in use | `docker-desktop`. `elasticsearch`, `kibana`, `soc_ai_agent` healthy; `logstash`, `hive_mind_broker` up; all 19 h. The five init jobs exited 0 (normal). Not stuck. |
| Kibana | Published on host port **5700** (`KIBANA_PORT=5700` in `.env`); `https://localhost:5700` returned 302. 5601 failed at `compose up` (`/forwards/expose returned unexpected status: 500`); cause **not proven**. |
| Zeek | `zeek-host-capture` active on `eth0` (manual pin, breaks after a WSL restart). Liveness timer ran at 09:30 and 11:40; the 09:30 line read `OK ... conn.log age 57s`. Log path is `/storage/PCAP/zeek_logs/conn.log`. |
| `NTFY_TOPIC` | Empty. Claim C2 still unproven. |
| Routers / Suricata | Unchanged from the 2026-11-04 handoff (`10.18.81.1` unreachable, no `eve.json` to ES, #587/#593). |

## 2. Done this session (branch `plan/claims-to-evidence-remediation`, PR #608; code commits pushed at `4658f99`, handoff and its correction at `ac93182`, this restructure after)

| Commit | What | Verified |
|---|---|---|
| `e3aa280` | Dispatcher and liveness tests run an isolated copy of the script (`isolated_script()`) because the scripts source `$HERE/.env` after the test builds its environment | 5 failures reproduced in a clean worktree with a key-populated `.env`; `tests/pipeline` 542 passed with and without a `.env`. Only those 5 are verified, not the earlier "14". |
| `dcf7d44` | `soc_pipeline.sh` follows `KIBANA_PORT` (env, else one grepped line from `.env`; `.env` not sourced; non-numeric falls back to 5601) | New `test_soc_pipeline_kibana_port.py`; fails 6/8 on the old script |
| `3d40194`, `f525631` | `stack_health.sh`, `provision_tenant.sh`, `deploy_soc_presentation.sh` (assignment moved below the `.env` source), `deploy_detections.sh`, `deploy_dashboards.sh`, `erase_tenant.sh` default to `${KIBANA_PORT:-5601}` | 9 tests fail on the old versions; `tests/pipeline` 553 passed, 1 skipped; shellcheck, ruff clean. **No script was run against live Kibana.** |
| `4658f99` | `planned_execution.md` LAST SESSION entries | Docs |

`main` had nothing new (0 behind). CI has not run on the push: full `pytest`, `mypy`, `yamllint` are **UNVERIFIED**.

## 3. Open work, in order
1. **Owner steps:** see section 0 (first, before anything else). Background: the 17:06 `cp` on 2026-11-04 copied only the liveness unit, and the repo's group-based version came after it, so nothing failed; the stack unit has never been copied.
2. **`NTFY_TOPIC`**: the owner writes it into `.env`; then induce a failure and show one push (P0 exit gate).
3. **Verify the Kibana change live:** run `stack_health.sh` / read the next `stack-health` run to confirm Kibana reports UP on 5700 (UNVERIFIED). Optionally find the cause of the 5601 `/forwards/expose` 500 (a stale proxy from the native engine is a guess, not evidence).
4. **Durable Zeek interface** (the `eth0` pin dies on WSL restart), **sensor placement #593**, `zeek-host-capture` ordering against the engine, tenant-trust gap P0.6, `slo_metrics` repeat pushes P0.7: unchanged from the 2026-11-04 handoff, section 4.
5. **Smaller:** `.env` is mode 644 holding secrets (use 640); compose warns that volumes `suburban_soc_data` and `suburban_soc_snapshots` "were not created by Docker Compose" (no compose labels; do not touch, ES data is on them; `external: true` is an owner call); README has no row for this session's work; PR #607 and the CVE exception dates (2026-11-25, 2026-11-30) as before.

## 4. Decisions only the owner can make
Sensor placement (#593) and router reachability; Option A (native dockerd) vs B (Docker Desktop, chosen for now); whether the git hooks should do anything (below); target hardware and LLM size.

## 5. Notes
- **Git hooks:** `.git/hooks/pre-commit` is a no-op; `post-commit` starts `wiki-sync-worker.sh`, which runs `agy` and can add a `docs(wiki)` follow-up commit. Both are mode 644, so git skips them (the "ignored" hint on every commit). Making them executable would start background `agy` runs and unrequested commits on this branch: left as is.
- **Uncommitted, not mine:** `CLAUDE.md` (a condensed rewrite) and `docs/deploy-changelog.md` (three 2026-10-24 deploy rows) are the owner's edits; leave them unless asked.
- **Lessons added:** a one-line dummy `.env` did not reproduce the failures; a `.env` with every real key name set to `x` did. When a test depends on host state, reproduce with key names, not a guess. The screenshot's `compose up` output was earlier scrollback, not current state; check the clock and `docker compose ps` before reacting to a pasted error.
- Branch + PR always; only the owner merges; never write a closing keyword before an issue number; `git fetch` and merge `main` before any push.

## 6. Paste this to start the next session
> Read `plans/20261105-session-handoff.md`, then `plans/20261104-session-handoff.md` sections 1, 6 and 7, then the top LAST SESSION of `planned_execution.md`. Re-check host state read-only (`systemctl is-enabled suburban-soc-stack`, `docker compose ps -a`, `systemctl is-active docker`) before trusting section 1. Start with section 0: ask me which of those owner steps are done and re-check each read-only, ask before any sudo or live change, and do not open further PRs unless I ask.
