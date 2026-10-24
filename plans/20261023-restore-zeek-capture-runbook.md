# Runbook — restore Zeek capture on the capture host

**Date:** 2026-10-23 · **Where to run it:** the local WSL capture host (needs `sudo`; a cloud session cannot do this)
**Time:** about 30 minutes for Parts 1–4, plus about 1 hour for Part 5 (M26 deploy)

This runbook turns `plans/20260907-restore-zeek-capture-and-deploy-m26.md` into an ordered checklist.
It is based on `planned_execution.md` (status dated 2026-09-28). **Live host state was not re-observed
for this document.** Part 1 checks the current state first, so skip any fix that Part 1 shows is not needed.

## Known state at last record (2026-09-28)

- Zeek has written no output since `conn.log` at **2026-09-14 15:38**.
- `zeek-host-capture.service` is `activating (auto-restart)`, `NRestarts=392`, exit 126, `host_capture.sh: Permission denied`.
- `slo-metrics.service` is `failed` (exit 3). The `slo_metrics` Elasticsearch password no longer authenticates.
- The 3 M26 units are not installed: `zeek-capture-liveness.timer`, `stack-health.timer`, `soc-alert-on-failure@.service`.
- Suricata, Filebeat, `intel-refresh.timer` and Docker Desktop were running.

The repo already contains the fixes (PR #566 added `SupplementaryGroups`, PR #553 and #564 added the M26 units).
The host most likely runs an older installed unit. **That is unverified**; Part 1 checks it.

## Part 0 — Prerequisites (2 minutes)

1. Open a WSL terminal on the capture host and `cd` to the repo (`$SOC_REPO`, under `/home/tjlam`).
2. Check that Docker Desktop is running. If `docker` is missing from PATH, start Docker Desktop first.
   ```bash
   /mnt/c/Windows/System32/wsl.exe -l -v     # docker-desktop must show Running
   docker version --format '{{.Server.Version}}'
   ```
3. Pull the latest repo.
   ```bash
   git pull origin main
   ```

## Part 1 — Diagnose (5 minutes, read-only)

Run these and record the output. Each answers one question.

```bash
# 1. Is capture running, and is output fresh?
systemctl is-active zeek-host-capture.service
systemctl show zeek-host-capture.service -p NRestarts,ActiveState,SubState,Result
ls -l --time-style=long-iso /storage/PCAP/zeek_logs/conn.log

# 2. What is the real error?
journalctl -u zeek-host-capture.service -n 30 --no-pager

# 3. Does the pinned interface exist?
grep CAPTURE_IFACE /etc/default/zeek-host-capture
ip -br link

# 4. Is the installed unit older than the repo unit?
diff <(sed 's/[[:space:]]*$//' /etc/systemd/system/zeek-host-capture.service) \
     <(sed 's/[[:space:]]*$//' configs/systemd/zeek-host-capture.service) && echo SAME || echo DIFFERENT
```

Decide from the results:

| Observation | Cause | Go to |
|---|---|---|
| `diff` says DIFFERENT, or the journal shows `Permission denied` | Installed unit predates PR #566 (problem A) | Part 2, then Part 3 |
| `CAPTURE_IFACE` names an interface that `ip -br link` does not list | Stale interface pin (problem B) | Part 3 |
| Unit is `failed` with exit 78 | Preflight parked it correctly; the interface pin is wrong | Part 3 |
| Unit is `active` and `conn.log` is fresh | Capture already works | Part 5 |
| Anything else | Stop. Do not guess. Copy the journal output into a new finding in `findings/` | — |

## Part 2 — Install the repo's fixed unit (5 minutes, needs sudo)

This fixes problem A: the unit runs as root but cannot traverse `/home/tjlam` (mode 750), because
`CapabilityBoundingSet` omits `CAP_DAC_OVERRIDE`. The repo unit grants traversal through
`SupplementaryGroups` and does not widen capabilities.

1. Confirm the repo unit has the fix.
   ```bash
   grep -n SupplementaryGroups configs/systemd/zeek-host-capture.service
   ```
   Expect a non-comment line `SupplementaryGroups=...`. If only comment lines match, stop and re-read the unit.
2. Install all repo units. This restarts the capture unit.
   ```bash
   sudo bash scripts/setup/redeploy_systemd_units.sh
   sudo systemctl daemon-reload
   sudo systemctl reset-failed zeek-host-capture.service
   ```

Do **not** add `CAP_DAC_OVERRIDE` to the unit. It gives a unit that runs `tcpdump` blanket root file access.

## Part 3 — Fix the capture interface (5 minutes, needs sudo)

This fixes problem B. WSL2 renumbers NICs across reboots, so the pin goes stale.

1. List interfaces and pick the one that holds the default route.
   ```bash
   ip -br link
   ip route show default
   ```
2. Write it to the config file. The 2026-09-07 diagnosis found only `lo` and `eth0`; use whatever step 1 shows.
   ```bash
   echo 'CAPTURE_IFACE=eth0' | sudo tee /etc/default/zeek-host-capture
   ```
3. Restart the unit.
   ```bash
   sudo systemctl reset-failed zeek-host-capture.service
   sudo systemctl restart zeek-host-capture.service
   ```

Parts 2 and 3 are both required. Fixing only A leaves the unit parked in `failed` (exit 78). Fixing only B leaves it looping.

## Part 4 — Verify capture (3 minutes)

```bash
systemctl is-active zeek-host-capture.service                    # expect: active
docker ps --filter name=zeek-host-capture                        # expect: one running container
docker ps --filter name=zeek-host-capture --format '{{.Image}}'  # expect: zeek/zeek:9.0.0@sha256:...
stat -c '%y %s' /storage/PCAP/intel/config.zeek                  # expect: today's date
sleep 60
ls -l --time-style=long-iso /storage/PCAP/zeek_logs/conn.log     # mtime must advance between two runs
```

Then confirm Elasticsearch receives the data (replace the credentials with your `.env` values):

```bash
curl -s --cacert <ES_CA> -u elastic:"$ELASTIC_PASSWORD" \
  'https://localhost:9200/logstash-security-*/_search?size=1&sort=@timestamp:desc&q=event.dataset:zeek.conn' \
  | head -c 600
```

**Done when:** `conn.log` mtime advances and the newest `zeek.conn` document is seconds old.

If the unit is still looping or `failed`, check the journal again. After three failed fixes, stop and
name the assumption that may be wrong; do not keep editing.

## Part 5 — Deploy the rest of M26 (about 1 hour, needs sudo)

Run only after Part 4 is green. Order matters.

1. **Resync the `slo_metrics` credential first.** The `slo_metrics` ES user exists, but
   `SLO_METRICS_PASSWORD` in `scripts/setup/.env` no longer authenticates. Reset the user's password in
   Elasticsearch, write the same value into `.env`, then confirm:
   ```bash
   sudo systemctl restart slo-metrics.service
   systemctl show slo-metrics.service -p Result,ExecMainStatus      # expect: success, 0
   ```
2. Install units (already done in Part 2 if you ran it) and load the syslog input.
   ```bash
   sudo bash scripts/setup/redeploy_systemd_units.sh
   sudo systemctl restart filebeat.service
   docker compose -f scripts/setup/docker-compose.yml restart logstash
   ```
3. Deploy the 2 new Sigma rules from #556.
   ```bash
   bash scripts/setup/deploy_detections.sh
   ```
4. Enable the monitoring timers.
   ```bash
   sudo systemctl enable --now stack-health.timer zeek-capture-liveness.timer
   ```
5. Verify. None of these may report `not-found`.
   ```bash
   systemctl status zeek-capture-liveness.timer stack-health.timer 'soc-alert-on-failure@.service' --no-pager | head -30
   ```

**Do not set `NTFY_TOPIC` yet.**
- Issue #567 is open: `soc_alert_on_failure.sh` has no rate limit and can send one push per restart cycle.
- Fix #567 and complete step 1 above, then provision `NTFY_TOPIC`.
- Otherwise about 15 unmeasurable metrics produce about 96 high-priority pushes a day, and the topic gets muted.

**Open question from the 2026-09-07 plan:** the liveness supervisor (#549) acts only when the unit is
`active` and `conn.log` is stale. The 2026-09-14 outage sat in `activating (auto-restart)`.
Confirm that state is covered before relying on #549 to catch a repeat.

## Part 6 — Prove the loop works end to end (15 minutes)

Run from a client on the monitored network.

```bash
cd tests/anomaly_simulation
bash preflight.sh
bash sim_portscan.sh
python3 verify_detections.py
```

**Done when:** `verify_detections.py` finds the port scan (T1046) notice in the SIEM.
Record the result in `evidence/` and `docs/deploy-changelog.md`.

## Rollback

- `redeploy_systemd_units.sh` does not keep a backup. Before Part 2, run:
  `sudo cp /etc/systemd/system/zeek-host-capture.service /root/zeek-host-capture.service.pre`.
  To roll back, copy it back, then run `sudo systemctl daemon-reload`.
- Stop capture without losing logs: `sudo systemctl stop zeek-host-capture.service`. Logs in `/storage/PCAP/zeek_logs/` stay.

## Also due: zeek image CVE exception expires 2026-10-28

CVE-2026-48930 is ignored for the `zeek/zeek` Trivy job until **2026-10-28** (issue #577, SOP-008 Tracked Exceptions).
After that date the `Container image scan (Trivy) (zeek/zeek)` check fails on every PR unless upstream has
shipped a patched image. Check for a newer `zeek/zeek` tag and bump the pin in the 4 capture paths and 3 test pins,
or renew the exception with a new expiry and a recorded reason.
