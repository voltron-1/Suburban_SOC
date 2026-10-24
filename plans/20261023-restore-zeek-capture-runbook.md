# Runbook — restore Zeek capture on the capture host

**Date:** 2026-10-23 · **Where to run it:** the local WSL capture host (needs `sudo`; a cloud session cannot do this)
**Time:** about 30 minutes for Parts 1–4, plus about 1 hour for Part 5 (M26 deploy)

This runbook turns `plans/20260907-restore-zeek-capture-and-deploy-m26.md` into an ordered checklist.
It is based on `planned_execution.md` (status dated 2026-09-28). **Live host state was not re-observed
for this document.** Part 1 checks the current state first, so skip any fix that Part 1 shows is not needed.

## Field notes from the 2026-10-24 run (read first)

This runbook was first used on 2026-10-24. Where it was wrong or incomplete, the corrected steps are in the
parts below and summarised here.

- **Real cause on that day:** `/etc/default/zeek-host-capture` pinned `CAPTURE_IFACE=eth3`, which was `DOWN`.
  The capture preflight (#551) did its job: the unit parked in `failed` with `status=78/CONFIG` instead of looping.
  `conn.log` last advanced **2026-10-19 19:33** (the repo notes said 2026-09-14; capture had worked in between).
  Fixed by setting `CAPTURE_IFACE=eth1` (the interface holding the default route).
- **Part 2 was not needed.** The installed unit already matched the repo's behaviour: the journal showed
  `host_capture.sh` running, so repo access (`SupplementaryGroups=tjlam`, line 258 of the repo unit) was not the blocker.
  Skip Part 2 unless the journal shows `Permission denied` / exit 126.
- **Part 5 was larger than written.** `redeploy_systemd_units.sh` does **not** install `intel-refresh.service`
  and does **not** enable the two timers. A stale installed `intel-refresh.service` (the old
  `Environment=ES_PASS=${INTEL_WRITER_PASSWORD}` literal, #271) caused `HTTP 401` on indexing until
  `scripts/setup/install_intel_refresh_timer.sh` replaced it. `stack-health.timer` has its own prerequisites in
  `docs/SOP-005-reliability.md`.
- **Known cosmetic bug:** the journal line `Referenced but unset environment variable evaluates to an empty string: err`
  and `WARNING: could not refresh intel.dat ... ()` come from `${err}` being expanded by systemd instead of bash in
  the unit's `ExecStartPre`. The copy failure itself is harmless (`intel.dat` is mode 600 and
  `intel-refresh.timer` is its real source).
- **Local git:** a stale local branch can make `git pull` start a rebase. Use `git pull --ff-only` and read Part 0.

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
3. Make sure you are on a clean `main`, then fast-forward. `--ff-only` refuses to rebase or merge.
   ```bash
   git branch --show-current && git status -sb      # expect: main, no local changes
   git pull --ff-only origin main
   ```
   If you are on another branch (for example an old `chore/...` branch whose PR was squash-merged), `git pull`
   may try to replay already-merged commits and conflict. Run `git rebase --abort`, save a backup with
   `git branch backup-<name>`, check the branch is redundant (`git diff --stat <squash-commit> HEAD -- <files it touched>`
   prints nothing), then `git switch main` and `git pull --ff-only origin main`.

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

## Part 2 — Install the repo's fixed unit (5 minutes, needs sudo) — SKIP if the Part 1 journal shows `host_capture.sh` ran

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
2. Set the interface that step 1 shows as `UP` and holding the default route (on 2026-10-24 that was `eth1`; on
   2026-09-07 it was `eth0`). Use `sed` so other settings in the file are kept, then confirm.
   ```bash
   sudo sed -i 's/^CAPTURE_IFACE=.*/CAPTURE_IFACE=eth1/' /etc/default/zeek-host-capture
   grep CAPTURE_IFACE /etc/default/zeek-host-capture
   ```
3. Pre-pull the pinned image so the start does not wait on a download, then restart the unit.
   ```bash
   docker pull zeek/zeek:9.0.0@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5
   sudo systemctl reset-failed zeek-host-capture.service
   sudo systemctl restart zeek-host-capture.service
   ```

Part 3 fixes the interface and is always needed when the preflight reports `is not up`. Part 2 is needed only if the journal also shows `Permission denied` / exit 126 (problem A). If both problems exist, fixing only A leaves the unit parked in `failed` (exit 78), and fixing only B leaves it looping.

## Part 4 — Verify capture (3 minutes)

```bash
systemctl is-active zeek-host-capture.service                    # expect: active
docker ps --filter name=zeek-host-capture                        # expect: one running container
docker ps --filter name=zeek-host-capture --format '{{.Image}}'  # expect: zeek/zeek:9.0.0 (docker ps shows the tag, not the digest)
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

1. **Check the `slo_metrics` credential first.** On 2026-09-06 the password in `scripts/setup/.env` no longer
   authenticated. On 2026-10-24 it did. Test it without printing it (needs the stack running):
   ```bash
   set -a; . scripts/setup/.env; set +a
   docker exec -e SLO_METRICS_PASSWORD elasticsearch bash -c 'curl -s -o /dev/null -w "%{http_code}\n" --cacert config/certs/ca/ca.crt -u "slo_metrics:$SLO_METRICS_PASSWORD" https://localhost:9200/_security/_authenticate'
   systemctl show slo-metrics.service -p Result,ExecMainStatus
   ```
   `200` means the credential works. Exit status **2** from `slo_metrics.py` is not an error: it means the run
   measured fine and found one or more SLO breaches (`SuccessExitStatus=0 2`); exit **3** means unmeasurable
   (credential or Elasticsearch failure). If it returns `401`, reset the user's password in Elasticsearch, write the
   same value into `.env`, and restart `slo-metrics.service`. Run `exec bash` afterwards: sourcing `.env` exports
   your passwords into that terminal.
2. Install units. `redeploy_systemd_units.sh` copies the capture, `slo-metrics`, `stack-health`, liveness and (since PR #590)
   `intel-refresh` units. Run the intel installer once as well to verify (it is idempotent; expect
   `indexed N indicators` and `recorded freshness heartbeat`, no `HTTP 401`).
   ```bash
   sudo bash scripts/setup/redeploy_systemd_units.sh
   bash scripts/setup/install_intel_refresh_timer.sh
   ```
3. **Filebeat: the host's config may be an old copy of the repo's.** `install_filebeat.sh` installs only the package;
   `/etc/filebeat/filebeat.yml` is separate. On 2026-10-24 the host ran a June 2026 file with no Suricata input, no
   syslog input (#556) and no `http.log` host rename (#228). Check, then replace only if the repo file is a superset:
   ```bash
   sudo diff /etc/filebeat/filebeat.yml configs/network/filebeat.yml | grep '^<'     # lines only in the live file: expect none
   ```
   Filebeat refuses a config file not owned by root, so test a root-owned copy, then move it into place. Each step runs
   only if the previous one succeeded; the old file is backed up first:
   ```bash
   sudo cp -a /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak-$(date +%Y%m%d)
   sudo install -m 0600 -o root -g root configs/network/filebeat.yml /etc/filebeat/filebeat.yml.new \
   && sudo env TENANT_ID=<tenant> filebeat test config -c /etc/filebeat/filebeat.yml.new --path.home /usr/share/filebeat --path.config /etc/filebeat --path.data /var/lib/filebeat --path.logs /var/log/filebeat \
   && sudo mv /etc/filebeat/filebeat.yml.new /etc/filebeat/filebeat.yml && sudo systemctl restart filebeat.service \
   || sudo rm -f /etc/filebeat/filebeat.yml.new
   ```
   `<tenant>` is the `TENANT_ID` in `/etc/systemd/system/filebeat.service.d/10-tenant.conf` (`home-smith` on this host).
   Rollback: copy the backup over `/etc/filebeat/filebeat.yml` and restart. Expect a one-time burst from the new syslog
   input (32,370 documents in 30 minutes on 2026-10-24). Known after the swap: a "points to an already known ingest
   target ... Skipping" warning for `ntp.log` (issue #591), and `suricata_ingest_lag_seconds` stays in breach because
   the repo's Filebeat looks for `/storage/PCAP/suricata/eve.json` (#443/#444).
   Then `docker compose -f scripts/setup/docker-compose.yml restart logstash` if you changed the Logstash config.
   **Skip `deploy_detections.sh` for the two M26 syslog rules.** Both (`system_lnx_self_health_unit_failed.yml`,
   `system_lnx_ca_fingerprint_mismatch.yml`) are `status: experimental`, and that script deploys only `stable`/`test`
   rules unless `--include-experimental`, which would deploy every experimental rule. They need passing fixtures first.
4. Enable the monitoring timers. They are **not** enabled by the redeploy script.
   - `zeek-capture-liveness.timer` has no prerequisite:
     `sudo systemctl enable --now zeek-capture-liveness.timer`
   - `stack-health.timer` needs `SOC_HEALTH_PASSWORD` set to a real value in `scripts/setup/.env` and the `soc_health`
     user to exist (test it like step 1 with `soc_health:$SOC_HEALTH_PASSWORD`), then the CA pin seeded **before** the
     first start (`docs/SOP-005-reliability.md`, "Installing the self-health lane"):
     ```bash
     sudo install -m 0600 -D /var/lib/suburban-soc-slo/ca_fingerprint.sha256 /var/lib/suburban-soc-health/ca_fingerprint.sha256
     sudo cp configs/systemd/stack-health.service configs/systemd/stack-health.timer /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable --now stack-health.timer
     sudo systemctl start stack-health.service; journalctl -u stack-health -n 40 --no-pager
     ```
     Good: every component `UP` (Elasticsearch `yellow` is expected on a single node). The next `slo-metrics` run (every
     15 minutes) should show `soc_health_stale_seconds` small instead of about 104 days.
5. Verify. None of these may report `not-found`.
   ```bash
   systemctl status zeek-capture-liveness.timer stack-health.timer 'soc-alert-on-failure@.service' --no-pager | head -30
   ```

**Do not set `NTFY_TOPIC` yet.**
- Issue #567 is open: `soc_alert_on_failure.sh` has no rate limit and can send one push per restart cycle.
- Fix #567 and complete step 1 above, then provision `NTFY_TOPIC`.
- Otherwise about 15 unmeasurable metrics produce about 96 high-priority pushes a day, and the topic gets muted.

**Limit of the liveness supervisor (#549):** it restarts the capture unit only when it is `active` and `conn.log` is
older than 1800 s. It never acts on `failed`. The 2026-10-19 outage was the `failed` kind (parked on a bad interface),
so #549 would not have caught it; only the SLO dashboard shows it, and nothing pushes an alert until `NTFY_TOPIC` is
set after #567.

**After Part 5, the SLO should show one breach:** `suricata_ingest_lag_seconds` (no data; #443/#444). The other
breaches seen on 2026-10-24 (`soc_health_stale_seconds`, `intel_feed_stale_heartbeats`) were cleared by the two fixes above.

## Part 6 — Prove the loop works end to end (15 minutes)

Run from a **second machine on the LAN**, aimed at the capture host's LAN address. `eth1` is this PC's own network
card: on 2026-10-24 the host's `conn.log` held only this PC's traffic and IPv6 housekeeping, no other IPv4 host (#593), and
`sim_portscan.sh`'s default target `127.0.0.1` never touches `eth1`.

```bash
cd tests/anomaly_simulation
cp .env.example .env        # then set TARGET_HOST and the ES/agent URLs for your setup
TARGET_HOST=192.168.1.103 bash sim_portscan.sh     # from the second machine; use the capture host's LAN IP
bash preflight.sh           # also needs OpenWrt and an SSH key for the quarantine checks
python3 verify_detections.py
```

**Done when:** `verify_detections.py` finds the port scan (T1046) notice in the SIEM.
Record the result in `evidence/` and `docs/deploy-changelog.md`.

## Rollback

- `redeploy_systemd_units.sh` does not keep a backup. Before Part 2, run:
  `sudo cp /etc/systemd/system/zeek-host-capture.service /root/zeek-host-capture.service.pre`.
  To roll back, copy it back, then run `sudo systemctl daemon-reload`.
- Stop capture without losing logs: `sudo systemctl stop zeek-host-capture.service`. Logs in `/storage/PCAP/zeek_logs/` stay.

## Also due: zeek image CVE exception expires 2026-11-25

CVE-2026-48930 is ignored for the `zeek/zeek` Trivy job until **2026-11-25** (extended from 2026-10-28 by PR #583; issue #577, SOP-008 Tracked Exceptions).
After that date the `Container image scan (Trivy) (zeek/zeek)` check fails on every PR unless upstream has
shipped a patched image. Check for a newer `zeek/zeek` tag and bump the pin in the 4 capture paths and 3 test pins,
or renew the exception with a new expiry and a recorded reason.
