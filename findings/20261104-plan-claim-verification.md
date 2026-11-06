# Verification of the claims behind plans/20261104-claims-to-evidence-remediation.md

Date: 2026-11-04 (host clock `2026-11-04 16:05 CST`). Session: local WSL host (`Ubuntu`), read-only checks only. No service was started, stopped or changed.
Limits: `sudo` needs a password here, so journals and `/etc/filebeat/filebeat.yml` were unreadable. Web results below were fetched through a summarizing tool, so
quoted text is that tool's output, not a raw page; re-check anything load-bearing at the cited URL.

## A. Host facts (commands run on this machine)

| Item | Observed | Contradicts earlier statement? |
|---|---|---|
| Docker Desktop | `docker-desktop` Running; Docker server 29.3.1 | No |
| `zeek-host-capture.service` | `ActiveState=failed`, `Result=exit-code`, `ExecMainStatus=78`, `ExecMainExitTimestamp=Tue 2026-11-03 10:34:15 CST`, `NRestarts=0` | **Yes**: handoff (2026-10-24) said capturing on `eth1` |
| Zeek log freshness | `/storage/PCAP/zeek_logs/conn.log` last written `2026-10-30 22:41`; now `2026-11-04 16:05` (about 4.7 days stale) | **Yes** |
| Capture interface | Installed unit has `Environment=CAPTURE_IFACE=eth0`. `ip -br -4 addr` shows only `eth0 172.21.123.120/20` (plus `lo`, `docker0`, a bridge). No `eth1`, no `192.168.1.x` address | **Yes**: handoff said `eth1` = `192.168.1.103/24` |
| Which Zeek runs live | `scripts/setup/host_capture.sh` L74-79 pipes `tcpdump` into `docker run ... zeek/zeek:9.0.0@sha256:70733f4e...c16de5`. Native `/opt/zeek/bin/zeek` reports **9.0.1** and is not on the live path (only a reference in `scripts/setup/configs/zeek/scan-detection.zeek`) | **Yes**: project notes say native is 9.0.0 (stale); the live sensor is the image, so PR #607 would change it |
| Local images | `zeek/zeek:9.0.0` (digest matches the pin), `8.2.1`, `latest`, `8.1.1`, `7.0`. **9.0.1 is not pulled** | n/a |
| Suricata | `suricata.service` active, 7.0.3; `suricata-host-capture.service` inactive and disabled | Consistent with handoff item 8 |
| Timers | `zeek-capture-liveness`, `slo-metrics`, `stack-health`, `intel-refresh` timers all active | Consistent |
| `NTFY_TOPIC` | **Empty or absent in `scripts/setup/.env`** (value not printed) | **Yes**: handoff said the topic is set and alerts reach the owner's phone. Could be set elsewhere; not found here |
| SOC Docker stack | **No Docker project from this repo was present** on the first check (no container labelled with this repo's compose directory) | **Yes**: handoff said "Docker stack up" |
| Ports | 5044, 5000, 9200 were listening, not confirmed to be this repo's services | Unknown |

Not determined: why the unit exited 78 (journal unreadable without sudo); why `conn.log` stopped on 10-30 before the unit failed on 11-03;
whether anything was pushed to the owner's phone for the failure; whether the SOC stack was moved or torn down on purpose.

## B. #577 / PR #607 claims

| Claim | Result | Source |
|---|---|---|
| `zeek/zeek:9.0.1` digest `sha256:524cb0ce...249dd0`, pushed 2026-10-26 | **Confirmed** (tags `9.0.1`, `latest`, `9.0`, `lts` share it; pushed `2026-10-26T18:26:11Z`) | `hub.docker.com/v2/repositories/zeek/zeek/tags` |
| CVE-2026-48930 is nodejs, fixed in trixie `20.19.2+dfsg-1+deb13u3` | **Confirmed**: "Embedded-nul hostnames can lead to silent authority rebinding...", DSA-6517-1 | `security-tracker.debian.org/tracker/CVE-2026-48930` |
| CVE-2026-111497 is brotli, fixed `1.1.0-2+deb13u1` | **Confirmed** (DSA-6582-1). **New concern:** the same page lists `nodejs 20.19.2+dfsg-1+deb13u3` as *vulnerable* with no trixie fix. The commit says libnode115 `deb13u3` "clears" this CVE. PR #607's Trivy job passed, so Trivy may not flag it, but the claim is unproven | `security-tracker.debian.org/tracker/CVE-2026-111497` |
| CVE-2026-110858, CVE-2026-42284, CVE-2026-78676 exist and concern GitPython | **Confirmed to exist** in the Debian tracker's python-git table. Per-trixie status not shown by the summary. Tracker lists trixie `3.1.44-1` and trixie-security **`3.1.44-1+deb13u1`** | `security-tracker.debian.org/tracker/source-package/python-git` |
| No `zkg`/GitPython use in the repo | **Confirmed** on the PR branch (`git grep`, matches only in comments) | local |
| 164-pcap golden diff | **Not run** (commit says so); 9.0.1 not pulled locally | commit `0402b52` |
| PR #607 state | Open, 19/19 checks SUCCESS, merge state CLEAN, no review | `gh pr view 607` |

Not done: `dpkg` inspection of the 9.0.1 image, a local Trivy scan of it, and the NVD cross-check.
Consequence worth acting on: Debian ships `python3-git 3.1.44-1+deb13u1` in trixie-security, so the image's remaining findings could be removed (a thin pinned layer that
upgrades or removes `python3-git`) instead of excepted. That is a proposal, not tested.

## C. Root causes found afterwards (same day; syslog is readable via the `adm` group, `journalctl -u zeek-host-capture` returned "-- No entries --" even under sudo per the owner)

| Finding | Evidence (verbatim where quoted) |
|---|---|
| Zeek lane is down because the pinned interface does not exist | `/etc/default/zeek-host-capture` contains `CAPTURE_IFACE=eth1` (root-owned, dated Oct 24 10:18). `EnvironmentFile=` overrides the unit's `Environment=CAPTURE_IFACE=eth0`. Running the repo's own `scripts/setup/capture_iface_preflight.sh eth1` (read-only) prints `FATAL: capture interface "eth1" is not up (waited 30s).` and exits **78**; the same script with `eth0` exits **0**. Host has only `eth0 172.21.123.120/20` |
| It fails on every WSL boot | syslog: `2026-11-01T17:23:29 ... zeek-host-capture.service: Main process exited, code=exited, status=78/CONFIG` (boot 17:22:58) and `2026-11-03T10:34:15 ... status=78/CONFIG` (boot 10:33:48). 14 WSL boots are retained between 2026-10-26 and 2026-11-03 |
| The design did what it was built to do, but nobody was told | `RestartPreventExitStatus=78` parked the unit in `failed` (no restart loop). The failure dispatcher ran, and wrote `soc_alert_on_failure: NTFY_TOPIC is unset -- cannot deliver alert for zeek-host-capture.service` (first seen 2026-10-31T11:53:45). `NTFY_TOPIC is unset` appears **684 times in the current syslog and 346 in syslog.1**; `slo_metrics` logs `WARNING: NTFY_TOPIC is unset -- SLO breach alerts will not be delivered`. So the handoff's "alerts reach the owner's phone" is **false on this host today** |
| The stack is not up after a boot | 2026-11-03T10:34:15 stack-health: `elasticsearch DOWN (unreachable)`, `kibana DOWN`, `logstash DOWN`, `ai_agent DOWN`, `broker DOWN`, `slo_metrics DOWN`; `ES CA could not be extracted this run (Docker engine unavailable?)`. Nothing autostarts this repo's compose project after a WSL restart |
| `conn.log` stopped 2026-10-30 22:41, before the 11-03 failure | Boots on 2026-10-30T20:19:53 and 2026-10-31T11:53:08 bracket it; cause of the stop itself not established |

Not changed: nothing was edited, restarted or enabled. A fix needs `sudo` and a placement decision (`eth0` here is the WSL NAT address, so it would capture only the VM's own traffic, not the LAN; #593).

## D. Placement, NTFY location and stack state (owner asked for all three; read-only checks, 2026-11-04 ~16:30 CST)

- **LAN visibility.** No `.wslconfig` exists, so WSL2 is in default NAT mode (WSL 3.0.3.0). Windows default route is `Wi-Fi 10.50.3.43/24` via `10.50.3.1`; other adapters: `Ethernet 3 172.16.0.150/32`, `VMware VMnet1 192.168.56.1/24`, WSL/Default-Switch vEthernets. No `192.168.1.x` adapter. `ping 192.168.1.1`: no reply; `10.50.3.1`: reply. A host NIC on a switched or Wi-Fi network sees only its own unicast plus broadcast/multicast, so no WSL networking mode alone yields LAN-wide visibility; that needs the router capture path (design intent, `stream_capture.sh`/`zeek_connect_host.sh`, vars `ROUTER_IP`/`ROUTER_USER`, **none set in `scripts/setup/.env`**), a mirror port, or an inline sensor. SSH keys exist (`id_ed25519`, `id_ed25519_hivemind`); router reachability and credentials not tested.
- **NTFY_TOPIC.** Defined only in `scripts/setup/.env`, **empty**. Not in `/etc/default/*`, unit drop-ins, `~/.config/suburban-soc`. That file is the one place both consumers read: `soc_alert_on_failure.sh` L35 sources `"$HERE/.env"` and compose reads it. It is gitignored (`.gitignore:103`). Its mode is **644** (contains the stack passwords); 600 would be tighter.
- **Docker.** `docker compose ls -a` now lists project `suburban-soc` (`/home/tjlam/projects/Suburban-SOC/scripts/setup/docker-compose.yml`): `soc_setup` and `soc_cert_pkcs8` `Exited (0)`; `elasticsearch`, `logstash`, `kibana`, `soc_ai_agent`, `hive_mind_broker`, `soc_roles`, `soc_provision`, `soc_lifecycle` all **`Created`, none running**; no `docker compose` process is running. **Port conflict:** this compose publishes `127.0.0.1:${ES_PORT:-9200}:9200`, and another container on this host already holds `0.0.0.0:9200`. Docker will refuse to start this repo's ES while that holds (inferred from the two port mappings; I did not try to start it).

## E. Why this repo's stack does not reach a running state (2026-11-04 ~16:20-16:40 CST; scoped to this repo's compose project only)

- **Last reported running.** Retained syslog holds 1,879 `stack-health` runs from `2026-10-25T15:49:01` to `2026-11-04T16:20:16`; every one that lists elasticsearch says `DOWN (unreachable)`, and no UP line is retained, so the earliest retained record is already DOWN. The last evidence of the stack running is secondhand: the handoff (SLO verified 13:25 and 13:29 CDT on 2026-10-24, "Docker stack up") and `docs/deploy-changelog.md` (`2026-10-24T18:25:06Z`, detections deployed, which needs a live ES). So: **last known running 2026-10-24 ~13:29 CDT; down by 2026-10-25 15:49 CDT; cause of that transition not recorded.**
- **A 16:14 `docker compose up` stopped early.** Containers were created `2026-11-04T22:14:12Z`; `soc_setup` and `soc_cert_pkcs8` ran and exited 0; `elasticsearch` stayed `Created` and never started. No compose process was running afterwards and the terminal output was not available to me.
- **My earlier "port 9200 conflict" inference was wrong.** `docker start elasticsearch` (this repo's container only) succeeded: bound `127.0.0.1:9200`, `healthy` within 20 s, existing data intact.
- **Blocker now: Kibana.** `docker compose up -d` started elasticsearch, `soc_lifecycle`, `soc_provision`, `soc_roles`, `logstash`, `hive_mind_broker`, then failed: `Error response from daemon: ports are not available: exposing port TCP 0.0.0.0:5601 -> 127.0.0.1:0: /forwards/expose returned unexpected status: 500`. Nothing listens on 5601 (Windows or WSL). Windows excluded TCP ranges are `1024-1123 1124-1223 5357 5358-5457 5558-5657 5758-5857 8883 8884`; **5601 is inside 5558-5657**. `KIBANA_PORT=5601` in the local `.env`; compose maps `${KIBANA_PORT:-5601}:5601`. 15 non-doc files mention 5601.
- **Separate defect: the Zeek liveness supervisor has never run on this host.** `zeek-capture-liveness.service` logs `/usr/bin/bash: .../zeek_capture_liveness.sh: Permission denied` on every run: 61, 32, 25, 40, 17, 31, 5, 49, 167, 197 per day from 2026-10-25 through 2026-11-04. The script is mode 755, but `/home/tjlam` is mode **750** and the unit runs as root with `CapabilityBoundingSet=` empty and `NoNewPrivileges=true`, so root has no DAC override and cannot traverse the home directory (inference from those four facts; not tested by changing anything). Its failure alert then goes nowhere because `NTFY_TOPIC` is unset.

## F. Outcome: stack restored 2026-11-04 (owner-approved port change)

- Changed (local, gitignored `scripts/setup/.env`, mode 644 unchanged): `KIBANA_PORT=5601` -> `5700`; added `KIBANA_URL=https://localhost:5700`. 5700 was outside every Windows excluded range at the time (`5558-5657`, `5758-5857` bracket it). Temporary full-file backup was deleted immediately (it held credentials).
- Ran `docker compose up -d kibana ai-agent` from `scripts/setup/`. Result: `elasticsearch` healthy, `kibana` healthy (`https://localhost:5700/api/status` -> HTTP 200), `ai-agent` healthy, `logstash` and `hive-mind-broker` running (no healthcheck defined), one-shots exited 0.
- Host timer confirmation, `stack-health` run at 16:45:15 CST: `elasticsearch UP (yellow)`, `kibana UP (available)`, `logstash UP`, `ai_agent UP`, `broker UP`, `slo_metrics UP (fresh 350s)`. So the timer honors the new `KIBANA_URL`. ES `yellow` is the documented single-node system-index state (README Known Issues).
- Not fixed: `soc_pipeline.sh` still hardcodes `https://localhost:5601` (lines 349, 645, 695); the port is not protected against a future Windows range change; Zeek lane still `failed` (pinned `eth1`); `NTFY_TOPIC` still empty; liveness supervisor still `Permission denied`; nothing committed.
