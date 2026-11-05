# Two Docker engines share one socket path (2026-11-04)

Read-only checks on the capture host, no sudo. UNVERIFIED items are marked.

## Verified
1. Native `dockerd` is enabled and running under systemd (`docker.service`, pid 588, `docker.socket` activated Nov 3 10:33:48).
2. Docker Desktop's WSL integration also runs (`docker-desktop-user-distro proxy`, started Nov 3 10:55:33). `/var/run/docker.sock` and `/run/docker-desktop-proxy.pid` have the identical mtime `2026-11-03 11:08:44.519916354`, so Desktop's proxy created that socket and replaced the one `docker.socket` made at 10:33:48. `ss -xlp` shows two listeners (inodes 7235 and 13940); the older one is orphaned and unreachable by path.
3. The CLI talks to Desktop: `docker info` -> `Name: docker-desktop`, `Docker Desktop (containerized)`, 29.3.1. The compose project `suburban-soc` and its volumes (`suburban-soc_certs`, `setup_suburban_soc_data`, ...) are visible there. Context `default` = `unix:///var/run/docker.sock`; `DOCKER_HOST` unset.
4. Docker Desktop `settings-store.json`: `AutoStart = False`, `WslEngineEnabled = True`, `EnableIntegrationWithDefaultWslDistro = True`. No `.wslconfig`.
5. Nothing orders against Docker. Every unit in `configs/systemd/` is `After=network-online.target` only; no unit starts the compose project; no script sets `DOCKER_HOST` or a context. Each `docker` call goes to whichever engine owns the path at that moment.
6. `restart: unless-stopped` is set only on elasticsearch, kibana, logstash, ai-agent, hive-mind-broker. It acts only inside an engine that is running.
7. Docker events history for the stack back to Nov 3 returned nothing (buffer not kept); Desktop `monitor.log` rotates in minutes. The earlier outage cause (stack down at Nov 4 16:14) is NOT established. The electron log shows Desktop's UI streaming logs for both compose projects at 16:38:45-49 CST, consistent with manual use; not proof.

## Not verified (needs sudo)
- What the native engine holds. `/var/lib/docker` is root-only. Suggested read-only check: `sudo sh -c 'ls /var/lib/docker/containers | wc -l'`, and `sudo grep -ho '"Name":"[^"]*"' /var/lib/docker/containers/*/config.v2.json`.
- Inference, not shown: before Desktop starts after a boot, systemd-launched `docker` calls (stack-health, `zeek-host-capture`'s `docker run`) reach the native engine, which probably lacks the stack and the pinned Zeek image. Matches stack-health's "Docker engine unavailable?" at boot.

## Decision (owner, 2026-11-04)
**Option B now; Option A is kept as the long-term target** (headless Linux edge node, no Windows sign-in). Revisit A when moving to real hardware or when a reboot-without-sign-in requirement appears. Do not delete A's notes below.

## Options
- **A. One engine, native dockerd, headless.** Disable Desktop integration for Ubuntu; `docker.service` plus a compose-start unit bring the stack up at WSL boot. Needs a data migration (ES data, certs, CA pin) and owner approval. Likely also avoids the Desktop port forwarder that rejected 5601 (inference).
- **B. One engine, Docker Desktop.** Disable the native engine (`docker.service`, `docker.socket`), set Desktop to start at sign-in, add a compose-start unit that waits for the engine. No data move; still needs a Windows sign-in after every reboot.
