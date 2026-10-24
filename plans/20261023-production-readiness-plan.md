# Production-readiness plan

**Date:** 2026-10-23
**Prerequisite:** capture is restored and verified. Do `plans/20261023-restore-zeek-capture-runbook.md` first.
**Source of truth for status:** `README.md` and `planned_execution.md` (last status entry 2026-09-28). Re-check each issue's state before starting it.

## How to read this plan

- **Facts from the repo** are cited with a file or issue number.
- **Proposed design** is marked *(proposal)*. The repo does not specify it; review it before building.
- Each item has: why it blocks production, steps, and a "done when" test you can run.
- Effort figures are estimates, not measurements.

## Priority order

| # | Item | Blocks production because | Issue | Effort | Needs |
|---|---|---|---|---|---|
| 1 | Zeek image CVE exception expires 2026-10-28 | CI fails on every PR after 2026-10-28 | #577 | 1 hour | Network, no hardware |
| 2 | Endpoint client certificates | Endpoint shippers cannot connect to Logstash | #265 | 2–3 hours | Live Docker |
| 3 | Suricata rule tuning | 20 of 100 rules are disabled; alert quality unknown | #446 | 1–2 weeks (traffic time) | Live traffic, owner input |
| 4 | Load test | Behaviour under load is unknown | #405 | 1 day | Live pipeline |
| 5 | Elasticsearch multi-node | Single node has no fault tolerance | none filed | 2–3 days *(proposal)* | 3 hosts or VMs |
| 6 | Real Windows telemetry | PowerShell rules never saw real data | #326 | Weeks of collection | Windows endpoints |
| 7 | SOC 2 Type II evidence | Change ledger has no real deploys | M10 scope note | Months | Process, auditor |
| 8 | Sensor placement: `eth1` sees only this PC's traffic (and not its DNS) | The deployment does not monitor the network it describes | #593, #592 | Decision first, then hours to days | Owner decision, router or mirror port |

**Do now (this week):** items 1 and 2. **Later:** items 3–7.

---

## 1. Renew or remove the zeek image CVE exception (due 2026-10-28)

**Why:** CVE-2026-48930 (nodejs, in every published `zeek/zeek` image) is ignored for the zeek-image Trivy job only,
until **2026-10-28** (`planned_execution.md`, "LAST SESSION — 2026-09-28"; SOP-008 Tracked Exceptions).
After that date the `Container image scan (Trivy) (zeek/zeek)` check fails, and it is a required check on `main`.
The repo records that the path is not reachable as deployed (ZeekJS-only; capture loads `.zeek` only).

**Steps (about 1 hour):**
1. Look for a newer `zeek/zeek` tag. Run `docker pull zeek/zeek:<newer-tag>` and `trivy image zeek/zeek:<newer-tag>`.
2. **If a patched image exists:** bump the pin in the 4 capture paths and 3 test pins. PR #578 touched these;
   run `git show a390b48 --stat` to list the files. Re-run the golden-output diff of the 164 fixture pcaps through
   old and new images, as PR #578 did. Run the CI `live-fire` job.
3. **If no patched image exists:** extend the exception. Edit the expiry in the Trivy ignore file and in
   SOP-008 Tracked Exceptions, record the date checked and the reason, and keep #577 open.
4. Open a PR. Do not write a closing keyword before an issue number (see `CLAUDE.md`); say "leaves #577 open" or close it manually after merge.

**Done when:** `Security Scan` passes on a fresh PR after 2026-10-28.

## 2. Endpoint client certificates (#265)

**Why:** Logstash's Beats input requires client certificates (`ssl_client_authentication => required`, #219).
`configs/endpoint/winlogbeat.yml` and the Filebeat endpoint config set only `ssl.certificate_authorities`, so shippers fail with
`tls: certificate required` (`docs/master_pipeline_guide.md:453`). PR #537 documented the gap; the cert-minting code is not written.

**Steps (about 2–3 hours):**
1. Read `scripts/setup/generate_certs.sh` and the `setup` service in `scripts/setup/docker-compose.yml` to see how the CA is made.
2. Add a per-endpoint client-certificate step *(proposal)*: a script that signs a cert for a given host name and `tenant.id`
   using the existing CA, writes `<host>.crt`, `<host>.key` (mode 600), and prints the CA path for the endpoint.
3. Add `ssl.certificate` and `ssl.key` to `configs/endpoint/winlogbeat.yml` and `configs/endpoint/filebeat_endpoint.yml`.
4. Update the two "Gap (issue #265)" notes in `docs/implementation_plan.md` and the troubleshooting row in `docs/master_pipeline_guide.md`.
5. Add a test that runs the mint script in a temp directory and checks the cert chains to the CA.
6. Run `docker compose up -d` on the capture host (cloud sessions have no Docker daemon, so this step cannot run there).

**Done when:** a test endpoint ships one event and it appears in `logstash-security-<tenant>-*`, with no `certificate required` error in the Logstash log.

## 3. Suricata rule tuning (#446, closed 2026-10-17; no open issue covers the remaining 20 rules)

**Why:** 80 of 100 rules are enabled. The other 20, from `planned_execution.md`: 14 need `detection_filter` tuning against real traffic,
2 are unresolved placeholders, 2 are DLP rules needing owner sign-off, 2 are dead as configured (`request-body-limit` decision).
Also, #443 and #444 (sensor and eve.json ingest) stay open because they need a live capture host with real traffic.

**Steps:**
1. Install `suricata-host-capture.service` (it is not installed on the host). Use `scripts/setup/redeploy_systemd_units.sh`.
   Confirm Zeek and Suricata run together without dropping packets; #443 flagged resource risk for this.
2. Collect 7 days of real traffic with all 14 threshold rules in alert-only mode. Count alerts per rule per day from `eve.json`.
3. For each of the 14: choose a `detection_filter` count and window so the baseline day gives near-zero alerts; record the chosen values and the baseline count.
4. **Owner decisions (cannot be made by Claude):** the 2 placeholder IOCs (institutional values), the 2 DLP rules (sign-off),
   the 2 `request-body-limit` rules (raise the limit or drop the rules).
5. Enable rules in small batches. After each batch, run the pcap replay harness from #445 and watch for a day.

**Done when:** every rule is either enabled with a recorded baseline or removed with a recorded reason, and #443/#444 criteria are met on live traffic.

## 4. Load test (#405 and README "not stress-tested")

**Why:** README Known Issues: "OpenWrt gateway streaming throughput has not been stress-tested; performance under extreme load is unknown."
#405 also asks for a benchmark of the Sigma field-resolution sweep.

**Steps (about 1 day):**
1. Define the target *(proposal)*: peak expected traffic for the neighbourhood deployment, in Mbit/s and connections/s. Get this figure from the owner; the repo does not state it.
2. Replay pcaps at 1×, 2×, 5× and 10× of that rate (for example with `tcpreplay`) into the capture interface.
3. At each rate record: packets dropped (tcpdump and Zeek stats), Zeek `conn.log` lag, Logstash queue depth, Elasticsearch indexing latency, `zeek_ingest_lag` from `slo-metrics` (target < 300 s per `evidence/README.md`).
4. Note the first rate at which any metric breaks its target. That is the capacity limit.
5. Record results in a new file under `findings/`.

**Done when:** a written capacity figure exists, with the limiting component named.

## 5. Elasticsearch multi-node *(proposal; no issue filed)*

**Why:** README Known Issues: single node, "not yet production-ready". `docker-compose.yml:527` sets `discovery.type=single-node`, and index templates use `number_of_replicas: 0` to keep indices green.

**Steps (2–3 days):**
1. File an issue and a milestone so the work is tracked.
2. Provision 3 nodes (3 master-eligible nodes avoids split-brain). Size the heap from the load test in item 4; the current heap is 2 GB (`ES_JAVA_OPTS=-Xms2g -Xmx2g`).
3. Replace `discovery.type=single-node` with `cluster.initial_master_nodes`, `discovery.seed_hosts`, and per-node certificates (extend `generate_certs.sh` with node names).
4. Change the index templates to `number_of_replicas: 1`. Confirm ILM and the snapshot policy `suburban-soc-daily-snapshots` still work (`docs/SOP-004-data-retention.md`).
5. Point Logstash, Kibana, the AI agent and `slo-metrics` at all nodes. Update `ES_CA` pinning checks (`verify_ca_fingerprint.sh`, `es_ca_cache.sh`) for the new CA.
6. Test: stop one node during ingest; confirm no data loss and cluster returns to green after restart.

**Done when:** killing any one node leaves ingest and search working, and a snapshot restore test succeeds.

## 6. Real Windows/PowerShell telemetry (#326)

**Why:** #326 is blocked on real telemetry accumulating. Without it, PowerShell rules such as `posh_ps_obfuscated_scriptblock` are only tested on fixtures.

**Steps:**
1. Enrol 2–3 Windows endpoints with Sysmon, Winlogbeat and PowerShell script block logging (4104). Use item 2's certificates.
2. Collect for at least 2 weeks of normal use.
3. Run `tests/anomaly_simulation/sim_win_*.ps1` on one endpoint and run `verify_detections.py`.
4. Count false positives per rule in the 2-week baseline; tune the coarse rules listed in #217.

**Done when:** each Windows rule has a recorded true-positive test and a recorded 2-week false-positive count.

## 7. SOC 2 Type II evidence

**Why:** `README.md` scope note: M10 means technical control design only. `docs/deploy-changelog.md` has one entry (2026-07-09, dashboards).
A Type II report needs controls operating over a defined period.

**Steps:**
1. Make every deploy go through `deploy_changelog.sh` (the file says it auto-appends). Add this to `docs/SOP-007-change-management.md` as a required step.
2. Pick an observation period with an auditor (commonly 3–12 months; confirm with the auditor).
3. Keep monthly evidence: access reviews (SOP-009), backup restore test (SOP-004), vulnerability scan results (SOP-008).
4. Engage an external auditor. This cannot be done by the repo alone.

**Done when:** an external auditor issues a report. Until then, do not describe the project as SOC 2 compliant.

## 8. Sensor placement (#593, #592) — added 2026-10-24

**Why:** on the capture host, `conn.log` held only this PC's own traffic and IPv6 housekeeping; no other IPv4 host appeared in about 30 minutes, and DNS lookups never cross `eth1` (WSL2's resolver stays on `lo`). The README describes boundary monitoring of the mesh.

**Steps:** (1) the owner chooses: capture from the OpenWrt router (`stream_capture.sh`), a switch mirror port or tap, or document a single-host scope. (2) Implement the choice and verify `conn.log` over a normal hour shows several LAN sources. (3) Decide the DNS option in #592. **Done when:** the README's coverage statement matches what `conn.log` shows.

---

## Not production-blocking but still open

- #333, #415, #421 (M17), #545 (M18): need a live stack. Do them while the stack is up for the load test.
- #567 (alert dispatcher rate limit) is listed in the capture runbook and must be done before `NTFY_TOPIC` is set.
- Unpinned-CA gaps: `checkpoints-compact.service`, `threat-intel-compact.service`, `configs/slo/slo-metrics.cron` (`planned_execution.md`, owner action 3).

## Sequence

1. Week 1: item 1 (before 2026-10-28), item 2, load test setup.
2. Weeks 2–3: items 3 and 4 run in parallel; item 6 collection starts once item 2 is done.
3. Weeks 4–5: item 5.
4. Ongoing: item 7.
