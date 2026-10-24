# Session handoff — 2026-10-24 (cloud session + live capture-host walk-through)

**Read this first, then `planned_execution.md` (LAST SESSION — 2026-10-24).** Written for a session with none of this conversation.
Facts come from the repo, GitHub, and output the owner pasted from the capture host. Anything marked **UNVERIFIED** was not run or checked.

## 1. Where things stand

| | State |
|---|---|
| `main` | Includes #581–#590 (all this session's PRs merged), plus the PR carrying this refresh if still open: check GitHub. |
| Capture host (observed 2026-10-24, last check ~11:50 CDT) | **Zeek capturing on `eth1`**, indexed. Unit redeployed 11:09 with the `$${err}` fix (verified: real error now in the journal). `stack-health`, `slo-metrics`, `intel-refresh`, `zeek-capture-liveness` timers scheduled. **Filebeat replaced 11:38** with the repo's config (backup `/etc/filebeat/filebeat.yml.bak-20261024`); syslog flowing. Docker stack up. |
| SLO | One breach expected: `suricata_ingest_lag_seconds` (Filebeat looks for `/storage/PCAP/suricata/eve.json`; no Suricata data reaches Elasticsearch). Re-verify. |
| What the sensor sees | **Only this PC's own traffic** (78 of 109 connection records from `192.168.1.103`, rest IPv6 chatter; no other IPv4 host) (#593). **Not this host's DNS** (WSL2 resolver traffic stays on `lo`) (#592). |
| Alerts | **No alert reaches anyone.** `NTFY_TOPIC` unset; #567 open; the end-to-end test has never run. |
| Session limits | Cloud: no Docker/ES/Suricata, no general DNS, cannot merge PRs. Capture host: sudo, Docker, `gh`. |

## 2. Merged this session

| PR | What | Verified how |
|---|---|---|
| #581 | Restore-capture runbook, production-readiness plan | Docs |
| #582 | Curl test accepts exit 2 or 77 | CI green; runner curl version never read |
| #583 | CVE-2026-48930 exception to **2026-11-25** | Docker Hub: newest `zeek/zeek` tag still `9.0.0`; Debian/NVD UNVERIFIED |
| #584 | `mint_endpoint_cert.sh`, endpoint `ssl.certificate`/`ssl.key`, 18 tests | Fake `docker` only. **Never run live** |
| #585 | `suricata_threshold_baseline.py`, 23 tests, tuning plan | CI green. **Never run on live traffic** |
| #586, #588, #589 | Handoff, runbook corrections, README/planned_execution rows | Docs |
| #590 | `$${err}` escape in the Zeek unit; redeploy script installs `intel-refresh`; class-guard test | CI green; **verified live**: journal now shows the real `cp` error (11:09 redeploy) |

## 3. Open work, in order

1. **Decide the sensor placement (#593).** It decides whether this is a one-host lab sensor or a network monitor. Options in the issue (router capture path, mirror port, or document it). Everything about "coverage" depends on it.
2. **Work issue #567** (alert rate limit), then set `NTFY_TOPIC`. Until both, nothing pushes an alert; a parked `failed` capture unit (the 2026-10-19 outage) would still be silent.
3. **Filebeat fingerprint skip (#591)** and **DNS blind spot (#592):** both need a design choice (options in the issues).
4. **Live-check #265:** `bash scripts/setup/mint_endpoint_cert.sh test-endpoint`, ship one event from a test endpoint, confirm it lands in `logstash-security-*`. Only if it does, close issue #265 by hand. Gap not fixed: Logstash trusts the shipper's own `[tenant][id]`.
5. **Runbook Part 6** (end-to-end alert test): from a second LAN machine, aim `sim_portscan.sh` at `192.168.1.103`; needs a `tests/anomaly_simulation/.env` and the preflight prerequisites (OpenWrt/SSH key).
6. **The two M26 syslog rules** are `status: experimental`, so `deploy_detections.sh` skips them. They need passing TP/TN fixtures to be promoted (`sigma-rule` skill). The syslog data they need is already flowing.
7. **Housekeeping:** retitle issue #577 (still names the perl CVE); Filebeat on the host is 8.19.23 against stack 9.3.2 (supported, but `install_filebeat.sh` says 9.x); `intel.dat` refresh warning in the Zeek unit is expected (mode 600); board and wiki updates need a local session; README rows for #590 and the new issues.
8. **Suricata (#587):** `suricata.service` (distro package) is `enabled`, the repo's `suricata-host-capture.service` is `disabled`. Even with a running sensor, Filebeat reads `/storage/PCAP/suricata/eve.json`; the distro default path is normally `/var/log/suricata/eve.json` (not verified on this host). CI blocks enabling any of the 14 threshold rules until each has a TP pcap fixture.
9. **Production plan items 4–8** (`plans/20261023-production-readiness-plan.md`): load test (#405, needs a peak-traffic figure), multi-node Elasticsearch, real Windows telemetry (#326), SOC 2 evidence, sensor placement (#593).

**Dated:** CVE exception expires **2026-11-25** (#577 stays open). Check Docker Hub for a `zeek/zeek` tag newer than `9.0.0` and Debian's tracker; bump the pin or re-justify.

## 4. Decisions only the owner can make

| Decision | Options | Needed for |
|---|---|---|
| **Sensor placement** (#593) | Router capture path, mirror port/tap, or document a single-host scope | Whether this monitors the network at all |
| DNS visibility (#592) | `lo` DNS capture, turn off WSL DNS tunnelling, or accept | DNS-based detections |
| Fingerprint fix (#591) | Longer fingerprint, native identity, or offset | Shipping every Zeek log |
| Peak traffic figure (Mbit/s, connections/s) | A number | Load test |
| Placeholders 9000013, 9000099 | Real values, or delete | #587 |
| DLP rules 9000065, 9000066 | Approve scanning, or delete | #587 |
| Upload-size rules 9000063, 9000064 | Raise `request-body-limit`, rewrite on flow bytes, or remove | #587 |
| Are the university-themed rules in scope for a residential mesh? | Keep/tune, or delete | #587 |
| CVE exception length (I chose 4 weeks) | Shorter or longer | #577 |

## 5. What did not work, and lessons

- **My runbook guesses were wrong in places.** Part 2 was unnecessary; Part 5 omitted the intel installer and the `stack-health` prerequisites. Corrections are now in the runbook's "Field notes" section. Trust observed output over the runbook.
- **I guessed the SLO breach was Zeek lag (it was fine).** Read the output before naming a cause.
- **A search tool returned 0 open Suricata issues** while #443/#444 were open. List, don't trust one search.
- **I wrote "leaves #446 open"** after reading that it was closed. Check issue state before writing it into a PR.
- **Cloud sandbox cannot reproduce CI's curl or any network test** (no DNS). **Local `ruff` differs from CI:** install `ruff==0.15.15`.
- **Stale installed units are a real failure class** (intel-refresh sat on the pre-#271 unit for weeks). Compare installed vs repo (`diff <(sed 's/[[:space:]]*$//' /etc/systemd/system/X) <(sed ... configs/systemd/X)`) before debugging a unit.
- **Measure before concluding.** Two of my network tests were invalid (a lookup outside the capture window; a `sudo` prompt eating the 2-second delay). Make timing tests self-contained (`sudo -v` first).
- **A search or grep that returns nothing is not evidence.** My Filebeat-skip grep missed JSON-escaped quotes. Check the pattern against a line you know exists.
- **Filebeat refuses a config not owned by root.** Test a root-owned copy.
- **Sourcing `.env` exports passwords into that terminal.** Use `exec bash` afterwards; pass secrets to `docker exec` by name (`-e NAME`), never by value.

## 6. Repo rules that bit or nearly bit

- **Never write a closing keyword before an issue number** in a PR title, body or commit, even negated (`CLAUDE.md`). Say "leaves #N open"; close issues by hand after merge.
- `main` needs 14 checks, `strict`, `enforce_admins`; only the owner merges. A merged PR's branch is deleted by workflow; a stale local tracking ref makes `--force-with-lease` say "stale info".
- Status lives in `planned_execution.md` and `README.md`; update both after merges. Cloud sessions cannot sync the Projects v2 board or push the wiki (local session with `gh` can; or paste).
- Never assert an IOC malicious, invent a CVE/hash/timestamp, or guess attribution (`CLAUDE.md`).

## 7. Paste this to start the next session

> Read `plans/20261024-session-handoff.md` and the LAST SESSION — 2026-10-24 section of `planned_execution.md`. State which open items in section 3 you can do from this environment (cloud: no Docker/ES/Suricata; local capture host: sudo available) and start with the first one you can complete. Do not open a PR unless I ask.
