# Issue #147 — Remaining Evidence & Validation Plan

> **For workers:** ops/evidence plan (not code). Each task has exact commands, expected output, and the evidence artifact to log. Steps use `- [ ]`. Conventions block must be sourced in every shell.

**Goal:** Finish evidencing #147 — complete Section A (A.4–A.6), re-capture Section B dashboards, verify Section C pipeline integrity, record Section D metrics on real telemetry, then pass Section E self-check and DoD.

**State at plan time:** A.1–A.3 ✅ (rows #7–#10, real bat0, tenant `home-smith`). `zeek-host-capture.service` STOPPED; manual bat0 stream running (PID 4871, container `unruffled_dijkstra`). Recon: `findings/2026-06-28-147-remaining-requirements.md`.

## Conventions (source in every shell)
```bash
cd /home/tjlam/projects/Suburban-SOC/scripts/setup && set -a && source .env && set +a
ES_URL="${ES_URL:-https://localhost:9200}"; KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
AUTH="-u ${ES_USER:-elastic}:${ES_PASS:-$ELASTIC_PASSWORD}"
ES() { curl -s -k $AUTH "$@"; }
TENANT=home-smith
```

## Global Constraints
- TLS always on; tenant-scoped indices (`logstash-security-home-smith`, `soar-actions-home-smith`, `soc-audit-home-smith`). Never `verify=False`.
- Real telemetry only; do not fabricate. Endpoint panels (B.3) get an honest "awaiting live endpoint" label.
- Every screenshot row in `evidence/README.md`: desc | SHA-256 | UTC window | source IP/host | index/data stream.
- Destructive/router-isolating actions need explicit user confirmation in-session.

## Decisions required before execution
1. **A.5 quarantine:** execute real isolation on a *disposable test MAC* (needs a throwaway device + `/approve`), OR honest-negative "tooling ready, not executed on production mesh." Default: honest-negative (consistent with A.2 "DROP not executed").
2. **A.4 variant:** standard ingest injection (`sim_intel_match.sh`) — default; or stronger bat0-organic (mesh client connects to `198.51.100.66`).

---

### Task 0: Verify SOAR auto-trigger is actually live (resolves a known discrepancy)
**Why:** memory + row #9 say network detections don't auto-fire the agent; `rules/elastic_watcher/soar_quarantine_alert.json` suggests they do. Ground-truth this — it changes whether A.1–A.4 auto-produce `soar-actions`.

- [ ] Check the Watcher is registered and its execution state:
```bash
ES "$ES_URL/_watcher/stats?pretty" | grep -iE 'watcher_state|execution'
ES "$ES_URL/_watcher/watch/soar_quarantine_alert?pretty" | grep -iE '"found"|"active"|condition'
```
Expected: watcher_state `started`; watch `found:true`. If 404 → not registered (memory stands).
- [ ] Check recent firings / agent contact:
```bash
ES "$ES_URL/.watcher-history-*/_search?pretty" -H 'Content-Type: application/json' -d '{"size":3,"query":{"match":{"watch_id":"soar_quarantine_alert"}},"sort":[{"result.execution_time":"desc"}]}' | grep -iE 'state|status_code|reason'
ES "$ES_URL/soar-actions-$TENANT/_count"
```
- [ ] **Record verdict** in the findings file. If LIVE: update memory `soar-trigger-not-wired-network` (mark superseded) and note A.1–A.3 may now have auto `soar-actions` to screenshot. If NOT: A.4/A.6 SOAR evidence stays manual via `section_a_evidence.sh`.

---

### Task 1: (bat0-window only) Ensure GeoIP-resolvable traffic exists for B.2
**Why:** B.2 GeoIP map needs a doc with resolved `source.geo`/`destination.geo` from a real public IP. Do this while the bat0 stream is still up; everything after can run with the service restored.

- [ ] Check whether GeoIP docs already exist (skip generation if so):
```bash
ES "$ES_URL/logstash-security-$TENANT/_count" -H 'Content-Type: application/json' -d '{"query":{"exists":{"field":"source.geo.country_name"}}}'
ES "$ES_URL/logstash-security-$TENANT/_count" -H 'Content-Type: application/json' -d '{"query":{"exists":{"field":"destination.geo.country_name"}}}'
```
Expected: count > 0 on at least one. If both 0 → generate (next step).
- [ ] (Only if absent) Drive a mesh-client→public flow across bat0 so Zeek logs a conn to a public IP. From the peer AP (user runs, as in A.3):
```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@10.18.81.14 'wget -O /dev/null http://1.1.1.1/ ; ping -c3 8.8.8.8'
```
- [ ] Confirm a public-IP conn indexed with geo, note the UTC window:
```bash
ES "$ES_URL/logstash-security-$TENANT/_search?pretty" -H 'Content-Type: application/json' -d '{"size":1,"query":{"exists":{"field":"destination.geo.location"}},"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","source.ip","destination.ip","destination.geo.country_name"]}'
```
Expected: ≥1 hit with a country name. Record window for the B.2 capture.

---

### Task 2: Restore the SLO-protecting host capture
**Why:** the eth0 service was stopped only for the bat0 evidence window; nothing remaining needs the bat0 stream. Restore persistent capture so ingest-lag SLO stays protected.

- [ ] User runs (real terminal, sudo): `sudo systemctl start zeek-host-capture`
- [ ] Stop the manual bat0 stream (Ctrl+C in its terminal, PID 4871) so only one capture writes the logs.
- [ ] Confirm single capture + service active:
```bash
systemctl is-active zeek-host-capture        # active
docker ps --filter ancestor=zeek/zeek --format '{{.Names}} {{.Status}}'   # exactly one
```
- [ ] Confirm ingest lag healthy (drains): re-run `slo_metrics.py` check in Task 9, expect lag ≤ targets.

---

### Task 3: A.4 — Live intel match
- [ ] Refresh intel then fire the match:
```bash
../../configs/intel/refresh_intel.sh
PEND0=$(curl -s -k $AUTH "$ES_URL/.." >/dev/null; cd /home/tjlam/projects/Suburban-SOC/tests/anomaly_simulation && ./sim_intel_match.sh; echo done)
```
(Note: `sim_intel_match.sh` self-records `/pending` delta; just run it from `tests/anomaly_simulation`.)
- [ ] Verify the ES doc:
```bash
ES "$ES_URL/logstash-security-$TENANT/_search?pretty" -H 'Content-Type: application/json' -d '{"size":1,"query":{"match":{"threat.indicator.ip":"198.51.100.66"}},"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","threat.indicator.ip","tenant.id","event.dataset"]}'
```
Expected: 1 hit, `threat.indicator.ip=198.51.100.66`, tenant `home-smith`.
- [ ] Verify SOAR draft + audit:
```bash
ES "$ES_URL/soar-actions-$TENANT/_search?pretty" -H 'Content-Type: application/json' -d '{"size":1,"sort":[{"@timestamp":"desc"}]}'
```
Expected: an entry tied to 198.51.100.66 (auto if Task 0 LIVE, else from the sim's manual `/alert`).
- [ ] Screenshot Discover (intel doc) + log row #11:
```bash
cd /home/tjlam/projects/Suburban-SOC/evidence/capture
node capture_kibana.mjs --app-path "/app/discover#/?_a=(index:'logstash-security-home-smith',columns:!(threat.indicator.ip,event.dataset),query:(language:kuery,query:'threat.indicator.ip:198.51.100.66'))" --from <W0> --to <W1> --out ../screenshots/a4-intel-match-home-smith.png
sha256sum ../screenshots/a4-intel-match-home-smith.png
```
- [ ] Read the PNG to confirm it shows the doc (not empty); add row to `evidence/README.md`.

---

### Task 4: A.6 — Exclusion holds (protected asset)
- [ ] Fire the protected-asset alert:
```bash
cd /home/tjlam/projects/Suburban-SOC/tests/anomaly_simulation && ./section_a_evidence.sh 2>&1 | tee /tmp/a6_run.log
```
Expected stdout: agent JSON `status: no_action_protected_asset` + a `case_id`.
- [ ] Verify the audit record (no isolation happened):
```bash
ES "$ES_URL/soc-audit-$TENANT/_search?pretty" -H 'Content-Type: application/json' -d '{"size":1,"query":{"query_string":{"query":"alert_excluded_asset OR no_action_protected_asset"}},"sort":[{"@timestamp":"desc"}]}'
```
Expected: 1 record, target `192.168.1.1`, `outcome:no_action`.
- [ ] Screenshot the agent response JSON + the `soc-audit` doc (Discover, `soc-audit-home-smith`); log row #12.

---

### Task 5: A.5 — Quarantine (per Decision 1)
**If honest-negative (default):**
- [ ] Run the read-only check to prove tooling exists without isolating a real device:
```bash
cd /home/tjlam/projects/Suburban-SOC/tests/anomaly_simulation && ./verify_quarantine.sh AA:BB:CC:DD:EE:FF; echo "exit=$?"
```
Expected: exit 1 (rule absent) or 3 (router unreachable) — documents "tooling ready, not executed."
- [ ] Log an honest row #13: "A.5 quarantine — tooling validated read-only; real isolation intentionally not executed on production mesh (see A.2). Broker/agent path covered by A.4/A.6 SOAR evidence."

**If execute-on-test-MAC (only with user confirmation + a disposable device):**
- [ ] Approve a draft for the test MAC via the agent `/approve` (signed), confirm broker dispatch, then `./verify_quarantine.sh <TEST_MAC>` → exit 0; capture nftables rule + broker log + `soar-actions` `response.automated=true`.

---

### Task 6: Section B — dashboards (screenshot each, hash, log)
For each: set `--from/--to` to a window covering the A.* events (+ Task 1 for B.2). After each capture, **Read the PNG** to confirm panels populated before logging the row.
```bash
cd /home/tjlam/projects/Suburban-SOC/evidence/capture
W0=2026-06-28T22:00:00.000Z; W1=2026-06-28T23:00:00.000Z   # widen to cover all A.* + GeoIP
for D in executive-dashboard network-dashboard-v3 dataquality-dashboard soc-navigation-hub intel-feed-health soc-slo soc-hunts soc-control-status; do
  node capture_kibana.mjs --dashboard "$D" --from "$W0" --to "$W1" --out "../screenshots/b-$D.png" ; sha256sum "../screenshots/b-$D.png"; done
```
- [ ] B.1 executive: confirm NIST CSF donut + ATT&CK heatmap + SOAR metrics populate.
- [ ] B.2 network: confirm GeoIP map point + TLS/SNI + top talkers (re-captures rows #1,#4 → mark those VERIFIED/retired).
- [ ] B.3 endpoint `endpoint-dashboard`: capture, then label panels **"awaiting a live endpoint"** — do NOT fabricate.
- [ ] B.4 data quality: confirm Document-Lag ~seconds (UTC).
- [ ] B.5 soc-navigation-hub: cross-links + KPIs reflect real data.
- [ ] B.6 supporting (intel-feed-health, soc-slo, soc-hunts, soc-control-status): real or honestly-empty.
- [ ] Add an `evidence/README.md` row per dashboard; flip rows #1–#4 off PENDING.

---

### Task 7: Section C — pipeline & platform integrity
- [ ] C.1 data streams green + ILM managed:
```bash
ES "$ES_URL/_data_stream/.ds-logstash-security-*?pretty" | grep -iE '"status"|"name"'
ES "$ES_URL/.ds-logstash-security-*/_ilm/explain?pretty" | grep -iE 'managed|policy|phase'
```
Expected: green; `managed:true`, policy `logstash-security-ilm`.
- [ ] C.2 tenant attribution:
```bash
ES "$ES_URL/logstash-security-*/_search?size=0&pretty" -H 'Content-Type: application/json' -d '{"aggs":{"tenants":{"terms":{"field":"tenant.id"}}}}'
```
Expected: `home-smith` bucket (+ any others as designed).
- [ ] C.3 snapshot-before-delete:
```bash
ES "$ES_URL/_slm/policy/suburban-soc-daily-snapshots?pretty" | grep -iE 'name|schedule'
ES -X POST "$ES_URL/_slm/policy/suburban-soc-daily-snapshots/_execute?pretty"
ES "$ES_URL/_snapshot/_status?pretty" | grep -iE 'state|snapshot'
```
- [ ] C.4 audit append-only: attempt update/delete on `soc-audit-$TENANT` as `soc_audit_appender`; expect rejection. Screenshot role def + denied write.
- [ ] C.5 TLS: `cd /home/tjlam/projects/Suburban-SOC/scripts/setup && ./verify_encryption.sh; echo exit=$?` → exit 0.
- [ ] Save each command's output to `evidence/` (or screenshot) and add rows.

---

### Task 8: Section D — SOC metrics (real measured values)
- [ ] Run after Task 2 (so lag reflects restored capture):
```bash
cd /home/tjlam/projects/Suburban-SOC/scripts/setup/ai_agent && python slo_metrics.py 2>&1 | tee /tmp/slo.out
```
- [ ] Record in `evidence/README.md`: MTTD, ATT&CK coverage (fired vs the 24 in `docs/detections/attack-coverage.*`), alert volume, FP rate; MTTR/containment latency + automation rate; ingest throughput, ingest lag (UTC), parse-error %, data-stream health, SLO attainment. **Measured values, not targets.**

---

### Task 9: Section E self-check + DoD + close-out
- [ ] Walk E.1–E.7 (provenance re-hash, no mock residue, timestamp/source cross-checks, end-to-end linkage, reproducibility re-run, GeoIP reality).
- [ ] No-mock-residue:
```bash
ES "$ES_URL/.alerts-security.alerts-mock/_count"; ES "$ES_URL/logstash-dynamic-2026/_count"
ES "$ES_URL/logstash-security-*/_count" -H 'Content-Type: application/json' -d '{"query":{"query_string":{"query":"mock OR fabricat* OR *.encrypted"}}}'
```
Expected: 0 / index_not_found on all.
- [ ] Re-hash every `evidence/screenshots/*.png` row; confirm matches.
- [ ] Update memory if Task 0 changed SOAR-trigger truth.
- [ ] Commit on branch (not main); open/refresh PR referencing #147 with the DoD checklist; request one reviewer approval.

---

## Self-review notes
- Spec coverage: A.4 (T3), A.5 (T5), A.6 (T4), B.1–B.6 (T6), C.1–C.5 (T7), D (T8), E+DoD (T9), prereq SOAR-truth (T0), GeoIP enablement (T1), SLO restore (T2). All runbook sections mapped.
- Open decisions surfaced up front (A.5 mode, A.4 variant).
- `<W0>/<W1>` placeholders in T3 are intentional: fill from the actual sim run window at execution time.
