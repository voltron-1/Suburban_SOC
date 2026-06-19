# SOP-147: Evidence Validation Runbook (Audit P0-4 remediation)

> **Tracks:** [Issue #147](https://github.com/sterlinggarnett/Suburban_SOC/issues/147) — "Evidence real telemetry: replace mock-data evidence (audit P0-4) and validate all dashboards/detections end-to-end."
>
> **Goal:** produce reviewer-checkable evidence that every dashboard panel and detection works on **real, attributable telemetry**, and purge all mock data. Every screenshot must be logged in **both** `evidence/README.md` and the GitHub Wiki with: one-line description, **SHA-256**, **UTC capture window**, **source IP(s)/host(s)**, and **source index/data stream**.

This runbook expands each section of the issue into ordered, copy-pasteable steps. It builds on `docs/SOP-022-anomaly-validation.md` (the simulation harness). Work top-to-bottom: **Prerequisites → A → B → C → Reviewer self-check → Definition of Done.**

---

## Conventions used below

```bash
# Run all ES/Kibana commands with the stack creds (auto-loaded from the setup .env).
cd scripts/setup && set -a && source .env && set +a
ES_URL="${ES_URL:-https://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
AUTH="-u ${ES_USER:-elastic}:${ES_PASS:-$ELASTIC_PASSWORD}"
# TLS is on; use -k for the self-signed dev CA (or point --cacert at the CA).
ES() { curl -s -k $AUTH "$@"; }
```

**Record the run window once, up front, and reuse it everywhere:**

```bash
WINDOW_START="$(date -u +%FT%TZ)"   # capture BEFORE you start generating telemetry
# ... run sims / capture ...
WINDOW_END="$(date -u +%FT%TZ)"     # capture AFTER
echo "UTC window: $WINDOW_START → $WINDOW_END"
```

**Hash + log every screenshot the same way:**

```bash
sha256sum evidence/screenshots/<name>.png        # Linux/WSL
# Get-FileHash evidence\screenshots\<name>.png -Algorithm SHA256   # PowerShell
```
Then add a row to `evidence/README.md` **and** the Wiki: `desc | SHA-256 | UTC window | source IP/host | index/data stream`.

---

## Section 0 — Prerequisites (do first)

### Step 0.1 — Purge mock data
Delete every fabricated index/doc so no panel can read it, then confirm the count is 0 or the index is gone.

```bash
# Remove the known fabricated indices
ES -X DELETE "$ES_URL/.alerts-security.alerts-mock"
ES -X DELETE "$ES_URL/logstash-dynamic-2026"

# Delete any hand-injected docs from the real alerts stream (mock markers / fake .encrypted / NK-CN-RU strings)
ES -X POST "$ES_URL/.internal.alerts-security.alerts-default-*/_delete_by_query" \
  -H 'Content-Type: application/json' -d '{
    "query": { "query_string": { "query": "mock OR fabricat* OR *.encrypted OR \"North Korea\"" } }
  }'

# Verify nothing remains
ES "$ES_URL/.alerts-security.alerts-mock/_count"          # expect 404 / index_not_found
ES "$ES_URL/logstash-dynamic-2026/_count"                 # expect 404 / index_not_found
```
✅ **Done when:** both `_count` calls return 0 or `index_not_found_exception`.

### Step 0.2 — Quarantine the suspect evidence (don't delete yet)
In `evidence/README.md`, mark every existing `screenshots/*.png` row **"PENDING RE-CAPTURE"**. The header disclaimer is already present — keep each unverified row flagged until it is re-captured in Sections A/B.

### Step 0.3 — Stack up & healthy
```bash
cd scripts/setup && docker compose up -d
./stack_health.sh                                  # ES, Kibana, Logstash, agent, broker all UP
ES "$ES_URL/_cluster/health?pretty"                # status: green/yellow, no unassigned primaries
```
✅ **Done when:** `stack_health.sh` shows nothing DOWN and Kibana answers on `:5601`.

### Step 0.4 — Confirm the emulation→detection wiring (static precondition)
```bash
python tests/validate_emulation_map.py             # expect 22/22 green
```
This proves every sim, log-source config, and Sigma rule in `configs/detections/emulation_telemetry.map` exists and ATT&CK tags match — **before** you spend a capture window.
✅ **Done when:** 22/22 pass.

### Step 0.5 — Generate real telemetry (pick Path A or Path B)

**Path A — Simulation harness (default, no special hardware):**
```bash
cd tests/anomaly_simulation
cp -n .env.example .env && $EDITOR .env            # set TARGET_HOST, ES creds, agent URL
./preflight.sh                                     # every prereq must PASS
# refresh real intel (shipped feed is TEST placeholders) OR use seeded 198.51.100.66
../../configs/intel/refresh_intel.sh
WINDOW_START="$(date -u +%FT%TZ)"
./run_all.sh                                       # portscan + ssh brute + EICAR, then verify_detections.py
./sim_intel_match.sh                               # live intel → ingest-time alert → agent draft
WINDOW_END="$(date -u +%FT%TZ)"
```

**Path B — Real boundary capture (if an OpenWrt mesh / capture NIC is available):**
```bash
cd scripts/setup
WINDOW_START="$(date -u +%FT%TZ)"
./stream_bat0_data.sh        # or stream_br_lan_data.sh / stream_raw_data.sh — note the interface
# let it run a defined window, then drive a few Path-A sims against the live network
WINDOW_END="$(date -u +%FT%TZ)"
```
✅ **Done when:** you have recorded `WINDOW_START`, `WINDOW_END`, the **source IP(s)/host(s)**, and (Path B) the **capture interface**.

---

## Section A — Detection → SOAR loop (one screenshot set per technique)

For each item: generate the event → confirm the raw Zeek doc indexed → confirm the SOAR action → screenshot the Kibana Case + the append-only audit record. Log all in `evidence/README.md` + Wiki.

### Step A.1 — Port scan (T1046)
```bash
cd tests/anomaly_simulation && ./sim_portscan.sh
```
Evidence to capture:
1. The `zeek.notice` `Scan::Port_Scan` doc — `ES "$ES_URL/logstash-security-*/_search?q=note:Scan::Port_Scan"`.
2. The Watcher `/alert` firing → draft in the agent `/pending`.
3. After approve → broker nftables **DROP** action in `soar-actions-*`.
4. The Kibana **Case** and the append-only `soc-audit-*` record (same source IP + window).

### Step A.2 — SSH brute force (T1110)
```bash
./sim_brute_ssh.sh
```
Evidence: ≥5 `zeek.ssh` sessions from one source → SOAR draft → Case → `soc-audit-*`. (Note: per `verify_detections.py`, the check is the **cadence** of 5+ sessions, not Zeek's per-conn auth inference.)

### Step A.3 — Malware download (T1105-ish, EICAR)
```bash
./sim_malware_download.sh
```
Evidence: the `zeek.files` doc with `application/zip` MIME indexed. Screenshot the file doc.

### Step A.4 — Live intel match
```bash
./sim_intel_match.sh          # uses refreshed feed OR seeded 198.51.100.66
```
Evidence: ES doc with `threat.indicator.ip` set → ingest-time `/alert` → agent `/pending` count grew → `soar-actions-*` entry.

### Step A.5 — Quarantine executed
```bash
./verify_quarantine.sh <TARGET_MAC>      # needs the MAC arg + a test router
```
Evidence: the nftables rule present on the router + the broker log + `soar-actions-*` with `response.automated=true`.

### Step A.6 — Exclusion holds (governance protected asset)
Fire an alert targeting `192.168.1.1` (the governance exclusion) and confirm the agent returns `no_action_protected_asset` and the asset is **never** isolated.
Evidence: the agent response JSON + the matching `soc-audit-*` record.

✅ **Section A done when:** each of A.1–A.6 has a screenshot row (or an honest negative result) with the full provenance set.

---

## Section B — Dashboards (the 5-dashboard ecosystem + supporting)

Open each dashboard in Kibana, set the time picker to **your recorded UTC window**, screenshot, hash, log.

### Step B.1 — Executive / Bird's-Eye (`executive-dashboard`)
Confirm KPIs, the **NIST CSF donut**, the **MITRE ATT&CK heatmap** (techniques driven by the real detections from Section A), and SOAR response metrics all populate.

### Step B.2 — Network & Traffic (`network-dashboard-v3`)
Traffic volume, top talkers, DNS/HTTP, **TLS/SNI**, and the **GeoIP map** populated from a real public source IP — confirm `source.geo.country_name` and lat/lon are present (re-captures evidence rows #1 and #4).

### Step B.3 — Endpoint & Host (`endpoint-dashboard`) — **evidence as "tooling ready" (decision #2)**
Do **not** fabricate endpoint data. Instead prove the path exists:
- `configs/endpoint/winlogbeat.yml` + `filebeat_endpoint.yml` ship TLS to `:5044`.
- The pipeline maps endpoint fields; the 19 endpoint Sigma rules convert/deploy.
- The 19 Windows emulation scripts (`tests/anomaly_simulation/sim_win_*.ps1`) exist to drive them once an endpoint attaches.

Mark live process-anomaly / auth / Sigma-hit panels **"awaiting a live endpoint."**

### Step B.4 — Data Quality & Ingestion (`dataquality-dashboard`)
Agent heartbeats, ingest throughput, parse-error tracking, and the **Document-Lag panel** — confirm lag is ~seconds (UTC `event.created`), not a timezone-sized offset.

### Step B.5 — SOC Home / Navigation Hub (`soc-navigation-hub`)
Cross-links resolve; at-a-glance KPIs reflect the real data from B.1–B.4.

### Step B.6 — Supporting dashboards
Intel Feed Health, SLO, Hunts, Control Status / Asset Inventory — each shows real (or honestly empty) data.

✅ **Section B done when:** every dashboard above has a re-captured screenshot row; endpoint panels are honestly labeled, not faked.

---

## Section C — Pipeline & platform integrity

### Step C.1 — Data streams green + ILM-managed
```bash
ES "$ES_URL/_data_stream/.ds-logstash-security-*?pretty"           # health: green
ES "$ES_URL/.ds-logstash-security-*/_ilm/explain?pretty"           # managed:true, policy:logstash-security-ilm
```

### Step C.2 — Tenant attribution
Confirm events carry the right `tenant.id` and per-tenant indices / Kibana spaces isolate as designed.
```bash
ES "$ES_URL/logstash-security-*/_search?size=0" -H 'Content-Type: application/json' \
  -d '{"aggs":{"tenants":{"terms":{"field":"tenant.id"}}}}'
```

### Step C.3 — Snapshot-before-delete wired
```bash
ES "$ES_URL/_slm/policy/suburban-soc-daily-snapshots?pretty"
ES -X POST "$ES_URL/_slm/policy/suburban-soc-daily-snapshots/_execute"   # take one
ES "$ES_URL/_snapshot/_status?pretty"                                    # verify it
```

### Step C.4 — Audit trail append-only
Confirm the agent's `soc_audit_appender` role cannot update/delete `soc-audit-*` (an update/delete attempt should be rejected). Screenshot the role definition + a denied write.

### Step C.5 — TLS end-to-end
```bash
cd scripts/setup && ./verify_encryption.sh        # beats→Logstash :5044 and Logstash→ES CA-verified
```
Confirm no plaintext path and no `verify=False` anywhere in the live config.

✅ **Section C done when:** C.1–C.5 each have a passing command output / screenshot logged.

---

## Section D — Industry SOC metrics (Definition of Done)

Capture **real measured values** from the evidenced window (not targets) and log them in `evidence/README.md`.

```bash
cd scripts/setup/ai_agent && python slo_metrics.py        # MTTD/MTTR/SLO from soar-actions-* + data-quality
```
Record:
- **Detection:** MTTD, ATT&CK technique coverage (techniques actually fired vs the **24** in `docs/detections/attack-coverage.md`; the 22 emulation→detection pairs span 21 of them), alert volume, false-positive rate.
- **Response:** MTTR / containment latency (`soar-actions-*` `response.latency_seconds`), automation rate (autonomous vs human-approved).
- **Operational:** ingest throughput, ingest lag (UTC Document-Lag), parse-error %, data-stream health, SLO attainment vs configured targets.

---

## Section E — Reviewer self-check (run before requesting approval)

Walk the issue's 7 reviewer checks yourself first:

1. **Provenance** — every `evidence/README.md` row has SHA-256 + UTC window + source IP/host + index. Re-hash each PNG; confirm it matches.
2. **No mock residue:**
   ```bash
   ES "$ES_URL/.alerts-security.alerts-mock/_count"     # 0 / absent
   ES "$ES_URL/logstash-dynamic-2026/_count"            # 0 / absent
   ES "$ES_URL/logstash-security-*/_count" -H 'Content-Type: application/json' \
     -d '{"query":{"query_string":{"query":"mock OR fabricat* OR *.encrypted"}}}'   # 0
   ```
3. **Timestamp cross-check** — docs behind each panel fall inside the recorded window; `event.created` is UTC and within seconds of `@timestamp`.
4. **Source cross-check** — IPs/MACs/hosts match the simulator (`tests/anomaly_simulation/.env` `TARGET_HOST`, EICAR/nmap source) or the real capture NIC — not "Russia/China/NK" fabrications.
5. **End-to-end linkage** — raw Zeek event → detection → `soar-actions-*` (with `response.latency_seconds`) → Kibana Case → `soc-audit-*`, all sharing source + window.
6. **Reproducibility** — re-run `run_all.sh` (Path A) or restart capture (Path B) + `verify_detections.py` against a fresh window → passing.
7. **GeoIP reality** — the map point resolves from a genuine public IP (e.g. `8.8.8.8`) with `source.geo.location` present.

---

## Definition of Done (final checklist)

- [ ] All mock indices/docs purged; no panel reads fabricated data (Step 0.1 / E.2).
- [ ] Every A/B/C checklist item has a re-captured screenshot + complete row in **both** `evidence/README.md` and the Wiki.
- [ ] Industry SOC metrics (Section D) recorded as real measured values.
- [ ] `run_all.sh` (Path A) or live run (Path B) + `verify_detections.py` pass against the evidenced window.
- [ ] Old/suspect screenshots replaced or clearly retired; `docs/AI_conversation_transcript.md` keeps its "mock data, not validation evidence" disclaimer.
- [ ] One reviewer approval on issue #147.
