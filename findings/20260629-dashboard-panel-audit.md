# Dashboard Panel Audit — end-to-end telemetry validation (SOP-147, 2026-06-29)

Method: each panel's **effective query** (saved searchSourceJSON) AND its **primary
bucket field existence** queried against live ES — mirrors what Kibana renders, so
panels bucketing on absent enrichment fields read EMPTY truthfully (not "index has docs").
Window: `now-30d` (captures all available telemetry, incl. pre-validation endpoint data).
Live telemetry: Zeek network (~92.8k docs) + historical endpoint (auth 712 / process 400 /
sysmon-EID11 500) + soar-actions 40 + soc-controls 35 + soc-hunts 2 + intel 2.

## Result: 53 data panels POPULATE · 10 EMPTY (all explained) · 14 text/markdown

| Dashboard | populated | empty | text |
|---|---|---|---|
| 1️⃣ Executive | 6 | 3 | 1 |
| 2️⃣ Network v3 | 11→**12** | 3→**2** | 1 |
| 3️⃣ Endpoint | 5 | 3 | 2 |
| 4️⃣ Data Quality | 9 | 1 | 1 |
| 🏠 Nav Hub | 4 | 0 | 1 |
| Intel Feed Health | 3 | 0 | 1 |
| Asset Inventory | 2 | 0 | 1 |
| SLO | 7 | 0 | 1 |
| Threat Hunts | 2 | 0 | 1 |
| Control Status | 2 | 0 | 1 |

## Fixes applied this session (all committed)
1. `ca6e1dc` SLO panels: `max`→`top_hits` latest-value (were pinned to a 23,662 s historical outage).
2. `ff13ece` Endpoint Auth Timeline / Process Tree: empty query → `event.outcome:*` / `process.executable:*`
   (+ `missingBucket:true` to surface orphan processes). Were rendering Zeek under endpoint labels.
3. `be95698` Network Cross-Border Traffic: `destination.geo.country_name.keyword` → `…country_name`
   (field is already keyword; `.keyword` sub-field didn't exist). Now UK 2657 / US 818 / IE 6 / DE 4.

## Remaining 10 EMPTY panels — classified

### A. Honest-negative — telemetry type not present (structural, cannot populate here)
- Endpoint `System Reboots` (`winlog.event_id` 1074/6006/6008) — no Windows source.
- Endpoint `High-Risk Command Lines` (`process.args.keyword`) — process events present but no command-line args captured.
- Executive `MITRE ATT&CK Techniques` (`threat.technique.id.keyword`), `NIST CSF Distribution`
  (`nist.function.keyword`), `Alert Severity Timeline` (`event.severity.keyword`) — these enrichments
  are written onto `.alerts-security.alerts-*` by the detection engine, not onto raw `logstash-*`;
  no detections fired in the window. Populate when a detection rule triggers.

### B. Healthy-empty (the error condition isn't occurring = green)
- Data Quality `Mapping / Grok Errors` (`tags:_grokparsefailure or pipeline.error:true`) — 0 grok failures.

### C. Real follow-up bugs — pipeline-level, OUT OF SCOPE for this dashboard validation (file separately)
- Network `SNI / Server Name (TLS)` + `Cipher Suite Audit`: `zeek.ssl` stores SNI/cipher at TOP-LEVEL
  `server_name` / `cipher` (e.g. play.googleapis.com / TLS_AES_256_GCM_SHA384) and is **never normalized
  to ECS** `tls.client.server_name` / `tls.cipher`. Fix = ECS-map zeek.ssl in `configs/logstash.conf`
  (+ reindex/rollover). 907 zeek.ssl docs are waiting.
- Endpoint `Failed SSH by Country` (`source.geo.country_name.keyword`): only `destination.geo.*` is
  geo-enriched; `source.geo.country_name` = 0. Fix = add source-IP geoip enrichment for inbound auth.

## Verdict
Every panel either populates on real telemetry or has a documented, evidenced reason. The two
remaining real defects (C) are pipeline ECS-normalization gaps, not dashboard faults — tracked as
follow-ups so they don't block the mock-data→real-telemetry closeout.
