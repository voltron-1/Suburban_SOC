# #147 — Remaining evidence requirements (recon for the plan)

Recon date: 2026-06-28. Done: A.1 portscan, A.2 ssh-brute (+ manual SOAR draft), A.3 malware download — all on real bat0 telemetry, tenant `home-smith`. Path B live bat0 capture from router `10.18.81.1`; peer-AP mesh client `10.18.81.14` crosses bat0.

Classification key: **BAT0** = needs fresh mesh traffic crossing bat0; **AGENT** = hits soc_ai_agent/broker API, no capture; **ES/KIBANA** = query/screenshot existing data.

## A.4 — Live intel match — INGEST+AGENT (not bat0)
- Cmd: `cd tests/anomaly_simulation && ./sim_intel_match.sh`
- Mechanism: posts a synthetic Zeek intel.log-shaped event to Logstash HTTP input `:5514`; pipeline maps `seen.indicator` → `threat.indicator.ip`. Seeded test IP `198.51.100.66` (in `configs/intel/intel.seed.dat`, refreshed by `configs/intel/refresh_intel.sh`).
- Hardware: none.
- Evidence: ES doc in `logstash-security-home-smith` with `threat.indicator.ip=198.51.100.66`; agent `/pending` grows; `soar-actions-home-smith` entry.
- Gotcha: must use canonical `scripts/setup/.env` creds + TLS (not the old `tests/anomaly_simulation/.env` plain-http).
- Optional stronger variant (BAT0): have a mesh client actually connect to `198.51.100.66` so Zeek flags it organically.

## A.5 — Quarantine executed — AGENT/BROKER + HARDWARE
- Cmd: `./verify_quarantine.sh <TARGET_MAC>`
- `verify_quarantine.sh` is READ-ONLY: SSHes the router (`OPENWRT_HOST`, default `192.168.1.1`; key `$HOME/.ssh/id_ed25519_hivemind`), checks UCI/nftables rule `SOAR_QUARANTINE_<MAC>` exists; exit 0/1/3.
- Actually CREATING the rule needs a human-approved `/approve` → broker dispatch → real isolation (intentionally not done on the production mesh; A.2 row says broker DROP not executed).
- Evidence (if executed): nftables rule on router + broker log (:8000) + `soar-actions-home-smith` `response.automated=true`.
- DECISION: execute against a disposable test MAC (real isolation, needs approval) vs honest-negative "tooling ready, not executed on production mesh."

## A.6 — Exclusion holds — AGENT only
- Cmd: `cd tests/anomaly_simulation && ./section_a_evidence.sh` (fires signed `/alert` at `192.168.1.1`, the governance exclusion).
- HMAC-SHA256 over `"<ts>.<body>"`, headers `x-elastic-timestamp`/`x-elastic-signature`, 300s replay window.
- Evidence: agent JSON `status: no_action_protected_asset` + `case_id`; `/pending` unchanged; `soc-audit-home-smith` `alert_excluded_asset` / `outcome: no_action`.
- Gotcha: exclusion list `governance/exclusion_list.txt`; agent fails CLOSED if unreadable. (See [[exclusion-list-failclosed-wsl-mount]].)

## SOAR auto-trigger — VERIFY (memory says NOT wired; file says wired)
- File: `rules/elastic_watcher/soar_quarantine_alert.json` — interval 1m; triggers on zeek.notice `Scan::Port_Scan`, zeek.ssh 5+ fails, zeek.conn `threat.indicator.domain`; webhook `http://soc_ai_agent:5000/alert`.
- MUST verify it is actually registered + firing in live ES (`_watcher/stats`, watcher history) before relying on it. If real, A.1–A.4 may auto-produce `soar-actions` and memory `soar-trigger-not-wired-network` is stale.

## Section B — dashboards (ES/KIBANA; B.2 may need BAT0 for GeoIP)
Capture: `cd evidence/capture && node capture_kibana.mjs --dashboard <ID> --from <UTC> --to <UTC> --out ../screenshots/<name>.png`
- Executive `executive-dashboard` (NIST CSF donut, ATT&CK heatmap)
- Network `network-dashboard-v3` (TLS/SNI, GeoIP map, top talkers) — GeoIP needs a public-IP flow that resolves `source.geo` (re-captures rows #1,#4): may need ambient bat0→internet traffic in the window.
- Endpoint `endpoint-dashboard` — HONEST "tooling ready / awaiting live endpoint" (do not fabricate).
- Data Quality `dataquality-dashboard` (heartbeats, Document-Lag panel ~seconds)
- SOC Home `soc-navigation-hub`
- Supporting: `intel-feed-health`, `soc-slo`, `soc-hunts`, `soc-control-status`
- Data view for Discover: tenant-scoped `logstash-security-home-smith` (wildcard `logstash-*` also works).

## Section C — pipeline integrity (ES/scripts)
- C.1 `_data_stream/.ds-logstash-security-*` green; `_ilm/explain` managed:true policy `logstash-security-ilm`.
- C.2 tenant agg on `tenant.id`.
- C.3 SLM policy `suburban-soc-daily-snapshots` (`_slm/policy/...`, `_execute`, `_snapshot/_status`).
- C.4 audit role `soc_audit_appender` — show update/delete on `soc-audit-*` rejected.
- C.5 `cd scripts/setup && ./verify_encryption.sh` (ES :9200 TLS-only + CA-verified, Beats :5044 mTLS). See [[filebeat-logstash-mtls-client-cert]].

## Section D — SOC metrics
- Cmd: `cd scripts/setup/ai_agent && python slo_metrics.py` → indexes `soc-slo-metrics`; computes MTTD/MTTR/coverage/FP%/ingest-lag/parse-error%; window default now-7d; creds from `scripts/setup/.env`; TLS fail-closed.

## Cross-cutting
- All ES/agent cmds: load `scripts/setup/.env`, TLS on, tenant-scoped indices (`*-home-smith`).
- Operational: `zeek-host-capture.service` currently STOPPED for the bat0 window; restore with `sudo systemctl start zeek-host-capture` after bat0 evidence is done. See [[zeek-host-capture-service-vs-bat0]].

---
## FINDING (discovered during T1, 2026-06-28): GeoIP enrichment mis-targeted (non-ECS path)
- **Symptom:** `logstash-security-home-smith` has 0 docs with `source.geo.country_name`/`destination.geo.country_name`; B.2 GeoIP map is empty.
- **Actual data path:** `destination.geo.geo.location` / `destination.geo.geo.country_name` (doubled `geo.geo`), plus `destination.geo.ip`.
- **Dashboards expect (ECS):** `destination.geo.location` (5 refs), `destination.geo.country_name.keyword`, `source.geo.country_name.keyword`.
- **Root cause:** `configs/logstash.conf` geoip filters target the child `[X][geo]` (lines 92,95 Beats branch; 192-201 network_logs branch). No `ecs_compatibility` set => LS8 pipeline defaults to ECS v1 => geoip plugin nests `geo`/`as` under the target's PARENT, so `[destination][geo]` -> `[destination][geo][geo]`.
- **Fix:** change all four geoip targets from `[source][geo]`/`[destination][geo]` to `[source]`/`[destination]`. Requires Logstash restart + fresh public-IP traffic to repopulate (old docs keep the wrong path until reindex/rollover).
- **Verified working:** GeoIP DOES resolve (185.125.190.56 -> GB), so the maxmind DB + lookup are fine; only the target path is wrong.

---
## Section C results (T7, 2026-06-28/29)
- **C.1** ILM managed=true, policy `logstash-security-ilm` (phase warm). Data stream present.
- **C.2** tenant agg: `home-smith` 66,748 · `acme-net` 2 · `unassigned` 19,794. Tenancy works; NOTE the 19,794 `unassigned` docs (:5514 http input + unstamped sources default to unassigned) — data-hygiene follow-up.
- **C.3** SLM `suburban-soc-daily-snapshots` (daily 01:30) executed on demand → `suburban-soc-snap-2026.06.29-i9lmc0w...`; prior last_success present. Snapshot-before-delete wired.
- **C.4** audit append-only: control collector C3 PASS (`appender = create-only, tamper-evident`).
- **C.5** verify_encryption.sh: ES :9200 TLS-only PASS, HTTPS cert CA-verified PASS, transport TLS PASS. Beats :5044 handshake check FAIL — probe presents no client cert; the input enforces mTLS and real Filebeat ships successfully (A.1–A.4 indexed), so the live path IS encrypted. Known gotcha [[filebeat-logstash-mtls-client-cert]]. No plaintext path; no verify=False.
- SOC2 controls (collect_control_evidence.sh): C1–C7 all PASS.
