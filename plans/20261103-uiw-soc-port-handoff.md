# Agent handoff: port Suburban-SOC components into UIW-SOC — 2026-11-03

**Receiver:** the agent working in the UIW-SOC repo.
**Task:** PORT (copy and adapt) the Suburban-SOC components that unblock UIW-SOC's tasks. The owner decided this on 2026-11-05: port, not reference.
**Why:** the UIW-SOC agent marked tasks as blocked because it found no Sigma pipeline ("Track T1"), no hive-mind-broker prompts, no Phase 1 Enrichment API and no RT-3 investigation output in UIW-SOC. Suburban-SOC, a sibling project by the same owner, has built the first two. Port them into UIW-SOC. The other two exist nowhere, so they cannot be ported.
**Port source:** `https://github.com/voltron-1/Suburban_SOC` (public), pinned at commit `07c151c` on `main`. Clone it next to UIW-SOC and copy from that clone.
**UNVERIFIED:** this handoff was written from the Suburban-SOC side only. The UIW-SOC repo was not reachable from that session, so UIW-SOC's folder layout, index names and router setup are unknown. Where a target path below does not fit UIW-SOC, keep the file but move it to UIW-SOC's equivalent folder.

## 1. What Suburban-SOC has built

### Detection plane

| Component | Where | State |
|---|---|---|
| Packet capture | `configs/systemd/zeek-host-capture.service`, OpenWrt tcpdump over SSH | Built. Live on the capture host 2026-10-24 (sees only the host's own traffic, #593) |
| Zeek | `configs/zeek/local.zeek`, intel feed `configs/intel/` | Built and running (native Zeek 9.0.0) |
| Suricata | `configs/suricata/`, 11 rule files in `rules/suricata/` (80 rules) | Rules + CI built. Live ingest not working: SLO shows no Suricata data (#587) |
| Filebeat → Logstash | `configs/network/`, `configs/endpoint/`, `configs/logstash.conf` | Built. Logstash does grok, GeoIP, ECS mapping, ATT&CK framework tagging, and the HMAC `/alert` trigger |
| Elasticsearch + Kibana | `configs/elasticsearch/`, dashboards in `configs/server/` | Built. TLS + RBAC, per-tenant indices, 4-dashboard set plus hub |
| Sigma detection pipeline | `rules/sigma/` (122 rules), `configs/detections/suburban-soc-ecs.yml`, `tests/detections/` | Built. Every rule has TP/TN fixtures, converts to Lucene in CI, maps to a playbook |
| Threshold rules | `rules/elastic/threshold/` (12 `.ndjson`) | Built, each paired with a Sigma rule |
| Threat hunts | `hunts/` (HUNT-001 to HUNT-005), `scripts/setup/run_hunts.py` | Built |
| Self-monitoring | `slo-metrics`, `stack-health`, `zeek-capture-liveness`, `intel-refresh`, `soc-alert-on-failure@` units | Built. ntfy phone alerts live since 2026-10-24 (copied from the 2026-10-24 handoff, not re-checked) |

### Response plane (SOAR)

| Component | Where | State |
|---|---|---|
| SOC AI agent (Flask, port 5000) | `scripts/setup/ai_agent/agent_app.py`, `agent.py` | Built. Receives HMAC-signed `/alert`, runs LLM triage, drafts containment to an approval queue |
| LLM triage prompt | `scripts/setup/ai_agent/agent.py:974` (`analyze_alert_with_ai`) | Built. One system prompt: 2-sentence summary, ATT&CK tactic, one remediation step. Data is sanitized before sending; hosted LLMs are blocked unless `LLM_ALLOW_HOSTED=true` |
| Approval gate | `/approve`, `/pending`, `checkpoints.py` | Built. Separate HMAC credential, atomic claim so an isolation runs once |
| hive-mind-broker (FastAPI, port 8000) | `scripts/hive-mind-broker/app.py`, `dispatcher.py`, `inventory.py` | Built. Checks HMAC + tenant scope, pushes nftables DROP rules to OpenWrt routers over SSH. **No LLM and no prompts** |
| Playbooks | `playbooks/data/` (122 JSON), `playbooks_blueprint.py` | Built, read-only HTML |
| Reporting | `slo_metrics.py`, `weekly_ciso_report.py` | Built |

## 2. The 4 items UIW-SOC reported as missing

| Item | Port it? | Detail |
|---|---|---|
| Sigma pipeline ("Track T1") | **Yes: Phase 1** | Fully built in Suburban-SOC |
| hive-mind-broker's real prompts | **Yes: Phases 2 and 3** | Port the broker (Phase 2) and the SOC agent, which holds the real LLM prompt (Phase 3). The broker itself has no prompts |
| Phase 1 Enrichment API | **No: does not exist** | Suburban-SOC enriches inside `configs/logstash.conf` only. No HTTP service to port. Tasks needing it stay blocked until it is designed |
| RT-3 investigation output | **No: does not exist** | "RT-3" appears nowhere in Suburban-SOC. Tasks needing it stay blocked |

## 3. Port plan (do the phases in order; one PR per phase)

### Phase 1: Sigma pipeline (about 45 minutes)

1. Copy these from the Suburban-SOC clone to the same paths in UIW-SOC:
   - `rules/sigma/` (122 rules)
   - `rules/elastic/threshold/` (12 `.ndjson`)
   - `configs/detections/suburban-soc-ecs.yml` → save as `configs/detections/uiw-soc-ecs.yml`
   - `configs/elasticsearch/logstash-security-template.json` (the Sigma test reads it)
   - `tests/detections/sigma_eval.py`, `fixtures.json`, `test_sigma_detections.py`, `test_threshold_rules.py`, `test_rule_description_hygiene.py`
   - `scripts/setup/deploy_detections.sh`
   - The Sigma jobs from `.github/workflows/detections.yml`
2. Rename: `author: Suburban-SOC` → `author: UIW-SOC` in 89 rules; `suburban-soc-ecs.yml` → `uiw-soc-ecs.yml` everywhere it is referenced (`grep -rn suburban` finds every hit).
3. Pin the toolchain exactly: `sigma-cli==3.1.0 pysigma==1.5.0 pysigma-backend-elasticsearch==2.1.1 pyparsing==3.3.2` (pyparsing 3.3.3 breaks pysigma).
4. Check UIW-SOC's field mapping: the rules expect ECS fields, `process.args` (never `process.command_line`), and index `logstash-*`. If UIW-SOC uses other names, change the ECS pipeline file, not the rules.
5. Leave out for now: `test_playbook_coverage.py` and the emulation-map tests. They need Suburban-SOC docs that are not part of this port.

**Done when:** `python -m pytest tests/detections/test_sigma_detections.py tests/detections/test_threshold_rules.py -q` passes in UIW-SOC, and `sigma convert -t lucene -f siem_rule_ndjson -p configs/detections/uiw-soc-ecs.yml rules/sigma/net_zeek_port_scan.yml` prints a query.

### Phase 2: hive-mind-broker (about 30 minutes)

1. Copy all of `scripts/hive-mind-broker/` (app, dispatcher, inventory, compaction script, Dockerfile, requirements, `inventory.example.yaml`, 4 test files). It has no Suburban-SOC branding.
2. Copy the broker jobs from `.github/workflows/soar-tests.yml`.
3. Rewire for UIW-SOC:
   - Write a real `inventory.yaml` (gitignored) listing UIW-SOC's routers, each with its own `tenant` slug.
   - Generate a NEW broker HMAC secret for UIW-SOC's `.env`. Do not reuse Suburban-SOC's.

**Done when:** `cd scripts/hive-mind-broker && cp inventory.example.yaml inventory.yaml && python -m pytest test_app.py test_inventory.py test_dispatcher.py -q` passes.

### Phase 3: SOC agent with the LLM prompt (about 60 minutes)

1. Copy:
   - all of `scripts/setup/ai_agent/` (includes `agent.py` with the prompt, `checkpoints.py`, `retry.py`, `templates/`)
   - `scripts/setup/lib/` (`env_loader.py`, `es_client.py`; the reporting code imports them)
   - `playbooks/data/` (the playbook viewer reads it)
   - `tests/ai_agent/`
2. Rename the 9 files in `scripts/setup/ai_agent/` that mention Suburban-SOC (`grep -rli suburban scripts/setup/ai_agent`).
3. Rewire for UIW-SOC's `.env`:
   - New, separate HMAC secrets for `/alert` and for `/approve` + `/pending`
   - Broker URL
   - `LLM_API_URL` and `LLM_MODEL`: the default is `gpt-4`; the code expects a local Ollama model unless `LLM_ALLOW_HOSTED=true`
4. Keep these security rules exactly as they are:
   - human approval by default (`AUTONOMOUS_ISOLATION` stays unset)
   - exclusion list checked first
   - atomic claim in `checkpoints.py`
   - 401 on any unsigned request
   - every action scoped to the alerting tenant

**Done when:** `python -m pytest tests/ai_agent/test_alert_auth.py tests/ai_agent/test_checkpoints_claim.py tests/ai_agent/test_agent.py -q` passes in UIW-SOC.

### After all 3 phases

- Re-check each blocked UIW-SOC task. Tasks that needed the Sigma pipeline or the prompts are unblocked.
- Tasks that need the Enrichment API or RT-3 output stay blocked. Record them as "needs design" in UIW-SOC's tracker.
