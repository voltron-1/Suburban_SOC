# Agent handoff to UIW-SOC: what Suburban-SOC has built — 2026-11-03

**Receiver:** the agent working in UIW-SOC.
**Purpose:** the UIW-SOC agent marked tasks as blocked because it found no Sigma pipeline ("Track T1"), no hive-mind-broker prompts, no Phase 1 Enrichment API and no RT-3 investigation output in the UIW-SOC codebase. Suburban-SOC, a sibling project by the same owner, already has some of these. This handoff tells the UIW-SOC agent which ones exist, where they are, and which ones are still missing everywhere, so it can unblock the tasks that have a real source.
**Source:** repo files on branch `claude/wonderful-allen-d4qlzz` (same content as `main` at `07c151c`), `README.md` Project Status, `plans/20261024-session-handoff.md`.
**Not re-checked live in this session:** the live capture-host state below is copied from the 2026-10-24 handoff. Treat it as **UNVERIFIED** for today.

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
| Self-monitoring | `slo-metrics`, `stack-health`, `zeek-capture-liveness`, `intel-refresh`, `soc-alert-on-failure@` units | Built. ntfy phone alerts live since 2026-10-24 |

### Response plane (SOAR)

| Component | Where | State |
|---|---|---|
| SOC AI agent (Flask, port 5000) | `scripts/setup/ai_agent/agent_app.py`, `agent.py` | Built. Receives HMAC-signed `/alert`, runs LLM triage, drafts containment to an approval queue |
| LLM triage prompt | `scripts/setup/ai_agent/agent.py:974` (`analyze_alert_with_ai`) | Built. One system prompt: 2-sentence summary, ATT&CK tactic, one remediation step. Data is sanitized before sending; hosted LLMs are blocked unless `LLM_ALLOW_HOSTED=true` |
| Approval gate | `/approve`, `/pending`, `checkpoints.py` | Built. Separate HMAC credential, atomic claim so an isolation runs once |
| hive-mind-broker (FastAPI, port 8000) | `scripts/hive-mind-broker/app.py`, `dispatcher.py`, `inventory.py` | Built. Checks HMAC + tenant scope, pushes nftables DROP rules to OpenWrt routers over SSH. **No LLM and no prompts** |
| Playbooks | `playbooks/data/` (122 JSON), `playbooks_blueprint.py` | Built, read-only HTML |
| Reporting | `slo_metrics.py`, `weekly_ciso_report.py` | Built |

## 2. The 4 items the UIW-SOC agent reported as missing

| Item | Built in Suburban-SOC? | Detail |
|---|---|---|
| Sigma pipeline ("Track T1") | **Yes** | See section 1. Nothing in the repo is labeled "Track T1" |
| hive-mind-broker's real prompts | **Broker yes, prompts no** | The broker only dispatches block rules. The real LLM prompt is in the SOC agent, `scripts/setup/ai_agent/agent.py:974` |
| Phase 1 Enrichment API | **No** | Enrichment exists only inside `configs/logstash.conf` (GeoIP, ECS, ATT&CK tags). No HTTP enrichment service exists |
| RT-3 investigation output | **No** | "RT-3" does not appear anywhere in the repo |

## 3. Next action for the UIW-SOC agent

1. Re-check each blocked UIW-SOC task. Any task that needs a Sigma pipeline is no longer blocked: use `rules/sigma/` and `configs/detections/suburban-soc-ecs.yml`.
2. Any task that needs "real prompts": use `scripts/setup/ai_agent/agent.py:974` from Suburban-SOC. The broker has none.
3. Tasks that need the Enrichment API or RT-3 output stay blocked: neither exists in UIW-SOC or Suburban-SOC. They need a design before any code.
4. Before copying any Suburban-SOC file into UIW-SOC, ask the owner. Copying needs renames (tenant IDs, branding) and rewiring (Elasticsearch indices, router inventory, HMAC secrets).
