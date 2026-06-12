# Suricata Evaluation — Signature Coverage Alongside Zeek (WS1.4)

**Status:** Evaluated · **Decision:** Adopt as a follow-up (not in M8) · **Owner:** Detection Engineering

## Question
Should Suburban-SOC run **Suricata** alongside **Zeek** on the boundary tap to add
signature-based detection?

## Why they are complementary (not redundant)
| | Zeek (have) | Suricata (proposed) |
|---|---|---|
| Model | Protocol analysis & behavioral logging | Signature/IDS matching (rule sets) |
| Strength | Rich connection/file/SSL/DNS metadata; passive asset inventory (WS1.4); custom scripting | Known-threat coverage via maintained rules (ET Open / ET Pro), payload inspection, file hashing |
| Output | `conn/dns/ssl/http/intel/known_*` logs | `eve.json` (alerts, flows, protocol records) |
| Gap it leaves | No out-of-the-box "known-bad signature" coverage | No behavioral/asset modeling |

Zeek already gives us behavioral telemetry, ECS enrichment, the Intel-framework match
path (WS1.3 → SOAR), and the passive asset inventory (WS1.4). What it does **not**
give is curated signature coverage of known exploits/malware C2 — which is exactly
Suricata + Emerging Threats rules.

## Recommended integration path (when adopted)
- Run Suricata in **IDS/EVE mode** on the same SPAN/tap interface as Zeek (or read the
  same PCAP in the offline pipeline) — no extra capture infrastructure.
- Ship `eve.json` with the existing **Filebeat → Logstash :5044** path, tagged
  `network_logs`; it already parses JSON. Add a Logstash branch mapping
  `alert.signature`, `alert.category`, `alert.signature_id`, and the ET ATT&CK
  metadata to ECS `rule.*` / `threat.technique.*`, and tenant-stamp like every other
  source (WS0.3).
- Feed high-confidence Suricata alerts into the same SOAR trigger model as the Intel
  matches (WS1.1), and surface them in Security → Alerts.
- Manage ET rules as code (versioned, `suricata-update`), mirroring the
  detection-as-code posture established for Sigma in WS1.2.

## Why it is a follow-up, not part of M8
- M8's detection-plane goal is met by Zeek + the **Sigma → Elastic Detection Engine**
  pipeline (WS1.2) + live intel (WS1.3); Suricata is additive breadth, best sequenced
  after the detection-engineering **CI/CD lifecycle (WS2.1)** exists so its rules are
  tested and promoted like the Sigma rules — not dumped in raw.
- Resource cost (CPU for deep packet inspection) and rule tuning (false-positive
  triage) warrant the operational maturity that Phase 2 brings.

## Decision
**Adopt Suricata in a later workstream** (post-WS2.1), via EVE JSON over the existing
Filebeat→Logstash path with rules managed as code. Tracked as a backlog item; not
required to close M8.
