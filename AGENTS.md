# AGENTS.md

Agent-neutral entry point for this repository. The full guide (commands, architecture, detection-as-code gates, security invariants, workflow and environment constraints) is **`CLAUDE.md`**. Read it in full before changing anything; this file does not repeat it so the two cannot drift.

## Project in one paragraph

Suburban-SOC is a mesh-network security monitoring pipeline: an OpenWrt router captures boundary traffic, Zeek and Suricata parse it, Filebeat and Logstash enrich and route it into Elasticsearch, Kibana visualizes it. A Flask SOC AI agent triages HMAC-signed alerts from Logstash's ingest-time trigger, maps them to MITRE ATT&CK and drafts containment to a human-approval queue; a FastAPI hive-mind broker dispatches approved, HMAC-signed block requests to the OpenWrt routers. Everything is multi-tenant (`tenant.id` on every event; per-tenant indices, roles and routing).

## Scope limits

These are design decisions, not bugs. Detection rules cite this section when they disclose a limitation.

- HTTPS payload inspection is out of scope without a decryption proxy. Rules see where a TLS connection went (the cleartext SNI) and how much moved, not what was sent.
- Elasticsearch runs single-node, so there is no replica fault tolerance.

## Further reading

`docs/` (SOPs), `docs/compliance_matrix.md`, the GitHub Wiki, and the milestone table in `README.md` for current project status.
