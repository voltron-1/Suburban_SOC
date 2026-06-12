# SOP-012 — Privacy & Data Handling

**Control family:** Privacy / Confidentiality (SOC 2 P1–P8, CC6.5) · **Workstream:** WS3.4 (M10)
**Owner:** SecOps / Data Protection · **Review cadence:** quarterly + on new data source

## Purpose

Suburban-SOC processes customer network + endpoint telemetry that may contain
personal data. This SOP defines the **data-handling lifecycle** — what we collect,
how we minimize it, how long we keep it, and how a tenant exercises **right-to-erasure**
(GDPR Art. 17 / CCPA deletion).

## Principle: collect security signal, not user content

Three controls, applied in order — earliest wins:

| # | Control | Where | What it does |
|---|---------|-------|--------------|
| 1 | **Capture scope** | `configs/zeek/local.zeek` (WS3.4) | Sensor logs connection/protocol **metadata only** — no packet payloads, no file carving, no basic-auth passwords, no cookies/auth headers. Data never captured can never leak. |
| 2 | **Ingest minimization** | `configs/logstash.conf` Category 3.5 (WS3.4) | Defensively drops payload/secret fields (`http.*.body`, `cookie`, `authorization`, URL creds, `user.email/full_name`) and redacts inline secrets (`password=`, `token=`, `api_key=`) in `message` before indexing. |
| 3 | **Retention limit** | ILM (WS0.5) + SLM (WS2.5) | Hot→delete lifecycle bounds how long any captured data lives; snapshots expire (45d). |

### What we deliberately keep

Usernames, source/destination IPs + MACs, DNS queries, TLS SNI, process/command-line,
auth outcomes — these are **security signal** (attribution, C2/exfil, lateral movement)
and are retained. Minimization removes *content and credentials*, not the metadata
detection depends on.

## Right-to-erasure

`scripts/setup/erase_tenant.sh <tenant-slug>` permanently removes **all** data for one
tenant and records a tamper-evident receipt.

```bash
cd ~/projects/Suburban-SOC/scripts/setup
./erase_tenant.sh acme-net --dry-run    # show scope, no changes
./erase_tenant.sh acme-net              # interactive (type slug to confirm)
./erase_tenant.sh acme-net --yes        # runbook / automation
```

It deletes:

- per-tenant data streams `logstash-security-<tenant>`, `soar-actions-<tenant>`
- the tenant audit index `soc-audit-<tenant>`
- tenant docs in shared indices via `delete_by_query` on `tenant.id`
  (`.alerts-security.*`, `asset-inventory-*`, `soar-actions-dynamic-*`)
- access artifacts: tenant role, user, Kibana space

**Evidence:** the erasure is written to the append-only audit trail (WS3.3) as
`event.action=tenant_erasure` (`in_progress` → `completed`) in `soc-audit-unassigned`,
so the deletion itself is provable (who ran it, when, how many docs). The shared
`unassigned` tenant is refused as a target.

**Snapshots:** SLM snapshots are immutable and may still contain the tenant's data
until they expire (≤45d, WS2.5). For a hard legal deadline, also delete the relevant
snapshots from `suburban-soc-snapshots`; otherwise erasure completes on snapshot
expiry. Record this in the erasure ticket.

### Validation (performed WS3.4)

Seeded tenant `erasetest` (data stream + audit index + shared `asset-inventory` doc),
ran `erase_tenant.sh erasetest --yes`:

- `logstash-security-erasetest` → **HTTP 404** (gone); `soc-audit-erasetest` → **404**
- `asset-inventory` docs with `tenant.id=erasetest` → **0** (delete_by_query)
- audit receipts present: `tenant_erasure` `in_progress` + `completed`

Ingest minimization verified live: an event with `password=…/token=…/api_key=…` indexed
as `password=[REDACTED] token=[REDACTED] api_key=[REDACTED]`, with `user=alice` preserved.

## Data inventory (summary)

| Data | Source | Personal data? | Retention | Erasure |
|------|--------|----------------|-----------|---------|
| Connection/DNS/TLS metadata | Zeek | IPs (pseudonymous) | ILM | per-tenant script |
| Endpoint process/auth events | Winlogbeat/Filebeat | usernames | ILM | per-tenant script |
| Detection alerts | Detection Engine | derived | ILM | `delete_by_query` |
| Audit trail | app (WS3.3) | actor identity | SLM (immutable) | retained for compliance |

## DSAR / access requests

A tenant access request is served from that tenant's Kibana Space + data view
(`provision_tenant.sh`); a tenant can only ever see its own slice (WS0.3 isolation,
WS3.2 RBAC). Export via the Space's saved search. Erasure as above.
