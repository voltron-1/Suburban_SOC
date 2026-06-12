# SOP-010 — Tamper-Evident Audit Trail (WS3.3)

**Status:** Active · **Milestone:** M10 · **Workstream:** WS3.3 · **SOC 2:** Security

## What is audited
Every privileged **response** action the SOC takes is recorded with **who / what /
when / tenant** to the append-only `soc-audit-<tenant>` index:
`alert_excluded_asset`, `autonomous_isolation`, `response_drafted`,
`response_approved` (each with `actor`, `event.action`, `event.outcome`, `target`,
`tenant.id`, `@timestamp`). Config/rule **deploys** are recorded separately by
WS3.5 (`soc-deploys` + git history).

## Tamper-evidence (write-once)
The agent's ES account holds the **append-only `soc_audit_appender` role**
(`create` privilege only — no `write`/`update`/`delete`/`manage`). It can ADD audit
records but **cannot modify or delete** them. Verified: an UPDATE, a doc DELETE, and
an index DELETE by the appender all return **403**. The audit indices are also
captured in the daily SLM snapshot (`configs/elasticsearch/ilm/slm-policy.json`),
giving an immutable off-cluster copy for the retention window.

## Native ES/Kibana audit logging (production add-on)
Elasticsearch security **audit logging** (`xpack.security.audit.enabled=true`) records
authentication/authorization events at the platform level, but it is a **Platinum/
Enterprise** feature — not available on the basic license this MVP runs. On a licensed
deployment, enable it in `docker-compose.yml` ES env and ship the audit log to the same
immutable store. The application-level audit above covers the response/quarantine
actions regardless of license.

## Acceptance (#104)
- [x] Every privileged action queryable with who/what/when/tenant (`soc-audit-*`)
- [x] Append-only / write-once store (create-only role; UPDATE/DELETE → 403)
- [x] Retained immutably (daily SLM snapshot includes `soc-audit-*`)
