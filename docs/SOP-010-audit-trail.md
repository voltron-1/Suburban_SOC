# Executive Summary
This Standard Operating Procedure (SOP) defines the tamper-evident audit trail for Suburban-SOC. It guarantees that every privileged response action and configuration deployment is immutably recorded with actor, action, timestamp, and tenant details.

## Name
SOP-010 — Tamper-Evident Audit Trail

## Problem Statement
Without an immutable audit trail, malicious actors or compromised accounts could silently alter detection rules or quarantine assets, then delete the logs to cover their tracks.

## Objectives
- Record every privileged SOC response action.
- Record every denied request at the broker layer.
- Enforce a write-once (append-only) architecture where no entity can modify or delete audit records.

## Compliance
- **NIST CSF**: PR.PT-1 (Audit/log records), DE.AE-3 (Event data collection).
- **SOC 2**: Security (Logical Access, Audit Logging).

## MITRE ATT&CK Framework
- Mitigates TA0005 Defense Evasion (T1070 Indicator Removal on Host) by ensuring audit logs cannot be modified even if the service account is compromised.

## Assumptions and Limitations
- Elasticsearch basic license does not include native platform-level audit logging.
- The `soc_audit_appender` role is correctly mapped to service accounts.

# Analysis
The audit trail is split into application-level logging (`soc-audit-<tenant>`, `soc-audit-unassigned`) and deployment logging (`soc-deploys`). The security relies entirely on the Elasticsearch RBAC restricting the service accounts to `create` privileges only.

## Monitoring and Notifications
The `soc-audit-*` indices are continuously monitored by the CCM (SOP-013) to ensure append-only permissions remain intact.

## Playbook Verification
To verify the audit trail's integrity:
1. Attempt to UPDATE or DELETE a document in `soc-audit-unassigned` using the `hive_mind_broker` or `soc_agent` credentials.
2. Verify that Elasticsearch returns a `403 Forbidden` response.

## Recommended Response Action(s)

### Identification
To investigate a suspected unauthorized action or broker denial:
- Query `soc-audit-<tenant>` for `event.action` types (`autonomous_isolation`, `alert_excluded_asset`).
- Query `soc-audit-unassigned` for `broker_request_denied`.

### Containment
If audit trail tampering is suspected (e.g., records are missing or a 403 test returns 200 OK):
- Immediately revoke the credentials of the compromised service accounts.
- Restrict cluster access until roles are audited.

### Eradication & Recovery
To restore the integrity of the audit trail:
1. Re-run `./scripts/setup/apply_roles.sh` to enforce the `soc_audit_appender` role.
2. Verify the daily SLM snapshots are intact to recover any maliciously deleted indices, provided the snapshot repository was not also compromised.

# References and Resources
- `configs/elasticsearch/roles/soc_audit_appender.json`
- `configs/elasticsearch/ilm/slm-policy.json`
