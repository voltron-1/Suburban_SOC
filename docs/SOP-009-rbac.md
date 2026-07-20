# Executive Summary
This Standard Operating Procedure (SOP) defines the Role-Based Access Control (RBAC) and least privilege model for Suburban-SOC. It specifies human and service account roles, ensuring entities can only perform their explicitly authorized tasks.

## Name
SOP-009 — RBAC & Least Privilege

## Problem Statement
Excessive permissions allow lateral movement or accidental data destruction. Services and analysts must not operate as the `elastic` superuser, and distinct roles must exist for analysts, detection engineers, and administrators.

## Objectives
- Maintain version-controlled, explicit roles for human and service accounts.
- Enforce least privilege for the Logstash writer and AI agent services.
- Ensure the `elastic` superuser is restricted to break-glass scenarios.

## Compliance
- **NIST CSF**: PR.AC-4 (Access permissions managed, incorporating least privilege).
- **SOC 2**: Security (Logical Access).

## MITRE ATT&CK Framework
- Mitigates TA0004 Privilege Escalation (T1078 Valid Accounts) by scoping compromised accounts to the minimum viable privilege.

## Assumptions and Limitations
- The ELK stack security features (xpack.security) are enabled.
- Roles are defined as JSON templates in `configs/elasticsearch/roles/`.

# Analysis
The environment distinguishes between operational roles (`soc_analyst`, `soc_detection_engineer`, `soc_admin`) and service roles (`logstash_writer`, `soc_agent_cases`, `tenant_*_viewer`). The `apply_roles.sh` script idempotently provisions these directly into Elasticsearch.

## Monitoring and Notifications
Privilege escalation attempts or 403 Forbidden errors for service accounts appear in the Elasticsearch audit logs and the `soc-audit-unassigned` index.

## Playbook Verification
To verify the RBAC rules:
1. Run `./tests/rbac/test_rbac.sh` which executes negative tests.
2. Ensure the output confirms that each role can only perform its authorized actions (e.g., `soc_analyst` gets a 403 when attempting to delete an index).

## Recommended Response Action(s)

### Identification
If unauthorized access is suspected or a service encounters permission errors:
- Review the user's role assignments in Kibana (Stack Management > Users).
- Check Elasticsearch audit logs for 403 Forbidden events mapped to the user/service.

### Containment
To contain a compromised or misconfigured account:
- Immediately disable the user in Kibana or reset their password.
- If a service account is compromised, rotate its credentials and restart the affected service.

### Eradication & Recovery
To restore or update RBAC configurations:
1. Edit the role definitions in `configs/elasticsearch/roles/*.json`.
2. Apply the roles to the cluster: `./scripts/setup/apply_roles.sh`.
3. Re-run `./tests/rbac/test_rbac.sh` to validate the negative tests pass.

# References and Resources
- `configs/elasticsearch/roles/`
- `scripts/setup/apply_roles.sh`
- `tests/rbac/test_rbac.sh`
