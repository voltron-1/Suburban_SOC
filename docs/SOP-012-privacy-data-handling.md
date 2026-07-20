# Executive Summary
This Standard Operating Procedure (SOP) defines the data-handling lifecycle for Suburban-SOC, covering what personal data is collected, how it is minimized, and how to execute right-to-erasure (GDPR/CCPA) requests.

## Name
SOP-012 — Privacy & Data Handling

## Problem Statement
The SOC processes network and endpoint telemetry that may contain personal data (IPs, usernames). Over-collection or failure to delete this data on request violates privacy regulations.

## Objectives
- Minimize data at the point of capture (metadata only, no payloads).
- Redact inline secrets and drop PII during Logstash ingest.
- Provide a reliable, tamper-evident mechanism to permanently erase a tenant's data.

## Compliance
- **NIST CSF**: PR.DS-5 (Data minimization).
- **SOC 2**: Privacy (P1–P8, CC6.5).
- **GDPR / CCPA**: Right to Erasure.

## MITRE ATT&CK Framework
- (N/A for Privacy, but minimizing payload capture reduces the blast radius of TA0009 Collection).

## Assumptions and Limitations
- The Zeek configuration is set to capture metadata only.
- Immutable SLM snapshots will naturally age out erased data within 45 days.

# Analysis
Data minimization is enforced via Zeek capture scopes and Logstash filters. When a tenant requests deletion, the `erase_tenant.sh` script purges their indices and shared documents, leaving an audit receipt.

## Monitoring and Notifications
Logstash actively monitors incoming logs for secrets (e.g., `password=`, `api_key=`) and redacts them inline before indexing.

## Playbook Verification
To verify data handling controls:
1. Review `configs/logstash.conf` to ensure redaction filters are active.
2. Search Kibana for `[REDACTED]` to confirm the filters are triggering on live data.

## Recommended Response Action(s)

### Identification
To process a Data Subject Access Request (DSAR) or erasure request:
- Verify the request authenticity.
- Identify the tenant's slug (e.g., `acme-net`).

### Containment
If a capture configuration accidentally collects payloads or secrets:
- Immediately halt the capture scripts (SOP-001).
- Use Kibana to locate and delete the accidental PII documents.
- Update `local.zeek` or `logstash.conf` to block the leak.

### Eradication & Recovery
To execute a Right-to-Erasure request:
1. Run `./scripts/setup/erase_tenant.sh <tenant-slug> --yes`.
2. Verify deletion: search for the tenant's indices (`logstash-security-<tenant>`) and expect a 404.
3. Verify the tamper-evident receipt: check `soc-audit-unassigned` for the `tenant_erasure` event.
4. If a strict legal deadline applies, manually delete the relevant snapshots from `suburban-soc-snapshots`.

# References and Resources
- `configs/zeek/local.zeek`
- `configs/logstash.conf`
- `scripts/setup/erase_tenant.sh`
