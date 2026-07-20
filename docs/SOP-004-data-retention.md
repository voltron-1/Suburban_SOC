# Executive Summary
This Standard Operating Procedure (SOP) bounds Elasticsearch storage and makes the evidence window explicit via Index Lifecycle Management (ILM). It governs the retention of security telemetry and SOAR response actions, ensuring data is aged out appropriately and always backed up before deletion.

## Name
SOP-004 — Data Lifecycle & Retention

## Problem Statement
Prior to WS0.5, the stack wrote unbounded daily indices without a lifecycle policy. Storage grew without limit, and the retention period was undefined, posing reliability and compliance risks.

## Objectives
- Convert tenant streams to ILM-governed data streams.
- Enforce explicit retention windows for telemetry (30 days) and evidence (365 days).
- Gate data deletion on a successful snapshot.

## Compliance
- **NIST CSF**: PR.DS-4 (Data Capacity & Retention), PR.DS-1 (Data-at-rest protection via lifecycle).
- **CIS Controls**: Control 3 (Data Protection).

## MITRE ATT&CK Framework
- (N/A for Data Lifecycle, though ensures forensic data availability for TA0007-TA0009).

## Assumptions and Limitations
- Snapshot policies (`suburban-soc-daily-snapshots`) are active.
- Indices follow the `logstash-security-*` and `soar-actions-*` naming conventions.
- Data retention windows must be reconciled with Privacy/Confidentiality commitments (WS3.4).

# Analysis
The pipeline distinguishes between high-volume telemetry (kept 30 days) and low-volume, high-value SOAR actions (kept 365 days). Both pipelines require snapshots before the deletion phase to ensure data is recoverable.

## Monitoring and Notifications
ILM automatically transitions indices between Hot, Warm, and Delete phases. Administrators should monitor snapshot success and disk capacity through Kibana.

## Playbook Verification
To verify the lifecycle policies are correctly applied:
1. Run `./scripts/setup/verify_lifecycle.sh`
2. Ensure ILM is attached, rollover is observed, and `wait_for_snapshot` is active in the delete phase.

## Recommended Response Action(s)

### Identification
Identify the data streams and their policies:
- `logstash-security-<tenant>`: 30 days retention.
- `soar-actions-<tenant>`: 365 days retention.

### Containment
If storage fills up unexpectedly:
- Check if snapshots are failing (which blocks the delete phase).
- Temporarily lower the retention threshold in `configs/elasticsearch/ilm/*.json` and re-apply using `configs/elasticsearch/apply-lifecycle.sh`.

### Eradication & Recovery
To install or reinstall the lifecycle policies from scratch:
1. Bring up the stack with the snapshot volume: `docker compose up -d`
2. Run the installer: `./configs/elasticsearch/apply-lifecycle.sh`
3. Legacy indices (`logstash-security-<tenant>-YYYY.MM.dd`) are untouched by ILM and can be manually aged out or reindexed via `configs/elasticsearch/reindex-existing.sh`.

# References and Resources
- `configs/elasticsearch/ilm/logstash-security.ilm.json`
- `configs/elasticsearch/ilm/soar-actions.ilm.json`
- `configs/elasticsearch/ilm/snapshot-repository.json`
- `configs/elasticsearch/ilm/slm-policy.json`
