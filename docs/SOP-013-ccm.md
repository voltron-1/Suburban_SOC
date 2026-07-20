# Executive Summary
This Standard Operating Procedure (SOP) defines the Continuous Control Monitoring (CCM) framework. It ensures SOC 2 technical controls are automatically evaluated on a schedule, alerting operators if any control regresses.

## Name
SOP-013 — Continuous Control Monitoring (CCM)

## Problem Statement
Point-in-time compliance audits do not prevent runtime drift. If TLS is disabled, backups fail, or RBAC roles are modified, the SOC must detect the regression immediately.

## Objectives
- Continuously evaluate 7 core technical controls (Encryption, RBAC, Audit, ILM, SLM, Scanning, Change Mgmt).
- Write immutable evidence to the `soc-controls` index on every run.
- Alert operators immediately upon any control failure.

## Compliance
- **NIST CSF**: DE.CM-1 (Network/environment monitored), ID.GV-4 (Governance and risk management).
- **SOC 2**: Monitoring (CC4.1, CC7.1–CC7.2).

## MITRE ATT&CK Framework
- Mitigates TA0005 Defense Evasion by alerting when security controls are disabled.

## Assumptions and Limitations
- The `collect_control_evidence.sh` script runs on a daily cron schedule.
- The `soc-controls` data view is configured in Kibana.

# Analysis
The CCM script acts as the "control that watches the controls." It records dated evidence of passes and fails. The resulting data populates the "[SOC] SOC 2 Control Status" dashboard.

## Monitoring and Notifications
If a control fails, the script pushes a high-priority alert to the configured `$NTFY_TOPIC`.

## Playbook Verification
To verify the CCM is functioning:
1. Open the "[SOC] SOC 2 Control Status (WS3.7)" dashboard in Kibana.
2. Confirm recent evidence documents are present for all 7 controls.
3. Verify the cron job is active (`crontab -l`).

## Recommended Response Action(s)

### Identification
When a CCM alert fires or the cron job exits non-zero:
- Open the Kibana dashboard and filter for `control.status : fail`.
- Read the `control.detail` field to identify the specific failure (e.g., C5 snapshot failed).

### Containment
- Acknowledge the alert.
- Do not make hasty changes; investigate the root cause logged in the `control.detail`.

### Eradication & Recovery
Remediate based on the specific control failure:
- **C1 (TLS off):** Recreate the stack from compose (`docker compose up -d`).
- **C5 (Snapshot failed):** Verify `path.repo` on the ES node, then manually trigger the SLM policy.
- **C2/C3 (Role drift):** Re-run `apply_roles.sh`.
- **C4 (ILM missing):** Re-run `apply-lifecycle.sh`.
After fixing the issue, manually run `bash collect_control_evidence.sh` to record the passing state and clear the dashboard failure.

# References and Resources
- `scripts/setup/collect_control_evidence.sh`
- `configs/server/control_status_dashboard.ndjson`
