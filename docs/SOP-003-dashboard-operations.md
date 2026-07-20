# Executive Summary
Deploying, verifying, and maintaining the four-dashboard SOC monitoring ecosystem (plus the SOC navigation hub) for the Suburban-SOC pipeline. This ensures continuous visibility into network, endpoint, and data quality metrics.

## Name
SOP-003 — Dashboard Operations

## Problem Statement
The SOC requires a unified set of dashboards to visualize ingested telemetry across Zeek, Sysmon, Filebeat, and internal pipeline metrics. Without a standard operational procedure to deploy and verify these dashboards, analysts lack reliable visibility.

## Objectives
Provide a reproducible, idempotent method for deploying the four core dashboards and the navigation hub.

## Compliance
- **NIST CSF (Detect, Respond, Recover)**: Ensures continuous monitoring capabilities and situational awareness.
- **NIST 800-160**: System Security Engineering, providing built-in visibility.

## MITRE ATT&CK Framework
- TA0007 Discovery (Network Dashboards)
- All TA mapping available via Executive Dashboard MITRE heatmap.

## Assumptions and Limitations
- ELK 9.3.2 stack running.
- Winlogbeat/Filebeat agents actively shipping to :5044.

# Analysis
All visualizations bind to the `logstash-pattern` data view (`logstash-*`). The Executive dashboard's SOAR panels additionally use `soar-actions-pattern`.

## Monitoring and Notifications
Once deployed, dashboards provide visual monitors for MTTD, Agent status, Threat intel hits, and data ingestion lags.

## Playbook Verification
To verify the deployment was successful:
1. Open `https://<host>:5601/app/dashboards` and confirm all five appear.
2. Verify objects via API: `curl -s "https://localhost:5601/api/saved_objects/dashboard/$id"`
3. Set time picker to Last 24 hours, generate traffic, and verify panels populate.

## Recommended Response Action(s)

### Identification
If dashboards fail to populate:
- Widen time picker; confirm ingest on Data Quality dashboard.
- Verify `ssl.log` generation for TLS panels.

### Containment
- If data views are missing ("Could not locate that data view"), immediately re-run the `deploy_dashboards.sh` script to provision `logstash-pattern`.

### Eradication & Recovery
To restore missing or corrupted dashboards:
- Linux/macOS: `./scripts/setup/deploy_dashboards.sh`
- Windows: `.\scripts\setup\deploy_dashboards.ps1`
Re-running is idempotent and will overwrite corrupted imports.

# References and Resources
- [SOP-001 Pipeline Operations](./SOP-001-pipeline-operations.md)
- [SOP-022 Anomaly Validation](./SOP-022-anomaly-validation.md)
