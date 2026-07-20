# Executive Summary
This Standard Operating Procedure (SOP) covers the three reliability pillars for Suburban-SOC: High Availability (HA), restore-tested backups, and self-monitoring. It ensures uptime and recoverable evidence for the SOC stack.

## Name
SOP-005 — Reliability of the SOC Stack

## Problem Statement
A production SOC requires guaranteed uptime and data recoverability. The default development stack is single-node, lacks tested backup procedures, and fails silently when components crash.

## Objectives
- Deploy and validate a 3-node HA Elasticsearch cluster.
- Prove automated snapshots work via restore testing.
- Enable self-monitoring and alerting for pipeline outages.

## Compliance
- **NIST CSF**: ID.BE-5 (Resilience requirements), PR.IP-4 (Backups), DE.AE-2 (Event detection/monitoring).
- **CIS Controls**: Control 11 (Data Recovery).

## MITRE ATT&CK Framework
- mitigates Impact (TA0040) like Data Destruction (T1485) and Endpoint Denial of Service (T1499).

## Assumptions and Limitations
- The production deployment uses `docker-compose.ha.yml`.
- Snapshots are configured to use a filesystem repo (`fs`) or S3-compatible object storage.

# Analysis
The reliability pillars are validated through regular drills, including node-kill exercises, automated canary restore tests, and continuous health checks.

## Monitoring and Notifications
The `stack_health.sh` script runs via cron every 5 minutes and pushes alerts to `ntfy` if any core component (Elasticsearch, Kibana, Logstash, broker, or agent) is down.

## Playbook Verification
To verify the stack's reliability:
1. Check HA status: `curl -sk -u elastic:$ELASTIC_PASSWORD https://localhost:9200/_cluster/health` (should be `green`, nodes: 3).
2. Ensure index replicas are ≥ 1.
3. Run `./scripts/setup/stack_health.sh` (should exit 0).

## Recommended Response Action(s)

### Identification
To detect an outage or data availability issue:
- Monitor ntfy for `DOWN` alerts.
- Check cluster health API for `yellow` or `red` status.

### Containment
If a node goes down:
- The cluster enters `yellow` status but remains serving (no data loss).
- Verify the remaining nodes have enough disk/memory to handle the load.

### Eradication & Recovery
**HA Recovery:**
Restart the downed node: `docker compose -f docker-compose.ha.yml start <node>`

**Backup Restore Drill:**
To verify backups or recover data from snapshots:
1. Canary test: `./scripts/setup/restore_test.sh`
2. Full index restore test: `./scripts/setup/restore_test.sh <index>`
For disaster recovery, restore into a scratch cluster and verify doc counts.

# References and Resources
- `scripts/setup/docker-compose.ha.yml`
- `scripts/setup/restore_test.sh`
- `scripts/setup/stack_health.sh`
- `configs/monitoring/reliability.cron`
