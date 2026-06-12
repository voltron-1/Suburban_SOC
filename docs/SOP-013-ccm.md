# SOP-013 — Continuous Control Monitoring (CCM)

**Control family:** Monitoring (SOC 2 CC4.1, CC7.1–CC7.2) · **Workstream:** WS3.7 (M10)
**Owner:** SecOps · **Review cadence:** monthly + after any control change

## Purpose

SOC 2 Type II is about controls operating **continuously over a period**, not a
point-in-time snapshot. This is the control that watches the other controls: it
re-checks every M10 technical control against the live stack, records dated evidence,
and alerts when a control **regresses**.

## What it checks

`scripts/setup/collect_control_evidence.sh` evaluates seven controls each run:

| ID | Control | SOC 2 | Evidence checked |
|----|---------|-------|------------------|
| C1 | Encryption in transit (WS3.1) | Confidentiality | `http` **and** `transport` TLS both `enabled=true` |
| C2 | RBAC least privilege (WS3.2) | Security | all 6 expected roles present |
| C3 | Audit trail append-only (WS3.3) | Security | `soc_audit_appender` grants **only** `create`/`create_index` |
| C4 | Retention / ILM (WS0.5) | Security | `logstash-security-ilm` policy present |
| C5 | Backups / SLM (WS2.5) | Availability | last snapshot succeeded, no failure newer than success |
| C6 | Vulnerability scanning (WS3.6) | Security | `security-scan.yml` CI gate present |
| C7 | Change management (WS3.5) | Security | deploys recorded to `soc-deploys` |

Each run writes one `create` doc per control to **`soc-controls`** (`control.id`,
`control.name`, `control.status` ∈ {pass, fail, no_data}, `control.detail`, `soc2.tsc`,
`@timestamp`). Evidence is immutable history (new docs per run) and is included in the
daily SLM snapshot for retention.

## Regression alerting

If any control returns `fail`, the script pushes a high-priority **ntfy** alert to
`$NTFY_TOPIC` and exits non-zero, so the scheduler (and the operator) sees the
regression immediately. `CCM_NO_ALERT=1` suppresses the push (for ad-hoc runs).

## Dashboard

`configs/server/control_status_dashboard.ndjson` → **[SOC] SOC 2 Control Status (WS3.7)**
in Kibana (deployed by `deploy_dashboards.sh`): a latest-status-per-control table, a
status-mix donut, and a header. Filter `control.status : fail` to triage. The
`soc-controls` data view is created on import.

## Schedule

Run on a timer (the "continuous" in CCM). Example cron (daily 02:00, after the 01:30
SLM snapshot so C5 reflects the night's backup):

```cron
0 2 * * *  cd /opt/suburban-soc/scripts/setup && \
           ES_CA=$PWD/certs/ca.crt bash collect_control_evidence.sh >> /var/log/soc-ccm.log 2>&1
```

For SOC 2 audit, daily is the floor; many controls (C5 especially) are daily-cadence.
The CI security scan (C6) and change log (C7) update on their own triggers; CCM records
the standing state.

## Regression response

1. Alert fires (ntfy) / non-zero exit in the scheduler.
2. Open the dashboard, filter `control.status : fail`, read `control.detail`.
3. Remediate by control:
   - **C1** TLS off → recreate the stack from compose (`docker compose up -d`); never `--no-deps` partial.
   - **C5** snapshot failed → check `path.repo` is set on the node (the common cause — see SOP for WS2.5), re-run `apply-lifecycle.sh`, `_slm/.../_execute`.
   - **C2/C3** role drift → re-run `apply_roles.sh`.
   - **C4** ILM missing → re-run `apply-lifecycle.sh`.
4. Re-run `collect_control_evidence.sh` to confirm green; the next `soc-controls` doc is the remediation evidence.

> Validated WS3.7: the monitor **correctly caught a real C5 regression** (a snapshot
> failed because the running node had lost `path.repo`); after re-executing the SLM
> policy, C5 returned `pass` and all 7 controls were green.
