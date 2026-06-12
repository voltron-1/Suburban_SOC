# SOP-009 — RBAC & Least Privilege (WS3.2)

**Status:** Active · **Milestone:** M10 · **Workstream:** WS3.2 · **SOC 2:** Security

## Roles (version-controlled in `configs/elasticsearch/roles/*.json`)
| Role | Who/what | Privileges |
|---|---|---|
| `soc_analyst` | human analyst | **read** SOC data + alerts; Discover/Dashboard read; **Cases all**; SIEM read |
| `soc_detection_engineer` | human detection eng | analyst + manage index templates; SIEM **all** (manage rules) |
| `soc_admin` | human SOC admin | manage SOC indices/ILM/SLM + all Kibana — but **not** `manage_security` (no user/role admin → not a superuser) |
| `logstash_writer` | Logstash service | write `logstash-*`/`soar-actions-*`/`asset-inventory-*` only |
| `soc_agent_cases` | AI-agent service | `feature_generalCases.all` only (open/close cases) |
| `tenant_*_viewer` | tenant viewer | read ONE tenant's indices + its space (provisioned by `provision_tenant.sh`) |

Apply: `./scripts/setup/apply_roles.sh`. Service accounts (`logstash_internal`,
`soc_agent`) use these roles — **no human or service uses the `elastic` superuser in
normal operation**; `elastic` is break-glass only.

## Verification — negative tests
`tests/rbac/test_rbac.sh` proves each account can do its job and **only** its job:
- `soc_analyst` reads SOC data, but **cannot** delete an index or create a role (403);
- `logstash_writer` writes its indices, but **cannot** read security alerts or create a
  user (403).

**Validated:** all 6 checks pass.

## Acceptance (#103)
- [x] Roles defined (tenant-viewer, analyst, detection-engineer, admin, service accounts)
- [x] Services scoped to least-privilege accounts, not `elastic`
- [x] Negative tests prove each account can only do its job
