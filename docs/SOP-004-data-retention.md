# SOP-004 — Data Lifecycle & Retention (WS0.5)

**Status:** Active · **Milestone:** M7 (Platform Security & Multi-Tenancy Foundation) ·
**Workstream:** WS0.5 · **Owner:** System Architect

## Purpose

Bound Elasticsearch storage and make the **evidence window explicit**. Before WS0.5
the stack wrote unbounded daily indices (`logstash-security-<tenant>-YYYY.MM.dd`,
`data_stream => false`) with no lifecycle policy — storage grew without limit and the
retention period was undefined. WS0.5 converts every tenant stream to an
**Index Lifecycle Management (ILM)**-governed **data stream** and gates deletion on a
snapshot.

## Retention policy (the documented window)

| Data | Data stream | ILM policy | Rollover (hot) | Retention | Rationale |
|------|-------------|-----------|----------------|-----------|-----------|
| Security telemetry (Zeek / endpoint) | `logstash-security-<tenant>` | `logstash-security-ilm` | 10 GB primary shard **or** 1 day | **30 days** | High volume; 30d is the raw-evidence window for triage/hunt. |
| SOAR response actions | `soar-actions-<tenant>` | `soar-actions-ilm` | 5 GB primary shard **or** 30 days | **365 days** | Low volume but evidentiary — every quarantine/analyst decision is kept a full year, outliving the raw telemetry. |

Phases:

- **Security telemetry:** `hot` (rollover, priority 100) → `warm` @ 2d (forcemerge to 1
  segment, read-only, priority 50) → `delete` @ 30d.
- **SOAR actions:** `hot` (rollover, priority 100) → `delete` @ 365d.

`min_age` for the delete phase is measured **from rollover**, so total lifetime ≈
rollover age + retention. Adjust the `delete.min_age` in
`configs/elasticsearch/ilm/*.json` to change a window; keep this table in sync.

> Privacy note: these windows are the technical enforcement of the capture/retention
> stance. WS3.4 (Privacy/Confidentiality) and any resident-facing data-handling
> commitment are the source of truth — reconcile the numbers there before changing them.

## Snapshot before delete

The `delete` phase uses ILM **`wait_for_snapshot`** against the SLM policy
`suburban-soc-daily-snapshots`, so an index is **never deleted until it has been
captured in a snapshot**.

- **Repository:** `suburban-soc-snapshots` (type `fs`, location `suburban-soc`), backed
  by the `suburban_soc_snapshots` Docker volume mounted at
  `/usr/share/elasticsearch/snapshots`. Enabled by `path.repo` in
  `scripts/setup/docker-compose.yml`.
- **SLM policy:** `suburban-soc-daily-snapshots` runs daily at 01:30, snapshots
  `logstash-security-*` + `soar-actions-*`, and expires snapshots after 45 days
  (keep 5–60).
- Single-node `fs` repo is the MVP posture. **WS9.1 (Reliability)** promotes this to
  object storage with periodic restore tests.

## Files

- `configs/elasticsearch/ilm/logstash-security.ilm.json` — 30d telemetry policy
- `configs/elasticsearch/ilm/soar-actions.ilm.json` — 365d evidence policy
- `configs/elasticsearch/ilm/snapshot-repository.json` — fs repo definition
- `configs/elasticsearch/ilm/slm-policy.json` — daily snapshot schedule + retention
- `configs/elasticsearch/logstash-security-template.json`,
  `configs/elasticsearch/soar-actions-template.json` — `data_stream:{}` + `index.lifecycle.name`
- `configs/logstash.conf` — output writes `create` ops to `logstash-security-<tenant>`
- `scripts/setup/ai_agent/agent_app.py` — `log_soar_action` writes to `soar-actions-<tenant>`
- `configs/elasticsearch/apply-lifecycle.sh` — installer (repo → SLM → ILM → templates)
- `scripts/setup/deploy_dashboards.sh` — step [6/7] runs the installer
- `scripts/setup/verify_lifecycle.sh` — acceptance check

## Install & verify

```bash
cd ~/projects/Suburban-SOC/scripts/setup

# 1. Bring up the stack with the snapshot volume + path.repo (one-time recreate).
docker compose up -d

# 2. Install the lifecycle (also runs as step [6/7] of deploy_dashboards.sh).
../../configs/elasticsearch/apply-lifecycle.sh

# 3. Prove it: ILM attached, ROLLOVER OBSERVED, snapshot-before-delete in place.
./verify_lifecycle.sh
```

## Acceptance (WS0.5, issue #91)

- [x] Indices converted to **data streams** (`data_stream:{}` templates; Logstash +
      agent write `op_type=create`).
- [x] ILM **hot/warm/delete** defined with a **documented retention window** (table above).
- [x] **Snapshot before delete** (SLM policy + ILM `wait_for_snapshot`).
- [x] Policies installed via the **deploy script** (`apply-lifecycle.sh`, wired into
      `deploy_dashboards.sh`).
- [x] **Rollover observed** + retention enforced — see `verify_lifecycle.sh`.

## Migration note

Pre-WS0.5 daily indices (`logstash-security-<tenant>-YYYY.MM.dd`) remain as ordinary
indices and are **not** governed by the new ILM policies. They are readable (they still
match the `logstash-*` data view) and can be aged out manually, or migrated with
`configs/elasticsearch/reindex-existing.sh`. New writes land in the data streams.
