# SOP-005 — Reliability of the SOC Stack (WS2.5)

**Status:** Active · **Milestone:** M9 (Operational Maturity / SOC-CMM L3) ·
**Workstream:** WS2.5 · **Owner:** SOC Operator

## Purpose
A paying customer needs uptime and recoverable evidence. This SOP covers the three
reliability pillars and the drills that prove them: **HA**, **restore-tested backups**,
and **self-monitoring**.

---

## 1. High Availability — multi-node Elasticsearch

The dev stack (`docker-compose.yml`) is single-node (no HA). Production runs the
**3-node** topology in `scripts/setup/docker-compose.ha.yml` (3 master+data nodes, TLS,
auto-generated per-node certs).

```bash
cd scripts/setup
docker compose -f docker-compose.ha.yml up -d
curl -sk -u elastic:$ELASTIC_PASSWORD https://localhost:9200/_cluster/health   # status:green nodes:3
```

**Index replicas ≥ 1 are required for HA** (so a node loss keeps a copy). Set on the
templates / data streams:
```bash
curl -sk -u elastic:$ELASTIC_PASSWORD -X PUT \
  https://localhost:9200/logstash-security-*/_settings -d '{"index":{"number_of_replicas":1}}'
```
(The WS0.5 single-node templates pin `replicas:0`; bump to `1` on the HA cluster.)

### Kill-a-node drill (validated)
```bash
docker compose -f docker-compose.ha.yml stop es02
curl -sk -u elastic:$ELASTIC_PASSWORD https://localhost:9200/_cluster/health
```
**Validated result:** with a replicated index, stopping a node leaves the cluster
**serving** — status goes `green → yellow` (degraded, not `red`), node count `3 → 2`,
and **all data stays readable (no loss)**. Restarting the node re-greens the cluster.
`yellow` here = "operational, one replica short", which is the HA win: an outage does
not stop the SOC or lose evidence.

---

## 2. Restore-tested backups

Automated snapshots are configured in WS0.5 (SLM policy `suburban-soc-daily-snapshots`).
A backup is only real once restored — `scripts/setup/restore_test.sh` proves it:

```bash
./scripts/setup/restore_test.sh            # canary round-trip (snapshot -> restore -> verify count)
./scripts/setup/restore_test.sh <index>    # restore-test a real index into a scratch copy
```
**Validated:** 25/25 canary docs snapshot→restore round-tripped from
`suburban-soc-snapshots`. Scheduled daily via `configs/monitoring/reliability.cron`.

### Object-storage snapshots (production)
The dev repo is `fs` (`path.repo`). Production points at **S3-compatible object
storage** (`configs/elasticsearch/snapshot/s3-repository.json`):
```bash
# 1. credentials go in the ES keystore (NOT the repo JSON):
bin/elasticsearch-keystore add s3.client.default.access_key
bin/elasticsearch-keystore add s3.client.default.secret_key
# 2. register (S3_ENDPOINT e.g. a MinIO or cloud endpoint):
curl -sk -u elastic:$ELASTIC_PASSWORD -X PUT \
  https://localhost:9200/_snapshot/suburban-soc-snapshots \
  --data-binary @configs/elasticsearch/snapshot/s3-repository.json
```
`restore_test.sh` and the SLM policy work unchanged against the S3 repo. For a
disaster-recovery drill, restore into a **scratch cluster** and verify counts.

---

## 3. Self-monitoring — the SOC detects its own outages

`scripts/setup/stack_health.sh` checks every component (Elasticsearch, Kibana,
Logstash, AI agent, Hive-Mind broker), records to `soc-health`, and raises an **ntfy
alert** if anything is DOWN. Scheduled every 5 min (`configs/monitoring/reliability.cron`).

```bash
./scripts/setup/stack_health.sh    # exit 0 healthy, 2 if any component down
```
**Validated:** all-up → `healthy` (exit 0); stopping the broker → `DOWN: broker`
(exit 2, ntfy alert). Optionally enable Kibana **Stack Monitoring** for historical
component metrics:
```bash
curl -sk -u elastic:$ELASTIC_PASSWORD -X PUT https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' -d '{"persistent":{"xpack.monitoring.collection.enabled":true}}'
```

---

## Acceptance (WS2.5, #101)
- [x] Multi-node ES for HA — kill a node, cluster stays serving (no data loss) — drill validated.
- [x] Automated snapshots (WS0.5 SLM) with **periodic restore tests** — `restore_test.sh` validated; daily cron; S3 object-storage config for production.
- [x] Self-monitoring with alerting — `stack_health.sh` detects component-down and alerts — validated.
