# SOP-011 — Encryption in Transit & at Rest

**Control family:** Confidentiality (SOC 2 CC6.1, CC6.7) · **Workstream:** WS3.1 (M10)
**Owner:** Platform / SecOps · **Review cadence:** quarterly + on topology change

## Purpose

Telemetry handled by Suburban-SOC is customer security data. This SOP defines how it
is encrypted **on every network hop** and **at rest**, and how that is verified for
SOC 2 Type II evidence.

## Scope — every hop

| Hop | Protocol | Mechanism | Evidence |
|-----|----------|-----------|----------|
| Endpoint → Logstash (Filebeat, :5044) | **TLS 1.3** | Logstash Beats input serves a CA-signed cert (`CN=logstash`); Filebeat verifies against `ca.crt` | `verify_encryption.sh` handshake check |
| Logstash → Elasticsearch (:9200) | **TLS 1.2+** | `logstash.conf` output `ssl_certificate_authorities` → stack CA | plaintext `:9200` refused |
| Kibana → Elasticsearch | **TLS 1.2+** | `elasticsearch.hosts: https://…` + CA | plaintext `:9200` refused |
| AI agent / broker → Elasticsearch | **TLS 1.2+** | HTTPS + CA mounted read-only | plaintext `:9200` refused |
| Inter-node (ES transport) | **TLS** | `xpack.security.transport.ssl.enabled=true` | `_nodes/settings` reports `true` |
| Analyst → Kibana | **TLS** (prod) | Reverse proxy / Kibana `server.ssl` terminates TLS at the edge | deployment-specific |

**Internal mesh hops** (SOAR `/alert` → agent :5000, agent → broker :8000) ride the
isolated `soc-mesh-net` bridge and are **HMAC-signed** (WS0.2). In production these are
additionally fronted with TLS at the ingress proxy; the HMAC signature is the integrity
+ authenticity control regardless of transport.

### How the Beats TLS cert is provisioned

`elasticsearch-certutil` (ES setup image) emits a CA-signed PEM cert for `logstash`,
**before** the setup's `find -exec chmod` strips `+x` from `certutil`. Because the Beats
SSL input requires a **PKCS8** key and the ES image has no `openssl`, the one-shot
`cert_pkcs8` service (logstash image — ships openssl 3.5) converts the key and hands the
material to logstash (uid 1000). `logstash` `depends_on: cert_pkcs8` (completed) so it
never starts without its server cert. All idempotent — reruns skip if the PKCS8 key exists.

## Encryption at rest

- **Elasticsearch data volume** and the **snapshot repository** rely on **host
  full-disk / volume encryption** — LUKS/dm-crypt on self-managed hosts, or
  provider-encrypted disks (e.g. encrypted EBS / managed-disk SSE) in cloud. ES has no
  built-in at-rest encryption on the basic license; disk-layer encryption is the control.
- **Snapshots** (`suburban-soc-snapshots`, WS0.5/2.5) are written to that encrypted
  store; WS9.1 promotes the repo to object storage with server-side encryption (SSE).
- **Secrets** (`.env`) are gitignored and never committed (gitleaks-enforced, WS3.6).
- This is an **operator attestation** item: a container cannot read the host crypto
  layer, so the deploying operator records the encrypted-volume evidence (e.g. `cryptsetup
  status`, or the cloud console disk-encryption flag) in the audit binder.

## Verification

```bash
bash scripts/setup/verify_encryption.sh    # run on the Linux host
```

Exits non-zero if any transit hop is missing TLS. Confirms: plaintext `:9200` refused,
ES HTTPS cert chains to the CA, transport TLS enabled, Beats `:5044` completes a
CA-verified TLS handshake, snapshot repo registered. The data-at-rest line is an
operator-attestation reminder. The WS3.7 continuous control monitor runs this on a
schedule and alerts on regression.

## Rotation

The stack CA and node/logstash certs are generated once into the `certs` volume. To
rotate: delete the relevant cert material from the volume and re-run `docker compose up
setup cert_pkcs8`, then recreate logstash. Plan CA rotation as a maintenance window —
every component verifies against the CA.
