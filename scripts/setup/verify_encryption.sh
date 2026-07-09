#!/usr/bin/env bash
# =============================================================================
# verify_encryption.sh — WS3.1 acceptance evidence: encryption in transit & at rest.
#
# Confirms, against the RUNNING stack, that telemetry is encrypted on every hop
# (no plaintext on the wire) and reports the at-rest posture. Exit 0 only if every
# transit check passes. Safe to run repeatedly; read-only (no mutations).
#
#   bash scripts/setup/verify_encryption.sh
#
# SOC 2 control evidence — pairs with docs/SOP-011-encryption.md. Collected by the
# WS3.7 continuous control monitor.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$HERE/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENVF" ]] && { set -a; . "$ENVF"; set +a; }
ES_PASS="${ELASTIC_PASSWORD:-${ES_PASS:-}}"
NET="${SOC_NET:-setup_soc-mesh-net}"
CERTVOL="${SOC_CERT_VOL:-setup_certs}"
LS_IMG="docker.elastic.co/logstash/logstash:${STACK_VERSION:-9.3.2}"
fails=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; fails=$((fails+1)); }
info() { echo "  [INFO] $1"; }

echo "== Encryption in transit =="

# 1) ES HTTP layer must be TLS-only — a plaintext request to :9200 must be refused.
code="$(curl -s -m5 -o /dev/null -w '%{http_code}' http://localhost:9200 2>/dev/null)"
[[ "$code" == "000" ]] && pass "ES :9200 rejects plaintext HTTP (TLS-only)" \
                        || fail "ES :9200 answered plaintext HTTP with $code (expected TLS-only)"

# 2) ES TLS cert must chain to the stack CA (verified, not -k).
docker run --rm -v "$CERTVOL":/certs alpine cat /certs/ca/ca.crt >/tmp/soc_ca.crt 2>/dev/null
if curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" https://localhost:9200 \
     | grep -q '"cluster_name"'; then
  pass "ES :9200 HTTPS cert verifies against the stack CA"
else
  fail "ES :9200 HTTPS cert did NOT verify against the stack CA"
fi

# 3) ES transport layer (inter-node) must run TLS — required for HA (WS2.4) / scale-out.
ttls="$(curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" \
        'https://localhost:9200/_nodes/settings?filter_path=nodes.*.settings.xpack.security.transport.ssl.enabled' 2>/dev/null)"
echo "$ttls" | grep -q '"enabled":"true"' \
  && pass "ES transport TLS enabled (xpack.security.transport.ssl.enabled=true)" \
  || info "ES transport TLS not reported enabled (single-node MVP; required before scale-out)"

# 4) Beats input (:5044, Filebeat->Logstash) must require TLS and present a CA-signed cert.
hs="$(docker run --rm --user 0 --network "$NET" -v "$CERTVOL":/certs --entrypoint sh "$LS_IMG" -c \
      'echo | openssl s_client -connect logstash:5044 -CAfile /certs/ca/ca.crt 2>/dev/null' 2>/dev/null)"
if echo "$hs" | grep -q 'Verify return code: 0 (ok)' && echo "$hs" | grep -q 'CN=logstash'; then
  proto="$(echo "$hs" | grep -oE 'TLSv1\.[0-9]' | head -1)"
  pass "Beats :5044 serves TLS ($proto), cert verifies against the CA (no plaintext telemetry)"
else
  fail "Beats :5044 did NOT complete a verified TLS handshake"
fi

echo "== Encryption at rest =="
# 5) Snapshot repository present (off-cluster immutable copy lives on encrypted storage).
if curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" \
     https://localhost:9200/_snapshot/suburban-soc-snapshots 2>/dev/null | grep -q '"type"'; then
  pass "Snapshot repository 'suburban-soc-snapshots' registered"
else
  info "Snapshot repository not registered (run apply-lifecycle.sh)"
fi
# 6) At-rest encryption of the ES data volume + snapshot storage is delivered by
#    host full-disk/volume encryption (LUKS/dm-crypt or cloud-provider encrypted
#    disks) — see docs/SOP-011-encryption.md. Operator attestation item; the script
#    cannot read the host crypto layer from inside a container.
info "Data-at-rest: ES volume + snapshot store rely on host disk encryption (SOP-011, operator attestation)"

rm -f /tmp/soc_ca.crt
echo
if [[ $fails -eq 0 ]]; then echo "[=] Encryption-in-transit verified on every checked hop."; exit 0
else echo "[=] $fails encryption check(s) FAILED."; exit 1; fi
