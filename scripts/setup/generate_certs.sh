#!/bin/bash
# =============================================================================
# generate_certs.sh — Internal CA + service certificates  (CDP §6)
# =============================================================================
# Re-enables transport security by minting a semester-scoped internal CA and
# per-service certificates for the SOC stack. Run this ONCE before
# `docker compose up`. Re-run each semester to rotate (CDP §6).
#
#   ./generate_certs.sh
#
# Produces (under ./certs, git-ignored):
#   certs/ca/ca.crt           internal CA certificate (trust anchor)
#   certs/ca/ca.key           CA private key (KEEP OFF GIT)
#   certs/es/es.crt|es.key    Elasticsearch node cert (http + transport)
#
# The transport layer is configured with verification_mode=certificate, so
# every node/client must present a cert signed by this CA — i.e. mTLS.
# =============================================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
CA_DIR="$CERT_DIR/ca"
ES_DIR="$CERT_DIR/es"
DAYS=180   # one semester; rotate on expiry

mkdir -p "$CA_DIR" "$ES_DIR"

if [[ -f "$CA_DIR/ca.crt" ]]; then
  echo "[=] CA already exists at $CA_DIR/ca.crt — delete ./certs to regenerate. Skipping."
  exit 0
fi

echo "[*] Generating internal CA (valid ${DAYS} days)..."
openssl genrsa -out "$CA_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days "$DAYS" \
  -subj "/O=UIW-SOC/OU=CDP/CN=UIW-SOC Internal CA" \
  -out "$CA_DIR/ca.crt"

echo "[*] Generating Elasticsearch node certificate..."
openssl genrsa -out "$ES_DIR/es.key" 4096
# SANs cover the in-network service name and localhost for host access.
openssl req -new -key "$ES_DIR/es.key" \
  -subj "/O=UIW-SOC/OU=CDP/CN=elasticsearch" \
  -out "$ES_DIR/es.csr"

cat > "$ES_DIR/es.ext" <<'EOF'
subjectAltName = DNS:elasticsearch, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth, clientAuth
EOF

openssl x509 -req -in "$ES_DIR/es.csr" \
  -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
  -sha256 -days "$DAYS" -extfile "$ES_DIR/es.ext" \
  -out "$ES_DIR/es.crt"

rm -f "$ES_DIR/es.csr" "$ES_DIR/es.ext"
chmod 600 "$CA_DIR/ca.key" "$ES_DIR/es.key"

echo "[+] Certificates written to $CERT_DIR"
echo "[!] Set ELASTIC_PASSWORD in scripts/setup/.env before 'docker compose up'."
