#!/usr/bin/env bash
# =============================================================================
# mint_endpoint_cert.sh — mint a CA-signed Beats CLIENT certificate (#265)
# =============================================================================
# Logstash's Beats input (:5044) requires client authentication
# (`ssl_client_authentication => "required"`, #219). The docker-compose `setup`
# service mints exactly one client cert, for the capture host's own Filebeat.
# A Winlogbeat/Filebeat on any other endpoint has no identity to present and
# fails with `remote error: tls: certificate required`. This script mints one
# per endpoint, signed by the same stack CA.
#
#   ./mint_endpoint_cert.sh <endpoint-name> [output-dir]
#
#   <endpoint-name>  lowercase letters, digits and hyphens, 1-63 chars, not
#                    starting or ending with a hyphen (e.g. "win-lab-01").
#                    It becomes the certificate CN and DNS SAN.
#   [output-dir]     default ./endpoint-certs/<endpoint-name>; must not exist
#                    or must be empty (an existing cert is never overwritten).
#
# Writes <output-dir>/<name>.crt, <name>.key (mode 600) and ca.crt.
#
# Environment:
#   ES_CONTAINER         running Elasticsearch container   (default: elasticsearch)
#   ENDPOINT_CERT_DAYS   validity in days                  (default: 365)
#
# DESIGN
#   * The CA PRIVATE KEY NEVER LEAVES THE ELASTICSEARCH CONTAINER. certutil runs
#     inside it (the same tool and image the compose `setup` service uses for
#     the filebeat/logstash certs), and only the finished client cert + key and
#     the PUBLIC ca.crt are copied out.
#   * The endpoint name is validated against a strict allow-list before it is
#     used anywhere, and is passed to the container as a positional argument,
#     never spliced into a shell string.
#   * The scratch directory inside the container is removed on every exit path.
#
# NOT COVERED (tracked, deliberately out of scope here): the certificate proves
# the shipper is trusted, but Logstash still takes [tenant][id] from the
# shipper's own config. A holder of any valid client cert can claim any tenant.
# Binding tenant to certificate identity is a separate Logstash-side change.
#
# Run from a host with Docker access to the stack. Not usable from a session
# without a live Docker daemon and a running Elasticsearch container.
# =============================================================================
set -euo pipefail

usage() {
  echo "usage: $0 <endpoint-name> [output-dir]" >&2
  echo "  endpoint-name: [a-z0-9-], 1-63 chars, no leading/trailing hyphen" >&2
}

NAME="${1:-}"
if [[ -z "$NAME" ]]; then
  usage
  exit 2
fi
if ! [[ "$NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
  echo "[REFUSED] invalid endpoint name: '$NAME'" >&2
  usage
  exit 2
fi

OUT_DIR="${2:-./endpoint-certs/$NAME}"
ES_CONTAINER="${ES_CONTAINER:-elasticsearch}"
DAYS="${ENDPOINT_CERT_DAYS:-365}"
if ! [[ "$DAYS" =~ ^[0-9]{1,5}$ ]] || (( DAYS < 1 )); then
  echo "[REFUSED] ENDPOINT_CERT_DAYS must be a positive integer, got '$DAYS'" >&2
  exit 2
fi

# Never overwrite an existing identity.
if [[ -e "$OUT_DIR" ]] && [[ -n "$(ls -A "$OUT_DIR" 2>/dev/null || true)" ]]; then
  echo "[REFUSED] $OUT_DIR already exists and is not empty — choose another directory." >&2
  exit 2
fi

if [[ "$(docker inspect -f '{{.State.Running}}' "$ES_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
  echo "[!] Container '$ES_CONTAINER' is not running. Start the stack first" >&2
  echo "    (docker compose up -d from scripts/setup) or set ES_CONTAINER." >&2
  exit 1
fi

WORK="/tmp/mint-endpoint-cert-$NAME-$$"
cleanup() {
  docker exec -u 0 "$ES_CONTAINER" rm -rf -- "$WORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

umask 077
mkdir -p "$OUT_DIR"

echo "[*] Minting client certificate for '$NAME' (valid $DAYS days)..."
# $1=scratch dir  $2=endpoint name  $3=days — positional, never interpolated.
docker exec -u 0 "$ES_CONTAINER" bash -c '
  set -euo pipefail
  work="$1"; name="$2"; days="$3"
  mkdir -m 700 "$work"
  printf "instances:\n  - name: %s\n    dns:\n      - %s\n" "$name" "$name" > "$work/instances.yml"
  bin/elasticsearch-certutil cert --silent --pem --days "$days" \
    -out "$work/bundle.zip" --in "$work/instances.yml" \
    --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key
  unzip -q "$work/bundle.zip" -d "$work/out"
' _ "$WORK" "$NAME" "$DAYS"

docker cp "$ES_CONTAINER:$WORK/out/$NAME/." "$OUT_DIR/"
docker cp "$ES_CONTAINER:/usr/share/elasticsearch/config/certs/ca/ca.crt" "$OUT_DIR/ca.crt"

for f in "$NAME.crt" "$NAME.key" ca.crt; do
  if [[ ! -s "$OUT_DIR/$f" ]]; then
    echo "[!] expected $OUT_DIR/$f is missing or empty — certutil output layout changed?" >&2
    exit 1
  fi
done
chmod 600 "$OUT_DIR/$NAME.key"
chmod 644 "$OUT_DIR/$NAME.crt" "$OUT_DIR/ca.crt"

if command -v openssl >/dev/null 2>&1; then
  if ! openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/$NAME.crt" >&2; then
    echo "[!] $OUT_DIR/$NAME.crt does not chain to $OUT_DIR/ca.crt — do NOT deploy it." >&2
    exit 1
  fi
else
  echo "[!] openssl not found on this host — skipped chain verification." >&2
fi

cat <<EOF

[+] Wrote $OUT_DIR/{$NAME.crt,$NAME.key,ca.crt}
    Move the .key to the endpoint over a trusted channel and delete the local copy.

    Windows (Winlogbeat), set these for the service:
      WINLOGBEAT_CA   = C:/ProgramData/winlogbeat/certs/ca.crt
      WINLOGBEAT_CERT = C:/ProgramData/winlogbeat/certs/$NAME.crt
      WINLOGBEAT_KEY  = C:/ProgramData/winlogbeat/certs/$NAME.key

    Linux (Filebeat):
      FILEBEAT_CA   = /etc/filebeat/certs/ca.crt
      FILEBEAT_CERT = /etc/filebeat/certs/$NAME.crt
      FILEBEAT_KEY  = /etc/filebeat/certs/$NAME.key
EOF
