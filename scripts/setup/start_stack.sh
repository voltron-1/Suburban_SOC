#!/usr/bin/env bash
# start_stack.sh -- bring the Suburban-SOC compose project up once the RIGHT Docker
# engine answers. Run by suburban-soc-stack.service at boot (Option B in
# findings/20261104-docker-engine-split.md).
#
# Why this exists: on the capture host two engines can own /var/run/docker.sock (native
# dockerd from systemd, and Docker Desktop's WSL proxy, which replaces the socket once
# Desktop is launched). The compose project and its volumes live in Docker Desktop's
# engine. Docker Desktop is not started by WSL, so after a reboot nothing started the
# stack. This script waits for the expected engine, then runs `docker compose up -d`.
#
# It refuses to start the stack on any other engine: `docker info` must report
# SOC_DOCKER_ENGINE_NAME (default docker-desktop). Starting it on the native engine would
# create a second, empty copy of the stack with fresh volumes and a new CA.
#
# Exit codes: 0 ok; 75 (EX_TEMPFAIL) engine never appeared within the wait;
#             78 (EX_CONFIG) scripts/setup/.env missing; otherwise compose's own status.
#
# Knobs (env): SOC_DOCKER_ENGINE_NAME, SOC_ENGINE_WAIT_SECONDS (default 14400 = 4 h, long
# enough for a sign-in), SOC_ENGINE_POLL_SECONDS (default 10).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED="${SOC_DOCKER_ENGINE_NAME:-docker-desktop}"
WAIT="${SOC_ENGINE_WAIT_SECONDS:-14400}"
POLL="${SOC_ENGINE_POLL_SECONDS:-10}"

# compose reads .env from this directory; without it every password is blank.
if [[ ! -f "$HERE/.env" ]]; then
  echo "start_stack: FATAL $HERE/.env is missing; refusing to start the stack with blank credentials (cp .env.example .env and fill it)" >&2
  exit 78
fi

deadline=$(( $(date +%s) + WAIT ))
last=""
while :; do
  name="$(timeout 10 docker info --format '{{.Name}}' 2>/dev/null || true)"
  if [[ "$name" == "$EXPECTED" ]]; then
    break
  fi
  state="${name:-no engine answering}"
  if [[ "$state" != "$last" ]]; then
    echo "start_stack: waiting for engine '$EXPECTED' (currently: $state)" >&2
    last="$state"
  fi
  if (( $(date +%s) >= deadline )); then
    echo "start_stack: gave up after ${WAIT}s; engine '$EXPECTED' never answered (last seen: $state). Start Docker Desktop." >&2
    exit 75
  fi
  sleep "$POLL"
done

echo "start_stack: engine '$EXPECTED' is up; starting the compose project" >&2
cd "$HERE"
# --no-recreate: at boot, start what exists; never rebuild containers because the
# compose file drifted. Intentional changes go through a manual `docker compose up -d`.
exec docker compose up -d --no-recreate
