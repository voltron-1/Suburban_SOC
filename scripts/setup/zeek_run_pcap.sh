#!/bin/bash
# Zeek RUN command — Offline PCAP Analysis
# When PCAP_FILE points to a real file, analyzes ONLY that file (the path the
# menu passes). Otherwise falls back to processing every *.pcap in
# /storage/PCAP/. Outputs JSON logs to /storage/PCAP/zeek_logs/ for Filebeat.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"
PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

sudo mkdir -p "$LOG_DIR"

# Processes one PCAP file through Zeek and moves its JSON logs into LOG_DIR,
# suffixed with the pcap name. Re-running a given pcap overwrites only its own
# logs (no cross-pcap duplication), so there is no need to wipe LOG_DIR.
# The pcap is bind-mounted read-only at a fixed path, so it can live anywhere
# on disk -- not just under /storage/PCAP.
process_pcap() {
  local pcap="$1"
  if [ ! -s "$pcap" ]; then
    echo "[WARN] Skipping empty or missing file: $pcap"
    return
  fi

  local pcap_name
  pcap_name=$(basename "$pcap" .pcap)
  echo "[INFO] Processing $pcap..."

  sudo mkdir -p /storage/PCAP/temp_zeek
  docker run --rm \
    -v /storage/PCAP:/data \
    -v /storage/PCAP/intel:/data/intel \
    -v "$pcap":/input.pcap:ro \
    -w /data/temp_zeek \
    zeek/zeek \
    zeek -C -r /input.pcap LogAscii::use_json=T /data/intel/config.zeek

  # Move and rename logs into the main zeek_logs directory so Filebeat catches them.
  for log in /storage/PCAP/temp_zeek/*.log; do
    if [ -f "$log" ]; then
      local base
      base=$(basename "$log" .log)
      sudo mv "$log" "${LOG_DIR}/${base}_${pcap_name}.log"
    fi
  done
  sudo rm -rf /storage/PCAP/temp_zeek
  echo "[INFO] Done: $pcap_name"
}

# Single-file mode: a specific, existing PCAP_FILE was provided (e.g. from the menu).
if [ -n "$PCAP_FILE" ] && [ -f "$PCAP_FILE" ]; then
  echo "[INFO] Single-file mode: $PCAP_FILE"
  process_pcap "$PCAP_FILE"
else
  # Batch mode: no specific file -- process every PCAP in /storage/PCAP.
  echo "[INFO] Batch mode: processing all PCAPs in /storage/PCAP"
  for pcap in /storage/PCAP/*.pcap; do
    process_pcap "$pcap"
  done
fi

echo "[INFO] Analysis complete. Logs in ${LOG_DIR}"
