#!/usr/bin/env bash
# clearing Zeek log files (reset environment)
# audit P3: set -euo pipefail + guard the destructive rm so an unset/empty LOG_DIR
# can never expand to `rm -rf /*`. Deletes the CONTENTS of the dir, not the dir.
set -euo pipefail

LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# Refuse to run on an empty/root/suspicious path.
case "$LOG_DIR" in
  ""|"/"|"/*"|".") echo "[ERR] refusing to clear '$LOG_DIR'" >&2; exit 1 ;;
esac
if [ ! -d "$LOG_DIR" ]; then
  echo "[INFO] $LOG_DIR does not exist — nothing to clear."
  exit 0
fi

echo "[INFO] Clearing contents of $LOG_DIR ..."
sudo find "$LOG_DIR" -mindepth 1 -delete
echo "[PASS] $LOG_DIR cleared."
