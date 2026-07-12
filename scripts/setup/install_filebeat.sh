#!/usr/bin/env bash
# Install Filebeat 9.x — matches ELK stack version (9.3.2)
# Run with: sudo bash scripts/setup/install_filebeat.sh

set -euo pipefail

echo "[INFO] Installing Filebeat 9.x..."

# Import the Elastic GPG key AND verify its fingerprint before trusting the repo
# (audit P2-10) — piping a fetched key straight into the keyring trusts whatever the
# network returns. The expected fingerprint is Elastic's published signing key.
ELASTIC_GPG_FPR="46095ACC8548582C1A2699A9D27D666CD88E42B4"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
GOT_FPR="$(gpg --show-keys --with-colons /usr/share/keyrings/elastic-keyring.gpg 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
if [ "$GOT_FPR" != "$ELASTIC_GPG_FPR" ]; then
  echo "[ERR] Elastic GPG fingerprint mismatch (got '${GOT_FPR}', expected '${ELASTIC_GPG_FPR}') — refusing to add the repo." >&2
  sudo rm -f /usr/share/keyrings/elastic-keyring.gpg
  exit 1
fi
echo "[PASS] Elastic GPG key verified ($ELASTIC_GPG_FPR)"

# Install prerequisite
sudo apt-get install -y apt-transport-https

# Add Elastic 9.x APT repository
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-9.x.list

# Install Filebeat
sudo apt-get update && sudo apt-get install -y filebeat

echo "[PASS] Filebeat installed: $(filebeat version 2>/dev/null | head -1)"
echo "[INFO] Next: apply config and start with soc_pipeline.sh -> [6] SOP-002"
