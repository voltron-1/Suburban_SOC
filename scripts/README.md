# Suburban SOC - Scripts

This directory contains utility and setup scripts designed to automate the deployment, data collection, and log ingestion pipeline for the Suburban SOC project. 

The primary goal of these scripts is to capture network traffic from remote routing devices, parse it using Zeek, and securely stream those logs via Filebeat to an ELK (Elasticsearch, Logstash, Kibana) stack.

## Architecture & Workflow

1. **Traffic Capture (`tcpdump`)**: Devices like the OpenWrt router capture raw network packets on specific interfaces (e.g., `br-lan` or `bat0`).
2. **Log Translation (`Zeek Docker`)**: The raw packet capture is piped over SSH directly into a local Zeek Docker container. Zeek decodes this data on-the-fly and outputs structured JSON connection logs.
3. **Log Ingestion (`Filebeat`)**: A locally installed Filebeat service monitors the Zeek log directory and securely ships the JSON data to Logstash.
4. **Visualization (`Kibana`)**: Logstash processes these events into Elasticsearch, making it available for real-time analysis in Kibana dashboards.

---

## Script Overviews

All main administrative scripts are currently located in the `setup/` subdirectory. However, for local developer environment setup, use the ones located in the root of `scripts/`.

### Developer Onboarding

* **`onboard_dev.ps1`** (Windows) / **`onboard_dev.sh`** (Linux/WSL): 
  Run this script to automatically check your local environment for necessary development dependencies (e.g., Git, GitHub CLI, Docker, OpenSSH, WSL). Ensures you are ready to use the data streaming tools and Agile GitHub scripts.

### Setup and Configuration

* **`install_filebeat.sh`**: 
  Installs Filebeat on Debian/Ubuntu-based systems by adding the Elastic APT repository and installing the agent. Ensure you run this on the machine hosting the Zeek logs.
* **`filebeat_config_snippet.yml`**: 
  Configuration lines intended for your `filebeat.yml` to specify the location of the Zeek JSON logs (`/storage/PCAP/zeek_logs/*.log`) and point the output directly to Logstash (`localhost:5044`).

### Network Streaming & Zeek Integration

* **`stream_capture.sh <bat0|br-lan|raw>`** (#173 — replaces the formerly-separate
  `stream_bat0_data.sh`/`stream_br_lan_data.sh`/`stream_raw_data.sh`):
  Pipes live traffic into the Zeek container to produce JSON output, one mode per
  capture source:
  * `bat0` — SSH to the mesh router (`ROUTER_IP`, default `10.18.81.1`), captures
    the B.A.T.M.A.N. advanced mesh interface (`bat0`).
  * `br-lan` — SSH to the LAN router (`ROUTER_IP`, default `192.168.1.233`),
    captures the standard bridged LAN interface (`br-lan`).
  * `raw` — streams raw live traffic locally from the `eth0` interface (no SSH);
    must be run with sudo.
* **`zeek_connect_host.sh`**: 
  Starts an interactive Zeek container bound directly to the host network layout, listening for any traffic on `eth0`.
* **`zeek_run_pcap.sh`**: 
  Used for offline analysis. Mounts a static PCAP file (`http.pcap`) and instructs Zeek to parse it to JSON.

### Utility Scripts

* **`clear_logs.sh`**: 
  Quickly purges and cleans existing Zeek logs in the `/storage/PCAP/zeek_logs/` directory to prevent disk bloat or to reset the environment.

## Usage

To use any of these components, ensure you have the appropriate permissions (root/sudo) and have made the script executable:

```bash
cd scripts/setup/
chmod +x <script_name>.sh
./<script_name>.sh
```

**Note**: Ensure your Docker engine is running before executing any Zeek ingestion or streaming tasks.
