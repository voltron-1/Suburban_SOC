# Suburban-SOC Final Report

> **Academic snapshot of the original design.** Superseded by [Architecture](Architecture) and the [repo README](https://github.com/voltron-1/Suburban_SOC#readme) — use those for the current system.

## Executive Summary
The Suburban-SOC project addresses the growing need for enhanced cybersecurity in residential environments. By establishing a mesh-based wireless network with centralized Security Operations Center (SOC) management, it replaces insecure home networks with a unified system. This pipeline captures and analyzes network traffic to identify potential threats, delivering enterprise-grade security and simple, plug-and-play connectivity for homeowners.

## Network Architecture & Scope
*   **Mesh Network Architecture:** Built around a single main gateway router acting as the mesh controller, distributing access through 6 remote wireless nodes.
*   **Targeted Monitoring:** We exclusively monitor and capture boundary HTTP traffic entering and exiting the main router.
*   **Security Justification:** This targeted approach ensures system efficiency by bypassing internal LAN noise (like local file sharing) and heavily encrypted tunnel traffic, avoiding unnecessary resource drain.
*   **Physical Flow:** ISP ➔ Main Gateway Router ➔ 6 Remote Wireless Nodes ➔ End-User Devices.

## Data Acquisition
*   **Implementation:** Using OpenWrt, we enabled remote packet capture directly on the gateway router.
*   **Flow & Storage:** The router mirrors the targeted network traffic and securely forwards it to a centralized host computer. This ensures continuous storage of raw `.pcap` files without overwhelming the router’s limited local storage.

## Processing Pipeline (Zeek & Filebeat)
*   **Zeek Integration:** Raw PCAPs are processed using a Zeek container, configured natively (`LogAscii::use_json=T`) to transform packets into structured, human-readable JSON security logs.
*   **Log Shipping:** A Filebeat agent (`filebeat.yml`) continuously monitors the Zeek output directory, actively harvesting the generated `.log` files.
*   **Pipeline Flow:** Host Computer (Raw PCAP) ➔ Zeek (JSON Transformation) ➔ Filebeat (Harvests & Ships).

## Visualization & ELK Integration
*   **Logstash Routing:** Filebeat streams the JSON logs directly into Logstash (Port `5044`), which parses and enriches the data (e.g., ECS normalization, GeoIP lookups).
*   **Elasticsearch Storage:** The enriched logs are indexed using a scalable daily categorization strategy (`logstash-security-%{+YYYY.MM.dd}`), enabling rapid and efficient queries.
*   **Kibana Dashboard:** A user-friendly interface visualizes network trends and anomalies, allowing SOC analysts to monitor both real-time and historical security events.

## SOAR Response Layer (Milestones 5 & 6)

> **2026-09-01 correction:** this section originally described a Kibana
> Watcher as the SOAR trigger. [#267](https://github.com/voltron-1/Suburban_SOC/issues/267)
> retired that path (Watcher isn't licensed on this stack's Basic license) in
> favor of an ingest-time, HMAC-signed trigger fired directly by Logstash —
> see [Architecture](Architecture) for the current diagram. The bullets below
> are corrected accordingly; the underlying quarantine mechanics (AI Agent
> triage, `isolate.sh`, idempotent `uci` rules) are unchanged.

*   **MAC-Based Quarantine:** Logstash's own ingest-time trigger (no Watcher) fires an HMAC-signed webhook on high-confidence IOC hits and POSTs to a Flask AI Agent (`agent_app.py`) on port 5000. The agent runs LLM triage (MITRE ATT&CK summary), then *drafts* containment to a human-approval queue that, once approved, invokes `isolate.sh` to SSH into OpenWrt and install a persistent `uci` MAC-DROP firewall rule. MAC addressing was chosen over IP because it survives DHCP rotation and is harder to spoof at Layer 2.
*   **Real-Time Push Alerts:** Critical events trigger both an ntfy mobile push (`subsoc-alerts-*` topic) and a rich Discord embed to the SOC channel — both include device IP, MAC, reason, and the AI-generated analysis. Discord delivery is gated on a `DISCORD_WEBHOOK_URL` env var with graceful no-op when unset.
*   **Layer-2 Telemetry:** Zeek's `policy/protocols/conn/mac-logging` policy emits `orig_l2_addr`/`resp_l2_addr` on every conn log; Logstash maps these to ECS `source.mac`/`destination.mac` so analysts can filter and visualize by device hardware identity.
*   **Idempotent Response:** `isolate.sh` checks for an existing `SOAR_QUARANTINE_<MAC>` rule before adding a new one, preventing duplicate uci entries if the ingest-time trigger re-fires on the same event.

## Challenges & Limitations
1.  **Encrypted Traffic Blind Spot:** The pipeline monitors boundary traffic but cannot inspect deep HTTPS payloads without an active SSL/TLS proxy.
2.  **SOAR Trigger Scope:** *(Updated 2026-09-01 — the trigger this originally described, a Kibana Watcher firing only on `threat.indicator.domain`, was retired by [#267](https://github.com/voltron-1/Suburban_SOC/issues/267).)* The current ingest-time Logstash trigger fires on both a `zeek.intel` IOC hit and a thresholded SSH brute-force notice (T1110). Port scans (`Scan::Port_Scan`, T1046) are deliberately and indefinitely dashboard-only — a bare SYN with no completed handshake carries no source-authenticity signal at this deployment's capture vantage point ([#331](https://github.com/voltron-1/Suburban_SOC/issues/331)) — and stay analyst-review-only by design, not as an unaddressed gap.
3.  **Unbenchmarked Stress Limits:** The OpenWrt gateway’s ability to continuously stream massive packet volumes has not yet been stress-tested for stability under extreme network loads.

## Future Enhancements
*   ~~**Widen SOAR Triggers:** Extend the Watcher to fire on `Scan::Port_Scan` and `zeek.ssh` brute-force cascades, closing the auto-response gap for the most common opportunistic attacks.~~ *(Done for SSH brute-force cascades — see the corrected Challenges & Limitations entry above. Port-scan was evaluated and deliberately kept dashboard-only, not left undone — [#331](https://github.com/voltron-1/Suburban_SOC/issues/331).)*
*   **SSL/TLS Decryption Proxy:** Implement an inspection proxy to analyze deep HTTPS payloads, eliminating the encrypted traffic blind spot.
*   **Live Threat Intelligence Feed:** Integrate continuously updated lists of malicious IPs and file hashes directly into Zeek so unknown indicators light up the same ingest-time trigger pathway.
*   **Anomaly Simulation Harness:** Build `tests/anomaly_simulation/` scripts (Issue #22) to continuously validate that nmap, brute-force, and malware-download scenarios still trigger the expected detections and quarantine actions after future refactors.
