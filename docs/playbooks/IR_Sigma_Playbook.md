# Executive Summary
This playbook provides a structured methodology to respond to alerts triggered by the Sigma rules deployed in Suburban-SOC.

## Name
IR Sigma Playbook (Endpoint & Network Alerts)

## Problem Statement
Suspicious activities mapped to MITRE ATT&CK (e.g., PowerShell execution, LSASS memory dumping, clearing event logs) require a standardized triage and containment response.

## Objectives
- Rapidly identify and validate suspicious activities flagged by Sigma rules.
- Contain affected endpoints and neutralize threats.
- Eradicate artifacts, recover systems, and tune rules to reduce false positives.

## Compliance
- NIST CSF: DE.AE (Detection Processes), RS.AN (Analysis)
- CIS Controls: 17 (Incident Response Management)

## MITRE ATT&CK Framework
- T1059.001 Execution (PowerShell)
- T1003.001 Credential Access (LSASS Memory)
- T1070.001 Defense Evasion (Clear Windows Event Logs)
- T1053.005 Execution / Persistence (Scheduled Task)
- T1033 Discovery (System Owner/User Discovery)
- T1218.010 Defense Evasion (Regsvr32)
- T1105 Command and Control (Ingress Tool Transfer)
- T1047 Execution (WMI)
- T1136.001 Persistence (Local Account)
- T1574 Privilege Escalation / Lateral Movement (RDP Session Hijacking)

## Assumptions and Limitations
- Assumes EDR and Logstash pipelines are fully operational.
- Requires Tier 2 Analyst or higher for Endpoint Isolation actions.

# Analysis
Analysts must evaluate the process lineage and evaluate for known administrative behavior versus adversarial action.

## Monitoring and Notifications
Alerts are generated natively in the Elastic Detection Engine and forwarded to the SOAR webhook or ntfy topics.

## Playbook Verification
- An alert corresponding to a managed Sigma rule fires (e.g. `proc_creation_win_lsass_dump.yml`).
- Endpoint telemetry indicating suspicious child processes is visible in Kibana.

## Recommended Response Action(s)

### Identification
- **Validate the Alert**: Verify if the activity aligns with known IT administrative tasks, scheduled patching, or approved software deployments.
- **Identify Context**: Identify the affected endpoint(s), the user account associated with the process, and the exact timestamp.
- **Examine Process Lineage**: Look at the parent and child processes.
- **Payload Decoding**: For PowerShell alerts, extract and decode the Base64 payload.
- **Evaluate Persistence**: Review parameters for newly created Scheduled Tasks or Local Accounts.

### Containment
- **Endpoint Isolation**: Quarantine the compromised host from the network using EDR functionality or network NACs to prevent lateral movement.
- **Account Suspension**: Disable the compromised Active Directory user accounts, as well as any newly discovered local accounts.
- **Perimeter Blocking**: Block malicious C2 IP addresses or domains identified during the investigation at the perimeter firewalls and web proxies.

### Eradication & Recovery
- **Terminate Processes**: Kill active malicious RDP sessions, background PowerShell tasks, or unauthorized WMI processes.
- **Remove Artifacts**: Delete malicious scheduled tasks, unauthorized registry modifications, and dropped payload files.
- **Credential Reset**: Force an immediate password reset for all user accounts that were exposed on the compromised host, especially if LSASS was accessed.
- **System Scans**: Run deep anti-virus and EDR scans to ensure all residual malware components are removed.
- **Restore & Reconnect**: Reconnect the endpoint to the network only once it is verified clean. Reimage the machine if deep persistence or rootkits are suspected.
- **Rule Tuning**: Update the Sigma rule falsepositives or exclusions list if the alert was triggered by a legitimate tool.

# References and Resources
- Suburban-SOC Emulation Coverage Checklist
