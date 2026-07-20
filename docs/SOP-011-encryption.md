# Executive Summary
This Standard Operating Procedure (SOP) defines how Suburban-SOC telemetry (customer security data) is encrypted in transit across all network hops and at rest on the storage volumes.

## Name
SOP-011 — Encryption in Transit & at Rest

## Problem Statement
Unencrypted telemetry risks exposing sensitive customer data and authentication tokens to network sniffers or physical disk theft, violating basic confidentiality requirements.

## Objectives
- Enforce TLS 1.2+ for all data in transit (Endpoint → Logstash, Logstash → ES, Kibana → ES).
- Ensure inter-node ES transport is TLS-encrypted.
- Ensure data at rest relies on full-disk/volume encryption.

## Compliance
- **NIST CSF**: PR.DS-1 (Data-at-rest protection), PR.DS-2 (Data-in-transit protection).
- **SOC 2**: Confidentiality (CC6.1, CC6.7).

## MITRE ATT&CK Framework
- Mitigates TA0009 Collection (T1040 Network Sniffing).

## Assumptions and Limitations
- The Elasticsearch setup container successfully mints the CA and PKCS8 keys.
- Data-at-rest encryption relies on the underlying host or cloud provider (e.g., LUKS, EBS encryption).

# Analysis
Every network hop in the SOC stack is secured. Internal mesh hops use HMAC signatures for authenticity, while TLS secures the transport. Certificate generation is idempotent and handled automatically by the stack setup scripts.

## Monitoring and Notifications
The CCM (SOP-013) continuously verifies TLS configurations. The `verify_encryption.sh` script provides a point-in-time check.

## Playbook Verification
To verify encryption controls:
1. Run `bash scripts/setup/verify_encryption.sh`.
2. Confirm the script exits with `0` (healthy), proving that plaintext connections to `:9200` are refused and TLS handshakes succeed.

## Recommended Response Action(s)

### Identification
If TLS fails (e.g., Filebeat logs a TLS handshake failure):
- Identify if the `certs` volume was recently recreated.
- Run `verify_encryption.sh` to pinpoint which hop is failing.

### Containment
If a certificate is compromised or missing:
- Stop the affected components to prevent plaintext transmission.
- Do not attempt to bypass TLS (`curl -k` is prohibited in production).

### Eradication & Recovery
To rotate or recover certificates:
1. Delete the compromised cert material from the `certs` volume.
2. Re-run `docker compose up setup cert_pkcs8`.
3. Re-provision the host Filebeat CA and client cert, then run `sudo systemctl restart filebeat`.
4. Document the host disk encryption status (LUKS/SSE) in the audit binder.

# References and Resources
- `scripts/setup/verify_encryption.sh`
- `scripts/setup/docker-compose.yml`
