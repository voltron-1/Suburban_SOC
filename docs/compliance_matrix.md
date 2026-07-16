# Compliance Mapping Matrix

This matrix maps Suburban-SOC's Sigma rules, Zeek/Filebeat telemetry, and existing SOPs against compliance frameworks (NIST CSF, NIST 800-171/53, and CIS Controls).

| Control Area | Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|---|
| **Identity & Access** | NIST CSF PR.AC-1 | Access to systems and assets is controlled | `net_zeek_ssh_bruteforce.yml`, `proc_creation_win_local_acct_create.yml` | SOP-009-rbac.md |
| **Audit & Accountability** | NIST 800-53 AU-2 | Event Logging | Zeek logs, Sysmon EID 1, Filebeat | SOP-010-audit-trail.md |
| **Data Protection** | CIS Control 3 | Data Protection & Privacy | `proc_creation_win_reg_save_sam.yml`, TLS-only stack | SOP-012-privacy-data-handling.md |
| **Incident Response** | NIST CSF RS.MI-1 | Incidents are contained and mitigated | `proc_creation_win_defender_tamper.yml` | IR_Sigma_Playbook.md |
| **Configuration Management** | NIST 800-171 3.4.1 | Establish and maintain baseline configurations | `sim_win_regsvr32_remote_sct.ps1` | SOP-007-change-management.md |
