# Suburban-SOC — SIEM Detection Queries (KQL/Lucene)

> **Generated** by `scripts/setup/build_kql_docs.py` from `rules/sigma/*.yml`
> through the `configs/detections/suburban-soc-ecs.yml` field pipeline. Do not
> hand-edit — re-run the generator. Queries target **`process.args`** (this
> stack's field), NOT the ECS-standard `process.command_line`.

**19 rules.** Each query is the exact Lucene the Sigma rule compiles to.

## Malicious File Download via Bitsadmin

- **Rule:** `proc_creation_win_bitsadmin_download.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1105

```
process.executable:*\\bitsadmin.exe AND process.args:*\/transfer*
```

## Payload Decoding via Certutil

- **Rule:** `proc_creation_win_certutil_decode.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1140

```
process.executable:*\\certutil.exe AND process.args:*decode*
```

## Clearing Windows Event Logs via Wevtutil

- **Rule:** `proc_creation_win_clear_event_logs.yml` · **level:** high · **status:** stable · **ATT&CK:** T1070.001

```
process.executable:*\\wevtutil.exe AND (process.args:(*\ cl\ * OR *\ clear\-log\ *))
```

## Windows Defender Real-Time Protection Disabled

- **Rule:** `proc_creation_win_defender_tamper.yml` · **level:** high · **status:** stable · **ATT&CK:** T1562.001

```
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.args:*Set\-MpPreference* AND process.args:*Disable*)
```

## Domain Group Discovery via Net.exe

- **Rule:** `proc_creation_win_domain_group_discovery.yml` · **level:** low · **status:** stable · **ATT&CK:** T1087.002

```
(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.args:*group* AND process.args:*\/domain*)
```

## Local User Account Creation via Net.exe

- **Rule:** `proc_creation_win_local_acct_create.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1136.001

```
(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.args:*user* AND process.args:*\/add*)
```

## LSASS Memory Dump via Comsvcs.dll

- **Rule:** `proc_creation_win_lsass_dump.yml` · **level:** high · **status:** stable · **ATT&CK:** T1003.001

```
process.executable:*\\rundll32.exe AND (process.args:*comsvcs.dll* AND process.args:*MiniDump*)
```

## Mshta Remote or Script Payload Execution

- **Rule:** `proc_creation_win_mshta_remote.yml` · **level:** high · **status:** stable · **ATT&CK:** T1218.005

```
process.executable:*\\mshta.exe AND (process.args:(*http* OR *javascript* OR *vbscript*))
```

## Domain Controller Discovery via Nltest

- **Rule:** `proc_creation_win_nltest_discovery.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1018

```
process.executable:*\\nltest.exe AND (process.args:(*\/dclist\:* OR *\/domain_trusts* OR *\/dsgetdc\:*))
```

## Suspicious PowerShell Encoded Command Execution

- **Rule:** `proc_creation_win_powershell_encoded.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1059.001

```
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.args:(*\ \-enc* OR *\ \-EncodedCommand* OR *\ \-ec\ *))
```

## RDP Session Hijacking via Tscon

- **Rule:** `proc_creation_win_rdp_hijack_tscon.yml` · **level:** high · **status:** stable · **ATT&CK:** T1574

```
process.executable:*\\tscon.exe AND process.args:*\/dest\:*
```

## SAM Hive Dump via Reg.exe

- **Rule:** `proc_creation_win_reg_save_sam.yml` · **level:** high · **status:** stable · **ATT&CK:** T1003.002

```
process.executable:*\\reg.exe AND (process.args:*save* AND process.args:*hklm\\sam*)
```

## Regsvr32 Execution from Remote Server

- **Rule:** `proc_creation_win_regsvr32_remote_sct.yml` · **level:** critical · **status:** stable · **ATT&CK:** T1218.010

```
process.executable:*\\regsvr32.exe AND (process.args:*\/i\:http* AND process.args:*scrobj.dll*)
```

## Registry Run Key Persistence via Reg.exe

- **Rule:** `proc_creation_win_run_key_persistence.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1547.001

```
process.executable:*\\reg.exe AND (process.args:*add* AND process.args:*CurrentVersion\\Run*)
```

## Scheduled Task Creation via Schtasks

- **Rule:** `proc_creation_win_scheduled_task.yml` · **level:** low · **status:** stable · **ATT&CK:** T1053.005

```
process.executable:*\\schtasks.exe AND (process.args:*\/create* AND process.args:*\/tn*)
```

## Windows Service Creation via Sc.exe

- **Rule:** `proc_creation_win_service_creation_sc.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1543.003

```
process.executable:*\\sc.exe AND (process.args:*create* AND process.args:*binpath*)
```

## Suspicious System Owner/User Discovery

- **Rule:** `proc_creation_win_user_discovery.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1033

```
process.executable:*\\whoami.exe AND process.args:*\/all*
```

## Shadow Copy Deletion via Vssadmin

- **Rule:** `proc_creation_win_vss_delete_shadows.yml` · **level:** high · **status:** stable · **ATT&CK:** T1490

```
process.executable:*\\vssadmin.exe AND (process.args:*delete* AND process.args:*shadows*)
```

## WMI Process Call Create

- **Rule:** `proc_creation_win_wmi_process_create.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1047

```
process.executable:*\\wmic.exe AND (process.args:*process* AND process.args:*call* AND process.args:*create*)
```
