<#
  Suburban-SOC :: Windows Emulation -- WMI Process Creation
  ATT&CK : T1047 (Execution)
  Detects: rules/sigma/proc_creation_win_wmi_process_create.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1047 -- WMI Process Creation"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_wmi_process_create.yml"

# --- safe-by-default telemetry generation ---
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="notepad.exe"}
Start-Sleep 1
if ($r.ProcessId) { Stop-Process -Id $r.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host "Spawned and closed notepad via WMI."

Write-Host "[+] Emulation complete."
