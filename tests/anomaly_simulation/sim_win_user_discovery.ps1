<#
  Suburban-SOC :: Windows Emulation -- System Owner / User Discovery
  ATT&CK : T1033 (Discovery)
  Detects: rules/sigma/proc_creation_win_user_discovery.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1033 -- System Owner / User Discovery"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_user_discovery.yml"

# --- safe-by-default telemetry generation ---
whoami /all
net user

Write-Host "[+] Emulation complete."
