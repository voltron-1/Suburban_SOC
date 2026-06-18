<#
  Suburban-SOC :: Windows Emulation -- Create Local Account
  ATT&CK : T1136.001 (Persistence)
  Detects: rules/sigma/proc_creation_win_local_acct_create.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1136.001 -- Create Local Account"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_local_acct_create.yml"

# --- safe-by-default telemetry generation ---
$u = "socEmuTmp"
net user $u "Sub!Soc#Emu1" /add 2>$null
net user $u /delete 2>$null
Write-Host "Created and removed throwaway account $u"

Write-Host "[+] Emulation complete."
