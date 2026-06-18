<#
  Suburban-SOC :: Windows Emulation -- Windows Service Creation
  ATT&CK : T1543.003 (Persistence)
  Detects: rules/sigma/proc_creation_win_service_creation_sc.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1543.003 -- Windows Service Creation"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_service_creation_sc.yml"

# --- safe-by-default telemetry generation ---
sc.exe create SuburbanSOCEmu binPath= "cmd.exe /c exit" start= demand 2>$null
sc.exe delete SuburbanSOCEmu 2>$null
Write-Host "Created and removed a throwaway service (reversible; needs admin)."

Write-Host "[+] Emulation complete."
