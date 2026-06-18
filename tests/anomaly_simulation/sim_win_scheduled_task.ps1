<#
  Suburban-SOC :: Windows Emulation -- Scheduled Task Persistence
  ATT&CK : T1053.005 (Persistence)
  Detects: rules/sigma/proc_creation_win_scheduled_task.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1053.005 -- Scheduled Task Persistence"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_scheduled_task.yml"

# --- safe-by-default telemetry generation ---
schtasks /create /tn SuburbanSOCEmu /tr "cmd.exe /c exit" /sc once /st 23:59 /f
schtasks /delete /tn SuburbanSOCEmu /f
Write-Host "Created and removed a throwaway scheduled task (reversible)."

Write-Host "[+] Emulation complete."
