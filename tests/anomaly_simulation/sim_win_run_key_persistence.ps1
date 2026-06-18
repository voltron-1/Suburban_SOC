<#
  Suburban-SOC :: Windows Emulation -- Registry Run Key Persistence
  ATT&CK : T1547.001 (Persistence)
  Detects: rules/sigma/proc_creation_win_run_key_persistence.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1547.001 -- Registry Run Key Persistence"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_run_key_persistence.yml"

# --- safe-by-default telemetry generation ---
$k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SuburbanSOCEmu /t REG_SZ /d "cmd.exe /c exit" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SuburbanSOCEmu /f
Write-Host "Added and removed a throwaway Run key (reversible)."

Write-Host "[+] Emulation complete."
