<#
  Suburban-SOC :: Windows Emulation -- Regsvr32 Execution
  ATT&CK : T1218.010 (Defense Evasion)
  Detects: rules/sigma/proc_creation_win_regsvr32_remote_sct.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1218.010 -- Regsvr32 Execution"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_regsvr32_remote_sct.yml"

# --- safe-by-default telemetry generation ---
regsvr32.exe /s /n /u /i:"about:blank" scrobj.dll 2>$null
Write-Host "regsvr32 invoked with a harmless about:blank target (no remote .sct)."

Write-Host "[+] Emulation complete."
