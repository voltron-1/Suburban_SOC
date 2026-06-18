<#
  Suburban-SOC :: Windows Emulation -- Encoded PowerShell
  ATT&CK : T1059.001 (Execution)
  Detects: rules/sigma/proc_creation_win_powershell_encoded.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1059.001 -- Encoded PowerShell"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_powershell_encoded.yml"

# --- safe-by-default telemetry generation ---
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'SuburbanSOC-Emulation'"))
powershell.exe -NoProfile -EncodedCommand $enc

Write-Host "[+] Emulation complete."
