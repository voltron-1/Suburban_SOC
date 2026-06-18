<#
  Suburban-SOC :: Windows Emulation -- Registry Hive Save (benign key)
  ATT&CK : T1003.002 (Credential Access)
  Detects: rules/sigma/proc_creation_win_reg_save_sam.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1003.002 -- Registry Hive Save (benign key)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_reg_save_sam.yml"

# --- safe-by-default telemetry generation ---
$out = Join-Path $env:TEMP "soc_emu.hiv"
reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" $out /y 2>$null
Remove-Item $out -ErrorAction SilentlyContinue
Write-Host "reg save against a NON-sensitive key (not SAM)."

Write-Host "[+] Emulation complete."
