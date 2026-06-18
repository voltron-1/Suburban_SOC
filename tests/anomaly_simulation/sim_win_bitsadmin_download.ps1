<#
  Suburban-SOC :: Windows Emulation -- BITS Ingress Tool Transfer
  ATT&CK : T1105 (Command and Control)
  Detects: rules/sigma/proc_creation_win_bitsadmin_download.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1105 -- BITS Ingress Tool Transfer"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_bitsadmin_download.yml"

# --- safe-by-default telemetry generation ---
$Url = "http://example.com/robots.txt"
$Dst = Join-Path $env:TEMP "soc_emu_bits.txt"
bitsadmin /transfer SocEmuJob /download /priority normal $Url $Dst 2>$null
Remove-Item $Dst -ErrorAction SilentlyContinue

Write-Host "[+] Emulation complete."
