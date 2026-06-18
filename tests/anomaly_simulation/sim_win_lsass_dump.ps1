<#
  Suburban-SOC :: Windows Emulation -- LSASS Memory Dump (benign target)
  ATT&CK : T1003.001 (Credential Access)
  Detects: rules/sigma/proc_creation_win_lsass_dump.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1003.001 -- LSASS Memory Dump (benign target)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_lsass_dump.yml"

# --- safe-by-default telemetry generation ---
$p = Start-Process notepad -PassThru; Start-Sleep -Seconds 1
$dmp = Join-Path $env:TEMP "soc_emu_benign.dmp"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($p.Id) $dmp full
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Remove-Item $dmp -ErrorAction SilentlyContinue
Write-Host "MiniDumped a benign process (notepad), NOT lsass."

Write-Host "[+] Emulation complete."
