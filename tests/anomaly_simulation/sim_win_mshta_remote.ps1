<#
  Suburban-SOC :: Windows Emulation -- Mshta Execution
  ATT&CK : T1218.005 (Defense Evasion)
  Detects: rules/sigma/proc_creation_win_mshta_remote.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1218.005 -- Mshta Execution"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_mshta_remote.yml"

# --- safe-by-default telemetry generation ---
$hta = Join-Path $env:TEMP "soc_emu.hta"
[IO.File]::WriteAllText($hta,'<html><script>close()</script></html>')
Start-Process mshta.exe $hta; Start-Sleep 1
Remove-Item $hta -ErrorAction SilentlyContinue

Write-Host "[+] Emulation complete."
