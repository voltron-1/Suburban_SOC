<#
  Suburban-SOC :: Windows Emulation -- Certutil Decode
  ATT&CK : T1140 (Defense Evasion)
  Detects: rules/sigma/proc_creation_win_certutil_decode.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1140 -- Certutil Decode"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_certutil_decode.yml"

# --- safe-by-default telemetry generation ---
$b64 = Join-Path $env:TEMP "soc_emu.b64"
$out = Join-Path $env:TEMP "soc_emu.txt"
[IO.File]::WriteAllText($b64,[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("SuburbanSOC")))
certutil -decode $b64 $out | Out-Null
Remove-Item $b64,$out -ErrorAction SilentlyContinue

Write-Host "[+] Emulation complete."
