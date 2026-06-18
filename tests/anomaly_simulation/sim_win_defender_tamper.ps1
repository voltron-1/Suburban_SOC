<#
  Suburban-SOC :: Windows Emulation -- Impair Defenses / Defender Tamper
  ATT&CK : T1562.001 (Defense Evasion)
  Detects: rules/sigma/proc_creation_win_defender_tamper.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1562.001 -- Impair Defenses / Defender Tamper"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_defender_tamper.yml"

# --- safe-by-default telemetry generation ---
Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object RealTimeProtectionEnabled,AntivirusEnabled | Format-List
Write-Host "[safe] would run: Set-MpPreference -DisableRealtimeMonitoring `$true"

if ($Armed) {
    Write-Warning 'ARMED MODE -- executing the real technique.'
    if ((Read-Host "Type DISABLE to really turn off real-time protection") -eq "DISABLE") {
      Set-MpPreference -DisableRealtimeMonitoring $true
      Write-Warning "Real-time protection DISABLED. Re-enable: Set-MpPreference -DisableRealtimeMonitoring \$false"
    } else { Write-Host "Aborted." }
}

Write-Host "[+] Emulation complete."
