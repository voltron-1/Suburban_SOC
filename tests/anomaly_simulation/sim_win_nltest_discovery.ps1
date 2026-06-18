<#
  Suburban-SOC :: Windows Emulation -- Domain Trust Discovery (nltest)
  ATT&CK : T1482 (Discovery)
  Detects: rules/sigma/proc_creation_win_nltest_discovery.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1482 -- Domain Trust Discovery (nltest)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_nltest_discovery.yml"

# --- safe-by-default telemetry generation ---
nltest /domain_trusts 2>$null
nltest /dclist: 2>$null

Write-Host "[+] Emulation complete."
