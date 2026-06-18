<#
  Suburban-SOC :: Windows Emulation -- Domain Group Discovery
  ATT&CK : T1069.002 (Discovery)
  Detects: rules/sigma/proc_creation_win_domain_group_discovery.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1069.002 -- Domain Group Discovery"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_domain_group_discovery.yml"

# --- safe-by-default telemetry generation ---
net group "Domain Admins" /domain 2>$null
if ($LASTEXITCODE -ne 0) { net localgroup administrators }

Write-Host "[+] Emulation complete."
