<#
  Suburban-SOC :: Windows Emulation -- Inhibit System Recovery (shadow copies)
  ATT&CK : T1490 (Impact)
  Detects: rules/sigma/proc_creation_win_vss_delete_shadows.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1490 -- Inhibit System Recovery (shadow copies)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_vss_delete_shadows.yml"

# --- safe-by-default telemetry generation ---
vssadmin list shadows 2>$null
Write-Host "[safe] would run: vssadmin delete shadows /all /quiet  (NOT deleting)"

if ($Armed) {
    Write-Warning 'ARMED MODE -- executing the real technique.'
    if ((Read-Host "Type DELETE to really remove ALL shadow copies") -eq "DELETE") {
      vssadmin delete shadows /all /quiet
      Write-Warning "Shadow copies deleted (restore points lost)."
    } else { Write-Host "Aborted." }
}

Write-Host "[+] Emulation complete."
