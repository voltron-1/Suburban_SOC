<#
  Suburban-SOC :: Windows Emulation -- RDP Session Hijack (tscon)
  ATT&CK : T1563.002 (Lateral Movement)
  Detects: rules/sigma/proc_creation_win_rdp_hijack_tscon.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1563.002 -- RDP Session Hijack (tscon)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_rdp_hijack_tscon.yml"

# --- safe-by-default telemetry generation ---
query session 2>$null
Write-Host "[safe] would run: tscon <id> /dest:<session>"

if ($Armed) {
    Write-Warning 'ARMED MODE -- executing the real technique.'
    $id = Read-Host "Session ID to tscon (your own lab session)"
    if ($id) { tscon $id /dest:console } else { Write-Host "Aborted." }
}

Write-Host "[+] Emulation complete."
