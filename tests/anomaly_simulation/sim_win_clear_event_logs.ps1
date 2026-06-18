<#
  Suburban-SOC :: Windows Emulation -- Clear Windows Event Logs
  ATT&CK : T1070.001 (Defense Evasion)
  Detects: rules/sigma/proc_creation_win_clear_event_logs.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  SAFE by default. The real, potentially destructive action is gated behind -Armed.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1070.001 -- Clear Windows Event Logs"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_clear_event_logs.yml"

# --- safe-by-default telemetry generation ---
Write-Host "[safe] would run: wevtutil cl <log>  (NOT clearing real logs)"
Get-WinEvent -ListLog Security,System -ErrorAction SilentlyContinue | Select-Object LogName,RecordCount | Format-Table

if ($Armed) {
    Write-Warning 'ARMED MODE -- executing the real technique.'
    $Log = "SuburbanSOC-EmuTest"
    New-EventLog -LogName $Log -Source $Log -ErrorAction SilentlyContinue
    Write-EventLog -LogName $Log -Source $Log -EventId 1 -Message "emu" -ErrorAction SilentlyContinue
    wevtutil cl $Log
    Write-Warning "Cleared throwaway log $Log (real Security/System logs untouched)."
}

Write-Host "[+] Emulation complete."
