<#
  The VM's logon-task starter (installed by vm_guest_setup.ps1 as C:\LabRunner\start_run_cd.ps1).
  Kept tiny and stable on purpose: it only looks for a run CD (AUTORUN_SCENARIO.txt +
  scenario_launcher.ps1, made by the laptop's tools\run_in_vm.py) and runs the launcher FROM THE
  CD, so launcher fixes ship on the CD without a new SETUP or snapshot (2026-10-18). No CD -> exits.
  Lives outside C:\LabTools, which the VM's agent counts as "our own project work".
  Every step and any error is reported to the laptop's receiver (record type LAUNCHER_STATE,
  label vmruns): the first version failed silently inside the VM (2026-10-18).
#>
$ErrorActionPreference = 'Stop'
$runId = '-'
function Report($state) {
    $rec = @{ source = 'launcher'; type = 'LAUNCHER_STATE'; run_id = $runId; state = "starter: $state"
              time = (Get-Date).ToUniversalTime().ToString('o'); host = $env:COMPUTERNAME }
    try {
        Invoke-RestMethod -Uri 'http://10.0.2.2:8770/batch' -Method Post -ContentType 'application/json' -TimeoutSec 10 `
            -Body (@{ label = 'vmruns'; records = @($rec) } | ConvertTo-Json -Depth 4) | Out-Null
    } catch {}
    try { New-Item -ItemType Directory -Force 'C:\LabRunner\data' | Out-Null; Add-Content -Path 'C:\LabRunner\data\launcher.log' -Value "$((Get-Date).ToString('s')) $runId starter: $state" } catch {}
}
trap { Report ("failed error: " + ($_.ToString() -replace '\s+', ' ')); exit 9 }

if (-not (Test-Path 'C:\LabTools')) { exit 0 }            # not the lab VM
# lab VM only: VirtualBox's Guest Additions service exists only inside a VirtualBox guest (a
# quick service lookup; the BIOS registry key read EMPTY for this task, 2026-10-18, and WMI is
# slow in a slow-mode logon)
if (-not (Get-Service -Name VBoxService -ErrorAction SilentlyContinue)) { Report 'failed not-the-lab-vm (no VBoxService)'; exit 0 }
# self-check as the normal user (review 2026-10-23): the lab folder must refuse our writes
$locked = $true
try { Set-Content -Path 'C:\LabTools\agent\_write_test.tmp' -Value 'x' -ErrorAction Stop; Remove-Item 'C:\LabTools\agent\_write_test.tmp' -ErrorAction SilentlyContinue; $locked = $false } catch {}
Report "started, looking for a run CD (lab folder locked for users: $locked)"
$until = (Get-Date).AddSeconds(180)                        # Windows may mount the CD a while after logon
$root = $null
while (-not $root -and (Get-Date) -lt $until) {
    foreach ($d in Get-PSDrive -PSProvider FileSystem) {
        if ((Test-Path (Join-Path $d.Root 'AUTORUN_SCENARIO.txt')) -and (Test-Path (Join-Path $d.Root 'scenario_launcher.ps1'))) { $root = $d.Root; break }
    }
    if (-not $root) { Start-Sleep -Seconds 3 }
}
if (-not $root) { Report 'no run CD, nothing to do'; exit 0 }    # a normal boot (or SETUP's self-test)
foreach ($l in Get-Content (Join-Path $root 'AUTORUN_SCENARIO.txt')) { if ($l -match '^\s*run_id\s*=\s*(\d{8}-\d{6}-[0-9a-f]{4})\s*$') { $runId = $Matches[1] } }
Report "found run CD at $root"
& (Join-Path $root 'scenario_launcher.ps1') -Root $root
$code = $LASTEXITCODE
Report "launcher ended (exit $code)"
exit $code
