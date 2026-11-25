<#
  Assumption A8: is the Windows 11 VM fast enough in VirtualBox's slow ("snail") mode?
  Targets (VERIFICATION_PLAN stage 5): boot to a usable desktop < 2 min, snapshot restore < 1 min.

  Slow-mode finding (2026-10-17): a LIVE snapshot (saving the running VM's memory) never
  finishes: VirtualBox copies memory in rounds while the guest keeps changing it, and under
  Windows' hypervisor it never catches up (91 rounds in 16 min). So snapshots are taken with
  the VM powered off (disk only), and "restore" = put the disk back + cold boot.

  Uses only VirtualBox's own tools (VBoxManage) and Guest Additions, no admin rights:
    1. Clean shutdown of the running, installed VM (Windows' own shutdown via ACPI)
    2. Takes snapshot <name> of the powered-off VM (disk only)
    3. Times a cold boot until Guest Additions report a logged-in user (= usable desktop)
    4. Clean shutdown again, restores <name>, and times the start until a logged-in user
    5. Deletes the snapshot unless -Keep
  Results go to recordings\vm_speed_<timestamp>.json.

    vm_speed_test.ps1                          # show what will happen
    vm_speed_test.ps1 -Run                     # run it with a throwaway snapshot "speedtest"
    vm_speed_test.ps1 -Run -Snapshot clean -Keep   # same, and keep the snapshot as the clean state
#>
param([switch]$Run, [string]$Snapshot = 'speedtest', [switch]$Keep)

$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
$vbm = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$vm = 'AnalystLab-Win11'
$timeout = 900   # give up after 15 min per step

function Vbox { & $vbm @args; if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args[0]) failed (exit $LASTEXITCODE)" } }
function State { ((& $vbm showvminfo $vm --machinereadable) | Select-String '^VMState=').Line -replace '.*="(.*)"', '$1' }
# Logged in SINCE $after: the property's own timestamp must be newer than $after. (After a crash
# VirtualBox can still show the value from before, so a bare "LoggedInUsers = 1" isn't proof.)
function LoggedInSince([datetime]$after) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $line = (& $vbm guestproperty enumerate $vm 2>$null) | Select-String '/VirtualBox/GuestInfo/OS/LoggedInUsers ' }
    finally { $ErrorActionPreference = $old }
    if (-not $line -or $line.Line -notmatch "=\s*'(\d+)'\s*@\s*(\S+)") { return $false }
    return ([int]$Matches[1] -ge 1) -and ([datetime]::Parse($Matches[2]).ToUniversalTime() -gt $after)
}
function WaitFor([scriptblock]$cond, [string]$what) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while (-not (& $cond)) {
        if ($sw.Elapsed.TotalSeconds -gt $timeout) { throw "Timed out waiting for: $what" }
        Start-Sleep -Seconds 2
    }
    return [math]::Round($sw.Elapsed.TotalSeconds, 1)
}
# Clean shutdown through the Guest Additions ("controlvm shutdown"): the virtual ACPI power
# button was ignored after the VM idled ~17 min (reproduced 2026-10-17), the Guest Additions
# request worked (13 s). The power button stays as a fallback.
function Shutdown {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $vbm controlvm $vm shutdown 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Vbox controlvm $vm acpipowerbutton }
    while ((State) -ne 'poweroff') {
        if ($sw.Elapsed.TotalSeconds -gt 180) { throw 'The VM did not shut down within 3 minutes. Nothing else changed.' }
        Start-Sleep -Seconds 2
    }
    return [math]::Round($sw.Elapsed.TotalSeconds, 1)
}
# Right after a shutdown or snapshot VirtualBox briefly keeps the VM "locked"; starting then fails.
# (showvminfo lists SessionState only while a session exists, so "no line" = unlocked.)
function WaitUnlocked {
    WaitFor { $l = (& $vbm showvminfo $vm --machinereadable) | Select-String '^SessionState='; (-not $l) -or ($l.Line -match 'Unlocked') } 'VirtualBox to release the VM' | Out-Null
}
function StartVm {
    # a few retries in case the lock is released a moment after it reports unlocked
    for ($i = 1; $i -le 5; $i++) {
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $msg = (& $vbm startvm $vm --type gui 2>&1 | Out-String) } finally { $ErrorActionPreference = $old }
        if ($LASTEXITCODE -eq 0) { return }
        if ($msg -notmatch 'already locked') { throw "VBoxManage startvm failed: $msg" }
        Start-Sleep -Seconds 3
    }
    throw 'VBoxManage startvm: the VM stayed locked.'
}
function BootTimed {
    WaitUnlocked
    $t0 = (Get-Date).ToUniversalTime()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    StartVm
    WaitFor { LoggedInSince $t0 } 'logged-in desktop' | Out-Null
    return [math]::Round($sw.Elapsed.TotalSeconds, 1)
}

Write-Output "VM: $vm   state: $(State)"
Write-Output "Steps: clean shutdown -> snapshot '$Snapshot' (VM off) -> timed cold boot -> clean shutdown -> timed restore + boot -> $(if ($Keep) {'keep'} else {'delete'}) snapshot"
if (-not $Run) { Write-Output 'Plan only. Run with -Run.'; exit 0 }
if ((State) -notin 'running', 'poweroff') { throw "The VM must be running or cleanly powered off (it is '$(State)')." }
if ((& $vbm snapshot $vm list 2>$null) -match "Name: $Snapshot \(") { throw "Snapshot '$Snapshot' already exists. Nothing changed." }

$shutSec = $null
if ((State) -eq 'running') {
    Write-Output '--> Clean shutdown'
    $shutSec = Shutdown
}
WaitUnlocked

Write-Output "--> Snapshot '$Snapshot' (VM off: disk only)"
$sw = [Diagnostics.Stopwatch]::StartNew()
Vbox snapshot $vm take $Snapshot --description 'Analyst Lab: taken powered off (live snapshots never finish in slow mode)' | Out-Null
$snapSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

Write-Output '--> Timing cold boot to a logged-in desktop'
$bootSec = BootTimed

Write-Output '--> Clean shutdown, then timing restore + boot'
Shutdown | Out-Null
WaitUnlocked
$sw = [Diagnostics.Stopwatch]::StartNew()
Vbox snapshot $vm restore $Snapshot
$restoreOnlySec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
$restoreBootSec = BootTimed
$restoreTotal = [math]::Round($restoreOnlySec + $restoreBootSec, 1)

if (-not $Keep) {
    Write-Output "--> Deleting snapshot '$Snapshot' (the VM keeps running; VirtualBox merges it in the background)"
    Vbox snapshot $vm delete $Snapshot
}

$result = [ordered]@{
    measured_at = (Get-Date).ToString('o'); vm = $vm; snapshot = $Snapshot; kept = [bool]$Keep
    clean_shutdown_seconds = $shutSec
    snapshot_take_seconds = $snapSec
    cold_boot_to_desktop_seconds = $bootSec; boot_target_seconds = 120; boot_pass = ($bootSec -lt 120)
    restore_seconds = $restoreOnlySec; restore_plus_boot_seconds = $restoreTotal
    restore_target_seconds = 60; restore_pass = ($restoreTotal -lt 60)
    note = 'restore = disk only + cold boot (live/memory snapshots do not finish in slow mode)'
}
$out = Join-Path $proj ("recordings\vm_speed_{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$result | ConvertTo-Json | Set-Content -Path $out -Encoding utf8
$result | ConvertTo-Json
Write-Output "Saved: $out"
