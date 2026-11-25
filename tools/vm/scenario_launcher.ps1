<#
  Runs ONE automated scenario run inside the VM, or a BATCH of them in one boot (batch= line in the
  run note, 2026-10-20: each run keeps its own run id, record and flush barrier). It is on the laptop-made run CD and is started
  by the VM's logon-task starter (C:\LabRunner\start_run_cd.ps1 = launcher_stub.ps1) when that
  finds the CD; living on the CD, it can be fixed without a new SETUP or snapshot. It runs in the
  starter's process, so its command line is the starter's: outside C:\LabTools, which the VM's
  agent counts as "our own project work" and never fingerprints (independent review 2026-10-18).
  No administrator rights, no password: it runs as the logged-in user, in the visible desktop.

  1. Reads AUTORUN_SCENARIO.txt (scenario + run id); never runs the same run id twice (list in
     C:\LabRunner\data\launcher_runs.txt), e.g. on a later boot with the CD still inserted.
  2. Waits until the VM's agent is running (its status file is fresh) and the laptop's
     receiver answers, so the run isn't recorded into a gap.
  2b. Waits until Windows' startup storm has passed (CPU < 60 % for 20 s, at most 8 min): in
     slow mode it can stall the whole VM for minutes.
  3. Runs the scenario with the CD's run_scenario.ps1 (it sends the run record, with run_id).
  4. Flush barrier ("the last car of the convoy carries a flag"): a 15 s settle pause (network,
     DNS and process-end events land in Sysmon's log later than file events), then waits until
     the agent has read everything and has no file left to fingerprint, then creates
     C:\AnalystLab\scenarios\_runner\barrier-<run_id>-ok.txt (or -late.txt if the agent didn't
     get there within 180 s). The agent sends everything in order, so when the laptop receives
     this marker's FILE_HASH, everything before it is there.
  Progress goes to the laptop's receiver as LAUNCHER_STATE records (label vmruns), to the
  VirtualBox guest property /AnalystLab/Runner ("<run_id> <state>") when VBoxControl exists,
  and to C:\LabRunner\data\launcher.log (outside the lab folder, which is read-only for users).
#>
param([Parameter(Mandatory)][string]$Root)

$ErrorActionPreference = 'Stop'
$dataDir = 'C:\LabRunner\data'                 # user-writable; C:\LabTools is read-only for users (2026-10-23)
New-Item -ItemType Directory -Force $dataDir | Out-Null
$log = Join-Path $dataDir 'launcher.log'
# Guest Additions 7.2 put their programs in System32 (VBoxService and VBoxTray run from there,
# seen 2026-10-18); older versions used their own folder
$vboxControl = @("$env:SystemRoot\System32\VBoxControl.exe", 'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe') |
               Where-Object { Test-Path $_ } | Select-Object -First 1
$agentStatus = 'C:\LabTools\recordings\.state\vm\status.json'
$barrierDir = 'C:\AnalystLab\scenarios\_runner'
$hostAddr = '10.0.2.2'
$runId = '-'

function Say($msg) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $msg
    Write-Output $line
    try { Add-Content -Path $log -Value $line -Encoding utf8 } catch {}
}
# Progress goes two ways: a record to the laptop's receiver (the reliable one: the VM may only
# talk to the laptop anyway) and the guest property (if VBoxControl is there).
function State($state) {
    Say "state: $state"
    $rec = @{ source = 'launcher'; type = 'LAUNCHER_STATE'; run_id = $runId; state = $state
              time = (Get-Date).ToUniversalTime().ToString('o'); host = $env:COMPUTERNAME }
    try {
        Invoke-RestMethod -Uri "http://${hostAddr}:8770/batch" -Method Post -ContentType 'application/json' -TimeoutSec 10 `
            -Body (@{ label = 'vmruns'; records = @($rec) } | ConvertTo-Json -Depth 4) | Out-Null
    } catch { Say "note: progress not delivered ($_)" }
    if ($vboxControl) {
        try { & $vboxControl --nologo guestproperty set /AnalystLab/Runner "$runId $state" --flags TRANSIENT 2>$null | Out-Null } catch {}
    }
}
# The agent's status file as (updated UTC, files waiting for a hash), or $null if it is missing,
# half-written or lacks a field (a missing field must never look like "0 waiting").
function AgentStatus {
    try {
        $s = Get-Content $agentStatus -Raw | ConvertFrom-Json
        if ($null -eq $s.updated -or $null -eq $s.files_waiting_for_hash) { return $null }
        return @{ updated = [datetime]::Parse([string]$s.updated, $null, [Globalization.DateTimeStyles]::AdjustToUniversal)
                  waiting = [int]$s.files_waiting_for_hash }
    } catch { return $null }
}

# any unexpected error is reported to the laptop (guest property) and the log, never silent
trap { State ("failed error: " + ($_.ToString() -replace '\s+', ' ')); exit 9 }

# 1. the run note (read first, so every report carries the run id)
$note = @{}
foreach ($l in Get-Content (Join-Path $Root 'AUTORUN_SCENARIO.txt')) { if ($l -match '^\s*(\w+)\s*=\s*(\S+)\s*$') { $note[$Matches[1]] = $Matches[2] } }
# scenario ids: ours (s1, s2j, c1) and blind ones (b1..b9, tools\run_blind.py: run_scenario.ps1 reads
# their program from blind\<id>\scenario.json on the CD)
if ($note.run_id -notmatch '^\d{8}-\d{6}-[0-9a-f]{4}$' -or $note.scenario -notmatch '^[scb]\d+[a-z]?$') {
    Say "REFUSED: AUTORUN_SCENARIO.txt is malformed"; exit 2
}
# the runs of this boot: a batch ("s3:<id>:calm,s4:<id>:fast"; fast = skip the calm-down wait,
# 2026-10-20) or the one scenario/run_id of a single run (always with the calm-down wait)
$items = @()
if ($note.batch) {
    foreach ($b in $note.batch.Split(',')) {
        if ($b -notmatch '^([scb]\d+[a-z]?):(\d{8}-\d{6}-[0-9a-f]{4}):(calm|fast)$') { Say "REFUSED: malformed batch item"; exit 2 }
        $items += @{ scenario = $Matches[1]; run_id = $Matches[2]; calm = ($Matches[3] -eq 'calm') }
    }
    if ($items[0].run_id -ne $note.run_id) { Say "REFUSED: the batch doesn't start with the note's run id"; exit 2 }
} else {
    $items += @{ scenario = $note.scenario; run_id = $note.run_id; calm = $true }
}
$runId = $note.run_id
State 'launcher-started'

# never outside the lab VM (the Guest Additions service exists only in a VirtualBox guest)
if (-not (Get-Service -Name VBoxService -ErrorAction SilentlyContinue) -or -not (Test-Path 'C:\LabTools')) {
    State 'failed not-the-lab-vm (no VBoxService or no C:\LabTools)'; exit 0
}
$doneList = Join-Path $dataDir 'launcher_runs.txt'
foreach ($it in $items) {
$runId = $it.run_id
if ((Test-Path $doneList) -and ((Get-Content $doneList) -contains $runId)) { State 'failed already-run (this run id ran before)'; exit 3 }
Add-Content -Path $doneList -Value $runId -Encoding ascii
State "found-cd $($it.scenario)"

# 2. agent running and laptop reachable
$until = (Get-Date).AddSeconds(180)
while ($true) {
    $s = AgentStatus
    $agentOk = $s -and ((Get-Date).ToUniversalTime() - $s.updated).TotalSeconds -lt 15
    $hostOk = $false
    try { Invoke-RestMethod -Uri "http://${hostAddr}:8770/health" -TimeoutSec 5 | Out-Null; $hostOk = $true } catch {}
    if ($agentOk -and $hostOk) { break }
    if ((Get-Date) -gt $until) {
        State "failed waiting (agent running: $([bool]$agentOk), laptop receiver reachable: $hostOk)"; exit 4
    }
    Start-Sleep -Seconds 3
}

# 2b. let Windows' startup storm pass (Defender, Edge, OneDrive, indexing...): in VirtualBox's
# slow mode it keeps both CPUs busy for minutes and can stall the whole VM (VBox.log "Giving up
# catch-up", 2026-10-18). Run on a calm machine: CPU < 60 % for 20 s in a row, at most 8 min.
if ($it.calm) {
    State 'settling'
    $cpu = New-Object System.Diagnostics.PerformanceCounter('Processor', '% Processor Time', '_Total')
    [void]$cpu.NextValue()
    $calm = 0
    $until = (Get-Date).AddSeconds(480)
    while ($calm -lt 10 -and (Get-Date) -lt $until) {
        Start-Sleep -Seconds 2
        if ($cpu.NextValue() -lt 60) { $calm++ } else { $calm = 0 }
    }
    $settled = if ($calm -ge 10) { 'calm' } else { 'still-busy-after-8-min' }
} else {
    $settled = 'no calm-down wait: the answer sheet allows it'   # S4, S5: no timing rules
}
State "running ($settled)"

# 3. the scenario (its own script on the CD sends the run record)
& powershell.exe -NoProfile -File (Join-Path $Root 'run_scenario.ps1') -Scenario $it.scenario -RunId $runId
$code = $LASTEXITCODE
if ($code -ne 0) { State "failed run_scenario exit $code"; exit 5 }

# 4. flush barrier. First a settle pause: network, DNS and process-end events reach Sysmon's log
# seconds later than file events (independent review 2026-10-18); then wait until the agent has
# read everything since (a status written after the pause) and has no file left to fingerprint.
State 'flushing'
Start-Sleep -Seconds 15
$after = (Get-Date).ToUniversalTime()
$until = (Get-Date).AddSeconds(180)
$flushed = $false
while ((Get-Date) -lt $until) {
    $s = AgentStatus
    if ($s -and $s.updated -gt $after.AddSeconds(2) -and $s.waiting -eq 0) { $flushed = $true; break }
    Start-Sleep -Seconds 2
}
New-Item -ItemType Directory -Force $barrierDir | Out-Null
$kind = if ($flushed) { 'ok' } else { 'late' }
Set-Content -Path (Join-Path $barrierDir "barrier-$runId-$kind.txt") -Value $runId -Encoding ascii
State "done $kind"
}   # next scenario of the batch (the laptop checks every run only once all runs are in: each window
    # then ends where the next run starts)
exit 0
