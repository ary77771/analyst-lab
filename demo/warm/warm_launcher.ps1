<#
  The WARM launcher (2026-11-21, Yousif: "open the vm with a button ... so we can run scenarioes
  faster and live"). PRACTICE RUNS ONLY, never official ones.

  It rides on a "warm CD" the laptop builds (demo\warm_vm.py), under the name the VM's unchanged
  logon starter looks for (scenario_launcher.ps1), so it runs in the starter's own process exactly as
  tools\vm\scenario_launcher.ps1 does: no administrator rights, no password, the same process tree as
  every run so far. Nothing inside the VM or its snapshot is changed.

  What is different from the one-boot launcher: after the usual waits it does NOT run a scenario and
  exit. It reports "warm-ready" and waits. Each time the laptop swaps in an ordinary run CD (built by
  the frozen tools\make_scenario_cd.ps1), it runs that CD's scenario once and waits again.

  The ONLY thing it ever starts:   powershell.exe -NoProfile -File <CD>\run_scenario.ps1 -Scenario <id> -RunId <id>
    - <id> must be one of the scenarios in $allowed, and the run id must be new;
    - every file on the swapped-in CD must be byte-identical to the file of the same name on the warm
      CD (their SHA-256 fingerprints are taken once, at the start, from the warm CD itself), so
      run_scenario.ps1 and the test programs are the ones the laptop built this session;
    - a batch CD, an unknown scenario, a changed file or a repeated run id is REFUSED and reported.
  There is no other command channel: it reads one small note file on the CD and nothing else.

  Time: the starter's scheduled task is stopped by Windows 30 minutes after logon (the snapshot's
  setting). This launcher counts from its own start and ENDS ITSELF at 27 minutes, and it refuses to
  start a test that could not finish before then, so no test is ever cut off mid-run. It posts no
  periodic messages: a regular rhythm from this PowerShell would add rows to every story.

  Progress goes to the laptop's receiver as LAUNCHER_STATE records (label vmruns), like the one-boot
  launcher's, with the same state words for a run ("found-cd", "running (...)", "flushing", "done ok").
  Two words are the warm launcher's own (2026-11-21, after a disc change that went wrong):
    "seen-cd"             once per run CD, when its note has been read and before its files are checked;
    "failed not-started"  the CD was checked, but it was gone or changed when the test was about to start.
#>
param([Parameter(Mandatory)][string]$Root)

$ErrorActionPreference = 'Stop'
$allowed = @('s1', 's4', 's5')                 # the scenarios the 3-test batch already runs in one boot
$endAfterMin = 27                              # this launcher ends itself here: 3 minutes before Windows stops the logon task
                                               # (its ExecutionTimeLimit is 30 minutes, tools\vm\vm_guest_setup.ps1)
$calmCapSec = 120                              # a warm machine is already settled: a short calm check, capped
$worstSec = $calmCapSec + 120 + 15 + 180       # one test at worst: calm check + the test + settle pause + flush barrier

$dataDir = 'C:\LabRunner\data'                 # user-writable; C:\LabTools is read-only for users
New-Item -ItemType Directory -Force $dataDir | Out-Null
$log = Join-Path $dataDir 'launcher.log'
$agentStatus = 'C:\LabTools\recordings\.state\vm\status.json'
$barrierDir = 'C:\AnalystLab\scenarios\_runner'
$doneList = Join-Path $dataDir 'launcher_runs.txt'
$hostAddr = '10.0.2.2'
$runId = '-'
$startedAt = (Get-Process -Id $PID).StartTime  # the starter's process = the scheduled task's start
$endAt = $startedAt.AddMinutes($endAfterMin)

function Say($msg) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $msg
    Write-Output $line
    try { Add-Content -Path $log -Value $line -Encoding utf8 } catch {}
}
function State($state) {
    Say "state: $state"
    $rec = @{ source = 'launcher'; type = 'LAUNCHER_STATE'; run_id = $runId; state = $state
              time = (Get-Date).ToUniversalTime().ToString('o'); host = $env:COMPUTERNAME }
    try {
        Invoke-RestMethod -Uri "http://${hostAddr}:8770/batch" -Method Post -ContentType 'application/json' -TimeoutSec 10 `
            -Body (@{ label = 'vmruns'; records = @($rec) } | ConvertTo-Json -Depth 4) | Out-Null
    } catch { Say "note: progress not delivered ($_)" }
}
function AgentStatus {
    try {
        $s = Get-Content $agentStatus -Raw | ConvertFrom-Json
        if ($null -eq $s.updated -or $null -eq $s.files_waiting_for_hash) { return $null }
        return @{ updated = [datetime]::Parse([string]$s.updated, $null, [Globalization.DateTimeStyles]::AdjustToUniversal)
                  waiting = [int]$s.files_waiting_for_hash }
    } catch { return $null }
}
function SecondsLeft { return [int]($endAt - (Get-Date)).TotalSeconds }
function ReadNote($path) {
    $n = @{}
    foreach ($l in Get-Content $path) { if ($l -match '^\s*(\w+)\s*=\s*(\S+)\s*$') { $n[$Matches[1]] = $Matches[2] } }
    return $n
}
function WaitCalm($capSec) {
    $cpu = New-Object System.Diagnostics.PerformanceCounter('Processor', '% Processor Time', '_Total')
    [void]$cpu.NextValue()
    $calm = 0
    $until = (Get-Date).AddSeconds($capSec)
    while ($calm -lt 10 -and (Get-Date) -lt $until) {
        Start-Sleep -Seconds 2
        if ($cpu.NextValue() -lt 60) { $calm++ } else { $calm = 0 }
    }
    return ($calm -ge 10)
}

trap { State ("failed error: " + ($_.ToString() -replace '\s+', ' ')); exit 9 }

# 1. the warm CD's own note: it must say warm=1, and its run id names this warm session
$note = ReadNote (Join-Path $Root 'AUTORUN_SCENARIO.txt')
if ($note.run_id -notmatch '^\d{8}-\d{6}-[0-9a-f]{4}$' -or $note.warm -ne '1') { Say 'REFUSED: not a warm CD note'; exit 2 }
$sessionId = $note.run_id
$runId = $sessionId
State 'launcher-started'

# never outside the lab VM (the Guest Additions service exists only in a VirtualBox guest)
if (-not (Get-Service -Name VBoxService -ErrorAction SilentlyContinue) -or -not (Test-Path 'C:\LabTools')) {
    State 'failed not-the-lab-vm (no VBoxService or no C:\LabTools)'; exit 0
}
if ((Test-Path $doneList) -and ((Get-Content $doneList) -contains $sessionId)) { State 'failed already-run (this warm session ran before)'; exit 3 }
Add-Content -Path $doneList -Value $sessionId -Encoding ascii

# 2. fingerprints of the warm CD's own files: a run CD must carry the very same files
$trusted = @{}
foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File) {
    $rel = $f.FullName.Substring($Root.Length).TrimStart('\').ToLower()
    if ($rel -in @('autorun_scenario.txt', 'scenario_launcher.ps1')) { continue }
    $trusted[$rel] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
}
if (-not $trusted.ContainsKey('run_scenario.ps1')) { State 'failed warm CD has no run_scenario.ps1'; exit 2 }

# 3. the VM's recorder running and the laptop reachable (as the one-boot launcher waits)
$until = (Get-Date).AddSeconds(180)
while ($true) {
    $s = AgentStatus
    $agentOk = $s -and ((Get-Date).ToUniversalTime() - $s.updated).TotalSeconds -lt 15
    $hostOk = $false
    try { Invoke-RestMethod -Uri "http://${hostAddr}:8770/health" -TimeoutSec 5 | Out-Null; $hostOk = $true } catch {}
    if ($agentOk -and $hostOk) { break }
    if ((Get-Date) -gt $until) { State "failed waiting (agent running: $([bool]$agentOk), laptop receiver reachable: $hostOk)"; exit 4 }
    Start-Sleep -Seconds 3
}

# 4. let Windows' startup storm pass, once (CPU < 60 % for 20 s in a row, at most 8 minutes)
State 'settling'
$settled = if (WaitCalm 480) { 'calm' } else { 'still-busy-after-8-min' }

# 5. ready: say how many seconds remain for STARTING a test (the laptop turns this into a clock time by its own clock)
State ("warm-ready ($settled) left={0}" -f [Math]::Max(0, (SecondsLeft) - $worstSec))

# 6. wait for run CDs, one test at a time, until the time is up
$refused = @{}
$seenIds = @{}
$lastWait = $null
# Why the loop is still waiting, reported only when the reason CHANGES (a handful of records per
# session, never a rhythm): warm cycle 1 (2026-11-20) timed out with no word at all from here.
function Waiting($why) {
    if ($why -ne $script:lastWait) { $script:lastWait = $why; $script:runId = $sessionId; State "waiting: $why" }
}
while ($true) {
    if ((SecondsLeft) -le 0) { $runId = $sessionId; State 'warm-ended (time is up; no test was running)'; exit 0 }
    Start-Sleep -Seconds 2
    $noteFile = Join-Path $Root 'AUTORUN_SCENARIO.txt'
    $n = $null
    $drive = $null
    try { $drive = New-Object System.IO.DriveInfo($Root) } catch {}
    if ($drive -and -not $drive.IsReady) { Waiting 'the CD drive is not ready (empty, or a disc is being read)'; continue }
    try {
        if (Test-Path -LiteralPath $noteFile) { $n = ReadNote $noteFile } else { Waiting "no note file on $Root" }
    } catch { Waiting ('note unreadable: ' + ($_.ToString() -replace '\s+', ' ')); $n = $null }   # the drive is empty during a swap
    if (-not $n -or -not $n.run_id) { continue }
    $id = [string]$n.run_id
    if ($id -eq $sessionId) {                                             # still the warm CD
        $label = '?'
        try { $label = $drive.VolumeLabel } catch {}
        Waiting "the drive still shows the warm CD's note (volume label: $label)"; continue
    }
    if ($refused.ContainsKey($id)) { continue }                           # already answered
    $done = (Test-Path $doneList) -and ((Get-Content $doneList) -contains $id)
    if ($done) { continue }                                               # a finished run's CD is still in the drive

    # A new note has been read: say so ONCE per run id, BEFORE the CD's files are read. From this word on
    # the laptop does not take this disc out to "put it in again" (2026-11-21, S4: the laptop's retry pulled
    # the disc within about 2 s of this launcher finally seeing it, and the read then failed for minutes;
    # whether the one caused the other is not proven).
    if ($id -match '^\d{8}-\d{6}-[0-9a-f]{4}$' -and -not $seenIds.ContainsKey($id)) {
        $seenIds[$id] = $true; $runId = $id; State 'seen-cd'; $runId = $sessionId
    }

    # check everything before anything is started
    $why = $null
    $scenario = ([string]$n.scenario).ToLower()
    if ($id -notmatch '^\d{8}-\d{6}-[0-9a-f]{4}$') { $why = 'malformed run id'; $id = '-' }
    elseif ($n.batch) { $why = 'a batch CD is not a warm run' }
    elseif ($allowed -notcontains $scenario) { $why = "scenario '$scenario' is not one of $($allowed -join ', ')" }
    else {
        # the CD may still be settling right after the swap: a read error here means "look again", never "run anyway"
        try {
            $seen = 0
            foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction Stop) {
                $rel = $f.FullName.Substring($Root.Length).TrimStart('\').ToLower()
                if ($rel -in @('autorun_scenario.txt', 'scenario_launcher.ps1')) { continue }
                if (-not $trusted.ContainsKey($rel)) { $why = "the CD holds a file the warm CD did not: $rel"; break }
                if ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -ne $trusted[$rel]) { $why = "a file differs from the warm CD's: $rel"; break }
                $seen++
            }
            if (-not $why -and $seen -ne $trusted.Count) { $why = "the CD holds $seen of the warm CD's $($trusted.Count) files" }
        } catch { Waiting ("run CD $id files unreadable: " + ($_.ToString() -replace '\s+', ' ')); continue }
    }
    if (-not $why -and (SecondsLeft) -lt $worstSec) { $why = "too little time left ($(SecondsLeft) s; a test may need $worstSec s)" }
    if ($why) { $refused[$id] = $true; $runId = $id; State "refused $why"; $runId = $sessionId; continue }

    # run it: the same steps and state words as the one-boot launcher
    $runId = $id
    Add-Content -Path $doneList -Value $runId -Encoding ascii
    State "found-cd $scenario"
    $isCalm = WaitCalm $calmCapSec
    # The disc in the drive must STILL be this run's. If the laptop gave up waiting and took it out, or put
    # another one in, nothing is started (2026-11-21: "found-cd" came 3.5 minutes after the laptop had
    # stopped waiting, and the test would have started with nobody watching, into a shutdown).
    $still = ''
    try { $still = [string](ReadNote $noteFile).run_id } catch {}
    if ($still -ne $runId) { State 'failed not-started (the CD was taken out or changed before the test started)'; $runId = $sessionId; continue }
    State ("running ({0})" -f $(if ($isCalm) { 'calm' } else { 'still-busy-after-calm-check' }))
    & powershell.exe -NoProfile -File (Join-Path $Root 'run_scenario.ps1') -Scenario $scenario -RunId $runId
    $code = $LASTEXITCODE
    if ($code -ne 0) { State "failed run_scenario exit $code"; $runId = $sessionId; continue }

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
    State ("done $kind left={0}" -f [Math]::Max(0, (SecondsLeft) - $worstSec))
    $runId = $sessionId
}
