<#
  The WARM launcher of the NO-DISC-CHANGE path (2026-11-21, PROOF and Yousif). PRACTICE RUNS ONLY.
  It is used only when the laptop's switch is on (demo\warm_vm.py: ANALYSTLAB_WARM_NO_DISC=1, off by
  default); the default is demo\warm\warm_launcher.ps1, where every test is a new CD.

  Like that one it rides on a "warm CD" the laptop builds, under the name the VM's unchanged logon
  starter looks for (scenario_launcher.ps1), and runs in the starter's own process: no administrator
  rights, no password, the same process tree as every run so far. Nothing inside the VM or its
  snapshot is changed. After the usual waits it reports "warm-ready" and waits; each time the laptop
  names a test, it runs that test once and waits again.

  NO DISC CHANGE. The warm CD stays in the drive for the whole session. It already holds
  run_scenario.ps1 and every scenario's programs (the frozen tools\make_scenario_cd.ps1 puts them on
  every CD). Why: on 2026-11-21 both disc changes made later than 14 minutes after this machine's
  start hung for minutes.

  THE RULE (PROOF): "The only thing the laptop can send the test machine is the name of one of this
  session's three pre-checked tests."

  The ONLY things it ever starts:
      powershell.exe -NoProfile -File <CD>\run_scenario.ps1 -Scenario <id> -RunId <id>
      VBoxControl.exe guestproperty get / wait   (the Guest Additions' own tool, from its two fixed places;
                                                  the frozen one-boot launcher already starts it for every
                                                  progress word)
    - the CD's files are checked ONCE, at the start, while the machine is quiet, against the SHA-256 the
      laptop wrote into the CD's note: a missing, extra or changed file ends the session before "ready";
    - the note carries one run id per test (made by the laptop at the start);
    - which test to run comes from the laptop as ONE VirtualBox guest property with a FIXED name. Its
      value is only ever COMPARED with the three run ids on the note: equal to one of them, that test is
      meant; not set, nothing is meant; anything else is refused in words and nothing happens. No part
      of the value is executed, used as a path or a file name, or passed on to anything. The property
      is READ here, never written;
    - a run id is started at most once;
    - right before a test starts, the signal must still name it and the warm CD must still be in the
      drive; otherwise nothing is started.

  Time: the starter's scheduled task is stopped by Windows 30 minutes after logon (the snapshot's
  setting). This launcher counts from its own start and ENDS ITSELF at 27 minutes, and it refuses to
  start a test that could not finish before then, so no test is ever cut off mid-run. It posts no
  periodic messages and starts nothing on a rhythm: while it waits, it sleeps inside ONE call that
  ends when the laptop changes the signal. Only if that call proves not to hold in this machine (it
  returns at once, four times in a row) does it look every 10 seconds instead, and it SAYS so
  ("waiting: the wait for the signal returns at once: looking every 10 seconds instead").

  Progress goes to the laptop's receiver as LAUNCHER_STATE records (label vmruns), like the one-boot
  launcher's, with the same state words for a run ("running (...)", "flushing", "done ok").
  Words of its own:
    "picked-up <id>"      the laptop's signal named this test and it may run (the calm check follows);
    "failed not-started"  it was picked up, but the laptop had called it off (or the CD was gone) when it
                          was about to start: nothing was started;
    "refused a signal that is not one of this session's three run ids"   said once per such signal.
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
$signalName = '/AnalystLab/Warm/Run'           # the ONE guest property the laptop sets (demo\warm_vm.py SIGNAL): a fixed name
$hostInfoName = '/VirtualBox/HostInfo/VBoxVer' # a property VirtualBox itself always sets: read once, to prove the laptop's properties reach this launcher
# VBoxControl's two places (as tools\vm\scenario_launcher.ps1 finds it; Guest Additions 7.x put it in System32)
$vboxControl = @("$env:SystemRoot\System32\VBoxControl.exe", 'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe') |
               Where-Object { Test-Path $_ } | Select-Object -First 1
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

# What the laptop's signal means right now: '' (not set: nothing), one of $allowed (its value EQUALS that test's
# run id on the CD's note), or '?' (set to anything else). The value is only compared; it is never executed,
# never used as a path or a name, never passed on, never written into a message.
function Signal {
    $ErrorActionPreference = 'Continue'
    $value = ''
    try {
        $out = & $vboxControl --nologo guestproperty get $signalName 2>$null
        foreach ($l in @($out)) { if ([string]$l -match '^\s*Value:\s*(\S.*?)\s*$') { $value = $Matches[1] } }
    } catch { return '' }
    if ($value -eq '') { return '' }
    foreach ($a in $allowed) { if ($runIds[$a] -ceq $value) { return $a } }
    return '?'
}
# Sleep until the laptop changes the signal (or the time is over): ONE call, however long it lasts.
function WaitForSignal($seconds) {
    $ErrorActionPreference = 'Continue'
    try { & $vboxControl --nologo guestproperty wait $signalName --timeout ([int]$seconds * 1000) 2>$null | Out-Null } catch {}
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

# one run id per test, from the note: made by the laptop at the start, never taken from anywhere else
$runIds = @{}
foreach ($a in $allowed) {
    $rid = [string]$note["run_$a"]
    if ($rid -notmatch '^\d{8}-\d{6}-[0-9a-f]{4}$' -or $rid -eq $sessionId -or $runIds.Values -contains $rid) { State "failed the warm CD's note carries no run id of its own for $a"; exit 2 }
    $runIds[$a] = $rid
}

# 2. the warm CD's files against the SHA-256 the laptop wrote into the note: checked ONCE, here, while the machine is quiet
$trusted = @{}
$listed = 0
[void][int]::TryParse([string]$note.files, [ref]$listed)
if ($listed -lt 1) { State "failed the warm CD's note lists no files"; exit 2 }
foreach ($i in 1..$listed) {
    if ([string]$note["file_$i"] -notmatch '^([0-9A-F]{64}):(\S+)$') { State "failed the warm CD's note: line $i of its file list can't be read"; exit 2 }
    $trusted[$Matches[2].ToLower()] = $Matches[1]
}
if (-not $trusted.ContainsKey('run_scenario.ps1')) { State "failed the warm CD's file list does not name run_scenario.ps1"; exit 2 }
$onCd = 0
foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File) {
    $rel = $f.FullName.Substring($Root.Length).TrimStart('\').ToLower()
    if ($rel -in @('autorun_scenario.txt', 'scenario_launcher.ps1')) { continue }
    if (-not $trusted.ContainsKey($rel)) { State "failed the warm CD holds a file its list does not name: $rel"; exit 2 }
    if ((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash -ne $trusted[$rel]) { State "failed a file on the warm CD differs from the laptop's list: $rel"; exit 2 }
    $onCd++
}
if ($onCd -ne $trusted.Count) { State "failed the warm CD holds $onCd of the $($trusted.Count) files its list names"; exit 2 }

# 2b. BEFORE "ready" is said: prove that a property set on the laptop's side can be read here (VirtualBox's own
#     version property always exists). If it can't, no test could ever be named: say so now, in words, instead
#     of a first click that does nothing. The signal itself must be "nothing" at this point.
if (-not $vboxControl) { State 'failed no VBoxControl.exe in the test machine (the laptop could not tell it which test to run)'; exit 5 }
$reads = $false
foreach ($try in 1..12) {
    try { $ErrorActionPreference = 'Continue'; $out = & $vboxControl --nologo guestproperty get $hostInfoName 2>$null } catch { $out = @() } finally { $ErrorActionPreference = 'Stop' }
    foreach ($l in @($out)) { if ([string]$l -match '^\s*Value:\s*\S') { $reads = $true } }
    if ($reads) { break }
    Start-Sleep -Seconds 5
}
if (-not $reads) { State "failed the laptop's signal can't be read in the test machine"; exit 5 }
if ((Signal) -eq '?') { State "failed the laptop's signal already says something that is not one of this session's run ids"; exit 5 }

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

# 6. wait for the laptop's signal, one test at a time, until the time is up
$refused = @{}
$lastWait = $null
$quick = 0
$strange = $false                                    # the present signal was already refused in words
$noteFile = Join-Path $Root 'AUTORUN_SCENARIO.txt'
# Why the loop is still waiting, reported only when the reason CHANGES (a handful of records per
# session, never a rhythm).
function Waiting($why) {
    if ($why -ne $script:lastWait) { $script:lastWait = $why; $script:runId = $sessionId; State "waiting: $why" }
}
while ($true) {
    if ((SecondsLeft) -le 0) { $runId = $sessionId; State 'warm-ended (time is up; no test was running)'; exit 0 }
    $scenario = Signal
    $id = $null
    if ($scenario -eq '?') {                           # set to something that is none of this session's run ids: refused, in words, once
        if (-not $strange) { $strange = $true; $runId = $sessionId; State "refused a signal that is not one of this session's three run ids (nothing was started)" }
    } else { $strange = $false }
    if ($allowed -contains $scenario) { $id = [string]$runIds[$scenario] }
    $ran = $id -and (Test-Path $doneList) -and ((Get-Content $doneList) -contains $id)
    if (-not $id -or $ran -or $refused.ContainsKey($id)) {
        # nothing to do: sleep inside one call until the laptop changes the signal
        $before = Get-Date
        WaitForSignal ([Math]::Max(1, [Math]::Min((SecondsLeft), 1800)))
        if (((Get-Date) - $before).TotalSeconds -lt 3) { $quick++ } else { $quick = 0 }
        if ($quick -ge 4) {                                # the wait does not hold (it should not happen): look every 10 s instead,
            Waiting 'the wait for the signal returns at once: looking every 10 seconds instead'    # and say so once
            Start-Sleep -Seconds 10
        }
        continue
    }
    $quick = 0

    # a test the laptop named: check before anything is started
    if ((SecondsLeft) -lt $worstSec) {
        $refused[$id] = $true; $runId = $id; State "refused too little time left ($(SecondsLeft) s; a test may need $worstSec s)"; $runId = $sessionId; continue
    }

    # run it: the same steps and state words as the one-boot launcher
    $runId = $id
    State "picked-up $scenario"
    $isCalm = WaitCalm $calmCapSec
    # Right before the start: the laptop must STILL name this test, and the warm CD must still be this
    # session's. If the laptop gave up waiting and called the test off, nothing is started (2026-11-21: a test
    # the laptop had given up on was found 3.5 minutes later and would have started with nobody watching).
    $still = ''
    try { $still = [string](ReadNote $noteFile).run_id } catch {}
    if ((Signal) -ne $scenario -or $still -ne $sessionId) {
        State 'failed not-started (the laptop called the test off, or the warm CD was gone, before the test started)'; $runId = $sessionId; continue
    }
    Add-Content -Path $doneList -Value $runId -Encoding ascii
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
