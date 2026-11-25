<#
  Runs one lab scenario INSIDE the VM, from the scenario CD built by tools\make_scenario_cd.ps1
  (start it with RUN_<SCENARIO>.cmd on that CD). No administrator rights needed.

  0. Refuses to run anywhere but the lab VM (VirtualBox machine with C:\LabTools), rule 8
  1. Sends any run records an earlier run couldn't deliver (kept in C:\LabRunner\data\runs)
  2. Empties the scenario's output folder, so its files are fresh creations (ground truth notes)
  3. Starts the scenario's first program from the CD and waits for it to finish (our scenarios:
     the table below; blind ones b1..b9: blind\<id>\scenario.json on the CD, tools\run_blind.py)
  4. Sends the run's start/end times and exit code to the laptop's receiver (label "vmruns"),
     so tools\check_scenario.py knows which time window to check; if the laptop can't be
     reached, the record is kept and sent by the next manual run (the checker must not silently
     check an older run instead). In automated runs the snapshot restore discards it; the
     laptop's runner then reports the run as missing

  The scenario programs are harmless and talk only to the lab's test server (DESIGN 7, rule 8).
  -RunId (given by scenario_launcher.ps1 for the laptop's one-command runner) goes into the run
  record, so the laptop checks exactly this run. Exit 0 = run recorded on the laptop; 6 = run
  done but its record is still waiting to be sent.
#>
param([Parameter(Mandatory)][string]$Scenario, [string]$HostAddr = '10.0.2.2', [string]$RunId = '',
      [int]$ServerPort = 18765,   # the lab test server (moved from 8765, which another program took, 2026-10-18)
      [switch]$ResolveOnly)       # tests on the laptop: only print what WOULD run (JSON) and stop; runs nothing

$ErrorActionPreference = 'Stop'
$cd = $PSScriptRoot
if (-not $ResolveOnly) {
    $model = (Get-CimInstance Win32_ComputerSystem).Model
    if ($model -notmatch 'VirtualBox' -or -not (Test-Path 'C:\LabTools')) {
        Write-Output "REFUSED: this is not the lab VM (model '$model'). Scenarios run only inside the VM."
        exit 3
    }
}
# What to start: ONLY the requested scenario's row is built (review 2026-10-30: building the whole
# table read s1\payload.sha256, which a blind run CD doesn't carry, so every blind run failed).
# scenario = start program on the CD, its arguments, the folder it writes into
$s = $Scenario.ToLower()
$srv = "http://${HostAddr}:$ServerPort"
$r = $null
switch ($s) {
    # S0: a BASELINE boot: runs nothing for 10 min, so the laptop can learn this VM's normal
    # activity (which programs start shells, which listen) without any scenario in it
    's0'  { $r = @{ exe = $null; out = $null; hold = 600 } }
    's1'  { $r = @{ exe = 's1\s1_fetch.exe'; out = 'C:\AnalystLab\scenarios\s1\payload'
                    args = @('-server', $srv, '-sha256', (Get-Content (Join-Path $cd 's1\payload.sha256') -Raw).Trim()) } }
    # S2: 10 check-ins 30 s apart; S2J: the same with each wait 30 s +-40 % (fixed seed: repeatable)
    's2'  { $r = @{ exe = 's2\s2_checkin.exe'; out = $null; args = @('-server', $srv, '-count', '10', '-interval', '30s') } }
    's2j' { $r = @{ exe = 's2\s2_checkin.exe'; out = $null
                    args = @('-server', $srv, '-count', '10', '-interval', '30s', '-jitter', '0.4', '-seed', '7') } }
    # C1 (control): S2's check-in program as the lab's listed updater (config/frozen.yaml beacon.expected)
    'c1'  { $r = @{ exe = 'c1\c1_updater.exe'; out = $null; args = @('-server', $srv, '-count', '10', '-interval', '30s') } }
    # S3: listen on 127.0.0.1:47213 for 60 s (loopback only; no traffic, nothing written)
    's3'  { $r = @{ exe = 's3\s3_listen.exe'; out = $null; args = @('-addr', '127.0.0.1:47213', '-hold', '60s') } }
    # S4: viewer -> cmd.exe -> PowerShell running s4\s4_note.ps1 from this CD (prints a line)
    's4'  { $r = @{ exe = 's4\s4_viewer.exe'; out = $null; args = @('-script', (Join-Path $cd 's4\s4_note.ps1')) } }
    # S5: 40 dummy files created, copied (.txt.s5copy) and the originals deleted, in its own folder
    's5'  { $r = @{ exe = 's5\s5_churn.exe'; out = 'C:\AnalystLab\scenarios\s5\work'
                    args = @('-dir', 'C:\AnalystLab\scenarios\s5\work', '-count', '40') } }
    # S6 (version 2): copies itself to its own folder, adds a Run-key value and a Startup-folder
    # script that would start the copy at the next logon (none follows: the VM is restored)
    's6'  { $r = @{ exe = 's6\s6_persist.exe'; out = 'C:\AnalystLab\scenarios\s6'
                    args = @('-dir', 'C:\AnalystLab\scenarios\s6') } }
}
# BLIND scenarios (b1..b99, written by someone else; tools\run_blind.py on the laptop): no table row.
# The run CD carries blind\<id>\scenario.json = {"exe": "bin\...", "args": [...], "out": <folder
# under C:\AnalystLab\scenarios\<id>\> or null}. Checked again here with the SAME rules as the
# laptop (tools\run_blind.py: PART, exe under bin\, out the scenario's own folder, args that
# PowerShell 5.1 passes unchanged: printable ASCII, not empty, no ", no space + trailing \).
if ($s -match '^b[1-9][0-9]?$') {
    $part = '[A-Za-z0-9_\-](?:[A-Za-z0-9_.\- ]*[A-Za-z0-9_\-])?'
    $bdir = Join-Path $cd "blind\$s"
    try { $b = Get-Content -LiteralPath (Join-Path $bdir 'scenario.json') -Raw | ConvertFrom-Json } catch { $b = $null }
    $bexe = if ($b -and $b.exe -is [string]) { $b.exe } else { '' }
    if ($bexe -cnotmatch '^[\x20-\x7e]+\z' -or $bexe -notmatch "^bin(?:\\$part)+\z" -or $bexe.Contains('..') -or
        -not (Test-Path -LiteralPath (Join-Path $bdir $bexe) -PathType Leaf)) {
        Write-Output "REFUSED: blind\$s\scenario.json is missing or names no program under blind\$s\bin\"; exit 2
    }
    $bout = $null
    if ($null -ne $b.out) {
        $bout = [string]$b.out
        if ($b.out -isnot [string] -or $bout -cnotmatch '^[\x20-\x7e]+\z' -or $bout -notmatch "^C:\\AnalystLab\\scenarios\\$s(?:\\$part)+\z" -or $bout.Contains('..')) {
            Write-Output "REFUSED: blind\$s\scenario.json 'out' must be null or a folder under C:\AnalystLab\scenarios\$s\"; exit 2
        }
    }
    $bargs = @()
    if ($null -ne $b.args) {
        if ($b.args -isnot [array]) { Write-Output "REFUSED: blind\$s\scenario.json 'args' must be a list"; exit 2 }
        foreach ($a in $b.args) {
            if ($a -isnot [string] -or $a -cnotmatch '^[\x20-\x7e]+\z' -or $a.Contains('"') -or
                ($a.Contains(' ') -and $a.EndsWith('\'))) {
                Write-Output "REFUSED: blind\$s\scenario.json 'args' must be non-empty strings without double quotes"; exit 2
            }
            $bargs += $a
        }
    }
    $r = @{ exe = "blind\$s\$bexe"; out = $bout; args = $bargs }
}
if (-not $r) { Write-Output "Unknown scenario '$Scenario'."; exit 2 }
if ($ResolveOnly) {
    $shown = @()
    if ($r.args) { $shown = @($r.args) }
    [pscustomobject]@{ exe = $r.exe; out = $r.out; args = $shown; hold = $r.hold } | ConvertTo-Json -Compress
    exit 0
}

$pending = 'C:\LabRunner\data\runs'          # outside C:\LabTools (read-only for users since 2026-10-23)
New-Item -ItemType Directory -Force $pending | Out-Null
function Send($file) {
    $body = @{ label = 'vmruns'; records = @(Get-Content $file -Raw | ConvertFrom-Json) } | ConvertTo-Json -Depth 4
    Invoke-RestMethod -Uri "http://${HostAddr}:8770/batch" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 15 | Out-Null
    # delivered: if removing the pending copy fails, don't let the caller send it again (a second
    # run record with the same run id would make the laptop's check ambiguous)
    try { Remove-Item $file -ErrorAction Stop } catch { Write-Output "note: delivered, but could not remove $file ($_)" }
}
foreach ($old in Get-ChildItem $pending -Filter '*.json' | Sort-Object Name) {
    try { Send $old.FullName; Write-Output "Delivered an earlier run's record: $($old.Name)" }
    catch { Write-Output "STOP: the laptop's receiver is unreachable (an earlier run is still undelivered). Start it with tools\lab_servers.ps1 on the laptop."; exit 4 }
}

if ($r.out -and (Test-Path -LiteralPath $r.out)) { Remove-Item -LiteralPath $r.out -Recurse -Force }
$start = (Get-Date).ToUniversalTime()
if ($r.exe) {
    $exe = Join-Path $cd $r.exe
    Write-Output "Scenario $($Scenario.ToUpper()): starting $exe"
    & $exe @($r.args)
    $code = $LASTEXITCODE
} else {
    Write-Output "Scenario $($Scenario.ToUpper()): baseline boot, running nothing for $($r.hold) s"
    Start-Sleep -Seconds $r.hold
    $code = 0
}
Start-Sleep -Seconds 3                                   # let the last events land
$end = (Get-Date).ToUniversalTime()
Write-Output ("Finished with exit code {0} after {1:N1} s" -f $code, ($end - $start).TotalSeconds)

$record = @{ source = 'runner'; type = 'SCENARIO_RUN'; scenario = $Scenario.ToUpper(); host = $env:COMPUTERNAME
             time = $start.ToString('o'); start = $start.ToString('o'); end = $end.ToString('o'); exit_code = $code
             server = "http://${HostAddr}:$ServerPort" }
if ($RunId) { $record.run_id = $RunId }
$file = Join-Path $pending ("{0:yyyyMMdd-HHmmss}-{1}.json" -f $start, $Scenario.ToUpper())
$record | ConvertTo-Json | Set-Content -Path $file -Encoding utf8
# A short receiver outage (restart, laptop busy) must not fail the run: keep trying for up to
# 5 minutes (outage drill 2026-10-23: one try made a run fail when the receiver was down for 60 s).
$giveUp = (Get-Date).AddMinutes(5)
while ($true) {
    try {
        Send $file
        Write-Output "RUN RECORDED on the laptop (start $($start.ToString('HH:mm:ss')) UTC). You can close this window."
        exit 0
    } catch {
        if ((Get-Date) -gt $giveUp) { break }
        Write-Output "Could not deliver the run record ($($_.Exception.Message)); trying again in 10 s."
        Start-Sleep -Seconds 10
    }
}
Write-Output "RUN NOT YET RECORDED: the laptop's receiver stayed unreachable for 5 min. The record is kept in $pending and sent by the next run."
exit 6
