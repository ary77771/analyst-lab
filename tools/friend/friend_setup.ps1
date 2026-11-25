<#
  Friend package: the part of Setup.exe that needs administrator rights (DESIGN 9.2).
  Run by Inno Setup (already elevated) after copying the files; never run by hand.

    friend_setup.ps1 -AppDir <install folder> -DataDir <C:\ProgramData\AnalystLab>
    friend_setup.ps1 ... -Finish     # at the first startup after a restart Windows asked for
    friend_setup.ps1 ... -Remove     # uninstall: tasks, Sysmon + its log (only if WE installed it)

  1. Folders: <DataDir> is readable only by SYSTEM, Administrators and the signed-in friend
     (raw recordings are private, also from other accounts on the laptop); only
     <DataDir>\control (pause file, statistics cache, self-test result) is writable by the friend.
  2. Sysmon. Already installed by someone else (any service described as System Monitor): left
     exactly as it is. Otherwise Windows' built-in Sysmon feature is turned on; if Windows wants
     a restart first, a one-time SYSTEM task finishes at the next startup (exit 3 tells Setup to
     offer the restart). Windows without the feature: Sysmon64.exe is downloaded from Microsoft
     (Sysinternals) into the admin-only install folder, its Microsoft signature checked, then
     installed. Our config: tools\sysmon\sysmon-config.xml.
  3. The recorder: task \AnalystLab\AnalystLab Recorder runs AnalystLab.exe agent as SYSTEM (so
     it works for friends without an admin account, and SYSTEM may read the Sysmon log), at
     startup + every 5 min (restarts it after a crash), starting from NOW (never from history
     recorded before the friend agreed), compressing finished days.
  What was done is kept in <DataDir>\install.json (uninstall reads it). The log
  (<DataDir>\setup-log.txt) holds fixed text and error TYPES only: no user, computer, files.

  Exit codes: 0 ok · 3 restart needed · 7 Sysmon signature invalid · 8 Sysmon install failed ·
              9 recorder did not start · 10 download failed · 11 a setup step failed
#>
param(
    [Parameter(Mandatory)][string]$AppDir,
    [Parameter(Mandatory)][string]$DataDir,
    [switch]$Finish,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
# Always run as 64-bit PowerShell. The uninstaller is a 32-bit program, and Windows hands a 32-bit
# program the 32-bit PowerShell, which sees a redirected System32 without sysmon.exe: the VM test
# 2026-10-20 uninstall therefore "found no Sysmon" and left it installed.
# (any 32-bit PowerShell on a 64-bit Windows, x64 or Arm64: review 2026-10-20)
if (-not [Environment]::Is64BitProcess -and (Test-Path (Join-Path $env:SystemRoot 'Sysnative'))) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-AppDir', $AppDir, '-DataDir', $DataDir)
    if ($Finish) { $relaunch += '-Finish' }
    if ($Remove) { $relaunch += '-Remove' }
    & $ps64 @relaunch
    exit $LASTEXITCODE
}
$taskPath = '\AnalystLab\'
$recorderTask = 'AnalystLab Recorder'
$finishTask = 'AnalystLab Finish Setup'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$config = Join-Path $AppDir 'setup\sysmon-config.xml'
$controlDir = Join-Path $DataDir 'control'
$marker = Join-Path $DataDir 'install.json'
New-Item -ItemType Directory -Force $DataDir | Out-Null
# a plain log, not Start-Transcript: a transcript's header names the user and the computer.
# Logging must never stop Setup (VM test 2026-10-20: a failed log write turned into "code 1").
$log = Join-Path $DataDir 'setup-log.txt'
# uninstall deletes the data folder, log included: its log goes to the temp folder instead
if ($Remove) { $log = Join-Path $env:TEMP 'AnalystLab-uninstall-log.txt' }
function Log { param([Parameter(ValueFromPipeline)]$m) process {
    try { Add-Content -Path $log -Value $m -Encoding UTF8 -ErrorAction Stop } catch { } } }

function Set-DataFolderAccess {
    <# C:\ProgramData\AnalystLab: private to SYSTEM, Administrators and the friend signed in at the
       screen (read), with only control\ writable by the friend. The FOLDERS get the permissions and
       everything inside simply inherits them. (VM test 2026-10-20: granting with /T stamped the
       folder-style permissions onto files too and left the setup log with no access at all, even
       for admins.) Also repairs a folder an earlier Setup left like that. #>
    $ErrorActionPreference = 'Continue'   # native tools: judged by exit code (5.1 turns their stderr into errors)
    New-Item -ItemType Directory -Force $controlDir, (Join-Path $DataDir 'recordings') | Out-Null
    $friend = (Get-CimInstance Win32_ComputerSystem).UserName      # also when an admin typed their password
    if (-not $friend -and (Test-Path (Join-Path $DataDir 'install.json'))) {
        # nobody signed in, but an earlier run already gave the folder to the friend: keep that.
        # (/grant:r only replaces the accounts it names, so "all users" would be ADDED next to the
        # friend: review 2026-10-20)
        return $false
    }
    $reader = if ($friend) { $friend } else { '*S-1-5-32-545' }      # first install with nobody signed in: all users
    takeown /F $DataDir /R /A /D Y 2>&1 | Out-Null                  # Administrators own everything (repair)
    icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${reader}:(OI)(CI)RX" /C /Q 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [System.IO.IOException]::new('icacls folder') }
    icacls "$DataDir\*" /reset /T /C /Q 2>&1 | Out-Null             # everything inside: inherit
    if ($LASTEXITCODE -ne 0) { throw [System.IO.IOException]::new('icacls reset') }
    icacls $controlDir /grant "${reader}:(OI)(CI)M" /C /Q 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw [System.IO.IOException]::new('icacls control') }
    return [bool]$friend
}

if (-not $Remove -and -not $Finish) {
    # FIRST, before anything is written into the folder (the log included). Not on -Finish: that
    # runs at startup before anyone signs in; the first run already set the friend's access.
    try { $signedIn = Set-DataFolderAccess }
    catch { Log "RESULT (11): folder permissions failed ($($_.Exception.GetType().Name))"; exit 11 }
}
Log ("=== {0} {1} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
     $(if ($Remove) { 'remove' } elseif ($Finish) { 'finish after restart' } else { 'install' }))

function Done([int]$code, [string]$msg) {
    Log "RESULT ($code): $msg"
    # the one-time finish task never stays behind, also when finishing fails (it would otherwise
    # rerun at every startup: review 2026-10-20)
    if ($Finish) { try { Remove-Task $finishTask -KeepRunning } catch { } }
    exit $code
}

function Need-Restart([string]$why) {
    # Sysmon's log only works after a restart: ask for it and finish then, or (already in the run
    # after the restart) give up honestly
    if ($Finish) { Done 8 "Sysmon's event log still doesn't work after the restart ($why)." }
    Set-Variable -Scope Script needRestart $true
    Register-FinishTask
}

function Step([string]$name, [int]$code, [scriptblock]$body) {
    # every step: fixed text + the error's TYPE only (messages can contain paths and names)
    try { & $body }
    catch { Done $code "$name failed ($($_.Exception.GetType().Name))" }
}

function Read-Marker {
    $m = [pscustomobject]@{ sysmon = 'unknown'; sysmon_exe = $null; feature_enabled_by_us = $false }
    if (Test-Path $marker) {
        try {
            $old = Get-Content $marker -Raw | ConvertFrom-Json
            foreach ($p in $old.PSObject.Properties) { $m | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
        } catch { Log "install.json unreadable ($($_.Exception.GetType().Name)); treated as new." }
    }
    return $m
}

function Save-Marker($m) { $m | ConvertTo-Json | Set-Content $marker -Encoding UTF8 }

function Remove-Task([string]$name, [switch]$KeepRunning) {
    if (Get-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction SilentlyContinue) {
        # -KeepRunning: the task running THIS script must not stop itself (review 2026-10-19)
        if (-not $KeepRunning) { Stop-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskPath $taskPath -TaskName $name -Confirm:$false
        Log "Removed task $name."
    }
}

function Find-Sysmon {
    # by description too, so a renamed install (sysmon -i under another file name) is found
    Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^sysmon' -or $_.Description -match 'System Monitor' } |
        Select-Object -First 1
}

function Test-MicrosoftSigned([string]$path) {
    $sig = Get-AuthenticodeSignature $path
    Log "Signature of $(Split-Path $path -Leaf): $($sig.Status)"
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
}

function Install-Sysmon([string]$exe, [string]$kind, $m) {
    # native programs: their stderr must not count as a script error (PowerShell 5.1); results
    # are judged by exit code and by the event channel appearing
    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path $exe)) { Done 8 'Sysmon program not found.' }
    if (-not (Test-MicrosoftSigned $exe)) { Done 7 'Sysmon is not signed by Microsoft; not installed.' }
    # same schema handling as tools\install_sysmon.ps1; the adjusted copy goes in the admin-only
    # install folder, never in a folder users can write (review 2026-10-19)
    $schemaText = & $exe -nologo -s 2>&1 | Out-String
    $binSchema = if ($schemaText -match 'schemaversion="([\d.]+)"') { $Matches[1] } else { $null }
    $cfgSchema = ([xml](Get-Content $config -Raw)).Sysmon.schemaversion
    $use = $config
    if ($binSchema -and ([version]$binSchema -lt [version]$cfgSchema)) {
        $use = Join-Path $AppDir "setup\sysmon-config-schema$binSchema.xml"
        (Get-Content $config -Raw) -replace "schemaversion=`"$cfgSchema`"", "schemaversion=`"$binSchema`"" |
            Set-Content -Path $use -Encoding UTF8
    }
    Log "Sysmon schema: program $binSchema, config $cfgSchema"
    & $exe -nologo -accepteula -i $use *> $null
    if ($LASTEXITCODE -ne 0) { & $exe -nologo -i $use *> $null }
    $code = $LASTEXITCODE
    Log "Sysmon install exit code: $code"
    if ($code -ne 0 -and -not (Find-Sysmon)) { Done 8 'Sysmon did not install.' }
    # ours from now on (uninstall removes it), even if its log needs a restart to work
    $m.sysmon = $kind
    $m.sysmon_exe = $exe
    Save-Marker $m
    # Its event log can take a while to come up in a slow machine, and after Sysmon was removed
    # earlier in the same Windows session it only works after a restart (VM test 2026-10-20).
    for ($i = 0; $i -lt 30 -and -not (Test-SysmonLog); $i++) { Start-Sleep -Seconds 2 }
    if (-not (Test-SysmonLog)) {
        Log 'Sysmon is installed, but its event log only works after a restart.'
        return $false
    }
    wevtutil sl $channel /ms:268435456 | Out-Null   # 256 MB: room for a few days if the recorder stops
    Log "Sysmon installed ($kind) with the Analyst Lab config."
    return $true
}

function Test-SysmonLog {
    # usable = Windows can open the log, not just knows its name
    try { $null = Get-WinEvent -ListLog $channel -ErrorAction Stop; return $true } catch { return $false }
}

function Register-FinishTask {
    Step 'registering the finish task' 11 {
        $finishArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -AppDir `"$AppDir`" -DataDir `"$DataDir`" -Finish"
        Register-ScheduledTask -TaskPath $taskPath -TaskName $finishTask -Force `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $finishArgs) `
            -Trigger (New-ScheduledTaskTrigger -AtStartup) `
            -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) `
            -Description 'Analyst Lab: finishes turning on Sysmon after the restart, then removes itself.' | Out-Null
    }
    Log 'Finishing at the next startup (one-time task).'
}

# ---------------------------------------------------------------------------------- remove
if ($Remove) {
    $ErrorActionPreference = 'Continue'        # uninstall: do as much as possible
    Log "PowerShell 64-bit: $([Environment]::Is64BitProcess)"
    Remove-Task $recorderTask
    Remove-Task $finishTask
    Get-Process -Name 'AnalystLab' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # files can only be deleted once the recorder has really let go of them
    for ($i = 0; $i -lt 30 -and (Get-Process -Name 'AnalystLab' -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
    Log "Recorder and window stopped: $(-not (Get-Process -Name 'AnalystLab' -ErrorAction SilentlyContinue))"
    $m = Read-Marker
    Log "Install record: Sysmon installed by $($m.sysmon); program present: $([bool]($m.sysmon_exe -and (Test-Path $m.sysmon_exe)))"
    if ($m.sysmon -in @('builtin', 'standalone') -and $m.sysmon_exe -and (Test-Path $m.sysmon_exe)) {
        wevtutil cl $channel                   # Sysmon's own log holds raw events too (review 2026-10-19)
        & $m.sysmon_exe -nologo -u force *> $null
        Log "Sysmon uninstall exit code: $LASTEXITCODE; Sysmon service still there: $([bool](Find-Sysmon))"
        Log 'Sysmon and its log removed (we had installed it).'
    } else {
        Log "Sysmon left as it was (installed by: $($m.sysmon))."
    }
    if ($m.feature_enabled_by_us) {
        Disable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Log 'Built-in Sysmon feature turned off again (Windows finishes this at the next restart).'
    }
    # the now-empty \AnalystLab\ folder in Task Scheduler (only if nothing else lives there)
    try {
        $ts = New-Object -ComObject Schedule.Service; $ts.Connect()
        $folder = $ts.GetFolder('\AnalystLab')
        if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) {
            $ts.GetFolder('\').DeleteFolder('AnalystLab', 0); Log 'Removed the empty Task Scheduler folder.'
        }
    } catch { }
    Done 0 'removed'
}

$m = Read-Marker

# ---------------------------------------------------------------------------------- 1. folders
# (set at the very top by Set-DataFolderAccess, before anything was written into the folder)
if ($Finish) { Log 'Folders: left as the first run set them.' }
elseif (-not $signedIn) { Log 'No signed-in user found; folder permissions kept (or, on a first install, all users may read).' }
else { Log 'Folders: data readable by the friend only; control folder writable by the friend; files inherit.' }

# ---------------------------------------------------------------------------------- 2. Sysmon
Log '--- Sysmon ---'
$svc = Find-Sysmon
$needRestart = $false
if ($svc -and $m.sysmon -in @('builtin', 'standalone')) {
    # ours, from an earlier run of Setup (e.g. this is the finish run after the restart)
    if (Test-SysmonLog) {
        wevtutil sl $channel /ms:268435456 | Out-Null
        Log "Sysmon (installed by Analyst Lab) is present and its log works."
    } else {
        Log "Sysmon (installed by Analyst Lab) is present, but its log only works after a restart."
        Need-Restart 'present, log not working'
    }
} elseif ($svc) {
    if ($m.sysmon -eq 'unknown') { $m.sysmon = 'already-there'; Save-Marker $m }
    Log "Sysmon is already installed (installed by: $($m.sysmon)); left exactly as it is."
} else {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
    if ($feature) {
        Log "Built-in Sysmon feature: $($feature.State)"
        if ($feature.State -ne 'Enabled') {
            Step 'turning on the Sysmon feature' 11 {
                $r = Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All -NoRestart
                $m.feature_enabled_by_us = $true
                Save-Marker $m
                if ($r.RestartNeeded) { Set-Variable -Scope Script needRestart $true }
            }
        }
        if ($needRestart) {
            Log 'Windows needs a restart before Sysmon can be installed.'
            Need-Restart 'feature just turned on'
        } elseif (-not (Install-Sysmon (Join-Path $env:WINDIR 'System32\sysmon.exe') 'builtin' $m)) {
            Need-Restart 'built-in Sysmon installed'
        }
    } else {
        Log 'This Windows has no built-in Sysmon; downloading the standalone version from Microsoft.'
        $dl = Join-Path $AppDir 'sysmon'           # inside Program Files: only admins can write here
        $zip = Join-Path $dl 'Sysmon.zip'
        $exe = Join-Path $dl 'Sysmon64.exe'
        Step 'downloading Sysmon' 10 {
            New-Item -ItemType Directory -Force $dl | Out-Null
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $z = [IO.Compression.ZipFile]::OpenRead($zip)
            try {                                  # only the one program, nothing else from the zip
                $entry = $z.Entries | Where-Object { $_.FullName -eq 'Sysmon64.exe' } | Select-Object -First 1
                if (-not $entry) { throw [System.IO.FileNotFoundException]::new('Sysmon64.exe') }
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $exe, $true)
            } finally { $z.Dispose() }
            Remove-Item $zip -Force
        }
        if (-not (Install-Sysmon $exe 'standalone' $m)) {
            Need-Restart 'standalone Sysmon installed'
        }
    }
}
if ($Finish) { Remove-Task $finishTask -KeepRunning }
# A restart is needed first: the finish run after it sets up the recorder, not this run (it would
# otherwise start every 5 minutes against a Sysmon log that doesn't work yet: review 2026-10-20)
if ($needRestart) { Done 3 'restart needed; the finish task sets up and starts the recorder after it' }

# ---------------------------------------------------------------------------------- 3. recorder
Log '--- Recorder task ---'
Step 'registering the recorder task' 11 {
    Remove-Task $recorderTask
    $exe = Join-Path $AppDir 'AnalystLab.exe'
    $recordings = Join-Path $DataDir 'recordings'
    $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $AppDir `
        -Argument "agent --recordings `"$recordings`" --label host --control-dir `"$controlDir`" --start now --compress-finished"
    $triggers = @((New-ScheduledTaskTrigger -AtStartup),
                  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew -StartWhenAvailable
    Register-ScheduledTask -TaskPath $taskPath -TaskName $recorderTask -Action $action -Trigger $triggers `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings $settings -Description 'Analyst Lab student project: records Sysmon events on this laptop only.' | Out-Null
    Log 'Recorder task registered (runs as SYSTEM, from now on).'
}

# ---------------------------------------------------------------------------------- 4. start
Step 'starting the recorder' 9 { Start-ScheduledTask -TaskPath $taskPath -TaskName $recorderTask }
$status = Join-Path $DataDir 'recordings\.state\host\status.json'
for ($i = 0; $i -lt 30 -and -not (Test-Path $status); $i++) { Start-Sleep -Seconds 1 }
if (-not (Test-Path $status)) { Done 9 'the recorder did not start within 30 s (see recordings\.state\host\agent.log)' }
Done 0 'installed and recording'
