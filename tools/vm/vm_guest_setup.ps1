<#
  Sets up the Analyst Lab VM. Runs INSIDE the VM, from the virtual CD built by
  tools\make_vm_bundle.ps1 (start it with SETUP.cmd on that CD). DESIGN.md 6.2.
  Needs no internet: Python and the packages come from the CD.

  Steps (each is skipped if already done, so running it again after a restart is safe):
    1. Copy the lab files from the CD to C:\LabTools (deliberately NOT under \AnalystLab\,
       which Sysmon records in full: the agent's own state writes would become noise)
    2. Install Python silently into C:\LabTools\python (no PATH change, no launcher)
    3. Create C:\LabTools\.venv and install the agent's packages offline from the CD
    4. Pause Windows Update (VM only: no restarts or update noise during scenarios or the demo);
       never sleep or hibernate (a sleeping VM records nothing); power button = shut down
       (VirtualBox's clean shutdown presses it; Windows' default ignored it, 2026-10-17)
    5. Create C:\AnalystLab\scenarios and exclude it from Defender (VM only; DESIGN 6.2, A15)
    6. Install Windows' built-in Sysmon with our config (tools\install_sysmon.ps1)
    7. Firewall (VM only): block all outgoing traffic except to the laptop's two lab ports
       (10.0.2.2 TCP 8770 receiver, 18765 test server), so the VM really is isolated: no
       internet, no home network (review 2026-10-17), no other laptop service (review 2026-10-31)
    8. Check the laptop is reachable at 10.0.2.2 (receiver 8770, test server 18765; A9); only a
       warning if not (the agent keeps its batches and retries)
    9. Register the agent task, sending events to the laptop (tools\install_agent_task.ps1)
   10. Register the scenario launcher task (C:\LabRunner\start_run_cd.ps1 at logon, no admin
       rights): it runs the launcher from a run CD that the laptop's tools\run_in_vm.py
       inserted, and does nothing otherwise
   11. Slim the VM: Microsoft's policy settings switch off startup work the lab never uses
       (OneDrive, Edge start/updater, Widgets, web search, indexing, SysMain, maintenance);
       Defender, firewall and Sysmon untouched
  Refuses to run outside a VirtualBox VM. Any error stops it with exit 4 (never "SETUP DONE").
  Transcript: C:\LabTools\recordings\vm_guest_setup_<time>.log
  Exit codes: 0 ok · 2 not elevated · 3 restart the VM and run again · 4 a step failed ·
              5 not the lab VM
#>
param([string]$Dest = 'C:\LabTools', [string]$HostAddr = '10.0.2.2', [int[]]$LabPorts = @(8770, 18765))

$ErrorActionPreference = 'Stop'
$cd = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent   # CD root (this file is at <CD>\lab\tools)

$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'VirtualBox') {
    Write-Output "REFUSED: this is not the lab VM (model '$model'). This setup changes Windows Update,"
    Write-Output 'Defender and firewall settings and must only run inside the VM.'
    exit 5
}
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'STOP: needs administrator rights. Double-click SETUP.cmd on the CD instead.'
    exit 2
}
New-Item -ItemType Directory -Force (Join-Path $Dest 'recordings') | Out-Null
Start-Transcript -Path (Join-Path $Dest ("recordings\vm_guest_setup_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force | Out-Null

function Step($msg) { Write-Output ''; Write-Output "=== $msg ===" }
function Fail($msg) { Write-Output "STOP (4): $msg"; Stop-Transcript | Out-Null; exit 4 }
trap { Fail "unexpected error: $_" }       # any cmdlet error (e.g. Defender, firewall) stops here

# a running agent holds its package files open; stop it before re-installing (step 9 restarts it)
$task = Get-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent' -ErrorAction SilentlyContinue
if ($task) { Stop-ScheduledTask -InputObject $task; Start-Sleep -Seconds 2 }

Step '1. Copy lab files'
# /A-:R clears the read-only flag that files get on a CD
robocopy (Join-Path $cd 'lab') $Dest /E /A-:R /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { Fail "robocopy failed (exit $LASTEXITCODE)" }
Write-Output "Copied to $Dest"

Step '2. Python'
$py = Join-Path $Dest 'python\python.exe'
if (Test-Path $py) {
    Write-Output "Already installed: $(& $py --version)"
} else {
    $installer = Get-ChildItem (Join-Path $cd 'python\python-*-amd64.exe') | Select-Object -First 1
    if (-not $installer) { Fail 'Python installer not found on the CD.' }
    $p = Start-Process $installer.FullName -Wait -PassThru -ArgumentList '/quiet', 'InstallAllUsers=1',
        "TargetDir=$(Join-Path $Dest 'python')", 'PrependPath=0', 'Include_launcher=0', 'Include_test=0',
        'Include_doc=0', 'Include_tcltk=0', 'Shortcuts=0'
    if ($p.ExitCode -ne 0 -or -not (Test-Path $py)) { Fail "Python install failed (exit $($p.ExitCode))" }
    Write-Output "Installed: $(& $py --version)"
}

Step '3. Virtual environment + packages (offline)'
$venvPy = Join-Path $Dest '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    & $py -m venv (Join-Path $Dest '.venv')
    if ($LASTEXITCODE -ne 0) { Fail 'venv creation failed' }
}
& $venvPy -m pip install --no-index --find-links (Join-Path $cd 'wheels') -r (Join-Path $Dest 'requirements-vm.txt') --disable-pip-version-check --quiet
if ($LASTEXITCODE -ne 0) { Fail 'package install failed' }
& $venvPy -c "import win32evtlog, psutil, httpx; print('packages ok')"
if ($LASTEXITCODE -ne 0) { Fail 'packages installed but not importable' }

Step '4. Pause Windows Update (this VM only)'
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if (-not (Test-Path $au)) { New-Item -Path $au -Force | Out-Null }
Set-ItemProperty -Path $au -Name NoAutoUpdate -Value 1 -Type DWord
Write-Output 'Automatic updates off (policy NoAutoUpdate=1)'
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /hibernate off
powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3   # 3 = shut down
powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3
powercfg /setactive SCHEME_CURRENT
Write-Output 'Never sleeps; power button shuts down'

Step '5. Scenarios folder + Defender exclusion (this VM only)'
$scen = 'C:\AnalystLab\scenarios'
New-Item -ItemType Directory -Force $scen | Out-Null
Add-MpPreference -ExclusionPath $scen
Write-Output "Excluded from Defender: $((Get-MpPreference).ExclusionPath -contains $scen)"

Step '6. Sysmon'
& (Join-Path $Dest 'tools\install_sysmon.ps1') -LogDir (Join-Path $Dest 'recordings')
$code = $LASTEXITCODE
if ($code -eq 3) {
    Write-Output 'Sysmon feature enabled; Windows needs a restart. Restart the VM, then run SETUP.cmd again.'
    Stop-Transcript | Out-Null; exit 3
}
if ($code -ne 0) { Fail "install_sysmon.ps1 exit $code (see its log in $Dest\recordings)" }

Step '7. Firewall: outgoing traffic only to the laptop''s two lab ports (this VM only)'
# Only the receiver and the test server (security review 2026-10-31: VirtualBox NAT maps 10.0.2.2
# to the LAPTOP'S LOOPBACK, so allowing every port let the VM reach any local service there, e.g.
# the dashboard). The rule is rebuilt every time, so a VM set up before keeps no wider rule.
$rule = 'AnalystLab: outgoing only to the laptop'
Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Allow -RemoteAddress $HostAddr `
    -Protocol TCP -RemotePort $LabPorts -Profile Any | Out-Null
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultOutboundAction Block
$profiles = Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.DefaultOutboundAction)" }
$f = Get-NetFirewallRule -DisplayName $rule | Get-NetFirewallPortFilter
Write-Output "Default outgoing: $($profiles -join ', '); allowed: $HostAddr TCP $($f.RemotePort -join ',') only"

Step '8. Can the VM reach the laptop?'
$warn = $false
foreach ($port in $LabPorts) {
    $ok = Test-NetConnection $HostAddr -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $ok) { $warn = $true }
    Write-Output ("{0}:{1} {2}" -f $HostAddr, $port, $(if ($ok) { 'reachable' } else { 'NOT reachable' }))
}
# the dashboard's port must now be blocked (shown only; it proves something only while it runs)
$dash = Test-NetConnection $HostAddr -Port 8780 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Output ("{0}:8780 (dashboard) {1}" -f $HostAddr, $(if ($dash) { 'REACHABLE (should be blocked!)' } else { 'blocked or not running' }))
if ($dash) { Fail 'the firewall still lets the VM reach the laptop''s dashboard port' }
if ($warn) { Write-Output 'WARNING: start the laptop side with tools\lab_servers.ps1 (the agent keeps its batches and retries).' }

Step '8b. Lab key + locked lab folder (security review 2026-10-23)'
# The key proves to the laptop that events come from this agent: readable only by SYSTEM and
# administrators (scenario programs run as the normal user, not elevated). The whole lab folder
# becomes read-only for normal users (they can't change the agent or plant a program inside it);
# the launcher and the scenario script keep their logs and pending run records in
# C:\LabRunner\data instead (review 2026-10-23).
$keyDir = 'C:\ProgramData\AnalystLabKey'
$keyFile = Join-Path $keyDir 'key.txt'
$cdKey = Join-Path $cd 'lab_key.txt'
if (Test-Path $cdKey) {
    New-Item -ItemType Directory -Force $keyDir | Out-Null
    Copy-Item $cdKey $keyFile -Force
    & icacls $keyDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls on $keyDir failed" }
    Write-Output "Lab key stored in $keyDir (SYSTEM and administrators only)"
    $keyArgs = " --lab-key-file `"$keyFile`""
} else {
    Write-Output 'note: no lab key on this CD (older bundle): the agent sends without a key'
    $keyArgs = ''
}
# owner first (an owner can always change permissions), then a clean, inherited read-only ACL
& icacls $Dest /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
& icacls $Dest /reset /T /C /Q | Out-Null
& icacls $Dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "icacls on $Dest failed" }
$runnerData = 'C:\LabRunner\data'
New-Item -ItemType Directory -Force $runnerData | Out-Null
& icacls $runnerData /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "icacls on $runnerData failed" }
Write-Output "$Dest is read-only for normal users; launcher data goes to $runnerData"

Step '9. Agent task (sends to the laptop)'
& (Join-Path $Dest 'tools\install_agent_task.ps1') -Label vm -AgentArgs "--label vm --send-to http://${HostAddr}:8770$keyArgs"
if ($LASTEXITCODE -ne 0) { Fail "install_agent_task.ps1 exit $LASTEXITCODE" }
if (-not (Get-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent' -ErrorAction SilentlyContinue)) { Fail 'agent task not registered' }

Step '10. Scenario launcher task (for the laptop''s one-command runner)'
# Local scripts (C:\LabRunner, the run CD) may run without '-ExecutionPolicy Bypass' (found 2026-10-24:
# a PowerShell started with Bypass trips the community Sigma rule 'Change PowerShell Policies to an
# Insecure Level' inside every run window). RemoteSigned: local scripts run, downloaded unsigned ones don't.
# SETUP itself runs with a Process-scope Bypass, so PowerShell reports the machine setting as 
# 'overridden by a more specific scope' (an error under ErrorActionPreference Stop) although it WAS
# set (2026-10-30): ignore that report and check the machine scope itself below. The text is in the
# error record ("$_"), not in the exception (whose Message is only 'Security error.', seen in the VM).
try { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop } catch { if ("$_" -notmatch 'more specific scope') { throw } }
if ((Get-ExecutionPolicy -Scope LocalMachine) -ne 'RemoteSigned') { Fail 'execution policy not set to RemoteSigned' }
Write-Output 'Script policy: RemoteSigned (this VM only)'
# Runs scenario_launcher.ps1 at each logon, as the logged-in user WITHOUT admin rights and in
# the visible desktop (Interactive: no password stored). It does nothing unless a run CD
# (AUTORUN_SCENARIO.txt) is inserted, so normal boots and the setup CD are unaffected.
# It lives OUTSIDE C:\LabTools: inside the VM the agent counts C:\LabTools as "our own project
# work" (origin=project, never fingerprinted), and a launcher started from there would pass that
# tag to the scenario and the barrier marker (independent review 2026-10-18). Only reads of
# C:\LabTools remain, which Sysmon doesn't record.
# Only a tiny starter is installed; the launcher itself comes on each run CD (fixable without
# a new SETUP or snapshot).
$launcherDir = 'C:\LabRunner'
$launcher = Join-Path $launcherDir 'start_run_cd.ps1'
New-Item -ItemType Directory -Force $launcherDir | Out-Null
Get-ChildItem $launcherDir -Filter '*.ps1' | Remove-Item -Force          # an older launcher version
Copy-Item (Join-Path $Dest 'tools\launcher_stub.ps1') $launcher -Force
if (-not (Test-Path $launcher)) { Fail "missing $launcher" }
$user = "$env:USERDOMAIN\$env:USERNAME"
# Starts 3 minutes after logon, after the worst of Windows' startup storm: in VirtualBox's slow
# mode a 2-CPU VM often freezes for 1.5-11 min in the first minutes after boot (with or without
# this task, measured 2026-10-18), and a PowerShell started then took up to 6.5 min to load.
$launcherTrigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$launcherTrigger.Delay = 'PT3M'
$lt = Get-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Scenario Launcher' -ErrorAction SilentlyContinue
if ($lt) { Unregister-ScheduledTask -InputObject $lt -Confirm:$false }
Register-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Scenario Launcher' `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -File `"$launcher`"" -WorkingDirectory $launcherDir) `
    -Trigger $launcherTrigger `
    -Principal (New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited) `
    -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew) `
    -Description 'Analyst Lab: runs a scenario when the laptop inserts a run CD.' | Out-Null
if (-not (Get-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Scenario Launcher' -ErrorAction SilentlyContinue)) { Fail 'launcher task not registered' }
Write-Output "Launcher task registered for $user (runs 3 min after logon, no admin rights)"
# Self-test in exactly the logon context (this user, no admin rights): the starter reports
# 'started' and 'no run CD' to the laptop, which checks for them BEFORE the snapshot is taken.
Start-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Scenario Launcher'
Write-Output 'Self-test: the launcher task runs once now and reports to the laptop (it ends by itself in about 3 min).'

Step '11. Slim the VM: switch off startup work the lab never uses (this VM only)'
# In VirtualBox's slow mode Windows' startup work (OneDrive, Edge, Widgets, indexing...) kept the VM
# busy for ~8 min after each boot (2026-10-18). Microsoft's documented policy settings, nothing
# downloaded; Defender, the firewall and Sysmon are NOT touched.
# Every item is optional: a setting Windows refuses (some keys belong to Windows itself, e.g. the
# maintenance key refused even an administrator, 2026-10-18) gives a note, never a failed SETUP.
$slimNotes = 0
function Policy($path, $name, $value) {
    try {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -ErrorAction Stop
    } catch { $script:slimNotes++; Write-Output "note: $name not set ($($_.Exception.Message))" }
}
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 1          # OneDrive
try { Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue } catch {}
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'StartupBoostEnabled' 0                     # Edge at logon
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'BackgroundModeEnabled' 0
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HideFirstRunExperience' 1
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'UpdateDefault' 0                     # Edge's updater
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'AutoUpdateCheckPeriodMinutes' 0
try { Get-ScheduledTask -TaskName 'MicrosoftEdgeUpdate*' -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null }
catch { Write-Output "note: Edge updater tasks not disabled ($_)" }
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0                    # Widgets
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 1      # web results in Start search
Policy 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 0
Policy 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
Policy 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance' 'MaintenanceDisabled' 1   # automatic maintenance
foreach ($svc in 'WSearch', 'SysMain', 'edgeupdate', 'edgeupdatem') {                     # indexing, pre-loading, updater
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        try { Set-Service -Name $svc -StartupType Disabled; if ($s.Status -eq 'Running') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } }
        catch { Write-Output "note: service $svc not disabled ($_)" }      # optional: never fail SETUP for this
    }
}
$disabled = (Get-Service -Name 'WSearch', 'SysMain' -ErrorAction SilentlyContinue | Where-Object StartType -eq 'Disabled').Count
Write-Output "Startup work switched off ($slimNotes setting(s) refused, see notes; $disabled of 2 heavy services disabled); takes full effect at the next boot"

Write-Output ''
Write-Output "SETUP DONE$(if ($warn) { ' (with a warning above)' }). Next (on the laptop): check recordings\vm\ is filling, then take the clean snapshot."
Stop-Transcript | Out-Null
exit 0
