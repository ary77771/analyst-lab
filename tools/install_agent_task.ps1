<#
  Registers (or removes) the Windows scheduled task that runs the Analyst Lab agent.
  Must run elevated. Uses Windows Task Scheduler, the standard way to run a background
  program at logon with administrator rights (needed to read the Sysmon log).

    install_agent_task.ps1            # create/replace the task and start it now
    install_agent_task.ps1 -Remove    # stop and delete the task
    install_agent_task.ps1 -Label vm -AgentArgs '--label vm --send-to http://10.0.2.2:8770'
                                      # inside the VM (vm_guest_setup.ps1 does this)

  Task: \AnalystLab\AnalystLab Agent
    - starts at logon of the current user, with highest privileges (no prompt at each logon)
    - runs .venv\Scripts\pythonw.exe -m agent.main (no console window)
    - never times out, runs on battery
    - ALSO a trigger every 5 minutes: Task Scheduler's "restart on failure" only covers a
      failed *launch*, not a program that exits with an error, so this repeating trigger is
      what restarts a crashed agent. While the agent runs, MultipleInstances=IgnoreNew skips
      the repeat, and the agent's own single-instance lock is a second guard.
#>
param([switch]$Remove, [string]$Label = 'host', [string]$AgentArgs = '')

$proj = Split-Path $PSScriptRoot -Parent
$taskPath = '\AnalystLab\'
$taskName = 'AnalystLab Agent'
$user = "$env:USERDOMAIN\$env:USERNAME"
$logDir = Join-Path $proj 'recordings'
New-Item -ItemType Directory -Force $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir ("install_agent_task_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force | Out-Null

$existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false
    Write-Output 'Removed existing task.'
}
if ($Remove) { Stop-Transcript | Out-Null; exit 0 }

$pythonw = Join-Path $proj '.venv\Scripts\pythonw.exe'
if (-not (Test-Path $pythonw)) { Write-Output "STOP: $pythonw not found"; Stop-Transcript | Out-Null; exit 2 }

# -E -s: ignore PYTHON* environment variables and the user's site-packages: the agent runs with
# admin rights, a user-level program must not be able to slip code into it (review 2026-10-23)
$action = New-ScheduledTaskAction -Execute $pythonw -Argument ("-E -s -m agent.main $AgentArgs".Trim()) -WorkingDirectory $proj
$atLogon = New-ScheduledTaskTrigger -AtLogOn -User $user
$every5 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)
$trigger = @($atLogon, $every5)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew -StartWhenAvailable

Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description 'Analyst Lab: records Sysmon events to the project recordings folder.' | Out-Null
Start-ScheduledTask -TaskPath $taskPath -TaskName $taskName
Start-Sleep -Seconds 8

$t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
$info = Get-ScheduledTaskInfo -TaskPath $taskPath -TaskName $taskName
Write-Output "Task state: $($t.State) | last run: $($info.LastRunTime) | last result: $($info.LastTaskResult)"
Write-Output "Triggers: $(($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task','' }) -join ', ')"
$status = Join-Path $proj "recordings\.state\$Label\status.json"
if (Test-Path $status) { Write-Output "Agent status:"; Get-Content $status | Write-Output }
else { Write-Output 'No agent status file yet.' }

Stop-Transcript | Out-Null
exit 0
