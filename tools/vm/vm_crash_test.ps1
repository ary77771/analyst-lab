<#
  Crash-restart test for the agent (stage 3), INSIDE the VM (start it with CRASHTEST.cmd on the
  setup CD; asks for administrator rights because the agent runs elevated).

  Kills the running agent the hard way (like a crash), then waits up to 7 minutes for Task
  Scheduler's repeating 5-minute trigger to start it again (install_agent_task.ps1: "restart on
  failure" doesn't cover a program that exits, the repeating trigger does). Reports the times
  to the laptop (label "vmdiag", section "crash test"). Completeness across the crash is then
  checked on the laptop with tools\lab_status.py --label vm (the restarted agent resumes from
  its saved bookmark).
#>
param([string]$HostAddr = '10.0.2.2')

$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'VirtualBox' -or -not (Test-Path 'C:\LabTools')) { Write-Output "REFUSED: not the lab VM."; exit 3 }

function Agent { Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | Where-Object { $_.CommandLine -match 'agent\.main' } }
$before = Agent
if (-not $before) { Write-Output 'No agent is running; nothing to test.'; exit 2 }
$killed = (Get-Date).ToUniversalTime()
foreach ($p in $before) { Stop-Process -Id $p.ProcessId -Force }
Write-Output ("Killed agent PID {0} at {1:HH:mm:ss} UTC. Waiting for Task Scheduler (up to 7 min)..." -f (($before.ProcessId) -join ','), $killed)

$back = $null
$deadline = (Get-Date).AddMinutes(7)
while ((Get-Date) -lt $deadline) {
    $now = Agent
    if ($now) { $back = (Get-Date).ToUniversalTime(); break }
    Start-Sleep -Seconds 5
}
$text = if ($back) {
    "killed {0:o}`nrestarted {1:o} (PID {2}) after {3:N0} s" -f $killed, $back, (($now.ProcessId) -join ','), ($back - $killed).TotalSeconds
} else { "killed {0:o}`nNOT restarted within 7 minutes" -f $killed }
Write-Output $text

$rec = @{ source = 'diag'; section = 'crash test'; time = (Get-Date).ToUniversalTime().ToString('o'); text = $text }
try {
    Invoke-RestMethod -Uri "http://${HostAddr}:8770/batch" -Method Post -ContentType 'application/json' -TimeoutSec 15 `
        -Body (@{ label = 'vmdiag'; records = @($rec) } | ConvertTo-Json -Depth 4) | Out-Null
    Write-Output 'SENT to the laptop. You can close this window.'
} catch { Write-Output "NOT SENT ($($_.Exception.Message)); please read the lines above to Claude." }
