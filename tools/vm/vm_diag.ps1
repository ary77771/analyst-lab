<#
  Collects VM-side facts for troubleshooting the agent and sends them to the laptop's receiver
  as label "vmdiag" (recordings\vmdiag\ on the laptop), so nobody has to read logs aloud.
  Runs INSIDE the VM, elevated (start it with DIAG.cmd on the virtual CD). Read-only, except
  that it turns on Windows' Task Scheduler history log (off by default) so the next start
  attempts are recorded too.

  Sends: boot and logon times, the agent task's state and triggers, the agent log tail,
  Task Scheduler history for the agent task, recent Application-log errors, Event Log and
  Sysmon service start times, and the Sysmon log's record range.
#>
param([string]$HostAddr = '10.0.2.2', [string]$Dest = 'C:\LabTools')

$ErrorActionPreference = 'Continue'
$records = New-Object System.Collections.ArrayList
function Add([string]$section, $value) {
    $text = ($value | Out-String -Width 220).TrimEnd()
    [void]$records.Add(@{ source = 'diag'; section = $section; time = (Get-Date).ToUniversalTime().ToString('o'); text = $text })
    Write-Output "--- $section"
}
$since = (Get-Date).AddHours(-3)

$os = Get-CimInstance Win32_OperatingSystem
Add 'times' ("now (UTC)  {0:o}`nlast boot  {1:o}" -f (Get-Date).ToUniversalTime(), $os.LastBootUpTime.ToUniversalTime())

$t = Get-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent' -ErrorAction SilentlyContinue
if ($t) {
    $i = Get-ScheduledTaskInfo -InputObject $t
    Add 'task' ("state {0}`nlast run {1:o}`nlast result {2} (0x{2:X})`nnext run {3:o}`naction {4} {5}" -f $t.State, $i.LastRunTime, $i.LastTaskResult, $i.NextRunTime, $t.Actions[0].Execute, $t.Actions[0].Arguments)
    Add 'task triggers' ($t.Triggers | Select-Object @{n='type';e={$_.CimClass.CimClassName}}, Enabled, StartBoundary, Delay, UserId, @{n='repeat';e={$_.Repetition.Interval}})
} else { Add 'task' 'NOT FOUND' }

$log = Join-Path $Dest 'recordings\.state\vm\agent.log'
if (Test-Path $log) { Add 'agent.log (last 80 lines)' (Get-Content $log -Tail 80) } else { Add 'agent.log' "missing: $log" }

$ts = 'Microsoft-Windows-TaskScheduler/Operational'
$cfg = Get-WinEvent -ListLog $ts -ErrorAction SilentlyContinue
Add 'task scheduler history log' ("enabled before this run: {0}" -f $cfg.IsEnabled)
if ($cfg -and $cfg.IsEnabled) {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $ts; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'AnalystLab' } | Select-Object -First 60
    Add 'task scheduler events (newest first)' ($ev | ForEach-Object { "{0:o} {1} {2}" -f $_.TimeCreated.ToUniversalTime(), $_.Id, ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(180, ($_.Message -replace '\s+', ' ').Length)) })
} elseif ($cfg) {
    wevtutil sl $ts /e:true
    Add 'task scheduler history log' 'was off; turned on now (records from the next boot)'
}

$app = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = $since } -ErrorAction SilentlyContinue | Select-Object -First 20
Add 'application errors (newest first)' ($app | ForEach-Object { "{0:o} {1} {2}: {3}" -f $_.TimeCreated.ToUniversalTime(), $_.Id, $_.ProviderName, (($_.Message -replace '\s+', ' ') -replace '^(.{0,200}).*', '$1') })

$svc = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $since; Id = 6005, 6006, 7036 } -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne 7036 -or $_.Message -match 'Sysmon|Windows Event Log|Task Scheduler' } | Select-Object -First 40
Add 'system: event log + service starts (newest first)' ($svc | ForEach-Object { "{0:o} {1} {2}" -f $_.TimeCreated.ToUniversalTime(), $_.Id, ($_.Message -replace '\s+', ' ') })

$sm = 'Microsoft-Windows-Sysmon/Operational'
$first = Get-WinEvent -LogName $sm -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
$last = Get-WinEvent -LogName $sm -MaxEvents 1 -ErrorAction SilentlyContinue
Add 'sysmon log range' ("oldest record {0} at {1:o}`nnewest record {2} at {3:o}" -f $first.RecordId, $first.TimeCreated.ToUniversalTime(), $last.RecordId, $last.TimeCreated.ToUniversalTime())

# isolation (setup step 7): the internet must be unreachable, the laptop reachable
$iso = foreach ($t in @(@{ h = '1.1.1.1'; p = 443; want = $false }, @{ h = '8.8.8.8'; p = 53; want = $false },
                        @{ h = $HostAddr; p = 8770; want = $true })) {
    $ok = Test-NetConnection $t.h -Port $t.p -InformationLevel Quiet -WarningAction SilentlyContinue
    "{0}:{1} reachable={2} expected={3} -> {4}" -f $t.h, $t.p, $ok, $t.want, $(if ($ok -eq $t.want) { 'OK' } else { 'NOT ISOLATED AS EXPECTED' })
}
Add 'isolation check' ($iso + (Get-NetFirewallProfile | ForEach-Object { "profile $($_.Name): enabled=$($_.Enabled) outbound=$($_.DefaultOutboundAction)" }))

$bm = Join-Path $Dest 'recordings\.state\vm\bookmark.xml'
if (Test-Path $bm) { Add 'agent bookmark' ((Get-Content $bm -Raw) + "`nsaved {0:o}" -f (Get-Item $bm).LastWriteTimeUtc) }

$body = @{ label = 'vmdiag'; records = $records } | ConvertTo-Json -Depth 5
try {
    $r = Invoke-RestMethod -Uri "http://${HostAddr}:8770/batch" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 15
    Write-Output ''
    Write-Output "SENT $($r.accepted) sections to the laptop. You can close this window."
} catch {
    $out = Join-Path $Dest ("recordings\vmdiag_{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $body | Set-Content -Path $out -Encoding utf8
    Write-Output "NOT SENT ($($_.Exception.Message)); saved to $out"
}
