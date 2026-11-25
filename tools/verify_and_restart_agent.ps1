<#
  Elevated helper for the stage 3 gate:
    1. Count check: Sysmon log vs agent recordings over a time window (tools\verify_agent_counts.py)
    2. Restart the agent task so it loads the latest code
  Output: recordings\verify_agent_<timestamp>.log / .json
  Exit code: 0 = all done and (if run) the count check matched exactly; 1 = count mismatch;
             2 = the restarted agent didn't report a fresh status.
#>
param(
    [string]$Since,
    [string]$Until,
    [switch]$RestartOnly,
    [switch]$NoRestart
)
$proj = Split-Path $PSScriptRoot -Parent
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$status = Join-Path $proj 'recordings\.state\host\status.json'
Start-Transcript -Path (Join-Path $proj "recordings\verify_agent_$stamp.log") -Force | Out-Null
$exitCode = 0
$sw = [Diagnostics.Stopwatch]::StartNew()

if (-not $RestartOnly) {
    Write-Output '=== 1. Count check ==='
    & (Join-Path $proj '.venv\Scripts\python.exe') (Join-Path $proj 'tools\verify_agent_counts.py') `
        --since $Since --until $Until --out (Join-Path $proj "recordings\verify_agent_$stamp.json")
    if ($LASTEXITCODE -ne 0) { $exitCode = 1; Write-Output 'COUNT CHECK: MISMATCH' } else { Write-Output 'COUNT CHECK: EXACT MATCH' }
    Write-Output ("(count check took {0:N0} s)" -f $sw.Elapsed.TotalSeconds)
}
if ($NoRestart) { Stop-Transcript | Out-Null; exit $exitCode }

Write-Output '=== 2. Restart agent task ==='
$before = if (Test-Path $status) { (Get-Content $status -Raw | ConvertFrom-Json).session } else { $null }
Write-Output "Restart requested at (UTC): $((Get-Date).ToUniversalTime().ToString('o'))"
Stop-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent'
Start-Sleep -Seconds 3
Start-ScheduledTask -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent'

# wait up to 60 s for the NEW agent session to write its status
$fresh = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    if (Test-Path $status) {
        $s = Get-Content $status -Raw | ConvertFrom-Json
        if ($s.session -ne $before) { $fresh = $s; break }
    }
}
$info = Get-ScheduledTaskInfo -TaskPath '\AnalystLab\' -TaskName 'AnalystLab Agent'
Write-Output "Task last run: $($info.LastRunTime) | result: $($info.LastTaskResult)"
if ($fresh) {
    Write-Output "New agent session $($fresh.session) started $($fresh.started); errors $($fresh.errors)"
    $fresh | ConvertTo-Json | Write-Output
} else {
    Write-Output 'RESTART CHECK: no new agent session reported within 60 s'
    $exitCode = 2
}
Write-Output ("(total {0:N0} s)" -f $sw.Elapsed.TotalSeconds)
Stop-Transcript | Out-Null
exit $exitCode
