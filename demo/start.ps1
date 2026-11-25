<#
  Starts everything the demo needs, in order, each in its own minimized window (close a window to
  stop that part). Nothing here needs admin rights, and nothing changes the frozen detection code.

    demo\start.ps1                       # replay = EVERY recorded run of our scenarios (124 runs, ~175 alerts)
    demo\start.ps1 -ReplaySmall          # replay = the one rehearsed S1 run (the old default)
    demo\start.ps1 -ReplayScenario s5    # one other recorded run on the REPLAY tab
    demo\start.ps1 -NoBrowser            # start the servers only

  1. Pre-flight "before" checks (stops here if NOT READY).
  2. The VM receiver and the test server (tools\lab_servers.ps1).
  3. A FRESH live store: the live loop follows the VM's recording from now on (--since-now), so no
     old alert can turn the banner red at minute 0 (debate 11 review, item 2).
  4. The live dashboard on 127.0.0.1:8780 (--demo live: LIVE badge + projector guard).
  5. The replay dashboard on 127.0.0.1:8781 (demo_replay: REPLAY badge, no VM runs).
  6. Pre-flight "after" checks, then Edge with a fresh, empty profile (no history or autocomplete on
     the projector), one tab per dashboard.
#>
# Default replay (Yousif, 2026-11-25: "the big one"): every recorded run of S1-S6 and S2J played back to back
# at 60x (tools\demo_replay.py --all-runs; ~10 min until all ~175 alerts are in). Never the blind B runs, never
# the Atomic Red Team runs (most of their alerts are our own test runner).
# -ReplaySmall: practice S1 run 20261030-195534-dac0, the recorded run whose report shows all three
# inks (8 proven, 1 suspected, 1 can't be known; checked 2026-11-20 against every stored replay) and
# the run report-next's before/after samples come from.
param([string]$ReplayScenario = "", [string]$ReplayRunId = "", [switch]$ReplaySmall, [switch]$NoBrowser)
if ($ReplaySmall) { $ReplayScenario = "s1"; $ReplayRunId = "20261030-195534-dac0" }

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root ".venv\Scripts\python.exe"
Set-Location $root
Remove-Item Env:ANALYSTLAB_OFFICIAL -ErrorAction SilentlyContinue
$env:PYTHONIOENCODING = "utf-8"

Write-Output "== 1. pre-flight (before) =="
& $py demo\preflight.py --before
if ($LASTEXITCODE -ne 0) { Write-Output "Stopping: fix the NO lines above first."; exit 1 }

Write-Output "== 2. lab servers =="
& powershell -NoProfile -ExecutionPolicy Bypass -File tools\lab_servers.ps1

Write-Output "== 3. fresh live store + live loop =="
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$live = Join-Path $root "recordings\live\demo-$stamp"
New-Item -ItemType Directory -Force $live | Out-Null
$store = Join-Path $live "events.db"; $alerts = Join-Path $live "alerts.db"
Start-Process -FilePath $py -WorkingDirectory $root -WindowStyle Minimized -ArgumentList @(
  "-m", "engine.live", "--label", "vm", "--store", "`"$store`"", "--alerts", "`"$alerts`"", "--since-now")

Write-Output "== 4. live dashboard (8780) =="
Start-Process -FilePath $py -WorkingDirectory $root -WindowStyle Minimized -ArgumentList @(
  "-m", "engine.dashboard", "--demo", "live", "--events", "`"$store`"", "--alerts", "`"$alerts`"", "--port", "8780")

Write-Output "== 5. replay dashboard (8781) =="
if ($ReplayScenario) {
  $replayArgs = @("tools\demo_replay.py", $ReplayScenario, "--port", "8781", "--speed", "3")
  if ($ReplayRunId) { $replayArgs += @("--run-id", $ReplayRunId) }
} else {
  $replayArgs = @("tools\demo_replay.py", "s1", "s2", "s3", "s4", "s5", "s6", "s2j", "--all-runs",
                  "--port", "8781", "--speed", "60", "--max-gap", "2")
}
Start-Process -FilePath $py -WorkingDirectory $root -WindowStyle Minimized -ArgumentList $replayArgs

Write-Output "waiting for the dashboards..."
foreach ($i in 1..40) {
  Start-Sleep -Milliseconds 750
  $up = 0
  foreach ($p in 8780, 8781) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:$p/api/mode" | Out-Null; $up++ } catch {} }
  if ($up -eq 2) { break }
}

Write-Output "== 6. pre-flight (after) =="
& $py demo\preflight.py --live-store "$store"
$ready = ($LASTEXITCODE -eq 0)

if (-not $NoBrowser) {
  $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
          Where-Object { Test-Path $_ } | Select-Object -First 1
  $profileDir = Join-Path $env:TEMP "analystlab-demo-profile-$stamp"
  if ($edge) {
    Start-Process -FilePath $edge -ArgumentList @("--user-data-dir=`"$profileDir`"", "--no-first-run", "--new-window",
      "--start-maximized", "http://127.0.0.1:8780/#live", "http://127.0.0.1:8781/#story")
  } else { Write-Output "Edge not found: open http://127.0.0.1:8780 and http://127.0.0.1:8781 yourself." }
}
if ($ready) { Write-Output "READY. Live: http://127.0.0.1:8780   Replay: http://127.0.0.1:8781" }
else { Write-Output "NOT READY: see the NO lines above." }
