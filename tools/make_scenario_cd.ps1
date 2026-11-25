<#
  Builds the "scenario CD" for the VM: the scenario programs and their run scripts, kept apart
  from the setup CD so the clean snapshot never contains scenario files. Same mechanism as
  tools\make_vm_bundle.ps1 (VirtualBox .viso). Build the programs first: build_scenarios.ps1.

    make_scenario_cd.ps1                              # manual CD: double-click RUN_S1 in the VM
    make_scenario_cd.ps1 -RunId <id> -Scenario s1     # run CD for tools\run_in_vm.py: adds
        AUTORUN_SCENARIO.txt (scenario + run id) and scenario_launcher.ps1, which the VM's logon
        task runs; written to build\analystlab-run.viso so the manual CD stays as it is

  CD layout:   RUN_S1.cmd, run_scenario.ps1, s1\s1_fetch.exe, s1\payload.sha256, s2\s2_checkin.exe,
               s3\s3_listen.exe, s4\s4_viewer.exe, s4\s4_note.ps1, s5\s5_churn.exe, s6\s6_persist.exe
               (+ AUTORUN_SCENARIO.txt and scenario_launcher.ps1 on a run CD)
  (s1_payload.exe is NOT on the CD: in S1 it is downloaded from the test server.)
#>
param([string]$RunId = '', [string]$Scenario = 's1', [string]$Batch = '')
# -Batch "s3:<run id>:calm,s4:<run id>:fast": the scenarios the VM's launcher runs one after another
# in one boot ("fast" = skip its calm-down wait); the note keeps scenario/run_id lines for the first
# one, which the VM's starter (in the snapshot) reads

$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
$viso = Join-Path $proj $(if ($RunId) { 'build\analystlab-run.viso' } else { 'build\analystlab-scenarios.viso' })
# the payload's fingerprint: s1_fetch runs the download only if it matches (safety)
$sha = Join-Path $proj 'build\s1_payload.sha256'
New-Item -ItemType Directory -Force (Split-Path $sha) | Out-Null
Set-Content -Path $sha -Value (Get-FileHash (Join-Path $proj 'scenarios\www\s1_payload.exe') -Algorithm SHA256).Hash -Encoding ascii -NoNewline
$map = [ordered]@{
    '/RUN_S1.cmd'         = Join-Path $proj 'tools\vm\RUN_S1.cmd'
    '/run_scenario.ps1'   = Join-Path $proj 'tools\vm\run_scenario.ps1'
    '/s1/s1_fetch.exe'    = Join-Path $proj 'scenarios\bin\s1_fetch.exe'
    '/s1/payload.sha256'  = $sha
    '/s2/s2_checkin.exe'  = Join-Path $proj 'scenarios\bin\s2_checkin.exe'
    '/s3/s3_listen.exe'   = Join-Path $proj 'scenarios\bin\s3_listen.exe'
    '/s4/s4_viewer.exe'   = Join-Path $proj 'scenarios\bin\s4_viewer.exe'
    '/s4/s4_note.ps1'     = Join-Path $proj 'scenarios\s4\s4_note.ps1'
    '/s5/s5_churn.exe'    = Join-Path $proj 'scenarios\bin\s5_churn.exe'
    '/s6/s6_persist.exe'  = Join-Path $proj 'scenarios\bin\s6_persist.exe'
    '/c1/c1_updater.exe'  = Join-Path $proj 'scenarios\bin\c1_updater.exe'
}
if ($RunId) {
    if ($RunId -notmatch '^\d{8}-\d{6}-[0-9a-f]{4}$') { throw "Bad run id '$RunId' (expected yyyyMMdd-HHmmss-xxxx)" }
    if ($Scenario -notmatch '^[sc]\d+[a-z]?$') { throw "Bad scenario '$Scenario'" }
    $note = Join-Path $proj 'build\run\AUTORUN_SCENARIO.txt'
    New-Item -ItemType Directory -Force (Split-Path $note) | Out-Null
    $item = '[sc]\d+[a-z]?:\d{8}-\d{6}-[0-9a-f]{4}:(calm|fast)'
    if ($Batch -and $Batch -notmatch "^$item(,$item)*$") { throw "Bad batch '$Batch'" }
    if ($Batch -and $Batch.Split(',')[0].Split(':')[1] -ne $RunId) { throw 'The batch must start with -RunId' }
    $text = "scenario=$($Scenario.ToLower())`r`nrun_id=$RunId"
    if ($Batch) { $text += "`r`nbatch=$($Batch.ToLower())" }
    Set-Content -Path $note -Value $text -Encoding ascii
    $map['/AUTORUN_SCENARIO.txt'] = $note
    $map['/scenario_launcher.ps1'] = Join-Path $proj 'tools\vm\scenario_launcher.ps1'
}
foreach ($src in $map.Values) { if (-not (Test-Path $src)) { throw "Missing: $src (run build_scenarios.ps1?)" } }
# The CD must hold FROZEN copies: a .viso points at files on the laptop, and VirtualBox reads them
# live with the size they had when the CD was made. Editing run_scenario.ps1 while the VM ran
# once gave the VM a cut-off script (S3 run 20261019-172814-a74e, 2026-10-19).
$stage = Join-Path $proj $(if ($RunId) { 'build\run\cd' } else { 'build\cd' })
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
foreach ($k in @($map.Keys)) {
    $copy = Join-Path $stage ($k.TrimStart('/') -replace '/', '\')
    New-Item -ItemType Directory -Force (Split-Path $copy) | Out-Null
    Copy-Item -LiteralPath $map[$k] -Destination $copy
    $map[$k] = $copy
}
$parts = @('--iprt-iso-maker-file-marker-bourne-sh', [guid]::NewGuid().ToString(), '--file-mode=0444', '--dir-mode=0555')
foreach ($k in $map.Keys) { $parts += "'$k=$($map[$k])'" }
New-Item -ItemType Directory -Force (Split-Path $viso) | Out-Null
Set-Content -Path $viso -Value ($parts -join ' ') -Encoding ascii -NoNewline
Write-Output "Wrote $viso ($($map.Count) files)"
if (-not $RunId) {
    Write-Output 'Insert it into the VM (replaces the setup CD in the first DVD drive):'
    Write-Output "  VBoxManage storageattach AnalystLab-Win11 --storagectl SATA --port 1 --device 0 --type dvddrive --medium `"$viso`""
}
