<#
  Builds the scenario programs (Go) into scenarios\bin\ and puts files the test server serves
  into scenarios\www\. Both folders are git-ignored build output.

    build_scenarios.ps1
#>
$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
$go = 'C:\Program Files\Go\bin\go.exe'
if (-not (Test-Path $go)) { $go = 'go' }
$bin = Join-Path $proj 'scenarios\bin'
$www = Join-Path $proj 'scenarios\www'
New-Item -ItemType Directory -Force $bin, $www | Out-Null

Push-Location (Join-Path $proj 'scenarios')
try {
    if (-not (Test-Path go.mod)) { & $go mod init analystlab/scenarios | Out-Null }
    $targets = @(
        @{ pkg = './s1/fetch';   exe = 's1_fetch.exe' },
        @{ pkg = './s1/payload'; exe = 's1_payload.exe' },
        @{ pkg = './s2/checkin'; exe = 's2_checkin.exe' },
        @{ pkg = './s3/listen';  exe = 's3_listen.exe' },
        @{ pkg = './s4/viewer';  exe = 's4_viewer.exe' },
        @{ pkg = './s5/churn';   exe = 's5_churn.exe' },
        @{ pkg = './s6/persist'; exe = 's6_persist.exe' },   # version 2 (package C)
        # C1 (control): the SAME check-in program as S2, under the listed updater's name
        @{ pkg = './s2/checkin'; exe = 'c1_updater.exe' }
    )
    foreach ($t in $targets) {
        & $go build -trimpath -o (Join-Path $bin $t.exe) $t.pkg
        if ($LASTEXITCODE -ne 0) { throw "go build $($t.pkg) failed" }
        Write-Output "built $($t.exe)"
    }
} finally { Pop-Location }

Copy-Item (Join-Path $bin 's1_payload.exe') (Join-Path $www 's1_payload.exe') -Force
Write-Output "served by the test server: $(Join-Path $www 's1_payload.exe')"
