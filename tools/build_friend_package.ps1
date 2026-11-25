<#
  Builds the friend package (DESIGN 9.2) on the laptop. No admin rights, changes nothing
  outside build\.

    tools\build_friend_package.ps1             # bundle + Setup.exe
    tools\build_friend_package.ps1 -BundleOnly # just the PyInstaller bundle

  1. PyInstaller (in .venv) bundles statusapp\launcher.py with Python into
     build\dist\AnalystLab\ ("onedir": AnalystLab.exe + _internal\). Windowed: no console.
  2. Inno Setup 6 (ISCC.exe, installed for the current user) packs that folder, the Sysmon
     config and tools\friend\friend_setup.ps1 into build\Setup-AnalystLab.exe
     (script: tools\friend\AnalystLab.iss).
  3. A virtual CD (build\analystlab-friend.viso) with Setup.exe, for the VM test.
#>
param([switch]$BundleOnly)
$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
Set-Location $proj
$py = Join-Path $proj '.venv\Scripts\python.exe'

Write-Output '=== 1. PyInstaller bundle ==='
& $py -m PyInstaller --noconfirm --clean --windowed --name AnalystLab `
    --distpath build\dist --workpath build\work --specpath build `
    --paths $proj `
    --hidden-import tools.compress_recordings --hidden-import win32com.shell `
    --exclude-module pandas --exclude-module matplotlib --exclude-module fastapi `
    --exclude-module uvicorn --exclude-module networkx --exclude-module pytest `
    --exclude-module numpy --exclude-module PIL `
    statusapp\launcher.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }
$exe = Join-Path $proj 'build\dist\AnalystLab\AnalystLab.exe'
$size = (Get-ChildItem (Split-Path $exe) -Recurse | Measure-Object Length -Sum).Sum / 1MB
Write-Output ("Bundle: {0} ({1:n1} MB)" -f $exe, $size)
if ($BundleOnly) { exit 0 }

Write-Output '=== 2. Setup.exe (Inno Setup) ==='
$iscc = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
if (-not (Test-Path $iscc)) { $iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' }
& $iscc /Q "/DProjectRoot=$proj" (Join-Path $proj 'tools\friend\AnalystLab.iss')
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
$setup = Join-Path $proj 'build\Setup-AnalystLab.exe'
Write-Output ("Setup: {0} ({1:n1} MB) SHA-256 {2}" -f $setup, ((Get-Item $setup).Length / 1MB),
              (Get-FileHash $setup -Algorithm SHA256).Hash)

Write-Output '=== 3. Friend-test CD for the VM ==='
# same mechanism as make_scenario_cd.ps1 (VirtualBox .viso): Setup.exe + the friend guide
$viso = Join-Path $proj 'build\analystlab-friend.viso'
$map = [ordered]@{ '/Setup-AnalystLab.exe' = $setup; '/BEFORE_YOU_INSTALL.txt' = (Join-Path $proj 'tools\friend\BEFORE_YOU_INSTALL.txt')
          '/PREP_NO_SYSMON.cmd' = (Join-Path $proj 'tools\friend\PREP_NO_SYSMON.cmd')
          '/vm_remove_sysmon.ps1' = (Join-Path $proj 'tools\friend\vm_remove_sysmon.ps1') }
$parts = @('--iprt-iso-maker-file-marker-bourne-sh', [guid]::NewGuid().ToString(), '--file-mode=0444', '--dir-mode=0555')
# frozen copies in a folder of their own per build: a .viso reads laptop files live, so a rebuild
# while the CD is in the VM would otherwise hand the VM a half-old, half-new Setup.exe
$stage = Join-Path $proj ('build\friend-cd\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
foreach ($k in @($map.Keys)) {
    $copy = Join-Path $stage $k.TrimStart('/')
    New-Item -ItemType Directory -Force (Split-Path $copy) | Out-Null
    Copy-Item -LiteralPath $map[$k] -Destination $copy
    $map[$k] = $copy
}
foreach ($k in $map.Keys) { $parts += "'$k=$($map[$k])'" }
Set-Content -Path $viso -Value ($parts -join ' ') -Encoding ascii -NoNewline
Write-Output "Wrote $viso (frozen copies in $stage)"

Write-Output '=== 4. The package friends receive ==='
# one folder (and the same as a zip): START HERE.html (the illustrated guide, pictures embedded so
# it needs no internet) + Setup-AnalystLab.exe
$guideDir = Join-Path $proj 'tools\friend\guide'
$html = Get-Content (Join-Path $guideDir 'guide.html') -Raw -Encoding UTF8
foreach ($m in [regex]::Matches($html, '\{\{IMG:([\w.-]+)\}\}')) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $guideDir ($m.Groups[1].Value)))
    $html = $html.Replace($m.Value, 'data:image/png;base64,' + [Convert]::ToBase64String($bytes))
}
if ($html -match '\{\{IMG:') { throw 'guide: a picture placeholder was not filled' }
$pkg = Join-Path $proj 'build\friend-package\Analyst Lab for friends'
if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
New-Item -ItemType Directory -Force $pkg | Out-Null
[IO.File]::WriteAllText((Join-Path $pkg 'START HERE.html'), $html, [Text.UTF8Encoding]::new($false))
Copy-Item $setup (Join-Path $pkg 'Setup-AnalystLab.exe')
$zip = Join-Path $proj 'build\AnalystLab-for-friends.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $pkg -DestinationPath $zip
Write-Output ("Package: {0} and {1} ({2:n1} MB)" -f $pkg, $zip, ((Get-Item $zip).Length / 1MB))
