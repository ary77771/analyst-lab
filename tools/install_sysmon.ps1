<#
  Installs Windows' built-in Sysmon with the Analyst Lab config, then verifies it.
  Must run elevated (administrator). Never restarts the machine.

  Steps:
    1. Check the built-in 'Sysmon' optional feature is enabled (enable it if not; stop if a restart is needed)
    2. Locate the built-in sysmon.exe and verify its Microsoft signature
    3. Install with tools\sysmon\sysmon-config.xml (adapting only the schema version number if needed)
    4. Raise the Sysmon log size to 1 GB
    5. Run tools\sysmon_check.py and cross-check its findings with Get-WinEvent

  Output goes to the transcript in -LogDir (default: recordings\, which git ignores).
  Exit codes: 0 ok · 3 restart needed · 5 feature missing · 6 binary missing ·
              7 signature invalid · 8 install failed · 9 checks failed
#>
param(
    [string]$LogDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'recordings')
)

$ErrorActionPreference = 'Continue'
$proj = Split-Path $PSScriptRoot -Parent
$config = Join-Path $proj 'tools\sysmon\sysmon-config.xml'
$python = Join-Path $proj '.venv\Scripts\python.exe'
New-Item -ItemType Directory -Force $LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Start-Transcript -Path (Join-Path $LogDir "install_sysmon_$stamp.log") -Force | Out-Null

function Stop-With([int]$code, [string]$msg) {
    Write-Output "STOP ($code): $msg"
    Stop-Transcript | Out-Null
    exit $code
}

Write-Output '=== 1. Built-in Sysmon feature ==='
$f = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
if (-not $f) { Stop-With 5 "Windows has no optional feature named 'Sysmon'." }
Write-Output "Feature 'Sysmon': $($f.State)"
if ($f.State -ne 'Enabled') {
    $r = Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All -NoRestart
    if ($r.RestartNeeded) { Stop-With 3 'Feature enabled; Windows needs a restart before installing. Not restarting.' }
}
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -match 'sysmon' } |
    Format-Table FeatureName, State -AutoSize | Out-String | Write-Output

Write-Output '=== 2. Locate and verify sysmon.exe ==='
$bin = Join-Path $env:WINDIR 'System32\sysmon.exe'
if (-not (Test-Path $bin)) { Stop-With 6 "$bin not found." }
$sig = Get-AuthenticodeSignature $bin
Write-Output "Binary:    $bin"
Write-Output "Version:   $((Get-Item $bin).VersionInfo.ProductVersion)"
Write-Output "Signature: $($sig.Status) / $($sig.SignerCertificate.Subject)"
Write-Output "SHA-256:   $((Get-FileHash $bin -Algorithm SHA256).Hash)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    Stop-With 7 'Signature is not a valid Microsoft signature.'
}

$schemaText = & $bin -nologo -s 2>&1 | Out-String
$binSchema = if ($schemaText -match 'schemaversion="([\d.]+)"') { $Matches[1] } else { $null }
$cfgSchema = ([xml](Get-Content $config -Raw)).Sysmon.schemaversion
Write-Output "Schema: binary $binSchema, our config $cfgSchema"

$useConfig = $config
if ($binSchema -and ([version]$binSchema -lt [version]$cfgSchema)) {
    $useConfig = Join-Path $LogDir "sysmon-config-schema$binSchema.xml"
    (Get-Content $config -Raw) -replace "schemaversion=`"$cfgSchema`"", "schemaversion=`"$binSchema`"" |
        Set-Content -Path $useConfig -Encoding UTF8
    Write-Output "Binary uses an older schema; installing a copy with only the version number changed: $useConfig"
}

Write-Output '=== 3. Install ==='
$already = Get-Service | Where-Object { $_.Name -match '^sysmon' }
if ($already) {
    Write-Output "Sysmon service already present ($($already.Name)); updating its config instead."
    & $bin -nologo -c $useConfig 2>&1 | Out-String | Write-Output
} else {
    & $bin -nologo -accepteula -i $useConfig 2>&1 | Out-String | Write-Output
    if ($LASTEXITCODE -ne 0) {
        Write-Output "Install with -accepteula returned $LASTEXITCODE; retrying without it (built-in versions may not take that switch)."
        & $bin -nologo -i $useConfig 2>&1 | Out-String | Write-Output
    }
}
$installCode = $LASTEXITCODE
Write-Output "Install exit code: $installCode"
Start-Sleep -Seconds 3
Get-Service | Where-Object { $_.Name -match 'sysmon' } | Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Output
$channelOk = $null -ne (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
Write-Output "Sysmon event log channel present: $channelOk"
if ($installCode -ne 0 -or -not $channelOk) { Stop-With 8 'Install did not complete.' }

Write-Output '=== 4. Log size 1 GB ==='
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
wevtutil gl Microsoft-Windows-Sysmon/Operational | Select-String 'enabled|maxSize|retention' | Out-String | Write-Output

Write-Output '=== Loaded configuration ==='
& $bin -nologo -c 2>&1 | Out-String | Write-Output

Write-Output '=== 5. Event check ==='
Start-Sleep -Seconds 5
$checkJson = Join-Path $LogDir "sysmon_check_$stamp.json"
& $python (Join-Path $proj 'tools\sysmon_check.py') --out $checkJson
$checkCode = $LASTEXITCODE
Write-Output "Check script exit code: $checkCode"

Write-Output '=== Independent cross-check (Get-WinEvent) ==='
$allPass = $false
if (Test-Path $checkJson) {
    $res = Get-Content $checkJson -Raw | ConvertFrom-Json
    $allPass = [bool]$res.all_pass
    # One read of the newest events (the check just ran, so they are recent) instead of one
    # whole-log XPath scan per record, which takes minutes on a full 1 GB log.
    $recent = @{}
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 -ErrorAction SilentlyContinue |
        ForEach-Object { $recent[[long]$_.RecordId] = $_ }
    foreach ($p in $res.checks.PSObject.Properties) {
        if (-not $p.Value.pass) { Write-Output ("{0,-36} MISSING" -f $p.Name); continue }
        foreach ($rid in $p.Value.record_ids) {
            $e = $recent[[long]$rid]
            if ($e) { Write-Output ("{0,-36} record {1}: Get-WinEvent sees event {2} at {3:o}" -f $p.Name, $rid, $e.Id, $e.TimeCreated) }
            else { Write-Output ("{0,-36} record {1}: NOT FOUND by Get-WinEvent" -f $p.Name, $rid); $allPass = $false }
        }
    }
}

Write-Output '=== Sysmon log size ==='
# Ask Windows for the totals instead of reading every event (reading 100k+ events took >10 min).
$info = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
if ($info) { Write-Output ("Records in log: {0} · file size {1:N1} MB of {2:N0} MB" -f $info.RecordCount, ($info.FileSize / 1MB), ($info.MaximumSizeInBytes / 1MB)) }

if (-not $allPass) { Stop-With 9 'Not every expected event was found.' }
Write-Output 'ALL CHECKS PASSED'
Stop-Transcript | Out-Null
exit 0
