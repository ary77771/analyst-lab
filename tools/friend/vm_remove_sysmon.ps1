<#
  Friend-package VM test only: removes Sysmon from the lab VM so Setup-AnalystLab.exe meets a
  laptop WITHOUT Sysmon, as a friend's would be. Refuses to run anywhere but the lab VM.
  Undone by restoring the 'clean' snapshot afterwards. Needs admin (PREP_NO_SYSMON.cmd asks).
#>
$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'VirtualBox' -or -not (Test-Path 'C:\LabTools')) {
    Write-Output "REFUSED: this is not the lab VM (model '$model')."
    exit 3
}
$bin = Join-Path $env:WINDIR 'System32\sysmon.exe'
& $bin -nologo -u force 2>&1 | Out-String | Write-Output
Start-Sleep -Seconds 3
$left = Get-Service | Where-Object { $_.Name -match '^sysmon' }
if ($left) { Write-Output "Sysmon service still present: $($left.Name) ($($left.Status))"; exit 4 }
Write-Output 'Sysmon removed from the VM. Now double-click Setup-AnalystLab.exe on this CD.'
exit 0
