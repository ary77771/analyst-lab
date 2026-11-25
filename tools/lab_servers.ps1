<#
  Starts the laptop side of the VM lab, each in its own minimized window (close the window to
  stop it). Both listen on 127.0.0.1 only; the VM reaches them as 10.0.2.2 (VirtualBox NAT).
    - VM receiver  127.0.0.1:8770  python -m engine.receiver   (VM events -> recordings\vm\)
    - test server  127.0.0.1:18765 tools\test_server.ps1         (serves scenarios\www\)
  No admin rights needed. A server that is already running is left alone.

    lab_servers.ps1           # start what isn't running, then check both
    lab_servers.ps1 -Check    # only check
#>
param([switch]$Check)

$proj = Split-Path $PSScriptRoot -Parent
$python = Join-Path $proj '.venv\Scripts\python.exe'
# "Listening" = something accepts a TCP connection on the port. Not Get-NetTCPConnection -State
# Listen: since the Windows preview update KB5127936 (2026-10-31) it reports listening sockets with
# a blank or wrong state, so this script thought running servers were down and started second
# copies (Python's http.server on Windows can share a port with them).
function Listening([int]$port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { return $c.ConnectAsync('127.0.0.1', $port).Wait(1000) -and $c.Connected }
    catch { return $false }
    finally { $c.Dispose() }
}
$servers = @(
    @{ name = 'VM receiver'; port = 8770; file = $python; args = @('-m', 'engine.receiver') },
    @{ name = 'test server'; port = 18765; file = 'powershell.exe'
       args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $proj 'tools\test_server.ps1')`"") }
)

if (-not $Check) {
    foreach ($s in $servers) {
        if (Listening $s.port) { Write-Output "$($s.name): already running on 127.0.0.1:$($s.port)"; continue }
        Start-Process -FilePath $s.file -ArgumentList $s.args -WorkingDirectory $proj -WindowStyle Minimized | Out-Null
        Write-Output "$($s.name): starting..."
    }
}

# Something listening is not enough: another program on the same port once answered the VM's
# download with "404" (2026-10-18). Each server must answer like ours.
function IsOurs($s) {
    try {
        if ($s.port -eq 18765) {
            return (Invoke-WebRequest -Uri 'http://127.0.0.1:18765/analystlab-test-server.txt' -UseBasicParsing -TimeoutSec 5).Content -match 'analyst-lab test server'
        }
        return [bool](Invoke-RestMethod -Uri 'http://127.0.0.1:8770/health' -TimeoutSec 5).ok
    } catch { return $false }
}
$ok = $true
foreach ($s in $servers) {
    $deadline = (Get-Date).AddSeconds($(if ($Check) { 0 } else { 20 }))
    while (-not (Listening $s.port) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    $state = if (-not (Listening $s.port)) { 'NOT RUNNING' }
             elseif (IsOurs $s) { 'RUNNING' }
             else { 'PORT TAKEN BY ANOTHER PROGRAM (close it, then run this again)' }
    $ok = $ok -and ($state -eq 'RUNNING')
    Write-Output ("{0,-12} 127.0.0.1:{1}  {2}" -f $s.name, $s.port, $state)
}
if ($ok) { exit 0 } else { exit 1 }
