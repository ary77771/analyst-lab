<#
  The lab's test server: Python's built-in web server (http.server), no code of our own.
  Serves scenarios\www\ on 127.0.0.1:18765 only (not reachable from the Wi-Fi network).
  The VM reaches it as http://10.0.2.2:18765 through VirtualBox NAT. (Port 8765 until 2026-10-18,
  when another program on this laptop took it; each run records the address it used.)

    test_server.ps1          # runs until closed (Ctrl+C)
#>
$proj = Split-Path $PSScriptRoot -Parent
& (Join-Path $proj '.venv\Scripts\python.exe') -m http.server 18765 --bind 127.0.0.1 --directory (Join-Path $proj 'scenarios\www')
