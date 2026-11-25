<#
  Builds the Analyst Lab "virtual CD" for the VM. The VM is isolated (no shared folders or
  clipboard), so files go in on a read-only CD. VirtualBox's own format for that is a .viso
  file: a text list of host files that VirtualBox shows to the VM as a CD (the unattended
  install uses the same mechanism). No admin rights needed. DESIGN.md 6.2.

    make_vm_bundle.ps1             # check the pieces and write build\analystlab-vm.viso
    make_vm_bundle.ps1 -Download   # first download Python + the agent's packages (~40 MB)
                                   # from python.org and PyPI into downloads\vm\ (git-ignored)

  CD layout:   SETUP.cmd                      double-click inside the VM
               lab\agent\*.py                 the agent (same code as on the laptop)
               lab\tools\...                  install scripts, Sysmon config, sysmon_check.py
               lab\requirements-vm.txt
               python\python-<ver>-amd64.exe  official installer, same version as the laptop
               wheels\*.whl                   packages for an offline install
#>
param([switch]$Download, [switch]$WithKey)   # -WithKey: a SETUP CD for a new snapshot (docs/plans/vm-security.md)

$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
$venvPy = Join-Path $proj '.venv\Scripts\python.exe'
$pyVersion = ((& $venvPy --version) -replace '^Python\s+', '').Trim()   # match the laptop exactly
$dl = Join-Path $proj 'downloads\vm'
$installer = Join-Path $dl "python-$pyVersion-amd64.exe"
$wheels = Join-Path $dl 'wheels'
$req = Join-Path $proj 'tools\vm\requirements-vm.txt'
$viso = Join-Path $proj 'build\analystlab-vm.viso'

if ($Download) {
    New-Item -ItemType Directory -Force $wheels | Out-Null
    if (-not (Test-Path $installer)) {
        $url = "https://www.python.org/ftp/python/$pyVersion/python-$pyVersion-amd64.exe"
        Write-Output "--> Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    }
    Write-Output '--> Downloading packages (wheels only, versions pinned by requirements-lock.txt)'
    & $venvPy -m pip download -r $req -c (Join-Path $proj 'requirements-lock.txt') --only-binary=:all: -d $wheels --disable-pip-version-check --quiet
    if ($LASTEXITCODE -ne 0) { throw 'pip download failed' }
}

# --- checks -----------------------------------------------------------------------------
$missing = @()
if (-not (Test-Path $installer)) { $missing += "Python installer $installer" }
foreach ($pkg in (Get-Content $req | Where-Object { $_ -match '^\s*([A-Za-z0-9_.-]+)==' } | ForEach-Object { $Matches[1] })) {
    # wheel file names use _ for - ; each package the agent needs must be on the CD
    $pattern = ($pkg -replace '-', '_') + '-*.whl'
    if (-not (Get-ChildItem (Join-Path $wheels $pattern) -ErrorAction SilentlyContinue)) { $missing += "wheel for $pkg in $wheels" }
}
if ($missing) {
    Write-Output 'Missing (run with -Download after approval):'
    $missing | ForEach-Object { Write-Output "  - $_" }
    exit 1
}
$sig = Get-AuthenticodeSignature $installer
Write-Output "Python installer: $pyVersion · signature $($sig.Status) · $($sig.SignerCertificate.Subject -replace ',.*$', '')"
Write-Output "SHA-256: $((Get-FileHash $installer -Algorithm SHA256).Hash)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
    throw 'The Python installer is not validly signed by the Python Software Foundation.'
}

# --- file list ----------------------------------------------------------------------------
$map = [ordered]@{}
$map['/SETUP.cmd'] = Join-Path $proj 'tools\vm\SETUP.cmd'
Get-ChildItem (Join-Path $proj 'agent\*.py') | ForEach-Object { $map["/lab/agent/$($_.Name)"] = $_.FullName }
foreach ($t in 'install_sysmon.ps1', 'install_agent_task.ps1', 'sysmon_check.py') { $map["/lab/tools/$t"] = Join-Path $proj "tools\$t" }
$map['/lab/tools/vm_guest_setup.ps1'] = Join-Path $proj 'tools\vm\vm_guest_setup.ps1'
$map['/lab/tools/launcher_stub.ps1'] = Join-Path $proj 'tools\vm\launcher_stub.ps1'
$map['/DIAG.cmd'] = Join-Path $proj 'tools\vm\DIAG.cmd'
$map['/lab/tools/vm_diag.ps1'] = Join-Path $proj 'tools\vm\vm_diag.ps1'
$map['/CRASHTEST.cmd'] = Join-Path $proj 'tools\vm\CRASHTEST.cmd'
$map['/lab/tools/vm_crash_test.ps1'] = Join-Path $proj 'tools\vm\vm_crash_test.ps1'
$map['/lab/tools/sysmon/sysmon-config.xml'] = Join-Path $proj 'tools\sysmon\sysmon-config.xml'
$map['/lab/requirements-vm.txt'] = $req
# The lab key (security review 2026-10-23): made once on the laptop (git-ignored, never printed);
# SETUP stores it in the VM where only administrators can read it, the VM agent sends it with every
# batch, and the receiver then refuses VM events without it. Delete the file to start a new key.
# Only a SETUP CD carries the key (-WithKey); eject it before taking the snapshot (the CD is
# readable by everyone in the VM). DIAG/CRASHTEST bundles are built without it.
$keyFile = Join-Path $proj 'recordings\.state\lab_key.txt'
if ($WithKey -and -not (Test-Path $keyFile)) {
    New-Item -ItemType Directory -Force (Split-Path $keyFile) | Out-Null
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    Set-Content -Path $keyFile -Value (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') -Encoding ascii -NoNewline
    Write-Output 'Made a new lab key (the receiver requires it after its next restart: build the new VM snapshot first).'
}
if ($WithKey) { $map['/lab_key.txt'] = $keyFile }
$map["/python/$(Split-Path $installer -Leaf)"] = $installer
Get-ChildItem (Join-Path $wheels '*.whl') | ForEach-Object { $map["/wheels/$($_.Name)"] = $_.FullName }

foreach ($src in $map.Values) { if (-not (Test-Path $src)) { throw "Missing file: $src" } }

# .viso format (as written by VirtualBox's unattended install): one line, shell-style quoting
$parts = @('--iprt-iso-maker-file-marker-bourne-sh', [guid]::NewGuid().ToString(), '--file-mode=0444', '--dir-mode=0555')
foreach ($k in $map.Keys) { $parts += "'$k=$($map[$k])'" }
New-Item -ItemType Directory -Force (Split-Path $viso) | Out-Null
Set-Content -Path $viso -Value ($parts -join ' ') -Encoding ascii -NoNewline

$mb = ($map.Values | ForEach-Object { (Get-Item $_).Length } | Measure-Object -Sum).Sum / 1MB
Write-Output ("Wrote {0}: {1} files, {2:N1} MB" -f $viso, $map.Count, $mb)
Write-Output 'Insert it into the VM (replaces the Windows install disc in the VM''s DVD drive):'
Write-Output "  VBoxManage storageattach AnalystLab-Win11 --storagectl SATA --port 1 --device 0 --type dvddrive --medium `"$viso`""
exit 0
