<#
  Creates the Analyst Lab Windows 11 VM with VirtualBox's built-in unattended install
  (VBoxManage unattended), the standard way to install Windows in VirtualBox without clicking
  through setup. No admin rights needed. DESIGN.md 6.2.

    create_vm.ps1                # show the plan only (nothing is created)
    create_vm.ps1 -Create        # create the VM and start the automatic install

  NAT note: since VirtualBox 7.0 a NAT guest can't reach the host's 127.0.0.1 via 10.0.2.2
  unless --nat-localhostreachable1 is on; the lab's test server and VM receiver depend on it.

  Slow-mode note: with Memory Integrity on, VirtualBox runs on Windows' hypervisor (NEM). The
  first install (4 CPUs, host I/O cache off) hung after the guest reset its disk ("AHCI#0: Port 0
  reset", 2026-10-16). Hence 2 CPUs + host I/O cache on + disk marked as SSD (VERIFICATION_LOG).

  VM: AnalystLab-Win11 · Windows 11 Pro · 2 CPUs · 8 GB RAM · 64 GB dynamically sized disk
      EFI + TPM 2.0 + Secure Boot (Windows 11 requirements) · NAT network · no shared
      clipboard, folders or USB (isolation) · Guest Additions (status, clean shutdown; their
      host time sync is turned OFF, see below)
  Local VM account: "analyst" with a random password saved to
  recordings\.state\vm\credentials.txt (git-ignored; a test credential for this lab VM only).
#>
param([switch]$Create)

$ErrorActionPreference = 'Stop'
$proj = Split-Path $PSScriptRoot -Parent
$vbm = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$vm = 'AnalystLab-Win11'
$iso = Join-Path $proj 'downloads\iso\Win11_26300_English_x64.iso'
$isoSha256 = 'BD4307DF32BC8AF33B39CCECB1174AEB345386630F89A2B86C7A4E36B55EA650'   # published by Microsoft
$credDir = Join-Path $proj 'recordings\.state\vm'
$credFile = Join-Path $credDir 'credentials.txt'

function Step($msg) { Write-Output "--> $msg" }

# PowerShell 5.1 doesn't stop on a failing external program, so every VBoxManage call goes
# through Vbox, which stops the script at the first non-zero exit code.
function Vbox {
    & $vbm @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args[0]) $($args[1]) failed (exit $LASTEXITCODE). Stopped; nothing after this step ran." }
}
# Best-effort VBoxManage call whose failure doesn't matter (e.g. a key press). With
# ErrorActionPreference=Stop, PowerShell 5.1 turns ANY stderr text from a redirected native
# command into a terminating error, so these run with 'Continue' locally.
function VboxQuiet {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $vbm @args 2>$null | Out-Null } finally { $ErrorActionPreference = $old }
}
function VboxText {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { (& $vbm @args 2>&1 | Out-String) } finally { $ErrorActionPreference = $old }
}

# --- checks -------------------------------------------------------------------------
if (-not (Test-Path $iso)) { throw "ISO not found: $iso" }
Step 'Verifying ISO fingerprint against Microsoft''s published SHA-256'
$hash = (Get-FileHash $iso -Algorithm SHA256).Hash
if ($hash -ne $isoSha256) { throw "ISO hash mismatch: $hash" }
Write-Output '    ISO verified.'

if ((& $vbm list vms) -match "`"$vm`"") { throw "A VM named $vm already exists. Nothing changed." }

Step 'Detecting editions on the ISO'
$detect = VboxText unattended detect --iso=$iso
$pro = [regex]::Match($detect, 'Image #(\d+)\s*=\s*Windows 11 Pro\b')
$imageIndex = if ($pro.Success) { [int]$pro.Groups[1].Value } else { 1 }
Write-Output "    Using image index $imageIndex ($(if ($pro.Success) {'Windows 11 Pro'} else {'first image; Pro not found'}))"

$baseFolder = (& $vbm list systemproperties | Select-String 'Default machine folder:\s*(.+)$').Matches[0].Groups[1].Value.Trim()
$disk = Join-Path $baseFolder "$vm\$vm.vdi"
$freeGB = [math]::Round((Get-PSDrive ($baseFolder.Substring(0,1))).Free / 1GB, 1)

Write-Output ''
Write-Output 'PLAN'
Write-Output "  VM name:        $vm"
Write-Output "  Folder:         $baseFolder\$vm"
Write-Output '  Hardware:       2 CPUs, 8 GB RAM, 128 MB video, EFI, TPM 2.0, Secure Boot, host I/O cache on'
Write-Output "  Disk:           $disk (64 GB max, grows as used; ~25-30 GB expected)"
Write-Output "  Free space now: $freeGB GB"
Write-Output '  Network:        NAT only (VM reaches the host at 10.0.2.2)'
Write-Output '  Isolation:      no shared clipboard, drag-and-drop, folders or USB'
Write-Output "  Install:        unattended, image $imageIndex, account 'analyst', English (US), Baghdad time zone, Guest Additions"
Write-Output "  Credentials:    $credFile (git-ignored)"
if (-not $Create) { Write-Output ''; Write-Output 'Plan only. Run with -Create to build it.'; exit 0 }

# --- create ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force $credDir | Out-Null
if (-not (Test-Path $credFile)) {
    $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $pw = -join (1..20 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    Set-Content -Path $credFile -Value $pw -NoNewline -Encoding ascii
}

Step 'Creating and configuring the VM'
Vbox createvm --name $vm --ostype Windows11_64 --register | Out-Null
Vbox modifyvm $vm --cpus 2 --memory 8192 --vram 128 --graphicscontroller vboxsvga `
    --firmware efi --tpm-type 2.0 --nic1 nat --nat-localhostreachable1 on `
    --audio-enabled off --usb-ohci off --usb-ehci off --usb-xhci off `
    --clipboard-mode disabled --drag-and-drop disabled
# No host time sync: in slow mode VirtualBox's corrections of the guest clock made Sysmon's
# network/DNS timestamps (events 3, 22) up to 9 s wrong; without them 0 of 358 were (2026-10-17,
# VERIFICATION_LOG). The guest keeps its own clock (set from the host at each boot).
Vbox setextradata $vm 'VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled' 1
Vbox modifynvram $vm inituefivarstore
Vbox modifynvram $vm enrollmssignatures
Vbox modifynvram $vm enrollorclpk
Vbox modifynvram $vm secureboot --enable

Step 'Creating the virtual disk'
Vbox createmedium disk --filename $disk --size 65536 --format VDI --variant Standard | Out-Null
Vbox storagectl $vm --name SATA --add sata --controller IntelAhci --portcount 2 --hostiocache on
Vbox storageattach $vm --storagectl SATA --port 0 --device 0 --type hdd --medium $disk --nonrotational on

Step 'Preparing the unattended install'
# 'Arabic Standard Time' is Windows' name for Baghdad (UTC+3); 'Arab Standard Time' is Riyadh.
Vbox unattended install $vm --iso=$iso --image-index=$imageIndex --user=analyst --user-password-file=$credFile --admin-password-file=$credFile `
    --full-user-name='Analyst Lab' --locale=en_US --country=US --time-zone='Arabic Standard Time' `
    --hostname='analystlab-vm.lab' --install-additions

Step 'Starting the VM (a window opens; Windows installs itself, ~30-60 min)'
Vbox startvm $vm --type gui

# On EFI firmware the Windows installer disc shows "Press any key to boot from CD or DVD" for
# ~5 s and gives up if nobody presses a key (found on the first run, 2026-10-16). Send Space
# for the first 20 s of THIS first boot only: during the install's later restarts a key press
# would start setup over, so nothing is sent after that.
Step 'Pressing Space for the installer''s "boot from CD" prompt (first 20 s only)'
$until = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $until) {
    VboxQuiet controlvm $vm keyboardputscancode 39 b9   # Space down/up
    Start-Sleep -Milliseconds 500
}
Write-Output 'Done. Do not type in the VM window while it installs.'
Write-Output 'If "Press any key to boot from CD or DVD" appears during later restarts, do NOT press a key.'
