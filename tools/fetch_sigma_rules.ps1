# Get the community Sigma rules at the exact commit the project uses (DESIGN 4.6).
#
#   powershell -File tools\fetch_sigma_rules.ps1
#
# Downloads github.com/SigmaHQ/sigma (about 60 MB) into downloads\sigma (git-ignored) and checks
# out commit e3f4662, so every clone of this project detects with the same 1,444 rules.
# Does nothing if that commit is already there. Ask Yousif before running it on a new machine
# (CLAUDE.md rule 5: downloads).
# Licence: the rules are under the Detection Rule License (DRL) 1.1: use is free, but alerts
# and reports must credit the rule's author(s) (engine/detect.py keeps each rule's author).

$ErrorActionPreference = 'Stop'
$Commit = 'e3f466211866e92553d8389d621ed13cfed5523d'
$Dest = Join-Path (Split-Path $PSScriptRoot -Parent) 'downloads\sigma'

if (Test-Path (Join-Path $Dest '.git')) {
    $have = (& git -C $Dest rev-parse HEAD).Trim()
    if ($have -eq $Commit) { Write-Output "Sigma rules already at $Commit."; exit 0 }
    & git -C $Dest fetch --quiet origin
} else {
    New-Item -ItemType Directory -Force (Split-Path $Dest -Parent) | Out-Null
    & git clone --quiet https://github.com/SigmaHQ/sigma.git $Dest
}
& git -C $Dest -c advice.detachedHead=false checkout --quiet $Commit
if ($LASTEXITCODE -ne 0) { throw "could not check out $Commit" }
Write-Output "Sigma rules at $Commit in $Dest"
