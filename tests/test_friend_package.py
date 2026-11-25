"""Friend package glue: paths inside the bundle, the one-program launcher, background compression
in the agent, and static checks of the Setup script (it needs admin, so it is run for real
only in the VM test)."""

import gzip
import json
import os
import sys
import time
import uuid

from agent import paths
from statusapp import launcher
from tests.test_agent_mechanics import run_agent, write_events

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_PS1 = os.path.join(PROJECT_ROOT, "tools", "friend", "friend_setup.ps1")


def test_paths_in_the_checkout_and_in_the_bundle(monkeypatch, tmp_path):
    monkeypatch.delenv("ANALYSTLAB_DATA", raising=False)
    assert paths.project_root() == PROJECT_ROOT
    assert paths.recordings_root() == os.path.join(PROJECT_ROOT, "recordings")
    exe = tmp_path / "Analyst Lab" / "AnalystLab.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setenv("ProgramData", str(tmp_path / "PD"))
    assert paths.project_root() == str(tmp_path / "Analyst Lab")        # what the tagger treats as ours
    assert paths.recordings_root() == str(tmp_path / "PD" / "AnalystLab" / "recordings")
    monkeypatch.setenv("ANALYSTLAB_DATA", str(tmp_path / "test"))
    assert paths.recordings_root() == str(tmp_path / "test" / "recordings")


def test_launcher_dispatches(monkeypatch):
    calls = []
    import agent.main
    import statusapp.app
    monkeypatch.setattr(agent.main, "main", lambda argv: calls.append(("agent", argv)) or 0)
    monkeypatch.setattr(statusapp.app, "main", lambda argv: calls.append(("status", argv)) or 0)
    launcher.main(["agent", "--label", "host"])
    launcher.main([])
    launcher.main(["status", "--mode", "lab"])
    assert calls == [("agent", ["--label", "host"]), ("status", []), ("status", ["--mode", "lab"])]


def test_agent_compresses_its_own_finished_days_only(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    old = time.time() - 3 * 86400
    for label in ("test", "other"):
        (tmp_path / label).mkdir()
        p = tmp_path / label / "2026-10-01.jsonl"
        p.write_bytes(json.dumps({"n": 1}).encode() + b"\n")
        os.utime(p, (old, old))
    write_events(provider, 1)
    from agent.main import Agent, parse_args
    args = parse_args(["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
                       "--label", "test", "--recordings", str(tmp_path), "--run-seconds", "3", "--no-ports",
                       "--compress-finished", "--compress-delay", "0"])
    a = Agent(args)
    a.run()
    a._compressor.join(10)
    assert gzip.decompress((tmp_path / "test" / "2026-10-01.jsonl.gz").read_bytes()) == b'{"n": 1}\n'
    assert not (tmp_path / "test" / "2026-10-01.jsonl").exists()
    assert (tmp_path / "other" / "2026-10-01.jsonl").exists()                # not this agent's folder


def test_agent_without_the_flag_compresses_nothing(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    (tmp_path / "test").mkdir()
    p = tmp_path / "test" / "2026-10-01.jsonl"
    p.write_text("{}\n", encoding="utf-8")
    old = time.time() - 3 * 86400
    os.utime(p, (old, old))
    write_events(provider, 1)
    run_agent(provider, tmp_path)
    assert p.exists()


def test_setup_script_parses_and_logs_nothing_personal():
    import subprocess
    check = ("$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
             f"'{SETUP_PS1}',[ref]$t,[ref]$e);$e.Count")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", check], capture_output=True, text=True)
    assert out.stdout.strip() == "0", out.stdout + out.stderr
    text = open(SETUP_PS1, encoding="utf-8").read()
    assert "Start-Transcript" not in text.replace("not Start-Transcript", "")   # its header names user + PC
    assert "Write-Output" not in text        # would also leak into function return values
    assert "-RunLevel Highest" in text and "--compress-finished" in text
    # Sysmon is only removed if WE installed it
    assert "$m.sysmon -in @('builtin', 'standalone')" in text


def test_inno_script_points_at_the_right_files():
    iss = open(os.path.join(PROJECT_ROOT, "tools", "friend", "AnalystLab.iss"), encoding="utf-8").read()
    for needed in (r"build\dist\AnalystLab\*", r"tools\friend\friend_setup.ps1", r"tools\sysmon\sysmon-config.xml",
                   "-Remove", "status --first-run", "PrivilegesRequired=admin"):
        assert needed in iss, needed
    assert "users-modify" not in iss        # the data folder is locked down by the script instead
    for rel in (r"tools\friend\friend_setup.ps1", r"tools\sysmon\sysmon-config.xml", r"tools\friend\BEFORE_YOU_INSTALL.txt"):
        assert os.path.exists(os.path.join(PROJECT_ROOT, rel))


def test_setup_script_follows_the_review_rules():
    text = open(SETUP_PS1, encoding="utf-8").read()
    assert text.count("-UserId 'SYSTEM' -LogonType ServiceAccount") == 2      # recorder + finish task
    assert "-LogonType Interactive" not in text and "$env:USERNAME" not in text
    assert "--start now" in text and "--control-dir" in text
    assert "Remove-Task $finishTask -KeepRunning" in text                       # never stops itself
    assert "wevtutil cl $channel" in text and "Disable-WindowsOptionalFeature" in text
    assert "/inheritance:r" in text and "(OI)(CI)M" in text                    # only control\ writable
    assert "users-modify" not in text
    assert "Join-Path $AppDir \"setup\\sysmon-config-schema" in text            # not in a user folder
    assert "Entries | Where-Object { $_.FullName -eq 'Sysmon64.exe' }" in text  # nothing else from the zip
    assert "Exception.GetType().Name" in text and "$_.Exception.Message" not in text


def test_setup_never_stamps_folder_permissions_onto_files():
    # VM test 2026-10-20: "/grant ... (OI)(CI) ... /T" left the setup log with no access at all
    text = open(SETUP_PS1, encoding="utf-8").read()
    for line in text.splitlines():
        if line.strip().startswith("icacls") and "/grant" in line:
            assert "/T" not in line, line
    assert 'icacls "$DataDir\\*" /reset /T' in text            # files inherit from their folder
    # the folder is locked BEFORE the first log line is written
    assert text.index("$signedIn = Set-DataFolderAccess") < text.index("Log (\"=== {0} {1} ===\"")
    assert "catch { } } }" in text                             # a failed log write never stops Setup


def test_setup_script_always_runs_as_64_bit():
    # VM test 2026-10-20: the 32-bit uninstaller got 32-bit PowerShell, which can't see System32\sysmon.exe
    text = open(SETUP_PS1, encoding="utf-8").read()
    assert "-not [Environment]::Is64BitProcess" in text and "Sysnative\\WindowsPowerShell" in text   # x64 and Arm64
    assert text.index("Is64BitProcess") < text.index("New-Item -ItemType Directory -Force $DataDir")
    assert "AnalystLab-uninstall-log.txt" in text                     # uninstall's log survives uninstall


def test_friend_guide_pictures_exist_and_nothing_personal():
    import re
    gdir = os.path.join(PROJECT_ROOT, "tools", "friend", "guide")
    html = open(os.path.join(gdir, "guide.html"), encoding="utf-8").read()
    pics = re.findall(r"\{\{IMG:([\w.-]+)\}\}", html)
    assert pics and all(os.path.exists(os.path.join(gdir, p)) for p in pics)
    assert "http://" not in html and "https://" not in html          # readable offline, loads nothing
    for promise in ("stays on your laptop", "Export my statistics", "Uninstall everything", "Run anyway",
                    "Day 1: a quick check", "Before you uninstall", "permanently deletes everything"):
        assert promise in html

def _acl_harness(tmp_path, user):
    """Run the REAL Set-DataFolderAccess on a temp folder, with the signed-in user faked."""
    import re as _re
    import subprocess
    text = open(SETUP_PS1, encoding="utf-8").read()
    fn = text[text.index("function Set-DataFolderAccess"):text.index("if (-not $Remove -and -not $Finish)")]
    data = tmp_path / "AnalystLab"
    who = f"'{user}'" if user else "$null"
    script = tmp_path / f"h-{bool(user)}.ps1"
    script.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data}'; $controlDir = Join-Path $DataDir 'control'\n"
        "New-Item -ItemType Directory -Force $DataDir | Out-Null\n"
        f"function Get-CimInstance {{ [pscustomobject]@{{ UserName = {who} }} }}\n"
        "if (-not (Test-Path (Join-Path $DataDir 'install.json'))) { Set-Content (Join-Path $DataDir 'install.json') '{}' }\n"
        + fn + "\n$r = Set-DataFolderAccess\n'R=' + $r\n"
        "$ErrorActionPreference = 'Continue'\n"
        "'ACL=' + ((Get-Acl $DataDir).Access | ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights }) -join '|'\n",
        encoding="utf-8")
    out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                         capture_output=True, text=True)
    return out.stdout + out.stderr


def test_a_run_with_nobody_signed_in_keeps_the_folder_private(tmp_path):
    # review 2026-10-20: the finish run at startup (nobody signed in) used to ADD "all users"
    import getpass
    import os as _os
    me = _os.environ.get("USERDOMAIN", "") + "\\" + getpass.getuser()
    first = _acl_harness(tmp_path, me)
    assert "R=True" in first and "ACL=" in first and "SYSTEM" in first           # the list really printed
    assert "BUILTIN\\Users" not in first
    again = _acl_harness(tmp_path, None)
    assert "R=False" in again and "SYSTEM" in again and "BUILTIN\\Users" not in again   # still friend-only


def test_setup_finish_run_never_touches_permissions_and_cleans_up():
    text = open(SETUP_PS1, encoding="utf-8").read()
    assert "if (-not $Remove -and -not $Finish)" in text
    assert "if ($Finish) { try { Remove-Task $finishTask -KeepRunning } catch { } }" in text   # in Done
    # the recorder is only set up after the restart, never before it
    assert text.index("if ($needRestart) { Done 3") < text.index("Step 'registering the recorder task'")
