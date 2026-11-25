"""Scenario S4 (unusual program chain viewer -> cmd -> PowerShell) against both checkers. The
key risk: cmd.exe and powershell.exe also run elsewhere in the VM (the scenario runner IS
PowerShell, and it connects to the laptop and writes files), so the checkers must follow the
chain by process identity and never blame the runner's activity on the scenario."""

import json
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
from test_check_graph_scenario import pool_file  # noqa: E402  (layer 2 needs a pool of normal rates)

VIEWER = r"D:\s4\s4_viewer.exe"
CMD = r"C:\Windows\System32\cmd.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS_LINE = PS + r" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File D:\s4\s4_note.ps1"
BASE = datetime(2026, 10, 20, 13, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def ev(rid, eid, sec, **data):
    t = (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal", "data": {"UtcTime": t, **data}}


def start(rid, sec, image, g, parent_g, parent_image, pid, line=None):
    return ev(rid, 1, sec, Image=image, ProcessGuid=g, ProcessId=pid, ParentProcessGuid=parent_g,
              ParentImage=parent_image, CommandLine=line or image)


def story(script_line=PS_LINE, ps_parent=("{C}", CMD), with_cmd=True, policy_files=True):
    rows = [start(100, 1, VIEWER, "{V}", "{RUN}", PS, 10)]
    if with_cmd:
        rows.append(start(101, 1.5, CMD, "{C}", "{V}", VIEWER, 11, "cmd.exe /c " + PS_LINE))
    rows.append(start(102, 2, PS, "{P}", ps_parent[0], ps_parent[1], 12, script_line))
    if policy_files:              # PowerShell's own script-policy check (seen in the first real run)
        tmp = r"C:\Users\labuser\AppData\Local\Temp\__PSScriptPolicyTest_"
        for i, (eid, ext) in enumerate([(11, ".ps1"), (11, ".psm1"), (26, ".ps1"), (26, ".psm1")]):
            rows.append(ev(110 + i, eid, 3 + i * 0.01, Image=PS, ProcessGuid="{P}", TargetFilename=tmp + "ab12cd34" + ext))
    rows.append(ev(103, 5, 5, Image=PS, ProcessGuid="{P}", ProcessId=12))
    if with_cmd:
        rows.append(ev(104, 5, 5.2, Image=CMD, ProcessGuid="{C}", ProcessId=11))
    rows.append(ev(105, 5, 7.3, Image=VIEWER, ProcessGuid="{V}", ProcessId=10))
    return rows


def decoys():
    """The runner's own PowerShell (started before the window) connects and writes; another,
    unrelated cmd -> PowerShell chain runs at the same time."""
    return [ev(200, 3, 3, Image=PS, ProcessGuid="{RUN}", Protocol="tcp", Initiated="true", SourceIp="10.0.2.15",
               SourcePort=50001, DestinationIp="10.0.2.2", DestinationPort=8770),
            ev(201, 11, 4, Image=PS, ProcessGuid="{RUN}", TargetFilename=r"C:\AnalystLab\scenarios\_runner\note.txt"),
            start(202, 2.5, CMD, "{C2}", "{RUN}", PS, 20, "cmd.exe /c echo hi"),
            start(203, 2.7, PS, "{P2}", "{C2}", CMD, 21, PS + r" -File D:\other\s4_note.ps1")]


def both(tmp_path, capsys, rows, end=9):
    for label, data in (("vm", rows), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S4", "exit_code": 0,
                                                    "time": iso(0), "start": iso(0), "end": iso(end),
                                                    "server": "http://10.0.2.2:18765"}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-20.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    a = check_scenario.main(["s4", "--recordings", str(tmp_path)])
    pool_file(tmp_path)
    b = check_graph_scenario.main(["s4", "--recordings", str(tmp_path)])
    return a, b, capsys.readouterr().out


def test_true_s4_story_passes_both_checks(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, story())
    assert (a, b) == (0, 0), out
    assert "fact  PASS  viewer started the shell" in out and "fact  PASS  shell started PowerShell" in out


def test_the_runners_own_powershell_and_another_chain_are_not_blamed(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, sorted(story() + decoys(), key=lambda r: r["time"]))
    assert (a, b) == (0, 0), out
    assert "absent  PASS  event 3" in out and "absent  PASS  event 11" in out


def test_powershell_started_directly_by_the_viewer_is_not_the_story(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, story(ps_parent=("{V}", VIEWER), with_cmd=False))
    assert a == 1 and b == 1


def test_another_script_fails(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(script_line=PS + r" -File D:\s4\other.ps1"))
    assert a == 1 and "step   3  FAIL" in out


def test_a_connection_by_the_scenarios_powershell_fails(tmp_path, capsys):
    rows = story()
    rows.insert(3, ev(150, 3, 3, Image=PS, ProcessGuid="{P}", Protocol="tcp", Initiated="true", SourceIp="10.0.2.15",
                      SourcePort=50002, DestinationIp="10.0.2.2", DestinationPort=18765))
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  event 3" in out

def test_any_other_file_written_by_the_scenarios_powershell_fails(tmp_path, capsys):
    rows = story()
    rows.insert(3, ev(160, 11, 3.5, Image=PS, ProcessGuid="{P}", TargetFilename=r"C:\Users\labuser\Documents\note.txt"))
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  event 11 for the scenario's programs/files: 1" in out


def test_without_powershells_policy_files_the_story_is_incomplete(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(policy_files=False))
    assert a == 1 and "step   4  FAIL" in out


# -- review 2026-10-20: false passes that must now fail ------------------------------------------
def test_a_program_started_by_the_scenarios_powershell_fails(tmp_path, capsys):
    rows = story()
    rows.insert(3, start(170, 3.2, r"C:\Windows\System32\notepad.exe", "{N}", "{P}", PS, 30))
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  event 1 for the scenario's programs/files: 1" in out


def test_policy_test_file_outside_the_temp_folder_fails(tmp_path, capsys):
    rows = story()
    for r in rows:
        if r.get("event_id") == 11:
            r["data"]["TargetFilename"] = r["data"]["TargetFilename"].replace(r"\AppData\Local\Temp", r"\Elsewhere")
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "step   4  FAIL" in out


def test_deleting_a_different_policy_file_than_was_created_fails(tmp_path, capsys):
    rows = story()
    for r in rows:
        if r.get("event_id") == 26 and r["data"]["TargetFilename"].endswith(".ps1"):
            r["data"]["TargetFilename"] = r["data"]["TargetFilename"].replace("ab12cd34", "zz99zz99")
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "0 of 1 are files step 4 created" in out


def test_a_script_from_another_folder_fails(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(script_line=PS + r" -File C:\Users\Public\s4_note.ps1"))
    assert a == 1 and "step   3  FAIL" in out


def test_a_viewer_from_another_folder_fails(tmp_path, capsys):
    rows = story()
    rows[0]["data"]["Image"] = r"C:\Users\Public\s4_viewer.exe"
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "step   1  FAIL" in out
