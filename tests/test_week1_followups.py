"""The three evidence-graph follow-ups Yousif decided on 2026-10-17 (HANDOFF section 6):
port owner start time, Windows' full path in FILE_HASH, and re-tagging laptop records on load."""

import os
import sqlite3
import uuid
from datetime import datetime, timezone

import psutil
import pytest
import win32api

from agent import ports as ports_module
from agent.enrich import hash_when_closed
from agent.main import Agent, parse_args
from engine.load import load_files
from engine.retag import Retagger
from engine.store import EventStore


# -- port owner start time ------------------------------------------------------------------------
def test_process_start_is_sysmon_format_utc_of_the_process():
    text = ports_module.process_start(os.getpid())
    expected = datetime.fromtimestamp(psutil.Process().create_time(), timezone.utc)
    assert len(text) == 23 and text[10] == " "                       # "YYYY-MM-DD HH:MM:SS.fff"
    parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    assert abs((parsed - expected).total_seconds()) < 0.002
    assert ports_module.process_start(None) is None


def test_port_records_carry_the_owner_start_time(tmp_path, monkeypatch):
    snapshots = [{}, {("127.0.0.1", 6100): 4242}]
    monkeypatch.setattr(ports_module, "listening_ports", lambda: snapshots.pop(0))
    monkeypatch.setattr(ports_module, "process_image", lambda pid: r"C:\x\server.exe")
    monkeypatch.setattr(ports_module, "process_start", lambda pid: "2026-10-17 18:00:00.123")
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    a = Agent(parse_args(["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
                          "--label", "test", "--recordings", str(tmp_path), "--run-seconds", "1"]))
    (rec,) = a._port_records()
    assert rec["type"] == "PORT_LISTEN_START" and rec["data"]["ProcessStartUtc"] == "2026-10-17 18:00:00.123"


# -- Windows' full path in FILE_HASH --------------------------------------------------------------
def test_fingerprint_reports_windows_full_path_for_a_short_name(tmp_path):
    long_dir = tmp_path / "a folder with a long name"
    long_dir.mkdir()
    target = long_dir / "program file.exe"
    target.write_bytes(b"x")
    short = win32api.GetShortPathName(str(target))
    if short.lower() == str(target).lower():
        pytest.skip("8.3 short names are disabled on this volume")
    status, sha, size, final = hash_when_closed(short)
    assert status == "ok" and final.lower() == str(target).lower()


# -- re-tagging on load ---------------------------------------------------------------------------
def sysmon(rid, eid, origin, **data):
    return {"host": "PC", "label": "host", "session": "s", "source": "sysmon", "channel": "c",
            "record_id": rid, "event_id": eid, "time": f"2026-10-16T10:00:{rid:02d}.0000000Z",
            "origin": origin, "data": data}


def day1_records():
    """Day-1 style: Claude's child powershell recorded as 'normal' (the rules were fixed later)."""
    created = sysmon(3, 11, "normal", ProcessGuid="{SH}", Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     TargetFilename=r"C:\Users\u\Downloads\x.ps1")
    return [
        sysmon(1, 1, "project", ProcessGuid="{CL}", Image=r"C:\Program Files\Claude\claude.exe"),
        sysmon(2, 1, "normal", ProcessGuid="{SH}", ParentProcessGuid="{CL}", Image=created["data"]["Image"],
               ParentImage=r"C:\Program Files\Claude\claude.exe"),
        created,
        {"host": "PC", "label": "host", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH",
         "time": "2026-10-16T10:00:04.0000000Z", "origin": "normal",
         "data": {"TargetFilename": created["data"]["TargetFilename"], "ProcessGuid": "{SH}", "hash_status": "ok",
                  "sha256": "AA", "ref_record_id": 3, "ref_time": created["time"]}},
        sysmon(5, 1, "normal", ProcessGuid="{BR}", ParentProcessGuid="{CL}", Image=r"C:\Program Files\Browser\browser.exe",
               ParentImage=r"C:\Program Files\Claude\claude.exe"),           # a browser from Claude stays normal
    ]


def test_retagger_applies_todays_rules_and_keeps_the_recorded_tag():
    rt = Retagger()
    out = [rt(r) for r in day1_records()]
    assert [r["origin"] for r in out] == ["project", "project", "project", "project", "normal"]
    assert out[1]["origin_recorded"] == "normal" and out[3]["origin_recorded"] == "normal"   # FILE_HASH follows its event 11
    assert rt.changed == 3


def test_vm_records_are_retagged_strictly():
    """Since 2026-10-23 (security review): in the VM, mentioning C:\\LabTools in a command line no
    longer makes a program "our own tools"; only programs living there (and their children) are."""
    def start(guid, image, cmd, parent="{P}"):
        return {"label": "vm", "host": "vm1", "source": "sysmon", "event_id": 1, "origin": "project",
                "data": {"ProcessGuid": guid, "ParentProcessGuid": parent, "Image": image, "CommandLine": cmd}}
    rt = Retagger()
    hider = rt(start("{A}", r"C:\Users\u\evil.exe", r"evil.exe C:\LabTools"))
    agent = rt(start("{B}", r"C:\LabTools\python\pythonw.exe", r"pythonw.exe -m agent.main"))
    child = rt(start("{C}", r"C:\Windows\System32\cmd.exe", "cmd /c x", parent="{B}"))
    assert (hider["origin"], agent["origin"], child["origin"]) == ("normal", "project", "project")
    planted = rt(start("{D}", r"C:\LabTools\recordings\x.exe", "x.exe"))       # copied into the data folder
    assert planted["origin"] == "normal"
    assert hider["origin_recorded"] == "project"
    other = dict(day1_records()[1], label="vmruns")
    assert Retagger()(other) is other                      # other labels unchanged


def test_loader_stores_both_tags(tmp_path):
    path = tmp_path / "2026-10-16.jsonl"
    import json
    path.write_text("".join(json.dumps(r) + "\n" for r in day1_records()), encoding="utf-8")
    store = EventStore(str(tmp_path / "x.db"))
    totals = load_files(store, [str(path)])
    store.close()
    assert totals["retagged"] == 3
    rows = sqlite3.connect(tmp_path / "x.db").execute(
        "SELECT record_id, origin, origin_recorded FROM events WHERE event_id = 1 ORDER BY record_id").fetchall()
    assert rows == [(1, "project", "project"), (2, "project", "normal"), (5, "normal", "normal")]
