"""engine/labs/_shared_defs.py: one clock, one harness test, one counting vocabulary (night 2)."""

import os
import sqlite3

import pytest

from engine.labs import _shared_defs as sd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.parametrize("marker,path", sd.SOURCES)
def test_every_harness_marker_is_still_in_its_source_file(marker, path):
    with open(os.path.join(ROOT, path), encoding="utf-8-sig", errors="replace") as f:
        assert marker in f.read(), f"{marker!r} is no longer in {path}: update _shared_defs"


def test_when_prefers_sysmons_own_time_and_spells_it_like_the_store():
    assert sd.when({"UtcTime": "2026-10-31 17:47:33.415", "time": "2026-10-31T17:47:34.6270622Z"}) == "2026-10-31T17:47:33.4150000Z"
    assert sd.when({"time": "2026-10-31T17:47:34.6270622Z"}) == "2026-10-31T17:47:34.6270622Z"
    assert sd.when({"UtcTime": None, "time": None}) is None
    assert sd.when_seconds({"UtcTime": "2026-10-31 17:47:33.5"}) - sd.when_seconds({"UtcTime": "2026-10-31 17:47:33.0"}) == pytest.approx(0.5)


HARNESS = [
    {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "CommandLine": "powershell.exe -NoProfile -File C:\\LabRunner\\start_run_cd.ps1"},
    {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "CommandLine": "powershell.exe -NoProfile -File D:\\run_scenario.ps1 -Scenario s1 -RunId 20261030-195534-dac0"},
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c D:\\RUN_S1.cmd"},
    {"Image": "C:\\Windows\\System32\\VBoxService.exe"},
    {"Image": "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxControl.exe", "CommandLine": "VBoxControl.exe guestproperty get x"},
    {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "DestinationIp": "10.0.2.2", "DestinationPort": 8770},
    {"Image": "C:\\LabTools\\python\\python.exe", "origin": "project"},
]
NOT_HARNESS = [
    {"Image": "D:\\s1\\s1_payload.exe", "CommandLine": "D:\\s1\\s1_payload.exe -server http://10.0.2.2:18765"},   # the test itself
    {"Image": "D:\\s1\\s1_fetch.exe", "DestinationIp": "10.0.2.2", "DestinationPort": 18765},                    # the test server
    {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -enc AAAA"},
    {"Image": "C:\\Windows\\System32\\svchost.exe", "DestinationIp": "10.0.2.3", "DestinationPort": 53},
    {"Image": "C:\\x\\a.exe", "CommandLine": "a.exe --mode run"},
]


def test_when_sql_orders_mixed_spellings_by_time_and_equals_when():
    """night-pivot's bug: Sysmon spells '2026-10-31 17:47:35' (space), the recorder '2026-10-31T17:47:34Z' (T);
    the bare COALESCE sorted the LATER Sysmon row first. The SQL clock must order by time and spell exactly like when()."""
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, UtcTime TEXT, time TEXT)")
    rows = [(1, "2026-10-31 17:47:35.100", "2026-10-31T17:47:36.0000000Z"),   # Sysmon row: happened 17:47:35.1
            (2, None, "2026-10-31T17:47:34.5000000Z"),                        # recorder row: 17:47:34.5 (earlier)
            (3, "2026-10-31 17:47:35.05", None),                              # Sysmon, 2 fraction digits: 17:47:35.05
            (4, None, "2026-10-31T17:47:40Z")]                                # recorder, no fraction: 17:47:40
    con.executemany("INSERT INTO events VALUES (?, ?, ?)", rows)
    expr = sd.when_sql({"utctime", "time"})
    order = [i for (i,) in con.execute(f"SELECT id FROM events ORDER BY {expr}")]
    assert order == [2, 3, 1, 4]
    old = [i for (i,) in con.execute("SELECT id FROM events ORDER BY COALESCE(UtcTime, time)")]
    assert old != order                                              # the old form really mis-sorts these
    for i, utc, t in rows:
        got = con.execute(f"SELECT {expr} FROM events WHERE id = ?", (i,)).fetchone()[0]
        assert got == sd.when({"UtcTime": utc, "time": t}), i
    assert con.execute(f"SELECT MIN({expr}), MAX({expr}) FROM events").fetchone() == (
        "2026-10-31T17:47:34.5000000Z", "2026-10-31T17:47:40.0000000Z")
    assert "COALESCE" not in sd.when_sql({"time"})                    # a store without UtcTime: the record time


def test_harness_rows_and_what_is_not_harness():
    assert all(sd.is_harness(r) for r in HARNESS), [r for r in HARNESS if not sd.is_harness(r)]
    assert not any(sd.is_harness(r) for r in NOT_HARNESS), [r for r in NOT_HARNESS if sd.is_harness(r)]
    assert sd.harness_reason(HARNESS[5]) == "the test machine reporting back to the laptop"


def test_the_sql_filter_agrees_with_the_python_test():
    con = sqlite3.connect(":memory:")
    cols = ["origin", "Image", "CommandLine", "DestinationIp", "DestinationPort"]
    con.execute(f"CREATE TABLE events (id INTEGER PRIMARY KEY, {', '.join(cols)})")
    rows = HARNESS + NOT_HARNESS
    for r in rows:
        con.execute(f"INSERT INTO events ({', '.join(cols)}) VALUES (?, ?, ?, ?, ?)", [r.get(c) for c in cols])
    where, params = sd.harness_sql({c.lower() for c in cols})
    kept = [i for (i,) in con.execute(f"SELECT id FROM events WHERE 1=1{where} ORDER BY id", params)]
    assert kept == list(range(len(HARNESS) + 1, len(rows) + 1))          # exactly the NOT_HARNESS rows survive


def test_the_sql_filter_uses_only_columns_the_store_has():
    where, params = sd.harness_sql({"image"})
    assert "CommandLine" not in where and "DestinationIp" not in where and params
    assert sd.harness_sql(set()) == ("", [])


def test_one_counting_vocabulary():
    assert sd.WORDS["programs"] == "programs" and sd.WORDS["program_starts"] == "program starts" and sd.WORDS["records"] == "records"
