"""v4 F3: analystlab.create_send_wipe (engine/own_rules.py): a process creates files, connects out,
and the same files are deleted again by it or a program it started directly."""
import sqlite3

import pytest

from engine import own_rules
from engine.store import EventStore
from tests.test_detect import ev, store

P, CHILD, OTHER, GRAND = "{PPPP}", "{CCCC}", "{OOOO}", "{GGGG}"
ZERO = "{00000000-0000-0000-0000-000000000000}"


def story(n=4, conn_at=10.0, ip="10.0.2.2", deleter=P, conn_by=P, del_at=20.0, gap=1.0, origin="normal",
          creator=P, del_host="h1"):
    """P starts (and starts CHILD, which starts GRAND), `creator` creates n files 1 s apart, connects
    out at conn_at, then the files are deleted from del_at on, `gap` s apart."""
    recs = [ev(1, 0.0, ProcessGuid=P, ParentProcessGuid="{XXXX}", Image=r"C:\x\tool.exe", origin=origin),
            ev(1, 0.5, ProcessGuid=CHILD, ParentProcessGuid=P, Image=r"C:\Windows\System32\cmd.exe"),
            ev(1, 0.6, ProcessGuid=OTHER, ParentProcessGuid="{XXXX}", Image=r"C:\x\cleaner.exe"),
            ev(1, 0.7, ProcessGuid=GRAND, ParentProcessGuid=CHILD, Image=r"C:\Windows\System32\cmd.exe")]
    files = [rf"C:\AnalystLab\w\f{i}.docx" for i in range(n)]
    recs += [ev(11, 1.0 + i, ProcessGuid=creator, Image=r"C:\x\tool.exe", TargetFilename=f, origin=origin)
             for i, f in enumerate(files)]
    if conn_at is not None:
        recs.append(ev(3, conn_at, ProcessGuid=conn_by, Initiated="true", DestinationIp=ip, DestinationPort=80))
    recs += [ev(26, del_at + gap * i, host=del_host, ProcessGuid=deleter, TargetFilename=f.upper() if i == 0 else f)
             for i, f in enumerate(files)]                       # Windows paths ignore case
    return recs


def alerts(tmp_path, records, **kw):
    con = sqlite3.connect(store(tmp_path, records))
    try:
        return own_rules.wipe_episodes(con, **kw)
    finally:
        con.close()


def keys(recs, eid):
    return {EventStore.dedup_key(r) for r in recs if r["event_id"] == eid}


def test_stage_send_wipe_is_medium_with_every_piece_as_evidence(tmp_path):
    recs = story()
    out = alerts(tmp_path, recs)
    assert len(out) == 1
    a = out[0]
    assert a.rule_id == "analystlab.create_send_wipe" and a.level == "medium"
    assert set(a.evidence) == keys(recs, 11) | keys(recs, 26) | keys(recs, 3)
    assert a.details == {"files": 4, "connections": 1, "destinations": ["10.0.2.2:80"], "program": "tool.exe"}
    assert a.time == "2026-10-22T10:00:22.000Z"                 # the 3rd deletion completes the set


@pytest.mark.parametrize("case", [
    dict(conn_at=None),              # never connected out
    dict(ip="127.0.0.1"),            # talked to itself
    dict(conn_at=0.8),               # connected before the first file existed
    dict(conn_at=40.0),              # only after the last deletion
])
def test_without_a_connection_in_between_it_is_low(tmp_path, case):
    out = alerts(tmp_path, story(**case))
    assert [a.level for a in out] == ["low"]
    assert keys(story(**case), 3).isdisjoint(out[0].evidence) and out[0].details["connections"] == 0


@pytest.mark.parametrize("case", [
    dict(n=2),                       # fewer than 3 files
    dict(deleter=OTHER),             # deleted by an unrelated program
    dict(del_at=1000.0),             # deleted long after (beyond 900 s)
    dict(origin="project"),          # our own tools
    dict(creator=CHILD, deleter=P),  # a parent deleting its child's files
    dict(deleter=GRAND),             # a grandchild deleting
    dict(del_host="h2"),             # same GUID, deletions on another computer
    dict(creator=ZERO, deleter=ZERO),  # zero GUID = parent unknown, never a real process
])
def test_near_misses_do_not_fire(tmp_path, case):
    assert alerts(tmp_path, story(**case)) == []


@pytest.mark.parametrize("deleter,conn_by", [(CHILD, CHILD), (CHILD, P), (P, CHILD)])
def test_a_child_that_deletes_or_connects_counts(tmp_path, deleter, conn_by):
    out = alerts(tmp_path, story(deleter=deleter, conn_by=conn_by))   # `cmd /c del`, an upload by a child
    assert [a.level for a in out] == ["medium"]


def test_files_spread_over_days_are_not_one_episode(tmp_path):
    day = 86400.0
    recs = [ev(1, 0.0, ProcessGuid=P, ParentProcessGuid="{XXXX}", Image=r"C:\x\browser.exe")]
    for i, t in enumerate([0.0, 10.0, 6 * day]):                  # two wiped on day 0, one on day 6
        f = rf"C:\Users\u\Downloads\part{i}.tmp.exe"
        recs += [ev(11, t + 1, ProcessGuid=P, TargetFilename=f), ev(26, t + 5, ProcessGuid=P, TargetFilename=f)]
    recs.append(ev(3, 3 * day, ProcessGuid=P, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=443))
    assert alerts(tmp_path, recs) == []


def repeated(conn_at=None):
    """a, b, c made at 1-3 s and wiped at 5-7 s; a made again at 50 s and wiped at 60 s."""
    recs = [ev(1, 0.0, ProcessGuid=P, ParentProcessGuid="{XXXX}", Image=r"C:\x\tool.exe")]
    for i, n in enumerate("abc"):
        recs += [ev(11, 1.0 + i, ProcessGuid=P, TargetFilename=rf"C:\AnalystLab\{n}.exe"),
                 ev(26, 5.0 + i, ProcessGuid=P, TargetFilename=rf"C:\AnalystLab\{n}.exe")]
    recs += [ev(11, 50.0, ProcessGuid=P, TargetFilename=r"C:\AnalystLab\a.exe"),
             ev(26, 60.0, ProcessGuid=P, TargetFilename=r"C:\AnalystLab\a.exe")]
    if conn_at is not None:
        recs.append(ev(3, conn_at, ProcessGuid=P, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80))
    return recs


def test_a_reused_file_name_does_not_delay_or_hide_anything(tmp_path):
    out = alerts(tmp_path, repeated())
    assert out[0].level == "low" and out[0].time == "2026-10-22T10:00:07.000Z" and out[0].details["files"] == 3
    recs = repeated(conn_at=55.0)                                 # the connection comes with the second round
    out = alerts(tmp_path, recs)
    assert out[0].level == "medium" and out[0].time == "2026-10-22T10:01:00.000Z" and out[0].details["files"] == 3
    assert set(out[0].evidence) == keys(recs, 11) | keys(recs, 26) | keys(recs, 3)   # both rounds of a.exe


def test_evidence_stops_at_the_alert_time(tmp_path):
    recs = story(conn_at=10.0) + [ev(3, 30.0, ProcessGuid=P, Initiated="true", DestinationIp="10.0.2.3",
                                     DestinationPort=80)]       # after the last deletion
    a = alerts(tmp_path, recs)[0]
    assert a.details["connections"] == 1 and a.details["destinations"] == ["10.0.2.2:80"]


def test_a_large_family_is_queried_in_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(own_rules, "_CHUNK", 2)
    kids = [ev(1, 0.8, ProcessGuid=f"{{K{i}}}", ParentProcessGuid=P, Image=r"C:\x\k.exe") for i in range(5)]
    recs = story(conn_at=None) + kids + [ev(3, 10.0, ProcessGuid="{K4}", Initiated="true",
                                            DestinationIp="10.0.2.2", DestinationPort=80)]
    assert [a.level for a in alerts(tmp_path, recs)] == ["medium"]


def test_time_is_when_set_and_connection_are_both_there(tmp_path):
    # connection after the 3rd deletion, before the 4th: complete at the 4th
    out = alerts(tmp_path, story(conn_at=22.5, del_at=20.0))
    assert out[0].level == "medium" and out[0].time == "2026-10-22T10:00:23.000Z"


def test_settings_and_run_all(tmp_path):
    assert alerts(tmp_path, story(n=3), min_files=4) == []
    assert alerts(tmp_path, story(del_at=100.0), window=60.0) == []
    assert alerts(tmp_path, story())[0].details["program"] == "tool.exe"


def learned(tmp_path, recs, baseline):
    con = sqlite3.connect(store(tmp_path, recs))
    try:
        return [a for a in own_rules.run_all(con, baseline=baseline) if a.rule_id == "analystlab.create_send_wipe"]
    finally:
        con.close()


def creates_with_image(recs, image=r"C:\x\tool.exe"):
    return [dict(r, data=dict(r["data"], Image=image)) if r["event_id"] == 11 else r for r in recs]


def test_learned_normal_only_unknown_programs_alert(tmp_path):
    recs = creates_with_image(story())
    empty = {"h1": {"shell_pairs": set(), "listeners": set(), "wipers": set()}}
    assert [a.level for a in learned(tmp_path, recs, empty)] == ["medium"]           # never seen: alert
    known = {"h1": {"shell_pairs": set(), "listeners": set(), "wipers": {"tool.exe"}}}
    assert learned(tmp_path, recs, known) == []                                     # does this normally
    other = {"h2": {"shell_pairs": set(), "listeners": set(), "wipers": set()}}
    assert learned(tmp_path, recs, other) == []                                     # no baseline for h1
    con = sqlite3.connect(store(tmp_path, recs))
    try:
        assert [a for a in own_rules.run_all(con) if a.rule_id == "analystlab.create_send_wipe"] == []  # no baseline
    finally:
        con.close()


@pytest.mark.parametrize("image,name", [(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe", "powershell.exe"),
                                        (r"C:\Windows\System32\cmd.exe", "cmd.exe"), ("<unknown process>", "<unknown process>")])
def test_shells_and_unknown_programs_are_never_silenced(tmp_path, image, name):
    recs = creates_with_image(story(), image)
    known = {"h1": {"shell_pairs": set(), "listeners": set(), "wipers": {name, "?"}}}
    assert [a.level for a in learned(tmp_path, recs, known)] == ["medium"]


def test_an_upper_case_host_finds_its_baseline(tmp_path):
    recs = [dict(r, host="LAPTOP-X") for r in creates_with_image(story())]
    assert [a.level for a in learned(tmp_path, recs, {"laptop-x": {"shell_pairs": set(), "listeners": set(),
                                                                    "wipers": set()}})] == ["medium"]
    assert learned(tmp_path, recs, {"laptop-x": {"shell_pairs": set(), "listeners": set(), "wipers": {"tool.exe"}}}) == []


def test_program_comes_from_the_create_event(tmp_path):
    recs = [r for r in creates_with_image(story(), r"C:\Apps\UPDATER.EXE") if not (r["event_id"] == 1 and r["data"]["ProcessGuid"] == P)]
    a = alerts(tmp_path, recs)[0]                  # its start was not recorded: the file events still name it
    assert a.details["program"] == "updater.exe"
    known = {"h1": {"shell_pairs": set(), "listeners": set(), "wipers": {"updater.exe"}}}
    assert learned(tmp_path, recs, known) == []
