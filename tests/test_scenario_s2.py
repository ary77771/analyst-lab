"""Scenarios S2/S2J (regular check-ins) against both checkers: a hand-made run that matches the
answer sheet, and broken variants that must FAIL (one check-in missing, rhythm off, a check-in
by another program, keep-alive hiding connections, a run with jitter checked as plain S2)."""

import json
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
from test_check_graph_scenario import pool_file  # noqa: E402  (layer 2 needs a pool of normal rates)

CHECKIN = r"D:\s2\s2_checkin.exe"
BASE = datetime(2026, 10, 19, 12, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def ev(rid, eid, sec, **data):
    t = BASE + timedelta(seconds=sec)
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal",
            "data": {"UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], **data}}


def conn(rid, sec, guid="{C}", image=CHECKIN, port=18765):
    return ev(rid, 3, sec, Image=image, ProcessGuid=guid, Protocol="tcp", Initiated="true", SourceIp="10.0.2.15",
              SourcePort=50000 + rid, DestinationIp="10.0.2.2", DestinationPort=port)


def run_of(gaps):
    """A run: start, check-ins at the given gaps (first at 1 s), end."""
    rows = [ev(100, 1, 0.5, Image=CHECKIN, ProcessGuid="{C}", ProcessId=7, ParentProcessGuid="{R}")]
    t = 1.0
    for i, g in enumerate([0] + list(gaps)):
        t += g
        rows.append(conn(101 + i, t))
    rows.append(ev(200, 5, t + 1, Image=CHECKIN, ProcessGuid="{C}"))
    return rows, t + 2


def write(tmp_path, rows, scenario, end):
    for label, data in (("vm", rows), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": scenario, "exit_code": 0,
                                                    "time": iso(0), "start": iso(0), "end": iso(end),
                                                    "server": "http://10.0.2.2:18765"}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-19.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")


def both(tmp_path, capsys, rows, end, scenario="s2"):
    write(tmp_path, rows, scenario.upper(), end)
    a = check_scenario.main([scenario, "--recordings", str(tmp_path)])
    pool_file(tmp_path)
    b = check_graph_scenario.main([scenario, "--recordings", str(tmp_path)])
    return a, b, capsys.readouterr().out


def test_true_s2_story_passes_both_checks(tmp_path, capsys):
    rows, end = run_of([30.2, 29.8, 30.4, 29.9, 30.1, 30.0, 30.3, 29.7, 30.0])
    a, b, out = both(tmp_path, capsys, rows, end)
    assert (a, b) == (0, 0), out
    assert "(10 matching, exactly 10 expected; gaps 29.7-30.4 s" in out
    assert "checkin connected to the test server 10 times  (10 edge(s)" in out


def test_one_checkin_missing_fails(tmp_path, capsys):
    rows, end = run_of([30] * 8)                     # 9 check-ins
    a, b, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and b == 1 and "(9 matching, exactly 10 expected" in out


def test_rhythm_off_fails(tmp_path, capsys):
    rows, end = run_of([30, 30, 30, 45, 30, 30, 30, 30, 30])
    a, _, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and "step   2  FAIL" in out and "gaps 30.0-45.0 s" in out


def test_checkin_by_another_program_does_not_count(tmp_path, capsys):
    rows, end = run_of([30] * 8)                     # 9 by s2_checkin ...
    rows.insert(-1, conn(150, end - 5, guid="{X}", image=r"C:\Windows\System32\curl.exe"))   # ... + 1 by curl
    a, b, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and b == 1 and "(9 matching, exactly 10 expected" in out


def test_one_long_connection_shows_up_once_and_fails(tmp_path, capsys):
    # keep-alive on would reuse one connection: Sysmon records one event 3, the rhythm is invisible
    rows, end = run_of([])
    a, b, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and b == 1


def test_jitter_variant_accepts_its_wider_spacing_but_s2_does_not(tmp_path, capsys):
    gaps = [21.3, 38.9, 25.0, 41.2, 19.4, 33.3, 30.0, 18.7, 36.6]
    rows, end = run_of(gaps)
    a, b, out = both(tmp_path, capsys, rows, end, scenario="s2j")
    assert (a, b) == (0, 0), out
    rows, end = run_of(gaps)
    for f in ("vm", "vmruns"):
        for p in (tmp_path / f).iterdir():
            p.unlink()
        (tmp_path / f).rmdir()
    a, _, out = both(tmp_path, capsys, rows, end, scenario="s2")
    assert a == 1 and "allowed 27-33 s" in out


def test_gap_too_short_fails(tmp_path, capsys):
    rows, end = run_of([30, 30, 30, 20, 30, 30, 30, 30, 30])
    a, _, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and "gaps 20.0-30.0 s" in out


def test_plain_rhythm_fails_the_jitter_variant(tmp_path, capsys):
    # review 2026-10-19: without a spread rule a run that lost its jitter would still pass S2J
    rows, end = run_of([30.1, 29.9, 30.2, 30.0, 29.8, 30.1, 30.0, 29.9, 30.2])
    a, _, out = both(tmp_path, capsys, rows, end, scenario="s2j")
    assert a == 1 and "spread 0.4 s, at least 10 s required" in out


def test_spacing_rule_without_a_count_is_an_answer_sheet_error(tmp_path, capsys, monkeypatch):
    sheet = tmp_path / "proj" / "scenarios" / "s9"
    sheet.mkdir(parents=True)
    sheet.joinpath("ground_truth.yaml").write_text(
        "scenario: S9\ntitle: t\nprograms: {checkin: s2_checkin.exe}\n"
        "steps:\n  - {id: 1, what: x, evidence: {sysmon_event: 3, Image_endswith: s2_checkin.exe,"
        " interval_seconds: {min: 1, max: 2}}}\n", encoding="utf-8")
    monkeypatch.setattr(check_scenario, "PROJECT_ROOT", str(tmp_path / "proj"))
    rows, end = run_of([])
    write(tmp_path, rows, "S9", end)
    assert check_scenario.main(["s9", "--recordings", str(tmp_path)]) == 1
    assert "interval/spread rules need count >= 2" in capsys.readouterr().out
