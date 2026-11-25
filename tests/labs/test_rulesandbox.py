"""Lab: Rule sandbox (engine/labs/rulesandbox.py): a known rule on a fixture store, through the real detectors'
path; plain errors for a malformed rule, an unknown field and a regular expression; the test machine only."""

import os

import pytest

from engine.labs import rulesandbox as R
from nighttools_fixtures import configure, store_with

RULE = """
title: Test downloader started with a server switch
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\\\\s1_fetch.exe'
    CommandLine|contains: '-server'
  condition: sel
level: high
"""


def _store(tmp_path):
    def start(guid, image, cmd, host="analystlab-vm", t="2026-11-01T10:00:05.000Z"):
        return {"host": host, "event_id": 1, "time": t,
                "data": {"ProcessGuid": guid, "Image": image, "CommandLine": cmd, "UtcTime": t[:-1]}}
    return store_with(str(tmp_path / "events.db"), [
        start("{a-1}", "D:\\s1\\s1_fetch.exe", "s1_fetch.exe -server http://10.0.2.2:18765"),
        start("{a-2}", "D:\\S1\\S1_FETCH.EXE", "S1_FETCH.EXE -SERVER http://10.0.2.2:18765", t="2026-11-01T11:00:05.000Z"),
        start("{a-3}", "C:\\Windows\\notepad.exe", "notepad.exe"),
        start("{l-1}", "C:\\x\\s1_fetch.exe", "s1_fetch.exe -server laptop", host="laptop"),   # never shown
    ])


RUNS = [{"run_id": "r1", "scenario": "S1", "host": "analystlab-vm", "start": "2026-11-01T09:59:00Z", "end": "2026-11-01T10:10:00Z"},
        {"run_id": "r2", "scenario": "B19", "host": "analystlab-vm", "start": "2026-11-01T10:59:00Z", "end": "2026-11-01T11:10:00Z"}]


def test_a_known_rule_matches_through_the_real_detectors_on_the_test_machine_only(tmp_path):
    ctx = configure(tmp_path, _store(tmp_path))
    with ctx.reading() as con:
        cols = [c[1] for c in con.execute("PRAGMA table_info(events)")]
    rules, fields = R.load(RULE, cols)
    assert fields == {"Image", "CommandLine"}
    out = R.run(ctx, rules, fields, runs=RUNS, kinds={"S1": "planted", "B19": "innocent"}, names={"s1": "Download and run"})
    r = out["rules"][0]
    assert r["records"] == 2                                   # both cases (Sigma is case-insensitive); not the laptop's
    assert {(e["run_id"], e["records"]) for e in r["runs"]} == {("r1", 1), ("r2", 1)} and r["outside"] == 0
    assert any("innocent test: B19" in w for w in r["warnings"]) and not any("S1" in w for w in r["warnings"])
    assert r["raised"] is True and r["sample"][0]["fields"][0]["read"] is True


@pytest.mark.parametrize("text, words", [
    ("title: x\ndetection: [unclosed", "not valid YAML"),
    ("title: x\nlogsource: {product: windows, category: process_creation}\ndetection:\n  sel: {Image: a}\n", "pySigma could not read"),
    (RULE.replace("CommandLine|contains", "NoSuchField|contains"), "does not have: NoSuchField"),
    (RULE.replace("CommandLine|contains", "CommandLine|re"), "Regular expressions"),
    (RULE.replace("process_creation", "webserver"), "does not record this rule's log source"),
    ("", "Paste a Sigma rule"),
])
def test_a_bad_rule_gives_a_plain_error(tmp_path, text, words):
    with pytest.raises(R.TryError) as e:
        R.load(text, ["Image", "CommandLine"])
    assert words in str(e.value)


def test_a_try_past_its_time_is_stopped_never_half_counted(tmp_path):
    ctx = configure(tmp_path, _store(tmp_path))
    rules, fields = R.load(RULE, ["Image", "CommandLine"])
    with pytest.raises(R.TryError) as e:
        R.run(ctx, rules, fields, time_limit=0, runs=RUNS, kinds={}, names={})
    assert "stopped" in str(e.value)


def test_runs_are_found_by_time_and_host():
    idx = R.RunIndex(RUNS + [{"run_id": "r3", "scenario": "S2", "host": "other-vm", "start": "2026-11-01T10:00:00Z", "end": "2026-11-01T10:20:00Z"}])
    assert idx.find("analystlab-vm", "2026-11-01T10:05:00Z")["run_id"] == "r1"
    assert idx.find("other-vm", "2026-11-01T10:05:00Z")["run_id"] == "r3"
    assert idx.find("analystlab-vm", "2026-11-01T10:30:00Z") is None


def test_kinds_come_from_the_projects_own_files():
    k = R.scenario_kinds()
    assert k.get("B19") == "innocent" and k.get("B18") == "planted" and k.get("C1") == "control" and k.get("S0") == "baseline"
