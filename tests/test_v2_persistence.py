"""Version 2 package C: registry autostart (Sysmon config v0.3, event 13) through the graph and the
checkers, on a hand-made S6 run that follows scenarios/s6/ground_truth.yaml: the graph's two new
facts (set_autostart, will_start), their independent re-check (tools/check_graph.py), the
scenario, graph and detection checkers end to end, and broken variants that must FAIL."""

import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta

import pytest

from engine import graph as G_
from engine.store import EventStore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_alerts  # noqa: E402
import check_graph  # noqa: E402
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
from test_check_graph_scenario import TEST_HUBS, pool_file  # noqa: E402

PERSIST = r"D:\s6\s6_persist.exe"
COPY = r"C:\AnalystLab\scenarios\s6\s6_startup.exe"
STARTUP = r"C:\Users\lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\analystlab_s6.cmd"
RUN_VALUE = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\AnalystLab S6"
H, HC = "CD" * 32, "EF" * 32
BASE = datetime(2026, 11, 7, 18, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def ev(rid, eid, sec, **data):
    t = BASE + timedelta(seconds=sec)
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal",
            "data": {"UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], **data}}


def file_hash(seq, sec, made, sha=None, status="ok"):
    return {"host": "VM", "label": "vm", "session": "s", "source": "agent", "seq": seq, "type": "FILE_HASH",
            "time": iso(sec), "origin": "normal",
            "data": {"TargetFilename": made["data"]["TargetFilename"], "ProcessGuid": made["data"]["ProcessGuid"],
                     "hash_status": status, "sha256": sha, "size": 10 if sha else None, "final_path": None,
                     "ref_record_id": made["record_id"], "ref_time": made["time"]}}


def s6_run(details=None, value=RUN_VALUE):
    p = dict(Image=PERSIST, ProcessGuid="{S}")
    folder = ev(202, 11, 2, TargetFilename=r"C:\AnalystLab\scenarios\s6", **p)
    copy = ev(203, 11, 3, TargetFilename=COPY, **p)
    script = ev(205, 11, 6, TargetFilename=STARTUP, **p)
    return [
        ev(201, 1, 1, ProcessId=20, ParentProcessGuid="{R}", Hashes="SHA256=22", **p),
        folder, file_hash(1, 2.5, folder, status="directory"),
        copy, file_hash(2, 4, copy, sha=H),
        ev(204, 13, 5, EventType="SetValue", TargetObject=value,
           Details=details if details is not None else f'"{COPY}" -startup', **p),
        script, file_hash(3, 7, script, sha=HC),
        ev(206, 5, 9, **p),
    ]


def graph_of(tmp_path, records):
    path = str(tmp_path / "g.db")
    st = EventStore(path)
    st.insert(records)
    st.close()
    return path, G_.build_graph(path)


def edges(G, kind):
    return [(u, v, d) for u, v, d in G.edges(data=True) if d.get("kind") == kind]


@pytest.mark.parametrize("details, target", [
    (r'"C:\x\a.exe" -startup', r"C:\x\a.exe"),
    (r"C:\x\a.exe -startup", r"C:\x\a.exe"),
    (r"C:\Program Files\x\a.exe", r"C:\Program Files\x\a.exe"),
    (r'"C:\x y\run.cmd"', r"C:\x y\run.cmd"),
    ("ctfmon.exe /n", None),                       # a bare name: which file is unknown
    ("DWORD (0x00000002)", None),                  # a service's start mode
    ("(Empty)", None), (None, None), ("", None),
])
def test_autostart_target(details, target):
    assert G_.autostart_target(details) == target


def test_graph_draws_set_autostart_and_will_start_to_the_fingerprinted_copy(tmp_path):
    path, G = graph_of(tmp_path, s6_run())
    (u, a, d), = edges(G, "set_autostart")
    assert G.nodes[u]["label"] == "s6_persist.exe" and G.nodes[a]["kind"] == "autostart"
    assert G.nodes[a]["label"] == "AnalystLab S6" and d["grade"] == "fact" and d["layer"] == 0
    (a2, f, _), = edges(G, "will_start")
    assert a2 == a and G.nodes[f]["sha256"] == H and G.nodes[f]["path"] == COPY   # the copy as written
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    row = lambda key: (lambda r: dict(r) if r else None)(con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone())
    assert check_graph.trace_all(row, G) == {}                    # the independent re-check agrees
    done = check_graph.completeness(con, G, include_project=True)
    assert done["event 13 -> set_autostart (+ no-actor gaps, no value named)"] == (1, 1)
    con.close()


def test_a_value_naming_no_full_path_gives_no_will_start(tmp_path):
    _, G = graph_of(tmp_path, s6_run(details="s6_persist.exe -startup"))
    assert len(edges(G, "set_autostart")) == 1 and edges(G, "will_start") == []


def test_the_recheck_catches_a_will_start_to_the_wrong_file(tmp_path):
    path, G = graph_of(tmp_path, s6_run())
    (a, f, d), = edges(G, "will_start")
    other = next(n for n, x in G.nodes(data=True) if x.get("kind") == "file" and x["path"] == STARTUP)
    G.remove_edge(a, f)
    G.add_edge(a, other, **d)                                      # same evidence, wrong file
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    row = lambda key: (lambda r: dict(r) if r else None)(con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone())
    assert check_graph.trace_all(row, G) == {"will_start: cited event does not say this": 1}
    con.close()


def write_run(tmp_path, records):
    for label, rows in (("vm", records), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S6", "exit_code": 0,
                                                      "time": iso(0), "start": iso(0), "end": iso(12)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-11-07.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def graph_check(tmp_path, records):
    write_run(tmp_path, records)
    pool_file(tmp_path)
    real = check_graph_scenario.load_hubs
    check_graph_scenario.load_hubs = lambda: TEST_HUBS
    try:
        return check_graph_scenario.main(["s6", "--recordings", str(tmp_path)])
    finally:
        check_graph_scenario.load_hubs = real


def test_s6_story_passes_the_scenario_and_graph_checkers(tmp_path, capsys):
    assert graph_check(tmp_path, s6_run()) == 0, capsys.readouterr().out
    out = capsys.readouterr().out
    assert out.count("fact  PASS") == 4 and "persist_autostart" in out
    assert check_scenario.main(["s6", "--recordings", str(tmp_path)]) == 0, capsys.readouterr().out


def test_s6_without_the_run_value_fails_both(tmp_path, capsys):
    recs = [r for r in s6_run() if r.get("event_id") != 13]
    assert graph_check(tmp_path, recs) != 0
    assert check_scenario.main(["s6", "--recordings", str(tmp_path)]) != 0
    capsys.readouterr()


def test_s6_value_in_another_key_fails_the_scenario_check(tmp_path, capsys):
    recs = s6_run(value=RUN_VALUE.replace(r"\Run\\", r"\RunOnce\\").replace(r"\Run\A", r"\RunOnce\A"))
    write_run(tmp_path, recs)
    assert check_scenario.main(["s6", "--recordings", str(tmp_path)]) != 0
    capsys.readouterr()


def test_s6_is_detected_by_the_community_rules(tmp_path, capsys, monkeypatch):
    """End to end with the real pinned SigmaHQ rules: both expected alerts (Run key, Startup folder)."""
    from engine import detect, score
    if not os.path.isdir(detect.COMMUNITY_RULES):
        pytest.skip("SigmaHQ rules not fetched (tools/fetch_sigma_rules.ps1)")
    write_run(tmp_path, s6_run())
    monkeypatch.setattr(score, "load_baseline", lambda *a, **k: None)   # the real baselines are private
    code = check_alerts.main(["s6", "--recordings", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0 and out.count("alert  PASS") == 2, out


def test_a_will_start_the_raw_event_does_not_support_fails_the_trace(tmp_path, capsys, monkeypatch):
    """The value names another program; a (broken) graph still links the entry to the copy."""
    recs = s6_run(details=r'"C:\AnalystLab\other\elsewhere.exe" -startup')
    real = check_graph_scenario.build_graph

    def forged(db, **kw):
        G = real(db, **kw)
        (a, d), = [(v, x) for _, v, x in G.edges(data=True) if x.get("kind") == "set_autostart"]
        honest = [f for _, f, x in G.out_edges(a, data=True) if x.get("kind") == "will_start"]
        assert [G.nodes[f]["label"] for f in honest] == ["elsewhere.exe"]        # what the value really names
        G.remove_edge(a, honest[0])
        copy = next(n for n, x in G.nodes(data=True) if x.get("kind") == "file" and x["path"] == COPY)
        G.add_edge(a, copy, **{**d, "kind": "will_start"})
        return G
    monkeypatch.setattr(check_graph_scenario, "build_graph", forged)
    assert graph_check(tmp_path, recs) != 0
    assert "names the copy (one event's data says so; it never ran here)': the cited raw events" in capsys.readouterr().out

# --- review 2026-11-07 ---

@pytest.mark.parametrize("details, named", [
    (r'"C:\x\a.exe" -startup', r"C:\x\a.exe"), (r"C:\x\a.exe -startup", r"C:\x\a.exe"),
    (r"C:\x\a.exe", r"C:\x\a.exe"), (r"C:\x\run.cmd,1", r"C:\x\run.cmd"),
    ("DWORD (0x00000002)", None), (None, None),
])
def test_the_rechecks_own_parser(details, named):
    assert check_graph.named_program(details) == named


def test_the_recheck_refuses_a_will_start_to_a_prefix_of_the_named_path(tmp_path):
    path, G = graph_of(tmp_path, s6_run())
    (a, f, d), = edges(G, "will_start")
    folder = next(n for n, x in G.nodes(data=True) if x.get("kind") == "file" and x["path"] == r"C:\AnalystLab\scenarios\s6")
    G.remove_edge(a, f)
    G.add_edge(a, folder, **d)                                   # the folder's path is part of the value's text
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    row = lambda key: (lambda r: dict(r) if r else None)(con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone())
    assert check_graph.trace_all(row, G) == {"will_start: cited event does not say this": 1}
    con.close()


def test_check_graph_reads_a_store_made_before_the_registry_fields(tmp_path):
    path, _ = graph_of(tmp_path, [r for r in s6_run() if r.get("event_id") != 13])
    con = sqlite3.connect(path)
    for col in ("EventType", "TargetObject", "Details", "NewName"):
        con.execute(f'ALTER TABLE events DROP COLUMN "{col}"')
    con.commit()
    G = G_.build_graph(path)
    row = check_graph.db_lookup(con)
    assert check_graph.trace_all(row, G) == {}
    assert check_graph.completeness(con, G, include_project=True)["event 13 -> set_autostart (+ no-actor gaps, no value named)"] == (0, 0)
    con.close()


def test_a_value_set_after_the_file_was_deleted_names_no_old_content(tmp_path):
    recs = s6_run()
    value = next(r for r in recs if r.get("event_id") == 13)
    recs.remove(value)
    gone = ev(207, 26, 4.5, Image=PERSIST, ProcessGuid="{S}", TargetFilename=COPY, Hashes=f"SHA256={H}")
    value["time"], value["data"]["UtcTime"] = iso(8), (BASE + timedelta(seconds=8)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    _, G = graph_of(tmp_path, recs + [gone, value])
    (_, f, _), = edges(G, "will_start")
    assert G.nodes[f]["sha256"] is None and G.nodes[f]["path"] == COPY   # the path, not the deleted content