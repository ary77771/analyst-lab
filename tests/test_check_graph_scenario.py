"""tools/check_graph_scenario.py (week-2 checkpoint: S1 replay vs answer sheet) against a hand-made
S1 run, and broken variants that must each FAIL: a fact missing, content not proven, content that
doesn't match, a hypothesis graded as a fact, a fact citing an event that doesn't say it; since
package F also: the expected hypothesis missing, an unlisted hypothesis between scenario nodes, a
wrong N, a hypothesis citing an event that doesn't say it, no pool of normal rates.

The hand-made run starts the payload 13 s after fetch connected (outside the 12 s timing window), so
the only hypothesis the story produces is the one S1's sheet lists (the real S1 also produces
"fetched, then started the payload", which the sheet must list: hypotheses.md Q2)."""

import json
import os
import sys
from datetime import datetime, timedelta

import pytest

from engine import confidence as C

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402

FETCH = r"D:\s1\s1_fetch.exe"
PAYLOAD = r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe"
H = "AB" * 32
BASE = datetime(2026, 10, 17, 18, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"


def pool_file(tmp_path):
    """A small hand-made pool of normal rates where the checker looks for it by default."""
    (tmp_path / "confidence").mkdir(exist_ok=True)
    per_band = {k: {b: (1, 100.0) for b in ("<60", "60-3600", ">=3600")} for k in C.KINDS}
    C.Pool({k: {} for k in C.KINDS}, per_band, C.pool_settings(C.load_config())).save(str(tmp_path / "confidence" / "pool.json"))


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def ev(rid, eid, sec, **data):
    t = BASE + timedelta(seconds=sec)
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal",
            "data": {"UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], **data}}


def file_hash(sec, made, sha=H, status="ok"):
    return {"host": "VM", "label": "vm", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH",
            "time": iso(sec), "origin": "normal",
            "data": {"TargetFilename": made["data"]["TargetFilename"], "ProcessGuid": made["data"]["ProcessGuid"],
                     "hash_status": status, "sha256": sha, "size": 10, "final_path": None,
                     "ref_record_id": made["record_id"], "ref_time": made["time"]}}


def good_run():
    made = ev(103, 11, 3, Image=FETCH, ProcessGuid="{F}", TargetFilename=PAYLOAD)
    return [
        ev(101, 1, 1, Image=FETCH, ProcessGuid="{F}", ProcessId=10, ParentProcessGuid="{R}", Hashes="SHA256=11"),
        ev(102, 3, 2, Image=FETCH, ProcessGuid="{F}", Protocol="tcp", Initiated="true", SourceIp="10.0.2.15",
           SourcePort=50000, DestinationIp="10.0.2.2", DestinationPort=8765),
        made,
        file_hash(4, made),
        ev(104, 1, 15, Image=PAYLOAD, ProcessGuid="{P}", ProcessId=11, ParentProcessGuid="{F}", ParentImage=FETCH,
           Hashes=f"SHA256={H}"),
        ev(105, 5, 17, Image=PAYLOAD, ProcessGuid="{P}"),
        ev(106, 5, 18, Image=FETCH, ProcessGuid="{F}"),
    ]


# a hand-made hub list (the real one is private, under recordings/): a Windows program not in the story
TEST_HUBS = frozenset({r"c:\windows\explorer.exe"})


def run(tmp_path, capsys, records, monkeypatch=None, graph_patch=None, pool=True, hubs=TEST_HUBS):
    for label, rows in (("vm", records), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0,
                                                      "time": iso(0), "start": iso(0), "end": iso(20)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    if pool:
        pool_file(tmp_path)
    if graph_patch:
        real = check_graph_scenario.build_graph
        monkeypatch.setattr(check_graph_scenario, "build_graph", lambda db, **kw: graph_patch(real(db, **kw)))
    real_hubs = check_graph_scenario.load_hubs
    check_graph_scenario.load_hubs = lambda: hubs
    try:
        code = check_graph_scenario.main(["s1", "--recordings", str(tmp_path)] + ([] if hubs else ["--no-hubs"]))
    finally:
        check_graph_scenario.load_hubs = real_hubs
    return code, capsys.readouterr().out


def t1_edge(G):
    return next(d for _, _, d in G.edges(data=True) if d.get("kind") == "content_from")


def test_true_story_passes(tmp_path, capsys):
    code, out = run(tmp_path, capsys, good_run())
    assert code == 0, out
    assert out.count("fact  PASS") == 4 and "hypothesis  PASS" in out and "trace  PASS" in out
    assert "T1 content_from, band low" in out and "method check from the raw records: life 17.0 s -> low at most" in out
    assert "N re-derived from the raw recording: 1" in out and "LIMITATION: a true link graded low" in out
    assert "expected_confidence" not in out and "no other hypothesis links two scenario nodes: PASS" in out   # Q1: the sheet expects no grade
    assert "1 expected hypotheses: PASS" in out


def test_no_pool_fails(tmp_path, capsys):
    code, out = run(tmp_path, capsys, good_run(), pool=False)
    assert code == 1 and "no pool of normal rates" in out


def test_expected_hypothesis_missing_fails(tmp_path, capsys, monkeypatch):
    def drop(G):
        G.remove_edges_from([(u, v, k) for u, v, k, d in G.edges(keys=True, data=True) if d.get("kind") == "content_from"])
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, drop)
    assert code == 1 and "0 layer-2 hypothesis edge(s) between its roles" in out


def test_unlisted_hypothesis_between_scenario_nodes_fails(tmp_path, capsys, monkeypatch):
    def add(G):
        f = next(n for n, d in G.nodes(data=True) if d.get("kind") == "process" and str(d.get("label")).lower() == "s1_fetch.exe")
        p = next(n for n, d in G.nodes(data=True) if d.get("kind") == "process" and str(d.get("label")).lower() == "s1_payload.exe")
        G.add_edge(f, p, kind="fetched_then_ran", grade="hypothesis", layer=2, row="T3", band="low", reason="x",
                   alternative="y", time=G.nodes[p]["start"], evidence=[], primary={}, support=[], via=f, assessable=True)
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, add)
    assert code == 1 and "unlisted hypothesis between scenario nodes: fetch fetched_then_ran payload" in out


def test_wrong_n_fails_the_method_check(tmp_path, capsys, monkeypatch):
    def bump(G):
        t1_edge(G)["n_causes"] = 5
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, bump)
    assert code == 1 and "N 5 on the edge, 1 outgoing connections" in out


def test_assessable_short_life_fails_the_method_check(tmp_path, capsys, monkeypatch):
    rows = good_run()
    rows[-1]["data"]["UtcTime"] = (BASE + timedelta(seconds=9)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]   # fetch ends at 9 s
    def pretend(G):
        t1_edge(G).update(assessable=True, band="medium", timing_band="medium")
        return G
    code, out = run(tmp_path, capsys, rows, monkeypatch, pretend)
    assert code == 1 and "but is graded assessable" in out


def test_optional_hypothesis_may_be_absent_but_a_listed_kind_must_match(tmp_path, capsys, monkeypatch):
    sheet = dict(yaml_sheet())
    sheet["expected_graph"] = dict(sheet["expected_graph"])
    sheet["expected_graph"]["hypotheses"] = sheet["expected_graph"]["hypotheses"] + [
        {"claim": "fetch started the payload because of what it fetched", "between": ["test_server", "payload"],
         "kind": "fetched_then_ran", "optional": True}]
    real = check_graph_scenario.yaml.safe_load          # only the answer sheet is replaced, not frozen.yaml
    monkeypatch.setattr(check_graph_scenario.yaml, "safe_load",
                        lambda f: sheet if "ground_truth" in str(getattr(f, "name", "")) else real(f))
    code, out = run(tmp_path, capsys, good_run())              # the payload starts 13 s after: no T3
    assert code == 0 and "optional, not produced in this run" in out
    sheet["expected_graph"]["hypotheses"][-1]["optional"] = False
    (tmp_path / "b").mkdir()
    code, out = run(tmp_path / "b", capsys, good_run())
    assert code == 1 and "0 layer-2 hypothesis edge(s)" in out
    # optional, but the raw records hold the pair inside the window (payload at 5 s) and the graph
    # drew nothing (patched away): that is a failure, not a note (review finding 8)
    sheet["expected_graph"]["hypotheses"][-1]["optional"] = True
    rows = good_run()
    rows[4]["data"]["UtcTime"] = (BASE + timedelta(seconds=5)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    (tmp_path / "d").mkdir()
    code, out = run(tmp_path / "d", capsys, rows)                 # not patched: the T3 is drawn and listed
    assert code == 0 and "fetch started the payload because of what it fetched  (T3 fetched_then_ran" in out
    def drop_t3(G):
        G.remove_edges_from([(u, v, k) for u, v, k, d in G.edges(keys=True, data=True) if d.get("kind") == "fetched_then_ran"])
        return G
    (tmp_path / "c").mkdir()
    code, out = run(tmp_path / "c", capsys, rows, monkeypatch, drop_t3)   # the graph patch stays on from here
    assert code == 1 and "the raw records hold a cause and effect inside the timing window" in out


def yaml_sheet():
    import yaml
    with open(os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_hypothesis_citing_an_event_that_does_not_say_it_fails(tmp_path, capsys, monkeypatch):
    def miscite(G):
        started = next(d for _, _, d in G.edges(data=True) if d["kind"] == "started")
        t1_edge(G)["evidence"] = started["evidence"] + started["evidence"]
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, miscite)
    assert code == 1 and "the cited raw events don't say what the hypothesis claims" in out


def test_payload_not_started_by_fetch_fails(tmp_path, capsys):
    rows = good_run()
    rows[4]["data"]["ParentProcessGuid"] = "{X}"
    code, out = run(tmp_path, capsys, rows)
    assert code == 1 and "FAIL  fact 'fetch started payload'" in out


def test_missing_fingerprint_fails(tmp_path, capsys):
    rows = [r for r in good_run() if r.get("type") != "FILE_HASH"]
    code, out = run(tmp_path, capsys, rows)
    assert code == 1 and "role payload_file: 0 matching node(s) with known content" in out


def test_fingerprint_not_matching_the_running_program_fails(tmp_path, capsys):
    rows = good_run()
    rows[3]["data"]["sha256"] = "CD" * 32                # the file fetch wrote is not what ran
    code, out = run(tmp_path, capsys, rows)
    assert code == 1 and "FAIL  fact 'payload process runs the payload file'" in out


def test_hypothesis_graded_as_fact_fails(tmp_path, capsys, monkeypatch):
    def add_fact(G):
        server = next(n for n, d in G.nodes(data=True) if d.get("kind") == "endpoint")
        file = next(n for n, d in G.nodes(data=True) if d.get("kind") == "file" and d.get("sha256"))
        G.add_edge(server, file, kind="delivered", grade="fact", layer=2, time=None, evidence=[], primary={})
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, add_fact)
    assert code == 1 and "hypothesis graded as a fact" in out and "unexpected fact: test_server delivered payload_file" in out


def test_fact_citing_an_event_that_does_not_say_it_fails(tmp_path, capsys, monkeypatch):
    def miscite(G):
        started = next(d for _, _, d in G.edges(data=True) if d["kind"] == "started")
        for _, _, d in G.edges(data=True):
            if d["kind"] == "connected_to":
                d["evidence"] = started["evidence"]       # cites a process start, not the connection
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch, miscite)
    assert code == 1 and "'fetch connected to test server': the cited raw events don't say what the edge claims" in out


def test_graph_check_uses_the_runs_own_server(tmp_path, capsys):
    rows = good_run()
    rows[1]["data"]["DestinationPort"] = 18765
    for label, data in (("vm", rows), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0, "time": iso(0),
                                                    "start": iso(0), "end": iso(20), "server": "http://10.0.2.2:18765"}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    pool_file(tmp_path)
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--no-hubs"]) == 0, capsys.readouterr().out


def test_failed_run_fails_even_if_the_graph_looks_right(tmp_path, capsys):
    for label, data in (("vm", good_run()), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 1,
                                                          "time": iso(0), "start": iso(0), "end": iso(20)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    pool_file(tmp_path)
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--no-hubs"]) == 1
    assert "exit code 1" in capsys.readouterr().out


def test_second_file_in_the_scenario_folder_fails(tmp_path, capsys):
    # review 2026-10-18: fetch also writes a second payload without a fingerprint; it must not go unseen
    rows = good_run()
    rows.insert(3, ev(110, 11, 3.5, Image=FETCH, ProcessGuid="{F}",
                      TargetFilename=r"C:\AnalystLab\scenarios\s1\payload\extra.exe"))
    code, out = run(tmp_path, capsys, rows)
    assert code == 1 and "other file node(s) in the scenario's folder" in out


def test_started_by_a_program_with_another_name_fails_the_trace(tmp_path, capsys, monkeypatch):
    # the trace re-checks the raw event's program names against the answer sheet
    rows = good_run()
    rows[4]["data"]["ParentImage"] = r"C:\Windows\explorer.exe"     # raw event names another parent program
    code, out = run(tmp_path, capsys, rows)
    assert code == 1 and "'fetch started payload': the cited raw events don't say what the edge claims" in out

def test_runner_view_shows_every_scenario_process(tmp_path, capsys):
    code, out = run(tmp_path, capsys, good_run())
    assert code == 0, out
    assert "hub(s) not followed" in out and "runner view (from the first program's starter" in out
    assert "all 2 scenario process(es) walked, all expected facts shown: PASS" in out


def test_a_hub_list_that_hides_a_scenario_process_fails(tmp_path, capsys):
    # if the downloader were (wrongly) a hub, a view from its starter would never reach the payload
    code, out = run(tmp_path, capsys, good_run(), hubs=frozenset({FETCH.lower()}))
    assert code == 1 and "treats scenario process(es) as hubs" in out


def test_without_hubs_the_runner_view_is_skipped(tmp_path, capsys):
    code, out = run(tmp_path, capsys, good_run(), hubs=None)
    assert code == 0 and "hub suppression off" in out and "runner view" not in out


def test_a_missing_hub_list_fails(tmp_path, capsys):
    def missing():
        raise FileNotFoundError("hub list recordings/hubs/hubs.json is missing on this machine")
    code, out = run(tmp_path, capsys, good_run(), hubs=None)
    real = check_graph_scenario.load_hubs
    check_graph_scenario.load_hubs = missing
    try:
        assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path)]) == 1
    finally:
        check_graph_scenario.load_hubs = real
    assert "FAIL  hub list" in capsys.readouterr().out

def test_a_scenario_program_on_the_hub_list_fails_even_as_the_last_program(tmp_path, capsys):
    # kept as a node but not walked: "present" is not enough (review 2026-10-24)
    code, out = run(tmp_path, capsys, good_run(), hubs=frozenset({PAYLOAD.lower()}))
    assert code == 1 and "treats scenario process(es) as hubs" in out


def test_a_hub_off_the_story_is_counted_and_passes(tmp_path, capsys):
    recs = good_run()
    recs[0]["data"]["ParentImage"] = r"C:\Windows\explorer.exe"          # the runner is a hub
    code, out = run(tmp_path, capsys, recs)
    assert code == 0, out
    assert "1 hub(s) not followed" in out and "runner view (from the first program's starter" in out


def test_a_first_program_without_a_recorded_starter_fails_the_strict_view(tmp_path, capsys, monkeypatch):
    def no_starter(G):
        G.remove_edges_from([(u, v, k) for u, v, k, d in G.edges(keys=True, data=True)
                             if d.get("kind") == "started" and G.nodes[v].get("label") == "s1_fetch.exe"])
        return G
    code, out = run(tmp_path, capsys, good_run(), monkeypatch=monkeypatch, graph_patch=no_starter)
    assert code == 1 and "starter is not recorded" in out


def test_a_broken_hub_file_is_a_clean_fail(tmp_path, capsys, monkeypatch):
    from tests.conftest import REAL_LOAD_HUBS
    run(tmp_path, capsys, good_run(), hubs=None)                        # set up the recordings
    monkeypatch.setattr(check_graph_scenario, "load_hubs", REAL_LOAD_HUBS)
    def broken():
        raise KeyError("hubs")
    monkeypatch.setattr(check_graph_scenario.config, "hubs", broken)
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path)]) == 1
    assert "FAIL  hub list" in capsys.readouterr().out

def test_the_runner_view_also_needs_every_expected_fact(tmp_path, capsys, monkeypatch):
    real = check_graph_scenario.GraphCheck._lacks
    # the runner view (facts only) loses a fact; the alert view (facts + hypotheses) does not
    monkeypatch.setattr(check_graph_scenario.GraphCheck, "_lacks",
                        lambda self, H, hypotheses=True: real(self, H, hypotheses) if hypotheses else ["a fact"])
    code, out = run(tmp_path, capsys, good_run())
    assert code == 1 and "lacks fact(s) ['a fact']" in out
