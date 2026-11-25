"""Lab: Story diff (engine/labs/storydiff.py). Two fixture runs written in a temp demo folder; the acceptance
check against /api/twin's data runs on the real replay stores when they are on this machine."""

import json
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.alerts import Alert, AlertStore
from engine.labs import storydiff as D
from nighttools_fixtures import configure, store_with

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def p1(guid, image, parent="{0}", pimage="C:\\Windows\\explorer.exe", t="2026-11-01T10:00:00.000Z"):
    return {"event_id": 1, "time": t, "data": {"ProcessGuid": guid, "ParentProcessGuid": parent, "Image": image,
                                                "ParentImage": pimage}}


def run_a():
    return [
        p1("{a1}", "D:\\blind\\b98\\bin\\b98_sync.exe"),
        p1("{a2}", "C:\\Windows\\System32\\cmdkey.exe", parent="{a1}", pimage="D:\\blind\\b98\\bin\\b98_sync.exe"),
        {"event_id": 11, "data": {"ProcessGuid": "{a1}", "Image": "D:\\blind\\b98\\bin\\b98_sync.exe",
                                  "TargetFilename": "C:\\AnalystLab\\scenarios\\b98\\work\\s1.dat"}},
        {"event_id": 11, "data": {"ProcessGuid": "{a1}", "Image": "D:\\blind\\b98\\bin\\b98_sync.exe",
                                  "TargetFilename": "C:\\AnalystLab\\scenarios\\b98\\work\\s2.dat"}},
        {"event_id": 26, "data": {"ProcessGuid": "{a1}", "Image": "D:\\blind\\b98\\bin\\b98_sync.exe",
                                  "TargetFilename": "C:\\AnalystLab\\scenarios\\b98\\work\\s1.dat"}},
        {"event_id": 3, "data": {"ProcessGuid": "{a1}", "Image": "D:\\blind\\b98\\bin\\b98_sync.exe",
                                 "DestinationIp": "10.0.2.2", "DestinationPort": 18765, "Initiated": "true"}},
        # background Windows activity and our own tools: not the test's steps
        p1("{w1}", "C:\\Windows\\System32\\svchost.exe"),
        {"event_id": 3, "data": {"ProcessGuid": "{w1}", "Image": "C:\\Windows\\System32\\svchost.exe",
                                 "DestinationIp": "185.0.0.1", "DestinationPort": 53, "Initiated": "true"}},
    ]


def run_b():
    return [
        p1("{b1}", "D:\\blind\\b99\\bin\\docsafe.exe"),
        {"event_id": 11, "data": {"ProcessGuid": "{b1}", "Image": "D:\\blind\\b99\\bin\\docsafe.exe",
                                  "TargetFilename": "C:\\AnalystLab\\scenarios\\b99\\work\\s7.dat"}},
        {"event_id": 26, "data": {"ProcessGuid": "{b1}", "Image": "D:\\blind\\b99\\bin\\docsafe.exe",
                                  "TargetFilename": "C:\\AnalystLab\\scenarios\\b99\\work\\s7.dat"}},
        p1("{w2}", "C:\\Windows\\System32\\wermgr.exe"),
    ]


def alert(rule, title, level):
    return Alert(rule_id=rule, title=title, source="sigma", level=level, time="2026-11-01T10:00:05.000Z",
                 host="analystlab-vm", reason="fixture", evidence=("k",))


@pytest.fixture
def demo(tmp_path, monkeypatch):
    root = tmp_path / "rec" / "demo"
    for rid, when, events, alerts in (
            ("20261101-100000-aaaa", "20261102-090000", run_a(), [alert("r-cmdkey", "Cmdkey listing", "high"),
                                                                  alert("r-wipe", "Create, send, wipe", "medium"),
                                                                  alert("r-acct", "Accounts listed", "low")]),
            ("20261101-110000-bbbb", "20261102-090100", run_b(), [alert("r-wipe-plain", "Create and wipe", "low")]),
            ("20261101-100000-aaaa", "20261101-080000", [], [])):          # an older replay of run A: not used
        d = root / f"{rid}-{when}"
        d.mkdir(parents=True)
        store_with(str(d / "events.db"), events)
        s = AlertStore(str(d / "alerts.db"))
        s.write(alerts)
        s.close()
    vm = tmp_path / "rec" / "vmruns"
    vm.mkdir()
    (vm / "2026-11-01.jsonl").write_text("\n".join(json.dumps(x) for x in [
        {"type": "SCENARIO_RUN", "run_id": "20261101-100000-aaaa", "scenario": "B98", "start": "2026-11-01T10:00:00Z", "exit_code": 0},
        {"type": "SCENARIO_RUN", "run_id": "20261101-110000-bbbb", "scenario": "B99", "start": "2026-11-01T11:00:00Z", "exit_code": 0}]) + "\n",
        encoding="utf-8")
    monkeypatch.delenv("ANALYSTLAB_REPLAYS", raising=False)
    return tmp_path / "rec"


def test_runs_are_the_newest_replay_of_each_run_with_its_scenario(demo):
    rs = D.runs(str(demo))
    assert [(r["id"], r["scenario"]) for r in rs] == [("20261101-110000-bbbb", "B99"), ("20261101-100000-aaaa", "B98")]
    assert rs[1]["replayed"] == "20261102-090000"


def test_general_path_hides_what_differs_from_run_to_run_anyway():
    assert D.general_path("C:\\AnalystLab\\scenarios\\b18\\work\\stage\\s12.dat") == "C:\\AnalystLab\\scenarios\\<test folder>\\work\\stage\\s#.dat"
    assert D.general_path("C:\\Users\\analyst\\AppData\\Local\\Temp\\x3.TMP") == "<user>\\AppData\\Local\\Temp\\x#.tmp"
    assert D.general_path("D:\\blind\\b18\\bin\\b18_sync.exe") == "<test CD>\\b#_sync.exe"


def test_only_the_tests_own_steps_and_everything_on_request(demo):
    a = D.runs(str(demo))[1]["folder"]
    import sqlite3
    con = sqlite3.connect(os.path.join(a, "events.db"))
    own, n = D.steps(con)
    every, _ = D.steps(con, everything=True)
    con.close()
    assert n == 2 and set(own["ran"]) == {"b98_sync.exe", "cmdkey.exe"}           # cmdkey: started BY the test
    assert set(own["connected"]) == {"10.0.2.2:18765"}
    assert "svchost.exe" in every["ran"] and "185.0.0.1:53" in every["connected"]


def test_diff_lines_up_kinds_and_alerts(demo):
    rs = {r["scenario"]: r for r in D.runs(str(demo))}
    d = D.diff(rs["B98"]["folder"], rs["B99"]["folder"])
    by = {k["kind"]: k for k in d["kinds"]}
    assert [x["key"] for x in by["ran"]["only_a"]] == ["b98_sync.exe", "cmdkey.exe"]
    assert [x["key"] for x in by["ran"]["only_b"]] == ["docsafe.exe"]
    assert [x["key"] for x in by["created"]["both"]] == ["C:\\AnalystLab\\scenarios\\<test folder>\\work\\s#.dat"]
    assert by["created"]["both"][0]["a"]["count"] == 2 and by["created"]["both"][0]["b"]["count"] == 1
    assert [x["key"] for x in by["connected"]["only_a"]] == ["10.0.2.2:18765"] and not by["connected"]["only_b"]
    s = {x["kind"]: x["who"] for x in d["summary"]}
    assert s == {"ran": "both", "created": "both", "deleted": "both", "connected": "only_a", "looked_up": "neither",
                 "registry": "neither"}
    r = d["alerts"]["raised"]
    assert (r["a"], r["b"]) == (2, 0) and sorted(x["title"] for x in r["only_a"]) == ["Cmdkey listing", "Create, send, wipe"]
    assert [x["title"] for x in d["alerts"]["below"]["only_b"]] == ["Create and wipe"]
    assert not d["same"]


def test_a_run_against_itself_shows_no_differences(demo):
    a = D.runs(str(demo))[1]["folder"]
    d = D.diff(a, a)
    assert d["same"] and d["differences"] == 0
    assert all(not k["only_a"] and not k["only_b"] for k in d["kinds"])


def test_routes_take_run_ids_only(tmp_path, demo):
    configure(tmp_path, tmp_path / "missing.db")
    from engine import labs
    labs.context().recordings = str(demo)
    app = FastAPI()
    app.include_router(D.router)
    c = TestClient(app)
    body = c.get("/api/labs/storydiff").json()
    assert [r["scenario"] for r in body["runs"]] == ["B99", "B98"] and "folder" not in body["runs"][0]
    d = c.get("/api/labs/storydiff/diff", params={"a": "20261101-100000-aaaa", "b": "20261101-110000-bbbb"}).json()
    assert d["a"]["scenario"] == "B98" and d["alerts"]["raised"]["a"] == 2
    assert c.get("/api/labs/storydiff/diff", params={"a": "..\\..\\x", "b": "20261101-110000-bbbb"}).status_code == 404


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(D.WORDS)), BANNED.search(json.dumps(D.WORDS))


def test_b18_vs_b19_says_what_the_twin_screen_says():
    """Acceptance (VISION #3): the twin's two official runs, diffed here, raise the same alerts per side as
    docs/results/v4/twin.json (what /api/twin shows). Needs the replay stores on this machine."""
    with open(os.path.join(ROOT, "docs", "results", "v4", "twin.json"), encoding="utf-8") as f:
        twin = json.load(f)
    root = D.demo_root()
    rs = {r["id"]: r for r in D.runs(os.path.dirname(root))} if root else {}
    sides = {s["scenario"]: s for s in twin["sides"]}
    a, b = sides["B18"], sides["B19"]
    if a["run_id"] not in rs or b["run_id"] not in rs:
        pytest.skip("the twin's replay stores are not on this machine")
    d = D.diff(rs[a["run_id"]]["folder"], rs[b["run_id"]]["folder"])
    raised = d["alerts"]["raised"]
    assert (raised["a"], raised["b"]) == (len(a["raised"]), len(b["raised"])) == (2, 0)
    assert sorted(x["title"] for x in raised["only_a"]) == sorted(x["title"] for x in a["raised"])
    below = d["alerts"]["below"]
    assert (below["a"], below["b"]) == (len(a["below_floor"]), len(b["below_floor"]))
    assert {x["kind"]: x["who"] for x in d["summary"]}["created"] == "both"            # both created files ...
    assert {x["kind"]: x["who"] for x in d["summary"]}["deleted"] == "both"            # ... and deleted them again
    assert D.diff(rs[a["run_id"]]["folder"], rs[a["run_id"]]["folder"])["same"]
