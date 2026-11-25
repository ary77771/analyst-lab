"""Labs, test a claim (engine/labs/claim.py), on the made-up story of tests/labs/pivotfix.py.

VISION's acceptance (docs/night/ideas.md #2) plus the analyst critique (2026-11-24): five answers, each with its
evidence; a claim the record speaks against is "Contradicted by the record" (with the records), one the record
cannot speak to is "No recorded evidence"; nothing is ever answered "false"."""

import json
from datetime import datetime, timedelta, timezone

import networkx as nx

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import claim as CL
from tests.labs.pivotfix import LAPTOP, FakeContext, story, use

F, C = "proc:analystlab-vm:{F}", "proc:analystlab-vm:{C}"
TOOLF = "file:analystlab-vm:c:\\users\\u\\tool.exe"
NET = "net:analystlab-vm:10.0.2.2:18765"
DNS = "dns:analystlab-vm:test.lab.example"


def add_hypothesis(G):
    """The S1-like dashed line: tool.exe's content may have come from the test server (hand-made layer 2)."""
    created = next(d for u, v, k, d in G.edges(keys=True, data=True) if d.get("kind") == "created")
    G.add_edge(NET, TOOLF, kind="content_from", grade="hypothesis", band="medium", p=0.034,
               reason="created 0.5 s after the connection", alternative="the program had the content already",
               time=created["time"], evidence=list(created["evidence"]))


@pytest.fixture
def world(tmp_path, monkeypatch):
    events_db, alerts_db, alert, keys = story(tmp_path)
    ctx = FakeContext(events_db, alerts_db)
    use(monkeypatch, ctx)
    app = FastAPI()
    app.include_router(CL.router)
    return TestClient(app), ctx, alert, keys


def ask(c, alert, s, verb, o):
    r = c.get(f"/api/labs/claim/{alert.alert_id}/test", params={"subject": s, "verb": verb, "object": o})
    assert r.status_code == 200, r.text
    return r.json()


def test_five_answers(world):
    c, ctx, alert, keys = world
    proven = ask(c, alert, F, "created", TOOLF)
    assert proven["answer"] == "proven" and proven["word"] == "Proven" and proven["ink"] == "fact"
    assert proven["claim"] == "fetch.exe (PID 10) created tool.exe"
    cite = proven["because"][0]["citations"][0]
    assert cite["key"] == keys[3] and cite["summary"] == "fetch.exe (PID 10) created tool.exe"
    assert {"kind": "file", "value": "C:\\Users\\u\\tool.exe", "role": "file"} in cite["entities"]   # a pivot link

    unknown = ask(c, alert, TOOLF, "content_from", NET)               # no fingerprint of tool.exe was recorded
    assert unknown["answer"] == "unknown" and unknown["ink"] == "gap"
    assert unknown["because"][0]["gap"] == "content_unknown" and "fingerprint" in unknown["because"][0]["missing"]

    # the critique's case: the "child" was already running before the "parent" started -> the record says otherwise
    contra = ask(c, alert, C, "started", F)
    assert contra["answer"] == "contradicted" and contra["word"] == "Contradicted by the record"
    assert "was already running at 2026-10-22 10:00:01 UTC, before tool.exe (PID 11) started at 2026-10-22 10:00:05" \
        in contra["because"][0]["sentence"]
    assert {x["key"] for x in contra["because"][0]["citations"]} >= {keys[5]}         # tool.exe's own start, cited

    # NetworkConnect is collected in full (tools/sysmon/sysmon-config.xml): no recorded connection -> contradicted
    net = ask(c, alert, C, "connected_to", NET)
    assert net["answer"] == "contradicted" and "recorded in full" in net["because"][0]["coverage"]

    # file deletions are collected only in part: their absence settles nothing
    nothing = ask(c, alert, C, "deleted", TOOLF)
    assert nothing["answer"] == "no_evidence" and nothing["coverage"] == "some"
    assert "not the same as false" in nothing["note"] and "only in part" in nothing["note"]


def test_suspected_with_a_graph_hypothesis(world):
    c, ctx, alert, keys = world
    ctx.add_edges = add_hypothesis
    s = ask(c, alert, TOOLF, "content_from", NET)
    assert s["answer"] == "suspected" and s["word"] == "Suspected"
    h = s["because"][0]
    assert h["band_word"] == "possible link" and h["alternative"] == "the program had the content already"
    assert h["citations"][0]["key"] == keys[3]


def test_a_claim_is_never_answered_false(world):
    """Every pair of things and every verb: the answer is one of the five, and no answer says "false"."""
    c, ctx, alert, keys = world
    ctx.add_edges = add_hypothesis
    parts = c.get(f"/api/labs/claim/{alert.alert_id}/parts").json()
    ids = [n["id"] for n in parts["nodes"]]
    seen = set()
    for s in ids:
        for o in ids:
            if s == o:
                continue
            for v in parts["verbs"]:
                a = ask(c, alert, s, v["id"], o)
                seen.add(a["answer"])
                assert a["answer"] in ("proven", "suspected", "contradicted", "unknown", "no_evidence")
                assert "false" not in json.dumps(a).lower().replace("not the same as false", "")
    assert seen == {"proven", "suspected", "contradicted", "unknown", "no_evidence"}


def test_the_record_of_something_else_is_shown(world):
    c, ctx, alert, keys = world
    a = ask(c, alert, F, "deleted", TOOLF)                          # fetch.exe CREATED it: said, as a fact
    assert a["answer"] == "no_evidence" and {"sentence": "fetch.exe (PID 10) created tool.exe", "ink": "fact"} in a["also"]


T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)


def tiny(edges, gaps=None):
    """A hand-made graph: processes A, B, Z (and P, A's parent), a file F; edges (u, v, kind, seconds)."""
    G = nx.MultiDiGraph()
    for n in ("P", "A", "B", "Z"):
        G.add_node(n, kind="process", label=n.lower() + ".exe", pid=None, gaps=list((gaps or {}).get(n, [])))
    G.add_node("F", kind="file", label="f.txt", gaps=[])
    for u, v, kind, sec in edges:
        G.add_edge(u, v, kind=kind, grade="fact", time=T0 + timedelta(seconds=sec), evidence=[])
    return G


class NoEvents:
    def event(self, key):
        return None


def test_another_recorded_parent_contradicts(world):
    G = tiny([("P", "A", "started", 1), ("Z", "B", "started", 5)])
    a = CL.test(NoEvents(), G, "A", "started", "B")
    assert a["answer"] == "contradicted" and "the record shows z.exe started b.exe" in a["because"][0]["sentence"]


def test_a_later_start_cannot_be_the_parent_but_an_earlier_one_can_be_unknown(world):
    gap = [{"kind": "parent_unknown", "reason": "parent not recorded", "time": None, "evidence": []}]
    G = tiny([("P", "A", "started", 8), ("B", "F", "created", 2)], gaps={"B": gap})
    assert CL.test(NoEvents(), G, "A", "started", "B")["answer"] == "contradicted"      # B was seen at 2 s, A began at 8 s
    G2 = tiny([("P", "A", "started", 1), ("B", "F", "created", 2)], gaps={"B": gap})
    assert CL.test(NoEvents(), G2, "A", "started", "B")["answer"] == "unknown"           # A began first: can't be known


def test_another_recorded_creator_contradicts_but_absence_of_a_filtered_event_does_not(world):
    G = tiny([("P", "A", "started", 1), ("Z", "F", "created", 3)])
    a = CL.test(NoEvents(), G, "A", "created", "F")
    assert a["answer"] == "contradicted" and "z.exe created f.txt" in a["because"][0]["sentence"]
    G2 = tiny([("P", "A", "started", 1)])
    assert CL.test(NoEvents(), G2, "A", "created", "F")["answer"] == "no_evidence"


def test_network_absence_counts_only_when_collected_in_full(world):
    G = tiny([("P", "A", "started", 1)])
    G.add_node("E", kind="endpoint", ip="10.0.2.2", gaps=[])
    full = {"NetworkConnect": {"state": "all", "rules": 0}}
    part = {"NetworkConnect": {"state": "some", "rules": 3}}
    assert CL.test(NoEvents(), G, "A", "connected_to", "E", cfg=full)["answer"] == "contradicted"
    a = CL.test(NoEvents(), G, "A", "connected_to", "E", cfg=part)
    assert a["answer"] == "no_evidence" and a["coverage"] == "some"
    assert CL.coverage("connected_to", {"NetworkConnect": {"state": "most", "rules": 2}}) == "some"   # exclusions: not "all"


def test_parts_and_suggestions_come_from_the_story(world):
    c, ctx, alert, keys = world
    ctx.add_edges = add_hypothesis
    p = c.get(f"/api/labs/claim/{alert.alert_id}/parts").json()
    assert {F, C, TOOLF, NET, DNS} <= {n["id"] for n in p["nodes"]}
    assert next(n for n in p["nodes"] if n["id"] == F)["gaps"] == ["parent_unknown"]
    assert next(n for n in p["nodes"] if n["id"] == NET)["entity"] == {"kind": "ip", "value": "10.0.2.2"}
    answers = [s["answer"] for s in p["suggestions"]]
    assert answers[:2] == ["proven", "suspected"] and "contradicted" in answers and len(set(answers)) == len(answers)
    for s in p["suggestions"]:                                       # each suggestion really gives its answer
        assert ask(c, alert, s["subject"], s["verb"], s["object"])["answer"] == s["answer"]
    assert p["answers"]["contradicted"] == "Contradicted by the record"


def test_bad_input_and_laptop_alerts(world, monkeypatch):
    c, ctx, alert, keys = world
    base = f"/api/labs/claim/{alert.alert_id}/test"
    assert c.get(base, params={"subject": F, "verb": "teleported", "object": C}).status_code == 400
    assert c.get(base, params={"subject": F, "verb": "started", "object": F}).status_code == 400
    assert c.get(base, params={"subject": F, "verb": "started", "object": "proc:nowhere"}).status_code == 404
    assert c.get("/api/labs/claim/nope/parts").status_code == 404
    laptop = next(a for a in ctx.alerts() if a.host == LAPTOP)
    assert c.get(f"/api/labs/claim/{laptop.alert_id}/parts").status_code == 404      # night rule 11
    assert [a["id"] for a in c.get("/api/labs/claim/alerts").json()] == [alert.alert_id]


class Rows:
    """ctx.event() for hand-made graphs: {key: row}."""
    def __init__(self, rows):
        self.rows = rows

    def event(self, key):
        return self.rows.get(key)


def test_time_order_uses_the_one_clock(world):
    """Night 2 shared clock: B was WRITTEN down at 10:00:06 but HAPPENED at 10:00:03 (Sysmon's UtcTime), before A
    started at 10:00:05: "A started B" is contradicted on the one clock, never on the record time alone."""
    rows = {"kA": {"time": "2026-10-22T10:00:05Z", "UtcTime": "2026-10-22 10:00:05.000"},
            "kB": {"time": "2026-10-22T10:00:06Z", "UtcTime": "2026-10-22 10:00:03.000"}}
    G = tiny([])
    G.add_edge("P", "A", kind="started", grade="fact", time=T0 + timedelta(seconds=5), evidence=[{"key": "kA"}])
    G.add_edge("B", "F", kind="created", grade="fact", time=T0 + timedelta(seconds=6), evidence=[{"key": "kB"}])
    G.nodes["B"]["gaps"] = [{"kind": "parent_unknown", "reason": "x", "time": None, "evidence": []}]
    a = CL.test(Rows(rows), G, "A", "started", "B")
    assert a["answer"] == "contradicted" and "already running at 2026-10-22 10:00:03 UTC" in a["because"][0]["sentence"]
    assert CL.test(NoEvents(), G, "A", "started", "B")["answer"] == "unknown"     # by the graph's record time: 6 > 5


def test_the_test_machinery_stays_out_of_the_dropdowns(world):
    c, ctx, alert, keys = world
    G = tiny([("P", "A", "started", 1)])
    G.add_node("R", kind="endpoint", ip="10.0.2.2", port=8770, gaps=[])          # the report back to the laptop
    G.add_node("V", kind="process", image=r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe",
               label="VBoxControl.exe", gaps=[])
    G.add_edge("P", "L", kind="started", grade="fact", time=T0, evidence=[{"key": "kL"}])
    G.nodes["L"].update(kind="process", label="powershell.exe", gaps=[])
    launcher = Rows({"kL": {"Image": "powershell.exe", "CommandLine": "powershell -File D:\\scenario_launcher.ps1"}})
    shown = {n["id"] for n in CL.parts(G, launcher, machinery=False)[0]}
    assert {"R", "V", "L"}.isdisjoint(shown) and {"A", "B", "F"} <= shown
    assert {"R", "V", "L"} <= {n["id"] for n in CL.parts(G, launcher, machinery=True)[0]}


def test_plain_words_for_the_professor(world):
    """VISION critique-4: suggestions read as plain sentences (no PIDs); the dropdowns name a program by its name
    (its PID only when two programs share it) and a file by its folder and name, never a bare fragment."""
    c, ctx, alert, keys = world
    p = c.get(f"/api/labs/claim/{alert.alert_id}/parts").json()
    assert all("(PID" not in s["plain"] for s in p["suggestions"])
    assert all(s["plain"] == CL.plain_claim(s["claim"]) for s in p["suggestions"])
    by = {n["id"]: n for n in p["nodes"]}
    assert by[F]["plain"] == "fetch.exe" and by[F]["kind_word"] == "program" and by[F]["pid"] == 10
    assert by[TOOLF]["plain"] == "u\\tool.exe" and by[TOOLF]["kind_word"] == "file"
    assert [n["kind"] for n in p["nodes"]][:2] == ["process", "process"]                 # programs first
    G = tiny([("P", "A", "started", 1), ("P", "B", "started", 2)])
    G.nodes["A"].update(label="same.exe", pid=1)
    G.nodes["B"].update(label="same.exe", pid=2)
    names = {n["id"]: n["plain"] for n in CL.parts(G)[0]}
    assert names["A"] == "same.exe (PID 1)" and names["B"] == "same.exe (PID 2)"       # only when names clash
