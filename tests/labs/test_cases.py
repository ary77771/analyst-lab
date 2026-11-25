"""Labs, the case board (engine/labs/cases.py), on the made-up story of tests/labs/pivotfix.py."""

import json
import os
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import report as report_mod
from engine.graph import build_graph
from engine.labs import cases as C
from tests.labs.pivotfix import FETCH, HASH, LAPTOP, VM, TOOL, FakeContext, story, use


def real_report(events_db):
    def build(alert):
        con = sqlite3.connect(events_db)
        try:
            G = build_graph(con)
        finally:
            con.close()
        return report_mod.build(alert, G, events_db)
    return build


@pytest.fixture
def world(tmp_path, monkeypatch):
    events_db, alerts_db, alert, keys = story(tmp_path)
    rec = tmp_path / "rec"
    ctx = FakeContext(events_db, alerts_db, recordings=str(rec), report=real_report(events_db))
    use(monkeypatch, ctx)
    app = FastAPI()
    app.include_router(C.router)
    return TestClient(app), ctx, alert, keys, rec


def test_a_case_from_start_to_finish(world):
    c, ctx, alert, keys, rec = world
    case = c.post("/api/labs/cases", json={"title": "Downloaded tool", "summary": "what started tool.exe?"}).json()
    cid = case["id"]
    assert C.CASE_ID.match(cid) and (rec / "cases" / f"{cid}.json").exists()

    a = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id}).json()
    assert a["label"] == alert.title and a["time"] == alert.time and a["snapshot"]["level"] == "high"
    assert a["case"] == {"id": cid, "title": "Downloaded tool"}         # the page says where the pin went
    e = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "event", "ref": keys[2]}).json()
    assert e["snapshot"]["summary"] == "fetch.exe (PID 10) connected to 10.0.2.2:18765"
    f = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "entity", "kind": "hash", "ref": HASH.upper()}).json()
    assert f["ref"] == HASH and f["snapshot"]["events"] == 2 and f["time"] == f["snapshot"]["first"]
    again = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "entity", "kind": "hash", "ref": HASH}).json()
    assert again["id"] == f["id"]                               # pinned once only
    h = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "hypothesis", "ref": "fetch.exe was started by a script"}).json()
    n = c.post(f"/api/labs/cases/{cid}/notes", json={"text": "check the user's downloads"}).json()

    full = c.get(f"/api/labs/cases/{cid}").json()
    assert len(full["pins"]) == 4 and full["notes"][0]["id"] == n["id"]
    assert full["marks"][f"p:{h['id']}"]["status"] == "open"
    times = [r["time"] for r in full["timeline"]]
    assert times == sorted(times) and len(times) == 3        # the analyst's hypothesis has no recorded time
    rep = full["alerts"][alert.alert_id]
    assert rep and "facts" in rep and any("tool.exe" in x["sentence"] for x in rep["facts"])

    m = c.put(f"/api/labs/cases/{cid}/marks", json={"key": f"p:{h['id']}", "status": "ruled_out", "note": "no script ran"}).json()
    assert m["status"] == "ruled_out"
    assert c.put(f"/api/labs/cases/{cid}/marks", json={"key": f"p:{h['id']}", "status": "maybe"}).status_code == 400
    assert c.put(f"/api/labs/cases/{cid}/marks", json={"key": "p:p-00000000", "status": "open"}).status_code == 404
    hk = f"h:{alert.alert_id}:e7d04dd12a7b0"
    assert c.put(f"/api/labs/cases/{cid}/marks", json={"key": hk, "status": "confirmed"}).status_code == 200
    assert c.put(f"/api/labs/cases/{cid}/marks", json={"key": "h:ffff:x", "status": "confirmed"}).status_code == 404

    assert c.delete(f"/api/labs/cases/{cid}/pins/{e['id']}").status_code == 200
    assert c.delete(f"/api/labs/cases/{cid}/notes/{n['id']}").status_code == 200
    assert c.delete(f"/api/labs/cases/{cid}/notes/{n['id']}").status_code == 404
    assert c.patch(f"/api/labs/cases/{cid}", json={"title": "Renamed"}).json()["title"] == "Renamed"
    row = c.get("/api/labs/cases").json()[0]
    assert row == {**row, "id": cid, "title": "Renamed", "pins": 3, "notes": 0}

    assert c.delete(f"/api/labs/cases/{cid}").status_code == 200
    assert c.get("/api/labs/cases").json() == []
    assert (rec / "cases" / "deleted" / f"{cid}.json").exists()   # moved, never erased


def test_bad_input_is_refused(world):
    c, ctx, alert, keys, rec = world
    cid = c.post("/api/labs/cases", json={"title": ""}).json()["id"]
    assert c.get(f"/api/labs/cases/{cid}").json()["title"] == "Untitled case"
    for bad in ("../../etc", "c-1", "..%5c..%5cx"):
        assert c.get(f"/api/labs/cases/{bad}").status_code == 404
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "rumour", "ref": "x"}).status_code == 400
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": "nope"}).status_code == 404
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "event", "ref": "nope"}).status_code == 404
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "entity", "ref": TOOL}).status_code == 404     # no kind
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": "  "}).status_code == 400
    assert c.post(f"/api/labs/cases/{cid}/notes", json={"text": "   "}).status_code == 400
    assert c.post("/api/labs/cases/c-20990101-000000-abcdef/notes", json={"text": "x"}).status_code == 404


def test_laptop_data_cannot_be_pinned_by_default(world, monkeypatch):
    """Night rule 11: the laptop's alert and events are refused unless the dashboard allows every machine."""
    c, ctx, alert, keys, rec = world
    monkeypatch.setenv("ANALYSTLAB_LABS_LAPTOP", "1")                  # the old switch: ignored
    laptop = next(a for a in ctx.alerts() if a.host == LAPTOP)
    cid = c.post("/api/labs/cases", json={"title": "x"}).json()["id"]
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": laptop.alert_id}).status_code == 404
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "event", "ref": keys[8]}).status_code == 404
    ctx.hosts = None                                                     # --labs-all-hosts
    assert c.post(f"/api/labs/cases/{cid}/pins", json={"type": "event", "ref": keys[8]}).status_code == 200


def test_the_alert_named_by_the_address(world):
    """#/labs/cases?alert=<id> (NextStrip's "Add to case"): the page asks for the alert's title to offer pinning it."""
    c, ctx, alert, keys, rec = world
    r = c.get(f"/api/labs/cases/alert/{alert.alert_id}").json()
    assert r == {"id": alert.alert_id, "title": alert.title, "level": "high", "time": alert.time}
    assert c.get("/api/labs/cases/alert/nope").status_code == 404
    laptop = next(a for a in ctx.alerts() if a.host == LAPTOP)
    assert c.get(f"/api/labs/cases/alert/{laptop.alert_id}").status_code == 404          # night rule 11


def test_the_stores_are_only_read(world):
    """Pinning reads the event store and the alert DB; both files stay byte-for-byte the same."""
    c, ctx, alert, keys, rec = world
    before = [open(p, "rb").read() for p in (ctx.events_db, ctx.alerts_db)]
    cid = c.post("/api/labs/cases", json={"title": "x"}).json()["id"]
    c.post(f"/api/labs/cases/{cid}/pins", json={"type": "entity", "kind": "program", "ref": FETCH})
    c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id})
    c.get(f"/api/labs/cases/{cid}")
    assert [open(p, "rb").read() for p in (ctx.events_db, ctx.alerts_db)] == before
    assert sorted(os.listdir(rec)) == ["cases"]


def test_a_broken_report_does_not_break_the_case(world):
    c, ctx, alert, keys, rec = world
    ctx._report = lambda a: (_ for _ in ()).throw(RuntimeError("this dashboard was started without an alert's report"))
    cid = c.post("/api/labs/cases", json={"title": "x"}).json()["id"]
    c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id})
    full = c.get(f"/api/labs/cases/{cid}").json()
    assert "error" in full["alerts"][alert.alert_id]


def test_a_damaged_file_is_skipped_in_the_list(world):
    c, ctx, alert, keys, rec = world
    cid = c.post("/api/labs/cases", json={"title": "good"}).json()["id"]
    (rec / "cases" / "c-20260101-000000-abcdef.json").write_text("{not json", encoding="utf-8")
    (rec / "cases" / "notes.txt").write_text("x", encoding="utf-8")
    assert [r["id"] for r in c.get("/api/labs/cases").json()] == [cid]
    saved = json.loads((rec / "cases" / f"{cid}.json").read_text(encoding="utf-8"))
    assert saved["title"] == "good" and not list((rec / "cases").glob("*.tmp"))


def test_drafts_are_marked_never_deleted(world):
    """VISION 2026-11-24: an untouched "Untitled case" with one pin must not be the first thing seen. The list
    marks it a draft (the page keeps drafts behind "show drafts"); naming it, a second pin or a note ends that."""
    c, ctx, alert, keys, rec = world
    blank = c.post("/api/labs/cases", json={"title": ""}).json()["id"]
    dated = c.post("/api/labs/cases", json={"title": "Case 2026-11-24 00:14"}).json()["id"]
    named = c.post("/api/labs/cases", json={"title": "S1 \u00b7 Download and run: x"}).json()["id"]
    c.post(f"/api/labs/cases/{blank}/pins", json={"type": "alert", "ref": alert.alert_id})
    rows = {r["id"]: r["draft"] for r in c.get("/api/labs/cases").json()}
    assert rows == {blank: True, dated: True, named: False}                        # all three still listed
    c.post(f"/api/labs/cases/{dated}/notes", json={"text": "worth keeping"})
    c.post(f"/api/labs/cases/{blank}/pins", json={"type": "event", "ref": keys[2]})
    rows = {r["id"]: r["draft"] for r in c.get("/api/labs/cases").json()}
    assert rows == {blank: False, dated: False, named: False}


def test_pinning_the_same_thing_again_changes_nothing(world):
    """Critique-4: a second pin of what a case already holds must not touch the case (its "last changed"), or a
    leftover draft would look freshly worked on and receive the next pin."""
    c, ctx, alert, keys, rec = world
    cid = c.post("/api/labs/cases", json={"title": ""}).json()["id"]
    first = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id}).json()
    path = rec / "cases" / f"{cid}.json"
    before = path.read_bytes()
    again = c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id}).json()
    assert again["id"] == first["id"] and path.read_bytes() == before
