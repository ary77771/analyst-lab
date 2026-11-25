"""Gap explorer (engine/labs/gaps.py): what the recorder could not see, on the hand-made store."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import gaps, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    """No dashboard context left by another test decides which machines these tests see."""
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    path = fx.build(tmp_path / "events.db")
    fx.use_store(monkeypatch, path)                  # this store, as a running dashboard would hand it over
    return path


@pytest.fixture()
def out(store):
    con = db.connect(store)
    try:
        return {s["id"]: s for s in gaps.explore(con, db.window(con, "24h"))["sections"]}
    finally:
        con.close()


def programs(section):
    return sorted(r["cells"]["program"] for r in section["rows"])


def test_every_kind_has_a_plain_explanation(out):
    assert list(out) == gaps.ORDER
    assert all(s["title"] and len(s["plain"]) > 40 for s in out.values())


def test_zero_parent_is_a_gap_not_a_process(out):
    s = out["parent_unknown"]
    assert programs(s) == ["C:\\Windows\\System32\\lsass.exe"] and s["total"] == 1
    assert "not a process" in s["plain"]


def test_processes_whose_start_was_never_recorded(out):
    s = out["origin_unknown"]
    rows = {r["cells"]["program"]: r["cells"]["seen_as"] for r in s["rows"]}
    assert rows == {"C:\\Windows\\System32\\svchost.exe": "acting", "C:\\Windows\\explorer.exe": "parent",
                    "C:\\Windows\\System32\\services.exe": "parent"}


def test_fingerprints_records_pauses_unreadable_and_sysmon_errors(out, store):
    assert out["content_unknown"]["total"] == 1 and out["content_unknown"]["rows"][0]["cells"]["why"] == "unreadable"
    # (in the 24 h window the fixture's notepad record, numbered 2 but dated three days earlier, is
    # outside: a hand-made oddity; the whole store has exactly the 5 skipped numbers)
    m = out["missing_records"]
    assert m["total"] == 6
    con = db.connect(store)
    try:
        whole = {s["id"]: s for s in gaps.explore(con, db.window(con, "all"))["sections"]}["missing_records"]
    finally:
        con.close()
    assert whole["total"] == 5 and len(whole["rows"]) == 1 and whole["rows"][0]["cells"]["missing"] == 5
    assert out["record_restarts"]["total"] == 0
    assert out["paused"]["total"] == 1
    assert out["unreadable"]["total"] == 1
    assert out["sysmon_errors"]["total"] == 1
    assert out["actor_unknown"]["total"] == 0


def test_silences_longest_first(out):
    s = out["silences"]
    assert s["rows"][0]["cells"]["length"] == "2.0 h" and s["rows"][0]["cells"]["ended_by"] == "events again (cause unknown)"
    assert all(r["count"] > 600 for r in s["rows"])


def test_a_restart_closes_a_silence_and_record_numbers_starting_again(tmp_path):
    b = fx.Builder()
    t = fx.T_END
    from datetime import timedelta
    b.start(t - timedelta(hours=5), fx.guid(1), "C:\\a.exe", fx.guid(9), "C:\\p.exe")
    b.rid = 2000
    b.sysmon(4, t - timedelta(hours=2), State="Started")           # record 2001: 2..2000 never arrived
    b.rid = 3                                                        # the numbering starts again (a cleared log)
    b.sysmon(4, t - timedelta(hours=1), State="Started")
    b.sysmon(4, t - timedelta(minutes=45), State="Started")           # record 5
    b.rid = 4                                                        # back to a snapshot: record 5 again
    b.sysmon(4, t - timedelta(minutes=30), State="Started")
    p = tmp_path / "r.db"
    s = EventStore(str(p))
    s.insert(b.records)
    s.close()
    con = db.connect(str(p))
    try:
        out = {x["id"]: x for x in gaps.explore(con, db.window(con, "24h"))["sections"]}
    finally:
        con.close()
    assert [r["cells"] for r in out["record_restarts"]["rows"]] == [
        {"host": fx.HOST, "from_record": 2001, "to_record": 4}, {"host": fx.HOST, "from_record": 5, "to_record": 5}]
    assert out["missing_records"]["total"] == 1999                     # 2..2000 between record 1 and record 2001
    assert out["missing_records"]["rows"][0]["cells"]["around"].startswith("a restart")   # record 2001 is a Sysmon start
    assert {r["cells"]["ended_by"] for r in out["silences"]["rows"]} == {"a restart (Sysmon started)"}


def test_many_small_holes_are_called_a_selected_store_not_a_loss():
    small = [{"count": 2}] * 150
    assert "only some kinds of events" in gaps._holes_note(small)
    assert gaps._holes_note([{"count": 2}] * 20) is None              # a few holes: just listed
    assert gaps._holes_note([{"count": 40}] * 150) is None            # big holes: no such excuse


def test_a_hole_without_a_restart_says_so(out):
    assert out["missing_records"]["rows"][0]["cells"]["around"] == "no restart recorded"


def test_a_late_record_is_not_a_loss():
    rows = [("h", i, f"t{n:02d}") for n, i in enumerate([1, 3, 2, 4])]      # (host, record_id, time)

    class Con:                                       # records() reads plain tuples through a cursor
        row_factory = None

        def cursor(self):
            return self

        def execute(self, sql, params):
            return rows
    import engine.labs.gaps as g
    orig = g._base
    g._base = lambda con, w, host, extra: ("FROM x", [])
    try:
        missing, restarts = g.records(Con(), None, None)
    finally:
        g._base = orig
    assert missing == [] and restarts == []


def test_api(store, monkeypatch):
    fx.use_store(monkeypatch, store)
    app = FastAPI()
    app.include_router(gaps.router)
    c = TestClient(app)
    r = c.get("/api/labs/gaps/?window=24h").json()
    assert r["kinds_with_gaps"] == 8 and r["window"]["name"] == "24h"
    assert c.get("/api/labs/gaps/?silence_minutes=0").status_code == 400
