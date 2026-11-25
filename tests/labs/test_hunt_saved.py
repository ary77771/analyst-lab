"""Saved hunts (engine/labs/hunts.py) on a hand-made store (tests/labs/hunt_fixtures.py)."""

import os
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import hunts, _huntdb as db
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
def con(store):
    c = db.connect(store)
    yield c
    c.close()


def run(con, hunt_id, window="24h", **kw):
    return hunts.run_hunt(con, hunt_id, db.window(con, window), **kw)


def programs(result, key="program"):
    return [r["cells"][key] for r in result["rows"]]


def test_window_counts_back_from_the_newest_event(con):
    w = db.window(con, "24h")
    assert w.until == fx.ts(fx.T_END)
    assert w.since.startswith("2026-10-31T12:00:00")
    assert db.window(con, "all").bounded is False
    with pytest.raises(ValueError):
        db.window(con, "3 weeks")


def test_deleted_after_run_finds_the_dropper_deleted_by_its_own_child(con):
    r = run(con, "deleted-after-run")
    assert programs(r) == [fx.EVIL]
    row = r["rows"][0]
    assert row["cells"]["how"] == "deleted by a program it started"
    assert row["cells"]["deleted_by"] == "cmd.exe"
    assert {"field": "Image", "value": fx.EVIL} in row["pivots"]


def test_user_folders_lists_downloads_and_leaves_out_the_labs_own_programs(con):
    r = run(con, "user-folders")
    assert programs(r) == [fx.EVIL, "C:\\Temp\\svc.exe"]  # Downloads first; python.exe (origin project) left out
    assert [x["cells"]["folder"] for x in r["rows"]] == ["Downloads", "Temp"]
    with_own = run(con, "user-folders", include_own=True)
    assert "C:\\Users\\analyst\\Downloads\\python.exe" in programs(with_own)


def test_unknown_network_programs(con):
    r = run(con, "unknown-net")
    progs = programs(r)
    assert fx.EVIL in progs
    assert "C:\\Program Files\\Google\\Chrome\\chrome.exe" not in progs   # has a publisher, standard folder
    assert "C:\\Windows\\System32\\svchost.exe" not in progs              # start unknown but in Windows: not listed
    evil = next(x for x in r["rows"] if x["cells"]["program"] == fx.EVIL)
    assert evil["cells"]["connections"] == 12 and evil["cells"]["destinations"] == 1
    assert "signature" in r["notes"][0].lower()


def test_autostart_sees_run_key_startup_folder_and_scheduled_task(con):
    r = run(con, "autostart")
    kinds = [x["cells"]["kind"] for x in r["rows"]]
    assert kinds.count("Run key") == 1 and "Startup folder" in kinds and "Scheduled task" in kinds
    run_key = next(x for x in r["rows"] if x["cells"]["kind"] == "Run key")
    assert run_key["cells"]["place"] == fx.RUN_KEY and run_key["cells"]["by"] == "evil.exe"


def test_script_engine_from_office_only(con):
    r = run(con, "script-engines")
    # explorer -> powershell is not listed; Word -> powershell and evil.exe (Downloads) -> cmd are
    whys = sorted((x["cells"]["engine"], x["cells"]["why"]) for x in r["rows"])
    assert whys == [("cmd.exe", "started by a program in Downloads"), ("powershell.exe", "started by an Office program")]


def test_renamed_tool(con):
    r = run(con, "renamed-tools")
    assert programs(r) == ["C:\\Temp\\svc.exe"]
    assert r["rows"][0]["cells"]["really_is"] == "certutil.exe"   # cmd.exe / PowerShell.EXE (case) are not renamed


def test_listeners_open_to_every_network_first(con):
    r = run(con, "listeners")
    assert [(x["cells"]["program"], x["cells"]["port"]) for x in r["rows"]] == [
        (fx.EVIL, 4444), ("C:\\Windows\\System32\\svchost.exe", 7680)]
    assert r["rows"][0]["cells"]["reachable_from"] == "every network the machine is on"
    assert r["rows"][1]["cells"]["reachable_from"] == "this machine only"


def test_window_excludes_older_events(con):
    # notepad ran three days before the newest event: inside 7d, outside 24h
    def ran(window):
        n = con.execute("SELECT COUNT(*) FROM events WHERE Image LIKE '%notepad.exe' AND time >= ? AND time <= ?",
                        db.window(con, window).sql()[1]).fetchone()[0]
        return n
    assert ran("24h") == 0 and ran("7d") == 1
    r = run(con, "deleted-after-run", window="1h")             # the deletion was ~2.7 h before the end
    assert r["count"] == 0


def test_limit_says_truncated_and_keeps_the_true_count(con):
    r = run(con, "listeners", limit=1)
    assert r["count"] == 2 and len(r["rows"]) == 1 and r["truncated"] is True


def test_a_store_without_registry_columns_says_not_recorded(tmp_path):
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT, time TEXT, event_id INTEGER, type TEXT, "
              "Image TEXT, ProcessGuid TEXT, ParentImage TEXT, CommandLine TEXT)")
    c.execute("INSERT INTO events (host, time, event_id, Image) VALUES ('h', '2026-11-01T00:00:00.0000000Z', 1, 'C:\\x.exe')")
    c.commit()
    c.close()
    con = db.connect(str(p))
    try:
        for h in hunts.HUNTS:                                  # no hunt fails on a store with few columns
            r = hunts.run_hunt(con, h["id"], db.window(con, "24h"))
            assert isinstance(r["rows"], list)
        auto = hunts.run_hunt(con, "autostart", db.window(con, "24h"))
        assert any("no registry events" in n for n in auto["notes"])
        assert hunts.run_hunt(con, "renamed-tools", db.window(con, "24h"))["not_recorded"]
    finally:
        con.close()


def test_store_is_opened_read_only(con):
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM events")


def test_api(store, monkeypatch):
    fx.use_store(monkeypatch, store)
    app = FastAPI()
    app.include_router(hunts.router)
    c = TestClient(app)
    listing = c.get("/api/labs/hunts/").json()
    assert [h["id"] for h in listing["hunts"]] == [h["id"] for h in hunts.HUNTS]
    assert all(h["why"] and h["columns"] for h in listing["hunts"])
    r = c.get("/api/labs/hunts/run/renamed-tools?window=7d").json()
    assert r["count"] == 1 and r["window"]["name"] == "7d"
    assert c.get("/api/labs/hunts/run/nope").status_code == 404
    assert c.get("/api/labs/hunts/run/listeners?window=forever").status_code == 400
    s = c.get("/api/labs/hunts/summary").json()
    assert {x["id"]: x["count"] for x in s["hunts"]}["listeners"] == 2


def test_the_store_comes_from_the_running_dashboards_context_only(store, monkeypatch):
    from engine import labs
    assert db.events_path() == store                        # fx.use_store: a Context, as the dashboard makes it
    monkeypatch.setenv("ANALYSTLAB_LABS_EVENTS", "C:\\elsewhere.db")   # the old switch: ignored now
    assert db.events_path() == store
    monkeypatch.setattr(labs, "_current", None)
    assert db.events_path() is None                         # no dashboard in this process: no store, no guess


def test_the_registry_mounts_the_hunts_lab():
    from engine import labs
    good, bad = labs.discover()
    assert "hunts" in [n for n, _ in good]
    assert not [b for b in bad if b["name"] in ("hunts", "_huntdb")]


def test_api_without_a_store(monkeypatch, tmp_path):
    fx.use_store(monkeypatch, str(tmp_path / "missing.db"))
    app = FastAPI()
    app.include_router(hunts.router)
    assert TestClient(app).get("/api/labs/hunts/run/listeners").status_code == 503
