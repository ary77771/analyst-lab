"""First seen / rare here (engine/labs/rarity.py) on the hand-made store."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import rarity, _huntdb as db
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


def items(r):
    return {x["cells"]["item"]: x for x in r["rows"]}


def test_programs_rarest_first_and_new_only_inside_the_focus(con):
    r = rarity.stack(con, "programs", db.window(con, "7d"), focus="24h")
    counts = [x["count"] for x in r["rows"]]
    assert counts == sorted(counts)                               # rarest first
    it = items(r)
    assert it["C:\\Windows\\System32\\svchost.exe"]["count"] == 21
    assert it[fx.EVIL]["count"] == 1 and it[fx.EVIL]["new"] is True
    assert it["C:\\Windows\\System32\\notepad.exe"]["new"] is False     # seen three days before the end
    assert "C:\\Users\\analyst\\Downloads\\python.exe" not in it       # the lab's own program
    assert r["can_mark_new"] is True
    assert sum(b["items"] for b in r["tail"]) == r["items"]
    assert r["once"] == sum(1 for x in r["rows"] if x["count"] == 1)


def test_nothing_is_new_when_the_period_is_not_longer_than_the_focus(con):
    r = rarity.stack(con, "programs", db.window(con, "24h"), focus="24h")
    assert r["can_mark_new"] is False and r["new"] == 0 and r["baseline"] is None
    assert any("No earlier recording to compare with" in n for n in r["notes"])


def test_a_long_window_over_a_short_recording_has_no_baseline(tmp_path, monkeypatch):
    """Critique 2026-11-24: a 7-day window over one minute of recording called every program 'new'."""
    b = fx.Builder()
    from datetime import timedelta
    for i in range(7):
        b.start(fx.T_END - timedelta(seconds=60 - i * 5), fx.guid(800 + i), f"C:\\p{i}.exe", fx.guid(1), "C:\\Windows\\explorer.exe")
    from engine.store import EventStore
    p = str(tmp_path / "short.db")
    s = EventStore(p)
    s.insert(b.records)
    s.close()
    con = db.connect(p)
    try:
        r = rarity.stack(con, "programs", db.window(con, "7d"), focus="24h")
    finally:
        con.close()
    assert r["items"] == 7 and r["new"] == 0 and r["can_mark_new"] is False and r["baseline"] is None


def test_the_baseline_is_shown(con):
    r = rarity.stack(con, "programs", db.window(con, "7d"), focus="24h")
    assert r["baseline"]["since"].startswith("2026-10-29T12:00:00")          # the first record inside the period
    assert r["baseline"]["until"].startswith("2026-10-31T12:00:00")          # the focus cut


def test_parent_child_pairs(con):
    r = rarity.stack(con, "pairs", db.window(con, "24h"))
    it = items(r)
    assert it["WINWORD.EXE → powershell.exe"]["count"] == 1
    assert it["explorer.exe → powershell.exe"]["count"] == 1
    assert it["services.exe → svchost.exe"]["count"] == 21
    assert it["(parent not recorded) → lsass.exe"]["cells"]["parent"] == "-"    # a gap, never a made-up parent


def test_destinations_count_connections_and_programs(con):
    r = rarity.stack(con, "destinations", db.window(con, "24h"))
    it = items(r)
    assert it["10.0.2.2:18765"]["count"] == 12 and it["10.0.2.2:18765"]["cells"]["programs"] == 1
    assert it["142.250.0.1:443"]["count"] == 4
    assert {"field": "DestinationIp", "value": "10.0.2.2"} in it["10.0.2.2:18765"]["pivots"]


def test_api_caches_and_filters(store, monkeypatch):
    fx.use_store(monkeypatch, store)
    app = FastAPI()
    app.include_router(rarity.router)
    c = TestClient(app)
    a = c.get("/api/labs/rarity/?kind=programs&window=7d").json()
    b = c.get("/api/labs/rarity/?kind=programs&window=7d").json()
    assert a["cached"] is False and b["cached"] is True and a["rows"] == b["rows"]
    new = c.get("/api/labs/rarity/?kind=programs&window=7d&new_only=true").json()
    assert new["rows"] and all(x["new"] for x in new["rows"]) and new["shown_of"] == a["new"]
    one = c.get("/api/labs/rarity/?kind=programs&window=7d&limit=1").json()
    assert len(one["rows"]) == 1 and one["truncated"] is True and one["items"] == a["items"]
    assert c.get("/api/labs/rarity/?kind=nope").status_code == 404
    assert c.get("/api/labs/rarity/?kind=pairs&focus=1y").status_code == 400
