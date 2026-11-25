"""Wave 3: network and persistence read ?alert=<id> and narrow to that alert's run and its own programs,
with "show all" (only_alert=false) one switch away; an alert that isn't here is said, not hidden."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import network, persistence, _huntdb as db
from tests.labs import hunt_fixtures as fx


class Ctx:
    hosts = frozenset({fx.HOST})

    def __init__(self, store, alerts):
        self.events_db, self.alerts_db, self._alerts = store, None, alerts

    def alert(self, alert_id):
        return next((a for a in self._alerts if a.alert_id == alert_id), None)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from engine import labs
    store = fx.build(tmp_path / "events.db")
    con = db.connect(store)
    try:
        evil_start = con.execute("SELECT dedup_key FROM events WHERE event_id = 1 AND Image = ?", (fx.EVIL,)).fetchone()[0]
    finally:
        con.close()
    a = SimpleNamespace(alert_id="a1", title="Program connected out", host=fx.HOST,
                        time="2026-11-01T09:10:30.123Z", evidence=(evil_start,))           # alerts spell ms with 3 digits
    other = SimpleNamespace(alert_id="a2", title="x", host=fx.LAPTOP, time=fx.ts(fx.T_END), evidence=())
    monkeypatch.setattr(labs, "_current", Ctx(store, [a, other]))
    app = FastAPI()
    app.include_router(network.router)
    app.include_router(persistence.router)
    return TestClient(app)


def test_network_narrows_to_the_alerts_run_and_program(client):
    r = client.get("/api/labs/network/?alert=a1").json()
    assert r["alert"]["narrowed"] is True and r["alert"]["programs"] == [fx.EVIL.lower()]
    assert {p["program"] for p in r["pairs"]} == {fx.EVIL}
    assert r["window"]["name"] == "alert" and r["window"]["since"].startswith("2026-11-01T08:59")   # the machine's start
    every = client.get("/api/labs/network/?alert=a1&only_alert=false").json()
    assert every["alert"]["narrowed"] is False
    assert {p["program"].rsplit("\\", 1)[-1] for p in every["pairs"]} >= {"evil.exe", "chrome.exe", "svchost.exe"}


def test_persistence_shows_what_the_alerts_program_left_behind(client):
    r = client.get("/api/labs/persistence/?alert=a1").json()
    assert [x["cells"]["kind"] for x in r["rows"]] == ["Run key"]                      # written by evil.exe
    assert r["counts"]["added"] == 1 and r["writes_in_window"] == 1
    # critique 3: every number counts the same rows ("0 present" next to "0 -> 55" was the bug)
    assert r["after_total"] == sum(1 for x in r["rows"] if x["status"] != "removed") == 1
    assert r["before_total"] == 0 and r["alert"]["limited"] is True
    assert r["scope_words"]["show_all"] == "show the whole recording"
    every = client.get("/api/labs/persistence/?alert=a1&only_alert=false").json()
    assert {x["cells"]["kind"] for x in every["rows"]} >= {"Run key", "Startup folder", "Scheduled task"}


def test_hunts_limit_to_the_alerts_time_window(client):
    from engine.labs import hunts
    client.app.include_router(hunts.router)
    r = client.get("/api/labs/hunts/run/listeners?alert=a1").json()
    assert r["window"]["name"] == "alert" and r["alert"]["limited"] is True
    assert r["window"]["since"].startswith("2026-11-01T08:59")
    s = client.get("/api/labs/hunts/summary?alert=a1").json()
    assert s["alert"]["limited"] is True and s["window"]["name"] == "alert"
    every = client.get("/api/labs/hunts/run/listeners?alert=a1&only_alert=false&window=7d").json()
    assert every["window"]["name"] == "7d" and every["alert"]["limited"] is False
    gone = client.get("/api/labs/hunts/run/listeners?alert=nope").json()
    assert gone["alert"] == {"id": "nope", "missing": True} and gone["window"]["name"] == "24h"


def test_rarity_and_gaps_limit_to_the_alerts_time_window_too(client):
    from engine.labs import gaps, rarity
    client.app.include_router(rarity.router)
    client.app.include_router(gaps.router)
    for path in ("/api/labs/rarity/?kind=programs&alert=a1", "/api/labs/gaps/?alert=a1"):
        r = client.get(path).json()
        assert r["window"]["name"] == "alert" and r["alert"]["limited"] is True, path
        every = client.get(path + "&only_alert=false&window=7d").json()
        assert every["window"]["name"] == "7d" and every["alert"]["limited"] is False, path
    # the alert's run starts at the machine start: nothing earlier in it, so nothing can be called new
    assert client.get("/api/labs/rarity/?kind=programs&alert=a1").json()["new"] == 0


def test_rarity_highlights_the_alerts_programs_and_how_rare_they_are(client):
    from engine.labs import rarity
    client.app.include_router(rarity.router)
    r = client.get("/api/labs/rarity/?kind=programs&alert=a1&only_alert=false&window=7d").json()
    assert [x["item"] for x in r["alert_items"]] == [fx.EVIL]
    item = r["alert_items"][0]
    assert item["seen"] == 1 and item["of"] == r["items"] and 1 <= item["rank"] <= r["items"]
    assert [x["cells"]["item"] for x in r["rows"] if x["alert"]] == [fx.EVIL]
    pairs = client.get("/api/labs/rarity/?kind=pairs&alert=a1&only_alert=false&window=7d").json()
    assert {x["item"] for x in pairs["alert_items"]} == {"explorer.exe → evil.exe"}
    assert client.get("/api/labs/rarity/?kind=programs&window=7d").json()["alert_items"] == []


def test_an_alert_that_is_not_here_is_said(client):
    for path in ("/api/labs/network/?alert=nope", "/api/labs/persistence/?alert=nope",
                 "/api/labs/network/?alert=a2"):                                         # a2: another machine's
        r = client.get(path).json()
        assert r["alert"] == {"id": path.rsplit("=", 1)[1], "missing": True}
        assert r["window"]["name"] == "24h"                                              # the page's own view instead


def test_no_alert_no_change(client):
    r = client.get("/api/labs/network/?window=24h").json()
    assert r["alert"] is None and r["totals"]["programs"] == 3


def test_run_window_reads_alert_times_spelled_with_milliseconds(tmp_path, monkeypatch):
    fx.use_store(monkeypatch, fx.build(tmp_path / "e.db"))
    con = db.connect(db.events_path())
    try:
        start, end, how = db.run_window(con, fx.HOST, "2026-11-01T08:59:00.000Z")         # the start itself
    finally:
        con.close()
    assert how == "boot" and start == fx.ts(fx.T_END - timedelta(hours=3, minutes=1)) and end is None
