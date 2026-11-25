"""Reading effort (engine/labs/reading.py): N raw records in the run, M cited, K steps, on the fixture store."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import reading, _huntdb as db
from tests.labs import hunt_fixtures as fx


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    path = fx.build(tmp_path / "events.db")
    fx.use_store(monkeypatch, path)
    return path


def keys(con, where, params=()):
    return [r[0] for r in con.execute(f"SELECT dedup_key FROM events WHERE host = ? AND {where} ORDER BY time", (fx.HOST, *params))]


def content_for(cited, steps=4):
    as_cites = [{"key": k, "event": 1, "record": 1, "time": None, "text": "x"} for k in cited]
    return {"alert": {"citations": as_cites[:1]}, "facts": [{"citations": as_cites[1:]}, {"citations": as_cites[:2]}],
            "hypotheses": [], "gaps": [], "counts": {"steps": steps}, "timeline": [1, 2]}


def times_of(con, cited):
    return {k: t for k, t in con.execute(f"SELECT dedup_key, time FROM events WHERE dedup_key IN ({','.join('?' * len(cited))})", cited)}


def test_n_m_k_for_a_run(store):
    con = db.connect(store)
    try:
        cited = keys(con, "Image = ? AND event_id IN (1, 3)", (fx.EVIL,))[:3]          # evil.exe's start + 2 connections
        c = content_for(cited)
        t = times_of(con, cited)
        for group in [c["alert"]["citations"]] + [f["citations"] for f in c["facts"]]:
            for x in group:
                x["time"] = t[x["key"]]
        alert = SimpleNamespace(host=fx.HOST, time=fx.ts(fx.T_END - __import__("datetime").timedelta(hours=2)))
        out = reading.effort(con, alert, c)
        boot = con.execute("SELECT MIN(time) FROM events WHERE event_id = 4 AND host = ?", (fx.HOST,)).fetchone()[0]
        expected_n = con.execute("SELECT COUNT(*) FROM events WHERE host = ? AND time >= ?", (fx.HOST, boot)).fetchone()[0]
    finally:
        con.close()
    assert out["m"] == 3 and out["k"] == 4 and out["n"] == expected_n and out["m"] <= out["n"]
    assert [x["key"] for x in out["cited"]] == cited                       # each once, in time order
    assert out["window"]["how"] == "boot" and out["window"]["start"] == boot
    assert out["one_in"] == round(expected_n / 3)
    assert "not minutes saved" in out["words"]["honest"]
    assert fx.LAPTOP not in str(out)                                        # the other machine is never counted


def test_a_cited_record_before_the_run_stretches_the_window_and_one_from_another_store_is_said(store):
    con = db.connect(store)
    try:
        old = keys(con, "Image LIKE '%notepad.exe'")                        # three days before the run's start
        c = content_for(old + ["other-store|key|1|2026-11-01T00:00:00Z"])
        c["alert"]["citations"][0]["time"] = times_of(con, old)[old[0]]
        out = reading.effort(con, SimpleNamespace(host=fx.HOST, time=fx.ts(fx.T_END)), c)
        whole = con.execute("SELECT COUNT(*) FROM events WHERE host = ?", (fx.HOST,)).fetchone()[0]
    finally:
        con.close()
    # the run (boot to end) + the one cited record from three days before, counted alone (here: the whole machine)
    assert out["m"] == 1 and out["n"] == whole
    assert out["window"]["how"] == "boot"
    assert any("counted one by one" in n for n in out["notes"]) and any("not in this event store" in n for n in out["notes"])


def test_a_cited_record_far_outside_the_run_does_not_inflate_n(store):
    con = db.connect(store)
    try:
        old = keys(con, "Image LIKE '%notepad.exe'")
        boot = con.execute("SELECT MIN(time) FROM events WHERE event_id = 4 AND host = ?", (fx.HOST,)).fetchone()[0]
        in_run = con.execute("SELECT COUNT(*) FROM events WHERE host = ? AND time >= ?", (fx.HOST, boot)).fetchone()[0]
        out = reading.effort(con, SimpleNamespace(host=fx.HOST, time=fx.ts(fx.T_END)), content_for(old))
    finally:
        con.close()
    assert out["n"] == in_run + 1 and out["window"]["start"] == boot


def test_citation_times_are_spelled_like_the_store():
    c = reading.citations({"alert": {"citations": [{"key": "k", "time": "2026-10-31T22:47:43.760000+00:00"}]}})
    assert c[0]["time"] == "2026-10-31T22:47:43.7600000Z"


class FakeCtx:
    hosts = frozenset({fx.HOST})

    def __init__(self, store, alerts, content):
        self.events_db, self.alerts_db, self._alerts, self._content = store, None, alerts, content

    def shown_alerts(self):
        return self._alerts

    def alert(self, alert_id):
        return next((a for a in self._alerts if a.alert_id == alert_id), None)

    def report(self, alert):
        return self._content


def test_api(store, monkeypatch):
    from engine import labs
    con = db.connect(store)
    try:
        cited = keys(con, "Image = ?", (fx.EVIL,))[:2]
    finally:
        con.close()
    a = SimpleNamespace(alert_id="a1", title="Regular check-in rhythm", time=fx.ts(fx.T_END), level="medium", host=fx.HOST)
    other = SimpleNamespace(alert_id="a2", title="x", time=fx.ts(fx.T_END), level="medium", host=fx.LAPTOP)
    monkeypatch.setattr(labs, "_current", FakeCtx(store, [a, other], content_for(cited)))
    app = FastAPI()
    app.include_router(reading.router)
    c = TestClient(app)
    listing = c.get("/api/labs/reading/").json()
    assert [x["id"] for x in listing["alerts"]] == ["a1"]                    # the other machine's alert is not offered
    r = c.get("/api/labs/reading/a1").json()
    assert r["m"] == 2 and r["k"] == 4 and r["n"] >= r["m"] and r["alert"]["id"] == "a1"
    assert c.get("/api/labs/reading/a2").status_code == 404
    assert c.get("/api/labs/reading/nope").status_code == 404
