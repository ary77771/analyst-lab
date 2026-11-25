"""Network view + check-in rhythm (engine/labs/network.py) on the hand-made store."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import beacon
from engine.labs import network, _huntdb as db
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


def pair(out, program, dest):
    return next(p for p in out["pairs"] if p["program"] == program and p["dest"] == dest)


def test_who_talked_to_whom(con):
    out = network.view(con, db.window(con, "24h"))
    evil = pair(out, fx.EVIL, "10.0.2.2:18765")
    assert evil["connections"] == 12
    chrome = [p for p in out["pairs"] if p["program"].endswith("chrome.exe")]
    assert sorted(p["dest"] for p in chrome) == [f"142.250.0.{i}:443" for i in range(1, 6)]
    assert out["totals"]["programs"] == 3 and out["totals"]["connections"] == 12 + 15 + 1 + 1
    assert "C:\\Users\\analyst\\Downloads\\python.exe" not in {p["program"] for p in out["pairs"]}


def test_the_30_second_check_in_is_regular_with_the_frozen_beacon_settings(con):
    cfg = beacon.load_config()
    out = network.view(con, db.window(con, "24h"))
    r = pair(out, fx.EVIL, "10.0.2.2:18765")["rhythm"]
    assert r["checkins"] == 12 and r["median_gap"] == 30.0
    assert r["regular"] is (r["regularity"] >= cfg.rhythm_threshold) and r["regular"] is True
    assert out["pairs"][0]["program"] == fx.EVIL                      # regular rhythms first
    # chrome's 3 connections per address are too few to judge: no score, never a made-up one
    assert all(p["rhythm"] is None for p in out["pairs"] if p["program"].endswith("chrome.exe"))
    assert out["totals"]["regular"] == 1


def test_graph_keeps_regular_programs_and_counts_what_it_leaves_out(con):
    g = network.view(con, db.window(con, "24h"))["graph"]
    assert g["programs"][0] == fx.EVIL
    assert any(e["regular"] and e["dest"] == "10.0.2.2:18765" for e in g["edges"])
    assert g["left_out"] == {"programs": 0, "pairs": 0}


def test_rhythm_points_and_histogram(con):
    r = network.rhythm(con, db.window(con, "24h"), fx.EVIL, "10.0.2.2", 18765)
    assert r["checkins"] == 12 and len(r["points"]) == 11
    assert {p["gap"] for p in r["points"]} == {30.0}
    assert r["median_gap"] == 30.0 and r["spread"] == 0 and r["regular"] is True
    assert sum(b["n"] for b in r["histogram"]) == 11


def test_histogram_is_log_spaced_for_wide_gaps():
    h = network._histogram([1, 2, 5, 100, 1000], bins=4)
    assert sum(b["n"] for b in h) == 5 and h[0]["from"] == 1 and round(h[-1]["to"]) == 1000
    assert h[1]["to"] / h[1]["from"] == pytest.approx(h[2]["to"] / h[2]["from"], rel=1e-3)


def test_no_scores_for_very_long_windows(con):
    out = network.view(con, db.window(con, "30d"))
    assert out["scored"] is False and all(p["rhythm"] is None for p in out["pairs"])
    assert any("8 days" in n for n in out["notes"])


def test_api(store, monkeypatch):
    fx.use_store(monkeypatch, store)
    app = FastAPI()
    app.include_router(network.router)
    c = TestClient(app)
    out = c.get("/api/labs/network/?window=24h").json()
    assert out["totals"]["regular"] == 1 and out["window"]["name"] == "24h"
    r = c.get("/api/labs/network/rhythm", params={"image": fx.EVIL, "ip": "10.0.2.2", "port": 18765}).json()
    assert r["checkins"] == 12
    assert c.get("/api/labs/network/?window=10y").status_code == 400
