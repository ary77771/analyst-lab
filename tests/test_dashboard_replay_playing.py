"""While a demo replay is still feeding its store, the screens say "No alert yet: the replay is still playing
(14 of 85 records)." instead of "No alerts have been raised in this recording." (2026-11-24: Watch said the
second about a recording of which 14 of 85 records had arrived).

In its own file on purpose: the files the live checks strip on Watch counts must keep their number of tests."""

import re

import pytest
from fastapi.testclient import TestClient

from engine.dashboard import live_status as L
from engine.dashboard import words as W
from engine.dashboard.app import create_app
from engine.labs import _replay

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)


@pytest.fixture(autouse=True)
def no_replay_left_over():
    _replay.reset()
    yield
    _replay.reset()


def dashboard(tmp_path, **kw):
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), mode="replay", **kw))


def test_health_says_how_far_a_playing_replay_is_and_stops_saying_it_when_the_replay_is_done(tmp_path):
    c = dashboard(tmp_path)
    assert "replay_playing" not in c.get("/api/health").json()                # no replay runs here: the key is not there at all
    _replay.started(85)
    h = c.get("/api/health").json()
    assert h["replay_playing"] == {"total": 85, "records": 0, "text": "No alert yet: the replay is still playing (0 of 85 records)."}
    assert h["replay_playing"]["text"] == L.WORDS["replay_playing"].format(n=0, total=85) and not BANNED.search(h["replay_playing"]["text"])
    _replay.finished()
    assert "replay_playing" not in c.get("/api/health").json()                # whole: the old sentence is true again
    assert c.get("/api/words").json()["no_alerts"] == W.WORDS["no_alerts"] == "No alerts have been raised in this recording."


def test_the_number_is_the_stores_own_count(tmp_path, monkeypatch):
    _replay.started(85)
    assert L.replay_playing(14) == {"total": 85, "records": 14, "text": "No alert yet: the replay is still playing (14 of 85 records)."}
    assert L.replay_playing(None)["records"] == 0 and L.replay_playing(85)["records"] == 85     # all records in, the last scoring pass still to come
    _replay.finished()
    assert L.replay_playing(85) is None
    _replay.reset()
    assert L.replay_playing(14) is None


def test_it_does_not_depend_on_labs_being_switched_on(tmp_path):
    c = dashboard(tmp_path, labs=False)                                      # --no-labs, the panic switch
    assert c.get("/api/labs/state").status_code == 404
    _replay.started(85)
    assert c.get("/api/health").json()["replay_playing"]["total"] == 85
    _replay.finished()
    assert "replay_playing" not in c.get("/api/health").json()


def test_its_trouble_never_breaks_the_health_answer(tmp_path, monkeypatch):
    c = dashboard(tmp_path)
    _replay.started(85)
    monkeypatch.setattr(_replay, "state", lambda: 1 / 0)
    h = c.get("/api/health")
    assert h.status_code == 200 and "replay_playing" not in h.json() and "records" in h.json()
