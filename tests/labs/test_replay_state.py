"""The replay says when its store is whole (engine/labs/_replay.py, GET /api/labs/state): the Labs shell
draws no lab before that, so no lab can say "isn't in this recording" about a half-loaded replay."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

from engine import labs
from engine.dashboard.app import create_app
from engine.labs import _replay

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools"))
import demo_replay  # noqa: E402
from tests.test_demo_replay import recordings  # noqa: E402,F401  (a small made-up recording of an S1 run)


@pytest.fixture(autouse=True)
def no_replay_left_over():
    _replay.reset()
    yield
    _replay.reset()


def test_a_dashboard_that_is_no_replay_says_nothing_is_filling(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    assert _replay.state() is None and c.get("/api/labs/state").json() == {"replay": None}
    _replay.finished()                                         # "finished" without a start means nothing
    assert _replay.state() is None


def test_the_state_follows_the_replay_from_its_start_to_its_last_scoring_pass(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), mode="replay"))
    _replay.started(85)
    assert c.get("/api/labs/state").json() == {"replay": {"total": 85, "done": False}}
    _replay.finished()
    assert c.get("/api/labs/state").json() == {"replay": {"total": 85, "done": True}}
    _replay.started(40)                                        # a replay started again in the same process: filling again
    assert c.get("/api/labs/state").json() == {"replay": {"total": 40, "done": False}}


def test_the_real_replay_says_started_before_its_first_record_and_done_only_after_its_alerts_are_stored(recordings, monkeypatch):
    run, records = demo_replay.prepare(str(recordings), "s1")
    seen = []
    real_replay, real_filling = demo_replay.replay, demo_replay._filling

    def watched_replay(recs, feeder, speed, max_gap):
        seen.append(("while feeding", _replay.state()))
        return real_replay(recs, feeder, speed, max_gap)

    def watched_filling(total):
        if total is None:                                      # the moment it says "done": are the alerts in the store?
            from engine.alerts import AlertStore
            folder = max((recordings / "demo").iterdir())
            s = AlertStore(str(folder / "alerts.db"))
            seen.append(("alerts stored when it says done", len(s.read())))
            s.close()
        return real_filling(total)

    monkeypatch.setattr(demo_replay, "replay", watched_replay)
    monkeypatch.setattr(demo_replay, "_filling", watched_filling)
    assert demo_replay.main(["s1", "--recordings", str(recordings), "--speed", "0", "--no-serve"]) == 0
    assert seen[0] == ("while feeding", {"total": len(records), "done": False})
    assert seen[1][0] == "alerts stored when it says done" and seen[1][1] >= 1
    assert _replay.state() == {"total": len(records), "done": True}


def test_no_lab_may_take_the_shells_own_address(tmp_path, monkeypatch):
    pkg = tmp_path / "state_labs"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    for name in ("state", "fine"):
        (pkg / f"{name}.py").write_text(f"from fastapi import APIRouter\nrouter = APIRouter(prefix='/api/labs/{name}')\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    good, bad = labs.discover("state_labs")
    assert [n for n, _ in good] == ["fine"] and [b["name"] for b in bad] == ["state"] and "rename the file" in bad[0]["problem"]
    for m in ("state_labs", "state_labs.fine"):
        sys.modules.pop(m, None)
