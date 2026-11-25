"""Demo mode: the LIVE/REPLAY badge, a replay starts no VM run, and the projector guard."""

import sqlite3

from fastapi.testclient import TestClient

from engine.dashboard import demo_mode as D
from engine.dashboard.app import create_app


def app(tmp_path, mode, detail=None):
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"),
                                 mode=mode, mode_detail=detail))


def test_replay_badge_and_no_vm_run(tmp_path):
    c = app(tmp_path, "replay", "S1, recorded 2026-10-30")
    m = c.get("/api/mode").json()
    assert m == {"mode": "replay", "badge": D.WORDS["replay"], "detail": "S1, recorded 2026-10-30", "can_run": False}
    (tmp_path / "scen").mkdir()
    assert c.post("/api/scenarios/s1/run").status_code == 409


def test_live_and_plain_modes(tmp_path):
    assert app(tmp_path, "live").get("/api/mode").json()["badge"] == D.WORDS["live"]
    assert app(tmp_path, None).get("/api/mode").json()["mode"] is None


def store(path, hosts):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT)")
    con.executemany("INSERT INTO events (host) VALUES (?)", [(h,) for h in hosts])
    con.commit()
    con.close()


def test_projector_guard_refuses_any_non_vm_machine(tmp_path):
    store(str(tmp_path / "vm.db"), ["analystlab-vm", "analystlab-vm"])
    store(str(tmp_path / "mixed.db"), ["analystlab-vm", "some-laptop"])
    assert D.projector_problems(str(tmp_path / "vm.db")) == []
    assert len(D.projector_problems(str(tmp_path / "mixed.db"))) == 1
    assert "some-laptop" not in D.projector_problems(str(tmp_path / "mixed.db"))[0]     # never prints the name


def test_each_demo_dashboard_is_told_only_where_the_other_one_is(tmp_path):
    """The replay page reads the live dashboard's health for its small notice and links back to it; the live
    page links to the replay. A rehearsal or a plain development server is told nothing."""
    for mode, expected in (("replay", {"live_url": D.LIVE_DASHBOARD, "replay_url": None}),
                           ("live", {"live_url": None, "replay_url": D.REPLAY_DASHBOARD}),
                           ("rehearsal", {"live_url": None, "replay_url": None}), (None, {"live_url": None, "replay_url": None})):
        c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), mode=mode))
        assert c.get("/api/peer").json() == expected, mode

