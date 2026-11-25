"""tools/demo_replay.py (demo backup): a recorded run replayed through the live loop gives exactly the
alerts batch scoring gives on the same window (the replay may not change what the demo shows), the
feed holds the window's records, a missing run is a plain message, and the served dashboard answers."""

import json
import os
import socket
import sys
import urllib.request

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import demo_replay  # noqa: E402
from engine import detect, score  # noqa: E402
from engine.alerts import AlertStore  # noqa: E402
from engine.store import EventStore  # noqa: E402
from tests.test_check_graph_scenario import good_run, iso  # noqa: E402


@pytest.fixture
def recordings(tmp_path):
    for label, rows in (("vm", good_run()), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0,
                                                         "time": iso(0), "start": iso(0), "end": iso(20)}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return tmp_path


def batch_alert_ids(recordings, tmp_path):
    """Batch scoring (engine/score.py's pass) over the same window, for comparison."""
    run, records = demo_replay.prepare(str(recordings), "s1")
    db = str(tmp_path / "batch.db")
    s = EventStore(db)
    s.insert(records)
    s.close()
    con = detect.open_store(db)
    try:
        alerts = score.score(con, score.load_rules(), score.load_baseline(score.baseline_files()))
    finally:
        con.close()
    return {a.alert_id for a in alerts}, len(records)


def demo_folder(recordings):
    (folder,) = (recordings / "demo").iterdir()
    return folder


def test_replay_gives_the_same_alerts_as_batch_scoring(recordings, tmp_path, capsys):
    assert demo_replay.main(["s1", "--recordings", str(recordings), "--speed", "0", "--every", "0.2", "--no-serve"]) == 0
    folder = demo_folder(recordings)
    s = AlertStore(str(folder / "alerts.db"))
    got = {a.alert_id for a in s.read()}
    s.close()
    want, n = batch_alert_ids(recordings, tmp_path)
    assert got == want and got                         # the S1 rule fires on the good run
    with open(folder / demo_replay.FEED / "replay.jsonl", encoding="utf-8") as f:
        assert sum(1 for _ in f) == n
    assert f"Replay done: {n} records" in capsys.readouterr().out


def test_paced_replay_gives_the_same_alerts(recordings, tmp_path):
    """At a speed the loop scores several times while records arrive (alerts may appear early)."""
    assert demo_replay.main(["s1", "--recordings", str(recordings), "--speed", "40", "--max-gap", "1",
                             "--every", "0.1", "--no-serve"]) == 0
    s = AlertStore(str(demo_folder(recordings) / "alerts.db"))
    got = {a.alert_id for a in s.read()}
    s.close()
    assert got == batch_alert_ids(recordings, tmp_path)[0]


def test_no_such_run_is_a_plain_message(recordings):
    with pytest.raises(SystemExit, match="No recorded run of S2"):
        demo_replay.main(["s2", "--recordings", str(recordings), "--no-serve"])
    with pytest.raises(SystemExit, match="with run id nope"):
        demo_replay.main(["s1", "--run-id", "nope", "--recordings", str(recordings), "--no-serve"])


def test_the_dashboard_serves_the_replayed_store(recordings):
    run, records = demo_replay.prepare(str(recordings), "s1")
    folder, store, alerts = demo_replay.make_folder(str(recordings), run)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = demo_replay.serve(store, alerts, port)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/config", timeout=10) as r:
            assert r.status == 200 and "levels" in json.loads(r.read())
    finally:
        server.should_exit = True
