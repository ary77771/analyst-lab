"""critique-4, final walk: the checklist said "67 recorded events from 20 programs" and the moment page "76 events ·
20 programs" for the same ±30 s. One rule now (engine/labs/moment.py counts_of): the two pages say the same numbers."""

import os
import re
import tempfile

import pytest
from fastapi.testclient import TestClient

from engine.labs import moment

S1 = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "recordings", "demo")
MAIN_S1 = os.path.join(S1, "20261030-195534-dac0-20261124-171427")


def numbers(client, alert_id):
    """(records, programs) as the checklist's question says them, and as the moment page counts them hidden."""
    q = next(q for q in client.get(f"/api/labs/checklist/{alert_id}").json()["questions"] if q["key"] == "around")
    m = re.match(r"(\d+) records? from (\d+) programs?", q["lines"][0]["text"])
    assert m, q["lines"][0]["text"]
    c = client.get(f"/api/labs/moment?alert={alert_id}&seconds=30").json()["counts"]
    return (int(m.group(1)), int(m.group(2))), (c["records"], c["programs"]), q["lines"][0]["text"]


def test_the_rule_counts_machinery_apart_and_matches_what_is_drawn():
    lanes = [{"id": "a", "own_tool": False}, {"id": "m", "own_tool": True}]
    events = [{"lane": "a"}, {"lane": "a"}, {"lane": "m"}]
    assert moment.counts_of(lanes, events) == {"records": 2, "programs": 1, "machinery_records": 1, "machinery_programs": 1}


def test_checklist_and_moment_agree_on_an_s1_like_story(tmp_path):
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None))
    said, counted, _ = numbers(c, a.alert_id)
    assert said == counted and said[0] > 0


@pytest.mark.skipif(not os.path.exists(os.path.join(MAIN_S1, "events.db")), reason="the S1 replay store is not on this machine")
def test_checklist_and_moment_agree_on_the_s1_replay():
    from engine.dashboard.app import create_app
    c = TestClient(create_app(os.path.join(MAIN_S1, "events.db"), os.path.join(MAIN_S1, "alerts.db"), recordings=tempfile.mkdtemp()))
    alert_id = c.get("/api/labs/checklist").json()["groups"][0]["id"]
    said, counted, line = numbers(c, alert_id)
    assert said == counted, line
