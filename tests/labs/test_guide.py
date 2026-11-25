"""Lab "One alert, start to finish" (engine/labs/guide.py): the walk-through's script and the alert it follows."""

import json
import re
from types import SimpleNamespace

from fastapi.testclient import TestClient

from engine.dashboard.app import create_app
from engine.labs import guide
from tests.labs.test_registry import app_of, stores  # noqa: F401  (the fixture store: one alert of the test machine's kind)

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)


def alert(i, level, time):
    return SimpleNamespace(alert_id=i, level=level, time=time, title=f"alert {i}", host="vm")


def test_the_alert_followed_is_the_highest_level_and_of_those_the_earliest():
    assert guide.pick([]) is None
    rows = [alert("a", "medium", "2026-11-23T10:00:05"), alert("b", "high", "2026-11-23T10:00:09"), alert("c", "high", "2026-11-23T10:00:07"),
            alert("d", "medium", "2026-11-23T10:00:01")]
    assert guide.pick(rows).alert_id == "c" and guide.pick(reversed(rows)).alert_id == "c"       # whatever order the store gives them in
    assert guide.pick(rows[:1] + rows[3:]).alert_id == "d"


def test_the_script_names_each_lab_once_and_says_what_a_lab_is_for_never_what_it_finds(stores, tmp_path):
    c = app_of(stores, tmp_path)
    d = c.get("/api/labs/guide").json()
    assert d["alert"] is None or set(d["alert"]) == {"id", "title", "level", "time", "host"}
    labs_named = [s["lab"] for s in d["steps"]]
    assert labs_named == ["why", "replay", "moment", "prove", "network", "respond", "cases"] and len(set(labs_named)) == len(labs_named)
    for s in d["steps"]:
        assert s["question"] and s["text"].endswith(".") and 40 <= len(s["text"]) <= 170            # one sentence on screen
    text = json.dumps(d["words"]) + json.dumps(d["steps"])
    assert not BANNED.search(text)
    for claim in ("attack", "malicious", "intruder", "innocent", "harmless", "was stolen", "S1", "B18"):   # the script fits any alert
        assert claim.lower() not in text.lower(), claim
    assert set(d["words"]) >= {"title", "intro", "which", "no_alert", "start", "step", "next", "back", "finish", "end", "finished", "left_out", "none_here"}
    assert "{n}" in d["words"]["step"] and "{total}" in d["words"]["step"]


def test_it_follows_the_stores_own_alert_and_says_so_when_there_is_none(stores, tmp_path):
    events, alerts, a = stores
    c = TestClient(create_app(events, alerts, recordings=str(tmp_path / "rec"), labs_hosts=None))
    d = c.get("/api/labs/guide").json()
    assert d["alert"]["id"] == a.alert_id and d["alert"]["title"] == a.title and d["alert"]["level"] == a.level
    # the test machine only, by default: this fixture's alert is another machine's, so there is nothing to follow
    assert TestClient(create_app(events, alerts, recordings=str(tmp_path / "rec"))).get("/api/labs/guide").json()["alert"] is None
    empty = TestClient(create_app(str(tmp_path / "none.db"), str(tmp_path / "none-a.db"), recordings=str(tmp_path / "rec")))
    d = empty.get("/api/labs/guide").json()
    assert d["alert"] is None and d["steps"] and "nothing to follow" in d["words"]["no_alert"]


def test_the_address_can_name_another_alert_and_an_unknown_one_is_said_never_replaced(tmp_path, monkeypatch):
    """Critique of 2026-11-24: on the live store the automatic pick is a start-up alert; "?alert=" names the
    one to follow instead."""
    rows = [alert("a", "medium", "2026-11-23T10:00:05"), alert("b", "high", "2026-11-23T10:00:09"), alert("c", "medium", "2026-11-23T10:00:01")]
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    monkeypatch.setattr(guide.labs, "context", lambda: SimpleNamespace(shown_alerts=lambda: list(rows)))
    auto = c.get("/api/labs/guide").json()
    assert auto["alert"]["id"] == "b" and auto["chosen"] is False and auto["unknown"] is False
    assert [x["id"] for x in auto["others"]] == ["c", "a"]                    # the rest, earliest first, to follow instead
    named = c.get("/api/labs/guide", params={"alert": "c"}).json()
    assert named["alert"]["id"] == "c" and named["chosen"] is True and named["unknown"] is False and [x["id"] for x in named["others"]] == ["a", "b"]
    gone = c.get("/api/labs/guide", params={"alert": "not-in-this-recording"}).json()
    assert gone["alert"] is None and gone["unknown"] is True and gone["chosen"] is False       # never silently the automatic pick
    assert [x["id"] for x in gone["others"]] == ["c", "a", "b"] and "isn't in this recording" in gone["words"]["unknown"]
    many = [alert(f"m{i:02d}", "medium", f"2026-11-23T10:00:{i:02d}") for i in range(30)]
    monkeypatch.setattr(guide.labs, "context", lambda: SimpleNamespace(shown_alerts=lambda: list(many)))
    assert len(c.get("/api/labs/guide").json()["others"]) == guide.MORE
