"""Attack coverage: the map's numbers equal the committed results page (README section 1)."""

import json
import os

from fastapi.testclient import TestClient

from engine.dashboard import coverage as CV
from engine.dashboard import scoreboard as SB
from engine.dashboard.app import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_map_numbers_equal_the_results_page(tmp_path):
    with open(os.path.join(ROOT, "docs", "results", "v4", "README.md"), encoding="utf-8") as f:
        art = SB.parse(f.read())["art"]
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    d = c.get("/api/coverage").json()
    assert (d["total"], d["caught"], d["caught_strict"], d["declared"]) == (art["tests"], art["q1_v4"], art["q2_v4"], art["gained"])
    assert sum(len(g["tests"]) for g in d["groups"]) == d["total"]


def test_every_new_catch_is_a_declared_one_and_misses_stay_visible():
    with open(CV.MAP, encoding="utf-8") as f:
        tests = json.load(f)["tests"]
    assert sum(t["result"] == "missed" for t in tests) == len(tests) - sum(t["result"] != "missed" for t in tests) > 0
    assert all(t["result"] in ("recorded", "declared", "missed") for t in tests)
    assert not any(t["result"] == "missed" and t["without_citing_rules"] for t in tests)   # stricter can't catch more


def test_a_changed_tile_changes_the_count(tmp_path, monkeypatch):
    with open(CV.MAP, encoding="utf-8") as f:
        data = json.load(f)
    data["tests"][0]["result"] = "missed" if data["tests"][0]["result"] != "missed" else "recorded"
    v = CV.view(data)
    assert v["caught"] != CV.view(json.load(open(CV.MAP, encoding="utf-8")))["caught"]
