"""Everyday names for test runs (engine/labs/_names.py): read from each scenario's own file, never typed."""

import json
import os

import yaml
from fastapi.testclient import TestClient

from engine.dashboard.app import create_app
from engine.labs import _names

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_every_name_is_the_title_its_scenarios_own_file_gives():
    names = _names.run_names()
    for sid in sorted(os.listdir(os.path.join(ROOT, "scenarios"))):
        path = os.path.join(ROOT, "scenarios", sid, "ground_truth.yaml")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                assert names[sid] == yaml.safe_load(f)["title"], sid
    assert names["s1"] == "Download and run" and "s4" in names and "s5" in names
    with open(os.path.join(ROOT, "docs", "results", "v4", "twin.json"), encoding="utf-8") as f:
        for side in json.load(f)["sides"]:
            assert names[side["scenario"].lower()] == side["title"]
    assert all(k == k.lower() and v and len(v) <= _names.MAX and "\n" not in v for k, v in names.items())


def test_a_run_without_a_title_has_no_name_and_broken_files_are_skipped(tmp_path):
    for sid, text in (("s1", "title: Download and run\n"), ("s9", "expected: []\n"), ("s8", "title: [not, a, line]\n"), ("s7", ": : not yaml : ["),
                      ("weird name", "title: never shown\n")):
        (tmp_path / "scenarios" / sid).mkdir(parents=True)
        (tmp_path / "scenarios" / sid / "ground_truth.yaml").write_text(text, encoding="utf-8")
    blind = tmp_path / "docs" / "results" / "blind"
    blind.mkdir(parents=True)
    (blind / "b1.yaml").write_text("title:   Lookalike   copy\n", encoding="utf-8")
    (blind / "b1.original.yaml").write_text("title: the first draft\n", encoding="utf-8")
    (blind / "s1.yaml").write_text("title: another name for s1\n", encoding="utf-8")
    (tmp_path / "docs" / "results" / "v4").mkdir(parents=True)
    (tmp_path / "docs" / "results" / "v4" / "twin.json").write_text("{ not json", encoding="utf-8")
    assert _names.run_names(str(tmp_path)) == {"s1": "Download and run", "b1": "Lookalike copy"}
    assert _names.run_names(str(tmp_path / "nothing-here")) == {}


def test_the_labs_listing_carries_the_names_and_no_rehearsed_endpoint_changed(tmp_path, monkeypatch):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    listing = c.get("/api/labs").json()
    assert listing["run_names"] == _names.run_names() and listing["enabled"] is True
    assert "run_names" not in c.get("/api/words").json()
    monkeypatch.setattr(_names, "run_names", lambda *a: 1 / 0)             # its trouble is never the listing's
    c2 = TestClient(create_app(str(tmp_path / "s2.db"), str(tmp_path / "a2.db"), recordings=str(tmp_path / "rec")))
    assert c2.get("/api/labs").json()["run_names"] == {}
