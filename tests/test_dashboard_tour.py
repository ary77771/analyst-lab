"""The guided tour's words (engine/dashboard/tour.py, GET /api/tour).

The tour explains the screens to someone who is not a specialist. Its words reach a screen, so they keep the
screens' rules: no overclaiming word, the three kinds of statement in Python's own words, nothing that depends
on what the store holds (the same tour on the live page and on a replay), and every step points at a part
that really exists in the page's source."""

import os
import re

from fastapi.testclient import TestClient

from engine.dashboard import tour as T
from engine.dashboard.app import create_app
from engine.dashboard.words import INKS
from tests.test_dashboard_words_scan import BANNED

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "dashboard", "src")


class NoRun:
    log, started, lock = None, None, None

    def status(self):
        return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()


def source():
    text = []
    for folder, _, files in os.walk(SRC):
        for f in files:
            if f.endswith((".tsx", ".ts")) and ".test." not in f:
                with open(os.path.join(folder, f), encoding="utf-8") as fh:
                    text.append(fh.read())
    return "\n".join(text)


def test_the_tour_is_served_and_is_the_same_whatever_the_store_holds(tmp_path):
    a = TestClient(create_app(str(tmp_path / "none.db"), str(tmp_path / "none-a.db"), recordings=str(tmp_path / "r"), runner=NoRun()))
    got = a.get("/api/tour").json()
    assert got == {"words": T.WORDS, "steps": T.STEPS} and len(got["steps"]) >= 10
    from tests.test_report import s1_like
    (tmp_path / "x").mkdir()
    con, alert, _ = s1_like(tmp_path / "x")
    con.close()
    b = TestClient(create_app(str(tmp_path / "x" / "s.db"), str(tmp_path / "none-a.db"), recordings=str(tmp_path / "r"), runner=NoRun(), mode="replay"))
    assert b.get("/api/tour").json() == got                                    # live or replay, full store or empty: the same words


def test_no_tour_word_claims_more_than_the_screens_may():
    texts = list(T.WORDS.values()) + [s["title"] for s in T.STEPS] + [s["text"] for s in T.STEPS]
    for t in texts:
        assert not BANNED.search(t), t
        for word in ("harmless", "benign", "guarantee", "always catches", "never misses", "100%", "malware-free", "clean"):
            assert word not in t.lower(), (word, t)
    # nothing about a particular program, file, address or alert: the tour is about the screens
    for t in texts:
        assert not re.search(r"\.exe\b|\b\d{1,3}(\.\d{1,3}){3}\b|\bS[1-9]\b|powershell", t, re.I), t
    # an alert is called a reason to look, never a verdict
    alerts = next(s for s in T.STEPS if s["title"] == "Alerts")
    assert "a reason to look, not a verdict" in alerts["text"]


def test_the_three_kinds_of_statement_are_explained_in_pythons_own_words():
    step = next(s for s in T.STEPS if s["title"] == "Three kinds of statement")
    for ink, colour, line in (("fact", "green", "solid"), ("hypothesis", "amber", "dashed"), ("gap", "violet", "dotted")):
        assert f"{INKS[ink]['word']} ({colour}, {line}): {INKS[ink]['explain']}" in step["text"]
    assert "never shows a suspicion in the colour of a proof" in step["text"]


def test_every_step_points_at_a_part_that_is_in_the_pages_source_and_at_a_known_screen():
    src = source()
    seen = []
    for s in T.STEPS:
        assert s["screen"] in ("watch", "story", "proof", "labs"), s
        assert set(s) == {"screen", "target", "title", "text"} and 20 <= len(s["text"]) <= 420 and len(s["title"]) <= 40
        for cls in re.findall(r"\.([a-z][a-z0-9-]*)", s["target"]):
            assert re.search(r"[\"' ]" + re.escape(cls) + r"[\"' ]", src), f"no '{cls}' in the page's source ({s['title']})"
        seen.append(s["screen"])
    # the walk goes screen by screen, in the order of the top bar, and never jumps back
    order = [x for i, x in enumerate(seen) if i == 0 or seen[i - 1] != x]
    assert order == ["watch", "story", "proof", "labs"]
    assert len({s["title"] for s in T.STEPS}) == len(T.STEPS)


def test_the_page_places_the_tour_and_writes_none_of_its_words():
    with open(os.path.join(SRC, "ui2", "Tour.tsx"), encoding="utf-8") as f:
        page = f.read()
    code = "\n".join(line.split("//")[0] for line in page.splitlines())
    assert "api.tour()" in code and "step.title" in code and "step.text" in code
    for s in T.STEPS:
        assert s["title"] not in code and s["text"][:40] not in code               # the words live in Python only
    for word in T.WORDS.values():
        assert f'"{word}"' not in code, word
    assert "fetch(" not in code and "api.run" not in code and "warmDo" not in code      # it starts nothing and asks for nothing else
