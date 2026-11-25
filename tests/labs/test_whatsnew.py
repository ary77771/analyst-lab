"""Lab: What's new tonight (engine/labs/whatsnew.py). Fixture status files in three builders' styles; the
screenshot route serves only names from the shots folder's own listing."""

import json
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import whatsnew as W

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)

SECTION_STYLE = """# night-x status
## 1. Pivot on anything: DONE
- **What:** pick a program, a file or an address and see everything that touched it.
- **Open:** Labs -> "Pivot", `#/labs/pivot?kind=hash&value=<sha256>`.
- **Switch off:** delete `engine/labs/pivot.py`.
- **Shots:** night-x-01-pivot-start.png, night-x-02-pivot-program.png (VM data).
- **Not done:** results capped at 300 events.

## 2. Case board: DONE
- **What:** cases; pin alerts from any lab.
- **Open:** `#/labs/cases?case=<id>`. Other labs pin with `#/labs/cases?pin=...`.
- **Switch off:** delete `engine/labs/cases.py`.
"""
TABLE_STYLE = """# night-y status
| lab | address | what it does |
|---|---|---|
| why | `#/labs/why?alert=<id>` | the rule that fired and the fields that matched it |
| moment | `#/labs/moment?alert=<id>` | everything on the host within a few seconds |

## Checks
- why: 22 tests, sabotage run fails as it should.
## Not done / known limits
- moment: the first open waits for the graph.
- Shots: night-y-01-why-rule.png, `-02-why-matched.png`.
"""
QUESTION_STYLE = """# Fable
## MORNING QUESTION FOR YOUSIF: whose server is running on port 18765?
- Something answered on the test server port that is not ours.
- Please look before the demo.
## 4. Replay in recorded time: DONE
- What it does: plays an alert's story by the recording's own clock.
- How to open it: #/labs/replay?alert=<id>
- How to switch off: delete the folder.
- NOT done: no build yet.
"""
SHOTS = ["night-x-01-pivot-start.png", "night-x-02-pivot-program.png", "night-x-03-case-board.png",
         "night-y-01-why-rule.png", "night-y-02-why-matched.png", "night-y-03-moment.png", "fable-07-replay.png"]


@pytest.fixture
def night(tmp_path):
    d = tmp_path / "docs" / "night"
    (d / "shots").mkdir(parents=True)
    (d / "status-night-x.md").write_text(SECTION_STYLE, encoding="utf-8")
    (d / "status-night-y.md").write_text(TABLE_STYLE, encoding="utf-8")
    (d / "status-fable.md").write_text(QUESTION_STYLE, encoding="utf-8")
    (d / "notes.md").write_text("not a status file #/labs/pivot", encoding="utf-8")
    for s in SHOTS:
        (d / "shots" / s).write_bytes(b"\x89PNG\r\n\x1a\nfixture")
    (d / "shots" / "evil name.png").write_bytes(b"x")
    return d


def test_status_files_and_sections(night, monkeypatch):
    monkeypatch.setattr(W, "night_dirs", lambda rec=None: [str(night)])
    files = W.status_files()
    assert sorted(files) == ["status-fable.md", "status-night-x.md", "status-night-y.md"]
    heads = [h for h, _ in W.sections(SECTION_STYLE)]
    assert heads == ["night-x status", "1. Pivot on anything: DONE", "2. Case board: DONE"]


def test_facts_come_from_the_labs_own_section(night, monkeypatch):
    monkeypatch.setattr(W, "night_dirs", lambda rec=None: [str(night)])
    files, shots = W.status_files(), W.shot_list()
    p = W.facts_for("pivot", files, shots)
    assert p["source"] == "status-night-x.md" and p["heading"] == "1. Pivot on anything: DONE"
    assert p["what"] == "pick a program, a file or an address and see everything that touched it."
    assert p["off"] == ["delete `engine/labs/pivot.py`."]                 # the card's own label is not repeated
    assert p["not_done"] == ["results capped at 300 events."]
    assert p["shots"] == ["night-x-01-pivot-start.png", "night-x-02-pivot-program.png"]
    c = W.facts_for("cases", files, shots)                     # its section names only itself: its own
    assert c["heading"] == "2. Case board: DONE" and c["what"] == "cases; pin alerts from any lab."


def test_table_rows_and_the_builders_general_sections(night, monkeypatch):
    monkeypatch.setattr(W, "night_dirs", lambda rec=None: [str(night)])
    files, shots = W.status_files(), W.shot_list()
    why = W.facts_for("why", files, shots)
    assert why["what"] == "the rule that fired and the fields that matched it"
    assert why["checks"] == ["why: 22 tests, sabotage run fails as it should."]
    assert why["shots"] == ["night-y-01-why-rule.png", "night-y-02-why-matched.png"]    # by the lab id in the name
    mo = W.facts_for("moment", files, shots)
    assert mo["not_done"] == ["moment: the first open waits for the graph."] and mo["shots"] == ["night-y-03-moment.png"]
    rep = W.facts_for("replay", files, shots)
    assert rep["what"] == "plays an alert's story by the recording's own clock." and rep["not_done"] == ["no build yet."]
    assert W.facts_for("nothing-here", files, shots) is None


def test_questions_for_yousif_are_found(night, monkeypatch):
    monkeypatch.setattr(W, "night_dirs", lambda rec=None: [str(night)])
    q = W.questions(W.status_files())
    assert len(q) == 1 and q[0]["source"] == "status-fable.md" and "port 18765" in q[0]["heading"]
    assert q[0]["lines"][0] == "Something answered on the test server port that is not ours."
    assert W.paragraphs(["**In one sentence:** the server", "is not ours.", "", "Why: nobody", "checked."]) == \
        ["In one sentence: the server is not ours.", "Why: nobody checked."]


def test_routes_list_labs_and_serve_only_listed_shots(night, monkeypatch, tmp_path):
    from engine import labs
    monkeypatch.setattr(W, "night_dirs", lambda rec=None: [str(night)])
    labs.configure(labs.Context(str(tmp_path / "e.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    app = FastAPI()
    app.include_router(W.router)
    c = TestClient(app)
    monkeypatch.setattr(W, "page_ids", lambda: {"replay", "pivot"})            # a page with no back end of its own
    body = c.get("/api/labs/whatsnew").json()
    assert body["labs"]["replay"]["source"] == "status-fable.md"
    assert body["labs"]["pivot"]["source"] == "status-night-x.md" and "whatsnew" not in body["labs"]
    assert body["questions"] and body["status_files"] == ["status-fable.md", "status-night-x.md", "status-night-y.md"]
    assert {"lab": "pivot", "source": "status-night-x.md", "line": "results capped at 300 events."} in body["not_done"]
    r = c.get("/api/labs/whatsnew/shot/night-x-01-pivot-start.png")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content.startswith(b"\x89PNG")
    for bad in ("evil%20name.png", "..%5Cstatus-fable.md", "status-fable.md", "nope.png", "..%2F..%2Fx.png"):
        assert c.get(f"/api/labs/whatsnew/shot/{bad}").status_code == 404, bad


def test_the_real_status_files_give_every_merged_lab_a_card():
    """On this machine's real docs/night: the night's labs are found, each with a sentence (when present)."""
    files = W.status_files()
    if len(files) < 3:
        pytest.skip("the builders' status files are not here")
    shots = W.shot_list()
    for lab in ("fileinspect", "yara", "lolbas", "secondopinion", "storydiff", "receipts"):
        f = W.facts_for(lab, files, shots)
        assert f and f["source"] == "status-night-tools.md" and f["what"], lab


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(W.WORDS)), BANNED.search(json.dumps(W.WORDS))
