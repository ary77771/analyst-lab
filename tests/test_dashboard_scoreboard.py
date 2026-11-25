"""The scoreboard's numbers are recomputed here from docs/results/v4/README.md, independently of
engine/dashboard/scoreboard.py's own parser (different code: plain line splitting), so a parser bug
or a hand-typed number would show up as a mismatch."""

import json
import os
import re

from fastapi.testclient import TestClient

from engine.dashboard import scoreboard as sb
from engine.dashboard.app import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "docs", "results", "v4", "README.md")


def readme():
    with open(README, encoding="utf-8") as f:
        return f.read()


def table_rows(section="## 3. ", text=None):
    """The story rows under one heading of a results page (round 4 = "## 3. ", round 5 = "## 5. "): the page
    with round 5 holds two such tables."""
    out, inside = [], False
    for line in (text or readme()).splitlines():
        if line.startswith("## "):
            inside = line.startswith(section)
        cells = [c.strip().strip("*").strip() for c in line.strip().strip("|").split("|")]
        if inside and len(cells) == 6 and cells[0].startswith("B") and cells[0][1:].isdigit():
            out.append(cells)
    return out


def test_round4_numbers_match_the_table():
    rows = table_rows()
    assert len(rows) == 8
    mal = [r for r in rows if r[1] == "malicious"]
    checkable = [r for r in mal if not r[3].startswith("NOT CHECKED")]
    inn = [r for r in rows if r[1] == "innocent"]
    n = sb.parse(readme())["round4"]
    assert n["checkable"] == len(checkable) == 3 and n["not_checked"] == 2
    assert n["v4_detected"] == sum(r[3].startswith("DETECTED") for r in checkable) == 2
    assert n["v3_detected"] == sum(r[2].startswith("DETECTED") for r in checkable) == 0
    assert n["v3_false_alarms"] == sum(r[2].startswith("FALSE ALARM") for r in inn) == 1
    assert n["v4_false_alarms"] == sum(r[3].startswith("FALSE ALARM") for r in inn) == 0
    assert n["story_pass"] == sum(r[5].startswith("PASS") for r in rows) == 2
    assert n["runs_each"] == [3]


def test_art_numbers_match_the_both_row():
    line = next(l for l in readme().splitlines() if l.startswith("| **both**"))
    nums = [int(x.split()[0].strip("*+")) for x in line.strip("|").split("|")[1:6]]
    a = sb.parse(readme())["art"]
    assert [a["tests"], a["q1_v3"], a["q1_v4"], a["q2_v3"], a["q2_v4"]] == nums == [170, 90, 107, 73, 75]
    assert (a["gained"], a["lost"], a["via_citing_rules"]) == (17, 0, 15)
    assert (a["p2_q2_v3"], a["p2_q2_v4"]) == (15, 15)


def test_api_sentences_carry_the_honest_context(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    d = c.get("/api/scoreboard").json()
    text = str(d)
    assert "Without those rules: v3 73, v4 75" in text            # ART next to its honest version
    assert "declared, not recorded" in text
    assert "not in the administrator phase alone (15 = 15)" in text
    assert "Lost on purpose: S3" in d["lost"] and "5 earlier runs" in d["lost"]
    # the promise "scored after that week ends; its result is added here once scored" is kept: the result stands there now
    assert "has been scored: 4 of its 4 budget lines passed" in d["laptop"][1] and "from 6.28 (v3) to 4.22 (v4)" in d["laptop"][1]
    assert "scored after that week ends" not in " ".join(d["laptop"])
    bars = {g["title"][:20]: [(b["value"], b["of"]) for b in g["bars"]] for g in d["groups"]}
    assert list(bars.values()) == [[(0, 3), (2, 3)], [(1, 3), (0, 3)], [(90, 170), (107, 170)]]


def test_a_changed_results_page_changes_the_board():
    text = readme().replace("| B22 | innocent | FALSE ALARM 3 | **CLEAN 3** |", "| B22 | innocent | FALSE ALARM 3 | FALSE ALARM 3 |")
    assert sb.parse(text)["round4"]["v4_false_alarms"] == 1


def test_each_number_says_in_words_which_version_it_is_and_what_its_total_counts():
    from engine.dashboard import scoreboard as S
    with open(S.README, encoding="utf-8") as f:
        n = S.parse(f.read())
    b = S.board(n)
    for g in b["groups"]:
        assert [x["name"] for x in g["bars"]] == [S.OLD, S.NEW] and [x["label"] for x in g["bars"]] == ["v3", "v4"]
        assert str(g["bars"][1]["of"]) in g["of_text"] and g["short"] and g["caveat"]
    assert b["groups"][0]["of_text"] == f"of the {n['round4']['checkable']} new attack stories we could check"
    assert str(n["art"]["q2_v4"]) in b["groups"][2]["caveat"] and str(n["art"]["q2_v3"]) in b["groups"][2]["caveat"]
