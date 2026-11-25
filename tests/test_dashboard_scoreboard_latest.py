"""The newest results on the Proof screen (the scores panel's second view, 2026-11-24): every number is
recomputed here from the result files by different code (plain line splitting) than
engine/dashboard/scoreboard.py's own parser.

In its own file on purpose: tests/test_dashboard_scoreboard.py is one of the files the live checks strip on
the Watch screen counts (engine/dashboard/checks.py FILES), and the rehearsed count must not move."""

import json
import os
import re

from fastapi.testclient import TestClient

from engine.dashboard import scoreboard as sb
from engine.dashboard.app import create_app
from tests.test_dashboard_scoreboard import ROOT, readme, table_rows

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)


def readme5():
    """The results page as of v4 a832a83 (with round 5), kept under its own name: README.md is not replaced."""
    with open(sb.README_R5, encoding="utf-8") as f:
        return f.read()


def test_the_page_with_round5_is_the_old_page_plus_one_section_and_the_old_page_is_untouched():
    """A dashboard started earlier reads README.md on every request with the code it has in memory, and that
    older code took story rows from the WHOLE page: on 2026-11-24 replacing the file made the running demo
    show 5 of 7. So the old page stays exactly as it was, and round 5 is read from its own file."""
    old, new = readme(), readme5()
    assert "## 5. " not in old and new.count("## 5. ") == 1
    assert new.replace("\r\n", "\n").startswith(old.replace("\r\n", "\n").rstrip("\n"))
    rows = [l for l in old.splitlines() if re.match(r"\| B\d+ \|", l)]
    assert len(rows) == 8                                                    # what the older code counts over the whole page
    assert sb.parse(old)["round4"] == sb.parse(new)["round4"]                # and round 4 is the same from either


def week_file(version):
    with open(sb.WEEKS[version], encoding="utf-8") as f:
        return f.read()


def bold_numbers(line):
    """The numbers a result file prints in bold on one line: "**7,866** = **95.21 per active hour**" -> [7866.0, 95.21]."""
    return [float(part.split()[0].replace(",", "")) for part in line.split("**")[1::2]]


def test_round5_numbers_match_the_table():
    rows = table_rows("## 5. ", readme5())
    assert len(rows) == 8 and len(table_rows()) == 8 and {r[0] for r in rows}.isdisjoint({r[0] for r in table_rows()})
    mal = [r for r in rows if r[1] == "malicious"]
    inn = [r for r in rows if r[1] == "innocent"]
    n = sb.numbers()["round5"]
    assert n == sb.parse(readme5())["round5"]
    assert (n["scenarios"], n["malicious"], n["innocent"], n["not_checked"]) == (8, len(mal), len(inn), 0) == (8, 4, 4, 0)
    assert n["v3_detected"] == sum(r[2].startswith("DETECTED") for r in mal) == 2
    assert n["v4_detected"] == sum(r[3].startswith("DETECTED") for r in mal) == 3
    assert n["v3_false_alarms"] == sum(r[2].startswith("FALSE ALARM") for r in inn) == 2
    assert n["v4_false_alarms"] == sum(r[3].startswith("FALSE ALARM") for r in inn) == 2
    assert n["missed_by_both"] == [r[0] for r in mal if r[2].startswith("MISSED") and r[3].startswith("MISSED")] == ["B26"]
    # better / same / worse, counted here by the words of each row and nothing else
    good = {"malicious": "DETECTED", "innocent": "CLEAN"}
    step = [(r[0], r[2].startswith(good[r[1]]), r[3].startswith(good[r[1]])) for r in rows]
    assert sorted(n["better"]) == sorted(i for i, a, b in step if b and not a) == ["B29", "B31"]
    assert n["worse"] == [i for i, a, b in step if a and not b] == ["B28"]
    assert n["same"] == sum(a == b for _, a, b in step) == 5
    assert n["story_pass"] == sum(r[5].startswith("PASS") for r in rows) == 1 and n["runs_each"] == [3]
    # "the same rule won B18 and B20 the round before": only because round 4's own table shows v4 gaining exactly those
    assert n["same_rule_won"] == ["B18", "B20"]
    assert {r[0] for r in table_rows() if r[1] == "malicious" and r[3].startswith("DETECTED") and not r[2].startswith("DETECTED")} == {"B18", "B20"}


def test_the_laptop_week_numbers_match_their_result_files():
    n = sb.numbers()
    for version, raised, rate, hours, days in (("v2", 7866, 95.21, 82.6, ("11-14", "11-20")), ("v3", 475, 6.28, 75.6, ("11-15", "11-21")),
                                               ("v4", 319, 4.22, 75.6, ("11-15", "11-21"))):
        lines = week_file(version).splitlines()
        raised_line = next(l for l in lines if l.startswith("- RAISED alerts"))
        assert bold_numbers(raised_line) == [raised, rate]
        assert bold_numbers(next(l for l in lines if l.startswith("- Active hours"))) == [hours]
        assert f"(2026-{days[0]} .. 2026-{days[1]}," in lines[2]
        w = n["weeks"][version]
        assert (w["raised"], w["rate"], w["active_hours"], (w["from"], w["to"])) == (raised, rate, hours, days), version
        assert abs(raised / hours - rate) < 0.06                               # the file's own rate is its own two numbers divided
    # the one rule behind most of v2's number, and the same rule in v3 and v4: from each file's rule table
    rule = "A program that never listened here opened a listening port"
    counts = {}
    for version in sb.WEEKS:
        row = next(l for l in week_file(version).splitlines() if l.startswith("|") and f"| {rule} |" in l)
        counts[version] = int(row.split("|")[4].strip().replace(",", ""))
        assert n["weeks"][version]["rules"][rule] == counts[version]
    assert counts == {"v2": 7337, "v3": 160, "v4": 4} and next(iter(n["weeks"]["v2"]["rules"])) == rule
    with open(sb.BRAKE, encoding="utf-8") as f:
        brake = f.read()
    assert brake.count("PASS") == 4 and "FAIL" not in brake
    assert n["brake"] == {"lines": 4, "passed": 4, "from": "11-15", "to": "11-21"}


def test_the_newest_view_says_the_numbers_and_shows_where_v4_got_worse(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    d = c.get("/api/scoreboard").json()
    new = d["latest"]
    week, attacks, innocent = new["groups"]
    assert [(b["label"], b["text"]) for b in week["bars"]] == [("v2", "95.2"), ("v3", "6.3"), ("v4", "4.2")]
    assert [b["name"] for b in week["bars"]] == ["Version 2", "Version 3", "Version 4"]
    # version 2's week is not the others' week: said on the page itself, beside the numbers
    assert week["caveat"] == "Version 2's week began on 11-14, the others' on 11-15. 7,337 of version 2's 7,866 alerts came from one rule."
    assert "lower is better" in week["of_text"]
    notes = " ".join(week["notes"])
    assert "11-14 to 11-20" in notes and "the same week 11-15 to 11-21" in notes and "2 is an overlapping one" in notes      # not the same week for v2: said
    assert "The same rule raised 160 in version 3 and 4 in version 4." in notes and "4 of its 4 lines passed" in notes
    assert [(b["value"], b["of"]) for b in attacks["bars"]] == [(2, 4), (3, 4)] and attacks["caveat"] == "1 was missed by both versions."
    assert [(b["value"], b["of"]) for b in innocent["bars"]] == [(2, 4), (2, 4)]
    # the honest regression stands ON the page (the caveat and the summary), not only in the notes
    assert innocent["caveat"] == "v4 cleared B31 but wrongly flagged B28."
    assert new["summary"] == "Of these 8: v4 better on 2, the same on 5, worse on 1."
    assert new["worse"].startswith("Where v4 got worse: B28.") and "found the attack stories B18 and B20 in the round before" in new["worse"]
    assert new["worse"] in innocent["notes"] and "where it got worse, not only where it got better" in new["intro"]
    assert "1 of the 8 stories, the same for v3 and v4" in " ".join(attacks["notes"])
    for g in new["groups"]:
        assert g["short"] and g["caveat"] and g["of_text"] and g["unit"]
    text = json.dumps(new)
    assert not BANNED.search(text)
    # nothing of the laptop's own use: no path, no program file, no address (the result files' other cells are never read)
    assert "\\\\" not in text and not re.search(r"\.(exe|dll|ps1|com|net|org)\b", text) and not re.search(r"\d+\.\d+\.\d+\.\d+", text)
    assert [s.split(" ")[0] for s in new["sources"]] == [os.path.relpath(p, ROOT).replace(os.sep, "/") for p in [sb.README_R5, *sb.WEEKS.values(), sb.BRAKE]]
    # the rehearsed view is what it was: the same three groups with the same numbers
    assert [[(b["value"], b["of"]) for b in g["bars"]] for g in d["groups"]] == [[(0, 3), (2, 3)], [(1, 3), (0, 3)], [(90, 170), (107, 170)]]


def test_a_changed_result_file_changes_the_newest_view():
    n = sb.numbers()
    text = readme5().replace("| B28 | innocent | CLEAN 3 | **FALSE ALARM 3** |", "| B28 | innocent | CLEAN 3 | CLEAN 3 |")
    assert text != readme5()
    m = dict(n, round5=sb.parse(text)["round5"])
    new = sb.latest(m)
    assert m["round5"]["worse"] == [] and new["worse"] == "" and new["summary"] == "Of these 8: v4 better on 2, the same on 6, worse on 0."
    assert new["groups"][2]["caveat"] == "Lower is better. v4 cleared B31." and new["groups"][2]["bars"][1]["value"] == 1
    week = sb.parse_week(week_file("v4").replace("**319** = **4.22 per active hour**", "**400** = **5.29 per active hour**"))
    assert sb.latest(dict(n, weeks=dict(n["weeks"], v4=week)))["groups"][0]["bars"][2]["text"] == "5.3"
    same = sb.parse_week(week_file("v2").replace("(2026-11-14 .. 2026-11-20,", "(2026-11-15 .. 2026-11-21,"))     # were it the same week, nothing is said about weeks
    assert sb.latest(dict(n, weeks=dict(n["weeks"], v2=same)))["groups"][0]["caveat"] == "7,337 of version 2's 7,866 alerts came from one rule."
    # the claim about the earlier round is dropped when the page no longer makes it, or round 4's table does not bear it out
    assert sb.parse(readme5().replace("WON B18 and B20 in round 4", "won two"))["round5"]["same_rule_won"] == []
    gone = readme5().replace("| B18 | malicious | MISSED 3 | **DETECTED 3** |", "| B18 | malicious | DETECTED 3 | DETECTED 3 |")
    assert sb.parse(gone)["round5"]["same_rule_won"] == [] and "round before" not in sb.latest(dict(n, round5=sb.parse(gone)["round5"]))["worse"]


def test_without_its_sources_the_newest_view_is_left_out_and_nothing_is_guessed(tmp_path, monkeypatch):
    old_page = readme()                                                     # the results page without round 5
    assert sb.parse(old_page)["round5"] is None
    b = sb.board(sb.parse(old_page))
    assert "latest" not in b and "scored after that week ends" in b["laptop"][1]
    monkeypatch.setitem(sb.WEEKS, "v3", str(tmp_path / "missing.md"))       # one week's file is not there
    n = sb.numbers()
    assert n["round5"] is None and n["weeks"] is None and n["brake"] is None and "latest" not in sb.board(n)
    monkeypatch.undo()
    monkeypatch.setattr(sb, "README_R5", str(tmp_path / "missing.md"))      # ... or the page with round 5
    assert sb.numbers()["round5"] is None and "latest" not in sb.board(sb.numbers())
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    d = c.get("/api/scoreboard").json()
    assert "latest" not in d and len(d["groups"]) == 3


def test_any_trouble_with_the_newest_results_leaves_the_first_view_standing(tmp_path, monkeypatch):
    """Review of 2026-11-24: only OSError and ValueError were caught, so another kind of error in the newest
    view would have taken the rehearsed first view down with it."""
    first = [[(b["value"], b["of"]) for b in g["bars"]] for g in sb.board(sb.parse(readme()))["groups"]]
    for what in ("latest", "parse_week", "parse_brake", "_round5"):
        monkeypatch.setattr(sb, what, lambda *a, **k: {}["a key that is not there"])
        c = TestClient(create_app(str(tmp_path / f"{what}.db"), str(tmp_path / f"{what}-a.db"), recordings=str(tmp_path / "rec")))
        r = c.get("/api/scoreboard")
        d = r.json()
        assert r.status_code == 200 and "latest" not in d, what
        assert [[(b["value"], b["of"]) for b in g["bars"]] for g in d["groups"]] == first == [[(0, 3), (2, 3)], [(1, 3), (0, 3)], [(90, 170), (107, 170)]]
        assert len(d["laptop"]) == 2 and d["lost"]
        monkeypatch.undo()
    n = sb.numbers()
    n["weeks"]["v3"].pop("rate")                                 # a week file of another shape: the old sentence stays, nothing half-written
    b = sb.board(n)
    assert "latest" not in b and "scored after that week ends" in b["laptop"][1]
