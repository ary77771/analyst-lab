"""The "How we know it works" screen (debate 11, sections A3-A4 and the fresh review's item 11).

Every number here is READ from the committed results page docs/results/v4/README.md (copied from
branch v4, where the scoring wrote it); nothing is typed by hand. tests/test_dashboard_scoreboard.py
recomputes each number from the same page and was broken on purpose once.

The sentences follow the agreed honest wording: scenarios, not runs; the ART gain next to the
version without the community rules that cite those tests; S3 as "lost on purpose"; the phase-2
miss of the pre-registered bar; the laptop brake as "scored on 11-22" until it is.

ADDED 2026-11-24 (PROOF's reviewed numbers), as a SECOND view of the same panel ("latest"): the
rehearsed view above is unchanged and stays the one shown first.
  - a week of the lab laptop's normal use, raised alerts per active hour for v2, v3 and v4: READ from
    the three machine-made result files (WEEKS) and the brake's file (BRAKE), copied byte for byte
    from the commits that scored them (main a62afba, v3 244d740, v4 81afaf4). Only their total lines
    and the first cells of their rule tables (rule title, count) are read: never a program or a folder.
  - blind round 5 (8 stories written after freeze-v4): READ from section 5 of the results page as it
    stands on v4 a832a83, kept under its OWN name (README_R5 = README-with-round5.md). README.md itself
    is NOT replaced: a dashboard that was started earlier reads that file on every request with the
    code it has in memory, and that older code read story rows from the whole page (on 2026-11-24 the
    replaced file made the running demo show 5 of 7 instead of 2 of 3 until it was put back).
    Round 4 is read from section 3 only, since both tables look alike.
  - "we show where it got worse": the story v4 lost (B28) stands on the page itself, not in the notes.
"""

import os
import re

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS = os.path.join(PROJECT_ROOT, "docs", "results")
README = os.path.join(RESULTS, "v4", "README.md")
README_R5 = os.path.join(RESULTS, "v4", "README-with-round5.md")     # the same page as of v4 a832a83 (it gained section 5)
# a week of the lab laptop's normal use, scored by each version's frozen code (v4: on v3's week)
WEEKS = {"v2": os.path.join(RESULTS, "v2", "false-alerts-official.md"),
         "v3": os.path.join(RESULTS, "v3", "false-alerts-official.md"),
         "v4": os.path.join(RESULTS, "v4", "false-alerts-official-v3runs.md")}
BRAKE = os.path.join(RESULTS, "v4", "v4-brake-official.md")

ROW = re.compile(r"^\| (B\d+) \| (malicious|innocent) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|\s*$", re.M)
ART_BOTH = re.compile(r"^\| \*\*both\*\* \| \*\*(\d+)\*\* \| \*\*(\d+) \([^)]*\)\*\* \| \*\*(\d+) \([^)]*\)\*\* \| "
                      r"\*\*(\d+) \([^)]*\)\*\* \| \*\*(\d+) \([^)]*\)\*\* \| \*\*\+(\d+) / (\d+)\*\*", re.M)
ART_P2 = re.compile(r"^\| phase 2 \(admin\) \| (\d+) \| (\d+) [^|]*\| (\d+) [^|]*\| (\d+) [^|]*\| (\d+) [^|]*\|", re.M)
ART_CITING = re.compile(r"(\d+) of the (\d+) rest on Sigma rules that cite ART tests")
LOST = re.compile(r"\*\*LOST (\d+), all (S\d+)\*\*")
WEEK = re.compile(r"\*\*(\d+\.\d+) -> (\d+\.\d+) per active hour\*\*")
SECTION = re.compile(r"^## (\d+)\. .*$", re.M)
WON = re.compile(r"WON (B\d+) and (B\d+) in round 4")
RAISED = re.compile(r"^- RAISED alerts \(>= medium\): \*\*([\d,]+)\*\* = \*\*(\d+\.\d+) per active hour\*\*", re.M)
ACTIVE = re.compile(r"^- Active hours: \*\*(\d+\.\d+)\*\*", re.M)
DAYS = re.compile(r"(?:TEST snapshot \(|snapshot days )(\d{4})-(\d\d-\d\d) \.\. \d{4}-(\d\d-\d\d)")


def _verdict(cell):
    m = re.match(r"\*{0,2}([A-Z ]+?) (\d+)\*{0,2}\s*$", cell.strip())
    return (m.group(1), int(m.group(2))) if m else (cell.strip(), None)


def _section(text, number):
    """The text under the heading "## <number>. ..." up to the next such heading; None when there is none."""
    heads = list(SECTION.finditer(text))
    for i, m in enumerate(heads):
        if int(m.group(1)) == number:
            return text[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
    return None


def _rows(text):
    return [{"id": sid, "kind": kind, "v3": _verdict(v3)[0], "v4": _verdict(v4)[0], "runs": _verdict(v4)[1], "story": _verdict(story)[0]}
            for sid, kind, v3, v4, _incident, story in ROW.findall(text or "")]


def _right(row, version):
    """Did this version do the right thing on this story: the alert on an attack story, none on an innocent one."""
    return row[version] == ("DETECTED" if row["kind"] == "malicious" else "CLEAN")


def _round5(text, round4):
    """Section 5 of the results page: the 8 stories written after freeze-v4. None when the page has no such section."""
    part = _section(text, 5)
    rows = _rows(part)
    if not rows:
        return None
    mal = [r for r in rows if r["kind"] == "malicious"]
    inn = [r for r in rows if r["kind"] == "innocent"]
    checked = [r for r in rows if "NOT CHECKED" not in (r["v3"], r["v4"])]
    won = WON.search(part)
    # the stories of the round before that the page says the same rule won: named only if round 4's own table agrees
    gained4 = {r["id"] for r in round4 if r["kind"] == "malicious" and _right(r, "v4") and not _right(r, "v3")}
    return {
        "scenarios": len(rows), "malicious": len(mal), "innocent": len(inn), "not_checked": len(rows) - len(checked),
        "v3_detected": sum(r["v3"] == "DETECTED" for r in mal), "v4_detected": sum(r["v4"] == "DETECTED" for r in mal),
        "missed_by_both": [r["id"] for r in mal if r["v3"] == "MISSED" and r["v4"] == "MISSED"],
        "v3_false_alarms": sum(r["v3"] == "FALSE ALARM" for r in inn), "v4_false_alarms": sum(r["v4"] == "FALSE ALARM" for r in inn),
        "better": [r["id"] for r in checked if _right(r, "v4") and not _right(r, "v3")],
        "worse": [r["id"] for r in checked if _right(r, "v3") and not _right(r, "v4")],
        "same": sum(_right(r, "v3") == _right(r, "v4") for r in checked),
        "runs_each": sorted({r["runs"] for r in rows}), "story_pass": sum(r["story"] == "PASS" for r in rows),
        "same_rule_won": list(won.groups()) if won and set(won.groups()) <= gained4 else [],
        "log_tidier": "B28's innocent logger" in part,              # the page's own words for what B28 is
        "rows": rows,
    }


def parse_week(text):
    """One version's week of normal laptop use (a machine-made result file): its total lines, and the title and
    count of each raised rule. ONLY those: the file's other cells are never read."""
    raised, active, days = RAISED.search(text), ACTIVE.search(text), DAYS.search(text)
    rules = {}
    for line in text.split("## Raised alerts by rule", 1)[-1].split("\n## ", 1)[0].splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")][:5]
        if len(cells) == 5 and cells[3].replace(",", "").isdigit():
            rules.setdefault(cells[2], int(cells[3].replace(",", "")))
    if not (raised and active and days and rules):
        raise ValueError("a laptop-week result file does not have the expected lines")
    return {"raised": int(raised.group(1).replace(",", "")), "rate": float(raised.group(2)), "active_hours": float(active.group(1)),
            "from": days.group(2), "to": days.group(3), "rules": rules}


def parse_brake(text):
    """v4's false-alarm budget on that week: how many of its lines passed."""
    results, days = re.findall(r"\b(PASS|FAIL)\b", text), DAYS.search(text)
    if not (results and days):
        raise ValueError("the brake's result file does not have the expected lines")
    return {"lines": len(results), "passed": results.count("PASS"), "from": days.group(2), "to": days.group(3)}


def parse(text):
    rows = _rows(_section(text, 3))
    mal = [r for r in rows if r["kind"] == "malicious"]
    checkable = [r for r in mal if r["v4"] != "NOT CHECKED"]
    inn = [r for r in rows if r["kind"] == "innocent"]
    both, p2, citing = ART_BOTH.search(text), ART_P2.search(text), ART_CITING.search(text)
    lost, week = LOST.search(text), WEEK.search(text)
    if not (rows and both and p2 and citing and lost and week):
        raise ValueError("docs/results/v4/README.md does not have the expected tables")
    return {
        "round4": {
            "scenarios": len(rows), "malicious": len(mal), "checkable": len(checkable),
            "not_checked": len(mal) - len(checkable),
            "v3_detected": sum(r["v3"] == "DETECTED" for r in checkable),
            "v4_detected": sum(r["v4"] == "DETECTED" for r in checkable),
            "innocent": len(inn),
            "v3_false_alarms": sum(r["v3"] == "FALSE ALARM" for r in inn),
            "v4_false_alarms": sum(r["v4"] == "FALSE ALARM" for r in inn),
            "runs_each": sorted({r["runs"] for r in rows}),
            "story_pass": sum(r["story"] == "PASS" for r in rows),
            "rows": rows,
        },
        "art": {"tests": int(both.group(1)), "q1_v3": int(both.group(2)), "q1_v4": int(both.group(3)),
                "q2_v3": int(both.group(4)), "q2_v4": int(both.group(5)), "gained": int(both.group(6)),
                "lost": int(both.group(7)), "via_citing_rules": int(citing.group(1)),
                "p2_q2_v3": int(p2.group(4)), "p2_q2_v4": int(p2.group(5))},
        "regression": {"lost": int(lost.group(1)), "scenario": lost.group(2)},
        "laptop_v1_week": {"v3": float(week.group(1)), "v4": float(week.group(2))},
        "round5": _newest(lambda: _round5(text, rows)),
    }


def _newest(read):
    """A piece of the newest results, or None when reading it fails in ANY way: the first view never depends on it."""
    try:
        return read()
    except Exception:
        return None


def numbers():
    """Every number of the screen, read from the result files. The newest ones (the laptop weeks, the brake) are
    left out, never guessed, when their files are not there or can't be read."""
    def read(path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    n = parse(read(README))
    try:
        n["round5"] = _round5(read(README_R5), n["round4"]["rows"])
        n["weeks"] = {v: parse_week(read(p)) for v, p in WEEKS.items()}
        n["brake"] = parse_brake(read(BRAKE))
    except Exception:                                             # any trouble with the newest sources: they are left out
        n["round5"] = n["weeks"] = n["brake"] = None
    return n


# Yousif, 2026-11-20: "showing small numbers isnt right and it isnt clear what they represent". Each bar now
# carries its version in words, and each group says in words what its total counts ("of_text").
OLD, NEW = "Old version (v3)", "New version (v4)"


VERSIONS = {"v2": "Version 2", "v3": "Version 3", "v4": "Version 4"}


def _ids(ids):
    return ", ".join(ids[:-1]) + (" and " if len(ids) > 1 else "") + ids[-1] if ids else ""


def _innocent_caveat(r):
    """The same count can hide a swap: say which innocent story v4 cleared and which one it wrongly flagged."""
    innocent = {x["id"] for x in r["rows"] if x["kind"] == "innocent"}
    cleared, flagged = [i for i in r["better"] if i in innocent], [i for i in r["worse"] if i in innocent]
    if flagged and cleared:
        return f"v4 cleared {_ids(cleared)} but wrongly flagged {_ids(flagged)}."
    if flagged:
        return f"Lower is better. v4 wrongly flagged {_ids(flagged)}, which v3 did not."
    return f"Lower is better. v4 cleared {_ids(cleared)}." if cleared else "Lower is better."


def latest(n):
    """The second view of the panel: a week of real use, and the newest stories nobody had seen. None unless every
    one of its sources was read."""
    r, w, brake = n.get("round5"), n.get("weeks"), n.get("brake")
    if not (r and w and brake):
        return None
    runs = r["runs_each"][0] if len(r["runs_each"]) == 1 else None
    top = next(iter(w["v2"]["rules"]))                           # the rule behind most of v2's raised alerts (the file lists them by count)
    top_n = {v: w[v]["rules"].get(top, 0) for v in WEEKS}
    same_week = (w["v3"]["from"], w["v3"]["to"]) == (w["v4"]["from"], w["v4"]["to"])
    worse = ""
    if r["worse"]:
        worse = f"Where v4 got worse: {_ids(r['worse'])}. "
        if r["worse"] == ["B28"] and r["log_tidier"]:
            worse += ("B28 is an innocent program that writes daily logs, checks in with the test server, then zips and deletes "
                      "its old logs. v4's own rule for 'creates files, talks out, then deletes them' raised an alert on it; "
                      "v3 has no such rule.")
            if r["same_rule_won"]:
                worse += f" The same rule is what found the attack stories {_ids(r['same_rule_won'])} in the round before."
    return {
        "title": "Newest tests, and a week of real use",
        "tabs": {"first": "Earlier tests", "latest": "Newest tests"},
        "intro": "Every version is tested on tests it has never seen, and we show where it got worse, not only where it got better.",
        "groups": [
            {"title": "A week of the lab laptop's normal use",
             "bars": [{"label": v, "name": VERSIONS[v], "value": w[v]["rate"], "text": f"{w[v]['rate']:.1f}", "of": w[v]["active_hours"]}
                      for v in WEEKS],
             "of_text": "per hour, over one week of normal use; lower is better",
             "unit": "raised alerts per active hour (on normal use every alert is a false alarm)",
             "short": "False alarms per hour of normal use",
             # not one week for all three: said ON the page, beside the numbers (not only in the notes)
             "caveat": ("" if (w["v2"]["from"], w["v2"]["to"]) == (w["v3"]["from"], w["v3"]["to"]) and same_week else
                        f"Version 2's week began on {w['v2']['from']}, the others' on {w['v3']['from']}. ")
                       + f"{top_n['v2']:,} of version 2's {w['v2']['raised']:,} alerts came from one rule.",
             "notes": [
                 f"Version 2 was scored on the week {w['v2']['from']} to {w['v2']['to']} ({w['v2']['active_hours']} active hours); "
                 f"versions 3 and 4 on {'the same' if same_week else 'the'} week {w['v3']['from']} to {w['v3']['to']} "
                 f"({w['v3']['active_hours']} active hours)" + (", so 3 against 4 is the same week and 2 is an overlapping one." if same_week else "."),
                 f"Raised alerts: version 2 {w['v2']['raised']:,}, version 3 {w['v3']['raised']:,}, version 4 {w['v4']['raised']:,}.",
                 f"Most of version 2's number came from one rule, \"{top}\": {top_n['v2']:,} of its {w['v2']['raised']:,} raised "
                 f"alerts. The same rule raised {top_n['v3']:,} in version 3 and {top_n['v4']:,} in version 4.",
                 f"v4's false-alarm budget for the week {brake['from']} to {brake['to']} was fixed before the week was opened: "
                 f"{brake['passed']} of its {brake['lines']} lines passed.",
             ]},
            {"title": f"The {r['scenarios']} newest stories, written after v4 was frozen by a fresh session that never saw the detectors",
             "bars": [{"label": "v3", "name": OLD, "value": r["v3_detected"], "of": r["malicious"]},
                      {"label": "v4", "name": NEW, "value": r["v4_detected"], "of": r["malicious"]}],
             "of_text": f"of the {r['malicious']} newest attack stories",
             "unit": "attack stories where the right alert was raised",
             "short": "Newest attack stories with the right alert",
             "caveat": (f"{len(r['missed_by_both'])} was missed by both versions." if len(r["missed_by_both"]) == 1 else
                        f"{len(r['missed_by_both'])} were missed by both versions."),
             "notes": [
                 (f"Each story was run {runs} times; every run gave the same result." if runs else
                  "Each story was run several times; every run gave the same result."),
                 f"Missed by both versions: {_ids(r['missed_by_both']) or 'none'}. Stories that could not be checked this round: {r['not_checked']}.",
                 f"Full story right (every expected link, nothing extra): {r['story_pass']} of the {r['scenarios']} stories, the same for v3 and v4.",
             ]},
            {"title": "The newest innocent look-alikes (false alarms, lower is better)",
             "bars": [{"label": "v3", "name": OLD, "value": r["v3_false_alarms"], "of": r["innocent"]},
                      {"label": "v4", "name": NEW, "value": r["v4_false_alarms"], "of": r["innocent"]}],
             "of_text": f"of the {r['innocent']} newest innocent look-alike stories",
             "unit": "innocent stories that raised an alert",
             "short": "Innocent look-alikes that raised an alert",
             "caveat": _innocent_caveat(r),
             "notes": [worse] if worse else []},
        ],
        "summary": f"Of these {r['scenarios'] - r['not_checked']}: v4 better on {len(r['better'])}, the same on {r['same']}, "
                   f"worse on {len(r['worse'])}.",
        "worse": worse,
        "sources": ["docs/results/v4/README-with-round5.md (section 5)", "docs/results/v2/false-alerts-official.md",
                    "docs/results/v3/false-alerts-official.md", "docs/results/v4/false-alerts-official-v3runs.md",
                    "docs/results/v4/v4-brake-official.md"],
    }


def board(n):
    r, a = n["round4"], n["art"]
    runs = r["runs_each"][0] if len(r["runs_each"]) == 1 else None
    out = _board(n, r, a, runs)                                   # the rehearsed first view: built first, by itself
    # Whatever goes wrong with the newest results (a source of another shape, a missing key, anything) must
    # never take the first view down with it (review of 2026-11-24): then there is simply no second view.
    try:
        new, brake, w = latest(n), n.get("brake"), n.get("weeks")
        scored = None
        if brake and w:                                           # the week has been scored: say the result, not the promise
            scored = (f"v4's own false-alarm check on a fresh week of normal use ({brake['from']} to {brake['to']}) has been "
                      f"scored: {brake['passed']} of its {brake['lines']} budget lines passed; raised alerts per active hour "
                      f"on that week went from {w['v3']['rate']:.2f} (v3) to {w['v4']['rate']:.2f} (v4).")
    except Exception as e:
        print(f"scoreboard: the newest results are left out ({type(e).__name__}: {e})", flush=True)
        return out
    if scored:
        out["laptop"][1] = scored
    if new:
        out["latest"] = new
    return out


def _board(n, r, a, runs):
    return {
        "title": "How we know it works",
        "intro": "Everything below comes from tests scored after the detection code was frozen. "
                 "v3 is the previous version, v4 the current one.",
        "groups": [
            {"title": "New attack stories, written after v4 was frozen by a separate session that never saw v4's code",
             "bars": [{"label": "v3", "name": OLD, "value": r["v3_detected"], "of": r["checkable"]},
                      {"label": "v4", "name": NEW, "value": r["v4_detected"], "of": r["checkable"]}],
             "of_text": f"of the {r['checkable']} new attack stories we could check",
             "unit": "attack stories where the right alert was raised",
             # short / caveat (2026-11-20, the Proof screen): a heading and ONE caveat short enough to stand
             # beside the big number; the full notes stay one click away
             "short": "New attack stories with the right alert",
             "caveat": f"{r['not_checked']} more could not be checked.",
             "notes": [
                 f"{r['not_checked']} more attack stories could not be checked: their answer sheets name one program "
                 "that their own story starts several times, so the checker refused to guess.",
                 f"Each story was run {runs} times; every run gave the same result." if runs else
                 "Each story was run several times; every run gave the same result.",
             ]},
            {"title": "Innocent look-alikes (false alarms, lower is better)",
             "bars": [{"label": "v3", "name": OLD, "value": r["v3_false_alarms"], "of": r["innocent"]},
                      {"label": "v4", "name": NEW, "value": r["v4_false_alarms"], "of": r["innocent"]}],
             "of_text": f"of the {r['innocent']} new innocent look-alike stories",
             "unit": "innocent stories that raised an alert",
             "short": "Innocent look-alikes that raised an alert",
             "caveat": f"Lower is better. Only {r['innocent']} stories.",
             "notes": [f"Full story right (every expected link, nothing extra): {r['story_pass']} of the "
                       f"{r['scenarios']} new stories, the same for v3 and v4."]},
            {"title": f"{a['tests']} attack tests from a public library (Atomic Red Team) that v4 never saw",
             "bars": [{"label": "v3", "name": OLD, "value": a["q1_v3"], "of": a["tests"]},
                      {"label": "v4", "name": NEW, "value": a["q1_v4"], "of": a["tests"]}],
             "of_text": f"of {a['tests']} public attack tests",
             "unit": "tests with an alert on the test's own programs",
             "short": "Public attack tests with an alert",
             "caveat": f"Without the community rules written with these tests in mind: {a['q2_v3']} to {a['q2_v4']}.",
             "visible": 2,
             "notes": [
                 f"All {a['gained']} new catches came from commands as they were typed (declared, not recorded); "
                 f"{a['via_citing_rules']} of them use community rules written with these same tests in mind. "
                 f"Without those rules: v3 {a['q2_v3']}, v4 {a['q2_v4']}.",
                 f"Our bar set before the test ('better' without those rules) was met over both phases, but not in "
                 f"the administrator phase alone ({a['p2_q2_v3']} = {a['p2_q2_v4']}).",
                 f"{a['lost']} tests were lost. 'Caught' means an alert on the programs the test started, not that "
                 "the alert names the exact technique.",
             ]},
        ],
        "lost": f"Lost on purpose: {n['regression']['scenario']} (a hidden listener reachable only from the machine itself) "
                f"went from caught to missed in its {n['regression']['lost']} earlier runs. We accepted this on 11-14; "
                "the same rule change later cleared the false alarm on the unseen innocent story B22.",
        "laptop": [
            f"On an earlier week of the lab laptop's normal use, raised alerts per active hour went from "
            f"{n['laptop_v1_week']['v3']:.2f} to {n['laptop_v1_week']['v4']:.2f}.",
            "v4's own false-alarm check on a fresh week of normal use (11-15 to 11-21) is scored after that week "
            "ends; its result is added here once scored.",
        ],
        "source": "docs/results/v4/README.md",
    }


router = APIRouter()


@router.get("/api/scoreboard")
def scoreboard():
    try:
        return board(numbers())
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=503, detail=f"results page not readable: {e}")
