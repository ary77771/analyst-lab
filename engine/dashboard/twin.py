"""The "Evil twin" screen (debate 12 E10): two blind round-4 stories that look alike, side by side.
A display of docs/results/v4/twin.json (demo/build_twin.py, frozen v4 on the official runs) plus
each story's v3 / v4 verdict from the committed results page (scoreboard.parse)."""

import json
import os

from fastapi import APIRouter, HTTPException

from . import scoreboard

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TWIN = os.path.join(PROJECT_ROOT, "docs", "results", "v4", "twin.json")

WORDS = {
    "title": "Evil twin",
    "intro": "Two stories written after v4 was frozen, by a separate session that never saw v4's code, and run in the "
             "test machine. In both recordings a program created files and deleted them again. Their writer says one "
             "is a backup tool and the other collects saved secrets and sends them out. What does the lab say about each?",
    "writer_title": "Writer's title:",
    "picked": "We picked this pair because they look alike. The scored counts for all the new stories are on "
              "'How we know it works'.",
    "kind": {"innocent": "Innocent (says the writer's answer sheet)", "attack": "Attack (says the writer's answer sheet)"},
    "raised": "Alerts raised",
    "none_raised": "No alert raised",
    "below": "Noted but below the alarm line (which starts at level {floor})",
    "steps": "What the recording shows",
    "verdicts": "Alert verdict over 3 runs each",
    "difference": "Both programs created files and deleted them again; on its own that stays below the alarm line. "
                  "The attack's program did two more things the recording shows: it ran cmdkey to list the saved "
                  "Windows logins (high alert), and it connected to the lab's test server between creating and deleting "
                  "its files (medium alert: a stricter version of the same rule). In the backup's recording the rule "
                  "found no connection between creating and deleting. A connection is how data could leave; the "
                  "recording shows the connection, not what was sent.",
}

# plain words next to an alert's own title, for the rules in this pair (the title stays as written)
PLAIN = {
    "07f8bdc2-c9b3-472a-9817-5a670b872f53": "ran cmdkey to list the saved Windows logins",
    "502b42de-4306-40b4-9596-6f590c81f073": "listed the computer's user accounts",
}
# the same rule id has two versions; the plain words depend on which one matched
WIPE_PLAIN = {
    True: "created files and deleted them again, with a connection out in between",
    False: "created files and deleted them again (no connection seen in between)",
}

# what WORDS["difference"] says, as checks on twin.json (tests/test_dashboard_twin.py), so a rebuilt
# twin.json can never leave the sentence false
CMDKEY_RULE = "07f8bdc2-c9b3-472a-9817-5a670b872f53"
WIPE_RULE = "analystlab.create_send_wipe"
CONNECTED_MARK = "after connecting out"

VERDICT_WORDS = {"DETECTED": "right alert raised", "MISSED": "missed", "CLEAN": "no false alarm", "FALSE ALARM": "false alarm"}


def headline(sides):
    """The pair's point in one plain sentence, BUILT from the data (how many alerts each side raised), so it can
    never say more than twin.json shows. Yousif, 2026-11-20: "the point of this isnt clear"."""
    inn = [s for s in sides if s["kind"] == "innocent"]
    att = [s for s in sides if s["kind"] == "attack"]
    if len(inn) != 1 or len(att) != 1:
        return None
    i, a = len(inn[0]["raised"]), len(att[0]["raised"])
    start = "Two programs that do the same thing on the surface: one innocent, one an attack (says their writer). "
    if a and not i:
        return start + f"The new version raised {a} alert{'' if a == 1 else 's'} on the attack and none on the innocent one."
    return start + f"Alerts raised by the new version: {i} on the innocent one, {a} on the attack."


def view():
    try:
        with open(TWIN, encoding="utf-8") as f:
            data = json.load(f)
        with open(scoreboard.README, encoding="utf-8") as f:
            rows = {r["id"]: r for r in scoreboard.parse(f.read())["round4"]["rows"]}
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=503, detail=f"twin data not readable: {e}")
    for side in data["sides"]:
        for a in side["raised"] + side["below_floor"]:
            a["plain"] = (WIPE_PLAIN[CONNECTED_MARK in a["title"]] if a["rule"] == WIPE_RULE else PLAIN.get(a["rule"]))
        r = rows.get(side["scenario"])
        side["verdicts"] = None if not r else {"v3": VERDICT_WORDS.get(r["v3"], r["v3"]), "v4": VERDICT_WORDS.get(r["v4"], r["v4"]),
                                               "runs": r["runs"]}
    return {"words": WORDS, **data, "headline": headline(data["sides"])}


router = APIRouter()


@router.get("/api/twin")
def twin():
    return view()
