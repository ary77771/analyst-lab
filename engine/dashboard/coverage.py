"""The "Attack coverage" screen (debate 12 E11): v4 on the 170 Atomic Red Team tests it had never
seen, one tile per test, grouped by attack technique, misses shown as plainly as catches.

A display of docs/results/v4/art-map.json (built by demo/build_art_map.py from the committed
results; nothing re-scored). Technique and test names come from Atomic Red Team (MIT licence),
whose technique names follow MITRE ATT&CK.
"""

import json
import os
from collections import OrderedDict

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAP = os.path.join(PROJECT_ROOT, "docs", "results", "v4", "art-map.json")

WORDS = {
    "title": "Attack coverage",
    "intro": "170 attack tests from Atomic Red Team, a public library of small attack tests, run only in the isolated "
             "test machine; v4 had never seen them. Each square is one test. Misses are shown as plainly as catches.",
    "results": {
        "recorded": "An alert raised on the test's own programs, from what was recorded",
        "declared": "An alert raised on the test's own programs, from the command as it was typed (declared, not recorded): new in v4",
        "missed": "Missed: no alert on the test's programs",
    },
    # the Proof screen's legend (2026-11-20): the same three kinds in a few words; the full sentences are in Details
    "results_short": {"recorded": "alert, from what was recorded", "declared": "alert, from the typed command only",
                      "missed": "no alert"},
    "declared_note": "{d} of these come from commands as typed, not from what was recorded.",
    "meaning": "'Caught' here means an alert was raised on the programs the test started; it does not check that the "
               "alert names the exact attack technique.",
    "toggle": "Leave out the community rules written with these same tests in mind",
    "toggle_note": "Some public detection rules were written by people who used these very tests. Leaving them out "
                   "is the stricter score.",
    "caught_label": "of {n} tests with an alert on the test's programs",
    "source": "Atomic Red Team by Red Canary (MIT licence); technique names © The MITRE Corporation (ATT&CK).",
}


def load():
    try:
        with open(MAP, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise HTTPException(status_code=503, detail=f"art-map.json missing (demo/build_art_map.py): {e}")


def view(data):
    groups = OrderedDict()
    for t in data["tests"]:
        parent = t["technique"].split(".")[0]
        g = groups.setdefault(parent, {"technique": parent, "name": t["technique_name"], "tests": []})
        g["tests"].append(t)
    tests = data["tests"]
    return {
        "words": WORDS,
        "total": len(tests),
        "caught": sum(t["result"] != "missed" for t in tests),
        "caught_strict": sum(t["without_citing_rules"] for t in tests),
        "declared": sum(t["result"] == "declared" for t in tests),
        "groups": list(groups.values()),
        "half": data["half"],
    }


router = APIRouter()


@router.get("/api/coverage")
def coverage():
    return view(load())
