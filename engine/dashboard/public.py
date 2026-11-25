"""The "Two machines (public data)" tab (debate 11, Yousif 2026-11-20: "Today lets build the public
data tab").

A DISPLAY of a result that was scored once, elsewhere: branch `two-machines` ran its linker
(engine/crosshost.py) on 27 public OTRF lateral-movement recordings (docs/results/linker/test.json),
and tools/linker_export.py on that branch wrote the two files read here (summary.json: the pooled
numbers copied from test.json; showcase.json: one file's cross-machine story). No linker code runs
in this server; nothing here grades anything. The files are public lab data (OTRF's own machine
names), never this laptop's recordings, so the tab is safe on a projector.
"""

import json
import os
import re

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LINKER = os.path.join(PROJECT_ROOT, "docs", "results", "linker")

# crosshost's frozen `claim` field says "probably" (its own older wording); the tab never shows it.
DROP_EDGE_FIELDS = {"claim"}
GUESS_PREFIX = re.compile(r"^Guess \([^)]*\): ")

WORDS = {
    "title": "Two machines",
    "badge": "PUBLIC DATA: recordings published by the OTRF Security-Datasets project, not made by us",
    "story_title": "What the two recordings show together",
    "numbers_title": "Across all 27 public recordings",
    "limit_title": "The honest limit",
    "dataset_title": "Where the data comes from",
    "machine_events": "events recorded",
    "not_in_picture": "no link to another machine in this recording",
    "licence_text": "not stated in our downloaded copy (the project's page lists MIT; not checked against a licence file)",
    "show_all":"Also show the other connections between these machines (Windows' own programs)",
    "focus_hint":"Faded lines are routine traffic between Windows' own programs; they are facts too, but not part of this step.",
}


def _load(name):
    path = os.path.join(LINKER, name)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"{name} is missing (made by tools/linker_export.py on branch two-machines)")


def headline(pooled):
    """Big numbers with their plain labels, taken from the pooled result (never typed by hand)."""
    guesses = pooled["hypotheses"]
    low = sum(v for k, v in guesses.items() if k.endswith("low"))
    na = sum(v for k, v in guesses.items() if k.endswith("not assessable"))
    worker = sum(v for k, v in guesses.items() if k.startswith("worker"))
    return [
        {"value": pooled["cross_machine_outgoing"], "label": "connections from one recorded machine to another"},
        {"value": pooled["facts"], "label": "recorded on both machines, so they are facts", "ink": "fact"},
        {"value": pooled["ambiguous"], "label": "ambiguous matches"},
        {"value": pooled["control1_problems"], "label": f"problems when all {pooled['control1_facts_checked']} facts were re-checked independently"},
        {"value": low + na, "label": f"guesses that a connection made the other machine start a program: {low + na - worker} "
                                     f"about any program plus {worker} about remote-work programs ({low} weak lead, {na} with "
                                     "no grade in all)", "ink": "hypothesis"},
    ]


def two_machines():
    summary, show = _load("summary.json"), _load("showcase.json")
    # the export's guess sentences start "Guess (low): "; the page shows the ink and band as a tag, so
    # the prefix would only repeat it in a fourth wording
    edges = [{k: (GUESS_PREFIX.sub("", v) if k == "sentence" else v) for k, v in e.items() if k not in DROP_EDGE_FIELDS}
             for e in show["edges"]]
    dataset = dict(show["dataset"], licence_text=WORDS["licence_text"] if show["dataset"].get("licence") == "unknown"
                   else show["dataset"].get("licence"))
    sentences = summary["sentences"]
    # The export's last story sentence says "the picture shows them" about the routine traffic; the
    # tab hides that traffic until the viewer ticks the box, so the sentence is shown only then.
    story = [s for s in show["story"] if not s.startswith("The other ")]
    others = [s for s in show["story"] if s.startswith("The other ")]
    return {
        "words": WORDS,
        "dataset": dataset,
        "file": show["file"],
        "choice_rule": show["choice_rule"],
        "machines": show["machines"],
        "story": story,
        "story_others": others,
        "nodes": show["nodes"],
        "edges": edges,
        "headline": headline(summary["pooled"]),
        "sentences": sentences[:-1],
        "limit": sentences[-1],
        "capture_lengths_s": summary.get("capture_lengths_s"),
    }


router = APIRouter()


@router.get("/api/public/two-machines")
def public_two_machines():
    return two_machines()
