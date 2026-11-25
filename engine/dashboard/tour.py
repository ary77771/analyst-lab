"""The guided tour (2026-11-23): a short walk through the screens for someone who is not a specialist.

GET /api/tour gives the steps: which screen, which part of it to point at, a title and two or three plain
sentences. The page only places the bubbles; every word is here, so the honesty checks read them like any
other word that reaches a screen (tests/test_dashboard_tour.py).

What the words may do: say what a part of the screen SHOWS and how to read it. What they may not do: say
anything about a particular alert, a particular program, or how the machine is doing. The tour is the same
on the live dashboard and on a replay, whatever the store holds, so nothing in it can depend on the data.
"""

from fastapi import APIRouter

from .words import INKS

WORDS = {
    "button": "Tour",
    "button_title": "A short walk through the screens, in plain words",
    "next": "Next", "back": "Back", "end": "End the tour", "done": "Done",
    "step": "{n} of {total}",
    "keys": "Arrow keys step · Esc ends",
    "missing": "(This part is not on the screen right now.)",
}

P, S, G = INKS["fact"], INKS["hypothesis"], INKS["gap"]

# the first step on a dashboard started with --no-labs (there is no fourth page then)
FIRST_WITHOUT_LABS = ("Analyst Lab watches a test computer and tells the story of what happened on it. It has three pages: "
                      "Watch shows what is arriving now, Story tells one alert step by step, and Proof shows how the lab "
                      "was checked.")

# screen: watch | story | proof | labs.  target: a CSS selector on that screen (the first match is pointed at).
STEPS = [
    {"screen": "watch", "target": ".ua-top",
     "title": "What this is",
     "text": "Analyst Lab watches a test computer and tells the story of what happened on it. It has four pages: "
             "Watch shows what is arriving now, Story tells one alert step by step, Proof shows how the lab was "
             "checked, and Labs holds tools for looking closer."},
    {"screen": "watch", "target": ".ua-run",
     "title": "The test machine",
     "text": "The tests run inside a separate, virtual computer, never on this laptop itself. On the live page a "
             "test is started here and its steps are ticked off as they happen. On a replay, a recorded run is "
             "shown instead and nothing is started."},
    {"screen": "watch", "target": ".ua-signal",
     "title": "What is arriving",
     "text": "The test computer reports what it does: a program started, a file created, a connection made. Each "
             "report is one record. This panel says in words what the lab sees right now, and the number counts "
             "the records received so far."},
    {"screen": "watch", "target": ".ua-alerts",
     "title": "Alerts",
     "text": "When the records match something the lab looks for, an alert is raised and appears here, with its "
             "level and its first steps. An alert is a reason to look, not a verdict. \"Open the story\" shows "
             "what led to it."},
    {"screen": "watch", "target": ".ck",
     "title": "Honesty checks",
     "text": "These are automatic tests of the lab itself. They check, for example, that every statement shown "
             "as proven points at a recorded event, and that no screen uses words that claim more than the "
             "records show. They can be run from here at any time."},
    {"screen": "story", "target": ".ua-story-head",
     "title": "One alert, as a story",
     "text": "This page tells one alert. The line at the top says what the alert is about, on which machine and "
             "when it was raised."},
    {"screen": "story", "target": ".ua-film",
     "title": "The map",
     "text": "Each box is a thing that took part: a program, a file, an address on the network. Each line is "
             "something that happened between two of them. The map draws itself in the order the events were "
             "recorded."},
    {"screen": "story", "target": ".ua-caption",
     "title": "Three kinds of statement",
     "text": f"Every line and every sentence is one of three kinds. {P['word']} (green, solid): {P['explain']}. "
             f"{S['word']} (amber, dashed): {S['explain']}. {G['word']} (violet, dotted): {G['explain']}. "
             "The lab never shows a suspicion in the colour of a proof."},
    {"screen": "story", "target": ".ua-bar",
     "title": "Play it again, step by step",
     "text": "The buttons play, pause and step through the story; each mark on the line is one step, and a click "
             "on a mark jumps to it. The numbers on the right count the statements of each kind told so far."},
    {"screen": "story", "target": ".ua-story-head .ua-btn",
     "title": "The full report",
     "text": "Below the map is the written report: every statement, each proven one with the recorded event it "
             "rests on, each suspicion with how strong the lead is, and a list of what the recording cannot show."},
    {"screen": "proof", "target": ".pf-scores",
     "title": "How well it finds things",
     "text": "Everything on this page comes from tests scored after the detection code was frozen: new attack "
             "stories written by a separate session that never saw the code, innocent look-alikes, and tests from "
             "a public library. The small print under each number says what was counted."},
    {"screen": "proof", "target": ".pf-wall",
     "title": "A public test set",
     "text": "Each square is one test from a public collection of attack techniques, run in the test computer. "
             "The colours say whether the lab's alert rested on something recorded, on something a command "
             "line declared, or whether the test was missed."},
    {"screen": "proof", "target": ".pf-pair",
     "title": "Look-alikes",
     "text": "Two stories that look alike, written by a separate session: by the writer's own answer sheet one "
             "is an attack and one is innocent. This shows what the lab raised for each, so it can be seen where "
             "it tells them apart and where it does not."},
    {"screen": "labs", "target": ".lab-page",
     "title": "Labs",
     "text": "Labs holds extra tools for an investigator: ways to search, compare and look closer at what was "
             "recorded. They only read. Nothing in Labs changes the records or the alerts."},
]

def make_router(labs=True):
    """`labs` False (the dashboard was started with --no-labs): the tour has no Labs step."""
    router = APIRouter()
    steps = STEPS
    if not labs:
        steps = [dict(s, text=FIRST_WITHOUT_LABS) if i == 0 else s for i, s in enumerate(STEPS) if s["screen"] != "labs"]

    @router.get("/api/tour")
    def tour():
        return {"words": WORDS, "steps": steps}

    return router


router = make_router()
