"""Lab "One alert, start to finish" (wave 3, W3-7): a walk-through of one whole investigation.

It follows ONE recorded alert through the labs, one question per step (what fired, see it happen, what
happened around it, how sure, how far, what now, keep it). It runs nothing and changes nothing: each step
is only the address of a lab opened on that alert, with one sentence saying what to look at there. The
page (dashboard/src/labs/guide/) lists the steps; while a walk-through is going, the Labs shell shows the
step's sentence in a bar above the lab (dashboard/src/labs/GuideBar.tsx).

Which alert: the dashboard's own store decides, nothing is typed. Of the alerts the screens show, the one
with the highest level, and of those the earliest. On the demo's replay store that is the alert of the
recorded S1 run (the store holds one alert). "?alert=<id>" names another one of the shown alerts instead
(critique of 2026-11-24: on the live store the automatic pick is a start-up alert); an id that is not among
them is said plainly, never silently replaced. The steps name labs by id; a lab that is not part of the
build, or is experimental, is left out by the page, so the script never points at a page that is not there.

Every sentence here says what a lab is FOR, never what it will find: what is found is the lab's own to
say, from the records.
"""

from fastapi import APIRouter

from engine import labs

router = APIRouter(prefix="/api/labs/guide")

WORDS = {
    "title": "One alert, start to finish",
    "intro": "One recorded alert, followed through the labs, one question per step. Nothing is run and nothing is "
             "changed: every step only opens a lab on this alert.",
    "which": "The alert followed here: of the alerts this dashboard shows, the one with the highest level, and of "
             "those the earliest.",
    "alert": "The alert",
    "chosen": "The alert followed here is the one named in the address.",
    "unknown": "This alert isn't in this recording, or it is below the level the screens show. Pick one of the "
               "alerts below to follow instead.",
    "others": "Follow another alert",
    "no_alert": "This recording holds no alert at the level the screens show, so there is nothing to follow yet.",
    "start": "Start the walk-through",
    "again": "Start again from step 1",
    "step": "Step {n} of {total}",
    "next": "Next",
    "back": "Back",
    "finish": "Finish",
    "end": "End the walk-through",
    "bar": "Walk-through",
    "left_out": "not part of this build",
    "none_here": "None of the walk-through's steps can be opened on this dashboard.",
    "finished": "That was the whole path: from the alarm to a case that can be handed on. Every page you saw read "
                "the same recording; none of them changed it.",
}

# lab id, the question, and one sentence on what to look at there
STEPS = [
    {"lab": "why", "question": "What fired?",
     "text": "Start with the alarm itself: which rule raised it, and the exact recorded values that made it fire."},
    {"lab": "replay", "question": "See it happen",
     "text": "Play the alert's story at the pace it was recorded: each link is drawn at its own moment."},
    {"lab": "moment", "question": "What happened around it?",
     "text": "Look left and right in time: everything the machine recorded in the seconds before and after."},
    {"lab": "prove", "question": "How sure are we?",
     "text": "Separate what is on record from what is only suspected, and see which single record would settle each "
             "open line."},
    {"lab": "network", "question": "How far did it go?",
     "text": "Check who this machine talked to, and whether a program kept calling out on a regular rhythm."},
    {"lab": "respond", "question": "What now?",
     "text": "Read the published response steps for this kind of alert, each with what the records can and cannot "
             "confirm."},
    {"lab": "cases", "question": "Keep it",
     "text": "Put the alert, your notes and the open questions into a case, and export its report."},
]


def pick(alerts):
    """The alert a walk-through follows: the highest level, and of those the earliest. None when there is none."""
    from engine.alerts import LEVELS
    alerts = list(alerts)
    if not alerts:
        return None
    return sorted(alerts, key=lambda a: (-LEVELS.index(a.level), str(a.time), str(a.alert_id)))[0]


MORE = 12                                            # how many other alerts the page offers to follow


def _row(a):
    return None if a is None else {"id": a.alert_id, "title": a.title, "level": a.level, "time": str(a.time), "host": a.host}


@router.get("")
def guide(alert: str = ""):
    """`alert`: the id of the alert to follow (one of the alerts the screens show). Without it: the store's
    own pick. `unknown` is true when an id was given that is not among them: then `alert` is null."""
    shown = labs.context().shown_alerts()
    auto = pick(shown)
    asked = next((a for a in shown if a.alert_id == alert), None) if alert else None
    a = asked if alert else auto
    return {"words": WORDS, "steps": STEPS, "alert": _row(a), "chosen": asked is not None, "unknown": bool(alert) and asked is None,
            "others": [_row(x) for x in sorted(shown, key=lambda x: (str(x.time), str(x.alert_id))) if x is not a][:MORE]}
