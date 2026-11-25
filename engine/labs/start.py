"""Lab "I have an alert" (night 2026-11-24, night-explain; VISION's W3-3): the investigation's front door. Pick an
alert (the same alert repeated is shown once, with how many times and since when), then six questions as a
numbered path, each with a one-line answer taken from the lab that owns it and an "open" link to that lab.

    GET /api/labs/start                 the shown alerts, grouped (title + rule), newest occurrence first
    GET /api/labs/start/{alert_id}      the six steps for one alert

Each answer is computed by the owning lab's own code (why, moment, the report, checklist, prove, respond), called
in-process and read-only; a lab that is missing or fails gives "not checked" for its step, never a guess. Every
line carries a status word (Proven / Suspected / Can't be known / Nothing recorded / Not checked).

Switch off: delete this file (and dashboard/src/labs/start/).
"""

from fastapi import APIRouter, HTTPException

from engine import labs

from ._explain_common import alert_row
from ._triage import WORDS, groups, steps

router = APIRouter(prefix="/api/labs/start")


@router.get("")
def pick():
    ctx = labs.context()
    return {"words": WORDS, "groups": groups(ctx.shown_alerts())}


@router.get("/{alert_id}")
def start(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    same = [x for x in ctx.shown_alerts() if x.title == a.title and x.rule_id == a.rule_id]
    return {"words": WORDS, "alert": alert_row(a), "repeats": len(same), "steps": steps(ctx, a)}
