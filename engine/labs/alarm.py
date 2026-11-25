"""Lab "This is what an alarm says" (night 2026-11-24, night-explain; VISION's idea #7): for one alert, what the
computer recorded (the raw records, in Sysmon's own field names) next to what the dashboard says in plain
words, with every word of a plain sentence that comes from a record traced to the field it came from.

    GET /api/labs/alarm                 the alerts the screens show, to pick one
    GET /api/labs/alarm/{alert_id}      the alarm (rule title, the engine's own reason), the raw records, and
                                        the story's sentences with their traces

Honest about what "raw" is: the event store keeps every field Sysmon wrote, one column per field, but not
the original XML; the page says the record is re-drawn from those stored fields. A word of a sentence is
traced only when it literally appears in a cited record's field (or is the verb for that record's event
type); everything else in the sentence is the dashboard's own wording and stays unmarked. Read-only.

Switch off: delete this file (and dashboard/src/labs/alarm/).
"""

from fastapi import APIRouter, HTTPException

from engine import labs

from ._explain_common import picker
from ._wordforword import (HEADER, HIDDEN, MAX_LINES, MAX_RECORDS, TRACE_FIELDS, VERBS, WORDS, explain,  # noqa: F401
                           record_view, story_lines, trace)

router = APIRouter(prefix="/api/labs/alarm")


@router.get("")
def pick():
    return picker(labs.context())


@router.get("/{alert_id}")
def alarm(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    return explain(ctx, a)
