"""The example lab, and a useful one: "what is in this store" in a few counted numbers.

Copy this file to start a lab: one APIRouter under /api/labs/<this file's name>, and `labs.context()` for
reading the running dashboard's stores. Only counts leave here: no names, no paths, no command lines.
"""

import sqlite3

from fastapi import APIRouter

from engine import labs

router = APIRouter(prefix="/api/labs/glance")

WORDS = {
    "title": "This store at a glance",
    "intro": "Counted from the event store and the alert database this dashboard is reading. Nothing here is a judgement.",
    "events": "recorded events", "hosts": "machines", "programs": "programs started", "alerts": "alerts raised",
    "shown": "at or above the level the screens show", "span": "first to last record", "levels": "Alerts by level",
    "empty": "The event store is empty or not there yet.",
}


@router.get("")
def glance():
    ctx = labs.context()
    out = {"words": WORDS, "events": 0, "hosts": 0, "programs": 0, "first": None, "last": None, "empty": True}
    try:
        with ctx.reading() as con:
            n, hosts, first, last = con.execute("SELECT COUNT(*), COUNT(DISTINCT host), MIN(time), MAX(time) FROM events").fetchone()
            programs = con.execute("SELECT COUNT(*) FROM events WHERE event_id = 1").fetchone()[0]
            out.update(events=n or 0, hosts=hosts or 0, programs=programs or 0, first=first, last=last, empty=not n)
    except (FileNotFoundError, sqlite3.OperationalError):
        pass
    alerts = ctx.alerts()
    levels = {}
    for a in alerts:
        levels[a.level] = levels.get(a.level, 0) + 1
    from engine.alerts import LEVELS
    out.update(alerts=len(alerts), shown=len(ctx.shown_alerts()), min_level=ctx.min_level(),
               levels=[{"level": lv, "count": levels[lv]} for lv in LEVELS if lv in levels])
    return out
