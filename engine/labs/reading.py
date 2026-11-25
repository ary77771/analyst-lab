"""Reading effort (Labs, night-hunt; VISION idea 4): for one alert's run on the test machine,
how many raw records a person would face (N), how many of them the story actually cites (M), and
how many steps the story found (K). The funnel, measured at request time.

It counts RECORDS, never minutes: no human reading time was ever measured, so none is claimed.

    GET /api/labs/reading/                 the alerts it can explain (the ones the screens show)
    GET /api/labs/reading/{alert_id}       N, M, K for that alert, the run window, the cited records

The run = the stretch of the machine's recording from the last Sysmon start (event 4, a boot) at or
before the alert to the next one (or to the machine's last record). A cited record from outside it (a
file written in an earlier run) is added to N one by one, so M <= N always and N is never inflated by
everything between. Only machines the dashboard allows (VM only by
default). The story's citations come from the dashboard's own report (labs.context().report).
"""

import sqlite3
import time

from fastapi import APIRouter, HTTPException

from . import _huntdb as db

router = APIRouter(prefix="/api/labs/reading", tags=["labs: reading"])

WORDS = {
    "title": "How much reading did the story save?",
    "intro": "To find out what happened without this tool, someone would read the machine's raw recording for the "
             "whole run. The story points at a handful of those records and puts them in order.",
    "n": "raw records in the run",
    "m": "records the story cites",
    "k": "steps in the story",
    "honest": "This counts records to read, not minutes saved: nobody's reading time was measured.",
    "window_boot": "From the machine's start before the alert to its next start (one test run).",
    "window_records": "From the machine's first to its last record (no start record was found around the alert).",
    "stretched": "Plus {n} cited record(s) from before or after the run (for example a file written earlier), "
                 "counted one by one.",
}


def _ctx():
    try:
        from engine import labs                                     # noqa: PLC0415
        return labs.context()
    except Exception:
        return None


def citations(content: dict) -> list:
    """Every record the story cites (the alert's own, facts, hypotheses, gaps), once each, in time order."""
    seen = {}
    groups = [(content.get("alert") or {}).get("citations") or []]
    for section in ("facts", "hypotheses", "gaps"):
        groups += [item.get("citations") or [] for item in content.get(section) or []]
    for group in groups:
        for c in group:
            if c and c.get("key") and c["key"] not in seen:
                # the report spells times '...+00:00', the store '...0000000Z': compare in the store's spelling
                t = db.parse_iso(c.get("time")) if c.get("time") else None
                seen[c["key"]] = {"key": c["key"], "event": c.get("event"), "record": c.get("record"),
                                  "time": db.iso(t) if t else c.get("time"), "text": c.get("text")}
    return sorted(seen.values(), key=lambda c: (c["time"] or "", c["key"]))


run_window = db.run_window                  # shared with network and persistence (their ?alert= view)


def effort(con, alert, content) -> dict:
    """N, M, K for one alert (any object with .host and .time) and its report content."""
    t0 = time.perf_counter()
    cited = citations(content)
    k = int((content.get("counts") or {}).get("steps") or len(content.get("timeline") or []))
    start, end, how = run_window(con, alert.host, alert.time)
    hw, hp = db.host_filter(alert.host)
    parts, params = [], []
    if start:
        parts.append("time >= ?")
        params.append(start)
    if end:
        parts.append("time < ?")
        params.append(end)
    where = " AND ".join(parts) or "1=1"
    n = con.execute(f"SELECT COUNT(*) FROM events WHERE {where}{hw}", params + hp).fetchone()[0]
    # cited records actually present in this store (a citation from another store is said, not counted)
    keys = [c["key"] for c in cited]
    present = {}
    for i in range(0, len(keys), 400):
        chunk = keys[i:i + 400]
        present.update({k_: t_ for k_, t_ in con.execute(
            f"SELECT dedup_key, time FROM events WHERE dedup_key IN ({','.join('?' for _ in chunk)}){hw}", chunk + hp)})
    for c in cited:
        c["in_store"] = c["key"] in present
    m = sum(1 for c in cited if c["in_store"])
    # a cited record from before or after the run (e.g. a file written in an earlier run) is added to N
    # one by one, never by stretching the window over everything in between (that would inflate N)
    outside = [k_ for k_, t_ in present.items() if (start and t_ < start) or (end and t_ >= end)]
    n += len(outside)
    notes = [WORDS["window_boot"] if how == "boot" else WORDS["window_records"]]
    if outside:
        notes.append(WORDS["stretched"].format(n=len(outside)))
    if m < len(cited):
        notes.append(f"{len(cited) - m} cited record(s) are not in this event store (the alert was raised on another one).")
    last = con.execute(f"SELECT MAX(time) FROM events WHERE 1=1{hw}", hp).fetchone()[0] if not end else end
    return {"n": n, "m": m, "k": k, "cited": cited, "window": {"start": start, "end": last, "how": how},
            "one_in": round(n / m) if m else None, "notes": notes, "words": WORDS,
            "ms": round((time.perf_counter() - t0) * 1000)}


def _alert_row(a):
    return {"id": a.alert_id, "title": a.title, "time": a.time, "level": a.level, "host": a.host}


@router.get("/")
def alerts():
    ctx = _ctx()
    if ctx is None:
        raise HTTPException(status_code=503, detail="no dashboard is running")
    rows = [_alert_row(a) for a in ctx.shown_alerts() if db.allowed_hosts() is None or a.host in db.allowed_hosts()]
    return {"alerts": rows[:200], "words": WORDS}


@router.get("/{alert_id}")
def reading(alert_id: str):
    ctx = _ctx()
    if ctx is None:
        raise HTTPException(status_code=503, detail="no dashboard is running")
    try:
        a = ctx.alert(alert_id)
    except PermissionError:                                   # another machine's alert: not shown here
        a = None
    allowed = db.allowed_hosts()
    if a is None or (allowed is not None and a.host not in allowed):
        raise HTTPException(status_code=404, detail="no such alert on the machines this dashboard shows")
    try:
        content = ctx.report(a)
    except Exception as e:                                   # the story can't be built: say so, never guess
        raise HTTPException(status_code=500, detail=f"the alert's story could not be built ({type(e).__name__})")
    try:
        con = db.connect(db.events_path())
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        return {"alert": _alert_row(a), **effort(con, a, content)}
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=500, detail=f"the event store could not be read ({e})")
    finally:
        con.close()
