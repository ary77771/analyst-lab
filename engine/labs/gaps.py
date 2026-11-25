"""Gap explorer (Labs, night-hunt): an honest list of what the recorder could NOT see.

Every investigation has blind spots; saying where they are is part of the answer. The gap kinds
use the evidence graph's own names (engine/graph.py: parent_unknown, origin_unknown,
actor_unknown, content_unknown) and add the recording's own holes:

    parent_unknown    a program start whose parent is all zeros: it started before Sysmon ran
                      (a gap, never a process)
    origin_unknown    a process seen acting (or as a parent) whose own start is not recorded
    actor_unknown     an event Sysmon could not pin to any process (all-zero ProcessGuid)
    content_unknown   a new program/script file whose fingerprint could not be taken
    missing_records   Windows numbered events that never reached the store
    silences          stretches with no events at all (off, asleep, or the recorder down)
    paused            the user paused the recording: only number, time and type were kept
    unreadable        events whose XML could not be read
    sysmon_errors     Sysmon itself reported an error (event 255)

    GET /api/labs/gaps/?window=24h[&start=&end=&host=&silence_minutes=10]
"""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from . import _huntdb as db

router = APIRouter(prefix="/api/labs/gaps", tags=["labs: gaps"])

ROWS = 200
# the all-zero GUID as Sysmon writes it (with and without braces, any case of the hex is the same digits),
# matched exactly so the ProcessGuid / ParentProcessGuid indexes can be used
ZEROS = "'', '{00000000-0000-0000-0000-000000000000}', '00000000-0000-0000-0000-000000000000'"
_cache, _lock = {}, threading.Lock()

KINDS = {
    "parent_unknown": ("Started before the recorder: parent unknown",
                       "These programs' start records name an all-zero parent: they started before Sysmon was running "
                       "(usually at boot). Who started them cannot be known from this recording. It is a gap, not a process."),
    "origin_unknown": ("Seen acting, but the start was never recorded",
                       "These processes made connections, wrote files or started other programs, but their own start is not "
                       "in the recording: they were already running when recording began, or started while it was off."),
    "actor_unknown": ("Events with no acting program",
                      "Sysmon could not pin these events to any process (all-zero ProcessGuid), usually the kernel or System. "
                      "The object (file, key, address) is real; the actor is not known."),
    "content_unknown": ("Files whose fingerprint could not be taken",
                        "A new program or script file was seen, but the agent could not read it to take its SHA-256 "
                        "(locked, deleted too fast, or a folder). What was inside is unknown."),
    "missing_records": ("Windows records that never reached the store",
                        "Windows numbers every Sysmon event. A jump in the numbers means events were written but never "
                        "arrived here: written before the recorder started reading (a machine's boot, a live session "
                        "started 'from now'), dropped, the log rolled over before the agent read it, or left out when "
                        "this store was built from a selection of event types."),
    "record_restarts": ("Record numbers that started again",
                        "The numbers went backwards: the log was cleared, or a test machine went back to a snapshot. "
                        "Not a loss by itself, but the numbering cannot vouch for completeness across it."),
    "silences": ("Silent stretches",
                 "No event at all for a long time. The machine may have been off or asleep, or the recorder down: "
                 "this recording alone cannot tell which, unless a restart record closes the silence."),
    "paused": ("Recording paused by the user",
               "During a pause only each event's number, time and type are kept; everything else was left out on purpose."),
    "unreadable": ("Events that could not be read",
                   "The event arrived but its content could not be parsed; it is kept as raw text only."),
    "sysmon_errors": ("Sysmon reported an error",
                      "Sysmon itself said something went wrong (event 255); events around it may be missing."),
}
ORDER = list(KINDS)


def _base(con, w, host, extra):
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    return f"FROM {db.events_from(con, w)} WHERE {extra}{tw}{hw}", tp + hp


def _row(cells, count=None, first=None, last=None, pivots=()):
    return {"cells": cells, "count": count, "first": first, "last": last,
            "pivots": [{"field": f, "value": v} for f, v in pivots if v]}


def _chunks(items, n=400):
    items = list(items)
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _started(con, guids):
    """The subset of `guids` that have a recorded start (event 1) anywhere in the store (_huntdb.started_guids:
    one pass over the starts; looking each up by ProcessGuid read every row of busy processes, 24.6 s)."""
    return set(guids) & db.started_guids(con)


def parent_unknown(con, w, host):
    frm, p = _base(con, w, host, f"event_id = 1 AND (ParentProcessGuid IS NULL OR ParentProcessGuid IN ({ZEROS}))")
    rows = [_row({"program": r["image"], "starts": r["n"]}, r["n"], r["first"], r["last"], [("Image", r["image"]), ("ProcessGuid", r["guid"])])
            for r in con.execute(f"SELECT lower(Image) AS li, MIN(Image) AS image, COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last, "
                                 f"MAX(ProcessGuid) AS guid {frm} GROUP BY li ORDER BY n DESC", p)]
    return rows, [("program", "Program"), ("starts", "Starts")], sum(r["count"] for r in rows)


def origin_unknown(con, w, host, cap=5000):
    """Processes acting in the window (any event but a start) or named as a parent, with no recorded start."""
    frm, p = _base(con, w, host, "event_id != 1 AND ProcessGuid IS NOT NULL AND ProcessGuid != ''")
    acting = {}
    for r in con.execute(f"SELECT ProcessGuid AS g, MIN(Image) AS image, COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last {frm} "
                         f"GROUP BY g LIMIT {cap + 1}", p):
        if not db.is_zero_guid(r["g"]):
            acting[r["g"]] = {"image": r["image"], "n": r["n"], "first": r["first"], "last": r["last"], "as": "acting"}
    frm1, p1 = _base(con, w, host, "event_id = 1 AND ParentProcessGuid IS NOT NULL AND ParentProcessGuid != ''")
    for r in con.execute(f"SELECT ParentProcessGuid AS g, MIN(ParentImage) AS image, COUNT(*) AS n, MIN(time) AS first, "
                         f"MAX(time) AS last {frm1} GROUP BY g LIMIT {cap + 1}", p1):
        if not db.is_zero_guid(r["g"]) and r["g"] not in acting:
            acting[r["g"]] = {"image": r["image"], "n": r["n"], "first": r["first"], "last": r["last"], "as": "parent"}
    capped = len(acting) > cap
    known = _started(con, acting)
    by_image = {}
    for g, a in acting.items():
        if g in known:
            continue
        b = by_image.setdefault(db.low(a["image"]) or "?", {"image": a["image"] or "(no program name recorded)", "procs": 0, "events": 0,
                                                             "first": a["first"], "last": a["last"], "guid": g, "as": set()})
        b["procs"] += 1
        b["events"] += a["n"]
        b["first"], b["last"] = min(b["first"], a["first"]), max(b["last"], a["last"])
        b["as"].add(a["as"])
    rows = [_row({"program": b["image"], "processes": b["procs"], "seen_as": " and ".join(sorted(b["as"])), "events": b["events"]},
                 b["procs"], b["first"], b["last"], [("Image", b["image"]), ("ProcessGuid", b["guid"])])
            for b in sorted(by_image.values(), key=lambda b: -b["procs"])]
    note = f"Only the first {cap} processes of the window were checked." if capped else None
    return rows, [("program", "Program"), ("processes", "Processes"), ("seen_as", "Seen as"), ("events", "Events")], \
        sum(r["count"] for r in rows), note


EVENT_WORDS = {3: "network connection", 11: "file created", 12: "registry key", 13: "registry value", 14: "registry rename",
               22: "name lookup", 23: "file deleted", 26: "file deleted", 15: "download marker", 5: "program ended"}


def actor_unknown(con, w, host):
    frm, p = _base(con, w, host, f"event_id != 1 AND ProcessGuid IN ({ZEROS})")
    rows = [_row({"event": EVENT_WORDS.get(r["e"], f"event {r['e']}"), "events": r["n"], "example": r["ex"]}, r["n"], r["first"], r["last"])
            for r in con.execute(f"SELECT event_id AS e, COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last, "
                                 f"MAX(COALESCE(TargetFilename, TargetObject, DestinationIp, QueryName)) AS ex {frm} GROUP BY e ORDER BY n DESC", p)]
    return rows, [("event", "What happened"), ("events", "Events"), ("example", "Example object")], sum(r["count"] for r in rows)


def content_unknown(con, w, host):
    if not db.has(con, "hash_status"):
        return [], [("file", "File")], 0
    frm, p = _base(con, w, host, "type = 'FILE_HASH' AND COALESCE(hash_status, '') NOT IN ('ok', 'directory')")
    rows = [_row({"file": r["f"], "why": r["s"] or "unknown"}, 1, r["t"], r["t"], [("TargetFilename", r["f"]), ("ProcessGuid", r["g"])])
            for r in con.execute(f"SELECT TargetFilename AS f, hash_status AS s, time AS t, ProcessGuid AS g {frm} ORDER BY time LIMIT {ROWS + 1}", p)]
    total = con.execute(f"SELECT COUNT(*) {frm}", p).fetchone()[0]
    return rows, [("file", "File"), ("why", "Agent's reason")], total


RESTART_DROP = 1000   # numbers falling back by more than this also start a new run (a cleared log)


def records(con, w, host):
    """Holes in the Sysmon record numbers, per host. In time order the numbers are split into runs
    where the numbering started again: a number seen a second time (a test machine back at a
    snapshot re-uses its numbers; a cleared log starts at 1 again). Inside a run the numbers are
    sorted, so a record written late (measured on the laptop: up to ~150 numbers behind, network
    events are reported late) fills its place instead of being counted as lost."""
    frm, p = _base(con, w, host, "record_id IS NOT NULL AND channel = ?")
    runs, restarts, state = [], [], {}
    cur = con.cursor()
    cur.row_factory = None                           # plain tuples: every Sysmon record of the window is read
    for h, rid, t in cur.execute(f"SELECT host, record_id, time {frm} ORDER BY time", [db.SYSMON] + p):
        st = state.get(h)
        if st is None or rid in st["ids"] or rid < st["hi"] - RESTART_DROP:
            if st is not None:
                restarts.append(_row({"host": h, "from_record": st["hi"], "to_record": rid}, 1, st["last"], t))
            st = state[h] = {"hi": rid, "ids": {}, "last": t}
            runs.append((h, st["ids"]))
        st["ids"].setdefault(rid, t)
        st["hi"], st["last"] = max(st["hi"], rid), t
    missing = []
    for h, ids in runs:
        order = sorted(ids)
        for a, b in zip(order, order[1:]):
            if b - a > 1:
                missing.append(_row({"host": h, "after_record": a, "next_record": b, "missing": b - a - 1}, b - a - 1, ids[a], ids[b]))
    return missing, restarts


def _mark_boots(con, w, host, holes):
    """Say for each hole whether the machine (re)started inside it: then the records may have been
    written before the recorder was reading, not lost while it was."""
    if not holes:
        return
    frm, p = _base(con, w, host, "event_id = 4 AND State = 'Started'")
    try:
        boots = sorted(t for (t,) in con.execute(f"SELECT time {frm}", p))
    except sqlite3.OperationalError:
        boots = []
    import bisect
    for h in holes:
        i = bisect.bisect_left(boots, h["first"] or "")
        inside = i < len(boots) and boots[i] <= (h["last"] or "")
        h["cells"]["around"] = "a restart: may be from before the recorder was reading" if inside else "no restart recorded"


def _holes_note(holes):
    """Many small holes = a store that keeps only some event types (measured: the 'learn' VM store has
    21 597 holes of 2-3 records; the live store it came from has 3, all across restarts)."""
    if len(holes) < 100:
        return None
    sizes = sorted(h["count"] for h in holes)
    if sizes[len(sizes) // 2] > 5:
        return None
    return (f"{len(holes):,} small holes (half of them {sizes[len(sizes) // 2]} records or fewer): this pattern usually means "
            "the store keeps only some kinds of events (built for a purpose from a larger recording), not that events were lost.")


def silences(con, w, host, minutes):
    """Stretches longer than `minutes` without any event; closed by a Sysmon start (event 4) = a restart."""
    frm, p = _base(con, w, host, "time IS NOT NULL")
    out, prev_t, prev_s, gap = [], None, None, minutes * 60
    cur = con.cursor()
    cur.row_factory = None                           # plain tuples: every event of the window is read
    for t, event_id, state in cur.execute(f"SELECT time, event_id, State {frm} ORDER BY time", p):
        s = db.fast_seconds(t)
        if s is None:
            continue
        if prev_s is not None and s - prev_s > gap:
            restart = event_id == 4 and (state or "") == "Started"
            out.append(_row({"length": _dur(s - prev_s), "seconds": round(s - prev_s),
                             "ended_by": "a restart (Sysmon started)" if restart else "events again (cause unknown)"},
                            round(s - prev_s), prev_t, t))
        prev_t, prev_s = t, s
    return out


def _dur(s):
    if s >= 86400:
        return f"{s / 86400:.1f} days"
    if s >= 3600:
        return f"{s / 3600:.1f} h"
    return f"{s / 60:.0f} min"


def paused(con, w, host):
    if not db.has(con, "paused"):
        return [], 0
    frm, p = _base(con, w, host, "paused = 1")
    r = con.execute(f"SELECT COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last {frm}", p).fetchone()
    if not r["n"]:
        return [], 0
    return [_row({"events": r["n"], "what": "number, time and type only"}, r["n"], r["first"], r["last"])], r["n"]


def unreadable(con, w, host):
    if not db.has(con, "parse_error"):
        return [], 0
    frm, p = _base(con, w, host, "parse_error IS NOT NULL")
    rows = [_row({"reason": r["e"][:160], "events": r["n"]}, r["n"], r["first"], r["last"])
            for r in con.execute(f"SELECT parse_error AS e, COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last {frm} "
                                 f"GROUP BY e ORDER BY n DESC LIMIT {ROWS}", p)]
    return rows, sum(r["count"] for r in rows)


def sysmon_errors(con, w, host):
    frm, p = _base(con, w, host, "event_id = 255")
    col = "Description" if db.has(con, "Description") else "NULL"
    rows = [_row({"message": (r["d"] or "(no message)").strip()[:200], "events": r["n"]}, r["n"], r["first"], r["last"])
            for r in con.execute(f"SELECT {col} AS d, COUNT(*) AS n, MIN(time) AS first, MAX(time) AS last {frm} "
                                 f"GROUP BY d ORDER BY n DESC LIMIT {ROWS}", p)]
    return rows, sum(r["count"] for r in rows)


WORKERS = 4      # sections read the store side by side, each on its own read-only connection


def _records_marked(con, w, host):
    found = records(con, w, host)
    _mark_boots(con, w, host, found[0])
    return found


def _run_sections(con, path, jobs, w, host):
    """{name: result or None (an older store without a column it needs)}. With the store's `path`, the sections
    run at the same time on their own connections (speed audit 2026-11-24: each reads the whole window, one after
    another they took 6 s for one day of the 2.4 GB laptop store); SQLite reads in parallel without the GIL."""
    def one(fn):
        c = db.connect(path) if path else con
        try:
            return fn(c, w, host)
        except sqlite3.OperationalError as e:
            if "no such column" not in str(e):
                raise
            return None
        finally:
            if c is not con:
                c.close()
    if not path:
        return {k: one(fn) for k, fn in jobs.items()}
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {k: ex.submit(one, fn) for k, fn in jobs.items()}
        return {k: f.result() for k, f in futures.items()}


def explore(con, w, host=None, silence_minutes=10, path=None) -> dict:
    """Every gap kind for the window. `path` = the store file: the sections then run side by side."""
    t0 = time.perf_counter()
    sections = {}

    def add(kind, rows, columns, total, note=None):
        title, plain = KINDS[kind]
        sections[kind] = {"id": kind, "title": title, "plain": plain, "total": total, "items": len(rows),
                          "rows": rows[:ROWS], "truncated": len(rows) > ROWS,
                          "columns": [{"key": k, "label": l} for k, l in columns], "note": note}

    # the slowest first, so they start at once
    got = _run_sections(con, path, {
        "origin_unknown": origin_unknown, "records": _records_marked,
        "silences": lambda c, w, h: silences(c, w, h, silence_minutes),
        "parent_unknown": parent_unknown, "actor_unknown": actor_unknown, "content_unknown": content_unknown,
        "paused": paused, "unreadable": unreadable, "sysmon_errors": sysmon_errors}, w, host)
    r = got["parent_unknown"]
    add("parent_unknown", *(r or ([], [("program", "Program")], 0)))
    r = got["origin_unknown"]
    add("origin_unknown", *(r[:3] if r else ([], [("program", "Program")], 0)), note=r[3] if r else None)
    r = got["actor_unknown"]
    add("actor_unknown", *(r or ([], [("event", "What happened")], 0)))
    r = got["content_unknown"]
    add("content_unknown", *(r or ([], [("file", "File")], 0)))
    miss, rest = got["records"] or ([], [])
    add("missing_records", sorted(miss, key=lambda x: -x["count"]),
        [("host", "Machine"), ("after_record", "After record"), ("next_record", "Next record"), ("missing", "Missing"),
         ("around", "Around it")], sum(x["count"] for x in miss), note=_holes_note(miss))
    add("record_restarts", rest, [("host", "Machine"), ("from_record", "From record"), ("to_record", "Back to")], len(rest))
    sil = got["silences"] or []
    add("silences", sorted(sil, key=lambda x: -x["count"]), [("length", "Length"), ("ended_by", "Ended by")], len(sil),
        note=f"Silences longer than {silence_minutes} minutes; together {_dur(sum(x['count'] for x in sil))}." if sil else None)
    rows, n = got["paused"] or ([], 0)
    add("paused", rows, [("events", "Events"), ("what", "What was kept")], n)
    rows, n = got["unreadable"] or ([], 0)
    add("unreadable", rows, [("reason", "Why"), ("events", "Events")], n)
    rows, n = got["sysmon_errors"] or ([], 0)
    add("sysmon_errors", rows, [("message", "Sysmon's message"), ("events", "Events")], n)
    out = [sections[k] for k in ORDER]
    return {"sections": out, "kinds_with_gaps": sum(1 for s in out if s["total"]), "silence_minutes": silence_minutes,
            "ms": round((time.perf_counter() - t0) * 1000)}


@router.get("/")
def gaps(window: str = "24h", start: str = None, end: str = None, host: str = None, silence_minutes: int = 10,
         alert: str = None, only_alert: bool = True):
    if not 1 <= silence_minutes <= 24 * 60:
        raise HTTPException(status_code=400, detail="silence_minutes must be between 1 and 1440")
    path = db.events_path()
    try:
        con = db.connect(path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        try:
            w, host, shown = db.scoped_window(con, window, start, end, host, alert, only_alert)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        sw, sp = db.scope_sql()
        key = (path, db.store_version(con), sw, tuple(sp), w.since, w.until, host, silence_minutes)
        with _lock:
            out = _cache.get(key)
        if out is None:
            out = explore(con, w, host, silence_minutes, path=path)
            with _lock:
                if len(_cache) > 32:
                    _cache.clear()
                _cache[key] = out
        return {**out, **db.result_meta(con, w, host), "alert": shown}
    finally:
        con.close()
