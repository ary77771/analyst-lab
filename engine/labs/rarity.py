"""First seen / rare here (Labs, night-hunt): stack counting, a classic hunting technique
(also called "least frequency of occurrence"). Count how often this machine has seen each
program, each parent -> child pair and each network destination, then read the list from the
rarest up: the one-off is where an intruder's program tends to hide among thousands of repeats.

    GET /api/labs/rarity/?kind=programs|pairs|destinations&window=7d&focus=24h&host=&include_own=false&limit=200

`window` = the period counted (counted back from the store's newest event); `focus` = "first seen
in the last <focus> of it" marks items the period had not seen before that (shown as NEW).
Rare is not bad: a monthly updater is rare too. The list says where to look first, nothing more.
Read-only; results are cached per (store size, question), so the second look is instant.
"""

import sqlite3
import threading
import time

from fastapi import APIRouter, HTTPException

from . import _huntdb as db
from . import _shared_defs as sd


def _T(con):
    """The one clock (engine/labs/_shared_defs.when): Sysmon's UtcTime when the store has it, else the record time."""
    return db.when_col(con)

router = APIRouter(prefix="/api/labs/rarity", tags=["labs: rarity"])

KINDS = {
    "programs": {"title": "Programs", "item": "Program file",
                 "explain": "How many times each program was started."},
    "pairs": {"title": "Parent → child", "item": "Started by → program",
              "explain": "How many times each program was started by each parent. A common program started by an "
                         "unusual parent shows up here even when the program itself is common."},
    "destinations": {"title": "Network destinations", "item": "Destination",
                     "explain": "How many outgoing connections went to each address and port, and from how many programs."},
}
FOCUS = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600, "7d": 7 * 24 * 3600}
BUCKETS = [(1, 1, "seen once"), (2, 5, "2-5 times"), (6, 20, "6-20 times"), (21, 100, "21-100 times"),
           (101, None, "more than 100")]
MAX_ROWS = 2000
_cache, _lock = {}, threading.Lock()


def _groups(con, kind, w, host, include_own):
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    own = db.own_filter(con, include_own)
    frm = db.events_from(con, w)
    if kind == "programs":
        sql = (f"SELECT lower(Image) AS k, MIN(Image) AS a, NULL AS b, COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, "
               f"MAX(ProcessGuid) AS guid, NULL AS extra FROM {frm} WHERE event_id = 1 AND Image IS NOT NULL AND {own}{tw}{hw} GROUP BY k")
    elif kind == "pairs":
        sql = (f"SELECT lower(COALESCE(ParentImage, '')) || ' > ' || lower(Image) AS k, MIN(ParentImage) AS a, MIN(Image) AS b, "
               f"COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, MAX(ProcessGuid) AS guid, NULL AS extra "
               f"FROM {frm} WHERE event_id = 1 AND Image IS NOT NULL AND {own}{tw}{hw} GROUP BY k")
    else:
        sql = (f"SELECT COALESCE(DestinationIp, '?') || ' ' || COALESCE(DestinationPort, '') AS k, DestinationIp AS a, "
               f"DestinationPort AS b, COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, MAX(DestinationHostname) AS guid, "
               f"COUNT(DISTINCT lower(Image)) AS extra FROM {frm} WHERE event_id = 3 AND Initiated = 'true' AND {own}{tw}{hw} "
               f"GROUP BY DestinationIp, DestinationPort")
    return list(con.execute(sql, tp + hp))


def _row(kind, g, new):
    if kind == "programs":
        cells = {"item": g["a"], "seen": g["n"]}
        pivots = [("Image", g["a"]), ("ProcessGuid", g["guid"])]
    elif kind == "pairs":
        parent = g["a"] or "(parent not recorded)"
        cells = {"item": f"{db.basename(parent) if g['a'] else parent} → {db.basename(g['b'])}", "parent": g["a"] or "-",
                 "program": g["b"], "seen": g["n"]}
        pivots = [("ProcessGuid", g["guid"]), ("Image", g["b"])]
    else:
        ip, port = g["a"], g["b"]
        dest = f"[{ip}]:{port}" if ":" in str(ip or "") else f"{ip}:{port}"
        cells = {"item": dest, "name": g["guid"] or "-", "programs": g["extra"], "seen": g["n"]}
        pivots = [("DestinationIp", ip), ("DestinationHostname", g["guid"])]
    return {"cells": cells, "count": g["n"], "first": sd.when_text(g["first"]), "last": sd.when_text(g["last"]), "new": new,
            "pivots": [{"field": f, "value": v} for f, v in pivots if v]}


def stack(con, kind, w, focus="24h", host=None, include_own=False) -> dict:
    """Every item of `kind` in window `w`, rarest first, with the long-tail histogram."""
    if kind not in KINDS:
        raise KeyError(kind)
    if focus not in FOCUS:
        raise ValueError(f"focus must be one of {sorted(FOCUS)}")
    t0 = time.perf_counter()
    notes = []
    try:
        groups = _groups(con, kind, w, host, include_own)
    except sqlite3.OperationalError as e:
        if "no such column" not in str(e):
            raise
        groups = []
        notes.append(f"This store did not record a field this count needs ({str(e).split(':')[-1].strip()}).")
    # "new / first seen" needs a real EARLIER BASELINE: recorded activity of this kind before the focus. A
    # window that reaches back 7 days over a recording of one minute has none (critique 2026-11-24: on the S1
    # replay all 7 of 7 programs were "new"). The baseline runs from the first record actually inside the
    # period (not the period's nominal start) to the focus cut.
    recorded = [db.seconds(t) for t in (w.since, db.oldest_time(con)) if t]
    start = max(recorded) if recorded else None
    ends = [db.seconds(t) for t in (w.until, db.newest_time(con)) if t]
    end = min(ends) if ends else None
    cut = (end - FOCUS[focus]) if end is not None else None
    earliest = min((s for g in groups if (s := db.seconds(g["first"])) is not None), default=None)
    can_mark = start is not None and cut is not None and start < cut and earliest is not None and earliest < cut
    baseline = {"since": db.iso_from(start), "until": db.iso_from(cut)} if can_mark else None
    rows = []
    for g in groups:
        first = db.seconds(g["first"])
        rows.append(_row(kind, g, bool(can_mark and first is not None and first >= cut)))
    rows.sort(key=lambda r: (r["count"], not r["new"], r["first"] or ""))
    tail = [{"label": label, "items": sum(1 for r in rows if r["count"] >= lo and (hi is None or r["count"] <= hi))}
            for lo, hi, label in BUCKETS]
    if not can_mark:
        notes.append(f"No earlier recording to compare with: everything in this period was first recorded within the last "
                     f"{focus}, so nothing is called new. 'New' needs a baseline recorded before that.")
    notes.append("Rare is not the same as bad: a monthly updater is rare too. Read from the top: the one-offs are where "
                 "a planted program has the fewest repeats to hide among.")
    if kind == "destinations":
        notes.append("Addresses, not names: a name appears only when Sysmon recorded it for the connection.")
    return {"kind": kind, **KINDS[kind], "focus": focus, "can_mark_new": can_mark, "baseline": baseline, "items": len(rows),
            "events": sum(r["count"] for r in rows), "new": sum(1 for r in rows if r["new"]),
            "once": sum(1 for r in rows if r["count"] == 1), "tail": tail, "rows": rows, "notes": notes,
            "ms": round((time.perf_counter() - t0) * 1000)}


def cached_stack(con, path, kind, w, focus, host, include_own):
    key = (path, db.store_version(con), kind, w.since, w.until, focus, host, include_own)
    with _lock:
        hit = _cache.get(key)
    if hit is not None:
        return {**hit, "cached": True}
    out = stack(con, kind, w, focus, host, include_own)
    with _lock:
        if len(_cache) > 64:
            _cache.clear()
        _cache[key] = out
    return {**out, "cached": False}


@router.get("/")
def rarity(kind: str = "programs", window: str = "7d", focus: str = "24h", start: str = None, end: str = None,
           host: str = None, include_own: bool = False, limit: int = 200, new_only: bool = False,
           alert: str = None, only_alert: bool = True):
    if kind not in KINDS:
        raise HTTPException(status_code=404, detail=f"kind must be one of {sorted(KINDS)}")
    path = db.events_path()
    try:
        con = db.connect(path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        try:
            w, host, shown = db.scoped_window(con, window, start, end, host, alert, only_alert)
            out = cached_stack(con, path, kind, w, focus, host, include_own)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # with ?alert=: mark the alert's own programs and say how rare each is (critique 2: "highlight the
        # alert's programs and how rare each one is"); the shared, cached rows are copied, never changed
        progs = set((shown or {}).get("programs") or ())
        alert_items = []
        if progs and kind in ("programs", "pairs"):
            def mine(r):
                return db.low(r["cells"].get("program") if kind == "pairs" else r["cells"]["item"]) in progs
            marked = [{**r, "alert": mine(r)} for r in out["rows"]]
            alert_items = [{"item": r["cells"]["item"], "seen": r["count"], "rank": i + 1, "of": len(marked), "new": r["new"]}
                           for i, r in enumerate(marked) if r["alert"]]
            out = {**out, "rows": marked}
        rows = [r for r in out["rows"] if r["new"]] if new_only else out["rows"]
        limit = max(1, min(int(limit), MAX_ROWS))
        return {**out, **db.result_meta(con, w, host), "rows": rows[:limit], "shown_of": len(rows),
                "truncated": len(rows) > limit, "kinds": {k: v["title"] for k, v in KINDS.items()}, "alert": shown,
                "alert_items": alert_items}
    finally:
        con.close()
