"""Persistence before/after (Labs, night-hunt): an Autoruns-style list of what starts by itself,
rebuilt from the recorded events, and what changed inside a chosen time window (e.g. a test).

Autoruns (Sysinternals) reads the live registry and disk; we cannot, we only have the recording.
So the list is REPLAYED: every recorded write to an autostart place is applied in time order
(SetValue = the entry is there with this value, DeleteValue/DeleteKey = gone; a file created in the
Startup folder = there, deleted = gone; `schtasks /create` / `/delete` = a task there / gone).
"Before" is the replay up to the window's start, "after" up to its end; the difference is what the
window changed.

    GET /api/labs/persistence/?window=24h | &start=ISO&end=ISO  [&host=&include_own=false]

Honest limits (returned as `not_seen`): entries that existed before recording began and were never
written since are invisible; places the Sysmon config does not watch are invisible.
"""

import re
import sqlite3
import threading
import time

from fastapi import APIRouter, HTTPException

from . import _huntdb as db

router = APIRouter(prefix="/api/labs/persistence", tags=["labs: persistence"])

START_MODES = {"0": "boot", "1": "system", "2": "automatic", "3": "manual", "4": "disabled",
               "DWORD (0x00000000)": "boot", "DWORD (0x00000001)": "system", "DWORD (0x00000002)": "automatic",
               "DWORD (0x00000003)": "manual", "DWORD (0x00000004)": "disabled"}
NOT_SEEN = [
    "Entries that existed before the recording began and were never written since: the list starts empty and only "
    "grows from what was recorded.",
    "Scheduled tasks made through the Task Scheduler API (not schtasks.exe or PowerShell), and every task's later runs.",
    "WMI event subscriptions, COM object hijacks, Image File Execution Options debuggers, AppInit_DLLs and browser "
    "extensions: the Sysmon config does not watch these places.",
    "Changes made while the recorder was off, asleep or paused.",
    "A test machine going back to a snapshot undoes entries without any recorded write. The replay cannot see "
    "that undo, so an entry a test creates again shows as 'rewritten', not 'added'.",
]
_TN = re.compile(r'/tn\s+("([^"]+)"|(\S+))', re.I)
_cache, _lock = {}, threading.Lock()


def _task_name(cmd):
    m = _TN.search(cmd or "")
    return (m.group(2) or m.group(3)) if m else None


def _changes(con, host=None, include_own=False, until=None):
    """Every recorded write to an autostart place up to `until`, in time order, as
    (time, key, kind, place, name, value or None for "gone", by_image, by_guid, what)."""
    own = db.own_filter(con, include_own)
    hw, hp = db.host_filter(host)
    uw, up = (" AND time <= ?", [until]) if until else ("", [])
    out = []
    cols = db.columns(con)
    # the whole history up to `until`: read by event type (autostart writes are few), never through
    # the time index (a range over nearly all of a multi-GB store)
    ev = "events INDEXED BY idx_events_event_id" if db.has_index(con, "idx_events_event_id") else "events"
    if {"targetobject", "eventtype"} <= cols:
        for r in con.execute(f"SELECT time, EventType, TargetObject, Details, Image, ProcessGuid FROM {ev} "
                             f"WHERE event_id IN (12, 13, 14) AND TargetObject IS NOT NULL AND {own}{hw}{uw}", hp + up):
            obj, et = r["TargetObject"], (r["EventType"] or "")
            kind = db.autostart_kind(obj)
            if kind == "Service" and db.low(obj).endswith("\\start"):
                kind = "Service start mode"
            place, _, name = obj.rpartition("\\")
            if et == "SetValue":
                value = r["Details"] or ""
                if kind == "Service start mode":
                    value = START_MODES.get(value.strip(), value)
                out.append((r["time"], ("reg", db.low(obj)), kind, place, name, value, r["Image"], r["ProcessGuid"], "value set"))
            elif et == "DeleteValue":
                out.append((r["time"], ("reg", db.low(obj)), kind, place, name, None, r["Image"], r["ProcessGuid"], "value deleted"))
            elif et == "DeleteKey":
                out.append((r["time"], ("regkey", db.low(obj)), kind, obj, "(whole key)", None, r["Image"], r["ProcessGuid"], "key deleted"))
            elif et == "RenameKey":
                out.append((r["time"], ("regkey", db.low(obj)), kind, obj, "(whole key)", None, r["Image"], r["ProcessGuid"], "key renamed"))
            # CreateKey: an empty key starts nothing; not an entry
    if "targetfilename" in cols:
        for r in con.execute(f"SELECT time, event_id, TargetFilename, Image, ProcessGuid FROM {ev} WHERE event_id IN (11, 23, 26) "
                             f"AND TargetFilename LIKE '%\\Start Menu\\Programs\\Startup\\%' AND {own}{hw}{uw}", hp + up):
            place, _, name = r["TargetFilename"].rpartition("\\")
            gone = r["event_id"] != 11
            out.append((r["time"], ("file", db.low(r["TargetFilename"])), "Startup folder", place, name,
                        None if gone else "(file)", r["Image"], r["ProcessGuid"], "file deleted" if gone else "file created"))
    if "commandline" in cols:
        for r in con.execute(f"SELECT time, CommandLine, ParentImage, ProcessGuid FROM {ev} WHERE event_id = 1 "
                             f"AND Image LIKE '%\\schtasks.exe' AND (CommandLine LIKE '%/create%' OR CommandLine LIKE '%/delete%') "
                             f"AND {own}{hw}{uw}", hp + up):
            name = _task_name(r["CommandLine"]) or "(name not given)"
            delete = "/delete" in db.low(r["CommandLine"])
            out.append((r["time"], ("task", db.low(name).lstrip("\\")), "Scheduled task", "Task Scheduler", name,
                        None if delete else r["CommandLine"], r["ParentImage"], r["ProcessGuid"],
                        "task deleted" if delete else "task created"))
    out.sort(key=lambda c: c[0] or "")
    return out


def replay(changes, until=None):
    """The entries present after applying `changes` up to `until` (inclusive): {key: entry}."""
    state = {}
    for t, key, kind, place, name, value, by, guid, what in changes:
        if until is not None and t > until:
            break
        if key[0] == "regkey":                            # a deleted key takes every value under it
            prefix = key[1] + "\\"
            for k in [k for k in state if k[0] == "reg" and (k[1].startswith(prefix) or k[1] == key[1])]:
                del state[k]
            continue
        if value is None:
            state.pop(key, None)
        else:
            state[key] = {"kind": kind, "place": place, "name": name, "value": value, "by": by, "guid": guid, "since": t,
                          "first": state.get(key, {}).get("first", t)}
    return state


def _entry(e, status, before=None):
    out = {"cells": {"kind": e["kind"], "place": e["place"], "name": e["name"], "value": e["value"],
                     "before": before if before is not None else "-", "by": db.basename(e["by"]) or "unknown", "status": status},
           "count": None, "first": e["first"], "last": e["since"], "status": status, "writer": db.low(e["by"]),
           "pivots": [{"field": "ProcessGuid", "value": e["guid"]}] if e.get("guid") else []}
    if e["kind"] not in ("Startup folder", "Scheduled task"):
        out["pivots"].insert(0, {"field": "TargetObject", "value": f"{e['place']}\\{e['name']}"})
    elif e["kind"] == "Startup folder":
        out["pivots"].insert(0, {"field": "TargetFilename", "value": f"{e['place']}\\{e['name']}"})
    return out


def compare(con, w, host=None, include_own=False) -> dict:
    t0 = time.perf_counter()
    try:
        changes = _changes(con, host, include_own, until=w.until)
    except sqlite3.OperationalError as e:
        if "no such column" not in str(e):
            raise
        changes = []
    before = replay(changes, w.since) if w.since else {}
    after = replay(changes)
    # a REAL "before" needs recording from before the window. A store that starts inside it (the live
    # store starts at boot) has an empty "before" by construction: its entries are "first seen in this
    # recording", never "added" (critique 2026-11-24: the live store said "55 added").
    hw, hp = db.host_filter(host)
    has_before = bool(w.since) and con.execute(
        f"SELECT 1 FROM events WHERE time < ?{hw} LIMIT 1", [w.since] + hp).fetchone() is not None
    new_word = "added" if has_before else "first_seen"
    rows = []
    for k, e in after.items():
        b = before.get(k)
        if b is None:
            rows.append(_entry(e, new_word))
        elif b["value"] != e["value"]:
            rows.append(_entry(e, "changed", before=b["value"]))
        elif w.since and e["since"] >= w.since:
            # written again with the same value inside the window: on a test machine that went back to a
            # snapshot this is usually the test creating it anew (the undo left no record)
            rows.append(_entry(e, "rewritten", before=b["value"]))
        else:
            rows.append(_entry(e, "unchanged"))
    for k, b in before.items():
        if k not in after:
            gone = dict(b)
            rows.append(_entry(gone, "removed"))
    in_window = [c for c in changes if (not w.since or c[0] >= w.since)]
    order = {"added": 0, "first_seen": 0, "changed": 1, "rewritten": 2, "removed": 3, "unchanged": 4}
    rows.sort(key=lambda r: (order[r["status"]], r["cells"]["kind"] == "Service start mode", r["cells"]["kind"], r["last"] or ""))
    log = [{"time": c[0], "kind": c[2], "place": c[3], "name": c[4], "what": c[8], "value": c[5],
            "by": db.basename(c[6]) or "unknown", "writer": db.low(c[6]),
            "pivots": [{"field": "ProcessGuid", "value": c[7]}] if c[7] else []}
           for c in in_window[-500:]]
    registry = {"targetobject", "eventtype"} <= db.columns(con)
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in order}
    return {"rows": rows, "counts": counts, "has_before": has_before,
            "before_note": None if has_before else
            "Nothing was recorded before this window, so there is no real 'before': the entries are shown as first "
            "seen in this recording, not as added.",
            "before_total": len(before), "after_total": len(after),
            "writes_in_window": len(in_window), "log": log, "log_truncated": len(in_window) > 500,
            "registry_recorded": registry,
            "not_seen": NOT_SEEN if registry else
            ["This store recorded no registry events (it is older than the registry config): Run keys, services and "
             "Winlogon entries cannot be seen here, only the Startup folder and schtasks.exe."] + NOT_SEEN,
            "ms": round((time.perf_counter() - t0) * 1000)}


@router.get("/")
def persistence(window: str = "24h", start: str = None, end: str = None, host: str = None, include_own: bool = False,
                show_unchanged: bool = False, alert: str = None, only_alert: bool = True):
    """With `alert`: before = the list at the start of the alert's run, after = at its end (what that test left
    behind) and, unless only_alert is false, only what the alert's own programs wrote."""
    path = db.events_path()
    try:
        con = db.connect(path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        scope = db.alert_scope(con, alert) if alert else None
        programs = None
        try:
            if scope and not scope.get("missing") and only_alert:   # this alert's run (and its own programs)
                w = scope["window"]
                host = scope["host"]
                programs = set(scope["programs"]) if scope["programs"] else None
            else:                                                     # "show the whole recording": the page's own window
                w = db.window(con, window, start, end)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        key = (path, db.store_version(con), w.since, w.until, host, include_own)
        with _lock:
            out = _cache.get(key)
        if out is None:
            out = compare(con, w, host, include_own)
            with _lock:
                if len(_cache) > 32:
                    _cache.clear()
                _cache[key] = out
        every, log, extra = out["rows"], out["log"], {}
        if programs is not None:
            # only what the alert's own programs wrote; EVERY count follows the same rows (critique 3: the page said
            # "0 present" next to "0 -> 55 entries" when the counts were narrowed and the totals were not)
            every = [r for r in every if r["writer"] in programs]
            log = [c for c in log if c["writer"] in programs]
            extra = {"counts": {s: sum(1 for r in every if r["status"] == s) for s in out["counts"]},
                     "writes_in_window": len(log),
                     "before_total": sum(1 for r in every if r["status"] in ("changed", "rewritten", "unchanged", "removed")),
                     "after_total": sum(1 for r in every if r["status"] != "removed")}
        rows = every if show_unchanged else [r for r in every if r["status"] != "unchanged"]
        shown = db.alert_public(scope, programs is not None, limited=only_alert)
        return {**out, **db.result_meta(con, w, host), **extra, "rows": rows[:1000], "truncated": len(rows) > 1000,
                "log": log, "alert": shown}
    finally:
        con.close()
