"""Lab "Around this moment" (night 2026-11-23, night-explain): everything recorded on one machine within
±N seconds of an alert or an event, grouped by process, with the clicked item highlighted.

    GET /api/labs/moment?alert=<id>&seconds=30
    GET /api/labs/moment?event=<event key>&seconds=30

Read-only over the event store. Times are when each event HAPPENED (Sysmon's UtcTime; the logged time when
there is none), as the detection engine and the graph use them; never compared across machines (DESIGN 4.4).
The lab's own test machinery (engine/labs/_shared_defs.py: our tools, the launcher, the VM's helper programs, the
report back to the laptop) is included and marked, so the page can hide it without
pretending they were not recorded. A window holding more than MAX_ROWS events is cut, and says so.

Switch off: delete this file (and dashboard/src/labs/moment/).
"""

import ntpath
import sqlite3
from datetime import timedelta

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.graph import parse_time
from engine.report import AGENT_EVENT_NAMES, EVENT_NAMES

from . import _shared_defs as sd
from ._explain_common import PICK_WORDS, picker

router = APIRouter(prefix="/api/labs/moment")

MAX_ROWS = 3000
MAX_SECONDS = 3600
MARGIN = timedelta(seconds=90)          # logged time can trail the happened time (Sysmon logs network late)

WORDS = {
    "title": "Around this moment",
    "intro": "Everything recorded on this machine just before and after the moment you picked, one row per program. "
             "Times are when each thing happened, counted from the moment.",
    "seconds": "Window",
    "zoom_in": "Zoom in",
    "zoom_out": "Zoom out",
    "reset": "Show all",
    "zoom_hint": "Scroll on the timeline to zoom, drag to move.",
    "anchor_alert": "The alert's own events",
    "anchor_event": "The event you picked",
    "alert_evidence": "Evidence of an alert",
    "own_tools": "Show the test machinery",
    "events": sd.WORDS["records"],                # the one word for recorded events, shared with the checklist
    "programs": sd.WORDS["programs"],
    "truncated": "More than {max} events in this window: the first {max} by time are shown. Pick a smaller window.",
    "empty": "Nothing was recorded on this machine in this window.",
    "machine": "the machine itself (no program named)",
    "started_by": "started by",
    "center": "Center here",
    "why": "Why?",
    "fields": "Recorded fields",
    **PICK_WORDS,
    "no_anchor": "That alert or event is not in this dashboard's stores.",
    "kinds": {"process": "program started or ended", "network": "network connection", "file": "file",
              "registry": "registry", "dns": "name lookup", "port": "listening port", "other": "other"},
}

KIND = {1: "process", 5: "process", 3: "network", 11: "file", 15: "file", 26: "file", 23: "file",
        12: "registry", 13: "registry", 14: "registry", 22: "dns"}
AGENT_KIND = {"FILE_HASH": "file", "PORT_LISTEN_START": "port", "PORT_LISTEN_STOP": "port"}
WHAT_FIELDS = ["TargetFilename", "final_path", "TargetObject", "QueryName", "DestinationHostname", "DestinationIp",
               "CommandLine", "Image"]
SHOWN_FIELDS = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "TargetFilename", "final_path",
                "TargetObject", "Details", "QueryName", "QueryResults", "DestinationIp", "DestinationPort",
                "DestinationHostname", "SourceIp", "SourcePort", "LocalIp", "LocalPort", "Protocol", "sha256",
                "Hashes", "hash_status", "ProcessId", "ParentProcessId", "IntegrityLevel", "origin"]


def _iso(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _when(row):
    return parse_time(row.get("UtcTime")) or parse_time(row.get("time"))


def kind_of(row):
    t = row.get("type")
    if t in AGENT_KIND:
        return AGENT_KIND[t]
    return KIND.get(row.get("event_id"), "other")


def name_of(row):
    t = row.get("type")
    if t in AGENT_EVENT_NAMES:
        return AGENT_EVENT_NAMES[t]
    return EVENT_NAMES.get(row.get("event_id"), f"event {row.get('event_id')}")


def what_of(row):
    """One short line for the row: what it is about (a file, an address, a key, a name...)."""
    eid = row.get("event_id")
    if eid == 1:
        return row.get("CommandLine") or row.get("Image") or ""
    if eid == 3:
        dst = row.get("DestinationHostname") or row.get("DestinationIp") or "?"
        return f"{dst}:{row.get('DestinationPort')}" if row.get("DestinationPort") not in (None, "") else str(dst)
    if eid == 5:
        return row.get("Image") or ""
    if row.get("type") in ("PORT_LISTEN_START", "PORT_LISTEN_STOP"):
        return f"{row.get('LocalIp') or ''}:{row.get('LocalPort') or ''}"
    for f in WHAT_FIELDS:
        if row.get(f) not in (None, ""):
            return str(row[f])
    return ""


def lane_of(row):
    """The program a row belongs to: its ProcessGuid; else its image and process id; else the machine."""
    g = row.get("ProcessGuid")
    if g and g.strip("{}").replace("0", "").replace("-", ""):
        return str(g).upper()          # one spelling: the store and the graph don't always agree on the case
    if row.get("Image") or row.get("ProcessId"):
        return f"{row.get('Image') or '?'}|{row.get('ProcessId') or '?'}"
    return "machine"


def counts_of(lanes, events):
    """How much happened in the window, by ONE rule shared with the checklist's "What exactly happened around it?"
    (critique-4 final walk: the two pages said 67 and 76): a program (lane) is the lab's own test machinery when
    every record of it is (sd.is_harness); those programs and their records are counted apart. It is exactly what
    this page draws with the test machinery hidden."""
    mach = {l["id"] for l in lanes if l.get("own_tool")}
    records = sum(1 for e in events if e["lane"] not in mach)
    return {"records": records, "programs": len(lanes) - len(mach),
            "machinery_records": len(events) - records, "machinery_programs": len(mach)}


def around(con, host, t0, seconds, anchor_keys=(), alert_keys=None, max_rows=MAX_ROWS):
    """Everything on `host` within ±seconds of t0 (a datetime), grouped into lanes (pure over a read-only
    connection; tests call it with fixtures). anchor_keys: highlighted; alert_keys: {key: [alert ids]}."""
    alert_keys = alert_keys or {}
    lo, hi = t0 - timedelta(seconds=seconds), t0 + timedelta(seconds=seconds)
    con.row_factory = sqlite3.Row
    q_lo, q_hi = (lo - MARGIN).strftime("%Y-%m-%dT%H:%M:%S"), (hi + MARGIN).strftime("%Y-%m-%dT%H:%M:%S~")
    cur = con.execute("SELECT * FROM events WHERE host = ? AND time >= ? AND time <= ? ORDER BY time, id",
                      (host, q_lo, q_hi))
    rows = []
    for r in cur:
        d = {k: r[k] for k in r.keys() if r[k] is not None and k != "raw_xml"}
        when = _when(d)
        if when is None or not (lo <= when <= hi):
            continue
        d["_t"] = when
        rows.append(d)
    rows.sort(key=lambda d: (d["_t"], d.get("id", 0)))
    total = len(rows)
    truncated = total > max_rows
    anchor = set(anchor_keys)
    if truncated:                       # keep the anchor's own rows, then the earliest others
        keep = [d for d in rows if d["dedup_key"] in anchor]
        rest = [d for d in rows if d["dedup_key"] not in anchor][:max(0, max_rows - len(keep))]
        rows = sorted(keep + rest, key=lambda d: (d["_t"], d.get("id", 0)))
    lanes, events = {}, []
    # a row with no ProcessGuid (e.g. a recorder row) joins the program with the same image and process id
    by_image_pid = {}
    for d in rows:
        lid = lane_of(d)
        if lid.startswith("{") and d.get("Image") and d.get("ProcessId") not in (None, ""):
            by_image_pid.setdefault((str(d["Image"]).lower(), str(d["ProcessId"])), lid)
    for d in rows:
        lid = lane_of(d)
        if not lid.startswith("{") and d.get("Image"):
            lid = by_image_pid.get((str(d["Image"]).lower(), str(d.get("ProcessId"))), lid)
        lane = lanes.setdefault(lid, {"id": lid, "image": None, "pid": None, "parent": None, "first": d["_t"],
                                      "count": 0, "anchor": False, "alerts": 0, "own_tool": True, "started_here": False})
        lane["count"] += 1
        if d.get("Image") and (lane["image"] is None or d.get("event_id") == 1):
            lane["image"] = d["Image"]
        if d.get("ProcessId") not in (None, "") and lane["pid"] is None:
            lane["pid"] = d["ProcessId"]
        if d.get("event_id") == 1:
            lane["started_here"] = True
            if d.get("ParentImage"):
                lane["parent"] = d["ParentImage"]
        harness = sd.is_harness(d)
        if not harness:
            lane["own_tool"] = False
        hit = d["dedup_key"] in anchor
        lane["anchor"] = lane["anchor"] or hit
        alerts = alert_keys.get(d["dedup_key"], [])
        lane["alerts"] += 1 if alerts else 0
        events.append({"key": d["dedup_key"], "lane": lid, "t": _iso(d["_t"]),
                       "offset": round((d["_t"] - t0).total_seconds(), 3), "event_id": d.get("event_id"),
                       "type": d.get("type"), "kind": kind_of(d), "name": name_of(d), "what": what_of(d),
                       "anchor": hit, "alerts": alerts, "own_tool": harness,
                       "fields": [[f, d[f]] for f in SHOWN_FIELDS if d.get(f) not in (None, "")]})
    out_lanes = []
    for lane in sorted(lanes.values(), key=lambda x: (not x["anchor"], x["first"])):
        img = lane["image"]
        out_lanes.append({**lane, "first": _iso(lane["first"]),
                          "label": (ntpath.basename(img) if img else None),
                          "parent": ntpath.basename(lane["parent"]) if lane["parent"] else None})
    return {"window": {"start": _iso(lo), "end": _iso(hi), "seconds": seconds, "t0": _iso(t0)},
            "lanes": out_lanes, "events": events, "total": total, "shown": len(events), "truncated": truncated,
            "counts": counts_of(out_lanes, events),
            "max_rows": max_rows}


@router.get("")
def moment(alert: str = None, event: str = None, seconds: float = 30):
    ctx = labs.context()
    seconds = max(1.0, min(float(seconds), MAX_SECONDS))
    if alert:
        a = ctx.alert(alert)
        if a is None:
            raise HTTPException(status_code=404, detail=WORDS["no_anchor"])
        t0, host, keys = parse_time(a.time), a.host, list(a.evidence)
        anchor = {"kind": "alert", "id": a.alert_id, "title": a.title, "level": a.level, "time": a.time, "host": host}
    elif event:
        ev = ctx.event(event)
        if ev is None:
            raise HTTPException(status_code=404, detail=WORDS["no_anchor"])
        t0, host, keys = _when(ev), ev.get("host"), [event]
        anchor = {"kind": "event", "id": event, "title": f"{name_of(ev)}: {what_of(ev)}", "level": None,
                  "time": _iso(t0) if t0 else None, "host": host}
    else:
        return {**picker(ctx), "words": WORDS, "anchor": None}
    if t0 is None:
        raise HTTPException(status_code=422, detail="the picked item has no readable time")
    alert_keys = {}
    for a in ctx.shown_alerts():
        if a.host == host:
            for k in a.evidence:
                alert_keys.setdefault(k, []).append(a.alert_id)
    with ctx.reading() as con:
        out = around(con, host, t0, seconds, keys, alert_keys)
    return {"words": WORDS, "anchor": anchor, **out}
