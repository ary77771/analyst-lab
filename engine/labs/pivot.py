"""Labs: pivot on anything (night 2026-11-23, builder night-pivot).

Give it one thing (a program, one run of a program, a file, a SHA-256 fingerprint, an IP address, a domain,
a registry key or a user) and it shows everything the event store links to it: the events that name it,
the processes that touched it with their parents and children, every other thing those events name (each
one a new pivot) and the alerts whose evidence includes those events.

    GET /api/labs/pivot?kind=hash&value=...         everything linked to one thing
    GET /api/labs/pivot/kinds                       the kinds, with the plain word for each
    GET /api/labs/pivot/search?q=...                things whose name contains q (to start a pivot)
    GET /api/labs/pivot/starts                      the things named by the newest alerts (starting points)

VM data only (night rule 11): every answer is limited to the machines the running dashboard allows
(labs.context().hosts: the lab VM's names, unless the dashboard was started with --labs-all-hosts). There is no
switch of this lab's own.

Read only: it runs SELECTs on the read-only connection the dashboard gives (engine.labs.context()). It
grades nothing: every line is a recorded event, cited by its key. A zero parent id means the parent was
never seen (it started before the recorder): it is shown as a gap, never as a process.
"""

import json
import re
import sqlite3

from fastapi import APIRouter, HTTPException

from . import _shared_defs as sd

router = APIRouter(prefix="/api/labs/pivot")

ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"

# kind -> (plain word, [(column, how it matches)]). "nocase" = same text ignoring case (paths, names);
# "exact" = same text; "contains" = the value appears inside the column (Sysmon's "SHA256=...,MD5=...").
KINDS = {
    "program": ("program", [("Image", "nocase"), ("ParentImage", "nocase")]),
    # a run's id: Sysmon writes it in one case, the evidence graph and the recorder may use another
    "process": ("one run of a program", [("ProcessGuid", "nocase"), ("ParentProcessGuid", "nocase")]),
    "file": ("file", [("TargetFilename", "nocase"), ("Image", "nocase")]),
    "hash": ("SHA-256 fingerprint", [("sha256", "nocase"), ("Hashes", "contains")]),
    "ip": ("IP address", [("DestinationIp", "exact"), ("SourceIp", "exact"), ("LocalIp", "exact")]),
    "domain": ("domain name", [("QueryName", "nocase"), ("DestinationHostname", "nocase")]),
    "registry": ("registry key", [("TargetObject", "nocase")]),
    "user": ("user", [("User", "nocase"), ("ParentUser", "nocase")]),
}
# columns read for each matched event (only those the store has are asked for)
WANTED = ["id", "dedup_key", "host", "time", "UtcTime", "origin", "event_id", "type", "Image", "ProcessGuid", "ProcessId",
          "ParentImage", "ParentProcessGuid", "ParentProcessId", "CommandLine", "TargetFilename", "sha256", "Hashes",
          "DestinationIp", "DestinationPort", "SourceIp", "LocalIp", "LocalPort", "QueryName", "DestinationHostname",
          "TargetObject", "EventType", "User", "hash_status", "final_path"]
LIMIT = 300
ALERT_LIMIT = 200
SEARCH_COLUMNS = [("program", "Image"), ("file", "TargetFilename"), ("domain", "QueryName"), ("ip", "DestinationIp"),
                  ("registry", "TargetObject"), ("user", "User"), ("hash", "sha256")]
SHA256 = re.compile(r"SHA256=([0-9A-Fa-f]{64})")
LOCAL_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}


def _context():
    from engine import labs                     # Fable's registry (engine/labs/__init__.py)
    return labs.context()


def allowed_hosts():
    """The machines a lab may show: exactly the running dashboard's choice, labs.context().hosts (the lab VM's
    names by default; None = every machine, only on a dashboard started with --labs-all-hosts). Without a running
    dashboard (or a context that does not say): the lab VM's names, never every machine."""
    try:
        ctx = _context()
    except Exception:
        ctx = None
    if ctx is not None and hasattr(ctx, "hosts"):
        return None if ctx.hosts is None else frozenset(ctx.hosts)
    try:
        from engine.dashboard.demo_mode import VM_HOSTS
        return frozenset(VM_HOSTS)
    except Exception:
        return frozenset({"analystlab-vm"})


def host_ok(host, allowed=None):
    allowed = allowed_hosts() if allowed is None else allowed
    return allowed is None or (host or "").lower() in {h.lower() for h in allowed}


def _host_sql(allowed):
    """(" AND lower(host) IN (...)", params), or ("", []) when every host may be shown."""
    if allowed is None:
        return "", []
    hs = sorted({h.lower() for h in allowed}) or ["\x00none"]
    return f" AND lower(host) IN ({','.join('?' for _ in hs)})", hs


def columns(con) -> dict:
    """lower-case name -> the store's real column name (columns are added on first sight)."""
    try:
        return {r[1].lower(): r[1] for r in con.execute("PRAGMA table_info(events)")}
    except sqlite3.DatabaseError:
        return {}


def _q(name):
    return '"' + name.replace('"', '""') + '"'


def where_for(kind, value, cols):
    """(SQL condition, params) that finds the events naming `value` as a `kind`; None if no column fits."""
    parts, params = [], []
    for col, how in KINDS[kind][1]:
        real = cols.get(col.lower())
        if not real:
            continue
        if how == "exact":
            parts.append(f"{_q(real)} = ?")
            params.append(value)
        elif how == "nocase":
            parts.append(f"{_q(real)} = ? COLLATE NOCASE")
            params.append(value)
        else:
            parts.append(f"instr(lower({_q(real)}), ?) > 0")
            params.append(value.lower())
    if not parts:
        return None, []
    return "(" + " OR ".join(parts) + ")", params


def _base(path):
    return re.split(r"[\\/]", path or "")[-1] or (path or "")


def summary(r) -> str:
    """One plain line saying what the event records (nothing more than the row holds)."""
    who = _base(r.get("Image")) or "a program"
    pid = f" (PID {r['ProcessId']})" if r.get("ProcessId") not in (None, "") else ""
    eid, typ = r.get("event_id"), (r.get("type") or "")
    if eid == 1:
        parent = _base(r.get("ParentImage")) or "an unknown parent"
        return f"{parent} started {who}{pid}"
    if eid == 3:
        name = r.get("DestinationHostname")
        dest = (name if name not in (None, "", "-") else None) or r.get("DestinationIp") or "?"
        return f"{who}{pid} connected to {dest}:{r.get('DestinationPort') or '?'}"
    if eid == 5:
        return f"{who}{pid} ended"
    if eid == 11:
        return f"{who}{pid} created {_base(r.get('TargetFilename')) or 'a file'}"
    if eid in (12, 13, 14):
        verb = {12: "created or deleted", 13: "set", 14: "renamed"}[eid]
        return f"{who}{pid} {verb} registry key {r.get('TargetObject') or '?'}"
    if eid == 22:
        return f"{who}{pid} looked up {r.get('QueryName') or '?'}"
    if typ == "FILE_HASH":
        path = r.get("final_path") or r.get("TargetFilename")
        return f"fingerprint taken of {_base(path) or 'a file'} ({r.get('hash_status') or 'status unknown'})"
    if typ.startswith("PORT_LISTEN"):
        state = "started" if typ.endswith("START") else "stopped"
        return f"{who} {state} listening on port {r.get('LocalPort') or '?'}"
    return f"{typ or 'event'} {eid if eid is not None else ''}".strip()


def entities_of(r) -> list:
    """Every thing an event names, as [{kind, value, role}]: each one can be pivoted on again."""
    out = []

    def add(kind, value, role):
        if value not in (None, "", "-") and str(value) != ZERO_GUID:          # "-": Sysmon's "not known"
            out.append({"kind": kind, "value": str(value), "role": role})

    add("program", r.get("Image"), "program")
    add("process", r.get("ProcessGuid"), "this run")
    add("program", r.get("ParentImage"), "parent program")
    add("process", r.get("ParentProcessGuid"), "parent run")
    add("file", r.get("TargetFilename"), "file")
    add("file", r.get("final_path"), "file")
    add("hash", (r.get("sha256") or "").lower() or None, "fingerprint")
    for m in SHA256.finditer(r.get("Hashes") or ""):
        add("hash", m.group(1).lower(), "fingerprint")
    add("ip", r.get("DestinationIp"), "remote address")
    if r.get("SourceIp") not in LOCAL_IPS and r.get("event_id") == 3 and str(r.get("Initiated")).lower() == "false":
        add("ip", r.get("SourceIp"), "remote address")
    add("domain", r.get("QueryName"), "domain")
    add("domain", r.get("DestinationHostname"), "domain")
    add("registry", r.get("TargetObject"), "registry key")
    add("user", r.get("User"), "user")
    seen, uniq = set(), []
    for e in out:
        k = (e["kind"], e["value"].lower())
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return uniq


def when_order(cols):
    """The one clock (engine/labs/_shared_defs.py: Sysmon's UtcTime first, else the record time) as an ORDER BY
    expression: sd.when_sql spells both stores' times exactly as sd.when() does, so text order is time order
    (tests/labs/test_pivot.py checks it with Sysmon's and the recorder's spellings mixed)."""
    return sd.when_sql(cols)


def harness_filter(con, cols, where, params, machinery):
    """(where, params, hidden): the WHERE clause without the lab's own test machinery (unless `machinery`), and how
    many rows that hid."""
    if machinery:
        return where, params, 0
    hs, hp = sd.harness_sql(cols)
    if not hs:
        return where, params, 0
    allrows = con.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
    kept = con.execute(f"SELECT COUNT(*) FROM events WHERE {where}{hs}", params + hp).fetchone()[0]
    return where + hs, params + hp, allrows - kept


def _rows(con, cols, where, params, limit=None, order=None):
    wanted = [cols[c.lower()] for c in WANTED if c.lower() in cols]
    if "initiated" in cols:
        wanted.append(cols["initiated"])
    sql = f"SELECT {', '.join(_q(c) for c in wanted)} FROM events WHERE {where} ORDER BY {order or when_order(cols)}, id"
    if limit:
        sql += f" LIMIT {int(limit)}"
    con.row_factory = sqlite3.Row
    try:
        return [{k: row[k] for k in row.keys()} for row in con.execute(sql, params)]
    finally:
        con.row_factory = None


def _process_label(image, pid):
    return f"{_base(image) or '?'}" + (f" (PID {pid})" if pid not in (None, "") else "")


def pivot(con, alerts, kind, value, host=None, limit=LIMIT, machinery=False) -> dict:
    """Everything the store links to one thing. `alerts` = engine.alerts.Alert objects (all of them).
    Times are the one clock (sd.when); the lab's own test machinery is left out unless `machinery`."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {sorted(KINDS)}")
    value = (value or "").strip()
    if not value:
        raise ValueError("value is empty")
    if kind == "hash":
        value = value.lower()
    cols = columns(con)
    where, params = where_for(kind, value, cols)
    out = {"kind": kind, "kind_word": KINDS[kind][0], "value": value, "host": host, "total": 0, "shown": 0,
           "first": None, "last": None, "events": [], "processes": [], "parents": [], "children": [],
           "linked": [], "alerts": [], "alerts_total": 0, "gaps": [], "machinery_hidden": 0,
           "words": {"machinery_switch": sd.WORDS["harness_switch"], "machinery_hidden": sd.WORDS["harness_hidden"]}}
    if where is None:
        return out
    allowed = allowed_hosts()
    if host:
        where, params = f"{where} AND host = ?", params + [host]
    hsql, hparams = _host_sql(allowed)
    where, params = where + hsql, params + hparams
    where, params, out["machinery_hidden"] = harness_filter(con, cols, where, params, machinery)
    keys_times = con.execute(f"SELECT dedup_key, {sd.when_sql(cols)} FROM events WHERE {where}", params).fetchall()
    out["total"] = len(keys_times)
    if not keys_times:
        return out
    times = sorted(sd.when_text(t) for _, t in keys_times if t)
    out["first"], out["last"] = (times[0], times[-1]) if times else (None, None)
    rows = _rows(con, cols, where, params, limit=limit)
    out["shown"] = len(rows)

    linked = {}
    procs = {}
    for r in rows:
        ents = entities_of(r)
        out["events"].append({"key": r["dedup_key"], "time": sd.when(r), "host": r.get("host"),
                              "event_id": r.get("event_id"), "type": r.get("type"), "summary": summary(r),
                              "command_line": r.get("CommandLine"), "entities": ents})
        for e in ents:
            if e["kind"] == kind and e["value"].lower() == value.lower():
                continue
            k = (e["kind"], e["value"].lower())
            slot = linked.setdefault(k, {"kind": e["kind"], "value": e["value"], "role": e["role"], "events": 0})
            slot["events"] += 1
        guid = r.get("ProcessGuid")
        if guid and guid.upper() != ZERO_GUID:
            p = procs.setdefault(guid.lower(), {"guid": guid, "image": r.get("Image"), "pid": r.get("ProcessId"),
                                                 "host": r.get("host"), "first": sd.when(r), "events": 0})
            p["events"] += 1
            p["image"] = p["image"] or r.get("Image")
            p["pid"] = p["pid"] if p["pid"] not in (None, "") else r.get("ProcessId")
    # a run named only by its id (e.g. the recorder's fingerprint rows): its program from its own records
    for p in procs.values():
        if not p["image"] and "processguid" in cols:
            row = con.execute(f"SELECT Image, ProcessId FROM events WHERE ProcessGuid = ? COLLATE NOCASE AND Image IS NOT NULL"
                              f"{_host_sql(allowed_hosts())[0]} ORDER BY (event_id = 1) DESC, time LIMIT 1",
                              [p["guid"], *_host_sql(allowed_hosts())[1]]).fetchone()
            if row:
                p["image"], p["pid"] = row[0], p["pid"] if p["pid"] not in (None, "") else row[1]
    out["linked"] = sorted(linked.values(), key=lambda e: (-e["events"], e["kind"], e["value"].lower()))[:200]
    for p in procs.values():
        p["label"] = _process_label(p["image"], p["pid"])
    out["processes"] = sorted(procs.values(), key=lambda p: (p["first"] or "", p["guid"]))[:100]

    guids = [p["guid"].lower() for p in out["processes"]]
    if kind == "process":
        guids = sorted(set(guids) | {value.lower()})
    if guids and "processguid" in cols and "parentprocessguid" in cols:
        marks = ",".join("?" for _ in guids)
        msql, mparams = ("", []) if machinery else sd.harness_sql(cols)        # the test machinery stays out here too
        starts = _rows(con, cols, f"event_id = 1 AND lower(ProcessGuid) IN ({marks}){hsql}{msql}", guids + hparams + mparams)
        parents = {}
        for r in starts:
            pg = r.get("ParentProcessGuid")
            if not pg or pg == ZERO_GUID:
                out["gaps"].append({"what": "parent unknown",
                                    "why": f"{_process_label(r.get('Image'), r.get('ProcessId'))} has a zero parent id: "
                                           "its parent started before the recorder, so it cannot be named",
                                    "key": r["dedup_key"]})
                continue
            parents.setdefault(pg, {"guid": pg, "image": r.get("ParentImage"), "pid": r.get("ParentProcessId"),
                                    "child": r.get("ProcessGuid"), "time": sd.when(r), "key": r["dedup_key"]})
        for p in parents.values():
            p["label"] = _process_label(p["image"], p["pid"])
        out["parents"] = list(parents.values())
        kids = _rows(con, cols, f"event_id = 1 AND lower(ParentProcessGuid) IN ({marks}){hsql}{msql}",
                     guids + hparams + mparams, limit=200)
        out["children"] = [{"guid": r.get("ProcessGuid"), "image": r.get("Image"), "pid": r.get("ProcessId"),
                            "parent": r.get("ParentProcessGuid"), "time": sd.when(r), "key": r["dedup_key"],
                            "label": _process_label(r.get("Image"), r.get("ProcessId"))} for r in kids]

    keys = {k for k, _ in keys_times}
    needle = value.lower()
    for a in alerts:
        if not host_ok(a.host, allowed):
            continue
        why = None
        shared = keys.intersection(a.evidence)
        if shared:
            why = f"{len(shared)} of its evidence events name this {KINDS[kind][0]}"
        elif len(needle) >= 4 and needle in (a.title + " " + a.reason + " " +
                                            json.dumps(a.details, default=str)).lower():
            why = f"its title, reason or details mention this {KINDS[kind][0]}"
        if why:
            out["alerts"].append({"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time,
                                  "host": a.host, "rule": a.rule_id, "why": why, "shared": len(shared)})
    out["alerts"].sort(key=lambda x: x["time"], reverse=True)
    out["alerts_total"] = len(out["alerts"])
    out["alerts"] = out["alerts"][:ALERT_LIMIT]
    return out


def search(con, q, limit=40, machinery=False) -> list:
    """Things whose name contains q (ignoring case), each with how many events name it: a way in."""
    q = (q or "").strip()
    if len(q) < 2:
        return []
    cols = columns(con)
    hsql, hparams = _host_sql(allowed_hosts())
    if not machinery:
        ms, mp = sd.harness_sql(cols)
        hsql, hparams = hsql + ms, hparams + mp
    out = []
    for kind, col in SEARCH_COLUMNS:
        real = cols.get(col.lower())
        if not real:
            continue
        rows = con.execute(f"SELECT {_q(real)}, COUNT(*) FROM events WHERE instr(lower({_q(real)}), ?) > 0{hsql} "
                           f"GROUP BY lower({_q(real)}) ORDER BY COUNT(*) DESC LIMIT ?",
                           (q.lower(), *hparams, limit)).fetchall()
        out += [{"kind": kind, "kind_word": KINDS[kind][0], "value": str(v), "events": n} for v, n in rows if v]
    if re.fullmatch(r"[0-9A-Fa-f]{64}", q):
        out.insert(0, {"kind": "hash", "kind_word": KINDS["hash"][0], "value": q.lower(), "events": None})
    out.sort(key=lambda e: -(e["events"] or 10 ** 9))
    return out[:limit]


def starts(con, alerts, n=8, machinery=False) -> list:
    """The newest alerts with the things their evidence names: one click starts a pivot."""
    cols = columns(con)
    allowed = allowed_hosts()
    hsql, hparams = _host_sql(allowed)
    if not machinery:
        ms, mp = sd.harness_sql(cols)
        hsql, hparams = hsql + ms, hparams + mp
    out = []
    for a in sorted((a for a in alerts if host_ok(a.host, allowed)), key=lambda a: a.time, reverse=True)[:n]:
        keys = list(a.evidence)[:50]
        ents = []
        if keys and cols:
            marks = ",".join("?" for _ in keys)
            seen = set()
            for r in _rows(con, cols, f"dedup_key IN ({marks}){hsql}", keys + hparams):
                for e in entities_of(r):
                    if e["kind"] == "process":
                        continue
                    k = (e["kind"], e["value"].lower())
                    if k not in seen:
                        seen.add(k)
                        ents.append(e)
        out.append({"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time, "entities": ents[:12]})
    return out


# -- the routes: thin wrappers over the functions above --------------------------------------------------

def _shown(ctx):
    try:
        return ctx.shown_alerts()
    except Exception:
        return ctx.alerts()


@router.get("/kinds")
def kinds():
    return [{"kind": k, "word": w} for k, (w, _) in KINDS.items()]


@router.get("")
def pivot_route(kind: str, value: str, host: str = None, limit: int = LIMIT, machinery: bool = False):
    ctx = _context()
    if kind not in KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {sorted(KINDS)}")
    try:
        con = ctx.events()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="this dashboard has no event store yet")
    try:
        return pivot(con, ctx.alerts(), kind, value, host=host or None, limit=max(1, min(limit, 2000)),
                     machinery=machinery)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        con.close()


@router.get("/search")
def search_route(q: str = "", machinery: bool = False):
    ctx = _context()
    try:
        con = ctx.events()
    except FileNotFoundError:
        return []
    try:
        return search(con, q, machinery=machinery)
    finally:
        con.close()


@router.get("/starts")
def starts_route(machinery: bool = False):
    ctx = _context()
    try:
        con = ctx.events()
    except FileNotFoundError:
        return []
    try:
        return starts(con, _shown(ctx), machinery=machinery)
    finally:
        con.close()
