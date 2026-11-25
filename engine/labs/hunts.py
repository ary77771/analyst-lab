"""Saved hunts (Labs, night-hunt): one-click questions over the event store, each with a plain
title, why an analyst cares, a result table and a count. Hunting = looking for trouble without
waiting for an alert; none of these is a detector and none raises an alert.

    GET /api/labs/hunts/                    the list of hunts
    GET /api/labs/hunts/run/{hunt_id}       one hunt's results  (?window=24h|1h|6h|7d|30d|all,
                                            &start=&end= ISO, &host=, &include_own=false, &limit=200)
    GET /api/labs/hunts/summary             every hunt's count for the window (the overview)

Read-only (engine/labs/_huntdb.py). Every query is bounded by the chosen time window, counted back
from the store's newest event. Each result row carries `pivots` ({field, value}) that the page
turns into links to the pivot page (#/labs/pivot?field=...&value=...).
"""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from . import _huntdb as db
from . import _shared_defs as sd


def _T(con):
    """The one clock (engine/labs/_shared_defs.when): Sysmon's UtcTime when the store has it, else the record time."""
    return db.when_col(con)

router = APIRouter(prefix="/api/labs/hunts", tags=["labs: hunts"])

MAX_ROWS = 1000                      # rows a hunt returns at most (the count says how many there were)
_summaries, _lock = {}, threading.Lock()   # the summary per store version and window (like gaps and network)
RUNNABLE = (".exe", ".scr", ".com")   # deleted files that can have run as a program
SCRIPT_ENGINES = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                  "rundll32.exe", "regsvr32.exe")
OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
          "mspub.exe", "visio.exe", "olk.exe")
BROWSERS = ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe")
READERS = ("acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "sumatrapdf.exe")
# Windows tools attackers like to copy under another name. Mirrors the idea of Sigma's
# "Potential Renamed Binary" rules (proc_creation_win_renamed_binary*): the file's own
# OriginalFileName (in its version info) names a known tool, the file on disk is called otherwise.
WINDOWS_TOOLS = ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe", "rundll32.exe", "regsvr32.exe",
                 "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe",
                 "reg.exe", "net.exe", "net1.exe", "wmic.exe", "msiexec.exe", "msbuild.exe", "installutil.exe",
                 "regasm.exe", "regsvcs.exe", "cmstp.exe", "forfiles.exe", "sc.exe", "at.exe", "whoami.exe",
                 "nltest.exe", "ntdsutil.exe", "vssadmin.exe", "wevtutil.exe", "curl.exe", "ftp.exe", "tar.exe",
                 "expand.exe", "extrac32.exe", "hh.exe", "odbcconf.exe", "pcalua.exe", "msdt.exe", "csc.exe",
                 "attrib.exe", "taskkill.exe", "tasklist.exe", "netsh.exe", "systeminfo.exe", "psexec.c",
                 "psexec.exe", "procdump", "7z.exe", "winrar.exe", "conhost.exe", "explorer.exe",
                 "svchost.exe", "lsass.exe", "taskhostw.exe", "dllhost.exe")
STANDARD_DIRS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
ALL_INTERFACES = ("0.0.0.0", "::", "[::]", "*")
DYNAMIC_PORTS = 49152


def _where(con, w, host, include_own, event_sql):
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    return f"FROM {db.events_from(con, w)} WHERE {event_sql} AND {db.own_filter(con, include_own)}{tw}{hw}", tp + hp


def _likes(col, patterns):
    return "(" + " OR ".join(f"{col} LIKE ?" for _ in patterns) + ")", list(patterns)


def _row(cells, count=None, first=None, last=None, pivots=()):
    return {"cells": cells, "count": count, "first": sd.when_text(first), "last": sd.when_text(last),
            "pivots": [{"field": f, "value": v} for f, v in pivots if v]}


def _folder_kind(path):
    p = db.low(path)
    if "\\downloads\\" in p:
        return "Downloads"
    if "\\appdata\\local\\temp\\" in p or "\\windows\\temp\\" in p or "\\temp\\" in p:
        return "Temp"
    if "\\appdata\\" in p:
        return "AppData"
    return "other"


def _chunks(items, n=400):
    items = list(items)
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _starts_by_guid(con, guids):
    """{guid: start row (event 1)}: _huntdb.start_rows (only processes with a recorded start are looked up, each
    stopping at its start; an IN list read every row of busy processes)."""
    return db.start_rows(con, guids, "ProcessGuid, Image, ParentImage, ParentProcessGuid, Company, Product, Description, "
                                     "OriginalFileName, Hashes, time")


# -- the hunts ------------------------------------------------------------------------------------
def hunt_deleted_after_run(con, w, host=None, include_own=False):
    """Program files that ran and were then deleted (by themselves, a program they started, or
    another program): the classic "tidy up after yourself" step of malware droppers."""
    if not db.has(con, "TargetFilename", "Image"):
        return [], [], "This store has no file events."
    likes, lp = _likes("TargetFilename", ["%" + ext for ext in RUNNABLE])
    frm, params = _where(con, w, host, include_own, f"event_id IN (23, 26) AND {likes}")
    deleted = {}
    for r in con.execute(f"SELECT TargetFilename, Image, ProcessGuid, {_T(con)} AS time {frm} ORDER BY time", lp + params):
        deleted.setdefault(db.low(r["TargetFilename"]), []).append(r)
    if not deleted:
        return [], [], None
    # one pass over the window's program starts (an IN list per chunk rescanned the window each time)
    frm1, p1 = _where(con, w, host, include_own, "event_id = 1")
    ran = {r["li"]: r for r in con.execute(
        f"SELECT lower(Image) AS li, MIN(Image) AS image, COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, "
        f"MAX(ProcessGuid) AS guid {frm1} GROUP BY li", p1) if r["li"] in deleted}
    deleters = _starts_by_guid(con, [d["ProcessGuid"] for path in ran for d in deleted[path]])
    rows = []
    for path, run in ran.items():
        after = [d for d in deleted[path] if d["time"] >= run["first"]]
        if not after:
            continue
        d = after[0]
        by = db.low(d["Image"])
        start = deleters.get(d["ProcessGuid"])
        if by == path:
            how = "deleted itself"
        elif start is not None and db.low(start["ParentImage"]) == path:
            how = "deleted by a program it started"
        else:
            how = "deleted by another program"
        rows.append(_row({"program": run["image"], "runs": run["n"], "how": how, "deleted_by": db.basename(d["Image"]),
                          "deleted_at": sd.when_text(d["time"])}, count=len(after), first=run["first"], last=d["time"],
                         pivots=[("Image", run["image"]), ("ProcessGuid", run["guid"]), ("TargetFilename", d["TargetFilename"])]))
    notes = ["Only programs that both ran and were deleted inside the chosen time window are listed.",
             "Deletions are recorded for program and script files only (the Sysmon config's file-delete list)."]
    return sorted(rows, key=lambda r: r["first"] or ""), notes, None


def hunt_user_folders(con, w, host=None, include_own=False):
    """Programs started from Downloads, Temp or AppData: installed software lives in Program
    Files; a program running from a download or temp folder is often something just fetched."""
    likes, lp = _likes("Image", ["%\\downloads\\%", "%\\temp\\%", "%\\appdata\\%"])
    frm, params = _where(con, w, host, include_own, f"event_id = 1 AND {likes}")
    rows = []
    for r in con.execute(f"SELECT lower(Image) AS li, MIN(Image) AS image, COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, "
                         f"MAX(ProcessGuid) AS guid, MAX(ParentImage) AS parent {frm} GROUP BY li", lp + params):
        rows.append(_row({"program": r["image"], "folder": _folder_kind(r["image"]), "runs": r["n"],
                          "started_by": db.basename(r["parent"]) or "unknown"},
                         count=r["n"], first=r["first"], last=r["last"],
                         pivots=[("Image", r["image"]), ("ProcessGuid", r["guid"])]))
    order = {"Downloads": 0, "Temp": 1, "AppData": 2, "other": 3}
    rows.sort(key=lambda r: (order[r["cells"]["folder"]], r["count"]))
    return rows, ["AppData also holds many per-user installs (chat apps, editors): look at the rare ones first."], None


def hunt_unknown_net(con, w, host=None, include_own=False):
    """Programs with no publisher in their version info, or living outside the Windows and
    Program Files folders, that made outgoing network connections."""
    frm, params = _where(con, w, host, include_own, "event_id = 3 AND Initiated = 'true' AND Image IS NOT NULL")
    groups = list(con.execute(f"SELECT lower(Image) AS li, MIN(Image) AS image, COUNT(*) AS n, "
                              f"COUNT(DISTINCT DestinationIp) AS dests, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, "
                              f"MAX(ProcessGuid) AS guid {frm} GROUP BY li", params))
    starts = _starts_by_guid(con, [g["guid"] for g in groups])
    rows = []
    for g in groups:
        s = starts.get(g["guid"])
        outside = not g["li"].startswith(STANDARD_DIRS)
        if s is None:
            publisher, why = None, "start not recorded"
        else:
            publisher = (s["Company"] or "").strip() or None
            why = None if publisher else "no publisher in the file"
        if not (outside or (s is not None and not publisher)):
            continue
        reasons = [x for x in (why if s is not None and not publisher else None,
                               "outside Windows / Program Files" if outside else None,
                               "start not recorded (gap)" if s is None else None) if x]
        rows.append(_row({"program": g["image"], "publisher": publisher or "-", "why": "; ".join(reasons),
                          "connections": g["n"], "destinations": g["dests"]},
                         count=g["n"], first=g["first"], last=g["last"],
                         pivots=[("Image", g["image"]), ("ProcessGuid", g["guid"])]))
    rows.sort(key=lambda r: (r["cells"]["publisher"] != "-", -r["count"]))
    notes = ["Signatures are not recorded (Sysmon's start record has no signature field and image loads are off). "
             "The publisher written inside the file is used instead, and anyone can write any name there."]
    return rows, notes, None


def hunt_autostart(con, w, host=None, include_own=False):
    """New or changed autostart entries: Run keys, services, Winlogon, the Startup folder and
    scheduled tasks. Malware that wants to survive a restart has to write one of these."""
    rows, notes = [], []
    if db.has(con, "TargetObject"):
        frm, params = _where(con, w, host, include_own, "event_id IN (12, 13, 14) AND TargetObject IS NOT NULL")
        seen = {}
        for r in con.execute(f"SELECT TargetObject, EventType, Details, Image, ProcessGuid, {_T(con)} AS time {frm} ORDER BY time", params):
            k = (r["TargetObject"], r["EventType"])
            if k in seen:
                seen[k][1] += 1
                seen[k][3] = r
            else:
                seen[k] = [r, 1, r["time"], r]
        for (obj, etype), (first_r, n, first, last_r) in seen.items():
            kind = db.autostart_kind(obj)
            rows.append(_row({"kind": kind, "place": obj, "change": etype or "-", "value": last_r["Details"] or "-",
                              "by": db.basename(last_r["Image"]) or "unknown"},
                             count=n, first=first, last=last_r["time"],
                             pivots=[("TargetObject", obj), ("Image", last_r["Image"]), ("ProcessGuid", last_r["ProcessGuid"])]))
    else:
        notes.append("This store recorded no registry events (it is older than the registry config): Run keys and "
                     "services cannot be seen here.")
    if db.has(con, "TargetFilename"):
        frm, params = _where(con, w, host, include_own,
                             "event_id IN (11, 23, 26) AND TargetFilename LIKE '%\\Start Menu\\Programs\\Startup\\%'")
        for r in con.execute(f"SELECT event_id, TargetFilename, Image, ProcessGuid, {_T(con)} AS time {frm} ORDER BY time", params):
            rows.append(_row({"kind": "Startup folder", "place": r["TargetFilename"],
                              "change": "file created" if r["event_id"] == 11 else "file deleted", "value": "-",
                              "by": db.basename(r["Image"]) or "unknown"}, count=1, first=r["time"], last=r["time"],
                             pivots=[("TargetFilename", r["TargetFilename"]), ("Image", r["Image"]),
                                     ("ProcessGuid", r["ProcessGuid"])]))
    if db.has(con, "CommandLine"):
        frm, params = _where(con, w, host, include_own,
                             "event_id = 1 AND ((Image LIKE '%\\schtasks.exe' AND CommandLine LIKE '%/create%') "
                             "OR CommandLine LIKE '%Register-ScheduledTask%' OR CommandLine LIKE '%New-ScheduledTask%')")
        for r in con.execute(f"SELECT Image, CommandLine, ProcessGuid, ParentImage, {_T(con)} AS time {frm} ORDER BY time", params):
            rows.append(_row({"kind": "Scheduled task", "place": "Task Scheduler", "change": "created",
                              "value": r["CommandLine"], "by": db.basename(r["ParentImage"]) or "unknown"},
                             count=1, first=r["time"], last=r["time"],
                             pivots=[("ProcessGuid", r["ProcessGuid"]), ("Image", r["Image"])]))
    rows.sort(key=lambda r: r["first"] or "")
    notes.append("Scheduled tasks are seen only when made with schtasks.exe or PowerShell's task commands; tasks "
                 "made by a program through the Task Scheduler API are not recorded. WMI subscriptions are not recorded.")
    notes.append("Only changes made while the recorder ran are visible: entries that existed before are not.")
    return rows, notes, None


def _engine_parent_reason(parent):
    p = db.low(parent)
    name = db.basename(p)
    if name in OFFICE:
        return "an Office program"
    if name in BROWSERS:
        return "a web browser"
    if name in READERS:
        return "a PDF reader"
    if _folder_kind(p) in ("Downloads", "Temp"):
        return f"a program in {_folder_kind(p)}"
    return None


def hunt_script_engines(con, w, host=None, include_own=False):
    """Script engines (PowerShell, cmd, wscript, mshta, rundll32...) started by an Office program,
    a browser, a PDF reader or a program in Downloads/Temp: a document or web page that starts a
    script is how many attacks begin."""
    likes, lp = _likes("Image", ["%\\" + e for e in SCRIPT_ENGINES])
    frm, params = _where(con, w, host, include_own, f"event_id = 1 AND {likes}")
    rows = []
    for r in con.execute(f"SELECT lower(Image) AS li, lower(ParentImage) AS lp, MIN(Image) AS image, MIN(ParentImage) AS parent, "
                         f"COUNT(*) AS n, MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, MAX(ProcessGuid) AS guid, "
                         f"MAX(CommandLine) AS cmd {frm} GROUP BY li, lp", lp + params):
        reason = _engine_parent_reason(r["parent"])
        if reason is None:
            continue
        rows.append(_row({"engine": db.basename(r["image"]), "parent": r["parent"], "why": f"started by {reason}",
                          "runs": r["n"], "example": r["cmd"] or "-"}, count=r["n"], first=r["first"], last=r["last"],
                         pivots=[("ProcessGuid", r["guid"]), ("Image", r["parent"])]))
    rows.sort(key=lambda r: r["first"] or "")
    return rows, [], None


def hunt_renamed_tools(con, w, host=None, include_own=False):
    """Windows tools running under another file name: the file says it is (for example)
    certutil.exe inside, but on disk it is called something else, a trick to slip past rules
    that look for the tool's name."""
    if not db.has(con, "OriginalFileName"):
        return [], [], "This store has no OriginalFileName field."
    q = ",".join("?" for _ in WINDOWS_TOOLS)
    frm, params = _where(con, w, host, include_own, f"event_id = 1 AND lower(OriginalFileName) IN ({q})")
    rows = []
    for r in con.execute(f"SELECT lower(Image) AS li, MIN(Image) AS image, lower(OriginalFileName) AS orig, COUNT(*) AS n, "
                         f"MIN({_T(con)}) AS first, MAX({_T(con)}) AS last, MAX(ProcessGuid) AS guid {frm} GROUP BY li, orig",
                         list(WINDOWS_TOOLS) + params):
        real = r["orig"].removesuffix(".mui")
        name = db.basename(r["li"])
        if name == real or (real == "pwsh.dll" and name == "pwsh.exe") or (real == "psexec.c" and name.startswith("psexec")) \
                or (real == "procdump" and name.startswith("procdump")):
            continue
        rows.append(_row({"program": r["image"], "really_is": real, "runs": r["n"]}, count=r["n"], first=r["first"],
                         last=r["last"], pivots=[("Image", r["image"]), ("ProcessGuid", r["guid"])]))
    rows.sort(key=lambda r: r["first"] or "")
    return rows, ["Same idea as Sigma's 'Potential Renamed Binary' rules: the name inside the file is compared "
                  "with the name on disk, for a list of Windows tools."], None


def hunt_listeners(con, w, host=None, include_own=False):
    """Programs that opened a listening port (waiting for others to connect in). A backdoor
    has to listen; most programs on a laptop never do."""
    if not db.has(con, "LocalPort", "LocalIp"):
        return [], [], "This store has no port records from the agent."
    frm, params = _where(con, w, host, include_own, "type = 'PORT_LISTEN_START'")
    rows = []
    groups = {}
    for r in con.execute(f"SELECT lower(Image) AS li, MIN(Image) AS image, LocalIp AS ip, LocalPort AS port, COUNT(*) AS n, "
                         f"MIN({_T(con)}) AS first, MAX({_T(con)}) AS last {frm} GROUP BY li, ip, port", params):
        ip = str(r["ip"])
        reach = 0 if ip in ALL_INTERFACES else (2 if ip.startswith("127.") or ip in ("::1", "[::1]") else 1)
        # Windows' dynamic range (49152+): one row per program, not one per short-lived port
        port = r["port"] if not isinstance(r["port"], (int, float)) or r["port"] < DYNAMIC_PORTS else "dynamic"
        g = groups.setdefault((r["li"], port), {"image": r["image"], "reach": 3, "n": 0, "first": r["first"],
                                                "last": r["last"], "ips": set(), "ports": set()})
        g["ports"].add(r["port"])
        g["reach"], g["n"] = min(g["reach"], reach), g["n"] + r["n"]          # IPv4 + IPv6 of one port = one row
        g["first"], g["last"] = min(g["first"], r["first"]), max(g["last"], r["last"])
        g["ips"].add(ip)
    words = ["every network the machine is on", "one network", "this machine only"]
    for (li, port), g in groups.items():
        shown = port if port != "dynamic" else f"{len(g['ports'])} dynamic port{'s' if len(g['ports']) != 1 else ''} (49152+)"
        rows.append(_row({"program": g["image"] or "unknown", "port": shown, "address": ", ".join(sorted(g["ips"])),
                          "reachable_from": words[g["reach"]], "times_opened": g["n"]},
                         count=g["n"], first=g["first"], last=g["last"], pivots=[("Image", g["image"])]))
    rows.sort(key=lambda r: (words.index(r["cells"]["reachable_from"]), -(r["count"] or 0)))
    return rows, ["Ports are checked by the agent every few seconds: a port opened and closed between two checks is missed."], None


def hunt_lolbas(con, w, host=None, include_own=False):
    """Windows' own tools run the way the LOLBAS project documents as misuse (download, run code, get round
    allow-listing, copy credentials...). The catalogue and the matching are night-tools' (engine/labs/lolbas.py,
    imported read-only): a row = a program start whose command line has at least half (and at least two) of the
    switches of one documented misuse. A resemblance is a place to look, not a finding."""
    try:
        from . import lolbas as lb                                   # noqa: PLC0415  (fails alone if missing)
    except Exception as e:
        return [], [], f"The LOLBAS check could not be loaded ({type(e).__name__})."
    catalogue = lb.load(lb.data_path(db._running_context()))
    if catalogue is None:
        return [], [], lb.WORDS["no_data"]
    frm, params = _where(con, w, host, include_own, "event_id = 1 AND Image IS NOT NULL")
    groups = {}
    for r in con.execute(f"SELECT Image, OriginalFileName, CommandLine, ProcessGuid, {_T(con)} AS time {frm} ORDER BY time", params):
        name, orig = db.basename(r["Image"]).lower(), (r["OriginalFileName"] or "").lower()
        entry = catalogue.get(name) or catalogue.get(orig)
        if entry is None or not r["CommandLine"]:
            continue
        m = lb.best_match(r["CommandLine"], entry)
        if not lb.resembles(m):
            continue
        g = groups.setdefault((db.low(r["Image"]), r["CommandLine"]), {"r": r, "m": m, "entry": entry, "n": 0, "first": r["time"]})
        g["n"] += 1
        g["last"] = r["time"]
    rows = []
    for (_, cmd), g in groups.items():
        m, e = g["m"], g["entry"]
        rows.append(_row({"tool": e.get("Name"), "use": " · ".join(x for x in (m.get("category"), m.get("usecase")) if x) or "-",
                          "closeness": f"{len(m['matched'])} of {m['of']} switches", "technique": m.get("mitre") or "-",
                          "program": g["r"]["Image"], "example": cmd},
                         count=g["n"], first=g["first"], last=g["last"],
                         pivots=[("Image", g["r"]["Image"]), ("ProcessGuid", g["r"]["ProcessGuid"])]))
    rows.sort(key=lambda r: r["first"] or "")
    return rows, [lb.WORDS["resemble_note"], lb.WORDS["source"]], None


HUNTS = [
    {"id": "deleted-after-run", "fn": hunt_deleted_after_run, "title": "Programs deleted after they ran",
     "why": "Droppers often run a program and then delete its file to hide. A program file that ran and then "
            "vanished is worth a look, above all when it deleted itself.", "technique": "T1070.004",
     "columns": [("program", "Program file"), ("how", "How it went"), ("deleted_by", "Deleted by"), ("runs", "Runs"),
                 ("deleted_at", "Deleted at")]},
    {"id": "user-folders", "fn": hunt_user_folders, "title": "Programs started from Downloads, Temp or AppData",
     "why": "Installed software lives in Program Files. Something running from a download or temp folder was "
            "often just fetched or unpacked.", "technique": "T1204.002",
     "columns": [("program", "Program file"), ("folder", "Folder"), ("started_by", "Started by (e.g.)"), ("runs", "Runs")]},
    {"id": "unknown-net", "fn": hunt_unknown_net, "title": "Unknown programs that used the network",
     "why": "A program with no publisher, or living outside the usual folders, that talks to the network could be "
            "sending data out or taking orders.", "technique": "T1071",
     "columns": [("program", "Program file"), ("publisher", "Publisher"), ("why", "Why listed"),
                 ("connections", "Connections"), ("destinations", "Destinations")]},
    {"id": "autostart", "fn": hunt_autostart, "title": "New autostart entries",
     "why": "To survive a restart, malware must add itself somewhere Windows starts things automatically: Run keys, "
            "services, the Startup folder, scheduled tasks.", "technique": "T1547.001",
     "columns": [("kind", "Kind"), ("place", "Where"), ("change", "Change"), ("value", "Value"), ("by", "Written by")]},
    {"id": "script-engines", "fn": hunt_script_engines, "title": "Script engines started by documents or browsers",
     "why": "Office, a browser or a PDF reader should not normally start PowerShell, cmd, wscript or mshta. When "
            "they do, a document or web page may be running code.", "technique": "T1059",
     "columns": [("engine", "Script engine"), ("parent", "Started by"), ("why", "Why listed"), ("runs", "Runs"),
                 ("example", "Example command")]},
    {"id": "lolbas", "fn": hunt_lolbas, "title": "Windows' own tools used in a documented-misuse way",
     "why": "Intruders 'live off the land': they use programs Windows already has (certutil, mshta, rundll32...) so "
            "nothing new needs to be dropped. Running one is normal; running it the way the LOLBAS project "
            "documents as misuse is worth a look.", "technique": "T1218",
     "columns": [("tool", "Windows tool"), ("use", "Documented misuse"), ("closeness", "How close"),
                 ("technique", "ATT&CK"), ("example", "Command line"), ("program", "Program file")]},
    {"id": "renamed-tools", "fn": hunt_renamed_tools, "title": "Renamed Windows tools",
     "why": "A Windows tool copied under another name slips past rules that look for its usual name.",
     "technique": "T1036.003",
     "columns": [("program", "File on disk"), ("really_is", "Really is"), ("runs", "Runs")]},
    {"id": "listeners", "fn": hunt_listeners, "title": "Programs listening on a port",
     "why": "A backdoor waits for connections. Most programs on a laptop never listen; the ones reachable from "
            "every network matter most.", "technique": "T1571",
     "columns": [("program", "Program"), ("port", "Port"), ("reachable_from", "Reachable from"),
                 ("times_opened", "Times opened")]},
]
BY_ID = {h["id"]: h for h in HUNTS}


def describe(h):
    return {"id": h["id"], "title": h["title"], "why": h["why"], "technique": h["technique"],
            "columns": [{"key": k, "label": l} for k, l in h["columns"]]}


def run_hunt(con, hunt_id, w, host=None, include_own=False, limit=200) -> dict:
    h = BY_ID.get(hunt_id)
    if h is None:
        raise KeyError(hunt_id)
    t0 = time.perf_counter()
    try:
        rows, notes, missing = h["fn"](con, w, host=host, include_own=include_own)
    except sqlite3.OperationalError as e:            # an older store without a field this hunt reads
        if "no such column" not in str(e):
            raise
        rows, notes, missing = [], [], f"This store did not record a field this hunt needs ({str(e).split(':')[-1].strip()})."
    limit = max(1, min(int(limit), MAX_ROWS))
    out = describe(h)
    out.update(db.result_meta(con, w, host))
    out.update({"count": len(rows), "events": sum(r["count"] or 0 for r in rows), "rows": rows[:limit],
                "truncated": len(rows) > limit, "notes": notes, "not_recorded": missing,
                "include_own": include_own, "ms": round((time.perf_counter() - t0) * 1000)})
    return out


# -- API ------------------------------------------------------------------------------------------
def _open():
    try:
        return db.connect()
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _window(con, window, start, end):
    try:
        return db.window(con, window, start, end)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


WORDS = {
    "intro": "Hunting means looking for trouble without waiting for an alert. Each question below runs over the "
             "recording for the chosen time window. A row is not a verdict: it is a place worth looking.",
    "why": "Why it matters",
    "found": "found",
    "events": "events",
    "more": "Showing the first {n} of {total}. Narrow the time window to see the rest.",
}


@router.get("/")
def list_hunts():
    return {"hunts": [describe(h) for h in HUNTS], "windows": list(db.WINDOWS), "default_window": db.DEFAULT_WINDOW,
            "words": WORDS}


def _scoped(con, window, start, end, host, alert, only_alert):
    """(window, host, alert for the page): _huntdb.scoped_window, a bad window answered with 400."""
    try:
        return db.scoped_window(con, window, start, end, host, alert, only_alert)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/run/{hunt_id}")
def run(hunt_id: str, window: str = db.DEFAULT_WINDOW, start: str = None, end: str = None, host: str = None,
        include_own: bool = False, limit: int = 200, alert: str = None, only_alert: bool = True):
    if hunt_id not in BY_ID:
        raise HTTPException(status_code=404, detail="no such hunt")
    con = _open()
    try:
        w, host, shown = _scoped(con, window, start, end, host, alert, only_alert)
        return {**run_hunt(con, hunt_id, w, host, include_own, limit), "alert": shown}
    finally:
        con.close()


@router.get("/summary")
def summary(window: str = db.DEFAULT_WINDOW, start: str = None, end: str = None, host: str = None,
            include_own: bool = False, alert: str = None, only_alert: bool = True):
    con = _open()
    try:
        w, host, shown = _scoped(con, window, start, end, host, alert, only_alert)
        path = db.events_path()
        sw, sp = db.scope_sql()
        key = (path, db.store_version(con), sw, tuple(sp), w.since, w.until, host, include_own)
        with _lock:
            items = _summaries.get(key)
        if items is not None:                       # the store only grows: the same version gives the same counts
            return {**db.result_meta(con, w, host), "hunts": items, "alert": shown}

        def one(h):                    # each hunt on its own read-only connection: they run side by side
            c = db.connect(path)
            try:
                return run_hunt(c, h["id"], w, host, include_own, limit=1)
            finally:
                c.close()
        # speed audit (2026-11-24): one after another the eight hunts took 6-15 s on the 2.4 GB laptop store
        with ThreadPoolExecutor(max_workers=4) as ex:
            done = list(ex.map(one, HUNTS))
        items = [{"id": h["id"], "title": h["title"], "count": r["count"], "ms": r["ms"], "not_recorded": r["not_recorded"]}
                 for h, r in zip(HUNTS, done)]
        with _lock:
            if len(_summaries) > 32:
                _summaries.clear()
            _summaries[key] = items
        return {**db.result_meta(con, w, host), "hunts": items, "alert": shown}
    finally:
        con.close()
