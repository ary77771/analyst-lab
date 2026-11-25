"""Lab: Second opinion. "Do well-known outside tools flag the same events as we do?"

Hayabusa (Yamato Security, AGPL-3.0) and Chainsaw (WithSecure, GPL-3.0) are free, widely used tools that hunt
through Windows event log files (.evtx) with their own rule sets (Hayabusa's rules + Sigma). This lab gives
both the same .evtx and runs OUR detectors on it too (engine.score, read-only: the same Sigma rules, our own
rules and the check-in rhythm rule), then lines the three up event by event (the log's EventRecordID):
flagged by both, only by us, only by them. Disagreement is the interesting part: a rule one side has and
the other lacks, or a channel we do not record (we read only Sysmon).

Which .evtx files: exports of the TEST MACHINE's Sysmon log saved with a run (the vmruns folder of the dashboard's recordings) and
public sample logs (downloads/evtx-attack-samples-*/, downloads/night/samples/). Never this laptop's own
logs (reading the live laptop log needs admin, and its data never goes to outside tools).

Our side needs nothing downloaded. Each outside tool runs only when it is in downloads/night/<tool>/
(python -m engine.labs._fetch hayabusa|chainsaw). Work happens in a background thread (loading ~1,900
Sigma rules takes about 40 s the first time); results are cached in the temp folder, never in the recordings folder.
"""

import glob
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import traceback

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _downloads

router = APIRouter(prefix="/api/labs/secondopinion")

SYSMON = "Microsoft-Windows-Sysmon/Operational"
TOOL_TIMEOUT_S = 600
WORK = os.path.join(tempfile.gettempdir(), "analystlab-secondopinion")
LEVELS = ["informational", "low", "medium", "high", "critical"]
LEVEL_ALIASES = {"info": "informational", "informational": "informational", "low": "low", "med": "medium",
                 "medium": "medium", "high": "high", "crit": "critical", "critical": "critical"}

WORDS = {
    "title": "Second opinion",
    "summary_title": "Compared so far",
    "summary_intro": ("Public sample event logs, each read by our detectors and by two free outside tools. Per log: "
                      "how many events both flagged, how many only one side flagged. A difference is a different rule "
                      "set, not a score."),
    "rule_sets": "Rule sets: ours = {ours} Sigma rules plus our own rules; Hayabusa {hayabusa} with its bundled rules; Chainsaw {chainsaw} with its Sigma rules.",
    "pick_another": "Compare another log",
    "jargon": {
        "Hayabusa": "a free tool analysts use to search Windows event logs for known misuse patterns",
        "Chainsaw": "another free tool for searching Windows event logs, with Sigma rules",
        "Sigma": "a shared rule format for spotting suspicious events in logs (our detectors use it too)",
        ".evtx": "the file format Windows saves its event logs in",
    },
    "intro": ("The same event log, read by our detectors and by well-known outside tools (Hayabusa, Chainsaw). "
              "Lined up event by event: where we agree, and where only one side raised its hand."),
    "both": "Same event, both", "near": "Same process within a minute", "only_ours": "Only by us",
    "only_theirs": "Only by them",
    "rule": ("Matching rule: one Sysmon event (its record number) is the unit. Same event = both flagged it. "
             "Same process within a minute = one side flagged this event, the other another event of the same "
             "process within 60 seconds. Only hits from the level the screens show (medium) up count, on both sides."),
    "other_channels": "Flagged by them in logs we do not record (we read only Sysmon)",
    "disagree_note": ("A disagreement is not a mistake by either side: rule sets differ, and each side's "
                      "threshold for raising a hand differs. Read the rule names."),
    "no_tool": "Not downloaded yet (python -m engine.labs._fetch {tool}).",
    "working": "Working: loading rules and reading the log (the first time takes about a minute).",
    "kinds": {"vm": "Test machine run", "sample": "Public sample log"},
    "floor_note": "Only alerts at or above the level the screens show are counted for us; for them, the same level.",
}

TOOLS = {
    "hayabusa": {"exe": ["hayabusa*.exe"], "license": "AGPL-3.0 (rules: DRL 1.1)",
                 "site": "https://github.com/Yamato-Security/hayabusa"},
    "chainsaw": {"exe": ["chainsaw*windows*.exe", "chainsaw.exe"], "license": "GPL-3.0 (Sigma rules: DRL 1.1)",
                 "site": "https://github.com/WithSecureLabs/chainsaw"},
}

_jobs, _jobs_lock = {}, threading.Lock()
_rules = {"rules": None, "lock": threading.Lock()}


# --- which logs --------------------------------------------------------------------------------------------
def evtx_files(recordings=None):
    """[{id, name, kind, folder, size, path}] of the .evtx files this lab may read (see the module text)."""
    out = []
    if recordings and os.path.isdir(os.path.join(recordings, "vmruns")):
        for p in sorted(glob.glob(os.path.join(recordings, "vmruns", "**", "*.evtx"), recursive=True)):
            out.append(("vm", p, os.path.relpath(os.path.dirname(p), os.path.join(recordings, "vmruns"))))
    for root in _sample_roots(recordings):
        for p in sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True)):
            out.append(("sample", p, os.path.relpath(os.path.dirname(p), root)))
    items, seen = [], set()
    for kind, p, folder in out:
        k = os.path.abspath(p).lower()
        if k in seen:
            continue
        seen.add(k)
        items.append({"id": hashlib.sha1(k.encode("utf-8", "replace")).hexdigest()[:16], "name": os.path.basename(p),
                      "kind": kind, "folder": "" if folder == "." else folder, "size": os.path.getsize(p),
                      "sysmon": "sysmon" in os.path.basename(p).lower(), "path": p})
    return items


def _sample_roots(recordings=None):
    roots = []
    for night in _downloads.roots(recordings):
        dl = os.path.dirname(night)                                  # .../downloads
        roots += sorted(glob.glob(os.path.join(dl, "evtx-attack-samples-*")))
        roots.append(os.path.join(night, "samples"))
    return [r for r in dict.fromkeys(roots) if os.path.isdir(r)]


# --- our side ------------------------------------------------------------------------------------------------
def read_evtx(path, runner=subprocess.run):
    """Every event of an .evtx FILE as the agent would record it, read with Windows' own wevtutil (reading a
    saved file needs no admin). The path is one argument of the command, never shell text."""
    from agent.parse import parse_event_xml
    r = runner(["wevtutil", "qe", path, "/lf:true", "/f:xml"], capture_output=True, text=True, encoding="utf-8",
               errors="replace", timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise RuntimeError(f"wevtutil could not read the file: {(r.stderr or '').strip()[:200]}")
    recs = []
    for x in re.findall(r"(?s)<Event[ >].*?</Event>", r.stdout or ""):
        try:
            e = parse_event_xml(x)
        except Exception:
            continue
        recs.append({"host": e["computer"] or "unknown", "label": "evtx", "session": "evtx",
                     "source": "sysmon" if e["channel"] == SYSMON else "windows", "channel": e["channel"],
                     "record_id": e["record_id"], "event_id": e["event_id"], "provider": e["provider"],
                     "time": e["time"], "origin": "normal", "data": e["data"]})
    return recs


def community_rules_dir():
    """Where the community Sigma rules are: engine.detect's own place, else the main checkout's (a worktree
    has no downloads/ of its own)."""
    from engine import detect
    if os.path.isdir(detect.COMMUNITY_RULES):
        return detect.COMMUNITY_RULES
    for night in _downloads.roots():
        p = os.path.join(os.path.dirname(night), "sigma", "rules", "windows")
        if os.path.isdir(p):
            return p
    return None


def our_rules():
    """The Sigma rules as engine.score loads them (community + our own folder), loaded once per process."""
    with _rules["lock"]:
        if _rules["rules"] is None:
            from engine import detect, score
            rules = score.load_rules()
            if not os.path.isdir(detect.COMMUNITY_RULES):
                d = community_rules_dir()
                if d:
                    rules = detect.load_rules([d], "sigma")[0] + rules
            _rules["rules"] = rules
        return _rules["rules"]


def our_side(records, workdir, rules=None, min_level=None):
    """Our detectors over these records in a temporary store: [{rule, title, level, record_ids}]."""
    from engine import detect, score
    from engine.store import EventStore
    db = os.path.join(workdir, "ours.db")
    if os.path.exists(db):
        os.remove(db)
    s = EventStore(db)
    s.insert(records)
    s.close()
    try:
        baseline = score.load_baseline()
    except Exception:
        baseline = None                      # learned-normal files are per host: sample hosts have none anyway
    con = detect.open_store(db)
    errors = []
    try:
        alerts = score.score(con, our_rules() if rules is None else rules, baseline, errors=errors)
    finally:
        con.close()
    out = []
    for a in alerts:
        ids = sorted({int(k.split("|")[2]) for k in a.evidence if k.count("|") >= 3 and k.split("|")[2].isdigit()})
        out.append({"rule": a.rule_id, "title": a.title, "level": a.level, "record_ids": ids})
    return out, errors


# --- their side ------------------------------------------------------------------------------------------------
def find_tool(name, recordings=None):
    d = _downloads.folder(name, recordings)
    if not d:
        return None
    for pat in TOOLS[name]["exe"]:
        hits = sorted(glob.glob(os.path.join(d, "**", pat), recursive=True), key=len)
        if hits:
            return hits[0]
    return None


def _norm_level(v):
    return LEVEL_ALIASES.get(str(v or "").strip().lower(), "informational")


def parse_hayabusa(text):
    """Hayabusa's JSONL timeline -> [{rule, level, record_id, channel, time}]."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rid = d.get("RecordID")
        if rid is None or not str(rid).isdigit():
            continue
        out.append({"rule": d.get("RuleTitle"), "level": _norm_level(d.get("Level")), "record_id": int(rid),
                    "channel": d.get("Channel"), "time": d.get("Timestamp")})
    return out


def parse_chainsaw(text):
    """Chainsaw hunt --json -> [{rule, level, record_id, channel, time}] (one row per document of a hit)."""
    try:
        hits = json.loads(text or "[]")
    except ValueError:
        return []
    out = []
    for h in hits if isinstance(hits, list) else []:
        docs = h.get("documents") or ([h["document"]] if h.get("document") else [])
        for doc in docs:
            sysd = (((doc or {}).get("data") or {}).get("Event") or {}).get("System") or {}
            rid = sysd.get("EventRecordID")
            if rid is None or not str(rid).isdigit():
                continue
            out.append({"rule": h.get("name"), "level": _norm_level(h.get("level")), "record_id": int(rid),
                        "channel": sysd.get("Channel"), "time": h.get("timestamp")})
    return out


def hayabusa_major(exe):
    """Hayabusa's major version from its file name (hayabusa-4.4.0-win-x64.exe -> 4), or None."""
    m = re.search(r"hayabusa-(\d+)\.", os.path.basename(exe).lower())
    return int(m.group(1)) if m else None


def tool_command(name, exe, evtx, out):
    """The command line for a tool (a list: every value is one argument). Settings = the matching rule in
    docs/night/status-night-tools.md: each tool's bundled rules, default rule selection."""
    root = os.path.dirname(exe)
    if name == "hayabusa":
        if (hayabusa_major(exe) or 4) >= 4:          # 4.x: dfir-timeline, -t jsonl; -b full channel names
            return [exe, "dfir-timeline", "-f", evtx, "-t", "jsonl", "-o", out, "-w", "-q", "-C", "-O", "-K", "-N", "-b", "-Q"]
        return [exe, "json-timeline", "-f", evtx, "-L", "-o", out, "-w", "-q", "-C"]
    base = _chainsaw_root(root)
    return [exe, "hunt", evtx, "-s", os.path.join(base, "sigma"), "--mapping",
            os.path.join(base, "mappings", "sigma-event-logs-all.yml"), "-r", os.path.join(base, "rules"),
            "--json", "-o", out, "-q"]


def _chainsaw_root(d):
    for _ in range(3):
        if os.path.isdir(os.path.join(d, "mappings")):
            return d
        d = os.path.dirname(d)
    return d


def _tool_paths(name, exe, evtx, workdir):
    from engine.labs._so_worker import fingerprint
    out = os.path.join(workdir, f"{name}.{'jsonl' if name == 'hayabusa' else 'json'}")
    key = {"evtx": fingerprint(evtx), "exe": fingerprint(exe), "cmd": tool_command(name, exe, evtx, out)[1:]}
    return out, out + ".meta.json", key


def tool_cached(name, exe, evtx, workdir):
    """(hits, seconds) from the tool's kept output for this very log and tool, or None. Reads files only."""
    try:
        out, meta, key = _tool_paths(name, exe, evtx, workdir)
        if not (os.path.isfile(out) and os.path.isfile(meta)):
            return None
        with open(meta, encoding="utf-8") as f:
            m = json.load(f)
        if m.get("key") != key:
            return None
        with open(out, encoding="utf-8", errors="replace") as f:
            text = f.read()
        return (parse_hayabusa(text) if name == "hayabusa" else parse_chainsaw(text)), m.get("seconds")
    except (OSError, ValueError):
        return None


def run_tool(name, exe, evtx, workdir, runner=subprocess.run):
    """(hits, seconds, cached?) of one outside tool on one log; its output is kept in the work folder and reused
    while the log and the tool are the same files."""
    from engine.labs._so_worker import fingerprint
    out = os.path.join(workdir, f"{name}.{'jsonl' if name == 'hayabusa' else 'json'}")
    meta = out + ".meta.json"
    key = {"evtx": fingerprint(evtx), "exe": fingerprint(exe), "cmd": tool_command(name, exe, evtx, out)[1:]}
    hit = tool_cached(name, exe, evtx, workdir)
    if hit is not None:
        return hit[0], hit[1], True
    for p in (out, meta):
        if os.path.exists(p):
            os.remove(p)
    t0 = time.time()
    r = runner(tool_command(name, exe, evtx, out), cwd=os.path.dirname(exe), capture_output=True, text=True,
               encoding="utf-8", errors="replace", timeout=TOOL_TIMEOUT_S,
               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if not os.path.exists(out):
        raise RuntimeError(f"{name} wrote no results (exit {r.returncode}): {(r.stderr or r.stdout or '').strip()[-300:]}")
    secs = round(time.time() - t0, 1)
    with open(out, encoding="utf-8", errors="replace") as f:
        text = f.read()
    with open(meta, "w", encoding="utf-8") as f:
        json.dump({"key": key, "seconds": secs}, f)
    return (parse_hayabusa(text) if name == "hayabusa" else parse_chainsaw(text)), secs, False


# --- lining up (the matching rule: docs/night/status-night-tools.md) -----------------------------------------
NEAR_S = 60                       # "same process nearby" = the same process within this many seconds
VERDICTS = ("both", "near", "only_ours", "only_theirs")


def process_of(r):
    """The process an event is about: ProcessGuid; for process access (10) / remote threads (8) the source."""
    d = r.get("data") or {}
    if r.get("event_id") in (8, 10):
        return d.get("SourceProcessGUID") or d.get("SourceProcessGuid")
    return d.get("ProcessGuid")


def _epoch(t):
    if not t:
        return None
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?", t)
    if not m:
        return None
    from datetime import datetime, timezone
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    frac = float("0." + m.group(7)) if m.group(7) else 0.0
    return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp() + frac


def compare(records, ours, theirs, min_level="informational", near_s=NEAR_S):
    """Event-by-event comparison of our alerts with each outside tool's hits (`theirs` = {tool: [hits]}). Only hits
    at or above `min_level` count, on both sides. Each row gets a verdict per tool (see VERDICTS)."""
    floor = LEVELS.index(min_level) if min_level in LEVELS else 0
    by_id = {r["record_id"]: r for r in records}
    sysmon_ids = {r["record_id"] for r in records if r["channel"] == SYSMON}
    ours_by, theirs_by, other = {}, {t: {} for t in theirs}, {}
    for a in ours:
        if LEVELS.index(a["level"]) >= floor:
            for rid in a["record_ids"]:
                ours_by.setdefault(rid, []).append({"title": a["title"], "level": a["level"]})
    for tool, hits in theirs.items():
        for h in hits:
            if LEVELS.index(h["level"]) < floor:
                continue
            if h["record_id"] not in sysmon_ids:
                other[tool] = other.get(tool, 0) + 1
                continue
            theirs_by[tool].setdefault(h["record_id"], []).append({"title": h["rule"], "level": h["level"]})

    def flagged_procs(ids):
        """{process: [times]} of the flagged events."""
        out = {}
        for rid in ids:
            r = by_id.get(rid)
            p, t = (process_of(r), _epoch(r.get("time"))) if r else (None, None)
            if p and t is not None:
                out.setdefault(p, []).append(t)
        return out

    def near(rid, procs):
        r = by_id.get(rid)
        if not r:
            return False
        p, t = process_of(r), _epoch(r.get("time"))
        return bool(p and t is not None and any(abs(t - u) <= near_s for u in procs.get(p, ())))

    ours_procs = flagged_procs(ours_by)
    rows, counts = {}, {}
    for tool, tb in theirs_by.items():
        their_procs = flagged_procs(tb)
        c = counts[tool] = {v: 0 for v in VERDICTS}
        for rid in set(ours_by) | set(tb):
            if rid in ours_by and rid in tb:
                v = "both"
            elif rid in ours_by:
                v = "near" if near(rid, their_procs) else "only_ours"
            else:
                v = "near" if near(rid, ours_procs) else "only_theirs"
            c[v] += 1
            rows.setdefault(rid, {})[tool] = v
    for rid in ours_by:
        rows.setdefault(rid, {})
    out = []
    for rid, verdicts in rows.items():
        r = by_id.get(rid) or {}
        d = r.get("data") or {}
        out.append({"record_id": rid, "time": r.get("time"), "event_id": r.get("event_id"), "channel": r.get("channel"),
                    "image": d.get("Image") or d.get("SourceImage"), "process": process_of(r) if r else None,
                    "ours": ours_by.get(rid, []), "theirs": {t: tb[rid] for t, tb in theirs_by.items() if rid in tb},
                    "verdicts": verdicts})
    out.sort(key=lambda x: (x["time"] or "", x["record_id"]))
    return {"rows": out, "counts": counts, "other_channels": other, "events": len(records),
            "sysmon_events": len(sysmon_ids), "ours_flagged": len(ours_by), "near_seconds": near_s,
            "theirs_flagged": {t: len(tb) for t, tb in theirs_by.items()}}


# --- the background job ------------------------------------------------------------------------------------
OURS_IN_PROCESS = False          # tests: run our side in this process (with their own small rule set)
WORKER_TIMEOUT_S = 900


def ours_cached(item, workdir):
    """Our side from <workdir>/ours.json when it was made for this very file (and this worker version), or None."""
    from engine.labs import _so_worker as W
    cached = os.path.join(workdir, "ours.json")
    if not os.path.isfile(cached):
        return None
    try:
        with open(cached, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("fingerprint") == W.fingerprint(item["path"]) and d.get("version") == W.VERSION:
            return d["records"], d["ours"], d["errors"], d["rules"]
    except (OSError, ValueError, KeyError):
        pass
    return None


def ours_for(item, workdir, runner=subprocess.run):
    """(slim records, our alerts, errors, rule count) for this log: from <workdir>/ours.json when it was made for
    this very file, else made by engine/labs/_so_worker.py in a separate Python process."""
    from engine.labs import _so_worker as W
    if OURS_IN_PROCESS:
        records = read_evtx(item["path"], runner=runner)
        ours, errors = our_side(records, workdir)
        d = {"version": W.VERSION, "fingerprint": W.fingerprint(item["path"]), "records": W.slim(records), "ours": ours,
             "errors": len(errors), "rules": len(_rules["rules"] or [])}
        with open(os.path.join(workdir, "ours.json"), "w", encoding="utf-8") as f:       # the same cache the worker writes
            json.dump(d, f)
        return d["records"], d["ours"], d["errors"], d["rules"]
    cached = os.path.join(workdir, "ours.json")
    hit = ours_cached(item, workdir)
    if hit is not None:
        return hit
    import sys
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    r = subprocess.run([sys.executable, "-m", "engine.labs._so_worker", item["path"], workdir], cwd=root,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=WORKER_TIMEOUT_S,
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0 or not os.path.isfile(cached):
        raise RuntimeError(f"our detectors could not run on this log: {(r.stderr or '').strip()[-300:]}")
    with open(cached, encoding="utf-8") as f:
        d = json.load(f)
    return d["records"], d["ours"], d["errors"], d["rules"]


def _job(item, recordings, min_level, runner=subprocess.run):
    key = item["id"]
    workdir = os.path.join(WORK, key)
    os.makedirs(workdir, exist_ok=True)
    st = _jobs[key]
    try:
        st["step"] = "reading the log and running our detectors (in their own process)"
        records, ours, n_errors, n_rules = ours_for(item, workdir, runner=runner)
        theirs, tools = {}, {}
        for name in TOOLS:
            exe = find_tool(name, recordings)
            if not exe:
                tools[name] = {"state": "missing"}
                continue
            st["step"] = f"running {name}"
            try:
                hits, secs, cached = run_tool(name, exe, item["path"], workdir, runner=runner)
                theirs[name] = hits
                tools[name] = {"state": "ran", "hits": len(hits), "seconds": secs, "cached": cached,
                               "version": _tool_version(name, exe)}
            except Exception as e:
                tools[name] = {"state": "failed", "reason": f"{type(e).__name__}: {e}"[:400]}
        result = compare(records, ours, theirs, min_level)
        result.update(tools=tools, our_errors=n_errors, our_alerts=len(ours), min_level=min_level, our_rules=n_rules)
        st.update(state="ready", result=result, finished=time.time())
    except Exception as e:
        st.update(state="error", error=f"{type(e).__name__}: {e}", detail=traceback.format_exc(limit=3))


def _tool_version(name, exe):
    m = re.search(r"(\d+\.\d+\.\d+)", exe.replace("\\", "/"))
    if m:
        return m.group(1)
    for part in re.split(r"[\\/]", exe):
        m = re.search(r"v(\d+\.\d+\.\d+)", part)
        if m:
            return m.group(1)
    return None


def cached_result(item, recordings, min_level):
    """The comparison from what is already on disk for this very log (our side and every downloaded tool), or None
    when any part has not been run yet. Reads files only: never starts wevtutil, the worker or a tool."""
    workdir = os.path.join(WORK, item["id"])
    ours = ours_cached(item, workdir)
    if ours is None:
        return None
    records, alerts, n_errors, n_rules = ours
    theirs, tools = {}, {}
    for name in TOOLS:
        exe = find_tool(name, recordings)
        if not exe:
            tools[name] = {"state": "missing"}
            continue
        hit = tool_cached(name, exe, item["path"], workdir)
        if hit is None:
            return None
        theirs[name] = hit[0]
        tools[name] = {"state": "ran", "hits": len(hit[0]), "seconds": hit[1], "cached": True,
                       "version": _tool_version(name, exe)}
    result = compare(records, alerts, theirs, min_level)
    result.update(tools=tools, our_errors=n_errors, our_alerts=len(alerts), min_level=min_level, our_rules=n_rules)
    return result


class Busy(Exception):
    """Another comparison is running (one at a time: each takes minutes of CPU)."""


def running():
    with _jobs_lock:
        return next(({"id": k, **v} for k, v in _jobs.items() if v["state"] == "working"), None)


def start(item, recordings, min_level, runner=subprocess.run, background=True):
    """Start one comparison (the ONLY way one starts: an explicit request). Raises Busy while another runs."""
    with _jobs_lock:
        busy = next((k for k, v in _jobs.items() if v["state"] == "working"), None)
        if busy is not None:
            raise Busy(busy)
        st = _jobs[item["id"]] = {"state": "working", "step": "starting", "started": time.time(), "min_level": min_level,
                                 "name": item["name"]}
    if background:
        threading.Thread(target=_job, args=(item, recordings, min_level, runner), daemon=True).start()
    else:
        _job(item, recordings, min_level, runner)
    return st


# --- routes ------------------------------------------------------------------------------------------------
def _public(i):
    return {k: i[k] for k in ("id", "name", "kind", "folder", "size", "sysmon")}


def _item(ctx, evtx_id):
    item = next((i for i in evtx_files(ctx.recordings) if i["id"] == evtx_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="no such log file")
    return item


@router.get("")
def listing():
    ctx = labs.context()
    tools = {n: {"present": bool(find_tool(n, ctx.recordings)), "license": t["license"], "site": t["site"]}
             for n, t in TOOLS.items()}
    files = evtx_files(ctx.recordings)
    busy = running()
    return {"words": WORDS, "tools": tools, "files": [_public(i) for i in files], "min_level": ctx.min_level(),
            "running": busy and {"id": busy["id"], "name": busy.get("name"), "step": busy.get("step")},
            "suggested": next((i["id"] for i in files if i["kind"] == "vm"),
                              next((i["id"] for i in files if i["name"] == "PanacheSysmon_vs_AtomicRedTeam01.evtx"),
                                   files[0]["id"] if files else None))}


@router.get("/result/{evtx_id}")
def result(evtx_id: str, all_levels: bool = False):
    """What is known about this log NOW, without starting anything: a running job's progress, the result from the
    files already kept on disk, or "not_run" (then the page offers a button that POSTs /run)."""
    ctx = labs.context()
    item = _item(ctx, evtx_id)
    min_level = "informational" if all_levels else ctx.min_level()
    with _jobs_lock:
        st = dict(_jobs.get(item["id"]) or {})
    out = {"file": _public(item)}
    if st.get("state") == "working":
        return {**out, "state": "working", "step": st.get("step"), "seconds": round(time.time() - st["started"], 1)}
    res = cached_result(item, ctx.recordings, min_level)
    if res is not None:
        return {**out, "state": "ready", "result": res}
    if st.get("state") == "error":
        return {**out, "state": "error", "error": st.get("error")}
    busy = running()
    return {**out, "state": "not_run", "busy": busy and busy.get("name")}


@router.post("/run/{evtx_id}")
def run(evtx_id: str, all_levels: bool = False):
    """Start the comparison for this log (our detectors in their own process, then each downloaded tool). One at a
    time in the whole dashboard; 409 while another runs."""
    ctx = labs.context()
    item = _item(ctx, evtx_id)
    try:
        st = start(item, ctx.recordings, "informational" if all_levels else ctx.min_level())
    except Busy as e:
        with _jobs_lock:
            name = (_jobs.get(str(e)) or {}).get("name")
        raise HTTPException(status_code=409, detail=f"another comparison is running ({name}); one at a time")
    return {"file": _public(item), "state": st["state"], "step": st.get("step")}


@router.get("/summary")
def summary():
    """Every log compared so far, from the kept results only (nothing is started): one row per log with, per
    outside tool, how many events both sides flagged, the same process nearby, only us, only them, at the
    screens' level. The scoring rule and the rule sets are named with it (critique-2 #12: summary first)."""
    ctx = labs.context()
    level = ctx.min_level()
    rows, tools_seen, rules = [], {}, None
    for item in evtx_files(ctx.recordings):
        if not os.path.isdir(os.path.join(WORK, item["id"])):
            continue
        res = cached_result(item, ctx.recordings, level)
        if res is None:
            continue
        rules = rules or res.get("our_rules")
        for t, s in res["tools"].items():
            if s.get("state") == "ran":
                tools_seen[t] = s.get("version")
        rows.append({"file": _public(item), "sysmon_events": res["sysmon_events"], "counts": res["counts"],
                     "ours_flagged": res["ours_flagged"], "theirs_flagged": res["theirs_flagged"]})
    totals = {t: {v: sum(r["counts"].get(t, {}).get(v, 0) for r in rows) for v in VERDICTS} for t in tools_seen}
    return {"words": WORDS, "level": level, "rows": rows, "totals": totals,
            "rule_sets": {"ours": rules, "tools": tools_seen}}

