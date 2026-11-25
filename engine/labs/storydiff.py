"""Lab: Story diff. "Two runs side by side: what did only A do, what did both do, what did only B do?"

The Evil twin screen (/api/twin), for any two recorded test-machine runs. A run is a replay store under the
recordings' demo folder (`<run id>-<when replayed>/events.db + alerts.db`, made by tools/demo_replay.py from the
run's own window; the newest replay of a run is used, as demo/build_twin.py does). Its scenario comes from the
run log (the vmruns label, SCENARIO_RUN rows).

Steps are compared by KIND of behaviour, not by exact names, so two different programs that do the same kind of
thing line up: ran <program>, created a file (folder pattern + extension), deleted a file, connected out
(address:port), looked up a name, changed the registry. The parts that differ from run to run anyway are
generalised: the test's own folder becomes <test folder>, user folders become <user>, digits in file names #.

By default only THE TEST'S OWN STEPS count: processes started from the test CD (D:\\) or from the test folder
(\\AnalystLab\\scenarios\\), and every process they started (followed by ProcessGuid); our own tools (origin
'project') never count. `everything=true` shows the whole recording window, background Windows activity included.

Alerts are compared by rule: raised (at or above the screens' level) or noted below it, in A, in B or in both.
Read-only; VM data only (night rule 11).
"""

import os
import re
import sqlite3

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _files

router = APIRouter(prefix="/api/labs/storydiff")

RUN_ID = re.compile(r"^(\d{8}-\d{6}-[0-9a-f]{4})-(\d{8}-\d{6})$")
KINDS = ["ran", "created", "deleted", "connected", "looked_up", "registry"]

WORDS = {
    "title": "Story diff",
    "intro": ("Two recorded test runs side by side: what only the first did, what both did, what only the second did, "
              "and which alerts each raised. Steps are compared by kind (ran a program, created a file, connected "
              "out...), so two different programs doing the same kind of thing line up."),
    "kinds": {"ran": "Ran a program", "created": "Created a file", "deleted": "Deleted a file",
              "connected": "Connected out", "looked_up": "Looked up a name", "registry": "Changed the registry"},
    "only_a": "Only in A", "both": "In both", "only_b": "Only in B",
    "own_steps": ("Only the test's own steps: programs started from the test CD or the test folder, and everything they "
                  "started. Background Windows activity and our own tools are left out."),
    "everything": "Everything in the two recording windows, background Windows activity included.",
    "raised": "Alerts raised", "below": "Noted below the alarm line (which starts at level {floor})",
    "same": "No differences: the two runs did the same kinds of steps and raised the same alerts.",
    "general": ("Names that differ from run to run anyway are generalised: the test's own folder is <test folder>, "
                "user folders are <user>, digits in file names are #."),
    "none": "No replayed test runs here yet (tools/demo_replay.py makes them).",
}


# --- which runs ------------------------------------------------------------------------------------------------
def demo_root(recordings=None):
    """The recordings' demo folder (replay stores): next to the dashboard's recordings, else the nearest
    demo folder of a recordings folder up the tree from this code (a worktree has no recordings of its own)."""
    if os.environ.get("ANALYSTLAB_REPLAYS"):
        return os.environ["ANALYSTLAB_REPLAYS"]
    if recordings and os.path.isdir(os.path.join(recordings, "demo")):
        return os.path.join(recordings, "demo")
    here = _files.CODE_ROOT
    for _ in range(6):
        p = os.path.join(here, "recordings", "demo")
        if os.path.isdir(p):
            return p
        here = os.path.dirname(here)
    return None


def scenarios_by_run(recordings):
    """{run id: scenario} from the run log (vmruns, SCENARIO_RUN rows)."""
    from engine.jsonl import iter_jsonl, recording_files
    out = {}
    if not recordings or not os.path.isdir(os.path.join(recordings, "vmruns")):
        return out
    for p in recording_files(os.path.join(recordings, "vmruns")):
        for r in iter_jsonl(p, {}):
            if r.get("type") == "SCENARIO_RUN" and r.get("run_id"):
                out[r["run_id"]] = {"scenario": r.get("scenario"), "start": r.get("start"), "exit_code": r.get("exit_code")}
    return out


def runs(recordings=None):
    """[{id, scenario, start, replayed, folder}] newest replay per run id, newest run first."""
    root = demo_root(recordings)
    if not root or not os.path.isdir(root):
        return []
    rec = recordings if recordings and os.path.isdir(os.path.join(recordings, "vmruns")) else os.path.dirname(root)
    meta = scenarios_by_run(rec)
    best = {}
    for d in os.listdir(root):
        m = RUN_ID.match(d)
        p = os.path.join(root, d)
        if not m or not os.path.isfile(os.path.join(p, "events.db")):
            continue
        rid, when = m.groups()
        if rid not in best or when > best[rid]["replayed"]:
            best[rid] = {"id": rid, "replayed": when, "folder": p, **(meta.get(rid) or {"scenario": None})}
    return sorted(best.values(), key=lambda r: r["id"], reverse=True)


# --- one run's steps ---------------------------------------------------------------------------------------------
_USER = re.compile(r"(?i)^c:\\users\\[^\\]+")
_TEST = re.compile(r"(?i)\\analystlab\\scenarios\\[^\\]+")
_CD = re.compile(r"(?i)^[d-z]:\\(?:blind\\)?[^\\]+(?:\\bin)?")


def _base(p):
    return re.split(r"[\\/]", p or "")[-1].lower()


def general_path(p):
    """A path with the parts that differ from run to run anyway replaced: <user>, <test folder>, <test CD>, #."""
    p = (p or "").replace("/", "\\")
    p = _USER.sub("<user>", p)
    p = _TEST.sub(r"\\AnalystLab\\scenarios\\<test folder>", p)
    p = _CD.sub("<test CD>", p) if not p.lower().startswith("c:") else p
    folder, _, name = p.rpartition("\\")
    stem, dot, ext = name.rpartition(".")
    stem = re.sub(r"\d+", "#", stem if dot else name)
    return (folder + "\\" if folder else "") + (stem + "." + ext.lower() if dot else stem)


def _is_test_root(image):
    i = (image or "").replace("/", "\\")
    return bool(re.match(r"(?i)^[d-z]:\\", i)) or bool(_TEST.search(i))


def steps(con, everything=False):
    """{kind: {key: {"count": n, "examples": [...]}}} of one run (see the module text)."""
    hw, hp = _files.host_clause()
    cols = {r[1].lower() for r in con.execute("PRAGMA table_info(events)")}
    rows = con.execute(
        "SELECT event_id, ProcessGuid, ParentProcessGuid, Image, ParentImage, TargetFilename, DestinationIp, "
        f"DestinationPort, Initiated, {'QueryName' if 'queryname' in cols else 'NULL'}, "
        f"{'TargetObject' if 'targetobject' in cols else 'NULL'}, origin, time "
        f"FROM events WHERE event_id IS NOT NULL AND COALESCE(origin, '') <> 'project'{hw} ORDER BY time, id", hp).fetchall()
    own = set()
    if not everything:
        for eid, guid, parent, image, *_ in rows:
            if eid == 1 and guid and (_is_test_root(image) or parent in own):
                own.add(guid)
    out = {k: {} for k in KINDS}

    def add(kind, key, example):
        e = out[kind].setdefault(key, {"count": 0, "examples": []})
        e["count"] += 1
        if example and example not in e["examples"] and len(e["examples"]) < 3:
            e["examples"].append(example)

    for eid, guid, parent, image, pimage, target, dip, dport, initiated, query, regkey, origin, t in rows:
        if not everything and guid not in own:
            continue
        actor = _base(image)
        if eid == 1:
            add("ran", _base(image), f"{_base(pimage)} → {_base(image)}")
        elif eid == 11 and target:
            add("created", general_path(target), f"{actor}: {target}")
        elif eid in (23, 26) and target:
            add("deleted", general_path(target), f"{actor}: {target}")
        elif eid == 3 and dip and str(initiated).lower() in ("true", "1"):
            add("connected", f"{dip}:{int(dport) if str(dport).isdigit() else dport}", actor)
        elif eid == 22 and query:
            add("looked_up", query.lower(), actor)
        elif eid in (12, 13, 14) and regkey:
            add("registry", general_path(re.sub(r"(?i)^hku\\[^\\]+", "HKU\\<user>", regkey)), actor)
    return out, len(own)


def alerts_of(folder):
    """(raised, below) of a run's alert database: [{rule, title, level}] (one per rule+title, with a count)."""
    from engine import config
    from engine.alerts import LEVELS, AlertStore
    db = os.path.join(folder, "alerts.db")
    if not os.path.exists(db):
        return [], []
    s = AlertStore(db)
    try:
        every = s.read()
    finally:
        s.close()
    floor = LEVELS.index(config.min_level())
    raised, below = {}, {}
    for a in every:
        if not _files.host_shown(a.host):
            continue
        d = raised if LEVELS.index(a.level) >= floor else below
        k = (a.rule_id, a.title)
        e = d.setdefault(k, {"rule": a.rule_id, "title": a.title, "level": a.level, "count": 0})
        e["count"] += 1
    return list(raised.values()), list(below.values())


# --- the diff --------------------------------------------------------------------------------------------------
def split(a, b, key=lambda x: x):
    """(only in a, in both, only in b) of two keyed collections."""
    ka, kb = {key(x): x for x in a}, {key(x): x for x in b}
    return ([ka[k] for k in ka if k not in kb], [(ka[k], kb[k]) for k in ka if k in kb], [kb[k] for k in kb if k not in ka])


def diff(folder_a, folder_b, everything=False):
    def read(folder):
        con = sqlite3.connect("file:" + os.path.join(folder, "events.db").replace("\\", "/") + "?mode=ro", uri=True)
        try:
            return steps(con, everything)
        finally:
            con.close()

    (sa, own_a), (sb, own_b) = read(folder_a), read(folder_b)
    kinds, differences = [], 0
    for k in KINDS:
        oa, both, ob = split(sa[k].items(), sb[k].items(), key=lambda kv: kv[0])
        kinds.append({"kind": k, "word": WORDS["kinds"][k],
                      "only_a": [{"key": key, **v} for key, v in sorted(oa)],
                      "both": [{"key": key, "a": va, "b": vb} for (key, va), (_, vb) in sorted(both, key=lambda p: p[0][0])],
                      "only_b": [{"key": key, **v} for key, v in sorted(ob)]})
        differences += len(oa) + len(ob)
    ra, ba = alerts_of(folder_a)
    rb, bb = alerts_of(folder_b)
    akey = lambda x: (x["rule"], x["title"])
    alerts = {}
    for name, (xa, xb) in (("raised", (ra, rb)), ("below", (ba, bb))):
        oa, both, ob = split(xa, xb, akey)
        alerts[name] = {"a": len(xa), "b": len(xb), "only_a": oa, "both": [x for x, _ in both], "only_b": ob}
        differences += len(oa) + len(ob)
    # the kinds of steps, counted (the twin's point: "both created files and deleted them again")
    summary = []
    for k in KINDS:
        na, nb = sum(v["count"] for v in sa[k].values()), sum(v["count"] for v in sb[k].values())
        summary.append({"kind": k, "word": WORDS["kinds"][k], "a": na, "b": nb,
                        "who": "both" if na and nb else "only_a" if na else "only_b" if nb else "neither"})
    return {"summary": summary, "kinds": kinds, "alerts": alerts, "differences": differences, "same": differences == 0,
            "own_processes": {"a": own_a, "b": own_b}, "everything": everything}


# --- routes ------------------------------------------------------------------------------------------------
def _public(r):
    return {k: r.get(k) for k in ("id", "scenario", "start", "replayed", "exit_code")}


def run_of(rs, when):
    """The run an alert time falls in: the latest run that started at or before it (same day), or None."""
    if not when:
        return None
    before = [r for r in rs if r.get("start") and r["start"][:19] <= when[:19] and r["start"][:10] == when[:10]]
    return max(before, key=lambda r: r["start"]) if before else None


@router.get("")
def listing(alert: str = None):
    ctx = labs.context()
    from engine import config
    rs = runs(getattr(ctx, "recordings", None))
    out = {"words": WORDS, "floor": config.min_level(), "runs": [_public(r) for r in rs], "alert": None, "suggested": None}
    if alert:
        a = ctx.alert(alert)
        if a is None or not ctx.allows(a.host):
            raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
        out["alert"] = {"id": a.alert_id, "title": a.title, "time": a.time}
        r = run_of(rs, a.time)
        if r:
            same = [x for x in rs if x["id"] != r["id"] and x.get("scenario") == r.get("scenario")]
            out["suggested"] = {"a": r["id"], "b": same[0]["id"] if same else None}
    return out


@router.get("/diff")
def run_diff(a: str, b: str, everything: bool = False):
    ctx = labs.context()
    rs = {r["id"]: r for r in runs(getattr(ctx, "recordings", None))}
    if a not in rs or b not in rs:
        raise HTTPException(status_code=404, detail="no replayed run with that id")
    out = diff(rs[a]["folder"], rs[b]["folder"], everything)
    return {"a": _public(rs[a]), "b": _public(rs[b]), **out}
