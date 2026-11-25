"""Lab: Process tree. "Which program started which, and with what command line?" for one alert's run.

The tree of program starts (Sysmon event 1) around an alert: from the alert's own programs (its story, as the
Story screen tells it) up through their parents, then everything those roots started within a window around
the alert. Every program shows its FULL command line, user and start time. The alert's own programs are
marked; the lab's test machinery (our runner) is dimmed; a parent whose start was not recorded is shown as
such (a gap), with the command line its children recorded for it.

The parts of a command line an analyst looks at first are marked (a web address, an IP address, a 64-digit
fingerprint, an encoded command, a "-server"-style switch), and the alert's line with most of them is named
"look here first". Marks are pointers to read, not findings. Read-only; VM data only (labs.context()).
"""

import re
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _files
from engine.labs import _shared_defs as sd

router = APIRouter(prefix="/api/labs/tree")

WINDOW_BEFORE = timedelta(minutes=10)
WINDOW_AFTER = timedelta(minutes=10)
MAX_NODES = 200

WORDS = {
    "title": "Process tree",
    "intro": ("Which program started which around this alert, each with its full command line, its user and when it "
              "started. The alert's own programs are marked; the lab's test machinery is dimmed."),
    "pick": "Pick an alert",
    "first": "Look here first",
    "first_why": "this command line names {what}",
    "marks_note": "Marked parts are what an analyst reads first: addresses, fingerprints, encoded commands. A pointer, not a finding.",
    "not_recorded": "start not recorded (it was running before the recorder, or started outside it); its command line is what its child recorded",
    "harness": "the lab's own test machinery",
    "own": "in this alert's story",
    "show_harness": "show the lab's test machinery",
    "show_full": "show the full chain to the system root ({n} more programs)",
    "show_branch": "show only this alert's branch",
    "folded_note": "Showing this alert's own programs, what they started, and the program that started them.",
    "none": "No program start of this alert's story is in this recording.",
    "kinds": {"url": "a web address", "ip": "an IP address", "hash": "a fingerprint (SHA-256)", "encoded": "an encoded command",
              "switch": "a server or download switch"},
}

MARKS = [
    ("url", re.compile(r"\b(?:https?|ftp)://[^\s\"']+", re.I)),
    ("ip", re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![\w.])")),
    ("hash", re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")),
    ("encoded", re.compile(r"(?i)(?<!\w)-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}")),
    ("switch", re.compile(r"(?i)(?<![\w-])-{1,2}(?:server|url|uri|download|upload|exfil|c2|beacon|sha256|hash|payload)\b")),
]
ZERO_GUID = re.compile(r"^\{?0{8}-0{4}-0{4}-0{4}-0{12}\}?$")


def marks(cmd):
    """[[start, end, kind]] of the parts of a command line to read first (overlaps: the longer one wins)."""
    found = []
    for kind, rx in MARKS:
        for m in rx.finditer(cmd or ""):
            found.append([m.start(), m.end(), kind])
    found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    out = []
    for s, e, k in found:
        if out and s < out[-1][1]:
            continue
        out.append([s, e, k])
    return out


def _t(s):
    try:
        return datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError:
        return None


def _base(p):
    return re.split(r"[\\/]", p or "")[-1]


def harness_check(ctx=None):
    """The lab's own test machinery: the one shared definition every lab uses (_shared_defs.is_harness)."""
    return sd.is_harness


def build(rows, own, alert_time, is_harness=lambda r: False):
    """The tree for these event-1 rows. `own` = the alert's story ProcessGuids (lower case). Returns
    {nodes: [...], roots: [guids], focus: guid or None} with each node:
    {guid, name, image, cmd, user, time, pid, parent, children, depth, own, ancestor, harness, recorded, marks}."""
    by = {}
    for r in rows:
        g = (r.get("ProcessGuid") or "").lower()
        if g and g not in by:
            by[g] = r
    kids = {}
    for g, r in by.items():
        p = (r.get("ParentProcessGuid") or "").lower()
        if p and not ZERO_GUID.match(p):
            kids.setdefault(p, []).append(g)
    # up from the alert's own programs: every ancestor; the topmost (recorded or not) are the roots
    ancestors, roots = set(), []
    for g in sorted(own):
        cur, seen = g, set()
        while cur and cur not in seen:
            seen.add(cur)
            r = by.get(cur)
            parent = (r.get("ParentProcessGuid") or "").lower() if r else ""
            if not r or not parent or ZERO_GUID.match(parent):
                if cur not in roots:
                    roots.append(cur)
                break
            ancestors.add(parent)
            if parent not in by:                      # a parent whose start was not recorded: it is the root
                if parent not in roots:
                    roots.append(parent)
                break
            cur = parent
    t0 = _t(alert_time)
    lo, hi = (t0 - WINDOW_BEFORE, t0 + WINDOW_AFTER) if t0 else (None, None)

    def in_window(g):
        r = by.get(g)
        t = _t(r.get("time")) if r else None
        return g in own or g in ancestors or t is None or lo is None or lo <= t <= hi

    nodes, order = {}, []

    def node(g, depth, parent):
        r = by.get(g)
        if r is None:                                 # the start was not recorded: what a child says about it
            child = by.get(next((k for k in kids.get(g, []) if k in by), ""), {})
            image, cmd = child.get("ParentImage"), child.get("ParentCommandLine")
            return {"guid": g, "name": _base(image) or "unknown program", "image": image, "cmd": cmd, "user": child.get("ParentUser"),
                    "time": None, "pid": child.get("ParentProcessId"), "recorded": False}
        return {"guid": g, "name": _base(r.get("Image")), "image": r.get("Image"), "cmd": r.get("CommandLine"),
                "user": r.get("User"), "time": r.get("time"), "pid": r.get("ProcessId"), "recorded": True}

    stack = [(g, 0, None) for g in reversed(roots)]
    while stack and len(order) < MAX_NODES:
        g, depth, parent = stack.pop()
        if g in nodes:
            continue
        n = node(g, depth, parent)
        r = by.get(g) or {}
        probe = r or {"CommandLine": n["cmd"], "Image": n["image"]}   # a parent not recorded: what its child says
        n.update(parent=parent, depth=depth, own=g in own, ancestor=g in ancestors,
                 harness=bool(is_harness(probe)), marks=marks(n["cmd"]), children=[])
        nodes[g] = n
        order.append(g)
        if parent and parent in nodes:
            nodes[parent]["children"].append(g)
        cs = sorted((c for c in kids.get(g, []) if in_window(c)), key=lambda c: (by[c].get("time") or "", c))
        stack.extend((c, depth + 1, g) for c in reversed(cs))
    focus = max((nodes[g] for g in order if nodes[g]["own"] and nodes[g]["marks"]),
                key=lambda n: (len({m[2] for m in n["marks"]}), len(n["marks"])), default=None)
    hidden = branch(nodes, order)
    return {"nodes": [nodes[g] for g in order], "roots": roots, "focus": focus and focus["guid"],
            "truncated": len(order) >= MAX_NODES, "folded": hidden}


def branch(nodes, order):
    """Critique 3 #9: on a live machine the tree starts at the system root (services.exe ...) and buries the
    alert. The page opens on the alert's OWN BRANCH: its own programs, everything they started, and the program
    one level up that started the topmost of them. Each node gets `branch` (in it or not) and `branch_depth`
    (its depth within it); the system chain above and the other programs beside are folded behind one switch.
    Returns how many programs are folded away (0: nothing to fold, the switch is not shown)."""
    own = [g for g in order if nodes[g]["own"]]
    # An own program that is only an ANCESTOR of other own ones (the story names e.g. svchost.exe above the
    # alert's programs) keeps just its own children; everything else it started is the system around, folded.
    chain = set()
    for g in own:
        p = nodes[g]["parent"]
        while p in nodes and p not in chain:
            if nodes[p]["own"]:
                chain.add(p)
            p = nodes[p]["parent"]
    below = set(own)
    for g in order:                                       # everything the alert's programs started (pre-order)
        p = nodes[g]["parent"]
        if p in below and (p not in chain or nodes[g]["own"]):
            below.add(g)
    above = {nodes[g]["parent"] for g in own              # the program one level up from each topmost own one
             if nodes[g]["parent"] in nodes and nodes[g]["parent"] not in below}
    keep = below | above if own else set(order)           # nothing of the alert's own in the tree: show all of it
    for g in order:
        n, p = nodes[g], nodes[g]["parent"]
        n["branch"] = g in keep
        n["branch_depth"] = (nodes[p]["branch_depth"] + 1 if p in keep else 0) if g in keep else None
    return len(order) - len(keep)


@router.get("")
def tree(alert: str = None):
    ctx = labs.context()
    alerts = [{"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time}
              for a in ctx.shown_alerts() if ctx.allows(a.host)]
    out = {"words": WORDS, "alerts": alerts, "alert": None, "tree": None}
    if not alert:
        return out
    try:
        scope = _files.alert_scope(ctx, alert)
    except _files.NotYet as e:                             # a replay still playing: the page says so and asks again
        out["waiting"] = str(e)
        return out
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    cols = ("time", "UtcTime", "ProcessGuid", "ParentProcessGuid", "Image", "CommandLine", "User", "ProcessId", "origin",
            "ParentImage", "ParentCommandLine", "ParentProcessId", "ParentUser")
    try:
        with ctx.reading() as con:
            have = {r[1].lower() for r in con.execute("PRAGMA table_info(events)")}
            sel = ", ".join(c if c.lower() in have else f"NULL AS {c}" for c in cols)
            rows = [dict(zip(cols, r)) for r in con.execute(
                f"SELECT {sel} FROM events WHERE event_id = 1 AND lower(host) = lower(?)", (scope["host"],))]
        for r in rows:                                     # one clock: Sysmon's UtcTime, else the record time
            r["time"] = sd.when(r) or r["time"]
        rows.sort(key=lambda r: r["time"] or "")
    except (FileNotFoundError, Exception) as e:            # an empty or missing store: said, never raised
        rows = []
    t = build(rows, scope["guids"], scope["alert"]["time"], harness_check(ctx))
    out.update(alert=scope["alert"], tree=t)
    if t["focus"]:
        f = next(n for n in t["nodes"] if n["guid"] == t["focus"])
        kinds = []
        for m in f["marks"]:
            w = WORDS["kinds"][m[2]]
            if w not in kinds:
                kinds.append(w)
        out["first"] = {"guid": f["guid"], "why": WORDS["first_why"].format(what=", ".join(kinds))}
    return out
