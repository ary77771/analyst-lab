"""Lab "Investigation checklist" (night 2026-11-24, night-explain; VISION's idea #6): for one alert, the questions an
analyst asks, each answered from the recorded evidence: in the story's own sentences (Proven / Suspected), or
"can't be known" with the missing witness (the prove lab's table), or "nothing recorded in this story" with how
much of that kind of activity this recorder records at all. It never says "clean".

    GET /api/labs/checklist                 the alerts the screens show, to pick one
    GET /api/labs/checklist/{alert_id}      the questions and their answers

"It" = the alert's own program (the ProcessGuid of its records) and every program it started, followed through
the story's own "started" links. Every answer line is a sentence of the alert's report (ctx.report: the same as
the Story screen and the report), so the checklist can never say more than the story does; a test compares
them. "Is it still running?" reads the store for the program's recorded end (Sysmon event 5). Read-only.

Switch off: delete this file (and dashboard/src/labs/checklist/).
"""

import re

from fastapi import APIRouter, HTTPException

from engine import labs

from . import _shared_defs as sd
from ._explain_common import MACHINERY_WORDS, PICK_WORDS, alert_row, picker, plainer, short_cmd, short_sha

router = APIRouter(prefix="/api/labs/checklist")

WORDS = {
    "title": "Investigation checklist",
    "intro": "Each answer is a sentence of the alert's own story; where the recording can't answer, it says so.",
    **PICK_WORDS,
    "questions": {
        "what": "What ran?",
        "who": "Who started it?",
        "user": "As which user?",
        "files": "Did it write files?",
        "network": "Did it connect out, and where to?",
        "persist": "Did it set up a way to come back (persistence)?",
        "deleted": "Did it delete anything?",
        "running": "Is it still running?",
        "unknown": "What can't be known here?",
        # merged from "I have an alert" (start) on 2026-11-24: computed by engine/labs/_triage.py
        "fired": "What fired?",
        "around": "What happened around it?",
        "sure": "How sure are we?",
        "todo": "What should be done?",
    },
    "sections": {"happened": "What happened?", "far": "How far did it go?", "sure": "How sure are we?", "now": "What now?"},
    "pick": "Pick an alert",
    "pick_note": "The same alert raised several times is shown once.",
    "times": "{n} times, first at {first}",
    "once": "once, at {first}",
    "status": {"fact": "Proven", "hypothesis": "Suspected", "gap": "Can't be known", "none": "Nothing recorded in this story",
               "mixed": "Partly proven", "unproven": "Not proven", "raised": "Alarm raised",
               "listed": "Published steps", "unchecked": "Not checked"},
    "scope": "\"It\" here: the alert's own program and every program it started ({n} in all).",
    "none_note": "Nothing of this kind is in this alert's story. That is not the same as \"it didn't happen\": {coverage}",
    "coverage": {"all": "this recorder records all {what}.", "some": "this recorder records only some {what} (its "
                 "configuration's filters), so one could have gone unrecorded.", "none": "this recorder does not record "
                 "{what} at all.", "unset": "this recorder's configuration does not set up {what}."},
    "coverage_what": {"files": "file creations", "network": "outgoing connections", "persist": "autostart changes",
                      "deleted": "file deletions"},
    "user_line": "The start record of {program} names the user: {user}.",
    "who_none": "No start of the alert's program is in this story (its view covers a time window around the alert; "
                "an older start lies outside it). Around this moment and the pivot show more of the recording.",
    "recording": "This recording: {records} from {machines} over {span}. The alert's story cites {cited} of them.",
    "program_cmd": "Command line",
    "program_launcher": "the lab's test launcher",
    "programs_hidden": "Hidden: programs of the lab's own test machinery: {n}.",
    "harness_switch": "Show the test machinery",
    "program_show_cmd": "show the full command lines",
    "raised_note": "The rule's verdict, as the alarm recorded it; this page did not re-check it on the records.",
    "program_parent": "Started by",
    "program_children": "Started",
    "program_unrecorded": "its start is not in this recording",
    "harness_parent": " (that is the lab's own test machinery: {reason})",
    "harness_hidden": "{n} lines of the lab's own test machinery (its launcher, its report back to the laptop) are left out.",
    "what_line": "The alert's own record names the program {program}.",
    "user_missing": "The start record of the alert's program names no user.",
    "running_ended": "{program} ended at {time} (its end is recorded).",
    "running_open": "No end of {program} is recorded up to this store's last record ({last}). It was still running "
                    "then, or the recorder stopped first: the recording can't tell which.",
    "running_nostart": "The alert's own program is not in the store, so its end can't be looked up.",
    "unknown_line": "In this story: {gaps}, {hyps}.",
    "unknown_edge": " Apart from {n} that started before this recording began (its edge, not a blind spot).",
    "witness": "Would be proven by",
    "more": "+{n} more",
    "open": {"why": "Why?", "moment": "Around this moment", "prove": "What would prove it?", "pivot": "Everything about this program",
             "persistence": "Persistence before/after", "story": "The story", "respond": "What to do next",
             "claim": "Test a claim", "alarm": "Word for word"},
    "no_story": "The evidence graph could not be built for this alert here, so only what its own records say is shown.",
}

MAX_LINES = 8
ZERO = re.compile(r"^\{?0{8}-0{4}-0{4}-0{4}-0{12}\}?$")
COVERAGE = {"files": "FileCreate", "network": "NetworkConnect", "persist": "RegistryEvent", "deleted": "FileDeleteDetected"}
# question -> (fact link kinds, hypothesis link kinds, which end of the link must be "it")
ASKS = {
    "files": ({"created"}, set(), "u"),
    "network": ({"connected_to", "looked_up"}, {"name_for_connection"}, "u"),
    "persist": ({"set_autostart", "will_start"}, set(), "u"),
    "deleted": ({"deleted"}, set(), "u"),
}


def _guid(node):
    """The ProcessGuid of a graph process node ('proc:<host>:{GUID}'), upper-case; None for other nodes."""
    if not isinstance(node, str) or not node.startswith("proc:"):
        return None
    return node.rsplit(":", 1)[-1].upper()


def scope(content, guids):
    """The alert's own process nodes and every process they started (through the story's 'started' facts)."""
    facts = content.get("facts", [])
    nodes = [f.get(e) for f in facts + content.get("hypotheses", []) for e in ("u", "v")]
    nodes += [g.get("node_id") for g in content.get("gaps", [])]
    own = {n for n in nodes if _guid(n) in guids}
    seen, todo = set(own), list(own)
    while todo:
        n = todo.pop()
        for f in facts:
            if f.get("kind") == "started" and f.get("u") == n and f.get("v") not in seen:
                seen.add(f["v"])
                todo.append(f["v"])
    return own, seen


def _lines(items, ink):
    return [{"ink": ink, "text": plainer(it.get("sentence") or it.get("plain") or ""), "time": it.get("time_precise") or (None if it.get("placement") == "before" else it.get("time"))}
            for it in items]


def _coverage(question, cfg):
    el = COVERAGE.get(question)
    st = (cfg or {}).get(el, {}).get("state", "unset") if el else "unset"
    st = "all" if st == "most" else st
    return WORDS["coverage"][st].format(what=WORDS["coverage_what"][question])


def _witness(kind, cfg):
    try:
        from . import prove
        return prove.explain_row(kind, cfg)
    except Exception:                       # the prove lab is optional: the checklist works without it
        return None


def _n(n, one, many):
    return f"{n} {one if n == 1 else many}"


def _folder_line(item):
    """A story line about creating a folder, said as a folder (the graph writes "created payload" for both)."""
    return dict(item, text=item["text"].replace(" created ", " created the folder ", 1))


def answer(content, guids, start_event=None, end_info=None, cfg=None, folders=(), harness=None, machinery=None,
           machinery_nodes=None):
    """The checklist (pure over the report's content; tests call it with fixtures)."""
    facts, hyps, gaps = content.get("facts", []), content.get("hypotheses", []), content.get("gaps", [])
    own, it = scope(content, guids)
    out = []

    hz = harness or {}                       # {story item id: why it is the lab's own test machinery}
    mz = machinery or {}                     # {story item id: plain note: it names the lab's own test launcher}

    def q(key, status, lines, note=None, witness=None, links=(), hidden=0):
        out.append({"key": key, "question": WORDS["questions"][key], "status": status, "lines": lines[:MAX_LINES],
                    "more": max(0, len(lines) - MAX_LINES), "note": note, "witness": witness, "links": list(links),
                    "harness_hidden": hidden})

    # what ran: the alert's program and the programs it started
    # the lab's own test machinery among "it" (on the live store: VirtualBox's helper started by the launcher) is
    # never the alert's activity: left out of what ran and of the count (critique-4), shown behind the switch
    shown = set(it) - set(machinery_nodes or ())
    started = [f for f in facts if f.get("kind") == "started" and f.get("v") in shown and f.get("u") in it]
    ran = [f for f in facts if f.get("kind") == "ran_as" and f.get("u") in shown]
    what = _lines(ran + started, "fact")
    if not what and start_event and start_event.get("Image"):
        what = [{"ink": "fact", "time": None, "text": WORDS["what_line"].format(program=start_event["Image"].rsplit("\\", 1)[-1])}]
    q("what", "fact" if what else "none", what,
      note=WORDS["scope"].format(n=len(shown)) if shown else None, links=["why", "pivot"])
    # who started it
    parent = [f for f in facts if f.get("kind") == "started" and f.get("v") in own and f.get("u") not in own]
    remote = [h for h in hyps if h.get("kind") in ("remote_command", "fetched_then_ran") and h.get("v") in own]
    no_parent = [g for g in gaps if g.get("kind") in ("parent_unknown", "origin_unknown") and g.get("node_id") in own]
    if parent:
        who = _lines(parent, "fact")
        for line, item in zip(who, parent):          # the parent may be the lab's own launcher: said so
            if mz.get(item.get("id")):
                line["text"] += ": " + mz[item["id"]]
            elif hz.get(item.get("id")):
                line["text"] += WORDS["harness_parent"].format(reason=hz[item["id"]])
        q("who", "fact", who + _lines(remote, "hypothesis"), links=["moment"])
    elif remote:
        q("who", "hypothesis", _lines(remote, "hypothesis"), witness=_witness(remote[0]["kind"], cfg), links=["prove"])
    elif no_parent:
        q("who", "gap", _lines(no_parent, "gap"), witness=_witness(no_parent[0]["kind"], cfg), links=["prove"])
    else:
        q("who", "none", [], note=WORDS["who_none"], links=["moment", "pivot"])
    # as which user
    if start_event and start_event.get("User"):
        q("user", "fact", [{"ink": "fact", "time": None, "text": WORDS["user_line"].format(
            program=(start_event.get("Image") or "?").rsplit("\\", 1)[-1], user=start_event["User"])}], links=["why"])
    else:
        q("user", "none", [{"ink": None, "time": None, "text": WORDS["user_missing"]}])
    # files, network, persistence, deletions: the story's own lines about "it"
    for key, (fk, hk, end) in ASKS.items():
        fl = [f for f in facts if f.get("kind") in fk and f.get(end) in it]
        hidden = sum(1 for f in fl if f.get("id") in hz)
        fl = [f for f in fl if f.get("id") not in hz]                # the test machinery is not the alert's activity
        if key == "network":
            nets = {f.get("v") for f in fl}
            hl = [h for h in hyps if h.get("kind") in hk and h.get("v") in nets]
        else:
            hl = [h for h in hyps if h.get("kind") in hk and h.get(end) in it]
        extra = []
        folder_lines = []
        if key == "files":                       # the content of a file it wrote that the recorder could not fingerprint
            # a created FOLDER (the recorder's FILE_HASH says "directory") is not a written file: said apart
            is_folder = lambda n: isinstance(n, str) and n.split(":", 2)[-1].lower() in folders
            folder_lines = [_folder_line(x) for x in _lines([f for f in fl if is_folder(f.get("v"))], "fact")]
            fl = [f for f in fl if not is_folder(f.get("v"))]
            written = {f.get("v") for f in fl}
            extra = [g for g in gaps if g.get("kind") == "content_unknown" and g.get("node_id") in written]
        status = "fact" if fl else "hypothesis" if hl else "none"
        links = {"files": ["moment", "pivot"], "network": ["moment", "pivot"], "persist": ["persistence", "moment"],
                 "deleted": ["moment"]}[key]
        q(key, status, _lines(fl, "fact") + _lines(hl, "hypothesis") + _lines(extra, "gap") + folder_lines,
          note=None if fl or hl else WORDS["none_note"].format(coverage=_coverage(key, cfg)), links=links, hidden=hidden)
    # still running?
    if end_info is None:
        q("running", "none", [{"ink": None, "time": None, "text": WORDS["running_nostart"]}])
    elif end_info.get("ended"):
        q("running", "fact", [{"ink": "fact", "time": end_info["ended"], "text": WORDS["running_ended"].format(
            program=end_info["program"], time=end_info["ended"])}], links=["moment"])
    else:
        q("running", "gap", [{"ink": "gap", "time": None, "text": WORDS["running_open"].format(
            program=end_info["program"], last=end_info.get("last") or "?")}], links=["moment"])
    # what can't be known
    real_gaps = [g for g in gaps if g.get("kind") not in ("origin_unknown", "parent_unknown")]
    in_story = real_gaps + hyps
    q("unknown", "gap" if in_story else "none",
      [{"ink": None, "time": None, "text": WORDS["unknown_line"].format(
          gaps=_n(len(real_gaps), "gap", "gaps"), hyps=_n(len(hyps), "suspected link", "suspected links"))
          + (WORDS["unknown_edge"].format(n=_n(len(gaps) - len(real_gaps), "program", "programs")) if len(gaps) > len(real_gaps) else "")}],
      links=["prove"])
    return {"questions": out, "scope": sorted(it), "own": sorted(own)}


def _span(seconds):
    if seconds is None:
        return "an unknown time"
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.0f} minutes"
    return f"{seconds / 3600:.1f} hours"


def recording_line(ctx, a, content):
    """One plain line: how big the recording is and how much of it the story cites (the reading-effort numbers)."""
    from engine.graph import parse_time
    try:
        with ctx.reading() as con:
            n, first, last = con.execute("SELECT COUNT(*), MIN(time), MAX(time) FROM events WHERE host = ?", (a.host,)).fetchone()
            machines = con.execute("SELECT COUNT(DISTINCT host) FROM events").fetchone()[0] or 1
    except Exception:
        return None
    t0, t1 = parse_time(first), parse_time(last)
    cited = {c["key"] for part in ("facts", "hypotheses", "gaps") for it in (content or {}).get(part, [])
             for c in it.get("citations", []) if c.get("key")}
    return WORDS["recording"].format(records=f"{n:,} records", machines=_n(machines, "machine", "machines"), span=_span((t1 - t0).total_seconds() if t0 and t1 else None),
                                     cited=len(cited))


def _end_info(ctx, a, start_event):
    """The alert's program's recorded end (event 5 with its ProcessGuid), and the store's last record time."""
    guid = (start_event or {}).get("ProcessGuid")
    if not guid or ZERO.match(guid):
        return None
    program = (start_event.get("Image") or "?").rsplit("\\", 1)[-1]
    with ctx.reading() as con:
        row = con.execute("SELECT MIN(COALESCE(UtcTime, time)) FROM events WHERE event_id = 5 AND ProcessGuid = ? COLLATE NOCASE AND host = ?",
                          (guid, a.host)).fetchone()
        last = con.execute("SELECT MAX(time) FROM events WHERE host = ?", (a.host,)).fetchone()
    return {"program": program, "ended": row[0] if row else None, "last": last[0] if last else None}


SECTION = {"fired": "happened", "what": "happened", "who": "happened", "user": "happened", "around": "happened",
           "files": "far", "network": "far", "persist": "far", "deleted": "far", "running": "far",
           "sure": "sure", "unknown": "sure", "todo": "now"}
ORDER = ["fired", "what", "who", "user", "around", "files", "network", "persist", "deleted", "running", "sure", "unknown", "todo"]


def triage_steps(ctx, a, content):
    """The four steps taken over from "I have an alert", each computed alone (never _triage.steps(): its "spread"
    step reads this checklist). A step that fails says "Not checked", the others go on."""
    from . import _triage
    plan = [("fired", "why", lambda: _triage.step_fired(ctx, a)), ("around", "moment", lambda: _triage.step_around(ctx, a)),
            ("sure", "claim", lambda: _triage.step_sure(content)), ("todo", "respond", lambda: _triage.step_todo(a))]
    out = []
    for key, lab, fn in plan:
        if content is None and key == "sure":
            out.append(_triage._unchecked(key, lab))
            continue
        try:
            out.append(fn())
        except Exception as e:
            out.append(_triage._unchecked(key, lab, f"{type(e).__name__}: {str(e)[:120]}"))
    return out


def with_triage(questions, steps):
    """The checklist's questions plus the triage steps it took over from "I have an alert", in reading order, each
    with its section. A triage step keeps its own status word (never stronger than its evidence)."""
    qs = {q["key"]: q for q in questions}
    for s in steps:
        if s["key"] in ("fired", "around", "sure", "todo"):
            qs[s["key"]] = {"key": s["key"], "question": WORDS["questions"][s["key"]], "status": s["status"],
                            "lines": [{"ink": s["status"], "time": None, "text": s["line"]}], "more": 0,
                            "note": s.get("reason") or (WORDS["raised_note"] if s["status"] == "raised" else None),
                            "witness": None, "links": [s["lab"]]}
    out = [qs[k] for k in ORDER if k in qs] + [q for k, q in qs.items() if k not in ORDER]
    for q in out:
        q["section"] = SECTION.get(q["key"], "happened")
    return out


def summary_of(ctx, a, content, cfg, out, programs, folders, marks, notes, mnodes):
    """The incident in one paragraph (engine/labs/_summary.py), each part labelled with the question or lab it
    summarises. Fails alone: no paragraph rather than a broken page."""
    try:
        from . import _summary
        launcher = {k for k, v in (notes or {}).items() if v == MACHINERY_WORDS["started_by"]}
        names, extra = _summary.gather(ctx, a, content, cfg, programs, folders, marks, launcher)
        shown = [n for n in out["scope"] if n not in set(mnodes)]
        para = _summary.summary(out["questions"], content, names, shown, extra)
        labels = {q["key"]: q["question"] for q in out["questions"]}
        labels.update(_summary.WORDS["sources"])
        for s in para:
            for p in s:
                p["label"] = labels.get(p["source"], p["source"])
        return para
    except Exception:
        return []


@router.get("")
def pick():
    from ._triage import groups
    ctx = labs.context()
    return {**picker(ctx), "words": WORDS, "groups": groups(ctx.shown_alerts())}


def folders_of(ctx, host):
    """The paths the recorder found to be folders (FILE_HASH with hash_status "directory"), lower-case."""
    try:
        with ctx.reading() as con:
            rows = con.execute("SELECT TargetFilename FROM events WHERE type = 'FILE_HASH' AND hash_status = 'directory' "
                               "AND host = ?", (host,)).fetchall()
    except Exception:
        return set()
    return {str(r[0]).lower() for r in rows if r[0]}


def programs_of(ctx, host, nodes, limit=12):
    """Each program of "it": its image, PID, FULL command line, its parent (image + command line) and the programs
    it started, from its own start record (Sysmon event 1). A program whose start is not recorded says so."""
    guids = [_guid(n) for n in nodes if _guid(n)]
    out = []
    try:
        with ctx.reading() as con:
            con.row_factory = __import__("sqlite3").Row
            for g in guids[:limit]:
                r = con.execute("SELECT Image, ProcessId, CommandLine, ParentImage, ParentCommandLine, User, UtcTime, time "
                                "FROM events WHERE event_id = 1 AND ProcessGuid = ? COLLATE NOCASE AND host = ? LIMIT 1",
                                (g, host)).fetchone()
                kids = con.execute("SELECT Image, ProcessId FROM events WHERE event_id = 1 AND ParentProcessGuid = ? "
                                   "COLLATE NOCASE AND host = ? ORDER BY time LIMIT 10", (g, host)).fetchall()
                out.append({"guid": g, "recorded": r is not None,
                            "image": r["Image"] if r else None, "pid": r["ProcessId"] if r else None,
                            "command_line": r["CommandLine"] if r else None,
                            "command_short": short_cmd(r["CommandLine"]) if r else None,
                            "parent": (r["ParentImage"] if r and r["ParentImage"] not in (None, "", "-") else None),
                            "parent_command_line": r["ParentCommandLine"] if r else None, "user": r["User"] if r else None,
                            "parent_machinery": (MACHINERY_WORDS["is"] if r and sd.harness_reason(
                                {"Image": r["ParentImage"], "CommandLine": r["ParentCommandLine"]}) else None),
                            "time": (r["UtcTime"] or r["time"]) if r else None,
                            "children": [{"image": k["Image"], "pid": k["ProcessId"]} for k in kids if k["Image"]]})
    except Exception:
        return []
    out.sort(key=lambda p: (not p["recorded"], p["time"] or ""))
    return out


@router.get("/{alert_id}")
def checklist(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    events = [ctx.event(k) for k in a.evidence[:20]]
    events = [e for e in events if e]
    guids = {str(e.get("ProcessGuid")).upper() for e in events if e.get("ProcessGuid") and not ZERO.match(str(e["ProcessGuid"]))}
    start = next((e for e in events if e.get("event_id") == 1), events[0] if events else None)
    try:
        from . import prove
        cfg = prove.config()
    except Exception:
        cfg = None
    try:
        content, story = ctx.report(a), True
    except Exception:
        content, story = {}, False
    from ._explain_common import harness_marks
    marks = harness_marks(ctx, content.get("facts", []) + content.get("hypotheses", [])) if story else {}
    from ._explain_common import machinery_notes
    notes = machinery_notes(ctx, a.host, content.get("facts", []) + content.get("gaps", [])) if story else {}
    mnodes = set()
    if story:
        from ._explain_common import process_machinery
        try:
            with ctx.reading() as con:
                mnodes = {n for n in scope(content, guids)[1] if process_machinery(con, a.host, n)}
        except Exception:
            mnodes = set()
    folders = folders_of(ctx, a.host)
    out = answer(content, guids, start, _end_info(ctx, a, start), cfg, folders=folders, harness=marks,
                 machinery=notes, machinery_nodes=mnodes)
    programs = programs_of(ctx, a.host, out["scope"])
    machinery_guids = {str(n).rsplit(":", 1)[-1].upper() for n in mnodes}
    for p in programs:
        p["harness"] = str(p.get("guid") or "").upper() in machinery_guids
    out["questions"] = with_triage(out["questions"], triage_steps(ctx, a, content if story else None))
    for q in out["questions"]:
        if q["key"] == "what":
            q["programs"] = programs
    out["summary"] = summary_of(ctx, a, content, cfg, out, programs, folders, marks, notes, mnodes) if story else []
    guid = (start or {}).get("ProcessGuid")
    words = dict(WORDS)
    try:
        from . import _summary
        words["summary"] = {k: v for k, v in _summary.WORDS.items() if k in ("title", "hover")}
    except Exception:
        words["summary"] = {}
    try:
        from . import prove
        words["verdict"] = prove.WORDS["verdict"]
    except Exception:
        words["verdict"] = {}
    return {"words": words, "alert": alert_row(a), "story": story, "guid": guid, "host": a.host,
            "recording": recording_line(ctx, a, content), **out}
