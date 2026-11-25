"""The triage steps of an alert (night-explain): what fired, what happened around it, how sure the story is,
whether it spread, what can't be seen, what should be done. Each step is computed by the lab that owns it (why,
moment, the report, checklist, prove, respond), in-process and read-only; a lab that is missing or fails gives
"Not checked", never a guess.

Shared by the checklist (the landing page) and the older "I have an alert" page, so a fix lands in both.
A step's status word is never stronger than its evidence (honest()).
"""
from ._explain_common import alert_row

WORDS = {
    "title": "I have an alert",
    "intro": "Start here. Pick an alert, then follow the six questions; each answer comes from the page that shows "
             "it in full, one click away.",
    "pick": "Step 1: pick an alert",
    "pick_note": "The same alert raised several times is shown once.",
    "times": "{n} times, first at {first}",
    "once": "once, at {first}",
    "no_alerts": "No alert at or above the level the screens show is in this alert database yet.",
    "path": "Step 2: six questions",
    "status": {"fact": "Proven", "hypothesis": "Suspected", "gap": "Can't be known", "none": "Nothing recorded",
               "unchecked": "Not checked", "mixed": "Partly proven",
               "unproven": "Not proven", "raised": "Alarm raised",
               "listed": "Published steps"},
    "questions": {
        "fired": "What fired?",
        "around": "What exactly happened around it?",
        "sure": "How sure are we?",
        "spread": "Did it spread or stay (connections, autostarts)?",
        "unseen": "What can't we see?",
        "todo": "What should be done?",
    },
    "fired": "The rule \"{rule}\" ({level}) fired on {events}.",
    "fired_checked": " Its match was checked again on the record itself.",
    "fired_python": "Analyst Lab's own rule \"{rule}\" ({level}) fired on {events}.",
    "around": "{events} from {programs} within 30 seconds either side.",
    "around_machinery": " Counted apart: the lab's own test machinery, {records} from {programs}.",
    "sure": "Its story: {facts} Proven, {hyps} Suspected, {gaps} Can't be known.",
    "spread_net": "Connections: {line}",
    "spread_persist": "Autostarts: {line}",
    "unseen": "Not proven in its story: {parts}.",
    "unseen_other": " {other} would need another kind of tool to settle (see which and why).",
    "unseen_here": " This recorder collects the kind of record that would settle each of them.",
    "unseen_none": "Its story has no Suspected line and no gap.",
    "unseen_edge": " Apart from {n} that started before this recording began (its edge, not a blind spot).",
    "todo": "MITRE lists {mits} and D3FEND {defs} for {techniques}.",
    "todo_reading": " (technique by Analyst Lab's reading of its own rule)",
    "todo_none": "Its rule names no ATT&CK technique, so there is no published response step for it.",
    "unchecked": "Not checked: {lab} is not available on this dashboard.",
    "open": "Open",
    "labs": {"why": "Why is this suspicious?", "moment": "Around this moment", "alarm": "This is what an alarm says",
             "checklist": "Investigation checklist", "prove": "What would prove it?", "respond": "What to do next",
             "claim": "Test a claim"},
}


def groups(alerts):
    """The alerts once per (title, rule), newest occurrence first: {id (newest), ids, count, first, last, ...}."""
    out = {}
    for a in sorted(alerts, key=lambda a: a.time):
        g = out.setdefault((a.title, a.rule_id), {"title": a.title, "rule_id": a.rule_id, "level": a.level,
                                                    "first": a.time, "ids": []})
        g["ids"].insert(0, a.alert_id)
        g["last"] = a.time
    rows = [dict(g, id=g["ids"][0], count=len(g["ids"])) for g in out.values()]
    return sorted(rows, key=lambda g: g["last"], reverse=True)


def honest(parts):
    """One status for a step built from several answers, never stronger than its weakest part: Proven only when
    every part is Proven; "Nothing recorded" only when every part is; a mix with something Proven is "Partly
    proven"; otherwise the weakest of Suspected / Can't be known."""
    parts = [p for p in parts if p]
    if not parts:
        return "none"
    if all(p == "fact" for p in parts):
        return "fact"
    if all(p == "none" for p in parts):
        return "none"
    if "fact" in parts:
        return "mixed"
    for weak in ("gap", "hypothesis", "unproven", "none"):
        if weak in parts:
            return weak
    return parts[0]


def _n(n, one, many):
    """'1 gap', '2 gaps': counts in plain words, never '(s)'."""
    return f"{n} {one if n == 1 else many}"


def _step(key, status, line, lab, extra=None):
    return {"key": key, "question": WORDS["questions"][key], "status": status, "status_word": WORDS["status"][status],
            "line": line, "lab": lab, "lab_name": WORDS["labs"].get(lab, lab), **(extra or {})}


def _unchecked(key, lab, reason=None):
    return _step(key, "unchecked", WORDS["unchecked"].format(lab=WORDS["labs"].get(lab, lab)), lab, {"reason": reason})


def step_fired(ctx, a):
    from . import why
    d = why.explain(ctx, a)
    if d["rule"]["kind"] in ("python", "beacon"):
        line = WORDS["fired_python"].format(rule=a.title, level=a.level, events=_n(d["events_total"], "recorded event", "recorded events"))
    else:
        line = WORDS["fired"].format(rule=a.title, level=a.level, events=_n(d["events_total"], "recorded event", "recorded events"))
        if d["check"] == "reproduced":
            line += WORDS["fired_checked"]
    # Proven only when this page re-checked the rule's match on the record itself; an own (Python) rule or a rule
    # whose check did not reproduce is "raised", never Proven
    status = "fact" if d["check"] == "reproduced" else "raised"
    return _step("fired", status, line, "why", {"numbers": {"events": d["events_total"], "check": d["check"]}})


def step_around(ctx, a):
    from engine.graph import parse_time
    from . import moment
    alert_keys = {}
    for x in ctx.shown_alerts():
        for k in x.evidence:
            alert_keys.setdefault(k, []).append(x.alert_id)
    with ctx.reading() as con:
        m = moment.around(con, a.host, parse_time(a.time), 30, list(a.evidence), alert_keys)
    c = m["counts"]                      # the moment page's own numbers: one rule, the same words (sd.WORDS)
    from . import _shared_defs as sd
    events, programs = c["records"], c["programs"]
    status = "fact" if events else "none"
    line = WORDS["around"].format(events=_n(events, "record", sd.WORDS["records"]),
                                  programs=_n(programs, "program", sd.WORDS["programs"]))
    if c["machinery_records"]:
        line += WORDS["around_machinery"].format(records=_n(c["machinery_records"], "record", sd.WORDS["records"]),
                                                 programs=_n(c["machinery_programs"], "program", sd.WORDS["programs"]))
    return _step("around", status, line, "moment", {"numbers": {"events": events, "programs": programs, **c}})


def step_sure(content):
    c = content.get("counts", {})
    n = {"facts": c.get("facts", 0), "hyps": c.get("hypotheses", 0), "gaps": c.get("gaps", 0)}
    status = "mixed" if (n["gaps"] or n["hyps"]) else "fact"
    return _step("sure", status, WORDS["sure"].format(**n), "claim", {"numbers": n})


def step_spread(alert_id):
    from . import checklist
    qs = {q["key"]: q for q in checklist.checklist(alert_id)["questions"]}
    parts, inks = [], []
    for key, word in (("network", "spread_net"), ("persist", "spread_persist")):
        q = qs.get(key)
        if not q:
            continue
        first = (q.get("lines") or [{}])[0]
        text = first.get("text") if isinstance(first, dict) else first
        parts.append(WORDS[word].format(line=text or checklist.WORDS["status"].get(q["status"], q["status"])))
        inks.append(q["status"])
    ink = honest(inks)
    return _step("spread", ink, " · ".join(p.rstrip(". ") + "." for p in parts), "checklist", {"numbers": {"inks": inks}})


def step_unseen(content):
    from . import prove
    cfg = prove.config()
    lines = prove.lines_of(content, cfg)
    edges = sum(1 for l in lines if l.get("edge"))
    lines = [l for l in lines if not l.get("edge")]          # the recording's edge is not a blind spot
    edge_note = WORDS["unseen_edge"].format(n=_n(edges, "program", "programs")) if edges else ""
    if not lines:
        return _step("unseen", "none", WORDS["unseen_none"] + edge_note, "prove",
                     {"numbers": {"lines": 0, "other": 0, "edges": edges}})
    other = sum(1 for l in lines if l["witness"] and l["witness"]["verdict"] == "elsewhere")
    hyps = sum(1 for l in lines if l["ink"] == "hypothesis")
    gaps = len(lines) - hyps
    parts = " and ".join(x for x in (_n(hyps, "suspected link", "suspected links") if hyps else "",
                                     _n(gaps, "gap", "gaps") if gaps else "") if x)
    line = WORDS["unseen"].format(parts=parts)
    if other:
        line += WORDS["unseen_other"].format(other=f"{other} of them" if len(lines) > 1 else "It")
    else:
        line += WORDS["unseen_here"]
    status = "unproven" if (hyps and gaps) else "hypothesis" if hyps else "gap"
    return _step("unseen", status, line + edge_note, "prove",
                 {"numbers": {"lines": len(lines), "other": other, "edges": edges}})


def step_todo(a):
    from . import _attack, _d3fend, _rule_tags, respond
    attack = _attack.load()
    if attack is None:
        return _unchecked("todo", "respond", "the ATT&CK data is not on this laptop (python -m engine.labs._fetch_attack)")
    techs = respond.steps(a, attack, _d3fend.load(), _rule_tags.index())
    if not techs:
        return _step("todo", "none", WORDS["todo_none"], "respond", {"numbers": {"techniques": 0}})
    m = sum(len(t["mitigations"]) for t in techs)
    d = sum((t["d3fend"] or {}).get("count", 0) for t in techs)
    line = WORDS["todo"].format(mits=_n(m, "mitigation", "mitigations"), defs=_n(d, "defence", "defences"),
                                techniques=", ".join(t["id"] for t in techs))
    if any(t.get("source") == "reading" for t in techs):
        line = line.rstrip(".") + WORDS["todo_reading"] + "."
    return _step("todo", "listed", line, "respond",
                 {"numbers": {"techniques": len(techs), "mitigations": m, "defences": d}})


def steps(ctx, a):
    try:
        content = ctx.report(a)
    except Exception:
        content = None
    plan = [("fired", "why", lambda: step_fired(ctx, a)), ("around", "moment", lambda: step_around(ctx, a)),
            ("sure", "claim", lambda: step_sure(content)), ("spread", "checklist", lambda: step_spread(a.alert_id)),
            ("unseen", "prove", lambda: step_unseen(content)), ("todo", "respond", lambda: step_todo(a))]
    out = []
    for key, lab, fn in plan:
        if content is None and key in ("sure", "unseen"):
            out.append(_unchecked(key, lab))
            continue
        try:
            out.append(fn())
        except Exception as e:                  # a missing or failing lab: its step says so, the rest go on
            out.append(_unchecked(key, lab, f"{type(e).__name__}: {str(e)[:120]}"))
    return out


