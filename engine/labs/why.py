"""Lab "Why is this suspicious?" (night 2026-11-23, night-explain): for one alert, the rule that fired, the
event fields that matched it, and the alert's steps in the evidence graph.

    GET /api/labs/why                 the alerts the screens show (newest first), to pick one
    GET /api/labs/why/{alert_id}      the explanation of one alert

Read-only: the rule file is parsed (never edited), the alert's own events are read from the event store,
and the graph steps are the report's own rows (ctx.report: the same facts, hypotheses and gaps as Story
and the report, in their own words). Nothing is re-scored: the alert is the engine's verdict, and this
page explains it. Where this page's check of the rule does not reproduce the match, it says so.

Switch off: delete this file (and dashboard/src/labs/why/); nothing else uses it.
"""

import inspect

from fastapi import APIRouter, HTTPException

from engine import labs

from . import _sigma_explain as sx
from ._explain_common import PICK_WORDS, alert_row as _alert_row, picker

router = APIRouter(prefix="/api/labs/why")

MAX_EVENTS = 12                       # a correlation alert can cite hundreds of events: the first few are shown

WORDS = {
    "title": "Why is this suspicious?",
    "blurb": "For one alert: the rule that fired, the exact fields that matched, and its steps in the evidence graph.",
    **PICK_WORDS,
    "rule_title": "The rule that fired",
    "logic_title": "What the rule looks for",
    "events_title": "The event fields that matched",
    "events_title_plain": "The alert's own events",
    "things": "Open in Pivot",
    "all_fields": "All recorded fields",
    "how_rule": "How the rule works, in its author's words",
    "rule_settings": "The settings it ran with and what it stored",
    "story_title": "Its steps in the evidence graph",
    "condition": "Fires when",
    "selection_held": "held",
    "selection_failed": "did not hold",
    "selection_unknown": "not checked here",
    "filter_note": "a filter: the rule fires only when this does NOT hold",
    "any_of": "any one of these",
    "all_of": "all of these",
    "sysmon_event": "Recorded as Sysmon event",
    "declared_note": "This alert was raised on a command as it was typed, not on a recorded event: the values below "
                     "were read from the command line (declared, not recorded: it may not have run).",
    "not_reproduced": "This page's own check of the rule did not reproduce the match on this event. The alert is the "
                      "engine's verdict (it ran the rule as SQL); this page could not explain it, and says so.",
    "partly_checked": "Some parts of the rule use a kind of value this page cannot check; those are marked "
                      "'not checked here', never guessed.",
    "rule_missing": "The rule file is not on this laptop, so its logic cannot be shown. The alert's own reason is below.",
    "reading": "Analyst Lab's reading of its own rule (our rules carry no ATT&CK tag)",
    "python_rule": "An Analyst Lab rule written in Python (Sigma cannot express it). Its own description and the "
                   "settings it ran with:",
    "beacon_rule": "The check-in rhythm rule (RITA's beacon method, re-implemented). Its own description and the "
                   "scores this alert got:",
    "more_events": "{shown} of {total} events shown.",
    "other_fields": "Other recorded fields",
    "no_story": "The evidence graph could not be built for this alert here.",
    "story_note": "The same rows as the Story screen and the report, in their own words.",
    "inks": {"fact": "Proven", "hypothesis": "Suspected", "gap": "Can't be known"},
    "ink_explain": {"fact": "a recorded event says so", "hypothesis": "may be true, not proven",
                    "gap": "the recording cannot show this"},
    "references": "Rule references",
    "falsepositives": "Known harmless causes (from the rule's author)",
    "tags": "Tags",
    "reason": "The alert's own reason",
    "source": "Rule text: SigmaHQ community rules (Detection Rule License 1.1) or Analyst Lab's own.",
    "open_moment": "Around this moment",
    "noise_title": "How noisy is this rule?",
    "harness_switch": "Show the test machinery",
    "harness_hidden": "Hidden: lines about the lab's own test machinery (its launcher, its report back to the laptop, "
                      "the VM's helper programs): {n}.",
    "noise_normal": "No attack ran that week, so each of those was a false alarm.",
    "wordforword_title": "What the computer recorded, and what we say",
    "details": "details",
    "open_next": "What to do next",
}

FIRST_FIELDS = ["Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine", "User",
                "TargetFilename", "TargetObject", "Details", "DestinationIp", "DestinationPort", "DestinationHostname",
                "QueryName", "ScriptBlockText"]
HIDDEN_FIELDS = {"raw_xml", "dedup_key", "id"}


def ordered_fields(event, first):
    """The event's fields as [[name, value]], the matched ones first, then the usual ones, then the rest."""
    shown = {k: v for k, v in event.items() if k not in HIDDEN_FIELDS and v is not None and v != ""}
    order = [f for f in first if f in shown]
    order += [f for f in FIRST_FIELDS if f in shown and f not in order]
    order += sorted(f for f in shown if f not in order)
    return [[f, shown[f] if isinstance(shown[f], (int, float)) else str(shown[f])] for f in order]


def _highlights(result):
    """{field: spans} for the items that matched in selections that held (filters are never 'why')."""
    out = {}
    for s in result.get("selections", []):
        if not s["matched"] or s["filter"]:
            continue
        for g in s["groups"]:
            for i in g:
                if i and i["matched"] and i["field"] and i["spans"]:
                    out.setdefault(i["field"], []).extend(i["spans"])
    return {f: sx._merge_spans(v) for f, v in out.items()}


def explain_events(rule, events, declared=None):
    """Each event checked against the rule: verdict, the selections, matched fields and highlights.
    declared = the alert's declared row (a dict) for an alert raised on a typed command."""
    out = []
    for key, ev in events:
        target = dict(ev or {})
        kind = "recorded"
        if declared:
            target = {**declared, "event_id": declared.get("event_id")}
            kind = "declared"
        result = sx.evaluate_any(rule, target) if rule is not None else None
        if result is not None and declared and result["matched"] is False and \
                len(str(declared.get("ScriptBlockText") or "")) < int(declared.get("length") or 0):
            result["matched"] = None             # the alert keeps only the start of long declared code: a miss
            result["truncated"] = True           # here may sit in the part it left out ("not checked", not red)
        fields = ordered_fields(target, result["matched_fields"] if result else [])
        highlights = _highlights(result) if result else {}
        # the field names in the event may differ in case from the rule's: map highlights onto the event's names
        lower = {f.lower(): f for f, _ in fields}
        highlights = {lower.get(sx.FIELD_MAP.get(f.lower(), f).lower(), f): v for f, v in highlights.items()}
        out.append({"key": key, "kind": kind, "missing": ev is None,
                    "event_id": (ev or {}).get("event_id"), "time": (ev or {}).get("UtcTime") or (ev or {}).get("time"),
                    "matched": result["matched"] if result else None,
                    "base_rule": (result or {}).get("base_rule"),
                    "selections": result["selections"] if result else [],
                    "matched_fields": [lower.get(sx.FIELD_MAP.get(f.lower(), f).lower(), f)
                                       for f in (result or {}).get("matched_fields", [])],
                    "highlights": highlights, "fields": fields})
    return out


def rule_doc(fn, module):
    """The rule's own description: its docstring, or else the paragraph of its module's docstring that starts with
    its name (engine/own_rules.py describes fetch_write_run there, not on the function)."""
    doc = inspect.getdoc(fn) if fn else None
    if doc:
        return doc
    if fn is None:
        return ""
    for para in (inspect.getdoc(module) or "").split("\n\n"):
        if para.strip().startswith(fn.__name__ + ":"):
            return para.strip()
    return ""


def python_rule(alert):
    """An own Python rule or the beacon rule: its docstring, its frozen settings, the alert's details."""
    from engine import config, own_rules
    if alert.source == "beacon" or alert.rule_id == "beacon":
        from engine import beacon
        return {"kind": "beacon", "title": alert.title, "doc": inspect.getdoc(beacon) or "",
                "settings": {}, "details": alert.details or {}}
    fn = {**own_rules.RULES, **own_rules.BASELINE_RULES}.get(alert.rule_id)
    try:
        settings = config.own_rule_params().get(alert.rule_id, {})
    except Exception:
        settings = {}
    return {"kind": "python", "title": alert.title, "doc": rule_doc(fn, own_rules),
            "function": f"engine/own_rules.py: {fn.__name__}" if fn else None,
            "settings": settings, "details": alert.details or {}}


def story_of(ctx, alert):
    """The alert's rows in the evidence graph (the report's own timeline), or None with the reason."""
    try:
        content = ctx.report(alert)
    except Exception as e:                                       # never a reason for the page to fail
        return {"available": False, "problem": f"{type(e).__name__}"}
    from . import _shared_defs as sd
    from ._explain_common import harness_marks, machinery_notes
    marks = harness_marks(ctx, content.get("facts", []) + content.get("hypotheses", []))
    notes = machinery_notes(ctx, alert.host, content.get("facts", []) + content.get("hypotheses", []) + content.get("gaps", []))
    rows = [{"ink": r.get("ink") or r.get("grade"), "text": r.get("text"), "short": r.get("short"),
             "time": sd.when_text(r.get("time_precise")) if r.get("time_precise") else
                     (None if r.get("placement") == "before" else sd.when_text(r.get("time"))),
             "offset": r.get("offset_text"),
             "in_chain": bool(r.get("in_chain")), "placement": r.get("placement"),
             "harness": marks.get(r.get("id")), "machinery": notes.get(r.get("id"))}
            for r in content.get("timeline", [])]
    return {"available": True, "counts": content.get("counts", {}), "summary": content.get("summary"),
            "rows": rows, "limitations": content.get("limitations", [])[:6]}


def explain(ctx, alert, max_events=MAX_EVENTS, folders=None):
    details = alert.details or {}
    out = {"words": WORDS, "alert": _alert_row(alert), "events_total": len(alert.evidence)}
    rule = None
    if alert.source != "beacon" and alert.rule_id not in _python_ids():          # a Sigma rule (theirs or ours)
        path = sx.find_rule_file(alert.rule_id, details.get("rule_file"), folders)
        rule = sx.load_rule(path, alert.rule_id) if path else None
        out["rule"] = dict(sx.describe(rule, path), found=True) if rule is not None else \
            {"found": False, "kind": "missing", "title": alert.title, "id": alert.rule_id,
             "author": details.get("author") or ""}
    else:
        out["rule"] = dict(python_rule(alert), found=True)
    out["rule"]["techniques"] = techniques_of(out["rule"].get("tags") or [], alert.rule_id)
    keys = list(alert.evidence)[:max_events]
    events = [(k, ctx.event(k)) for k in keys]
    declared = details.get("declared") if details.get("derived_from") == "command_line" else None
    if rule is not None:
        out["events"] = explain_events(rule, events, declared)
    else:
        out["events"] = [{"key": k, "kind": "declared" if declared else "recorded", "missing": ev is None,
                          "event_id": (ev or {}).get("event_id"), "time": (ev or {}).get("UtcTime") or (ev or {}).get("time"),
                          "matched": None, "base_rule": None, "selections": [], "matched_fields": [], "highlights": {},
                          "fields": ordered_fields(dict(ev or {}), [])} for k, ev in events]
    verdicts = [e["matched"] for e in out["events"] if not e["missing"]]
    out["check"] = ("na" if rule is None else "reproduced" if any(v is True for v in verdicts)
                    else "not_checked" if any(v is None for v in verdicts) else "not_reproduced")
    out["partly_checked"] = any(i and i["matched"] is None for e in out["events"] for s in e["selections"]
                                for g in s["groups"] for i in g)
    out["story"] = story_of(ctx, alert)
    out["wordforword"] = word_for_word(ctx, alert)
    out["noise"] = noise_line(alert)
    return out


def word_for_word(ctx, alert):
    """The alert's cited records next to the story's sentences, each traced word pointing at its field (merged from
    "This is what an alarm says" on 2026-11-24: Why's first screen). None when it can't be built here."""
    try:
        from . import _wordforword as ww
        d = ww.explain(ctx, alert)
    except Exception:
        return None
    from . import _shared_defs as sd
    cache = {}

    def harness(key):
        if key not in cache:
            ev = ctx.event(key)
            cache[key] = sd.harness_reason(ev) if ev else None
        return cache[key]

    from ._explain_common import machinery_notes
    try:
        content = ctx.report(alert)
        notes = machinery_notes(ctx, alert.host, content.get("facts", []) + content.get("hypotheses", []))
    except Exception:
        notes = {}
    for line in d["lines"]:                 # a sentence whose records are all test machinery: hidden by default
        reasons = [harness(k) for k in line["keys"]]
        line["harness"] = reasons[0] if reasons and all(reasons) else None
        line["machinery"] = notes.get(line.get("id"))
    return {"words": d["words"], "lines": d["lines"], "records": d["records"], "records_total": d["records_total"],
            "story": d["story"]}


def noise_line(alert):
    """One line: how often this rule rang on a week of normal use (or in the public / blind tests), from the
    receipts lab's committed-results reader. None when that lab is not here."""
    try:
        from . import receipts
        r = receipts.record_for(alert.rule_id, alert.title, receipts.records())
        W = receipts.WORDS
    except Exception:
        return None
    safe = lambda tpl, vals: tpl.format_map(type("D", (dict,), {"__missing__": lambda s, k: "?"})(vals))
    if r.get("normal"):
        n = dict(r["normal"])
        n.setdefault("period", "the week measured")
        text = safe(W["normal_line"], n) + ". " + WORDS["noise_normal"]
    elif r.get("public"):
        text = safe(W["public_line"], r["public"]) + "."
    elif r.get("blind"):
        text = safe(W["blind_line"], r["blind"]) + "."
    else:
        text = W["never"]
    return {"text": text, "measured": bool(r.get("measured"))}


def techniques_of(tags, rule_id=None):
    """[{id, name, reading}] for the ATT&CK techniques a rule's tags name (MITRE's name when the data is here); for
    one of our own untagged rules, Analyst Lab's reading of it (reading=True, said so on the page)."""
    from . import _attack, _own_tags
    attack = _attack.load()
    out = []
    for t in _attack.technique_tags(tags):
        cur = attack.resolve(t)[0] if attack else None
        out.append({"id": cur or t, "name": attack.full_name(cur) if (attack and cur) else None, "reading": False})
    if not out and rule_id and attack:
        techs, _, _ = _own_tags.techniques_for_alert(attack, rule_id, [])
        out = [{"id": t, "name": attack.full_name(t), "reading": True} for t in techs]
    return out


def _python_ids():
    from engine import own_rules
    return set(own_rules.RULES) | set(own_rules.BASELINE_RULES)


@router.get("")
def pick(limit: int = 300):
    return picker(labs.context(), limit)


@router.get("/{alert_id}")
def why(alert_id: str):
    ctx = labs.context()
    a = ctx.alert(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="This alert isn't in this recording.")
    return explain(ctx, a)
