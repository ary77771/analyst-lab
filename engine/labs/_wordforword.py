"""Word for word (night-explain): an alert's cited records in Sysmon's own field names, next to the story's plain
sentences, with every word of a sentence that comes from a record traced to its field. Shared by "Why is this
suspicious?" (its first screen since 2026-11-24) and the older "This is what an alarm says" lab."""


import ntpath
import re


from engine.report import AGENT_EVENT_NAMES, EVENT_NAMES

from ._explain_common import PICK_WORDS, alert_row, picker


MAX_LINES = 15
MAX_RECORDS = 15
WORDS = {
    "title": "This is what an alarm says",
    "intro": "On the left, what the computer recorded, word for word. On the right, what the dashboard says about it "
             "in plain words. Each marked word on the right comes from the field it points to on the left; unmarked "
             "words are the dashboard's own.",
    **PICK_WORDS,
    "view_side": "Side by side",
    "view_alarm": "Alarm only",
    "view_story": "Story only",
    "alarm_title": "The alarm, as the rule engine wrote it",
    "rule": "Rule",
    "reason": "The engine's own sentence",
    "details": "What the engine stored with it",
    "raw_title": "What the computer recorded",
    "raw_note": "What Windows wrote down, field by field, in Sysmon's own names (re-drawn from the stored fields, "
                "nothing changed). The recorder's own notes are folded under each record and marked as ours.",
    "recorder_notes": "The recorder's own notes (not from Windows)",
    "by_recorder": "This record was written by Analyst Lab's recorder, not by Windows.",
    "story_title": "What the dashboard says",
    "story_note": "The story's own sentences (the same as the Story screen and the report). Point at a marked word to "
                  "see the field it came from.",
    "cites": "Comes from record",
    "verb_from": "the record's type",
    "own_words": "the dashboard's own wording",
    "no_story": "The evidence graph could not be built for this alert here; only the alarm and its records are shown.",
    "no_lines": "No sentence of this alert's story cites one of its records.",
    "inks": {"fact": "Proven", "hypothesis": "Suspected", "gap": "Can't be known"},
    "more_records": "{shown} of {total} records shown.",
    "open_why": "Why is this suspicious?",
    "details": "details",
}

# fields worth tracing (others, like GUIDs or hashes, rarely appear in a sentence and would only add noise)
TRACE_FIELDS = ["Image", "ParentImage", "TargetFilename", "final_path", "TargetObject", "QueryName", "DestinationHostname",
                "DestinationIp", "DestinationPort", "SourceIp", "SourcePort", "LocalIp", "LocalPort", "ProcessId",
                "ParentProcessId", "User", "CommandLine", "Details", "OriginalFileName"]
# the verbs the story writes for each record type (engine/report.py sentences); traced to "the record's type"
VERBS = {1: ["started"], 3: ["connected to", "contacting", "connected"], 5: ["ended", "exited"], 11: ["created", "wrote"],
         13: ["set"], 15: ["marked", "downloaded"], 22: ["looked up"], 26: ["deleted"]}
HIDDEN = {"raw_xml", "id", "dedup_key"}
# Windows' own System part of a record (Computer, Channel, Provider, EventRecordID, EventID, TimeCreated, by our names)
HEADER = ["host", "channel", "provider", "record_id", "event_id", "time"]
# what Analyst Lab's recorder notes about a record (not Windows' words): shown apart, folded, and marked as ours
RECORDER_NOTES = ["source", "origin", "origin_recorded", "session", "seq", "label", "type", "paused", "parse_error"]


def _candidates(field, value):
    """The strings of a field value that may appear in a sentence: the value, and for a path its file name."""
    v = str(value).strip()
    out = []
    if not v:
        return out
    if field in ("Image", "ParentImage", "TargetFilename", "final_path"):
        out.append(ntpath.basename(v))
    if field == "TargetObject":
        out.append(v.rsplit("\\", 1)[-1])
    if len(v) <= 120:
        out.append(v)
    return [c for c in dict.fromkeys(out) if len(c) >= 1]


def trace(sentence, records):
    """[{start, end, field, key, value}] for the words of `sentence` found in the cited records' fields
    (longest first, never overlapping), plus the verb for a record's event type ({field: "EventID"})."""
    found, taken = [], []
    cands = []
    for key, rec in records:
        if not rec:
            continue
        for f in TRACE_FIELDS:
            if rec.get(f) in (None, ""):
                continue
            for c in _candidates(f, rec[f]):
                cands.append((c, f, key, str(rec[f])))
        for verb in VERBS.get(rec.get("event_id"), []):
            cands.append((verb, "EventID", key, f"{rec.get('event_id')} ({EVENT_NAMES.get(rec.get('event_id'), '?')})"))
    cands.sort(key=lambda c: -len(c[0]))
    low = sentence.lower()
    for c, field, key, value in cands:
        word = c.lower()
        # whole words only: '5' must not match inside '5744', 'cmd.exe' not inside 'xcmd.exe'
        for m in re.finditer(r"(?<![\w.\\])" + re.escape(word) + r"(?![\w])", low):
            s, e = m.start(), m.end()
            if any(s < te and ts < e for ts, te in taken):
                continue
            taken.append((s, e))
            found.append({"start": s, "end": e, "field": field, "key": key, "value": value})
    return sorted(found, key=lambda x: x["start"])


def record_view(key, rec):
    if rec is None:
        return {"key": key, "missing": True, "header": [], "fields": []}
    name = AGENT_EVENT_NAMES.get(rec.get("type")) or EVENT_NAMES.get(rec.get("event_id")) or f"event {rec.get('event_id')}"
    header = [[h, rec[h]] for h in HEADER if rec.get(h) not in (None, "")]
    notes = [[h, rec[h]] for h in RECORDER_NOTES if rec.get(h) not in (None, "")]
    skip = HIDDEN | set(HEADER) | set(RECORDER_NOTES)
    fields = [[k, rec[k]] for k in rec if k not in skip and rec[k] not in (None, "")]
    by = "recorder" if rec.get("source") == "agent" else "windows"
    return {"key": key, "missing": False, "name": name, "event_id": rec.get("event_id"), "header": header, "fields": fields,
            "notes": notes, "by": by}


def story_lines(content, alert):
    """The report's sentences that cite this alert's records first (the alert's own chain), then other facts
    and hypotheses, each with the record keys it cites."""
    own = set(alert.evidence)
    rows = []
    for ink, items in (("fact", content.get("facts", [])), ("hypothesis", content.get("hypotheses", []))):
        for it in items:
            keys = [c["key"] for c in it.get("citations", []) if c.get("key")]
            if keys:
                rows.append({"ink": ink, "id": it.get("id"), "text": it.get("sentence") or "", "keys": keys,
                             "own": bool(own & set(keys)) or bool(it.get("in_chain")), "order": it.get("order") or 0})
    rows.sort(key=lambda r: (not r["own"], r["order"]))
    return rows[:MAX_LINES]


def explain(ctx, a):
    out = {"words": WORDS, "alert": alert_row(a),
           "alarm": {"title": a.title, "level": a.level, "rule_id": a.rule_id, "source": a.source, "reason": a.reason,
                     "time": a.time, "details": {k: v for k, v in (a.details or {}).items() if k != "declared"},
                     "declared": (a.details or {}).get("declared")}}
    try:
        content = ctx.report(a)
        lines, story = story_lines(content, a), True
    except Exception:
        lines, story = [], False
    keys = list(dict.fromkeys(list(a.evidence)[:MAX_RECORDS] + [k for l in lines for k in l["keys"]]))[:MAX_RECORDS * 2]
    recs = {k: ctx.event(k) for k in keys}
    for l in lines:
        l["traces"] = trace(l["text"], [(k, recs.get(k)) for k in l["keys"]])
    out.update(story=story, lines=lines, records=[record_view(k, recs[k]) for k in keys],
               records_total=len(set(a.evidence) | {k for l in lines for k in l["keys"]}))
    return out


