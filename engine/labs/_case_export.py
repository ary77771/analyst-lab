"""Exports of a case (engine/labs/cases.py): a printable HTML report, a STIX 2.1 bundle and a Timesketch
timeline. The leading underscore keeps this file out of the Labs registry (it has no routes of its own).

Every export says only what the case and the stores hold: recorded events stay facts, the evidence graph's
hypotheses stay hypotheses with their band, gaps stay gaps, and the analyst's marks are shown as the
analyst's, next to (never instead of) the grade the evidence gave. Text from the case (notes, labels,
command lines) is escaped: it is data, never markup.
"""

import csv
import io
import json
import re
from datetime import datetime, timezone
from html import escape

from . import _shared_defs as sd
from . import pivot as pivot_mod

EVIDENCE_PER_ALERT = 60          # an alert's evidence events read for the exports (the rest are counted)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso(t):
    """The store's times ("2026-10-22T10:00:00.123Z", "...+00:00", "2026-10-22 10:00:00.123") as
    timezone-aware datetimes in UTC; None when there is no time."""
    if not t:
        return None
    s = str(t).strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def _utc(t):
    d = iso(t)
    return d.strftime("%Y-%m-%d %H:%M:%S UTC") if d else "?"


def evidence_rows(ctx, case):
    """{alert id: [event rows of its evidence]} for the pinned alerts (from the snapshot's keys)."""
    out = {}
    for p in case["pins"]:
        if p["type"] != "alert":
            continue
        keys = list((p.get("snapshot") or {}).get("evidence") or [])[:EVIDENCE_PER_ALERT]
        rows = []
        for k in keys:
            try:
                r = ctx.event(k)
            except Exception:
                r = None
            if r and pivot_mod.host_ok(r.get("host")):          # night rule 11
                rows.append(r)
        out[p["ref"]] = rows
    return out


# -- the printable report ----------------------------------------------------------------------------------

CSS = """
:root { --fact: #1b8a5a; --hypo: #a86e00; --gap: #6d4fc2; --ink: #16181d; --muted: #545b66; --line: #d6d9de; }
* { box-sizing: border-box; }
body { font: 15px/1.55 "Inter", system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: #fff;
  max-width: 60rem; margin: 2rem auto; padding: 0 1.5rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; } h2 { font-size: 1.15rem; margin: 2rem 0 .6rem; padding-bottom: .3rem;
  border-bottom: 2px solid var(--ink); } h3 { font-size: 1rem; margin: 1.2rem 0 .4rem; }
.meta, .muted { color: var(--muted); font-size: .85rem; }
.lead { font-size: 1.05rem; white-space: pre-wrap; }
table { width: 100%; border-collapse: collapse; margin: .4rem 0 1rem; font-size: .88rem; }
th, td { text-align: left; vertical-align: top; padding: .35rem .5rem; border-bottom: 1px solid var(--line); }
th { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
td.t { white-space: nowrap; font-variant-numeric: tabular-nums; font-family: ui-monospace, "JetBrains Mono", Consolas, monospace; font-size: .8rem; }
code, .mono { font-family: ui-monospace, "JetBrains Mono", Consolas, monospace; font-size: .8rem; word-break: break-all; }
.ink { margin: .35rem 0; padding: .3rem .7rem; border-left: 4px solid var(--line); page-break-inside: avoid; }
.ink.fact { border-left: 4px solid var(--fact); } .ink.hypothesis { border-left: 4px dashed var(--hypo); }
.ink.gap { border-left: 4px dotted var(--gap); }
.tag { display: inline-block; font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
  padding: 0 .4rem; border: 1px solid currentColor; border-radius: 3px; margin-right: .4rem; }
.tag.fact { color: var(--fact); } .tag.hypothesis { color: var(--hypo); } .tag.gap { color: var(--gap); }
.mark { display: inline-block; font-size: .78rem; font-weight: 600; padding: 0 .45rem; border-radius: 3px; background: #eef0f3; }
.mark.confirmed { background: #dff3e9; color: #145c3c; } .mark.ruled_out { background: #e6e8ec; color: #2c3440; }
.legend { display: flex; gap: 1.2rem; flex-wrap: wrap; font-size: .85rem; margin: .3rem 0 1rem; }
.box { border: 1px solid var(--line); border-radius: 6px; padding: .7rem .9rem; margin: .6rem 0; page-break-inside: avoid; }
.note { white-space: pre-wrap; }
.print { position: fixed; top: 1rem; right: 1rem; font: inherit; padding: .4rem .9rem; border: 1px solid var(--ink);
  background: #fff; border-radius: 6px; cursor: pointer; }
.rhead { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; padding-bottom: .4rem;
  border-bottom: 3px solid var(--ink); font-size: .75rem; color: var(--muted); }
.rhead > span:first-child { font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--ink); }
h1 { margin-top: 1rem; }
.three { display: grid; gap: .1rem; margin: 1rem 0 1.2rem; border: 1px solid var(--line); border-left: 6px solid var(--ink);
  border-radius: 6px; page-break-inside: avoid; }
.three > div { display: grid; grid-template-columns: 9.5rem 1fr; gap: 1rem; padding: .6rem .9rem; }
.three > div + div { border-top: 1px solid var(--line); }
.three b { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; padding-top: .15rem; }
.three p { margin: 0; }
table.marks td:nth-child(3) { white-space: nowrap; }
.pic { margin: .4rem 0 1rem; page-break-inside: avoid; }
.inshort { margin: .8rem 0 .2rem; padding: .7rem .9rem; background: #f4f5f7; border-radius: 6px; page-break-inside: avoid; }
.inshort b { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }
.inshort p { margin: .3rem 0 0; font-size: 1.02rem; line-height: 1.55; }
.pic svg { display: block; width: 100%; height: auto; max-height: 95mm; }
.pic figcaption { font-size: .8rem; margin-top: .3rem; }
@page { size: A4; margin: 16mm 14mm 18mm; }
@media print { body { font-size: 10pt; } .pb { break-before: page; } h1 { font-size: 18pt; } }
@media print { .print { display: none; } body { margin: 0; max-width: none; } h2 { page-break-after: avoid; }
  a { color: inherit; text-decoration: none; } }
"""


def _ink_words():
    try:
        from engine.dashboard.words import INKS
        return {k: v["word"] for k, v in INKS.items()}
    except Exception:
        return {"fact": "fact", "hypothesis": "hypothesis", "gap": "gap"}


def _mark(case, key):
    m = (case.get("marks") or {}).get(key)
    if not m:
        return ""
    words = case.get("status_words") or {}
    note = f" <span class='muted'>({escape(m['note'])})</span>" if m.get("note") else ""
    return f"<span class='mark {escape(m['status'])}'>Analyst: {escape(words.get(m['status'], m['status']))}</span>{note}"


def _primary_alert(case):
    """The alert the report is about: the earliest pinned alert (None when no alert is pinned)."""
    alerts = [p for p in case["pins"] if p["type"] == "alert"]
    return sorted(alerts, key=lambda p: str(p.get("time") or ""))[0] if alerts else None


def _plural(n, one, many=None):
    return f"{n} {one if n == 1 else (many or one + 's')}"


SURE_FALLBACK = "Of the {total} lines of its story, {facts} {facts_verb} proven by a record, {hyps} suspected and {gaps} can't be known"


def how_sure_counts(rep, ink):
    """The "How sure" line from the story's own counts (report.build's counts: the very numbers the checklist's
    "In short" paragraph says, in its own sentence from engine/labs/_summary.py), then how many of the proven lines
    are the alert's own steps, so the report and the checklist can't seem to disagree."""
    facts, hyps, gaps = rep.get("facts") or [], rep.get("hypotheses") or [], rep.get("gaps") or []
    c = rep.get("counts") or {}
    f, h, g = (int(c.get("facts", len(facts))), int(c.get("hypotheses", len(hyps))), int(c.get("gaps", len(gaps))))
    if not f + h + g:
        return "Nothing of this alert's story is recorded here. "
    try:
        from ._summary import WORDS as SUMMARY_WORDS
        sentence = SUMMARY_WORDS["sure"]
    except Exception:
        sentence = SURE_FALLBACK
    out = sentence.format(total=f + h + g, facts=f, facts_verb="is" if f == 1 else "are", hyps=h, gaps=g) + ". "
    bands = sorted({x.get("band_label") for x in hyps if x.get("band_label")})
    out += f"{ink['fact']}: a recorded event says so" + (f"; {ink['hypothesis'].lower()}: {', '.join(bands)}" if bands else "") + ". "
    steps = sum(1 for x in facts if x.get("in_chain"))
    if steps and steps < f:
        out += (f"{steps} of the proven lines {'is' if steps == 1 else 'are'} the alert's own "
                f"{'step' if steps == 1 else 'steps'} (What happened). ")
    return out


def first_page(case, ink):
    """The three lines and the marks a reader needs first, in plain words: {headline, meta, happened, sure,
    unknown, marks: [(hypothesis, evidence says, analyst)], unmarked}. Only what the case and the alert's own
    report say; nothing is graded here."""
    marks = case.get("marks") or {}
    words = case.get("status_words") or {}
    primary = _primary_alert(case)
    rep = (case.get("alerts") or {}).get(primary["ref"]) if primary else None
    rep = rep if rep and not rep.get("error") else None
    snap = (primary or {}).get("snapshot") or {}
    headline = primary["label"] if primary else case["title"]
    meta = []
    if primary:
        meta.append(f"Alert raised {_utc(primary.get('time'))}, level {snap.get('level', '?')}")
    title = case["title"]
    if title.endswith(": " + headline):                     # "S1 · Download and run: <alert>": say the run only
        meta.append(title[: -len(headline) - 2])
    elif title != headline and not re.match(r"^(Untitled case|Case \d{4}-\d{2}-\d{2} \d{2}:\d{2})$", title):
        meta.append(f"Case: {title}")
    facts = (rep or {}).get("facts") or []
    chain = sorted([f for f in facts if f.get("in_chain")] or facts, key=lambda f: str(f.get("time") or ""))
    steps = [f.get("sentence", "") for f in chain[:4]]
    happened = (snap.get("reason") or "").strip()
    if steps:
        happened = (happened + " " if happened else "") + "In order: " + ", then ".join(steps) + \
            (f", and {_plural(len(chain) - 4, 'more step')}." if len(chain) > 4 else ".")
    if not happened:
        happened = (f"The case holds {_plural(len(case['pins']), 'pinned item')}; no alert is pinned."
                    if case["pins"] else "Nothing is pinned to this case yet.")
    hyps = (rep or {}).get("hypotheses") or []
    gaps = (rep or {}).get("gaps") or []
    n_conf = sum(1 for m in marks.values() if m["status"] == "confirmed")
    n_out = sum(1 for m in marks.values() if m["status"] == "ruled_out")
    if rep:
        sure = how_sure_counts(rep, ink)
    else:
        sure = "This alert's own report could not be read here, so how sure it is cannot be said. " if primary else ""
    sure += (f"The analyst confirmed {n_conf} and ruled out {n_out}." if (n_conf or n_out)
             else "The analyst has not marked anything yet.")
    if gaps:
        plain = [g.get("plain") or g.get("what") or "" for g in gaps[:2]]
        unknown = "; ".join(x for x in plain if x) + (f"; and {_plural(len(gaps) - 2, 'more thing')}" if len(gaps) > 2 else "") + "."
    elif rep:
        unknown = "Around this alert the records leave nothing open that they could have shown."
    else:
        unknown = "Cannot be said without the alert's report."
    rows = []
    for p in case["pins"]:
        if p["type"] == "alert":
            for h in ((case.get("alerts") or {}).get(p["ref"]) or {}).get("hypotheses") or []:
                m = marks.get(f"h:{p['ref']}:{h.get('id')}")
                if m:
                    rows.append((h.get("sentence", ""), f"{ink['hypothesis']} ({h.get('band_label') or 'no grade'})",
                                 words.get(m["status"], m["status"]), m.get("note") or ""))
        elif p["type"] == "hypothesis":
            m = marks.get(f"p:{p['id']}") or {"status": "open"}
            rows.append((p["label"], "the analyst's own idea", words.get(m["status"], m["status"]), m.get("note") or ""))
    unmarked = max(0, len(hyps) - sum(1 for h in hyps if marks.get(f"h:{(primary or {}).get('ref')}:{h.get('id')}")))
    return {"headline": headline, "meta": f" · ".join(meta), "happened": happened, "sure": sure.strip(),
            "unknown": unknown, "marks": rows, "unmarked": unmarked}


def in_short(alert_id):
    """(title, plain text) of the checklist's own "In short" paragraph for one alert (engine/labs/_summary.py through
    engine/labs/checklist.py, the very paragraph the checklist shows), or None. Its parts are joined exactly as the
    checklist page joins them; its hover labels and click links are left out (this is for print)."""
    try:
        from . import checklist
        d = checklist.checklist(alert_id)
        sentences = d.get("summary") or []
        if not sentences:
            return None
        title = ((d.get("words") or {}).get("summary") or {}).get("title") or "In short"
        text = " ".join("".join(str(p.get("text") or "") for p in s) for s in sentences).strip()
        return (title, text) if text else None
    except Exception:                                       # the checklist can't answer here: no paragraph
        return None


def render_report(case, evidence=None, picture=None, shorts=None):
    """The case as one printable HTML page (A4): page 1 reads like an incident report (the alert in plain words,
    three lines: what happened, how sure, what is not known; the analyst's marks); the evidence follows.
    `case` = cases.expand(...) output; `evidence` = evidence_rows(); `picture` = the story's SVG (_story_svg.py);
    `shorts` = [(alert title, (title, text) or None)]: the checklist's "In short" paragraph per pinned alert."""
    evidence = evidence or {}
    ink = _ink_words()
    e = escape
    pins = case["pins"]
    by = {t: [p for p in pins if p["type"] == t] for t in ("alert", "event", "entity", "hypothesis")}
    fp = first_page(case, ink)
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{e(fp['headline'])}: incident report</title><style>{CSS}</style></head><body>",
           "<button class='print' onclick='window.print()'>Print / save as PDF</button>",
           f"<header class='rhead'><span>Incident report</span><span>Analyst Lab · case <code>{e(case['id'])}</code> · "
           f"made {e(_utc(_now()))}</span></header>",
           f"<h1>{e(fp['headline'])}</h1>"]
    if fp["meta"]:
        out.append(f"<p class='meta'>{e(fp['meta'])}</p>")
    for label, short in (shorts or []):
        if short:
            title, text = short
            about = f" {e(label)}" if len(shorts) > 1 else ""
            out.append(f"<section class='inshort'><b>{e(title)}{(':' + about) if about else ''}</b><p>{e(text)}</p></section>")
    out.append("<section class='three'>"
               f"<div><b>What happened</b><p>{e(fp['happened'])}</p></div>"
               f"<div><b>How sure</b><p>{e(fp['sure'])}</p></div>"
               f"<div><b>What is not known</b><p>{e(fp['unknown'])}</p></div></section>")
    if picture:
        out.append("<h2>The story in one picture</h2><figure class='pic'>" + picture +
                   f"<figcaption class='muted'>Solid green: recorded ({e(ink['fact'])}). Dashed amber: "
                   f"{e(ink['hypothesis']).lower()}. Dotted grey: what the records cannot show. Greyed out: the "
                   "program that started this chain.</figcaption></figure>")
    out.append("<h2>The analyst's marks</h2>")
    if fp["marks"]:
        out.append("<table class='marks'><tr><th>Hypothesis</th><th>The evidence says</th><th>The analyst says</th></tr>")
        for h, ev, mark, note in fp["marks"]:
            n = f"<br><span class='muted'>{e(note)}</span>" if note else ""
            out.append(f"<tr><td>{e(h)}</td><td>{e(ev)}</td><td><b>{e(mark)}</b>{n}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class='muted'>The analyst has not marked any hypothesis yet.</p>")
    if fp["unmarked"]:
        out.append(f"<p class='muted'>{_plural(fp['unmarked'], 'other suspected link')} of this alert "
                   f"{'is' if fp['unmarked'] == 1 else 'are'} not marked yet (listed in section 3).</p>")
    if (case.get("summary") or "").strip():
        out.append(f"<h2>The analyst's summary</h2><p class='lead'>{e(case['summary'])}</p>")
    out.append(f"<div class='legend'><span><span class='tag fact'>{e(ink['fact'])}</span>a recorded event says so</span>"
               f"<span><span class='tag hypothesis'>{e(ink['hypothesis'])}</span>may be true, not proven (graded by the evidence graph)</span>"
               f"<span><span class='tag gap'>{e(ink['gap'])}</span>the records cannot show it</span></div>")
    out.append("<p class='muted'>An analyst's mark (confirmed / ruled out) is the analyst's judgement. It is shown next to "
               "the grade the evidence gave and never changes it: a confirmed hypothesis is still not a recorded fact. "
               f"This case holds {_plural(len(by['alert']), 'alert')}, {_plural(len(by['event']), 'recorded event')}, "
               f"{_plural(len(by['entity']), 'thing')} and {_plural(len(case['notes']), 'note')}.</p>")
    out.append("<div class='pb'></div>")

    # 2. timeline
    out.append("<h2>1. Timeline of the pinned items</h2>")
    if case.get("timeline"):
        out.append("<table><tr><th>Recorded time</th><th>What</th><th>Item</th></tr>")
        for t in case["timeline"]:
            item = f"<code>{e(t['ref'])}</code>" if t["type"] == "entity" else e(t["label"])
            kind = f" ({e(t['kind'])})" if t.get("kind") else ""
            out.append(f"<tr><td class='t'>{e(_utc(t['time']))}</td><td>{e(t['type'])}{kind}</td><td>{item}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class='muted'>Nothing pinned has a recorded time.</p>")

    # 3. evidence
    out.append("<h2>2. Evidence</h2>")
    if by["alert"]:
        out.append("<h3>Alerts</h3>")
        for p in by["alert"]:
            s = p.get("snapshot") or {}
            rows = evidence.get(p["ref"], [])
            n_ev = len(s.get("evidence") or [])
            out.append(f"<div class='box'><p><strong>{e(p['label'])}</strong> · level {e(str(s.get('level', '?')))} · "
                       f"{e(_utc(p.get('time')))} · rule <code>{e(str(s.get('rule', '?')))}</code></p>"
                       f"<p>{e(str(s.get('reason', '')))}</p>")
            if rows:
                out.append(f"<p class='muted'>Its evidence ({n_ev} event(s){'; the first ' + str(len(rows)) + ' listed' if n_ev > len(rows) else ''}):</p>"
                           "<table><tr><th>Recorded time</th><th>Event</th><th>Key</th></tr>")
                for r in sorted(rows, key=lambda r: sd.when(r) or ""):
                    out.append(f"<tr><td class='t'>{e(_utc(sd.when(r)))}</td><td>{e(pivot_mod.summary(r))}</td>"
                               f"<td><code>{e(str(r.get('dedup_key', '')))}</code></td></tr>")
                out.append("</table>")
            out.append("</div>")
    if by["event"]:
        out.append("<h3>Recorded events</h3><table><tr><th>Recorded time</th><th>Event</th><th>Key</th></tr>")
        for p in sorted(by["event"], key=lambda p: str(p.get("time") or "")):
            s = p.get("snapshot") or {}
            cmd = f"<br><code>{e(s['command_line'])}</code>" if s.get("command_line") else ""
            out.append(f"<tr><td class='t'>{e(_utc(p.get('time')))}</td><td>{e(s.get('summary') or p['label'])}{cmd}</td>"
                       f"<td><code>{e(p['ref'])}</code></td></tr>")
        out.append("</table>")
    if by["entity"]:
        out.append("<h3>Things</h3><table><tr><th>Kind</th><th>Value</th><th>Events naming it</th><th>First / last seen</th></tr>")
        for p in by["entity"]:
            s = p.get("snapshot") or {}
            out.append(f"<tr><td>{e(str(s.get('kind_word') or p.get('kind') or ''))}</td><td><code>{e(p['ref'])}</code></td>"
                       f"<td>{e(str(s.get('events', '?')))}</td><td class='t'>{e(_utc(s.get('first')))}<br>{e(_utc(s.get('last')))}</td></tr>")
        out.append("</table>")
    if not pins:
        out.append("<p class='muted'>Nothing is pinned to this case.</p>")

    # 4. facts vs hypotheses vs gaps
    out.append("<h2>3. What is recorded, what is suspected, what cannot be known</h2>")
    for p in by["alert"]:
        rep = (case.get("alerts") or {}).get(p["ref"])
        out.append(f"<h3>Around the alert “{e(p['label'])}”</h3>")
        if not rep:
            out.append("<p class='muted'>This alert is no longer in the alert database.</p>")
            continue
        if rep.get("error"):
            out.append(f"<p class='muted'>Its report could not be built here ({e(rep['error'])}).</p>")
            continue
        facts = rep.get("facts") or []
        chain = [f for f in facts if f.get("in_chain")] or facts
        for f in chain:
            out.append(f"<div class='ink fact'><span class='tag fact'>{e(ink['fact'])}</span>{e(f.get('sentence', ''))} "
                       f"<span class='muted'>· {e(_utc(f.get('time')))}</span></div>")
        if len(chain) < len(facts):
            out.append(f"<p class='muted'>{len(facts) - len(chain)} more recorded link(s) around this alert are in its own report.</p>")
        for h in rep.get("hypotheses") or []:
            band = f" ({e(h['band_label'])})" if h.get("band_label") else ""
            alt = f"<br><span class='muted'>Other explanation: {e(h['alternative'])}</span>" if h.get("alternative") else ""
            why = f"<br><span class='muted'>Why: {e(h['reason'])}</span>" if h.get("reason") else ""
            out.append(f"<div class='ink hypothesis'><span class='tag hypothesis'>{e(ink['hypothesis'])}</span>{e(h.get('sentence', ''))}{band} "
                       f"{_mark(case, 'h:' + p['ref'] + ':' + str(h.get('id')))}{why}{alt}</div>")
        for g in rep.get("gaps") or []:
            out.append(f"<div class='ink gap'><span class='tag gap'>{e(ink['gap'])}</span>{e(g.get('plain') or g.get('what') or '')}</div>")
    if by["hypothesis"]:
        out.append("<h3>The analyst's own hypotheses</h3>")
        for p in by["hypothesis"]:
            out.append(f"<div class='ink hypothesis'><span class='tag hypothesis'>analyst</span>{e(p['label'])} "
                       f"{_mark(case, 'p:' + p['id']) or '<span class=mark>Analyst: open</span>'}</div>")
    if not by["alert"] and not by["hypothesis"]:
        out.append("<p class='muted'>No alert and no hypothesis is pinned, so there is nothing to grade here.</p>")

    # 5. notes
    out.append("<h2>4. Analyst notes</h2>")
    if case["notes"]:
        for n in case["notes"]:
            out.append(f"<div class='box'><p class='meta'>{e(_utc(n['time']))} (the analyst's clock)</p><p class='note'>{e(n['text'])}</p></div>")
    else:
        out.append("<p class='muted'>No notes.</p>")

    # 6. how this report was made
    out.append("<h2>5. How this report was made</h2><p class='muted'>Made by Analyst Lab from the case file and the "
               "recorded events, without AI. Each event is cited by its key in the event store. Facts, hypotheses and "
               "gaps come from each alert's own report (the evidence graph); the analyst's pins, marks and notes are "
               "shown as the analyst's. Times are UTC.</p></body></html>")
    return "\n".join(out)


# -- Timesketch ------------------------------------------------------------------------------------------------

TS_FIELDS = ["message", "datetime", "timestamp", "timestamp_desc", "case_id", "source", "item", "host", "event_key"]


def _ts_row(case, t, desc, message, item, host="", key=""):
    d = iso(t)
    if d is None:
        return None
    return {"message": message, "datetime": d.isoformat(), "timestamp": int(d.timestamp() * 1_000_000),
            "timestamp_desc": desc, "case_id": case["id"], "source": "Analyst Lab", "item": item,
            "host": host or "", "event_key": key or ""}


def timesketch_rows(case, evidence=None):
    """Timesketch's timeline format (message, datetime, timestamp_desc + extra columns), oldest first."""
    evidence = evidence or {}
    rows = []
    seen = set()

    def add(r):
        if r and (r["datetime"], r["message"], r["event_key"]) not in seen:
            seen.add((r["datetime"], r["message"], r["event_key"]))
            rows.append(r)

    for p in case["pins"]:
        s = p.get("snapshot") or {}
        if p["type"] == "alert":
            add(_ts_row(case, p.get("time"), "Alert raised", f"Alert: {p['label']} ({s.get('level', '?')}): {s.get('reason', '')}",
                        "alert", p.get("host"), ""))
            for r in evidence.get(p["ref"], []):
                add(_ts_row(case, sd.when(r), "Event recorded", pivot_mod.summary(r), "alert evidence", r.get("host"), r.get("dedup_key")))
        elif p["type"] == "event":
            add(_ts_row(case, p.get("time"), "Event recorded", s.get("summary") or p["label"], "event", p.get("host"), p["ref"]))
        elif p["type"] == "entity":
            add(_ts_row(case, s.get("first"), "First seen", f"{s.get('kind_word', p.get('kind'))} first seen: {p['ref']}", "thing"))
            add(_ts_row(case, s.get("last"), "Last seen", f"{s.get('kind_word', p.get('kind'))} last seen: {p['ref']}", "thing"))
    for n in case["notes"]:
        add(_ts_row(case, n["time"], "Analyst note written", f"Analyst note: {n['text']}", "note"))
    for key, m in (case.get("marks") or {}).items():
        label = next((p["label"] for p in case["pins"] if f"p:{p['id']}" == key), key)
        add(_ts_row(case, m["time"], "Analyst mark set", f"Analyst marked hypothesis {label} as {m['status']}", "mark"))
    return sorted(rows, key=lambda r: (r["timestamp"], r["message"]))


def to_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=TS_FIELDS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def to_jsonl(rows):
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


# -- STIX 2.1 ----------------------------------------------------------------------------------------------------

def _pattern_value(v):
    """A STIX pattern string literal: backslash and quote escaped."""
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _basename(path):
    return pivot_mod._base(path)


def stix_bundle(case, evidence=None):
    """The case as a STIX 2.1 bundle (stix2 library): SCOs for the things, observed-data for recorded events
    and each alert's evidence, indicators for the pinned things, notes for alerts, hypotheses and the analyst's
    notes, opinions for the analyst's marks, relationships, all gathered in one grouping."""
    import stix2                                             # imported here: a missing library never breaks the lab

    evidence = evidence or {}
    now = datetime.now(timezone.utc)
    me = stix2.Identity(name="Analyst Lab", identity_class="system",
                        description="Analyst Lab (a local recorder and investigation lab): exported from a case.")
    objs, scos = [me], {}

    def sco(kind, value):
        """One STIX Cyber-observable per (kind, value), shared by everything that names it."""
        k = (kind, str(value).lower())
        if k in scos:
            return scos[k]
        if kind == "hash":
            o = stix2.File(hashes={"SHA-256": str(value).lower()})
        elif kind in ("file", "program"):
            o = stix2.File(name=_basename(value) or str(value), custom_properties={"x_analystlab_path": str(value)},
                           allow_custom=True)
        elif kind == "ip":
            o = stix2.IPv6Address(value=value) if ":" in str(value) else stix2.IPv4Address(value=value)
        elif kind == "domain":
            o = stix2.DomainName(value=value)
        elif kind == "registry":
            o = stix2.WindowsRegistryKey(key=value)
        elif kind == "user":
            o = stix2.UserAccount(user_id=str(value), account_login=str(value).split("\\")[-1])
        else:
            return None
        scos[k] = o
        objs.append(o)
        return o

    def observed(rows, label):
        refs, times = [], []
        for r in rows:
            for ent in pivot_mod.entities_of(r):
                o = sco(ent["kind"], ent["value"])
                if o is not None and o.id not in refs:
                    refs.append(o.id)
            d = iso(sd.when(r))
            if d:
                times.append(d)
        if not refs or not times:
            return None
        od = stix2.ObservedData(created_by_ref=me.id, first_observed=min(times), last_observed=max(times),
                                number_observed=len(rows), object_refs=refs,
                                custom_properties={"x_analystlab_label": label,
                                                   "x_analystlab_event_keys": [str(r.get("dedup_key")) for r in rows]},
                                allow_custom=True)
        objs.append(od)
        return od

    alert_od, indicators = {}, []
    for p in case["pins"]:
        s = p.get("snapshot") or {}
        if p["type"] == "alert":
            od = observed(evidence.get(p["ref"], []), f"evidence of the alert {p['label']}")
            alert_od[p["ref"]] = od
            objs.append(stix2.Note(created_by_ref=me.id, abstract=f"Alert: {p['label']}",
                                   content=f"Level {s.get('level', '?')}, rule {s.get('rule', '?')}, raised {p.get('time')}. {s.get('reason', '')}",
                                   object_refs=[od.id] if od else [me.id]))
        elif p["type"] == "event":
            row = {"time": p.get("time"), "dedup_key": p["ref"]}
            for ent in s.get("entities") or []:
                row.setdefault({"program": "Image", "file": "TargetFilename", "hash": "sha256", "ip": "DestinationIp",
                                "domain": "QueryName", "registry": "TargetObject", "user": "User"}.get(ent["kind"], "_"), ent["value"])
            observed([row], s.get("summary") or p["label"])
        elif p["type"] == "entity":
            kind = p.get("kind")
            o = sco(kind, p["ref"])
            path = {"hash": "file:hashes.'SHA-256'", "ip": ("ipv6-addr:value" if ":" in p["ref"] else "ipv4-addr:value"),
                    "domain": "domain-name:value", "registry": "windows-registry-key:key", "user": "user-account:user_id",
                    "file": "file:name", "program": "file:name"}.get(kind)
            if path is None:
                continue
            value = _basename(p["ref"]) if kind in ("file", "program") else (p["ref"].lower() if kind == "hash" else p["ref"])
            ind = stix2.Indicator(created_by_ref=me.id, name=f"{s.get('kind_word', kind)}: {p['ref']}",
                                  description=f"Pinned to the case '{case['title']}': named by {s.get('events', '?')} recorded event(s).",
                                  pattern=f"[{path} = {_pattern_value(value)}]", pattern_type="stix",
                                  valid_from=iso(s.get("first")) or now, indicator_types=["unknown"])
            objs.append(ind)
            indicators.append((ind, o))

    for ind, o in indicators:                     # after every observed-data exists, whatever the pin order
        for od in [x for x in objs if getattr(x, "type", "") == "observed-data" and o is not None and o.id in x.object_refs]:
            objs.append(stix2.Relationship(ind, "based-on", od, created_by_ref=me.id))

    opinion = {"confirmed": "agree", "ruled_out": "disagree", "open": "neutral"}
    marks = case.get("marks") or {}
    for p in case["pins"]:
        if p["type"] != "hypothesis":
            continue
        n = stix2.Note(created_by_ref=me.id, abstract="Analyst's hypothesis", content=p["label"], object_refs=[me.id])
        objs.append(n)
        m = marks.get(f"p:{p['id']}")
        if m:
            objs.append(stix2.Opinion(created_by_ref=me.id, opinion=opinion[m["status"]], object_refs=[n.id],
                                      explanation=f"The analyst marked it {m['status']}. {m.get('note', '')}".strip()))
    for aid, rep in (case.get("alerts") or {}).items():
        od = alert_od.get(aid)
        for h in (rep or {}).get("hypotheses") or []:
            n = stix2.Note(created_by_ref=me.id, abstract=f"Hypothesis of the evidence graph ({h.get('band_label') or h.get('band') or 'no band'})",
                           content=h.get("sentence") or "", object_refs=[od.id] if od else [me.id])
            objs.append(n)
            m = marks.get(f"h:{aid}:{h.get('id')}")
            if m:
                objs.append(stix2.Opinion(created_by_ref=me.id, opinion=opinion[m["status"]], object_refs=[n.id],
                                          explanation=f"The analyst marked it {m['status']}. {m.get('note', '')}".strip()))
    for note in case["notes"]:
        objs.append(stix2.Note(created_by_ref=me.id, abstract="Analyst note", content=note["text"], object_refs=[me.id]))

    extra = {"description": case["summary"]} if case.get("summary") else {}
    group = stix2.Grouping(created_by_ref=me.id, name=case["title"], context="suspicious-activity",
                           object_refs=[o.id for o in objs], **extra)
    return stix2.Bundle(objects=objs + [group], allow_custom=True)


# -- indicators only (for the sweep lab, another tool, or a colleague) --------------------------------------------

IOC_KINDS = (("hash", "SHA-256 fingerprints"), ("ip", "IP addresses"), ("domain", "domain names"), ("file", "files"))


def iocs(case, evidence=None):
    """{kind: sorted values}: the fingerprints, addresses, domains and files the case names (its pinned things,
    its pinned events, and its pinned alerts' evidence). Programs count as files; runs, users and registry keys
    are left out (they are not indicators another machine could match)."""
    evidence = evidence or {}
    out = {k: set() for k, _ in IOC_KINDS}

    def add(kind, value):
        kind = "file" if kind == "program" else kind
        if kind in out and value not in (None, "", "-"):
            out[kind].add(str(value).lower() if kind in ("hash", "domain") else str(value))

    for p in case["pins"]:
        if p["type"] == "entity":
            add(p.get("kind"), p["ref"])
        elif p["type"] == "event":
            for e in (p.get("snapshot") or {}).get("entities") or []:
                add(e["kind"], e["value"])
        elif p["type"] == "alert":
            for r in evidence.get(p["ref"], []):
                for e in pivot_mod.entities_of(r):
                    add(e["kind"], e["value"])
    return {k: sorted(v, key=str.lower) for k, v in out.items()}


def iocs_text(case, evidence=None):
    """One indicator per line, a "#" heading per kind (the sweep lab and most tools skip "#" lines)."""
    found = iocs(case, evidence)
    lines = [f"# Indicators from the case \"{case['title']}\" ({case['id']}), Analyst Lab. One per line."]
    for kind, words in IOC_KINDS:
        if found[kind]:
            lines += ["", f"# {words}"] + found[kind]
    return "\n".join(lines) + "\n"
