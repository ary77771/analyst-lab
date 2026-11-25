"""Labs: the case board (night 2026-11-23, builder night-pivot).

An analyst opens a case, pins evidence from any lab (alerts, events, things such as a file or an address,
and their own hypotheses), writes notes, and marks each hypothesis "confirmed", "ruled out" or "open". The
case shows a timeline of the pinned items, and turns into a printable report, a STIX 2.1 bundle and a
Timesketch timeline (engine/labs/_case_export.py).

Storage: one JSON file per case in the folder `cases` inside the recordings folder the dashboard was started
with (engine.labs.context().recordings; git-ignored, never committed: DESIGN 9.1). This is the only thing the
lab writes; the event store and the alert database are only read. A deleted case is moved to the
sub-folder `deleted`, never erased.

What the analyst marks is the ANALYST's judgement and is always shown as such, next to (never instead of)
the grade the evidence graph gave: a hypothesis the analyst confirms stays a hypothesis of the graph.

    GET    /api/labs/cases                          the cases, newest first
    POST   /api/labs/cases                          {title, summary?}: a new case
    GET    /api/labs/cases/{id}                     the case, its pinned alerts' facts/hypotheses/gaps, timeline
    PATCH  /api/labs/cases/{id}                     {title?, summary?}
    DELETE /api/labs/cases/{id}                     moved to the sub-folder `deleted` (kept, not erased)
    POST   /api/labs/cases/{id}/pins                {type, ref, label?, time?, kind?, host?}
    DELETE /api/labs/cases/{id}/pins/{pin}
    POST   /api/labs/cases/{id}/notes               {text}
    DELETE /api/labs/cases/{id}/notes/{note}
    PUT    /api/labs/cases/{id}/marks               {key, status, note?}: an analyst's mark on a hypothesis
    GET    /api/labs/cases/{id}/report              the printable HTML report
    GET    /api/labs/cases/{id}/stix                a STIX 2.1 bundle (JSON)
    GET    /api/labs/cases/{id}/timesketch.csv      a Timesketch timeline (also .jsonl)
    GET    /api/labs/cases/{id}/iocs.txt            indicators only, one per line (the sweep lab's input)
"""

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from . import _shared_defs as sd
from . import pivot as pivot_mod

router = APIRouter(prefix="/api/labs/cases")

CASE_ID = re.compile(r"^c-\d{8}-\d{6}-[0-9a-f]{6}$")
ITEM_ID = re.compile(r"^[pn]-[0-9a-f]{8}$")
PIN_TYPES = ("alert", "event", "entity", "hypothesis")
STATUSES = ("open", "confirmed", "ruled_out")
STATUS_WORDS = {"open": "open", "confirmed": "confirmed by the analyst", "ruled_out": "ruled out by the analyst"}
MAX_TEXT = 4000
_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _context():
    from engine import labs                     # Fable's registry (engine/labs/__init__.py)
    return labs.context()


class CaseBook:
    """The cases in one folder. Every write is whole-file and atomic (a temp file, then a rename)."""

    def __init__(self, folder):
        self.folder = folder

    def _path(self, case_id):
        if not CASE_ID.match(case_id or ""):
            raise KeyError(case_id)
        return os.path.join(self.folder, case_id + ".json")

    def list(self):
        out = []
        if not os.path.isdir(self.folder):
            return out
        for name in os.listdir(self.folder):
            if not name.endswith(".json") or not CASE_ID.match(name[:-5]):
                continue
            try:
                c = self.get(name[:-5])
            except (KeyError, ValueError, OSError):
                continue
            out.append({"id": c["id"], "title": c["title"], "created": c["created"], "updated": c["updated"],
                        "pins": len(c["pins"]), "notes": len(c["notes"]), "draft": is_draft(c)})
        return sorted(out, key=lambda c: (c["updated"], c["id"]), reverse=True)

    def get(self, case_id):
        p = self._path(case_id)
        if not os.path.exists(p):
            raise KeyError(case_id)
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def save(self, case):
        case["updated"] = now()
        os.makedirs(self.folder, exist_ok=True)
        p = self._path(case["id"])
        tmp = p + f".{secrets.token_hex(4)}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(case, f, ensure_ascii=False, indent=1)
        os.replace(tmp, p)
        return case

    def create(self, title, summary=""):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        case = {"id": f"c-{stamp}-{secrets.token_hex(3)}", "title": _text(title, 200) or "Untitled case",
                "summary": _text(summary), "created": now(), "updated": now(), "pins": [], "notes": [], "marks": {}}
        with _lock:
            return self.save(case)

    def change(self, case_id, fn):
        """Read, change with fn(case), write: one at a time."""
        with _lock:
            case = self.get(case_id)
            result = fn(case)
            self.save(case)
            return result if result is not None else case

    def delete(self, case_id):
        with _lock:
            p = self._path(case_id)
            if not os.path.exists(p):
                raise KeyError(case_id)
            bin_ = os.path.join(self.folder, "deleted")
            os.makedirs(bin_, exist_ok=True)
            os.replace(p, os.path.join(bin_, os.path.basename(p)))


AUTO_TITLE = re.compile(r"^(Untitled case|Case \d{4}-\d{2}-\d{2} \d{2}:\d{2})$")


def is_draft(case):
    """A case nobody has worked on yet: an automatic title, at most one pin, no note, no summary. The case board
    keeps drafts behind "show drafts" so a test click is not the first thing a visitor sees; nothing is deleted."""
    return (bool(AUTO_TITLE.match(case.get("title") or "Untitled case")) and len(case.get("pins") or []) <= 1
            and not case.get("notes") and not (case.get("summary") or "").strip())


def _text(s, limit=MAX_TEXT):
    return (s or "").strip()[:limit]


def _new_id(prefix):
    return f"{prefix}-{secrets.token_hex(4)}"


# -- what a pin keeps: a snapshot taken when it is pinned, so the case reads the same tomorrow --------------

def snapshot(ctx, ptype, ref, kind=None):
    """What the stores say about the pinned thing now (None for an analyst's own hypothesis)."""
    if ptype == "alert":
        a = ctx.alert(ref)
        if a is None or not pivot_mod.host_ok(a.host):        # night rule 11: the lab VM's data only
            raise LookupError("no such alert")
        return {"title": a.title, "level": a.level, "time": a.time, "host": a.host, "rule": a.rule_id,
                "source": a.source, "reason": a.reason, "evidence": list(a.evidence)}
    if ptype == "event":
        row = ctx.event(ref)
        if row is None or not pivot_mod.host_ok(row.get("host")):
            raise LookupError("no such event")
        return {"time": sd.when(row), "host": row.get("host"), "event_id": row.get("event_id"),      # the one clock
                "type": row.get("type"), "summary": pivot_mod.summary(row),
                "command_line": row.get("CommandLine"), "entities": pivot_mod.entities_of(row)}
    if ptype == "entity":
        if kind not in pivot_mod.KINDS:
            raise LookupError(f"an entity needs a kind, one of {sorted(pivot_mod.KINDS)}")
        con = ctx.events()
        try:
            r = pivot_mod.pivot(con, [], kind, ref, limit=1)
        finally:
            con.close()
        return {"kind_word": r["kind_word"], "events": r["total"], "first": r["first"], "last": r["last"],
                "value": r["value"]}
    return None


def add_pin(book, ctx, case_id, ptype, ref, label="", time=None, kind=None, host=None):
    if ptype not in PIN_TYPES:
        raise ValueError(f"type must be one of {PIN_TYPES}")
    ref = _text(ref, 2000)
    if not ref:
        raise ValueError("ref is empty")
    if ptype == "entity" and kind == "hash":
        ref = ref.lower()
    snap = snapshot(ctx, ptype, ref, kind)
    if ptype == "hypothesis":
        label = label or ref
    elif not label:
        label = (snap or {}).get("title") or (snap or {}).get("summary") or ref
    when = time or (snap or {}).get("time") or (snap or {}).get("first")

    def same(p):
        return p["type"] == ptype and p["ref"].lower() == ref.lower() and (p.get("kind") or None) == (kind or None)

    # pinned once only, and pinning it again changes nothing (not even "last changed": a leftover draft must stay
    # a leftover, critique-4)
    existing = next((p for p in book.get(case_id)["pins"] if same(p)), None)
    if existing is not None:
        return existing

    def fn(case):
        for p in case["pins"]:
            if same(p):
                return p
        pin = {"id": _new_id("p"), "type": ptype, "ref": ref, "kind": kind if ptype == "entity" else None,
               "label": _text(label, 300), "time": when, "host": host or (snap or {}).get("host"),
               "added": now(), "snapshot": snap}
        case["pins"].append(pin)
        if ptype == "hypothesis":
            case["marks"].setdefault(f"p:{pin['id']}", {"status": "open", "note": "", "time": now()})
        return pin

    return book.change(case_id, fn)


def remove(book, case_id, field, item_id):
    def fn(case):
        before = len(case[field])
        case[field] = [x for x in case[field] if x["id"] != item_id]
        if len(case[field]) == before:
            raise KeyError(item_id)
        case["marks"].pop(f"p:{item_id}", None)
    return book.change(case_id, fn)


def add_note(book, case_id, text):
    text = _text(text)
    if not text:
        raise ValueError("a note needs some text")

    def fn(case):
        note = {"id": _new_id("n"), "text": text, "time": now()}
        case["notes"].append(note)
        return note
    return book.change(case_id, fn)


def mark(book, case_id, key, status, note=""):
    """An analyst's mark on a hypothesis: key = "h:<alert id>:<hypothesis id>" or "p:<pin id>"."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if not re.match(r"^(h:[0-9a-f]{1,40}:[A-Za-z0-9_.-]{1,80}|p:p-[0-9a-f]{8})$", key or ""):
        raise ValueError("key must be h:<alert id>:<hypothesis id> or p:<pin id>")

    def fn(case):
        if key.startswith("p:") and not any(p["id"] == key[2:] and p["type"] == "hypothesis" for p in case["pins"]):
            raise KeyError(key)
        if key.startswith("h:") and not any(p["type"] == "alert" and p["ref"] == key.split(":")[1] for p in case["pins"]):
            raise KeyError(key)
        case["marks"][key] = {"status": status, "note": _text(note, 1000), "time": now()}
        return case["marks"][key]
    return book.change(case_id, fn)


# -- the case as the board and the exports read it --------------------------------------------------------

def _report_of(ctx, alert_id):
    """The facts, hypotheses and gaps the report gives for a pinned alert (Python's own grading), or None."""
    try:
        a = ctx.alert(alert_id)
        if a is None or not pivot_mod.host_ok(a.host):
            return None
        c = ctx.report(a)
    except Exception as e:                       # no graph in this dashboard, an alert of another store, ...
        return {"error": f"{type(e).__name__}: {e}"}
    keep = lambda xs, fields: [{k: x.get(k) for k in fields if k in x} for x in (xs or [])]
    return {"summary": c.get("summary"), "counts": c.get("counts"),
            "facts": keep(c.get("facts"), ("id", "sentence", "time", "kind", "citations", "in_chain")),
            "hypotheses": keep(c.get("hypotheses"), ("id", "sentence", "band", "band_label", "reason", "alternative",
                                                     "time", "citations")),
            "gaps": keep(c.get("gaps"), ("id", "what", "where", "reason", "plain", "time"))}


def timeline(case):
    """The pinned items that have a recorded time, oldest first (the analyst's notes keep their own clock)."""
    rows = [{"time": p["time"], "type": p["type"], "label": p["label"], "pin": p["id"], "kind": p.get("kind"),
             "ref": p["ref"]} for p in case["pins"] if p.get("time")]
    return sorted(rows, key=lambda r: (r["time"], r["pin"]))


def expand(ctx, case):
    """The case plus, for each pinned alert, its report's facts / hypotheses / gaps, and the timeline."""
    out = dict(case)
    out["alerts"] = {p["ref"]: _report_of(ctx, p["ref"]) for p in case["pins"] if p["type"] == "alert"}
    out["timeline"] = timeline(case)
    out["status_words"] = STATUS_WORDS
    return out


# -- the routes --------------------------------------------------------------------------------------------

def _book(ctx):
    """The cases of the running dashboard: always inside the recordings folder IT was given (never a path
    of this file's own), so a test dashboard never touches the real cases."""
    rec = getattr(ctx, "recordings", None)
    if not rec:
        raise HTTPException(status_code=503, detail="this dashboard has no recordings folder to keep cases in")
    return CaseBook(os.path.join(rec, "cases"))


def _call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except KeyError:
        raise HTTPException(status_code=404, detail="no such case or item")
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


class NewCase(BaseModel):
    title: str = ""
    summary: str = ""


class CaseChange(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None


class NewPin(BaseModel):
    type: str
    ref: str
    label: str = ""
    time: Optional[str] = None
    kind: Optional[str] = None
    host: Optional[str] = None


class NewNote(BaseModel):
    text: str


class Mark(BaseModel):
    key: str
    status: str
    note: str = ""


@router.get("")
def list_cases():
    return _book(_context()).list()


@router.post("")
def create_case(body: NewCase):
    return _book(_context()).create(body.title, body.summary)


@router.get("/alert/{alert_id}")
def alert_brief(alert_id: str):
    """One alert's title, level and time, for "pin this alert to the open case" (NextStrip's last step opens
    #/labs/cases?alert=<id>). 404 for an alert this dashboard does not show (another machine, or none)."""
    a = _context().alert(alert_id)
    if a is None or not pivot_mod.host_ok(a.host):
        raise HTTPException(status_code=404, detail="This alert isn't in this recording")
    return {"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time}


@router.get("/{case_id}")
def get_case(case_id: str):
    ctx = _context()
    return _call(lambda: expand(ctx, _book(ctx).get(case_id)))


@router.patch("/{case_id}")
def change_case(case_id: str, body: CaseChange):
    def fn(case):
        if body.title is not None:
            case["title"] = _text(body.title, 200) or case["title"]
        if body.summary is not None:
            case["summary"] = _text(body.summary)
    return _call(_book(_context()).change, case_id, fn)


@router.delete("/{case_id}")
def delete_case(case_id: str):
    _call(_book(_context()).delete, case_id)
    return {"moved_to": "cases/deleted"}


@router.post("/{case_id}/pins")
def pin(case_id: str, body: NewPin):
    ctx = _context()
    book = _book(ctx)
    p = _call(add_pin, book, ctx, case_id, body.type, body.ref, body.label, body.time, body.kind, body.host)
    return {**p, "case": {"id": case_id, "title": book.get(case_id)["title"]}}   # which case it went to


@router.delete("/{case_id}/pins/{pin_id}")
def unpin(case_id: str, pin_id: str):
    return _call(remove, _book(_context()), case_id, "pins", pin_id)


@router.post("/{case_id}/notes")
def note(case_id: str, body: NewNote):
    return _call(add_note, _book(_context()), case_id, body.text)


@router.delete("/{case_id}/notes/{note_id}")
def unnote(case_id: str, note_id: str):
    return _call(remove, _book(_context()), case_id, "notes", note_id)


@router.put("/{case_id}/marks")
def put_mark(case_id: str, body: Mark):
    return _call(mark, _book(_context()), case_id, body.key, body.status, body.note)


# -- exports (engine/labs/_case_export.py) -------------------------------------------------------------------

def _full(case_id):
    from . import _case_export as X
    ctx = _context()
    case = _call(lambda: expand(ctx, _book(ctx).get(case_id)))
    return X, case, X.evidence_rows(ctx, case)


def _name(case, ext):
    return f'attachment; filename="{case["id"]}.{ext}"'


@router.get("/{case_id}/report", response_class=HTMLResponse)
def report(case_id: str):
    from . import _story_svg
    X, case, ev = _full(case_id)
    alerts = sorted((p for p in case["pins"] if p["type"] == "alert"), key=lambda p: str(p.get("time") or ""))
    pic = _story_svg.for_alert(_context(), alerts[0]["ref"]) if alerts else None      # the first alert's story
    shorts = [(p["label"], X.in_short(p["ref"])) for p in alerts]                     # the checklist's own paragraph
    return HTMLResponse(X.render_report(case, ev, picture=pic["svg"] if pic else None, shorts=shorts),
                        headers={"Cache-Control": "no-store"})


@router.get("/{case_id}/stix")
def stix(case_id: str):
    X, case, ev = _full(case_id)
    try:
        bundle = X.stix_bundle(case, ev)
    except ImportError:
        raise HTTPException(status_code=503, detail="the stix2 library is not installed in this Python (pip install stix2)")
    return Response(bundle.serialize(pretty=True), media_type="application/json",
                    headers={"Content-Disposition": _name(case, "stix.json")})


@router.get("/{case_id}/iocs.txt")
def iocs_txt(case_id: str):
    """Indicators only: fingerprints, addresses, domains and files, one per line (what the sweep lab takes)."""
    X, case, ev = _full(case_id)
    return Response(X.iocs_text(case, ev), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": _name(case, "iocs.txt")})


@router.get("/{case_id}/iocs")
def iocs_json(case_id: str):
    X, case, ev = _full(case_id)
    found = X.iocs(case, ev)
    return {"iocs": found, "text": X.iocs_text(case, ev), "count": sum(len(v) for v in found.values())}


@router.get("/{case_id}/timesketch.csv")
def timesketch_csv(case_id: str):
    X, case, ev = _full(case_id)
    return Response(X.to_csv(X.timesketch_rows(case, ev)), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": _name(case, "timesketch.csv")})


@router.get("/{case_id}/timesketch.jsonl")
def timesketch_jsonl(case_id: str):
    X, case, ev = _full(case_id)
    return Response(X.to_jsonl(X.timesketch_rows(case, ev)), media_type="application/x-ndjson",
                    headers={"Content-Disposition": _name(case, "timesketch.jsonl")})
