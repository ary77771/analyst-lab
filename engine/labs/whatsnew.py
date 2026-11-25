"""Lab: What's new tonight. The morning page: one card per lab built on the night of 2026-11-23, with what it is
for, how to open it, how to switch it off, what is NOT done, its checks and its screenshots, all quoted from the
builders' own status files (docs/night/status-*.md); plus the questions they left for Yousif.

Nothing here is newly claimed: every sentence is a line of a status file, shown with the file it came from. A lab
without a status entry says so. Screenshots are served read-only from docs/night/shots/, only by a name that is
in that folder's own listing (and looks like a plain .png name), never by a path from the browser.

Where the status files are: docs/night/ next to this code (the branch's committed copies win), and next to the
dashboard's recordings folder (the main checkout, where PROOF copies the ones not committed yet).
"""

import os
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from engine import labs
from engine.labs import _files

router = APIRouter(prefix="/api/labs/whatsnew")

SHOT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.png$")
WORDS = {
    "title": "What's new tonight",
    "intro": ("On the night of 23 to 24 November five builders added investigation pages, called labs, without "
              "changing the screens you rehearsed. One card per lab: what it is for, how to open it and switch it off, "
              "what is not done, and how it was checked, in the builders' own words from their status files."),
    "questions": "Questions left for you",
    "not_done": "Not done, or done only in part",
    "no_entry": "No status entry mentions this lab yet.",
    "source": "From",
    "loaded": "Loaded in this dashboard", "left_out": "Left out of this dashboard",
}

_KEYS = {
    "open": re.compile(r"(?i)\b(open(s|ed)?\b|how to open|address)"),
    "off": re.compile(r"(?i)(switch(ed)? off|off switch|how to switch it off|turn(ed)? off)"),
    "not_done": re.compile(r"(?i)\b(not done|not yet|NOT DONE|known limits?|open item)"),
    "checks": re.compile(r"(?i)(\b\d+\s*(/\s*\d+\s*)?(python |lab |unit |frontend )?(tests?|pass(ed)?)\b|\bvitest\b|\bpytest\b|\bsabotage\b|\btsc\b)"),
}


# --- the status files --------------------------------------------------------------------------------------------
def night_dirs(recordings=None):
    out = [os.path.join(_files.CODE_ROOT, "docs", "night")]
    if recordings:
        out.append(os.path.join(os.path.dirname(os.path.abspath(recordings)), "docs", "night"))
    here = _files.CODE_ROOT
    for _ in range(6):                          # a worktree also reads the main checkout's copies
        here = os.path.dirname(here)
        out.append(os.path.join(here, "docs", "night"))
    seen, res = set(), []
    for d in out:
        if os.path.isdir(d) and d.lower() not in seen:
            seen.add(d.lower())
            res.append(d)
    return res


def status_files(recordings=None):
    """{file name: text}: every docs/night/status-*.md; the first folder (this code's own) wins a name, except
    over a copy that is only a pointer ("moved")."""
    out = {}
    for d in night_dirs(recordings):
        for name in sorted(os.listdir(d)):
            if not re.match(r"^status-[\w.-]+\.md$", name):
                continue
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
                text = f.read()
            if name not in out or (len(out[name]) < 400 and len(text) > len(out[name])):
                out[name] = text
    return out


def sections(text):
    """[(heading, [lines])] of a markdown text (a section runs to the next heading of any level)."""
    out, head, lines = [], "", []
    for line in text.splitlines():
        if line.startswith("#"):
            if head or lines:
                out.append((head, lines))
            head, lines = line.lstrip("#").strip(), []
        else:
            lines.append(line)
    out.append((head, lines))
    return out


def _mention(lab_id):
    return re.compile(rf"(#/labs/{re.escape(lab_id)}\b|labs/{re.escape(lab_id)}[/.`]|engine/labs/{re.escape(lab_id)}\.py)")


def _bullets(lines):
    """Join wrapped continuation lines onto their bullet: ['- a b', '  c'] -> ['- a b c']."""
    out = []
    for l in lines:
        if out and l.startswith("  ") and not l.strip().startswith(("-", "|", "*")) and l.strip():
            out[-1] += " " + l.strip()
        else:
            out.append(l.rstrip())
    return [l for l in out if l.strip()]


def _clean(s):
    s = re.sub(r"^\s*[-*]\s*", "", s).strip()
    return re.sub(r"\*\*([^*]+)\*\*", r"\1", s)


def facts_for(lab_id, files, shots):
    """What the status files say about one lab: {source, heading, what, open, off, not_done, checks, notes, shots},
    or None. Best source: a section whose heading names the lab's address; then a row of a table of labs; then any
    section that mentions it (there, the mentioning line itself is the description)."""
    rx = _mention(lab_id)
    best = None
    for fname, text in files.items():
        for head, lines in sections(text):
            body = _bullets(lines)
            hits = [l for l in body if rx.search(l)]
            labs_named = set(re.findall(r"#/labs/([a-z0-9-]+)", head + "\n" + "\n".join(body)))
            own = bool(rx.search(head)) or (labs_named == {lab_id} and not any(l.lstrip().startswith("|") for l in hits))
            if not hits and not own:
                continue
            rows = [l for l in hits if l.lstrip().startswith("|")]
            if own:
                pick = lambda k: [_clean(l) for l in body if _KEYS[k].search(l) and not l.lstrip().startswith("|")][:3]
                what = _what(body)
                cand = {"what": what, "open": pick("open"), "off": pick("off"), "not_done": pick("not_done"),
                        "checks": pick("checks"), "notes": [_clean(l) for l in body if not l.lstrip().startswith("|")][:14],
                        "score": 10}
            elif rows:
                cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
                cand = {"what": _clean(max((c for c in cells if not rx.search(c)), key=len, default="")),
                        "open": [_clean(c) for c in cells if rx.search(c)][:1], "off": [], "not_done": [], "checks": [],
                        "notes": [], "score": 6}
            else:
                line = _clean(hits[0])
                cand = {"what": line, "open": [], "off": [_clean(l) for l in hits if _KEYS["off"].search(l)][:2],
                        "not_done": [_clean(l) for l in hits if _KEYS["not_done"].search(l)][:2],
                        "checks": [_clean(l) for l in hits if _KEYS["checks"].search(l)][:2], "notes": [], "score": 2}
            cand.update(source=fname, heading=head, text=head + "\n" + "\n".join(body if own else hits))
            if best is None or cand["score"] > best["score"]:
                best = cand
    if best is None:
        return None
    # what the builder's other sections say about this lab (general "Not done" / "Checks" sections)
    for head, lines in sections(files[best["source"]]):
        if head == best["heading"]:
            continue
        named = re.compile(rf"^\s*[-*]?\s*(\*\*)?{re.escape(lab_id)}\b\s*(\*\*)?:", re.I)   # "- why: 22 tests"
        hits = [_clean(l) for l in _bullets(lines) if rx.search(l) or named.search(l)]
        if re.search(r"(?i)not done|known limits|open", head):
            best["not_done"] += [h for h in hits if h not in best["not_done"]][:2]
        elif re.search(r"(?i)\bchecks?\b|tests?", head):
            best["checks"] += [h for h in hits if h not in best["checks"]][:2]
    best["what"] = re.sub(r"(?i)^(what it does|what)\s*:\s*", "", best["what"]).strip()
    label = re.compile(r"(?i)^(off switch|switch off|how to switch (it )?off|not done( yet)?|checks?|checked|tests)\s*:\s*")
    for k in ("off", "not_done", "checks"):
        best[k] = [label.sub("", x).strip() for x in best[k]]
    best["shots"] = shots_in(best["text"], shots, lab_id)
    best.pop("text")
    best.pop("score")
    return best


def _what(body):
    """The section's "What it does" line (with its first sub-points when it ends in a colon), else its first line."""
    for i, l in enumerate(body):
        if re.match(r"(?i)^\s*[-*]\s*\*\*what", l):
            what = _clean(l)
            if what.endswith(":"):
                subs = [_clean(x).rstrip(";") for x in body[i + 1:i + 4] if re.match(r"^\s{2,}[-*]", x)]
                what = what + " " + "; ".join(subs[:2])
            return what
    return next((_clean(l) for l in body if not l.lstrip().startswith("|")), "")


def shots_in(text, shots, lab_id=None):
    """Shot files named in a text (by full stem, or by a short '-NN-name' form after a full name with its prefix),
    and files whose name carries the lab's id as one of its parts (night-explain-01-why-rule.png for "why")."""
    found = []
    for name in sorted(shots):
        stem = name[:-4]
        if stem in text or (lab_id and lab_id in re.split(r"[-_.]", stem.lower())):
            found.append(name)
            continue
        m = re.match(r"^(.*?)(-\d\d[\w-]*)$", stem)
        if m and m.group(1) and m.group(1) in text and re.search(rf"(?<![\w-]){re.escape(m.group(2))}\b", text):
            found.append(name)
    return found[:4]


def paragraphs(lines):
    """Lines joined into paragraphs (blank lines and bullets start a new one), markdown emphasis removed."""
    out, cur = [], []
    for l in lines:
        s = l.strip()
        if not s or re.match(r"^[-*] ", s):
            if cur:
                out.append(" ".join(cur))
            cur = [s[2:]] if s else []
        else:
            cur.append(s)
    if cur:
        out.append(" ".join(cur))
    return [re.sub(r"\*\*|(?<!\w)\*(?=\w)|(?<=\w)\*(?!\w)", "", p).strip() for p in out if p.strip()]


def questions(files):
    """Headings (with their first lines) that put a question to Yousif."""
    out = []
    for fname, text in files.items():
        for head, lines in sections(text):
            if re.search(r"(?i)question.*yousif|for yousif|yousif.*decide", head):
                body = paragraphs(lines)[:6]
                out.append({"source": fname, "heading": head, "lines": body})
    return out


def shot_list(recordings=None):
    """{png name: full path} of docs/night/shots/ (this code's own folder first)."""
    out = {}
    for d in night_dirs(recordings):
        s = os.path.join(d, "shots")
        if os.path.isdir(s):
            for name in os.listdir(s):
                if SHOT_NAME.match(name) and name not in out:
                    out[name] = os.path.join(s, name)
    return out


def page_ids():
    """The ids of the lab pages in dashboard/src/labs/<id>/index.tsx (a page may have no back end of its own)."""
    root = os.path.join(_files.CODE_ROOT, "dashboard", "src", "labs")
    if not os.path.isdir(root):
        return set()
    return {d for d in os.listdir(root) if re.match(r"^[a-z0-9-]+$", d) and os.path.isfile(os.path.join(root, d, "index.tsx"))}


# --- routes ------------------------------------------------------------------------------------------------
@router.get("")
def whatsnew():
    ctx = labs.context()
    rec = getattr(ctx, "recordings", None)
    files = status_files(rec)
    shots = shot_list(rec)
    good, bad = labs.discover()
    loaded = sorted(n for n, _ in good)
    every = sorted((set(loaded) | {b["name"] for b in bad} | page_ids()) - {"whatsnew", "glance"})
    per = {lab: facts_for(lab, files, shots) for lab in every}
    not_done = [{"lab": lab, "source": f["source"], "line": l} for lab, f in per.items() if f for l in f["not_done"]]
    return {"words": WORDS, "labs": per, "loaded": loaded, "left_out": bad and [{"name": b["name"], "problem": b["problem"]} for b in bad],
            "questions": questions(files), "not_done": not_done, "status_files": sorted(files)}


@router.get("/shot/{name}")
def shot(name: str):
    ctx = labs.context()
    shots = shot_list(getattr(ctx, "recordings", None))
    if not SHOT_NAME.match(name) or name not in shots:
        raise HTTPException(status_code=404, detail="no such screenshot")
    return FileResponse(shots[name], media_type="image/png")
