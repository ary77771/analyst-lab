"""Lab: Alarm track record ("receipts"). "How often has this alarm rung before, and was it right?"

Per rule, its measured record from ALREADY-COMMITTED results of the frozen v4 (nothing is re-scored here):
  normal use      docs/results/v4/false-alerts-official-v1runs.md, "Raised alerts by rule": how often the rule
                  rang in the laptop week of the test of normal use (counts per rule only; on normal use every alert is a false alarm).
  public tests    docs/results/v4/art-official-phase1.md and -phase2.md: for how many Atomic Red Team tests the rule
                  was one of the rules that detected the test (column "rules (level)" of DETECTED rows).
  blind runs      docs/results/v4/blind-detection-official-v3runs.md, "Per run": alerts the rule raised on steps the
                  answer sheet did not mark ("other alerts"), and in how many runs.
Each source is cited by its file and the last commit that changed it. A rule with no record says "never measured".

Only rule ids, titles and numbers leave here: the results files' program categories are not passed on.
"""

import os
import re
import subprocess
import threading

from fastapi import APIRouter

from engine import labs
from engine.labs import _files

router = APIRouter(prefix="/api/labs/receipts")

ROOT = _files.CODE_ROOT
SOURCES = {
    "normal": ("docs/results/v4/false-alerts-official-v1runs.md",),
    "public": ("docs/results/v4/art-official-phase1.md", "docs/results/v4/art-official-phase2.md"),
    "blind": ("docs/results/v4/blind-detection-official-v3runs.md",),
    "rounds": ("docs/results/v4/README-with-round5.md",),
}

# What the blind rounds 4 and 5 say about single rules. The committed results score a blind run per SCENARIO
# (the per-run tables list only "other alerts", and v4 raised none there), so the rule behind a verdict is
# stated only in the write-up of each round. Each row quotes that sentence; tests/labs/test_receipts.py checks
# that the quote and the scenario rows of the verdict table are still in the committed file, so a row can never
# outlive what the file says.
BLIND_VERDICTS = [
    {"rule": "analystlab.create_send_wipe", "round": 4, "scenarios": ["B18", "B20"], "kind": "planted", "runs": 6,
     "outcome": "flagged", "table": {"B18": "**DETECTED 3**", "B20": "**DETECTED 3**"},
     "quote": "B18 and B20 via **F3 `create_send_wipe`**"},
    {"rule": "analystlab.create_send_wipe", "round": 5, "scenarios": ["B28"], "kind": "innocent", "runs": 3,
     "outcome": "false_alarm", "table": {"B28": "**FALSE ALARM 3**"},
     "quote": "exactly one alert, v4's own rule **F3 `analystlab.create_send_wipe` at medium**"},
    {"rule": "analystlab.new_listener", "round": 4, "scenarios": ["B22"], "kind": "innocent", "runs": 3,
     "outcome": "below_line", "table": {"B22": "**CLEAN 3**"},
     "quote": "so v4 grades `new_listener` low"},
]
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

WORDS = {
    "title": "Alarm track record",
    "intro": ("Each alarm's record from the lab's published results of the frozen version 4: how often it rang on a "
              "week of normal use, how often it was one of the rules that flagged a public test, and how often it rang "
              "on blind test steps nobody marked. Counted from committed results files; nothing is re-scored here."),
    "normal": "Normal use (a week on the laptop)",
    "normal_line": ("Rang {alerts} times in {hours} active hours of normal use on the laptop, {period} ({per_hour} per "
                    "active hour, on {days} days)"),
    "normal_note": "On normal use every alert counts as a false alarm.",
    "public": "Public tests (Atomic Red Team in the test machine)",
    "public_line": "One of the rules that flagged {tests} of the {executed} executed public tests",
    "blind": "Blind test runs",
    "blind_line": "Rang {alerts} times in {runs} of {total} blind runs on steps the answer sheet did not mark",
    "blind_verdict": {
        "flagged": "Blind round {round}: it is the rule that flagged the planted steps of {scenarios} ({kind}, {runs} runs)",
        "false_alarm": "Blind round {round}: it raised a false alarm on {scenarios} ({kind}, {runs} runs)",
        "below_line": "Blind round {round}: on {scenarios} ({kind}, {runs} runs) it stayed below the alarm line",
    },
    "blind_kind": {"planted": "a planted misuse, says the writer's answer sheet",
                   "innocent": "innocent, says the writer's answer sheet"},
    "never": "Never measured: this rule has no record in the published results.",
    "blind_none": "In the {total} blind runs, version 4 raised no alert on a step the answer sheet did not mark.",
    "alerts": "This store's alerts, each with its rule's record",
    "all": "Every rule with a record",
    "cite": "Source",
    "hours_label": "active hours of normal use (laptop week {period}, a test of normal use)",
    "hours_source": ("Active hours: {hours} h, laptop week {period} (a test of normal use), counted with {code}. Source: {file} at commit "
                     "{commit}. Other pages may count a different week, so their active hours can differ."),
}

_lock = threading.Lock()
_cache = {"key": None, "data": None}


# --- the results files -------------------------------------------------------------------------------------------
def _read(rel):
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


def table_after(text, heading):
    """Rows (lists of cell strings) of the first markdown table after the heading line that contains `heading`."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("#") and heading.lower() in l.lower()), None)
    if start is None:
        return []
    rows, seen_table = [], False
    for l in lines[start + 1:]:
        if l.startswith("|"):
            seen_table = True
            cells = [c.strip() for c in l.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                rows.append(cells)
        elif seen_table:
            break
        elif l.startswith("#"):
            break
    return rows


def _num(s):
    s = (s or "").replace(",", "").replace("*", "").strip()
    try:
        return float(s) if "." in s else int(s)
    except ValueError:
        return None


def normal_period(text):
    """The week the normal-use numbers were measured on, from the file's own header ("snapshot (A .. B"), or None."""
    span = re.search(r"snapshot \((\d{4}-\d\d-\d\d) \.\. (\d{4}-\d\d-\d\d)", text or "")
    return f"{span.group(1)} to {span.group(2)}" if span else None


def normal_code(text):
    """Which version's code counted the normal-use numbers, from the file's header ("(v4 code)"), or None."""
    m = re.search(r"\((v\d+) code\)", text or "")
    return f"the {m.group(1)} code" if m else None


def hours_source(data):
    """Where the active-hours figure comes from: {hours, period, code, file, commit, date} (None when unknown)."""
    src = next((s for s in data["sources"] if s["kind"] == "normal"), None)
    if data.get("hours") is None or not src or not src["present"]:
        return None
    return {"hours": data["hours"], "period": data.get("period"), "code": data.get("code"), "file": src["file"],
            "commit": src["commit"], "date": src["date"]}


def parse_normal(text):
    """{title: {alerts, per_hour, days, programs}} and the week's active hours."""
    hours = re.search(r"Active hours:\s*\**([\d.,]+)", text)
    rows = table_after(text, "Raised alerts by rule")
    head, out = (rows[0] if rows else []), {}
    idx = {h: i for i, h in enumerate(head)}
    for r in rows[1:]:
        try:
            title = r[idx["rule"]]
            out[title] = {"alerts": _num(r[idx["alerts"]]), "per_hour": _num(r[idx["per active hour"]]),
                          "days": _num(r[idx["days"]]), "programs": _num(r[idx["programs"]]), "level": r[idx["level"]]}
        except (KeyError, IndexError):
            continue
    return out, _num(hours.group(1)) if hours else None


def parse_public(texts):
    """({rule id: {tests, techniques}}, executed tests): DETECTED rows' "rules (level)" cells."""
    per, executed = {}, 0
    for text in texts:
        m = re.search(r"executed:\s*(\d+)", text)              # the file's own count (rows also list tests not run)
        executed += int(m.group(1)) if m else 0
        for l in text.splitlines():
            if not re.match(r"^\| T\d", l):
                continue
            cells = [c.strip() for c in l.strip().strip("|").split("|")]
            if len(cells) < 8 or cells[2] != "DETECTED":
                continue
            for rid in set(UUID.findall(cells[7])) | set(re.findall(r"analystlab\.[\w.]+|beacon", cells[7])):
                e = per.setdefault(rid, {"tests": 0, "techniques": set()})
                e["tests"] += 1
                e["techniques"].add(cells[0])
    return {k: {"tests": v["tests"], "techniques": sorted(v["techniques"])} for k, v in per.items()}, executed


def parse_blind(text):
    """({rule id: {alerts, runs}}, number of runs) from the "Per run" table's "other alerts" column."""
    rows = table_after(text, "Per run")
    per, total = {}, 0
    for r in rows[1:]:
        if len(r) < 8:
            continue
        total += 1
        for rid, n in re.findall(r"([\w.-]+)\[[a-z]+\]: (\d+)", r[7]):
            e = per.setdefault(rid, {"alerts": 0, "runs": 0})
            e["alerts"] += int(n)
            e["runs"] += 1
    return per, total


def commit_of(rel):
    """(short commit, date) of the last commit that changed a results file, or (None, None)."""
    try:
        r = subprocess.run(["git", "log", "-1", "--format=%h %cs", "--", rel], cwd=ROOT, capture_output=True, text=True,
                           timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        parts = (r.stdout or "").split()
        return (parts[0], parts[1]) if len(parts) == 2 else (None, None)
    except (OSError, subprocess.SubprocessError):
        return None, None


def records():
    """Everything parsed once per change of the results files."""
    files = [f for fs in SOURCES.values() for f in fs]
    key = tuple((f, os.path.getmtime(os.path.join(ROOT, *f.split("/")))) for f in files
                if os.path.exists(os.path.join(ROOT, *f.split("/"))))
    with _lock:
        if _cache["key"] == key:
            return _cache["data"]
    have = lambda f: os.path.exists(os.path.join(ROOT, *f.split("/")))
    normal_text = _read(SOURCES["normal"][0]) if have(SOURCES["normal"][0]) else ""
    normal, hours = parse_normal(normal_text) if normal_text else ({}, None)
    public, executed = parse_public([_read(f) for f in SOURCES["public"] if have(f)])
    blind, total = parse_blind(_read(SOURCES["blind"][0])) if have(SOURCES["blind"][0]) else ({}, 0)
    rounds_text = _read(SOURCES["rounds"][0]) if have(SOURCES["rounds"][0]) else ""
    verdicts = {}
    for v in BLIND_VERDICTS:
        if v["quote"] in rounds_text:                    # only what the committed file still says
            verdicts.setdefault(v["rule"], []).append({k: v[k] for k in ("round", "scenarios", "kind", "runs", "outcome")})
    sources = []
    for name, fs in SOURCES.items():
        for f in fs:
            c, d = commit_of(f) if have(f) else (None, None)
            sources.append({"kind": name, "file": f, "present": have(f), "commit": c, "date": d})
    data = {"blind_verdicts": verdicts, "normal": normal, "hours": hours, "period": normal_period(normal_text), "code": normal_code(normal_text), "public": public, "executed": executed, "blind": blind,
            "blind_runs": total, "sources": sources}
    with _lock:
        _cache.update(key=key, data=data)
    return data


def record_for(rule_id, title, data):
    """One rule's receipts: {normal, public, blind} each a dict or None, and `measured`."""
    n = data["normal"].get(title) if title else None
    p = data["public"].get(rule_id) if rule_id else None
    b = data["blind"].get(rule_id) if rule_id else None
    bv = data.get("blind_verdicts", {}).get(rule_id) if rule_id else None
    out = {"rule": rule_id, "title": title, "measured": bool(n or p or b or bv), "blind_verdicts": bv,
           "normal": dict(n, hours=data["hours"], period=data.get("period") or "the week measured") if n else None,
           "public": dict(p, executed=data["executed"]) if p else None,
           "blind": dict(b, total=data["blind_runs"]) if b else None}
    out["normal"] and out["normal"].pop("level", None)
    return out


# --- routes ------------------------------------------------------------------------------------------------
@router.get("")
def receipts():
    ctx = labs.context()
    data = records()
    shown = [a for a in ctx.shown_alerts() if _files.host_shown(a.host)]
    alerts = []
    for a in shown:
        alerts.append({"id": a.alert_id, "title": a.title, "rule": a.rule_id, "level": a.level, "time": a.time,
                       "record": record_for(a.rule_id, a.title, data)})
    # every rule with a record: by title (normal use) and by id (public / blind); titles unknown for id-only rules
    rules = {}
    for title, n in data["normal"].items():
        rules[("t", title)] = record_for(None, title, data)
    known = {a.rule_id: a.title for a in ctx.alerts()}
    try:                                                   # titles from the rule files (night-explain's index)
        from engine.labs import _rule_tags
        titles = {rid: r.get("title") for rid, r in _rule_tags.index().items()}
    except Exception:
        titles = {}
    known = {**titles, **known}
    for rid in set(data["public"]) | set(data["blind"]) | set(data.get("blind_verdicts", {})):
        rules[("r", rid)] = record_for(rid, known.get(rid), data)
    every = sorted(rules.values(), key=lambda r: -((r["normal"] or {}).get("alerts") or 0) - 1000 * ((r["public"] or {}).get("tests") or 0))
    return {"words": WORDS, "sources": data["sources"], "hours": data["hours"], "period": data.get("period"),
            "hours_source": hours_source(data),
            "executed": data["executed"],
            "blind_runs": data["blind_runs"], "blind_rules": len(set(data["blind"]) | set(data.get("blind_verdicts", {}))),
            "alerts": alerts, "rules": every}
