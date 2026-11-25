"""Lab: Rule sandbox (night-tools, 2026-11-24, EXPERIMENTAL). "Would my detection idea have fired here?"

The analyst pastes a Sigma rule (or starts from one of the rules the lab already runs), presses "Try it", and
sees what it would have matched in this dashboard's recording of the test machine:
  - how many records it matches (recorded events; registry writes and PowerShell code DECLARED on a command
    line are counted apart, as the real detectors treat them), and for a correlation rule how many windows;
  - in which test runs and scenarios (the run log's SCENARIO_RUN rows, everyday names from _names);
  - a sample of the matched records, with the fields the rule reads marked;
  - a warning for every innocent, control or baseline run it would have fired on.

Nothing new matches here. The rule goes through the real detectors' own path, read-only:
  engine.detect.load_rules  (pySigma + the SQLite backend + our Sysmon pipeline + our filter documents)
  engine.detect.detect      (the same pass the live loop runs, declared rows included, on the lab's read-only
                             connection, which shows the test machine's rows only: labs.context().reading())
load_rules reads files, so the pasted text is written to a temporary folder outside the project and deleted
straight after. Nothing is saved, nothing under rules/ or the detectors changes, no alert is written anywhere.

Guards: one try at a time (409); at most MAX_TEXT characters; at most TIME_LIMIT_S seconds of SQL (SQLite's
progress handler stops it, and the answer then says "stopped", never a partial count); fields must be ones
the store or Sysmon knows (a plain error otherwise); and no regular expressions (`|re`): their matching runs
in Python inside SQLite, where the time limit cannot stop one slow pattern, which would freeze the dashboard.

A scenario's kind is read from the project's own files, never typed here: `| Bnn | innocent |` rows of the
blind rounds' write-up (docs/results/v4/README-with-round5.md and README.md), `control: true` and
`baseline: true` in scenarios/<id>/ground_truth.yaml. A scenario with none of these is "kind not on record".
"""

import glob
import os
import re
import shutil
import tempfile
import threading
import time
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from engine import labs
from engine.labs import _files

router = APIRouter(prefix="/api/labs/rulesandbox")

ROOT = _files.CODE_ROOT
MAX_TEXT = 64 * 1024
TIME_LIMIT_S = 20.0
SAMPLE = 20
VALUE_CHARS = 400
KIND_FILES = ("docs/results/v4/README-with-round5.md", "docs/results/v4/README.md")
CONTEXT_FIELDS = ("Image", "CommandLine", "ParentImage", "TargetFilename", "DestinationIp", "DestinationPort",
                  "TargetObject", "Details", "QueryName", "User")
SANDBOX_NS = uuid.UUID("6f1c9a52-7d43-4c0e-9a8e-2b1d5c3e4f10")

WORDS = {
    "title": "Rule sandbox",
    "intro": ("Try a detection idea against what was recorded on the test machine. Paste a Sigma rule, or start "
              "from one of the rules the lab already runs, and press Try it."),
    "sandbox": ("This is a sandbox: nothing here changes the real detectors. The rule is tried once, through the "
                "detectors' own matching code, over this recording's test-machine records, and then forgotten."),
    "start_from": "Start from a rule the lab runs",
    "try": "Try it",
    "trying": "Trying the rule…",
    "matches": "records it matches",
    "declared": "matched on a command line's declared registry write or PowerShell code (not recorded events)",
    "windows": "correlation windows",
    "runs": "Test runs it would have fired in",
    "outside": "matched records outside any recorded test run",
    "sample": "Some of the matched records",
    "fields_note": "Marked fields are the fields this rule reads; a field under 'not' did not have to match.",
    "warn_innocent": "This rule would have fired on an innocent test: {name} ({runs} run(s), {records} record(s)).",
    "warn_control": "This rule would have fired on a control run: {name} ({runs} run(s), {records} record(s)).",
    "warn_baseline": "This rule would have fired on a baseline boot where nothing was run: {name} ({runs} run(s), {records} record(s)).",
    "raised": "At level {level} it would be raised (shown as an alert).",
    "stored": "At level {level} it would be stored but not raised: the screens start at {floor}.",
    "none": "It matches nothing in this recording.",
    "kinds": {"innocent": "innocent test", "planted": "planted misuse", "control": "control run",
              "baseline": "baseline boot", None: "kind not on record"},
    "categories": "Log sources the lab records (product: windows)",
    "unnamed": "unnamed run",
}

ERRORS = {
    "empty": "Paste a Sigma rule first.",
    "too_long": "That is longer than a rule needs to be (at most 64 KB).",
    "yaml": "This is not valid YAML: {msg}",
    "sigma": "pySigma could not read this as a Sigma rule: {msg}",
    "fields": "This rule reads field(s) the recording does not have: {fields}. Field names are Sysmon's, e.g. Image, CommandLine, TargetFilename.",
    "regex": ("Regular expressions (|re) are not tried in the sandbox: one slow pattern could freeze the whole "
              "dashboard, and the time limit cannot stop it. Try the idea with contains / startswith / endswith."),
    "skipped": "The lab does not record this rule's log source. It records product: windows with category {cats}.",
    "no_rule": "No Sigma rule was found in the text.",
    "stopped": "The try was stopped after {secs:.0f} seconds: the rule is too slow for the sandbox. Narrow it down.",
    "failed": "The rule could not be run: {msg}",
    "busy": "Another rule is being tried; one at a time.",
    "store": "This dashboard has no event store to try the rule on.",
}

_lock = threading.Lock()
_cache = {}


class Attempt(BaseModel):
    yaml: str


class TryError(ValueError):
    """A plain-words reason a try could not run (shown to the analyst as is)."""


# --- what the project's own files say ---------------------------------------------------------------------------
def _read(rel):
    try:
        with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def scenario_kinds(root=None):
    """{scenario id upper case: "innocent" | "planted" | "control" | "baseline"} from the project's own files."""
    root = root or ROOT
    out = {}
    for rel in KIND_FILES:
        try:
            with open(os.path.join(root, *rel.split("/")), encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        for sid, kind in re.findall(r"(?m)^\|\s*(B\d+)\s*\|\s*(innocent|malicious)\s*\|", text):
            out.setdefault(sid.upper(), "innocent" if kind == "innocent" else "planted")
    for path in glob.glob(os.path.join(root, "scenarios", "*", "ground_truth.yaml")):
        try:
            import yaml
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception:
            continue
        sid = str(doc.get("scenario") or os.path.basename(os.path.dirname(path))).upper()
        if doc.get("baseline") is True:
            out[sid] = "baseline"
        elif doc.get("control") is True:
            out[sid] = "control"
    return out


def run_log(recordings):
    """[{run_id, scenario, host, start, end}] from the run log (the dashboard's vmruns folder, SCENARIO_RUN rows)."""
    folder = os.path.join(recordings or "", "vmruns")
    if not recordings or not os.path.isdir(folder):
        return []
    from engine.jsonl import iter_jsonl, recording_files
    files = recording_files(folder)
    key = ("runs", tuple((p, os.path.getmtime(p)) for p in files))
    if _cache.get("runs_key") == key:
        return _cache["runs"]
    out = []
    for p in files:
        for r in iter_jsonl(p, {}):
            if r.get("type") == "SCENARIO_RUN" and r.get("run_id") and r.get("start"):
                out.append({"run_id": r["run_id"], "scenario": str(r.get("scenario") or "").upper() or None,
                            "host": (r.get("host") or "").lower() or None, "start": r["start"], "end": r.get("end")})
    _cache.update(runs_key=key, runs=out)
    return out


def _t(s):
    from engine.graph import parse_time
    try:
        return parse_time(s)
    except Exception:
        return None


class RunIndex:
    """The run log with its times read once, searched by start time (a broad rule can match thousands of records)."""

    def __init__(self, runs):
        import bisect
        self._bisect = bisect
        self.rows = sorted(((_t(r["start"]), _t(r["end"]) if r.get("end") else None, r) for r in runs if _t(r["start"])),
                           key=lambda x: x[0])
        self.starts = [x[0] for x in self.rows]

    def find(self, host, when):
        """The latest-starting run whose [start, end] holds `when` on `host` (no end: the rest of that day), or None."""
        t = _t(when)
        if t is None:
            return None
        i = self._bisect.bisect_right(self.starts, t)
        for s, e, r in reversed(self.rows[max(0, i - 50):i]):        # runs never overlap by more than a few
            if r["host"] and host and r["host"] != str(host).lower():
                continue
            if (e is not None and t <= e) or (e is None and s.date() == t.date()):
                return r
        return None


def run_for(runs, host, when):
    """The run whose [start, end] holds `when` on `host` (a run with no end: the rest of that day), or None."""
    return RunIndex(runs).find(host, when)


# --- the rule ---------------------------------------------------------------------------------------------------
def _rule_fields(sigma_rule):
    def walk(x, out):
        for it in getattr(x, "detection_items", []) or []:
            if hasattr(it, "detection_items"):
                walk(it, out)
            elif getattr(it, "field", None):
                out.add(it.field)
        return out
    det = getattr(sigma_rule, "detection", None)
    return set().union(*[walk(v, set()) for v in (det.detections.values() if det else [])]) if det else set()


def prepare_text(text):
    """(YAML text with an id on every rule document, the fields the rules read). Raises TryError."""
    import yaml
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule
    if not text or not text.strip():
        raise TryError(ERRORS["empty"])
    if len(text) > MAX_TEXT:
        raise TryError(ERRORS["too_long"])
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as e:
        raise TryError(ERRORS["yaml"].format(msg=" ".join(str(e).split())[:200]))
    if not docs or not all(isinstance(d, dict) for d in docs):
        raise TryError(ERRORS["no_rule"])
    for d in docs:                                        # a pasted idea often has no id: one made from its title
        if ("detection" in d or "correlation" in d) and not d.get("id"):
            d["id"] = str(uuid.uuid5(SANDBOX_NS, str(d.get("title") or d.get("name") or "rule")))
    out = yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True)
    try:
        coll = SigmaCollection.from_yaml(out)
    except Exception as e:
        raise TryError(ERRORS["sigma"].format(msg=" ".join(str(e).split())[:200]))
    fields = set()
    for r in coll.rules:
        if isinstance(r, SigmaRule):
            fields |= _rule_fields(r)
    return out, fields


def load(text, columns):
    """The rule(s) as the real detectors load them: (rules, fields read). Raises TryError."""
    from engine import detect
    from engine.store import SYSMON_FIELDS
    prepared, fields = prepare_text(text)
    known = {c.lower() for c in columns} | {f.lower() for f in SYSMON_FIELDS} | {k.lower() for k in detect.FIELD_MAP}
    unknown = sorted(f for f in fields if f.lower() not in known)
    if unknown:
        raise TryError(ERRORS["fields"].format(fields=", ".join(unknown[:8])))
    folder = tempfile.mkdtemp(prefix="analystlab-sandbox-")      # outside the project; deleted below
    try:
        path = os.path.join(folder, "rule.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(prepared)
        rules, skipped, failures = detect.load_rules([path], source="sigma")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    if failures:
        msg = failures[0][1]
        raise TryError(ERRORS["sigma"].format(msg=" ".join(str(msg).split())[:200]))
    if not rules:
        if skipped:
            raise TryError(ERRORS["skipped"].format(cats=", ".join(sorted(detect.CATEGORY_EVENT_ID))))
        raise TryError(ERRORS["no_rule"])
    if any("REGEXP" in q.upper() for r in rules for q in r.queries):
        raise TryError(ERRORS["regex"])
    return rules, fields


def run(ctx, rules, fields, time_limit=TIME_LIMIT_S, runs=None, kinds=None, names=None):
    """Try loaded rules over the lab's read-only connection (test machine only). Returns the answer dict."""
    from engine import detect
    from engine.alerts import LEVELS
    deadline = time.monotonic() + time_limit
    stopped = {"yes": False}

    def handler():                                   # keeps aborting once the time is up (every later pass too)
        if time.monotonic() > deadline:
            stopped["yes"] = True
            return 1
        return 0

    try:
        with ctx.reading() as con:
            con.set_progress_handler(handler, 20000)
            timings = {}
            alerts = detect.detect(con, rules, "informational", timings)
            if stopped["yes"]:
                raise TryError(ERRORS["stopped"].format(secs=time_limit))
            errors = timings.get("_errors") or []
            if errors and not alerts:
                raise TryError(ERRORS["failed"].format(msg=" ".join(str(errors[0][1]).split())[:200]))
            keys = sorted({k for a in alerts for k in a.evidence})
            cols = [c[1] for c in con.execute("PRAGMA table_info(events)")]
            have = {c.lower() for c in cols}
            when_col = "COALESCE(UtcTime, time)" if "utctime" in have else "time"
            rows = {}                                     # every match: only what places it in a run
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                for key, host, when in con.execute(f"SELECT dedup_key, host, {when_col} FROM events WHERE dedup_key IN "
                                                   f"({','.join('?' * len(part))})", part):
                    rows[key] = {"host": host, "when": when}
            full = {}                                     # the sample: whole records
            first = []
            for rule in rules:
                first += sorted({k for a in alerts if a.rule_id == rule.rule_id for k in a.evidence})[:SAMPLE]
            for i in range(0, len(first), 500):
                part = first[i:i + 500]
                cur = con.execute(f"SELECT * FROM events WHERE dedup_key IN ({','.join('?' * len(part))})", part)
                names_ = [d[0] for d in cur.description]
                for row in cur:
                    d = dict(zip(names_, row))
                    full[d["dedup_key"]] = d
            if stopped["yes"]:
                raise TryError(ERRORS["stopped"].format(secs=time_limit))
            con.set_progress_handler(None, 0)
    except FileNotFoundError:
        raise TryError(ERRORS["store"])
    runs = run_log(getattr(ctx, "recordings", None)) if runs is None else runs
    index = RunIndex(runs)
    kinds = scenario_kinds() if kinds is None else kinds
    if names is None:
        from engine.labs._names import run_names
        names = run_names()
    floor = ctx.min_level()
    out_rules = []
    for rule in rules:
        mine = [a for a in alerts if a.rule_id == rule.rule_id]
        declared = [a for a in mine if (a.details or {}).get("derived_from")]
        rkeys = sorted({k for a in mine for k in a.evidence})
        by_run, outside = {}, 0
        for n, k in enumerate(rkeys):
            if n % 500 == 0 and time.monotonic() > deadline:      # the Python side keeps to the same limit
                raise TryError(ERRORS["stopped"].format(secs=time_limit))
            r = rows.get(k)
            if r is None:
                continue
            hit = index.find(r["host"], r["when"])
            if hit is None:
                outside += 1
                continue
            e = by_run.setdefault(hit["run_id"], {"run_id": hit["run_id"], "scenario": hit["scenario"], "records": 0})
            e["records"] += 1
        scen = {}
        for e in by_run.values():
            s = scen.setdefault(e["scenario"], {"scenario": e["scenario"], "runs": 0, "records": 0,
                                                "kind": kinds.get(e["scenario"] or ""),
                                                "name": _name(e["scenario"], names)})
            s["runs"] += 1
            s["records"] += e["records"]
        warnings = [WORDS[f"warn_{s['kind']}"].format(name=s["name"], runs=s["runs"], records=s["records"])
                    for s in scen.values() if s["kind"] in ("innocent", "control", "baseline")]
        sample = []
        for k in rkeys[:SAMPLE]:
            r = full.get(k)
            if r is None:
                continue
            read = {f.lower() for f in fields}
            shown = [c for c in cols if c.lower() in read] + [c for c in CONTEXT_FIELDS if c in r and c.lower() not in read]
            sample.append({"time": r.get("UtcTime") or r.get("time"), "event_id": r.get("event_id"),
                           "fields": [{"field": c, "value": _short(r.get(c)), "read": c.lower() in read}
                                      for c in shown if r.get(c) not in (None, "")]})
        out_rules.append({
            "id": rule.rule_id, "title": rule.title, "level": rule.level, "correlation": rule.correlation,
            "raised": LEVELS.index(rule.level) >= LEVELS.index(floor),
            "level_line": (WORDS["raised"] if LEVELS.index(rule.level) >= LEVELS.index(floor) else WORDS["stored"]).format(level=rule.level, floor=floor),
            "alerts": len(mine), "records": len(rkeys), "declared": len(declared),
            "windows": len(mine) if rule.correlation else None,
            "runs": sorted(by_run.values(), key=lambda e: e["run_id"]), "outside": outside,
            "scenarios": sorted(scen.values(), key=lambda s: str(s["scenario"])),
            "warnings": warnings, "sample": sample, "fields": sorted(fields),
        })
    return {"rules": out_rules, "errors": [f"{rid}: {msg}" for rid, msg in (timings.get("_errors") or [])][:5]}


def _name(scenario, names):
    if not scenario:
        return WORDS["unnamed"]
    t = names.get(scenario.lower())
    return f"{scenario} · {t}" if t else f"{scenario} · {WORDS['unnamed']}"


def _short(v):
    s = "" if v is None else str(v)
    return s if len(s) <= VALUE_CHARS else s[:VALUE_CHARS] + "…"


# --- starting points ----------------------------------------------------------------------------------------------
def _community_index():
    from engine import detect
    if "community" not in _cache:
        idx = {}
        for p in glob.glob(os.path.join(detect.COMMUNITY_RULES, "**", "*.yml"), recursive=True):
            idx.setdefault(os.path.basename(p).lower(), p)
        _cache["community"] = idx
    return _cache["community"]


def starting_points(ctx):
    """{key: {key, title, source, path}}: our own Sigma rules, and the community rules that raised an alert in
    this recording (their file found by name in the pinned SigmaHQ folder). Served by key, never by path."""
    from engine import detect
    import yaml
    out = {}
    for p in sorted(glob.glob(os.path.join(detect.OWN_RULES, "**", "*.yml"), recursive=True)):
        try:
            with open(p, encoding="utf-8") as f:
                doc = next(d for d in yaml.safe_load_all(f) if isinstance(d, dict))
        except Exception:
            continue
        key = f"analystlab.{doc.get('name') or os.path.splitext(os.path.basename(p))[0]}"
        out[key] = {"key": key, "title": doc.get("title") or key, "source": "Analyst Lab rule", "path": p}
    try:
        alerts = ctx.alerts()
    except Exception:
        alerts = []
    idx = _community_index() if any(a.source == "sigma" for a in alerts) else {}
    for a in alerts:
        f = ((a.details or {}).get("rule_file") or "").lower()
        if a.source == "sigma" and f in idx and a.rule_id not in out:
            out[a.rule_id] = {"key": a.rule_id, "title": a.title, "source": "community Sigma rule that fired here", "path": idx[f]}
    return out


# --- routes ---------------------------------------------------------------------------------------------------------
@router.get("")
def overview():
    from engine import detect
    ctx = labs.context()
    points = starting_points(ctx)
    return {"words": WORDS, "limits": {"seconds": TIME_LIMIT_S, "chars": MAX_TEXT, "sample": SAMPLE},
            "categories": sorted(detect.CATEGORY_EVENT_ID),
            "starting": [{k: v for k, v in p.items() if k != "path"} for p in points.values()]}


@router.get("/rule/{key}")
def rule_text(key: str):
    p = starting_points(labs.context()).get(key)
    if not p:
        raise HTTPException(status_code=404, detail="No such starting rule.")
    with open(p["path"], encoding="utf-8") as f:
        return {"key": key, "title": p["title"], "yaml": f.read()}


@router.post("/try")
def try_it(body: Attempt):
    ctx = labs.context()
    if not _lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail=ERRORS["busy"])
    try:
        try:
            with ctx.reading() as con:
                columns = [c[1] for c in con.execute("PRAGMA table_info(events)")]
        except FileNotFoundError:
            raise HTTPException(status_code=422, detail=ERRORS["store"])
        try:
            rules, fields = load(body.yaml, columns)
            return run(ctx, rules, fields)
        except TryError as e:
            raise HTTPException(status_code=422, detail=str(e))
    finally:
        _lock.release()
