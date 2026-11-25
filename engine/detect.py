"""Detection engine (package A, DESIGN 4.6): run Sigma rules over the event store, write alerts.

    python -m engine.detect --db recordings/scratch/dev/dev-vm.db --alerts out-alerts.db
    python -m engine.detect --db ... --rules <folder> --source analystlab

Sigma only: every detector together (Sigma, our own Python rules, the check-in rhythm rule) is
engine/score.py, which the live loop also uses.

Sigma rules (community rules at the pinned commit, tools/fetch_sigma_rules.ps1, and our own in
rules/analystlab/ when that folder exists: today our own rules are Python, engine/own_rules.py)
are converted to SQL by pySigma 2.0.1 + the SQLite backend 2.1.1, with our
small processing pipeline (Sigma category -> Sysmon event id; pysigma-pipeline-sysmon would do
the same but needs pySigma 1.x). Only rules for `product: windows` in a category we record are
used; every converted query is checked to really carry its event-id condition. The queries run
against a temporary view `logs` over the event store that:
  - holds only Sysmon events, never our own tools (origin 'project') or paused skeleton rows;
  - compares text case-insensitively, as Sigma requires (the backend writes plain '=', which
    is case-sensitive in SQLite). SQLite's NOCASE folds only A-Z: 'Ä' vs 'ä' still differ
    (a stated limitation; Windows paths in our data are almost all ASCII);
  - gives correlation rules `rowid`, and `timestamp` = when the event HAPPENED (Sysmon's
    UtcTime), not when it was logged: Sysmon logs network events seconds late, which would
    otherwise break "A, then B" sequences (review 2026-10-22).
REGEXP is supplied as a Python function. The store is only read (dev snapshots are read-only).

Simple rules give one alert per matching event. Correlation rules (event_count, value_count,
temporal, temporal_ordered) run per computer (DESIGN 4.4: times are never compared across
machines); the backend reports one row per qualifying window, and overlapping windows of the same
rule and group are merged into ONE alert (one burst = one alert), with every event as evidence.
All alert times are written as YYYY-MM-DDTHH:MM:SS.fffZ. Alerts go to their own database
(engine/alerts.py).

Declared registry writes (v4 F7, engine/regcmd.py): Sysmon here records registry events only for
autostart places, so `reg add <key> ...` elsewhere leaves only reg.exe's process start. After the
normal pass, the simple registry rules run a SECOND time over a temporary table of the registry
events those command lines DECLARE (in Sysmon's spelling). Such a row is never stored and never a
graph fact; its alert cites the reg.exe start, says the write was declared (it may have failed) and
carries details.derived_from = "command_line". A reg.exe process that has a recorded registry
event is left to that real event. Correlation rules never see declared rows. Switch:
config/frozen.yaml declared_registry.reg_command.

Limits: a correlation rule must be in the same file as its base rules. `after_id` (for the live
loop) narrows only simple rules; correlation rules always see the whole store (their windows need
history), and repeats are harmless because alert ids are stable.

Community rules are under the Detection Rule License 1.1: each alert keeps the rule's author.
"""

import argparse
import functools
import glob
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
from sigma.rule import SigmaRule

from . import pscmd, regcmd
from .alerts import LEVELS, Alert, AlertStore
from .graph import parse_time
from .store import SYSMON_FIELDS

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMUNITY_RULES = os.path.join(PROJECT_ROOT, "downloads", "sigma", "rules", "windows")
OWN_RULES = os.path.join(PROJECT_ROOT, "rules", "analystlab")
# v4 (F6): Sigma FILTER documents (Sigma's own format for excluding known-good activity from rules we
# don't own, pySigma SigmaFilter), applied to the rules they name; the SigmaHQ files stay untouched.
FILTER_RULES = os.path.join(PROJECT_ROOT, "rules", "filters")
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sigma log categories we record -> Sysmon event id(s) (Sysmon schema 4.91, our config v0.3).
# Registry (v0.3, autostart places only): 12 = key created/deleted, 13 = value set, 14 = renamed;
# Sigma's registry_event means any of them (SigmaHQ's Sysmon taxonomy).
# file_delete -> 26 on purpose: SigmaHQ's pipeline maps it to 23 (FileDelete, which ARCHIVES every deleted
# file); our config turns 23 off and records 26 (FileDeleteDetected, the same deletion, nothing kept).
CATEGORY_EVENT_ID = {
    "process_creation": 1, "network_connection": 3, "process_termination": 5,
    "file_event": 11, "create_stream_hash": 15, "dns_query": 22, "file_delete": 26,
    "registry_add": 12, "registry_delete": 12, "registry_set": 13, "registry_rename": 14,
    "registry_event": (12, 13, 14),
}
# v4 F8: log categories we do NOT record, whose rules see only DECLARED rows (never the store):
# ps_script = PowerShell's script block log (Microsoft-Windows-PowerShell/Operational, event 4104).
DECLARED_CATEGORY_EVENT_ID = {"ps_script": 4104}
SCRIPT_EVENT_ID = 4104


# v4 (found 2026-11-17): the extra conditions SigmaHQ's own Sysmon pipeline adds (pySigma-pipeline-sysmon,
# sysmon_generic_logsource_additional_conditions): event 12 holds key creation AND deletion, so the two
# categories also need EventType. Before, a "key deleted" rule could fire on a key being created.
CATEGORY_CONDITIONS = {"registry_add": {"EventType": "CreateKey"},
                       "registry_delete": {"EventType": ["DeleteKey", "DeleteValue"]}}


def _ids(category):
    eid = CATEGORY_EVENT_ID.get(category, DECLARED_CATEGORY_EVENT_ID.get(category))
    return list(eid) if isinstance(eid, tuple) else [eid]
FIELD_MAP = {"EventID": "event_id", "Provider_Name": "provider"}


def sysmon_pipeline() -> ProcessingPipeline:
    items = [ProcessingItem(identifier=f"analystlab_sysmon_{cat}",
                            transformation=AddConditionTransformation({"EventID": eid if isinstance(eid, int) else list(eid),
                                                                       **CATEGORY_CONDITIONS.get(cat, {})}),
                            rule_conditions=[LogsourceCondition(category=cat, product="windows")])
             for cat, eid in {**CATEGORY_EVENT_ID, **DECLARED_CATEGORY_EVENT_ID}.items()]
    items.append(ProcessingItem(identifier="analystlab_fields", transformation=FieldMappingTransformation(FIELD_MAP)))
    return ProcessingPipeline(name="Analyst Lab Sysmon", priority=20, items=items)


@dataclass
class Rule:
    rule_id: str
    title: str
    level: str
    source: str               # "sigma" (community) or "analystlab" (ours)
    path: str
    queries: list
    correlation: bool = False
    author: str = ""
    status: str = ""
    description: str = ""
    tags: list = field(default_factory=list)
    categories: tuple = ()    # the Sigma log categories of its base rule(s), e.g. ("registry_set",)

    @property
    def registry(self) -> bool:
        """A simple rule that reads registry events (the rules offered declared writes, v4 F7)."""
        return not self.correlation and any(str(c).startswith("registry_") for c in self.categories)

    @property
    def declared_only(self) -> bool:
        """A rule for a log we do not record (v4 F8): it never runs over the store, only over declared rows."""
        return any(c in DECLARED_CATEGORY_EVENT_ID for c in self.categories)

    @property
    def script(self) -> bool:
        """A simple PowerShell script rule (ps_script): offered the code declared on command lines (v4 F8)."""
        return not self.correlation and "ps_script" in self.categories


def _level(rule) -> str:
    lvl = getattr(rule, "level", None)
    name = lvl.name.lower() if lvl is not None else "informational"
    return name if name in LEVELS else "informational"


def _rule_files(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "**", "*.yml"), recursive=True)))
        else:
            out.append(p)
    return out


def _ours(logsource) -> bool:
    return (logsource.category in CATEGORY_EVENT_ID or logsource.category in DECLARED_CATEGORY_EVENT_ID) \
        and logsource.product == "windows"


def _base_rules(rule):
    """The base (single-event) rules a correlation is built on, recursively."""
    out = []
    for ref in rule.rules:
        r = ref.rule
        out.extend(_base_rules(r) if isinstance(r, SigmaCorrelationRule) else [r])
    return out


def load_filters(folder=FILTER_RULES) -> list:
    """Our Sigma filter documents (rules/filters/*.yml) as pySigma SigmaFilter objects."""
    out = []
    for path in _rule_files([folder]) if os.path.isdir(folder) else []:
        try:
            with open(path, encoding="utf-8") as f:
                found = SigmaCollection.from_yaml(f.read(), collect_filters=True).filters
        except Exception as e:                       # loud and named, never a half-filtered rule set
            raise ValueError(f"filter file {os.path.basename(path)}: {type(e).__name__}: {e}") from e
        if not found:
            raise ValueError(f"filter file {os.path.basename(path)} holds no Sigma filter")
        out.extend(found)
    return out


def _unmatched_filters(filters, rule_ids) -> list:
    """(title, missing ids) of filters naming a rule that was not loaded: such a filter would silently
    do nothing (e.g. after a SigmaHQ update renames or drops the rule), so it is reported."""
    out = []
    for f in filters:
        missing = [str(r.reference) for r in f.filter.rules if str(r.reference) not in rule_ids]
        if missing:
            out.append((f.title, missing))
    return out


def load_rules(paths, source="sigma", filters=None):
    """Convert every rule file under `paths`. Returns (rules, skipped, failures):
    skipped = files with no rule for a Windows category we record (a count, not an error);
    failures = [(path, error)] for files in our categories that didn't convert.
    filters: SigmaFilter list applied to the rules they name (default: rules/filters/, v4 F6)."""
    backend = sqliteBackend(sysmon_pipeline())
    filters = load_filters() if filters is None else filters
    rules, skipped, failures, seen = [], 0, [], set()
    for path in _rule_files(paths):
        try:
            with open(path, encoding="utf-8") as f:
                collection = SigmaCollection.from_yaml(f.read())
            collection.resolve_rule_references()
            if filters:
                collection.apply_filters(filters)
        except Exception as e:                       # malformed YAML / Sigma, missing base rule
            failures.append((path, f"{type(e).__name__}: {e}"))
            continue
        base = [r for r in collection.rules if isinstance(r, SigmaRule)]
        if base and not any(_ours(r.logsource) for r in base):
            skipped += 1
            continue
        for r in collection.rules:
            correlation = isinstance(r, SigmaCorrelationRule)
            parts = _base_rules(r) if correlation else [r]
            if not all(_ours(b.logsource) for b in parts):
                if correlation:
                    failures.append((path, f"correlation '{r.title}' uses a rule outside our Windows categories"))
                continue
            if correlation and any(b.logsource.category in DECLARED_CATEGORY_EVENT_ID for b in parts):
                failures.append((path, f"correlation '{r.title}' uses a log we do not record (declared rows are "
                                       "never correlated)"))
                continue
            try:
                if correlation:
                    queries = backend.convert_correlation_rule(r, backend.default_format)
                else:
                    queries = backend.convert_rule(r, backend.default_format)
                queries = backend.finalize(queries, backend.default_format)
            except Exception as e:
                failures.append((path, f"{type(e).__name__}: {e}"))
                continue
            if not queries:                          # a base rule used only inside a correlation
                continue
            needed = {f"event_id={i}" for b in parts for i in _ids(b.logsource.category)}
            if not all(all(n in q for n in needed) for q in queries):
                failures.append((path, "converted query lacks its event-id condition"))
                continue
            if source == "analystlab":
                if not r.name:
                    failures.append((path, "own rules need a name (rule id 'analystlab.<name>')"))
                    continue
                rid = f"analystlab.{r.name}"
            else:
                rid = str(r.id) if r.id else None
            if not rid:
                failures.append((path, "rule has no id"))
                continue
            if rid in seen:
                failures.append((path, f"duplicate rule id {rid}"))
                continue
            seen.add(rid)
            rules.append(Rule(rid, r.title, _level(r), source, path, list(queries), correlation,
                              author=r.author or "", status=str(r.status.name.lower()) if r.status else "",
                              description=(r.description or "").strip(),
                              tags=[str(t) for t in (r.tags or [])],
                              categories=tuple(sorted({b.logsource.category for b in parts}))))
    full_community = source == "sigma" and [os.path.abspath(p) for p in paths] == [os.path.abspath(COMMUNITY_RULES)]
    if filters and full_community:                   # only a full load can tell "the rule is gone"
        for title, missing in _unmatched_filters(filters, seen):
            failures.append((FILTER_RULES, f"filter '{title}' names rule(s) that were not loaded: {', '.join(missing)}"))
    return rules, skipped, failures


@functools.lru_cache(maxsize=4096)
def _compiled(pattern):
    return re.compile(pattern)


def _regexp(pattern, value):
    if value is None:
        return False
    try:
        return _compiled(pattern).search(str(value)) is not None
    except re.error:
        return False


def prepare(con: sqlite3.Connection, after_id: int = None, host: str = None):
    """(Re)create REGEXP and the temporary `logs` view (see the module docstring) on a store
    connection. after_id: only events stored after that row id; host: only that computer."""
    con.create_function("REGEXP", 2, _regexp, deterministic=True)
    cols = con.execute("PRAGMA table_info(events)").fetchall()
    if not cols:
        raise ValueError("no events table in this database")
    parts = ["id AS rowid", "COALESCE(UtcTime, time) AS timestamp"]
    for _, name, ctype, *_ in cols:
        q = '"' + name.replace('"', '""') + '"'
        parts.append(f"{q} COLLATE NOCASE AS {q}" if ctype.upper() == "TEXT" else q)
    have = {c[1].lower() for c in cols}
    # a store made before a field joined SYSMON_FIELDS (e.g. registry fields, config v0.3) has
    # no column for it: an empty one, so its rules find nothing instead of failing
    parts.extend(f'NULL AS "{f}"' for f in SYSMON_FIELDS if f.lower() not in have)
    where = [f"channel = '{SYSMON_CHANNEL}'", "COALESCE(origin, '') <> 'project'", "COALESCE(paused, 0) = 0"]
    if after_id is not None:
        where.append(f"id > {int(after_id)}")
    if host is not None:
        where.append("host = '" + str(host).replace("'", "''") + "'")
    con.execute("DROP VIEW IF EXISTS temp.logs")
    con.execute(f"CREATE TEMP VIEW logs AS SELECT {', '.join(parts)} FROM events WHERE {' AND '.join(where)}")


# -- declared registry writes (v4 F7) ------------------------------------------------------------------
DERIVED_FROM = "command_line"
# what a declared row keeps of the reg.exe process start it was read from. A real Sysmon registry event
# has exactly: RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image, TargetObject, Details, User;
# RuleName is NOT copied (it would be the name of a process-creation config rule, not a registry one),
# and neither is anything else of the process start (CommandLine, ParentImage, ...).
_DECLARED_COPY = ("host", "label", "session", "source", "channel", "record_id", "seq", "type", "provider", "time",
                  "origin", "origin_recorded", "paused", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User")
# registry rows fill EventType/TargetObject/Details (F7); script rows ScriptBlockText and Path (F8: a real
# 4104 of inline code has an EMPTY Path, so '' as there; the backend's NOT is NULL-safe anyway, COALESCE)
_DECLARED_SET = ("event_id", "EventType", "TargetObject", "Details", "ScriptBlockText", "Path")
_REGISTRY_IDS = (12, 13, 14)
DECLARED_TEXT_SHOWN = 2000            # characters of declared code kept in an alert's details (the start cites all)
_DECLARED_TYPES = {"record_id": "INTEGER", "seq": "INTEGER", "paused": "INTEGER", "event_id": "INTEGER",
                   "ProcessId": "NUMERIC"}            # everything else TEXT, exactly as the event store
_DECLARED_NEEDS = {"commandline", "image", "processguid", "channel", "host", "event_id", "dedup_key"}
_VISIBLE = (f"channel = '{SYSMON_CHANNEL}'", "COALESCE(origin, '') <> 'project'", "COALESCE(paused, 0) = 0")


def _declared_rows(command_line, image, original_name) -> list:
    """The events one process start declares: registry events for reg.exe (F7), one script block for
    powershell.exe (F8), else none."""
    if regcmd.is_reg(image, original_name):
        return regcmd.declared(command_line, image)
    if pscmd.is_powershell(image, original_name):
        text = pscmd.script_text(command_line)
        return [] if text is None else [{"event_id": SCRIPT_EVENT_ID, "ScriptBlockText": text, "Path": ""}]
    return []


def _declare(con, have, after_id=None, problems=None) -> bool:
    """Bring temp.declared_events up to date with the store: one row per event a process start
    declares (registry events of reg.exe, engine/regcmd.py; the script block of powershell.exe,
    engine/pscmd.py), carrying that start's id, dedup_key, host, time and process fields. Per connection, every event is read once: the table remembers the id range it
    covers, and a fresh connection that only looks after `after_id` (the live loop opens one per
    tick) starts there instead of re-reading the whole store. A command line that cannot be read is
    skipped and counted in `problems`, never fatal. False when this store cannot carry declared
    rows (a hand-made table without the needed columns)."""
    if not _DECLARED_NEEDS <= have:
        return False
    copy = [c for c in _DECLARED_COPY if c.lower() in have]
    typed = ", ".join(f'"{c}" {_DECLARED_TYPES.get(c, "TEXT")}' for c in (*_DECLARED_COPY, *_DECLARED_SET))
    con.execute(f"CREATE TEMP TABLE IF NOT EXISTS declared_events (id INTEGER, dedup_key TEXT, {typed})")
    con.execute("CREATE TEMP TABLE IF NOT EXISTS declared_state (low INTEGER NOT NULL, upto INTEGER NOT NULL)")
    row = con.execute("SELECT low, upto FROM temp.declared_state").fetchone()
    want = max(int(after_id or 0), 0)
    low, upto = row if row else (want, want)
    top = max(con.execute("SELECT MAX(id) FROM events").fetchone()[0] or 0, upto)
    spans = [s for s in ((want, low), (upto, top)) if s[0] < s[1]]     # (from, to]: not covered yet
    if not spans:
        return True
    original = '"OriginalFileName"' if "originalfilename" in have else "NULL"
    rows, skipped = [], []
    for lo, hi in spans:
        found = con.execute(
            f'SELECT id, dedup_key, "CommandLine", "Image", {original}, {", ".join(chr(34) + c + chr(34) for c in copy)} '
            f'FROM events WHERE event_id = 1 AND id > ? AND id <= ? AND channel = ? '
            f'AND ("Image" LIKE ? OR {original} LIKE ? OR "Image" LIKE ? OR {original} LIKE ?)',
            (lo, hi, SYSMON_CHANNEL, "%reg.exe", "reg.exe", "%powershell.exe", "powershell.exe")).fetchall()
        for id_, key, command_line, image, original_name, *kept in found:
            try:
                events = _declared_rows(command_line, image, original_name)
            except Exception as e:                   # one unreadable command line must not switch the pass off
                skipped.append(f"{type(e).__name__}: {e}")
                continue
            for ev in events:
                rows.append((id_, key, *kept, *(ev.get(c) for c in _DECLARED_SET)))
    mine = not con.in_transaction                    # never commit a caller's own open transaction
    names = ["id", "dedup_key", *(f'"{c}"' for c in (*copy, *_DECLARED_SET))]
    con.executemany(f"INSERT INTO temp.declared_events ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})", rows)
    con.execute("DELETE FROM temp.declared_state")
    con.execute("INSERT INTO temp.declared_state VALUES (?, ?)", (min(low, want), top))
    if mine:
        con.commit()                                 # or this connection would stop seeing new events (live loop)
    if skipped and problems is not None:
        problems.append(f"{len(skipped)} command line(s) could not be read and were skipped ({skipped[0][:100]})")
    return True


def prepare_declared(con: sqlite3.Connection, after_id: int = None, problems: list = None) -> int:
    """Point the temporary `logs` view at the DECLARED registry events only (see the module
    docstring), with the same columns and filters as `prepare`; returns how many rows it shows (0
    also when the store cannot carry them). A reg.exe process that has a recorded registry event
    the rules can see is left out: Sysmon was watching that key, the real event speaks. Every other
    column of a real process start (CommandLine, ParentImage, RuleName, ...) is empty, as on a real
    registry event. Call `prepare` afterwards."""
    con.create_function("REGEXP", 2, _regexp, deterministic=True)
    cols = con.execute("PRAGMA table_info(events)").fetchall()
    have = {c[1].lower() for c in cols}
    if not cols or not _declare(con, have, after_id, problems):
        return 0
    mine = {c.lower() for c in (*_DECLARED_COPY, *_DECLARED_SET)} | {"id", "dedup_key"}
    parts = ["id AS rowid", "COALESCE(UtcTime, time) AS timestamp"]
    for _, name, ctype, *_ in cols:
        q = '"' + name.replace('"', '""') + '"'
        if name.lower() not in mine:
            parts.append(f"NULL AS {q}")
        else:
            parts.append(f"{q} COLLATE NOCASE AS {q}" if ctype.upper() == "TEXT" else q)
    # a store made before the registry fields existed (Sysmon config < v0.3) has no column for them:
    # the declared table always does
    parts.extend(f'"{f}" COLLATE NOCASE AS "{f}"' for f in _DECLARED_SET if f.lower() not in have)
    parts.extend(f'NULL AS "{f}"' for f in SYSMON_FIELDS if f.lower() not in have and f not in _DECLARED_SET)
    seen_for_real = " AND ".join(["e.event_id IN (12, 13, 14)", f"e.channel = '{SYSMON_CHANNEL}'"]
                                 + [f"COALESCE(e.{c}, {d}) {op}" for c, d, op in (("origin", "''", "<> 'project'"), ("paused", "0", "= 0"))
                                    if c in have])
    # the shadow is for REGISTRY rows only: a PowerShell process that also wrote a recorded registry
    # value keeps its declared script block (we never record script blocks, so nothing shadows those)
    where = [*_VISIBLE, f'(d.event_id NOT IN {_REGISTRY_IDS} OR NOT EXISTS (SELECT 1 FROM events AS e '
                        f'WHERE e."ProcessGuid" = d."ProcessGuid" AND e.host IS d.host AND {seen_for_real}))']
    if after_id is not None:
        where.append(f"id > {int(after_id)}")
    con.execute("DROP VIEW IF EXISTS temp.logs")
    con.execute(f"CREATE TEMP VIEW logs AS SELECT {', '.join(parts)} FROM temp.declared_events AS d WHERE {' AND '.join(where)}")
    return con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]


def open_store(path: str, read_only: bool = True) -> sqlite3.Connection:
    if read_only:
        con = sqlite3.connect("file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro", uri=True)
    else:
        con = sqlite3.connect(path)
    prepare(con)
    return con


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _from_epoch(seconds) -> str:
    return iso(datetime.fromtimestamp(float(seconds), timezone.utc))


def _reason(rule: Rule) -> str:
    who = f", by {rule.author}" if rule.author and rule.source == "sigma" else ""
    kind = "community Sigma rule" if rule.source == "sigma" else "Analyst Lab rule"
    return f"Matched the {kind} \"{rule.title}\" (level {rule.level}{who})"


def _simple_alerts(con, rule, untimed=None, declared=False):
    """One alert per matching event. declared=True (the caller pointed `logs` at the declared view,
    prepare_declared, v4 F7): a match is a registry change read from a reg.exe command line; the
    alert cites that process start (event 1), says so, and is raised once per start however many
    candidate spellings matched. Whether a row is declared is the CALLER's knowledge, never a field
    of the row (a recorded event cannot pose as declared, nor the reverse)."""
    out, declared_seen = [], set()
    for q in rule.queries:
        cur = con.execute(q)
        names = [d[0] for d in cur.description]
        for row in cur:
            d = dict(zip(names, row))
            when = parse_time(d.get("UtcTime")) or parse_time(d["time"])
            if when is None:                    # skip just this event (a forged or broken record
                if untimed is not None:         # must not hide the rule's other alerts): counted
                    untimed.append((rule.rule_id, d["dedup_key"]))
                continue
            details = {"event_id": d.get("event_id"), "author": rule.author, "rule_file": os.path.basename(rule.path)}
            reason = _reason(rule) + "."
            if declared:
                if d["dedup_key"] in declared_seen:
                    continue
                declared_seen.add(d["dedup_key"])
                if d.get("event_id") == SCRIPT_EVENT_ID:
                    text = str(d.get("ScriptBlockText") or "")
                    shown = {"event_id": SCRIPT_EVENT_ID, "ScriptBlockText": text[:DECLARED_TEXT_SHOWN],
                             "length": len(text)}
                    reason = (_reason(rule) + ": the PowerShell code was read from powershell.exe's command line "
                              "(declared, not recorded: it may not have run).")
                else:
                    shown = {"event_id": d.get("event_id"), "EventType": d.get("EventType"),
                             "TargetObject": d.get("TargetObject"), "Details": d.get("Details")}
                    reason = (_reason(rule) + ": the registry change was read from reg.exe's command line "
                              "(declared, not recorded: it may have failed).")
                details.update({"event_id": 1, "derived_from": DERIVED_FROM, "declared": shown})
            out.append(Alert(rule.rule_id, rule.title, rule.source, rule.level, iso(when), d.get("host") or "",
                             reason, (d["dedup_key"],), details))
    return out


def _windows(con, rule):
    """The backend's qualifying windows for one correlation rule: dicts with group, start, end,
    occurrence, metric, value, rowids."""
    out = []
    for q in rule.queries:
        cur = con.execute(q)
        names = [d[0] for d in cur.description]
        for row in cur:
            d = dict(zip(names, row))
            rowids = []
            for eid in json.loads(d["event_ids"] or "[]"):
                m = re.fullmatch(r"(?:e:)?\d+:(\d+)", str(eid))
                if not m:
                    raise ValueError(f"unreadable correlation event id {eid!r}")
                rowids.append(int(m.group(1)))
            out.append({"group": d["group_keys"] or "{}", "start": float(d["window_start"]),
                        "end": float(d["window_end"]), "occurrence": float(d["occurrence_time"]),
                        "metric": d["metric_name"], "value": d["metric_value"], "rowids": rowids})
    return out


def _merge(windows):
    """Overlapping windows of the same group -> one (one burst = one alert)."""
    merged = []
    for w in sorted(windows, key=lambda w: (w["group"], w["start"], w["end"])):
        last = merged[-1] if merged else None
        if last and last["group"] == w["group"] and w["start"] <= last["end"]:
            last["end"] = max(last["end"], w["end"])
            last["occurrence"] = min(last["occurrence"], w["occurrence"])
            last["rowids"] = sorted(set(last["rowids"]) | set(w["rowids"]))
            if isinstance(w["value"], (int, float)) and isinstance(last["value"], (int, float)):
                last["value"] = max(last["value"], w["value"])
            last["windows"] += 1
        else:
            merged.append(dict(w, rowids=sorted(set(w["rowids"])), windows=1))
    return merged


def _correlation_alerts(con, rule, host):
    out = []
    for w in _merge(_windows(con, rule)):
        if not w["rowids"]:
            raise ValueError(f"correlation window without events in {rule.rule_id}")
        rows = con.execute(f"SELECT dedup_key FROM events WHERE id IN ({','.join('?' * len(w['rowids']))})",
                           w["rowids"]).fetchall()
        keys = tuple(sorted(r[0] for r in rows))
        reason = (f"{_reason(rule)}: {w['metric']} reached {w['value']} between {_from_epoch(w['start'])} and "
                  f"{_from_epoch(w['end'])} ({len(keys)} events).")
        out.append(Alert(rule.rule_id, rule.title, rule.source, rule.level, _from_epoch(w["occurrence"]), host or "",
                         reason, keys, {"group": json.loads(w["group"]), "metric": w["metric"], "value": w["value"],
                                        "window_start": _from_epoch(w["start"]), "window_end": _from_epoch(w["end"]),
                                        "windows_merged": w["windows"], "author": rule.author,
                                        "rule_file": os.path.basename(rule.path)},
                         incident=f"{w['group']}|{w['occurrence']:.3f}"))    # grows live: stays one alert
    return out


def detect(con, rules, min_level="informational", timings=None, after_id=None, declared=None):
    """All alerts from `rules` at or above `min_level`. `timings` (dict) gets seconds per rule;
    a rule that fails (SQL error, unreadable result) is listed in timings["_errors"] and
    skipped, never silently. Rebuilds the `logs` view, so columns added since are included.
    declared: which declared rows the simple rules are also offered: "registry" (registry writes
    declared on reg.exe command lines, v4 F7) and/or "script" (code declared on powershell.exe command
    lines, v4 F8). True = both, False = none, None = config/frozen.yaml (declared_registry,
    declared_script). Rules for logs we do not record (ps_script) run ONLY over declared rows."""
    if declared is None:
        from . import config
        declared = config.declared_kinds()
    kinds = {"registry", "script"} if declared is True else (set() if declared is False else set(declared))
    if kinds - {"registry", "script"}:
        raise ValueError(f"unknown declared kind(s): {sorted(kinds - {'registry', 'script'})}")
    floor = LEVELS.index(min_level)
    chosen = [r for r in rules if LEVELS.index(r.level) >= floor]
    out = []

    untimed = []
    failed = set()

    def problem(who, message):
        if timings is not None:
            timings.setdefault("_errors", []).append((who, message))

    def attempt(rule, fn):
        t0 = time.perf_counter()
        try:
            out.extend(fn())
        except Exception as e:                  # any failure of one rule is reported, never fatal
            failed.add(rule.rule_id)
            if timings is not None:
                timings.setdefault("_errors", []).append((rule.rule_id, f"{type(e).__name__}: {e}"))
            return
        if timings is not None:
            timings[rule.rule_id] = timings.get(rule.rule_id, 0.0) + time.perf_counter() - t0

    prepare(con, after_id=after_id)
    for rule in chosen:
        if not rule.correlation and not rule.declared_only:
            attempt(rule, lambda rule=rule: _simple_alerts(con, rule, untimed))
    offered = [r for r in chosen if (r.registry and "registry" in kinds) or (r.script and "script" in kinds)]
    if offered:
        try:
            problems = []
            try:
                shown = prepare_declared(con, after_id=after_id, problems=problems)
            except Exception as e:              # reported like a failed rule; the normal pass stands
                shown = 0
                problems.append(f"{type(e).__name__}: {e}")
            for message in problems:
                problem("declared", message)
            if shown:
                for rule in offered:
                    if rule.rule_id not in failed:      # already reported by the normal pass: once is enough
                        attempt(rule, lambda rule=rule: _simple_alerts(con, rule, untimed, declared=True))
        finally:
            prepare(con, after_id=after_id)     # `logs` is the real view again, whatever happened
    correlations = [r for r in chosen if r.correlation]
    if correlations:
        hosts = [h for (h,) in con.execute(f"SELECT DISTINCT host FROM events WHERE channel = '{SYSMON_CHANNEL}'")]
        for host in hosts:
            prepare(con, host=host)
            for rule in correlations:
                attempt(rule, lambda rule=rule, host=host: _correlation_alerts(con, rule, host))
        prepare(con, after_id=after_id)
    if untimed and timings is not None:
        timings["_untimed"] = untimed          # matching events skipped for having no readable time
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run Sigma rules over an event store and write alerts (counts printed only)")
    ap.add_argument("--db", required=True, help="event store (opened read-only)")
    ap.add_argument("--alerts", required=True, help="alert database to write")
    ap.add_argument("--rules", nargs="*", help="rule files or folders (default: community + own rules)")
    ap.add_argument("--source", choices=["sigma", "analystlab"], help="with --rules: whose rules these are")
    ap.add_argument("--min-level", default="informational", choices=LEVELS)
    a = ap.parse_args(argv)
    sets = [(a.rules, a.source or "sigma")] if a.rules else [([COMMUNITY_RULES], "sigma"), ([OWN_RULES], "analystlab")]
    rules, failed = [], 0
    for paths, source in sets:
        if not all(os.path.exists(p) for p in paths):
            print(f"no rules at {paths} ({source}): skipped")
            continue
        got, skipped, failures = load_rules(paths, source)
        failed += len(failures)
        print(f"{source}: {len(got)} rules converted, {skipped} files with no rule for what we record, {len(failures)} failed")
        for path, err in failures[:5]:
            print(f"   failed: {os.path.basename(path)}: {err[:120]}")
        rules += got
    con = open_store(a.db)
    timings = {}
    t0 = time.perf_counter()
    alerts = detect(con, rules, a.min_level, timings)
    took = time.perf_counter() - t0
    store = AlertStore(a.alerts)
    new = store.write(alerts, events_db=os.path.abspath(a.db))
    store.close()
    errors = timings.pop("_errors", [])
    untimed = timings.pop("_untimed", [])
    if untimed:
        print(f"skipped {len(untimed)} matching event(s) with no readable time")
    by_level = {lvl: sum(1 for x in alerts if x.level == lvl) for lvl in LEVELS}
    print(f"ran {len(rules)} rules in {took:.1f} s; rule errors: {len(errors)}; alerts: {len(alerts)} ({new} new) {by_level}")
    for rid, err in errors[:5]:
        print(f"   error in {rid}: {err[:120]}")
    slow = sorted(timings.items(), key=lambda kv: -kv[1])[:3]
    print("slowest rules (s):", [(rid[:24], round(s, 2)) for rid, s in slow])
    return 1 if (errors or failed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
