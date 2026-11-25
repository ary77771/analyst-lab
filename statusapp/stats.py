"""Numbers-only statistics from a laptop's recordings (DESIGN 9.1: raw events never leave it).

A friend's laptop keeps its raw recording locally; what it sends is ONE small text file of
counts that the friend reads first. This module makes those counts:

  - how long it recorded: days, active hours (an active minute = a minute with at least one
    normal-use event, as in tools/noise_report.py), minutes paused;
  - how many events of each kind (process start, network connection, ...) in total, per active
    hour, and per active hour one by one (without dates or times), which is what week 3 needs
    to measure how often things happen by chance;
  - what was left out (our own lab tools, pauses) and health (Sysmon numbering complete?).

It never outputs a name, path, address, domain or command line: the export is checked to
have exactly the expected layout, our own fixed labels and bounded numbers before it is written
(check_summary below).
Schema 1; the exact set of numbers is finalised with the week-3 detectors (the raw recording
stays on the laptop, so a later version can recompute from it).

Reading 300 MB a day takes a while, so results are cached per day (<state>/stats-cache.json):
finished (compressed) days are read once, today's file is read on from where it stopped.
"""

import bisect
import json
import os
import sys
import threading
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from agent.control import parse_utc  # noqa: E402
from agent.state import atomic_write_text  # noqa: E402
from engine.jsonl import iter_jsonl, recording_files  # noqa: E402

SCHEMA = 1
CACHE_VERSION = 2          # 2: re-delivered events counted once
EVENT_NAMES = {1: "process starts", 3: "network connections", 4: "Sysmon status changes",
               5: "process ends", 11: "files created (watched kinds)", 15: "download markers",
               16: "Sysmon setting changes", 22: "DNS lookups", 26: "files deleted (watched kinds)"}
TARGET_DAYS = 7
SYSMON = "sysmon"


def _minute(t: str):
    """Minutes since 1970 for a Sysmon-format UTC time, or None."""
    try:
        return int(parse_utc(t).timestamp() // 60)
    except (ValueError, TypeError, AttributeError):
        return None


class Ranges:
    """A set of record numbers kept as sorted [low, high] runs (Sysmon numbers are nearly
    continuous, so a day of 300,000 events is a handful of runs)."""

    def __init__(self, runs=None):
        self.runs = [list(r) for r in (runs or [])]

    def add(self, n: int) -> bool:
        """Add a number; False if it was already there (a re-delivered event)."""
        runs = self.runs
        if runs and runs[-1][1] + 1 == n:            # the usual case: the next number
            runs[-1][1] = n
            return True
        i = bisect.bisect_right(runs, [n, float("inf")])
        if i and runs[i - 1][0] <= n <= runs[i - 1][1]:
            return False                              # seen before (a re-delivery)
        runs.insert(i, [n, n])
        # merge with neighbours that now touch
        if i + 1 < len(runs) and runs[i][1] + 1 >= runs[i + 1][0]:
            runs[i][1] = max(runs[i][1], runs.pop(i + 1)[1])
        if i and runs[i - 1][1] + 1 >= runs[i][0]:
            runs[i - 1][1] = max(runs[i - 1][1], runs.pop(i)[1])
        return True

    def update(self, other: "Ranges") -> None:
        merged = []
        for lo, hi in sorted(self.runs + other.runs):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.runs = merged

    def count(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.runs)

    def missing(self) -> int:
        return sum(b[0] - a[1] - 1 for a, b in zip(self.runs, self.runs[1:]))


class DayStats:
    """Counts from one day's recording file. Mergeable across days."""

    def __init__(self):
        self.signature = None       # (file name, size, mtime) the counts were made from
        self.offset = 0             # bytes of a plain .jsonl already counted (complete lines only)
        self.counts = {}            # event id -> normal-use events
        self.hourly = {}            # hour since 1970 -> {event id -> normal-use events}
        self.minutes = set()        # active minutes (since 1970)
        self.excluded = {"project": 0, "paused": 0}
        self.other_records = 0      # agent records (ports, fingerprints, pauses) and non-Sysmon events
        self.records = Ranges()     # Sysmon record numbers seen
        self.sessions = set()
        self.pauses = {}            # requested -> until (from PAUSE_* records)
        self.bad_lines = 0
        self.bad_files = 0
        self.duplicates = 0

    def feed(self, r: dict) -> None:
        if r.get("session"):
            self.sessions.add(r["session"])
        if r.get("source") == "agent":
            self.other_records += 1
            if str(r.get("type", "")).startswith("PAUSE_"):
                d = r.get("data") or {}
                if d.get("requested") and d.get("until"):
                    self.pauses[d["requested"]] = d["until"]     # a later change (resume) wins
            return
        if r.get("source") != SYSMON:
            self.other_records += 1
            return
        if r.get("record_id") is not None:
            try:
                new = self.records.add(int(r["record_id"]))
            except (TypeError, ValueError):
                new = True
            if not new:
                # the agent re-sends the last batch after a crash or restart: count it once
                # (review 2026-10-19; a re-delivery that crosses midnight lands in the next
                # day's file and is still counted twice: rare, stated as a limitation)
                self.duplicates += 1
                return
        if r.get("paused"):
            self.excluded["paused"] += 1
            return
        if r.get("origin") == "project":
            self.excluded["project"] += 1
            return
        eid = r.get("event_id")
        m = _minute(r.get("time"))
        if not isinstance(eid, int) or eid not in SYSMON_EVENT_IDS or m is None:
            self.other_records += 1
            return
        self.counts[eid] = self.counts.get(eid, 0) + 1
        hour = self.hourly.setdefault(m // 60, {})
        hour[eid] = hour.get(eid, 0) + 1
        self.minutes.add(m)

    # cache form -------------------------------------------------------------------------
    def to_json(self) -> dict:
        return {"signature": self.signature, "offset": self.offset,
                "counts": {str(k): v for k, v in self.counts.items()},
                "hourly": {str(h): {str(k): v for k, v in c.items()} for h, c in self.hourly.items()},
                "minutes": sorted(self.minutes), "excluded": self.excluded,
                "other_records": self.other_records, "records": self.records.runs,
                "sessions": sorted(self.sessions), "pauses": self.pauses,
                "bad_lines": self.bad_lines, "bad_files": self.bad_files, "duplicates": self.duplicates}

    @classmethod
    def from_json(cls, d: dict) -> "DayStats":
        s = cls()
        s.signature = d.get("signature")
        s.offset = d.get("offset", 0)
        s.counts = {int(k): v for k, v in d.get("counts", {}).items()}
        s.hourly = {int(h): {int(k): v for k, v in c.items()} for h, c in d.get("hourly", {}).items()}
        s.minutes = set(d.get("minutes", []))
        s.excluded = dict(d.get("excluded", s.excluded))
        s.other_records = d.get("other_records", 0)
        s.records = Ranges(d.get("records"))
        s.sessions = set(d.get("sessions", []))
        s.pauses = dict(d.get("pauses", {}))
        s.bad_lines, s.bad_files = d.get("bad_lines", 0), d.get("bad_files", 0)
        s.duplicates = d.get("duplicates", 0)
        return s


def _signature(path):
    st = os.stat(path)
    return [os.path.basename(path), st.st_size, int(st.st_mtime)]


CHUNK = 8 * 1024 * 1024


def _read_on(path: str, day: DayStats) -> None:
    """Count the complete lines of a plain .jsonl from day.offset on, 8 MB at a time (a day can
    be 300 MB; review 2026-10-19). The agent may be writing the last line right now: an
    unfinished line is counted next time."""
    with open(path, "rb") as f:
        f.seek(day.offset)
        carry = b""
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            data = carry + block
            end = data.rfind(b"\n") + 1
            for line in data[:end].splitlines():
                if not line.strip():
                    continue
                try:
                    day.feed(json.loads(line))
                except (ValueError, UnicodeDecodeError):
                    day.bad_lines += 1
            day.offset += end
            carry = data[end:]


def update_day(path: str, cached: DayStats = None) -> DayStats:
    """Counts for one recording file, reusing what the cache already counted."""
    sig = _signature(path)
    if cached is not None and cached.signature == sig:
        return cached
    if path.endswith(".jsonl") and cached is not None and cached.signature \
            and cached.signature[0] == sig[0] and cached.signature[1] <= sig[1]:
        day = cached                                  # same file, grown: read on
    else:
        day = DayStats()                              # new, replaced, or now compressed
    if path.endswith(".jsonl"):
        _read_on(path, day)
    else:
        bad = {}
        for r in iter_jsonl(path, bad):
            day.feed(r)
        day.bad_lines, day.bad_files = bad.get("bad_lines", 0), bad.get("bad_files", 0)
    day.signature = sig
    return day


def day_name(path: str) -> str:
    return os.path.basename(path).split(".", 1)[0]


_collect_lock = threading.Lock()      # the window's jobs (progress, export, preview) may overlap


def collect(recordings: str, label: str = "host", cache_dir: str = None) -> dict:
    """{day: DayStats} for every recording day, using and refreshing the cache in cache_dir
    (default: the recorder's state folder; the friend bundle uses its writable control folder)."""
    with _collect_lock:
        return _collect(recordings, label, cache_dir or os.path.join(recordings, ".state", label))


def _collect(recordings, label, state_dir):
    cache_path = os.path.join(state_dir, "stats-cache.json")
    try:
        with open(cache_path, encoding="utf-8") as f:
            raw = json.load(f)
        cache = ({k: DayStats.from_json(v) for k, v in raw.get("days", {}).items()}
                 if raw.get("version") == CACHE_VERSION else {})
    except (OSError, ValueError, AttributeError):
        cache = {}
    days = {}
    for path in recording_files(os.path.join(recordings, label)):
        name = day_name(path)
        days[name] = update_day(path, cache.get(name))
    try:
        os.makedirs(state_dir, exist_ok=True)
        atomic_write_text(cache_path, json.dumps({"version": CACHE_VERSION,
                                                  "days": {k: v.to_json() for k, v in days.items()}}))
    except OSError:
        pass                                          # a cache is a convenience, never required
    return days


def paused_minutes(pauses: dict, now=None) -> int:
    """Total minutes covered by pauses (overlaps counted once), up to now: the rest of a pause
    still running hasn't happened yet."""
    now = now or datetime.now(timezone.utc)
    spans = []
    for start, end in pauses.items():
        try:
            a, b = parse_utc(start), min(parse_utc(end), now)
        except (ValueError, TypeError, AttributeError):
            continue
        if b > a:
            spans.append((a, b))
    total, cur = 0.0, None
    for a, b in sorted(spans):
        if cur and a <= cur[1]:
            cur = (cur[0], max(cur[1], b))
            continue
        if cur:
            total += (cur[1] - cur[0]).total_seconds()
        cur = (a, b)
    if cur:
        total += (cur[1] - cur[0]).total_seconds()
    return round(total / 60)


def summarize(days: dict, selftest: dict = None, now=None) -> dict:
    """The numbers that leave the laptop. Only numbers and fixed text."""
    counts, minutes, hourly, pauses = {}, set(), {}, {}
    excluded = {"project": 0, "paused": 0}
    records, sessions = Ranges(), set()
    bad_lines = bad_files = other = dups = 0
    for d in days.values():
        dups += d.duplicates
        for k, v in d.counts.items():
            counts[k] = counts.get(k, 0) + v
        for h, c in d.hourly.items():
            into = hourly.setdefault(h, {})
            for k, v in c.items():
                into[k] = into.get(k, 0) + v
        minutes |= d.minutes
        for k in excluded:
            excluded[k] += d.excluded.get(k, 0)
        records.update(d.records)
        sessions |= d.sessions
        pauses.update(d.pauses)
        bad_lines, bad_files, other = bad_lines + d.bad_lines, bad_files + d.bad_files, other + d.other_records

    active_hours = len(minutes) / 60
    days_recorded = len({m // 1440 for m in minutes})
    per_hour_minutes = {}
    for m in minutes:
        per_hour_minutes[m // 60] = per_hour_minutes.get(m // 60, 0) + 1
    names = {k: EVENT_LABELS.get(k, f"event type {k}") for k in sorted(counts)}
    return {
        "schema": SCHEMA,
        "days_recorded": days_recorded,
        "target_days": TARGET_DAYS,
        "active_hours": round(active_hours, 1),
        "paused_minutes": paused_minutes(pauses, now),
        "events": {names[k]: counts[k] for k in sorted(counts)},
        "events_per_active_hour": {names[k]: round(counts[k] / active_hours, 1) if active_hours else 0
                                   for k in sorted(counts)},
        # one entry per hour with activity, in order, WITHOUT its date or time
        "hours": [{"active_minutes": per_hour_minutes.get(h, 0),
                   "events": {str(k): v for k, v in sorted(hourly[h].items())}} for h in sorted(hourly)],
        "left_out": {"our own lab tools": excluded["project"], "while paused (counted only)": excluded["paused"]},
        "health": {"sysmon_records": records.count(), "sysmon_records_missing": records.missing(),
                   "recorder_sessions": len(sessions), "damaged_lines": bad_lines,
                   "damaged_files": bad_files, "other_records": other, "re_delivered_skipped": dups},
        "self_test": {"runs": (selftest or {}).get("runs", 0), "last_passed": (selftest or {}).get("last_passed")},
    }


# the export --------------------------------------------------------------------------------
class NotNumbersOnly(ValueError):
    pass


SYSMON_EVENT_IDS = range(1, 30)                  # Sysmon's event types (schema 4.91 has 1-29)
EVENT_LABELS = {k: EVENT_NAMES.get(k, f"event type {k}") for k in SYSMON_EVENT_IDS}
MAX_COUNT = 10**9


def check_summary(s) -> None:
    """The last guard before anything is written for sending: the EXACT layout of summarize()'s
    output, every key at every level from our own fixed lists, every value a bounded number
    (review 2026-10-19: a loose "only our words anywhere" check let e.g. a port number pass as
    a key and an address pass as a big number). Raises NotNumbersOnly."""

    def fail(where):
        raise NotNumbersOnly(f"unexpected content at {where}")

    def keys(d, allowed, where, exact=True):
        if not isinstance(d, dict) or not set(d) <= set(allowed) or (exact and set(d) != set(allowed)):
            fail(where)

    def num(v, hi, where, ints=True):
        ok_type = isinstance(v, int) if ints else isinstance(v, (int, float))
        if isinstance(v, bool) or not ok_type or not 0 <= v <= hi:
            fail(where)

    keys(s, ["schema", "days_recorded", "target_days", "active_hours", "paused_minutes", "events",
             "events_per_active_hour", "hours", "left_out", "health", "self_test"], "top")
    if s["schema"] != SCHEMA or s["target_days"] != TARGET_DAYS:
        fail("schema")
    num(s["days_recorded"], 3660, "days_recorded")
    num(s["active_hours"], 10**5, "active_hours", ints=False)
    num(s["paused_minutes"], 10**6, "paused_minutes")
    labels = set(EVENT_LABELS.values())
    keys(s["events"], labels, "events", exact=False)
    keys(s["events_per_active_hour"], s["events"], "events_per_active_hour")
    for k in s["events"]:
        num(s["events"][k], MAX_COUNT, "events")
        num(s["events_per_active_hour"][k], 10**7, "events_per_active_hour", ints=False)
    if not isinstance(s["hours"], list) or len(s["hours"]) > 24 * 3660:
        fail("hours")
    hour_keys = {str(k) for k in SYSMON_EVENT_IDS}
    for h in s["hours"]:
        keys(h, ["active_minutes", "events"], "hours")
        num(h["active_minutes"], 60, "hours.active_minutes")
        keys(h["events"], hour_keys, "hours.events", exact=False)
        for v in h["events"].values():
            num(v, 10**7, "hours.events")
    keys(s["left_out"], ["our own lab tools", "while paused (counted only)"], "left_out")
    keys(s["health"], ["sysmon_records", "sysmon_records_missing", "recorder_sessions", "damaged_lines",
                       "damaged_files", "other_records", "re_delivered_skipped"], "health")
    for v in list(s["left_out"].values()) + list(s["health"].values()):
        num(v, MAX_COUNT, "counts")
    keys(s["self_test"], ["runs", "last_passed"], "self_test")
    num(s["self_test"]["runs"], 10**5, "self_test.runs")
    if s["self_test"]["last_passed"] not in (True, False, None):
        fail("self_test.last_passed")

MACHINE_MARK = "---- machine-readable copy of the same numbers (for Yousif's tools) ----"


def export_text(summary: dict, created: str) -> str:
    """The file a friend reads and sends: plain English first, the same numbers as JSON last."""
    check_summary(summary)
    if not (len(created) == 10 and created[4] == "-" and created[7] == "-" and created.replace("-", "").isdigit()):
        raise NotNumbersOnly("created must be a date")
    s = summary

    def n(v):
        return f"{v:,}" if isinstance(v, int) else f"{v:,.1f}"

    lines = [
        "Analyst Lab - my statistics",
        "===========================",
        f"Made on: {created}",
        "",
        "This file contains ONLY numbers: how many events of each kind this laptop produced,",
        "and how many per hour of use. It contains NO program names, file names, websites,",
        "addresses or command lines, and no dates or times of individual hours.",
        "Please read it. If you are happy with it, send it to Yousif.",
        "",
        "Recording",
        f"  Days recorded ............ {s['days_recorded']} of {s['target_days']}",
        f"  Active hours ............. {n(s['active_hours'])}",
        f"  Paused ................... {s['paused_minutes']} min",
        "",
        "Events from normal use         total     per active hour",
    ]
    for name, total in s["events"].items():
        lines.append(f"  {name:<28} {n(total):>9}     {n(s['events_per_active_hour'][name]):>9}")
    lines += [
        "",
        "Left out of the numbers above",
        f"  Our own lab tools ........ {n(s['left_out']['our own lab tools'])} events",
        f"  While paused ............. {n(s['left_out']['while paused (counted only)'])} events (only counted)",
        "",
        "Health",
        f"  Sysmon records ........... {n(s['health']['sysmon_records'])}, missing {n(s['health']['sysmon_records_missing'])}",
        f"  Recorder sessions ........ {s['health']['recorder_sessions']}",
        f"  Damaged lines skipped .... {s['health']['damaged_lines']}",
        f"  Self-tests run ........... {s['self_test']['runs']}, last one "
        + {True: "passed", False: "FAILED", None: "-"}[s["self_test"]["last_passed"]],
        f"  Hours listed one by one .. {len(s['hours'])} (in the copy below)",
        "",
        MACHINE_MARK,
        json.dumps(s, indent=1, ensure_ascii=True),
        "",
    ]
    return "\n".join(lines)


def read_export(text: str) -> dict:
    """Yousif's side: the numbers back from a friend's file (checked the same way)."""
    _, _, body = text.partition(MACHINE_MARK)
    summary = json.loads(body)
    check_summary(summary)
    return summary
