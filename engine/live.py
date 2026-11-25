"""Live loop (package L, for the demo): follow the recordings while they grow, load new events
into a live event store, run the rules every few seconds, and write new alerts.

    python -m engine.live --label vm --store recordings/live/vm.db --alerts recordings/live/vm-alerts.db

Today the receiver (engine/receiver.py) only appends to recordings/<label>/<UTC day>.jsonl;
nothing scored them while a scenario ran. This module:
  - reads only COMPLETE new lines of each day file (remembers a byte offset per file; a line
    still being written is read on the next pass), finished .gz days once at start;
  - loads them into a WRITABLE live store (never the read-only dev snapshots), re-tagging
    laptop records like engine/load.py;
  - runs every detector through engine/score.py, exactly as batch scoring does: Sigma rules
    (simple ones only on the new events, correlations on the whole store, see engine/detect.py),
    our own rules and the check-in rhythm rule; stores alerts; ids are stable, so alerts already
    stored are not new again;
  - records when each alert was first seen (`seen_utc` in details), so "time to detect"
    (event time -> alert) can be measured.
Counts only on screen (privacy rule 7): rule titles, levels, times; no paths or addresses.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone

from . import beacon, config, detect, own_rules, score
from .alerts import AlertStore, declared_note
from .jsonl import iter_jsonl, recording_files
from .replay import parse_time
from .retag import Retagger
from .store import EventStore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Follower:
    """New complete records of a label folder since the last call."""

    def __init__(self, folder: str, retag: bool):
        self.folder = folder
        self.offsets = {}                      # path -> bytes already read (complete lines)
        self.done_gz = set()
        self.retagger = Retagger() if retag else None
        self.bad_lines = 0

    def poll(self):
        out = []
        for path in recording_files(self.folder):
            if path.endswith(".gz"):
                if path in self.done_gz:
                    continue
                counters = {}
                out.extend(iter_jsonl(path, counters))
                self.bad_lines += counters.get("bad_lines", 0)
                self.done_gz.add(path)
                continue
            start = self.offsets.get(path, 0)
            if os.path.getsize(path) < start:
                start = 0                      # the file was truncated or rewritten: read it again (the store dedups)
            with open(path, "rb") as f:
                f.seek(start)
                chunk = f.read()
            end = chunk.rfind(b"\n")
            if end < 0:
                continue                       # nothing complete yet
            for raw in chunk[:end + 1].splitlines():
                if not raw.strip():
                    continue
                try:
                    out.append(json.loads(raw.decode("utf-8")))
                except (UnicodeDecodeError, ValueError):
                    self.bad_lines += 1
            self.offsets[path] = start + end + 1
        if self.retagger:
            out = [self.retagger(r) for r in out]
        return out


def _rollback(store):
    """Undo a failed insert, including columns it added (the store caches column names)."""
    store.db.rollback()
    store.columns = {row[1].lower(): row[1] for row in store.db.execute("PRAGMA table_info(events)")}


class LiveLoop:
    def __init__(self, folder, store_path, alerts_path, rules, retag=False, own=True, min_level="informational",
                 baseline=None, beacon_cfg=None, since=None):
        self.follower = Follower(folder, retag)
        self.since = since                      # a UTC datetime: records before it are skipped (the demo's fresh start)
        self.store_path = store_path
        self.alerts_path = alerts_path
        self.rules = rules
        self.own = own
        self.min_level = min_level
        self.baseline = baseline                # engine.baseline.load(...): enables the learned-normal rules
        self.beacon_cfg = beacon_cfg            # None: config/frozen.yaml's beacon block
        self.last_id = 0
        self.rejected = 0                      # records the store refused (quarantined in rejected.jsonl)
        self.rule_errors = []                  # (rule id, error) from the last pass: never silent

    def tick(self, now=None):
        """One pass: load new records, score, store. Returns (records loaded, new alerts)."""
        records = self.follower.poll()
        if self.since is not None:              # after re-tagging, which needs the whole stream
            records = [r for r in records if not r.get("time") or parse_time(r["time"]) >= self.since]
        store = EventStore(self.store_path)
        if records:
            try:
                store.insert(records)
            except Exception:
                # one malformed record must not stop the loop (and, since offsets live in memory,
                # crash it again on every restart): store the good ones, quarantine the rest
                _rollback(store)
                for r in records:
                    try:
                        store.insert([r])
                    except Exception as e:
                        _rollback(store)
                        self._quarantine(r, e)
        store.close()
        con = detect.open_store(self.store_path)
        try:
            top = con.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            if top == self.last_id:
                return len(records), []
            # the same pass as batch scoring (engine/score.py): Sigma, own rules, check-in rhythm
            self.rule_errors = []
            if self.own:
                alerts = score.score(con, self.rules, self.baseline, self.beacon_cfg, after_id=self.last_id,
                                     errors=self.rule_errors, min_level=self.min_level)
            else:
                timings = {}
                alerts = detect.detect(con, self.rules, self.min_level, timings, after_id=self.last_id)
                self.rule_errors = timings.get("_errors", [])
            self.last_id = top
        finally:
            con.close()
        seen = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z")
        sink = AlertStore(self.alerts_path)
        known = {r[0] for r in sink.db.execute("SELECT alert_id FROM alerts")}
        fresh = []
        for a in alerts:
            if a.alert_id not in known:
                a.details["seen_utc"] = seen
                fresh.append(a)
                known.add(a.alert_id)
        # all alerts go to the store: an incident alert seen before is updated there when it has
        # grown (more evidence), keeping its first seen_utc; only new ones are returned
        sink.write(alerts, events_db=os.path.abspath(self.store_path))
        sink.close()
        return len(records), fresh

    def _quarantine(self, record, error):
        self.rejected += 1
        path = os.path.join(os.path.dirname(os.path.abspath(self.store_path)), "rejected.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"error": f"{type(error).__name__}: {error}"[:300],
                                "record": repr(record)[:2000]}, ensure_ascii=True) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Follow recordings, score them live, write alerts")
    ap.add_argument("--label", default="vm", help="recordings/<label>/ to follow")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--store", required=True, help="live event store to write (NOT a dev snapshot)")
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--every", type=float, default=5.0, help="seconds between passes")
    ap.add_argument("--min-level", default="informational", choices=detect.LEVELS)   # same as engine.detect
    ap.add_argument("--once", action="store_true", help="one pass, then stop")
    ap.add_argument("--baseline", nargs="*", help="learned-normal files (default: the ones config/frozen.yaml lists)")
    ap.add_argument("--since-now", action="store_true",
                    help="skip records recorded before this start (a demo shows only the new run's alerts)")
    a = ap.parse_args(argv)
    if os.path.join("scratch", "dev") in os.path.normcase(os.path.realpath(a.store)):
        raise SystemExit("refusing: the live store must not be a dev snapshot")
    rules = score.load_rules()
    files = a.baseline if a.baseline is not None else score.baseline_files()
    baseline = score.load_baseline(files)
    print(f"learned-normal baselines: {len(files)} file(s)" + ("" if files else " (shell-parent, listener and wipe rules off)"))
    from . import beacon as _beacon
    if _beacon.load_config().short_unseen:                  # v4 F2 (review 2026-11-17): say when it cannot run
        lists = score.connectors_of(baseline) or {}
        print(f"short check-in test for never-seen programs (F2): connector lists for {len(lists)} machine(s); "
              "a machine without one gets no F2 alerts")
    loop = LiveLoop(os.path.join(a.recordings, a.label), a.store, a.alerts, rules,
                    retag=a.label in ("host", "vm"), min_level=a.min_level, baseline=baseline,
                    since=datetime.now(timezone.utc) if a.since_now else None)
    n_own = len(own_rules.RULES) + (len(own_rules.BASELINE_RULES) if baseline else 0)
    print(f"following recordings/{a.label}/ with {len(rules)} Sigma rules + {n_own} own rules + the check-in rhythm rule")
    while True:
        t0 = time.perf_counter()
        n, fresh = loop.tick()
        floor = detect.LEVELS.index(config.min_level())   # everything is stored; only these are announced
        for x in [x for x in fresh if detect.LEVELS.index(x.level) >= floor]:
            print(f"  ALERT [{x.level}] {x.title} at {x.time}{declared_note(x)}")
        for rid, err in loop.rule_errors[:3]:
            print(f"  RULE ERROR {rid[:24]}: {err[:100]}")
        if loop.rejected:
            print(f"  {loop.rejected} malformed record(s) quarantined so far (rejected.jsonl next to the store)")
        if n:
            print(f"{n} new records, {len(fresh)} new alerts ({time.perf_counter() - t0:.1f} s)")
        if a.once:
            return 0
        time.sleep(max(0.0, a.every - (time.perf_counter() - t0)))


if __name__ == "__main__":
    raise SystemExit(main())
