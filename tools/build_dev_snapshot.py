"""Build the read-only DEV snapshot databases (fair-test rule 1, docs/plans/hard-part-plan.md).

    python tools/build_dev_snapshot.py                # dev = recordings up to 2026-10-22 (UTC)

Dev data is what we may build and tune on: the laptop's recordings up to and including the
cutoff day, and the VM scenario runs that already exist. Laptop days after the cutoff, friends'
files, the official clean-boot runs and the blind scenarios are TEST data and never go in here.

Writes recordings/scratch/dev/ (git-ignored, privacy rule 7):
  dev-laptop.db   laptop events, re-tagged with today's origin rules. Built HERE, in the main
                  project folder, on purpose: engine/retag.py recognises our own development
                  work by the folder its code lives in, so a database built from a git worktree
                  would count all main-folder development as normal use.
  dev-vm.db       VM recordings + table `runs` (one row per recorded scenario run).
Each has a table `snapshot` (what went in, when, the cutoff). The day being recorded when the
snapshot is built is only included up to that moment; the rest of that day is neither dev
nor test. The files are switched to plain journal mode and marked read-only, so other sessions
open them with sqlite3.connect("file:<path>?mode=ro", uri=True) (not engine.store.EventStore,
which writes).
"""

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from engine.jsonl import recording_files  # noqa: E402
from engine.load import load_files  # noqa: E402
from engine.store import EventStore  # noqa: E402

def _frozen_cutoff():
    """The last dev day as frozen in config/frozen.yaml (data.dev_cutoff_day_utc): one source."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine import config
    return config.load()["data"]["dev_cutoff_day_utc"]


DEFAULT_CUTOFF = _frozen_cutoff()
DAY = re.compile(r"(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?$")


def day_files(folder, cutoff):
    """Recording files of a label folder whose UTC day is <= cutoff, in day order."""
    out = []
    for path in recording_files(folder):
        m = DAY.search(os.path.basename(path))
        if m and m.group(1) <= cutoff:
            out.append(path)
    return out


def _writable(path):
    if os.path.exists(path):
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def build(db_path, files, cutoff, retag, extra=None):
    _writable(db_path)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    store = EventStore(db_path)
    totals = load_files(store, files, retag=retag)
    store.close()
    db = sqlite3.connect(db_path)
    # a day's file can hold a few records stamped just after midnight: those are test data
    end = (datetime.strptime(cutoff, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    totals["after_cutoff_removed"] = db.execute("DELETE FROM events WHERE time >= ?", (end,)).rowcount
    if extra:
        extra(db)
    db.execute("CREATE TABLE snapshot (key TEXT PRIMARY KEY, value TEXT)")
    info = {
        "built_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cutoff_day_utc": cutoff,
        "files": json.dumps([os.path.basename(f) for f in files]),
        "retagged": str(retag),
        "totals": json.dumps(totals),
        "events": str(db.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
        "last_event_time": str(db.execute("SELECT MAX(time) FROM events").fetchone()[0]),
    }
    db.executemany("INSERT INTO snapshot VALUES (?, ?)", info.items())
    db.commit()
    mode = db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]   # one plain file: read-only opens need no -wal/-shm
    db.close()
    if str(mode).lower() != "delete":
        raise RuntimeError(f"could not switch {db_path} to a plain journal (got {mode})")
    os.chmod(db_path, stat.S_IREAD)
    return info


def add_runs(recordings, cutoff):
    import check_scenario                      # tools/ (the one reader of runner records)

    def extra(db):
        # Only runs that exist today are dev. Official runs (package R) and blind scenarios are
        # recorded after the cutoff day, so the date rule keeps them out; their runner will also
        # mark them, and this must then refuse them by that mark (open item, package R).
        db.execute("CREATE TABLE runs (run_id TEXT, scenario TEXT, start TEXT, \"end\" TEXT, "
                   "exit_code INTEGER, server TEXT, record TEXT)")
        for r in check_scenario.all_runs(recordings):
            if str(r.get("start", ""))[:10] <= cutoff:
                db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (r.get("run_id"), r.get("scenario"), r.get("start"), r.get("end"),
                            r.get("exit_code"), r.get("server"), json.dumps(r)))
    return extra


def open_dev(path):
    """A read-only connection to a dev snapshot (any session, any worktree)."""
    uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def show_info(path):
    """Counts only (privacy rule 7): what's in a snapshot."""
    db = open_dev(path)
    meta = dict(db.execute("SELECT key, value FROM snapshot"))
    print(os.path.basename(path), {k: meta[k] for k in ("built_utc", "cutoff_day_utc", "events", "last_event_time")})
    print("  by event id:", db.execute("SELECT event_id, COUNT(*) FROM events GROUP BY 1 ORDER BY 1").fetchall())
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='runs'").fetchone():
        print("  runs:", db.execute("SELECT scenario, COUNT(*) FROM runs GROUP BY 1 ORDER BY 1").fetchall())
    db.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the read-only dev snapshot databases")
    ap.add_argument("--cutoff", default=DEFAULT_CUTOFF, help="last dev day (UTC), YYYY-MM-DD")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--only", choices=["laptop", "vm"])
    ap.add_argument("--info", action="store_true", help="show what the existing snapshots hold (counts)")
    a = ap.parse_args(argv)
    out = os.path.join(a.recordings, "scratch", "dev")
    if not a.info and os.path.isfile(os.path.join(PROJECT_ROOT, ".git")):
        # a git worktree has a .git FILE; the main folder has a .git folder. Built from a
        # worktree, retag.py would treat the main folder's development as normal use.
        print("Refusing: run this from the main project folder, not a git worktree.")
        return 2
    if a.info:
        for name in ("dev-vm.db", "dev-laptop.db"):
            if os.path.exists(os.path.join(out, name)):
                show_info(os.path.join(out, name))
        return
    os.makedirs(out, exist_ok=True)
    if a.only in (None, "vm"):
        info = build(os.path.join(out, "dev-vm.db"), day_files(os.path.join(a.recordings, "vm"), a.cutoff),
                     a.cutoff, retag=False, extra=add_runs(a.recordings, a.cutoff))
        print("dev-vm.db:", info["events"], "events,", len(json.loads(info["files"])), "files")
    if a.only in (None, "laptop"):
        info = build(os.path.join(out, "dev-laptop.db"), day_files(os.path.join(a.recordings, "host"), a.cutoff),
                     a.cutoff, retag=True)
        print("dev-laptop.db:", info["events"], "events,", len(json.loads(info["files"])), "files,",
              "retagged", json.loads(info["totals"]).get("retagged"))


if __name__ == "__main__":
    main()
