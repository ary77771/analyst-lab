"""Build the read-only laptop TEST snapshot (package J part 2: experiments J4, J5 and J7 on the
laptop days AFTER the frozen dev cutoff; docs/plans/package-j2-prereg.md).

    python tools/build_test_snapshot.py                      # days cutoff+1 .. yesterday (UTC)
    python tools/build_test_snapshot.py --to 2026-11-20      # a fixed last day (say it in the report)
    python tools/build_test_snapshot.py --info               # what the existing snapshot holds (counts)

Same machinery as tools/build_dev_snapshot.py (the laptop's host recordings, re-tagged with today's
origin rules, one plain read-only SQLite file), but the OTHER side of the split: only days from
`--from` (default: the day after config/frozen.yaml data.dev_cutoff_day_utc) to `--to` (default:
yesterday, because the day still being recorded is incomplete). Rows stamped before the first day
or after the last day are removed. The `snapshot` table records `from_day_utc`, `cutoff_day_utc`
(= the last day) and `kind = test`, so tools/experiments.py can refuse anything else.

Writes recordings/scratch/test/<--name> (default test-laptop.db, v1's test week; v2's days go to
`--name test-laptop-v2.db`). An existing snapshot is NEVER overwritten (v2 pre-registration: v1's test
week is a frozen input of the regression): choose another name. Git-ignored, privacy rule 7. Must be run from the
main project folder (engine/retag.py recognises our own development work by its folder; from a
worktree, the main folder's development would count as normal use). Prints counts only.
"""

import argparse
import os
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import build_dev_snapshot as dev  # noqa: E402
from engine import config  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402

OUT_DIR = ("scratch", "test")
DB_NAME = "test-laptop.db"


def next_day(day: str) -> str:
    return (datetime.strptime(day, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")


def yesterday_utc() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def day_files_between(folder, start, end):
    """Recording files of a label folder whose UTC day lies in [start, end], in day order."""
    out = []
    for path in recording_files(folder):
        m = dev.DAY.search(os.path.basename(path))
        if m and start <= m.group(1) <= end:
            out.append(path)
    return out


def build(db_path, files, start, end, retag=True):
    """The dev builder's build() over the files, minus rows before `start`; then the snapshot
    table gets from_day_utc and kind=test. Returns the dev builder's info dict."""
    if start > end:
        raise ValueError(f"--from {start} is after --to {end}")

    def drop_before(db):
        db.execute("DELETE FROM events WHERE time < ?", (start,))

    info = dev.build(db_path, files, end, retag=retag, extra=drop_before)
    os.chmod(db_path, stat.S_IREAD | stat.S_IWRITE)
    db = sqlite3.connect(db_path)
    db.executemany("INSERT OR REPLACE INTO snapshot VALUES (?, ?)", [("from_day_utc", start), ("kind", "test")])
    db.commit()
    mode = db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
    db.close()
    if str(mode).lower() != "delete":
        raise RuntimeError(f"could not switch {db_path} to a plain journal (got {mode})")
    os.chmod(db_path, stat.S_IREAD)
    info["from_day_utc"] = start
    return info


def default_path(recordings, name=DB_NAME):
    return os.path.join(recordings, *OUT_DIR, name)


def main(argv=None):
    cutoff = config.load()["data"]["dev_cutoff_day_utc"]
    ap = argparse.ArgumentParser(description="Build the read-only laptop TEST snapshot (days after the dev cutoff)")
    ap.add_argument("--from", dest="start", default=next_day(cutoff), help="first test day (UTC), YYYY-MM-DD")
    ap.add_argument("--to", dest="end", default=yesterday_utc(), help="last test day (UTC), YYYY-MM-DD; default yesterday")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--info", action="store_true", help="show what the existing snapshot holds (counts)")
    ap.add_argument("--name", default=DB_NAME, help=f"file name under recordings/scratch/test/ (default {DB_NAME}: v1's test week; "
                                                     "v2: test-laptop-v2.db). An existing file is never overwritten")
    a = ap.parse_args(argv)
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.db", a.name):
        print(f"Refusing: --name {a.name!r} must be a plain file name ending in .db")
        return 2
    out = default_path(a.recordings, a.name)
    if a.info:
        if os.path.exists(out):
            dev.show_info(out)
            con = dev.open_dev(out)
            print("  from_day_utc:", dict(con.execute("SELECT key, value FROM snapshot")).get("from_day_utc"))
            con.close()
        else:
            print(f"no test snapshot at {out}")
        return 0
    if a.start <= cutoff:
        print(f"Refusing: --from {a.start} is not after the frozen dev cutoff {cutoff} (dev days are never test data).")
        return 2
    if a.end < a.start:
        print(f"Refusing: --to {a.end} is before --from {a.start}.")
        return 2
    if os.path.isfile(os.path.join(PROJECT_ROOT, ".git")):
        print("Refusing: run this from the main project folder, not a git worktree.")
        return 2
    if os.path.exists(out):
        print(f"Refusing: {a.name} already exists and is never overwritten (v1's test week and every built snapshot are "
              f"frozen inputs); choose another --name.")
        return 2
    os.makedirs(os.path.dirname(out), exist_ok=True)
    files = day_files_between(os.path.join(a.recordings, "host"), a.start, a.end)
    if not files:
        print(f"Refusing: no laptop recording days between {a.start} and {a.end}.")
        return 2
    info = build(out, files, a.start, a.end, retag=True)
    print(f"{a.name}: {info['events']} events, {len(files)} day files ({a.start} .. {a.end}), retagged "
          f"{__import__('json').loads(info['totals']).get('retagged')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
