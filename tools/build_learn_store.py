"""Build a LEARNING event store (v4 F3): the Sysmon events a learned-normal rule needs, from one
recording folder, up to and including a given UTC day. Used to learn the "wipers" baselines
(python -m engine.baseline --wipers). Only process starts (1), connections (3), file creations
(11) and deletions (26) are kept, so 29 laptop days fit in ~6 GB. Laptop records are re-tagged with
today's origin rules (as engine/load.py does), so our own tools never count as normal use.

    python tools/build_learn_store.py --label host --to 2026-11-14 --out recordings/scratch/learn/laptop-to-1114.db
    python tools/build_learn_store.py --label vm --to 2026-11-14 --out recordings/scratch/learn/vm-to-1114.db

An existing output file is never overwritten. Prints counts only (privacy rule 7)."""
import argparse
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.jsonl import iter_jsonl, recording_files  # noqa: E402
from engine.retag import Retagger  # noqa: E402
from engine.store import EventStore  # noqa: E402

KEEP = (1, 3, 11, 26)


def build(recordings, label, to_day, out, batch=20000):
    if os.path.exists(out):
        raise FileExistsError(f"{out} exists; never overwritten")
    files = [f for f in recording_files(os.path.join(recordings, label)) if os.path.basename(f)[:10] <= to_day]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    s, rows, n = EventStore(out), [], Counter()
    retagger = Retagger() if label == "host" else None     # file order, as engine/load.py (review 2026-11-15:
    try:                                                   # streamed, not read_recordings' all-in-memory sort)
        for path in files:
            for r in iter_jsonl(path):
                if retagger:
                    r = retagger(r)
                if r.get("source") == "sysmon" and r.get("event_id") in KEEP:
                    rows.append(r)
                    n[r["event_id"]] += 1
                    if len(rows) >= batch:
                        s.insert(rows)
                        rows = []
        if rows:
            s.insert(rows)
    finally:
        s.close()
    return len(files), dict(n)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--label", required=True, choices=("host", "vm"))
    ap.add_argument("--to", required=True, help="last UTC day included, YYYY-MM-DD")
    ap.add_argument("--out", required=True)
    ap.add_argument("--recordings", default=os.path.join(ROOT, "recordings"))
    a = ap.parse_args(argv)
    nfiles, counts = build(a.recordings, a.label, a.to, a.out)
    print(f"{nfiles} recording file(s) up to {a.to}; events kept: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
