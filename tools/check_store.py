"""Stage 4 real-data check: the database holds exactly what the recordings contain.

Compares, per event type, the number of unique events in the JSONL recordings with the
database rows of the same labels (host, vm, ...), then checks up to 10 random events field
by field. Prints only counts and field NAMES, never values (privacy rule, DESIGN 9.1).

    python tools/check_store.py --db recordings/lab.db recordings/host/*.jsonl
"""

import argparse
import collections
import os
import random
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.jsonl import expand_patterns, iter_jsonl  # noqa: E402
from engine.store import RESERVED_LOWER, EventStore  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("patterns", nargs="+")
    p.add_argument("--db", required=True)
    a = p.parse_args()

    counters = {}
    records = {}
    for path in expand_patterns(a.patterns):
        for r in iter_jsonl(path, counters):
            records[EventStore.dedup_key(r)] = r
    labels = sorted({r.get("label") for r in records.values()})

    expected = collections.Counter(str(r.get("event_id") or r.get("type")) for r in records.values())
    db = sqlite3.connect(a.db)
    marks = ",".join("?" for _ in labels)
    actual = collections.Counter({str(k): n for k, n in db.execute(
        f"SELECT COALESCE(CAST(event_id AS TEXT), type), COUNT(*) FROM events WHERE label IN ({marks}) GROUP BY 1",
        labels)})
    print(f"labels: {labels}; damaged lines skipped: {counters.get('bad_lines', 0)}")
    print("per type  (recordings vs database):")
    for k in sorted(set(expected) | set(actual)):
        print(f"  {k:>18}: {expected[k]:7} vs {actual[k]:7}  {'OK' if expected[k] == actual[k] else 'MISMATCH'}")

    cols = [d[0] for d in db.execute("SELECT * FROM events LIMIT 0").description]
    lower_to_col = {c.lower(): c for c in cols}
    sample = random.Random(1).sample(sorted(records), min(10, len(records)))
    mismatched_fields = 0
    for key in sample:
        row = db.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone()
        if row is None:
            mismatched_fields += 1
            print("  event missing from the database")
            continue
        stored = dict(zip(cols, row))
        for field, value in records[key].get("data", {}).items():
            name = f"data_{field}" if field.lower() in RESERVED_LOWER else field
            col = lower_to_col.get(name.lower())
            stored_value = stored.get(col) if col else None
            if col is None or str(stored_value) != str(value if not isinstance(value, (list, dict)) else str(value)):
                mismatched_fields += 1
                print(f"  field mismatch: {field}")          # name only, never the value
    ok = expected == actual and mismatched_fields == 0
    print(f"{len(sample)} random events checked field by field; mismatches: {mismatched_fields}")
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
