"""Stage 3 real-data check: did the agent record exactly what Sysmon logged?

Independent of the agent's code path: reads the Sysmon channel directly (EvtQuery, not a
subscription, no bookmarks), takes every record in a time window, and compares the set of
record IDs with the agent's JSONL recordings. Reports missing and duplicate records.
Needs administrator rights (reading the Sysmon log).

    python tools/verify_agent_counts.py --since 2026-10-16T13:56:00Z --until 2026-10-16T15:00:00Z
"""

import argparse
import collections
import json
import os
import re
import sys

import win32evtlog

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from engine.jsonl import iter_jsonl, recording_files  # noqa: E402  (reads recordings only; Sysmon is read directly)


def sysmon_record_ids(since: str, until: str) -> set:
    """Record IDs Sysmon logged in [since, until). Reads newest-first and stops once past
    `since`, instead of an XPath time filter (which scans the whole 1 GB log every time)."""
    handle = win32evtlog.EvtQuery(CHANNEL, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection)
    lo, hi = _norm(since), _norm(until)
    ids = set()
    older_seen = 0
    while True:
        batch = win32evtlog.EvtNext(handle, 500)
        if not batch:
            break
        for e in batch:
            xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
            t = _norm(re.search(r"SystemTime='([^']+)'", xml).group(1))
            if t >= hi:
                continue
            if t < lo:
                older_seen += 1                  # a few late-logged events can interleave,
                continue                         # so stop only after a clear run of older ones
            older_seen = 0
            ids.add(int(re.search(r"<EventRecordID>(\d+)<", xml).group(1)))
        if older_seen >= 2000:
            break
    return ids


def recorded_record_ids(label: str, since: str, until: str):
    counts = collections.Counter()
    for path in recording_files(os.path.join(PROJECT_ROOT, "recordings", label)):
        for r in iter_jsonl(path):               # damaged lines are skipped
            if r.get("source") == "sysmon" and r.get("time") and _norm(since) <= _norm(r["time"]) < _norm(until):
                counts[r["record_id"]] += 1
    return counts


def _norm(t: str) -> str:
    """Fixed-width UTC text (7 fractional digits, no 'Z') so string order = time order."""
    t = t.rstrip("Z")
    whole, _, frac = t.partition(".")
    return f"{whole}.{(frac + '0000000')[:7]}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--since", required=True, help="UTC, e.g. 2026-10-16T13:56:00Z")
    p.add_argument("--until", required=True)
    p.add_argument("--label", default="host")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    a.since = a.since.replace("+00:00", "Z")
    a.until = a.until.replace("+00:00", "Z")

    in_log =sysmon_record_ids(a.since, a.until)
    recorded = recorded_record_ids(a.label, a.since, a.until)
    missing = sorted(in_log - set(recorded))
    extra = sorted(set(recorded) - in_log)
    duplicates = sorted(rid for rid, n in recorded.items() if n > 1)

    result = {
        "window": [a.since, a.until],
        "sysmon_log_count": len(in_log),
        "recorded_unique": len(recorded),
        "recorded_total_lines": sum(recorded.values()),
        "missing_count": len(missing), "missing_sample": missing[:20],
        "extra_count": len(extra), "extra_sample": extra[:20],
        "duplicate_count": len(duplicates), "duplicate_sample": duplicates[:20],
        "exact_match": not missing and not extra and not duplicates,
    }
    with open(a.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["exact_match"] else 1)


if __name__ == "__main__":
    main()
