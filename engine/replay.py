"""Replay recordings: feed recorded events back, in time order, at real speed, faster, or instantly.

Uses: building and testing the engine without the VM running, automated replay tests,
repeatable experiments, and the demo backup (replaying a real recorded run).

    python -m engine.replay recordings/host/2026-10-16.jsonl --speed 0 --db out.db     # instant
    python -m engine.replay run.jsonl --speed 10 --max-gap 5 --out copy.jsonl          # 10x, idle gaps cut to 5 s

Timing is scheduled against the wall clock (each event at start + recorded offset / speed),
so processing time doesn't add up into drift. Records without a time (unreadable events)
are kept, placed right after the event before them in the file.
"""

import argparse
import json
import re
import time
from datetime import datetime, timedelta, timezone

from .jsonl import expand_patterns, iter_jsonl

_TIME = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)?$")


def parse_time(text: str) -> datetime:
    """ISO-8601 with any number of fractional digits and Z or an offset -> aware UTC datetime."""
    m = _TIME.match(text.strip())
    if not m:
        raise ValueError(f"unrecognised time: {text!r}")
    whole, frac, zone = m.groups()
    dt = datetime.fromisoformat(whole)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    if zone in (None, "Z"):
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if zone[0] == "+" else -1
    offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])) * sign
    return (dt.replace(tzinfo=timezone(offset))).astimezone(timezone.utc)


def read_recordings(paths, retag: bool = False) -> list:
    """All records from the files, in time order (stable: equal times keep file order).
    retag=True re-tags laptop records with today's rules in FILE order (as engine.load does),
    so a replayed store equals a loaded one."""
    from .retag import Retagger
    retagger = Retagger() if retag else None
    keyed = []
    last = datetime.min.replace(tzinfo=timezone.utc)
    n = 0
    for path in paths:
        for r in iter_jsonl(path):                 # damaged lines are skipped
            if retagger:
                r = retagger(r)
            if r.get("time"):
                last = parse_time(r["time"])
            keyed.append((last, n, r))
            n += 1
    keyed.sort(key=lambda x: (x[0], x[1]))
    return [r for _, _, r in keyed]


def replay(records, consume, speed: float = 0, max_gap: float = None,
           sleep=time.sleep, clock=time.monotonic) -> int:
    """Call consume(record) for each record. speed=0: instant; speed=N: N times real time.
    max_gap caps idle gaps (in recorded seconds) so long quiet periods don't stall a demo."""
    start = clock()
    offset = 0.0                                   # recorded seconds since the first event
    previous = None
    for record in records:
        if speed and record.get("time"):
            t = parse_time(record["time"])
            if previous is not None:
                gap = (t - previous).total_seconds()
                if max_gap is not None:
                    gap = min(gap, max_gap)
                offset += max(gap, 0.0)
                wait = start + offset / speed - clock()
                if wait > 0:
                    sleep(wait)
            previous = t
        consume(record)
    return len(records)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("patterns", nargs="+")
    p.add_argument("--speed", type=float, default=0, help="0 = instant, 1 = real time, 10 = 10x")
    p.add_argument("--max-gap", type=float, default=None)
    p.add_argument("--db", help="replay into an event store (SQLite)")
    p.add_argument("--out", help="replay into a JSONL file")
    p.add_argument("--keep-tags", action="store_true", help="--db: keep the agent's recorded origin tags")
    a = p.parse_args(argv)

    paths = expand_patterns(a.patterns)          # also the compressed days (.jsonl.gz)
    records = read_recordings(paths, retag=bool(a.db) and not a.keep_tags)
    if a.db:
        from .store import EventStore
        store = EventStore(a.db)
        buffer, last_flush = [], [time.monotonic()]

        def to_store(r):                           # batch commits: one per 5,000 events or per second
            buffer.append(r)
            if len(buffer) >= 5000 or (a.speed and time.monotonic() - last_flush[0] >= 1):
                store.insert(buffer)
                buffer.clear()
                last_flush[0] = time.monotonic()

        n = replay(records, to_store, a.speed, a.max_gap)
        if buffer:
            store.insert(buffer)
        store.close()
    elif a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            n = replay(records, lambda r: f.write(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"),
                       a.speed, a.max_gap)
    else:
        n = replay(records, lambda r: None, a.speed, a.max_gap)
    print(f"replayed {n} events")


if __name__ == "__main__":
    main()
