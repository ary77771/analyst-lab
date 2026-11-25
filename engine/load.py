"""Load agent recordings (JSONL) into the event store.

    python -m engine.load recordings/host/*.jsonl --db recordings/lab.db

A line that isn't valid JSON (a partial line left by a crash) is skipped and counted.
Laptop records are re-tagged with today's origin rules (engine/retag.py; --keep-tags to skip).
"""

import argparse

from .jsonl import expand_patterns, iter_jsonl as read_jsonl
from .retag import Retagger
from .store import EventStore


def load_files(store: EventStore, paths, batch_size: int = 5000, retag: bool = True) -> dict:
    totals = {"read": 0, "inserted": 0, "duplicates": 0, "bad_lines": 0, "retagged": 0}
    retagger = Retagger() if retag else None
    for path in paths:
        batch = []
        for record in read_jsonl(path, totals):
            batch.append(retagger(record) if retagger else record)
            if len(batch) >= batch_size:
                _flush(store, batch, totals)
        _flush(store, batch, totals)
    if retagger:
        totals["retagged"] = retagger.changed
    return totals


def _flush(store, batch, totals):
    if batch:
        inserted, dupes = store.insert(batch)
        totals["read"] += len(batch)
        totals["inserted"] += inserted
        totals["duplicates"] += dupes
        batch.clear()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("patterns", nargs="+")
    p.add_argument("--db", required=True)
    p.add_argument("--keep-tags", action="store_true", help="keep the agent's recorded origin tags")
    a = p.parse_args(argv)
    paths = expand_patterns(a.patterns)          # also the compressed days (.jsonl.gz)
    store = EventStore(a.db)
    print(load_files(store, paths, retag=not a.keep_tags))
    store.close()


if __name__ == "__main__":
    main()
