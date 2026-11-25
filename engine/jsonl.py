"""The one safe way to read recordings (JSON lines), used by every reader in the project.

Reads bytes and decodes each line on its own, so a damaged line (a partial line or a
multi-byte UTF-8 character cut by a crash, e.g. in an Arabic file name) is skipped and
counted instead of stopping the whole read.

Finished days may be gzip-compressed (`<day>.jsonl.gz`, tools/compress_recordings.py); every
reader goes through iter_jsonl and recording_files/expand_patterns, so both forms read alike.
If a day exists in both forms (a compression interrupted before the original was deleted), the
original `.jsonl` is used and the `.gz` ignored, so nothing is ever counted twice.
"""

import glob
import gzip
import json
import os
import zlib


def iter_jsonl(path: str, counters: dict = None):
    """Yield one parsed record per good line; count bad lines in counters['bad_lines'].
    A compressed file that is itself damaged (cut short, corrupt) yields its readable part and
    is counted in counters['bad_files'] instead of stopping the whole read (review 2026-10-19)."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        try:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    yield json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    if counters is not None:
                        counters["bad_lines"] = counters.get("bad_lines", 0) + 1
        except (EOFError, gzip.BadGzipFile, zlib.error):
            if counters is not None:
                counters["bad_files"] = counters.get("bad_files", 0) + 1


def _one_per_day(paths):
    """Sorted paths with at most one per recording: `x.jsonl` beats `x.jsonl.gz`."""
    chosen = {}
    for p in paths:
        if not (p.endswith(".jsonl") or p.endswith(".jsonl.gz")):
            continue                                   # e.g. a leftover .gz.tmp: never a recording
        key = p[:-3] if p.endswith(".jsonl.gz") else p
        if key not in chosen or not p.endswith(".gz"):
            chosen[key] = p
    return [chosen[k] for k in sorted(chosen)]


def recording_files(folder: str):
    """Every recording in a label folder (recordings/<label>/), compressed or not, in day order."""
    return _one_per_day(glob.glob(os.path.join(folder, "*.jsonl")) + glob.glob(os.path.join(folder, "*.jsonl.gz")))


def expand_patterns(patterns):
    """Command-line patterns such as recordings/host/*.jsonl: each also matches the compressed
    form of the same files (pattern + '.gz')."""
    found = set()
    for pat in patterns:
        found.update(glob.glob(pat))
        if pat.endswith(".jsonl"):
            found.update(glob.glob(pat + ".gz"))
    return _one_per_day(found)
