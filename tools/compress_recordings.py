"""Compress finished days of recordings with gzip (Python's built-in; ~10x smaller, still readable
by every project reader via engine/jsonl.py).

    python tools/compress_recordings.py          # show what would be compressed (nothing changes)
    python tools/compress_recordings.py --go     # compress them

A day is "finished" when its date (UTC, as the agents name their files) is before today AND the
file has not been written for --idle-hours (default 2): agents and the VM receiver only ever
append to today's file. For each file:
  1. write <day>.jsonl.gz.tmp, then rename it to <day>.jsonl.gz
  2. verify: the decompressed bytes must be identical to the original (SHA-256)
  3. only then delete the original <day>.jsonl
If anything fails the original stays; a day in both forms is read once (the original wins).
Never touches recordings outside recordings/<label>/ and prints counts, sizes and day names only.
"""

import argparse
import glob
import gzip
import hashlib
import os
import shutil
import sys
import time
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHUNK = 1024 * 1024


def sha256_of(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(CHUNK), b""):
        h.update(block)
    return h.hexdigest()


def finished_days(recordings, idle_hours, now=None):
    """(label, path) of every .jsonl that is safe to compress."""
    now = now or time.time()
    today = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    out = []
    for label in sorted(os.listdir(recordings)):
        folder = os.path.join(recordings, label)
        if label.startswith(".") or not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            day = name[:-len(".jsonl")] if name.endswith(".jsonl") else None
            if day is None or len(day) != 10 or day >= today:
                continue
            if now - os.path.getmtime(path) < idle_hours * 3600:
                continue
            out.append((label, path))
    return out


def compress(path):
    """Compress one file safely. Returns (original bytes, compressed bytes)."""
    gz, tmp = path + ".gz", path + ".gz.tmp"
    try:
        with open(path, "rb") as src:
            before = sha256_of(src)
        with open(path, "rb") as src, open(tmp, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6) as dst:
                shutil.copyfileobj(src, dst, CHUNK)
            raw.flush()
            os.fsync(raw.fileno())                      # on disk BEFORE the original is deleted
                                                        # (power loss; review 2026-10-19)
        with gzip.open(tmp, "rb") as check:             # closed before any delete (Windows)
            unpacked = sha256_of(check)
        if unpacked != before:
            raise ValueError("decompressed content differs from the original; original kept")
        with open(path, "rb") as src:                   # unchanged while we worked?
            if sha256_of(src) != before:
                raise ValueError("the original changed while compressing (still being written?); kept")
        os.replace(tmp, gz)
    finally:
        if os.path.exists(tmp):                         # never leave a half-made file behind
            os.remove(tmp)
    size = os.path.getsize(path)
    try:
        os.remove(path)
    except PermissionError as e:                        # e.g. the VM receiver still holds the day open
        raise StillOpen(f"compressed and verified, but the original is still open ({e}); "
                        "both forms kept (read once), retried next time") from e
    return size, os.path.getsize(gz)


class StillOpen(Exception):
    """The .gz is complete and verified; only deleting the original failed (a file lock)."""


def main(argv=None):
    p = argparse.ArgumentParser(description="gzip finished days of recordings")
    p.add_argument("--go", action="store_true", help="compress (default: only show the plan)")
    p.add_argument("--idle-hours", type=float, default=2.0)
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    a = p.parse_args(argv)

    both = [p for p in glob.glob(os.path.join(a.recordings, "*", "*.jsonl")) if os.path.exists(p + ".gz")]
    for p in both:                                     # readers use the original; say so
        print(f"note: {os.path.basename(os.path.dirname(p))}/{os.path.basename(p)} exists in both forms "
              "(readers use the uncompressed one)")
    todo = finished_days(a.recordings, a.idle_hours)
    if not todo:
        print("Nothing to compress (only today's files, or files written in the last "
              f"{a.idle_hours:g} h).")
        return 0
    total = sum(os.path.getsize(path) for _, path in todo)
    print(f"{len(todo)} finished day(s), {total / 2**20:,.0f} MB:")
    for label, path in todo:
        print(f"  {label}/{os.path.basename(path)}  {os.path.getsize(path) / 2**20:,.1f} MB")
    if not a.go:
        print("\nPlan only. Run with --go to compress.")
        return 0

    before = after = failed = 0
    for label, path in todo:
        try:
            b, c = compress(path)
            before, after = before + b, after + c
            print(f"  done  {label}/{os.path.basename(path)}: {b / 2**20:,.1f} -> {c / 2**20:,.1f} MB")
        except StillOpen as e:
            print(f"  OPEN  {label}/{os.path.basename(path)}: {e}")
        except (OSError, ValueError) as e:
            failed += 1
            print(f"  KEPT  {label}/{os.path.basename(path)}: {e}")
    if before:
        print(f"\n{before / 2**20:,.0f} MB -> {after / 2**20:,.0f} MB ({before / max(after, 1):.1f}x smaller)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
