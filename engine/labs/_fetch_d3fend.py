"""Fetch MITRE D3FEND (defensive techniques and their ATT&CK mappings) for the "What to do next" lab;
never committed (downloads/).

    python -m engine.labs._fetch_d3fend                  # release 1.6.0 (2026-08-31)
    python -m engine.labs._fetch_d3fend --version 1.6.0 --out <folder>

Writes <out>/d3fend.csv (ID, tactic, technique name, definition), <out>/d3fend-full-mappings.csv (D3FEND's
own inferred ATT&CK <-> D3FEND mappings, as its website shows them) and <out>/manifest.json (version,
sha256 per file, urls). <out> defaults to downloads/night/d3fend in the nearest downloads folder.
Only public data comes IN; nothing of this laptop is sent. D3FEND © The MITRE Corporation, licensed for
research, development and commercial use (https://d3fend.mitre.org/tou).
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

from . import _downloads

FILES = ("d3fend.csv", "d3fend-full-mappings.csv")
USER_AGENT = "analystlab-night-fetch/1.0"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="1.6.0")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    out = a.out or (os.path.join(_downloads.root(), "night", "d3fend") if _downloads.root() else None)
    if not out:
        raise SystemExit("no downloads folder found; pass --out")
    os.makedirs(out, exist_ok=True)
    manifest = {"version": a.version, "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": {}}
    for name in FILES:
        url = f"https://d3fend.mitre.org/ontologies/d3fend/{a.version}/{name}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=300) as r:
            data = r.read()
        head = data[:200].decode("utf-8", "replace")
        if "," not in head.splitlines()[0]:
            raise SystemExit(f"{name}: not a CSV")
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        manifest["files"][name] = {"url": url, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        print(f"{name}: {len(data) / 1e6:.1f} MB")
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"D3FEND {a.version} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
