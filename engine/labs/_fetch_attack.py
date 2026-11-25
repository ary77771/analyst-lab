"""Fetch MITRE ATT&CK (Enterprise, STIX 2.1) for the night-explain labs; never committed (downloads/).

    python -m engine.labs._fetch_attack                # newest release listed by mitre-attack/attack-stix-data
    python -m engine.labs._fetch_attack --version 18.1 # one release
    python -m engine.labs._fetch_attack --out <folder>

Writes <out>/enterprise-attack-<version>.json and <out>/manifest.json ({version, file, sha256, bytes, url,
fetched_utc}). <out> defaults to downloads/night/attack in the nearest downloads folder (the main checkout's
when run from a worktree). Only public data comes IN; nothing of this laptop is sent anywhere.
Source: https://github.com/mitre-attack/attack-stix-data (ATT&CK © The MITRE Corporation, used under its
terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

from . import _downloads

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
INDEX = f"{BASE}/index.json"
USER_AGENT = "analystlab-night-fetch/1.0"


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def newest_version(index):
    for coll in index.get("collections", []):
        if "enterprise" in (coll.get("name") or "").lower():
            versions = sorted(coll.get("versions", []), key=lambda v: [int(x) for x in str(v["version"]).split(".")])
            return str(versions[-1]["version"]), versions[-1].get("url")
    raise SystemExit("index.json lists no Enterprise ATT&CK collection")


def default_out():
    root = _downloads.root()
    if not root:
        raise SystemExit("no downloads folder found; pass --out")
    return os.path.join(root, "night", "attack")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", help="ATT&CK release, e.g. 18.1 (default: the newest)")
    ap.add_argument("--out", help="folder (default: downloads/night/attack)")
    a = ap.parse_args(argv)
    out = a.out or default_out()
    os.makedirs(out, exist_ok=True)
    if a.version:
        version, url = a.version, f"{BASE}/enterprise-attack/enterprise-attack-{a.version}.json"
    else:
        version, url = newest_version(json.loads(_get(INDEX)))
        url = url or f"{BASE}/enterprise-attack/enterprise-attack-{version}.json"
    data = _get(url)
    bundle = json.loads(data)                       # must be valid JSON before it is kept
    if bundle.get("type") != "bundle":
        raise SystemExit("not a STIX bundle")
    name = f"enterprise-attack-{version}.json"
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
    manifest = {"version": version, "file": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "url": url, "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "objects": len(bundle.get("objects", []))}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"ATT&CK Enterprise {version}: {len(data) / 1e6:.1f} MB, {manifest['objects']} objects -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
