"""Fetch what the night-tools labs read, into downloads/night/<tool>/ (git-ignored). Run by hand:

    python -m engine.labs._fetch yara        YARA-Forge "core" rule set   -> downloads/night/yara/yara-forge-core/
    python -m engine.labs._fetch lolbas      LOLBAS project data (JSON)   -> downloads/night/lolbas/lolbas.json
    python -m engine.labs._fetch hayabusa    Hayabusa (Windows x64 zip)   -> downloads/night/hayabusa/
    python -m engine.labs._fetch chainsaw    Chainsaw (+ its Sigma rules) -> downloads/night/chainsaw/
    python -m engine.labs._fetch all

Each fetch goes into a NEW, empty folder (an old one is renamed aside, never merged), writes SOURCE.txt
(url, version, sha256 of what was downloaded, licence, date) and runs nothing it downloaded. Only public
release files are requested; nothing about this laptop or its recordings is sent anywhere.

Licences (checked 2026-11-23; each tool's own LICENSE file is kept next to it):
  YARA-Forge rule packages: each rule keeps its original licence in its `meta` (the package lists them);
      the YARA-Forge tooling itself is GPL-3.0.
  LOLBAS project data: GPL-3.0.
  Hayabusa: AGPL-3.0 (its rules, hayabusa-rules: Detection Rule License 1.1).
  Chainsaw: GPL-3.0 (its bundled Sigma rules: Detection Rule License 1.1).
"""

import hashlib
import io
import json
import os
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone

from engine.labs import _downloads

UA = "analystlab-fetch"            # a generic client name (no personal details)
SOURCES = {
    "yara": {"repo": "YARAHQ/yara-forge", "asset": "yara-forge-rules-core.zip", "sub": "yara-forge-core",
             "license": "per rule (meta.license); YARA-Forge tooling GPL-3.0"},
    "lolbas": {"url": "https://lolbas-project.github.io/api/lolbas.json", "license": "GPL-3.0 (LOLBAS project)"},
    "hayabusa": {"repo": "Yamato-Security/hayabusa", "asset_re": r"hayabusa-[\d.]+-win-x64\.zip$",
                 "license": "AGPL-3.0; rules: Detection Rule License 1.1"},
    # the "+rules" package: the binaries with the sigma/, mappings/ and rules/ folders `hunt` needs
    "chainsaw": {"repo": "WithSecureLabs/chainsaw", "asset_re": r"chainsaw_all_platforms\+rules\.zip$",
                 "license": "GPL-3.0; Sigma rules: Detection Rule License 1.1"},
}


def _get(url, accept=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **({"Accept": accept} if accept else {})})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def latest_asset(repo, name=None, pattern=None):
    """(download url, release tag) of the latest GitHub release's asset with this name / matching pattern."""
    import re
    rel = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest", "application/vnd.github+json"))
    for a in rel.get("assets", []):
        if (name and a["name"] == name) or (pattern and re.search(pattern, a["name"])):
            return a["browser_download_url"], rel.get("tag_name")
    raise SystemExit(f"{repo}: no asset {name or pattern} in release {rel.get('tag_name')}")


def _fresh(folder):
    if os.path.exists(folder):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        os.replace(folder, f"{folder}.old-{stamp}")
    os.makedirs(folder)
    return folder


def _safe_extract(blob, dest):
    """Unzip without letting any member escape `dest` (no absolute paths, no ..)."""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for m in z.infolist():
            target = os.path.abspath(os.path.join(dest, m.filename))
            if not target.startswith(os.path.abspath(dest) + os.sep):
                raise SystemExit(f"refusing a zip member outside the folder: {m.filename}")
        z.extractall(dest)


def _source_txt(folder, url, version, blob, license_):
    with open(os.path.join(folder, "SOURCE.txt"), "w", encoding="utf-8") as f:
        f.write(f"url: {url}\nversion: {version}\nsha256: {hashlib.sha256(blob).hexdigest()}\n"
                f"bytes: {len(blob)}\nlicense: {license_}\n"
                f"fetched: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")


def fetch(what, recordings=None):
    s = SOURCES[what]
    if "url" in s:
        url, version = s["url"], "latest"
    else:
        url, version = latest_asset(s["repo"], s.get("asset"), s.get("asset_re"))
    blob = _get(url)
    base = _downloads.target(what, recordings)
    folder = _fresh(os.path.join(base, s["sub"]) if s.get("sub") else base)
    if url.endswith(".zip"):
        _safe_extract(blob, folder)
    else:
        with open(os.path.join(folder, os.path.basename(url)), "wb") as f:
            f.write(blob)
    _source_txt(folder, url, version, blob, s["license"])
    print(f"{what}: {version} from {url} -> {folder} (sha256 {hashlib.sha256(blob).hexdigest()})")
    return folder


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv or argv[0] not in list(SOURCES) + ["all"]:
        raise SystemExit(__doc__)
    for w in (list(SOURCES) if argv[0] == "all" else argv[:1]):
        fetch(w)


if __name__ == "__main__":
    main()
