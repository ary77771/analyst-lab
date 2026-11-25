"""Shared by the night-tools labs (fileinspect, yara): which files the recording mentions, and which of
them we have a copy of on THIS laptop that is provably the same content.

The leading underscore keeps this helper out of the Labs discovery (it has no router on purpose).

How a recorded file is linked to a file on this disk (honest by construction):
  "sha256"  the recording holds the file's SHA-256 (Sysmon `Hashes` of a started program, or the agent's
            FILE_HASH of a written file) and a local file has exactly that SHA-256: the same content.
  "path"    the event came from this very laptop and the file is still at the recorded path; if the
            recording also holds a SHA-256 and the file's differs, it is "changed" and NOT inspected.
  "name"    only a file with the same name exists here (content unknown or different): listed, never
            inspected as if it were the recorded file.
  None      no copy here (e.g. a file that only ever existed inside the test machine).

Local copies are looked for in the lab's own folders (the test programs and the test server's files),
never in a scan of the whole disk. Addresses of files are their SHA-256 (or a short id), never a path the
browser sends: the dashboard can be reached from the test machine, so a path from a request is not trusted.
"""

import glob
import hashlib
import json
import os
import re
import socket
import sqlite3
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_ROOT = os.path.dirname(os.path.dirname(HERE))          # the checkout this code runs from
MAX_HASH_BYTES = 512 * 1024 * 1024                          # files larger than this are not hashed
ENV_DIRS = "ANALYSTLAB_LAB_FILES"                           # os.pathsep-separated folders (an override)
ENV_ROOTS = "ANALYSTLAB_LAB_ROOTS"                          # more checkouts to look in (their scenarios/, build/)
LAB_SUBDIRS = (("scenarios", "bin"), ("scenarios", "www"), ("build", "run", "cd"))   # build/run/cd = the run CD
WARM_SESSIONS = 3                                          # the newest warm-machine sessions' CDs are indexed
LIST_CAP = 1500                                           # at most this many recorded files are listed

# a written file is worth listing when it is a program or a script (like agent/filetypes.should_hash)
EXEC_EXT = re.compile(r"\.(exe|dll|sys|scr|cpl|ocx|com|msi|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|jar|py)$", re.I)

_lock = threading.Lock()
_hash_cache = {}                                            # (path, size, mtime_ns) -> sha256
# kept between dashboard starts (lab files only: content fingerprints of our own test programs)
CACHE_FILE = os.path.join(tempfile.gettempdir(), "analystlab-labfiles-sha256.json")
_disk = {"loaded": False, "dirty": False}


def _load_disk_cache():
    if _disk["loaded"]:
        return
    _disk["loaded"] = True
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            for row in json.load(f):
                _hash_cache[(row[0], row[1], row[2])] = row[3]
    except (OSError, ValueError, IndexError, TypeError):
        pass


def _save_disk_cache():
    if not _disk["dirty"]:
        return
    try:
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([[k[0], k[1], k[2], v] for k, v in _hash_cache.items() if _is_lab_key(k)], f)
        os.replace(tmp, CACHE_FILE)
        _disk["dirty"] = False
    except OSError:
        pass


_lab_prefixes = set()


def _is_lab_key(k):
    return any(k[0].lower().startswith(p) for p in _lab_prefixes)


def sha256_of(path):
    """SHA-256 of a file (cached by path+size+mtime), or None when it can't be read or is too large."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not os.path.isfile(path) or st.st_size > MAX_HASH_BYTES:
        return None
    key = (os.path.abspath(path), st.st_size, st.st_mtime_ns)
    with _lock:
        if key in _hash_cache:
            return _hash_cache[key]
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    digest = h.hexdigest()
    with _lock:
        _hash_cache[key] = digest
        _disk["dirty"] = True
    return digest


def lab_dirs(recordings=None):
    """The folders holding the lab's own test files: ANALYSTLAB_LAB_FILES if set, else scenarios/bin,
    scenarios/www (and the run-CD staging folders) next to the recordings folder and next to this code."""
    env = os.environ.get(ENV_DIRS)
    if env:
        roots, subs = [p for p in env.split(os.pathsep) if p], [()]
    else:
        roots = [CODE_ROOT] + [p for p in os.environ.get(ENV_ROOTS, "").split(os.pathsep) if p]
        if recordings:
            roots.insert(0, os.path.dirname(os.path.abspath(recordings)))
        subs = LAB_SUBDIRS
    out, seen = [], set()

    def add(d):
        d = os.path.abspath(d)
        if d.lower() not in seen and os.path.isdir(d):
            seen.add(d.lower())
            out.append(d)

    for r in roots:
        for s in subs:
            add(os.path.join(r, *s))
        if not env:
            # the warm test machine's CDs: build/warm/<session>/warm/cd and .../<test>/cd (newest sessions)
            sessions = sorted(glob.glob(os.path.join(r, "build", "warm", "*")), reverse=True)[:WARM_SESSIONS]
            for sess in sessions:
                for d in sorted(glob.glob(os.path.join(sess, "*", "cd"))):
                    add(d)
    # NOT the blind rounds' folders: a sealed round placed there must never become browsable in Labs
    return out


# --- which machines a lab shows (night rule 11): ONLY what the dashboard's Labs context allows ----------------
def vm_hosts():
    from engine.dashboard.demo_mode import VM_HOSTS
    return {h.lower() for h in VM_HOSTS}


def allowed_hosts():
    """The machines a lab may show: `labs.context().hosts` (the test machine by default; None = every machine,
    only on a dashboard started with --labs-all-hosts). Without a running dashboard: the test machine only."""
    from engine import labs
    try:
        ctx = labs.context()
    except RuntimeError:
        return frozenset(vm_hosts())
    return None if ctx.hosts is None else frozenset(h.lower() for h in ctx.hosts)


def laptop_allowed():
    return allowed_hosts() is None


def host_clause():
    """(" AND lower(host) IN (?, ...)", params) for SQL over an events table (also a replay store's, which the
    context's own view does not cover); ("", ()) when every machine is allowed."""
    hosts = allowed_hosts()
    if hosts is None:
        return "", ()
    names = sorted(hosts)
    return (f" AND lower(host) IN ({', '.join('?' for _ in names)})" if names else " AND 0=1"), tuple(names)


def host_shown(host):
    hosts = allowed_hosts()
    return hosts is None or (host or "").lower() in hosts


def local_index(dirs, max_files=1200):
    """{sha256: path} and {lower-case name: [paths]} of the files in the lab folders (two levels deep)."""
    by_sha, by_name, n = {}, {}, 0
    with _lock:
        _load_disk_cache()
        _lab_prefixes.update(os.path.abspath(d).lower() for d in dirs)
    try:
        for d in dirs:
            for root, sub, files in os.walk(d):
                if os.path.relpath(root, d).count(os.sep) >= 1:
                    sub[:] = []
                for f in sorted(files):
                    if n >= max_files:
                        return by_sha, by_name
                    p = os.path.join(root, f)
                    sha = sha256_of(p)
                    if sha:
                        by_sha.setdefault(sha, p)
                        by_name.setdefault(f.lower(), []).append(p)
                        n += 1
        return by_sha, by_name
    finally:
        with _lock:
            _save_disk_cache()


def _sha_from_hashes(text):
    """The SHA256 part of a Sysmon `Hashes` value ("SHA256=ABC..,MD5=.."), lower case, or None."""
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", text or "")
    return m.group(1).lower() if m else None


def _basename(path):
    return re.split(r"[\\/]", path or "")[-1]


def this_machine():
    return socket.gethostname().lower()


def recorded_files(con):
    """Every program started (event 1) and every program/script written (FILE_HASH, event 11) in the store:
    [{host, path, sha256|None, kind, first, last, times}] grouped by host + content (or host + path)."""
    cols = {r[1].lower() for r in con.execute("PRAGMA table_info(events)")}
    groups = {}

    def add(host, path, sha, kind, t):
        if not path or not host_shown(host):
            return
        key = (host, sha) if sha else (host, path.lower())
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"host": host, "path": path, "sha256": sha, "kinds": set(), "first": t, "last": t,
                               "times": 0, "paths": set()}
        g["kinds"].add(kind)
        g["paths"].add(path)
        g["times"] += 1
        if t and (g["first"] is None or t < g["first"]):
            g["first"] = t
        if t and (g["last"] is None or t > g["last"]):
            g["last"] = t

    hw, hp = host_clause()
    try:
        for host, image, hashes, t in con.execute(
                f"SELECT host, Image, Hashes, time FROM events WHERE event_id = 1 AND Image IS NOT NULL{hw}", hp):
            add(host, image, _sha_from_hashes(hashes), "started", t)
        fp = "final_path" if "final_path" in cols else "NULL"
        for host, path, final, sha, status, t in con.execute(
                f"SELECT host, TargetFilename, {fp}, sha256, hash_status, time FROM events WHERE type = 'FILE_HASH'{hw}", hp):
            if status == "directory":
                continue
            add(host, final or path, (sha or "").lower() or None if status in (None, "ok") else None, "written", t)
        for host, path, t in con.execute(
                f"SELECT host, TargetFilename, time FROM events WHERE event_id = 11 AND TargetFilename IS NOT NULL{hw}", hp):
            if EXEC_EXT.search(path):
                add(host, path, None, "written", t)
    except sqlite3.OperationalError:
        return []
    # a written file without a fingerprint whose path also has a fingerprinted row: keep only the latter
    with_sha = {(g["host"], p.lower()) for g in groups.values() if g["sha256"] for p in g["paths"]}
    out = [g for k, g in groups.items() if g["sha256"] or (g["host"], g["path"].lower()) not in with_sha]
    out.sort(key=lambda g: g["last"] or "", reverse=True)
    return out[:LIST_CAP]


def file_id(host, path, sha):
    return sha if sha else "p" + hashlib.sha1(f"{host}|{(path or '').lower()}".encode("utf-8", "replace")).hexdigest()[:20]


def catalogue(con, recordings=None, machine=None):
    """The list a lab page shows: recorded files (linked to a local copy where provable) plus the lab's own
    test files that the recording does not mention. Each item has an `id` the browser sends back."""
    machine = (machine or this_machine()).lower()
    by_sha, by_name = local_index(lab_dirs(recordings))
    items, used = [], set()
    for g in (recorded_files(con) if con is not None else []):
        sha, local, match = g["sha256"], None, None
        if sha and sha in by_sha:
            local, match = by_sha[sha], "sha256"
        elif (g["host"] or "").lower() == machine and os.path.isfile(g["path"]):
            # still at its place on this laptop: the content is compared when the file is opened (resolve_local),
            # not here, so listing a big laptop store does not read every program on the disk
            local, match = g["path"], "path"
        if match is None and _basename(g["path"]).lower() in by_name:
            # a lab copy with the same name but not the recorded content: it may be opened, always labelled as
            # the lab's current copy (never as the file that ran); its own fingerprint is shown, not the recorded one
            match = "name"
            local = sorted(by_name[_basename(g["path"]).lower()], key=lambda q: -os.path.getmtime(q))[0]
        if local:
            used.add(os.path.abspath(local).lower())   # (a lookalike's copy too: never listed twice, critique-2 #17)
        items.append({"id": file_id(g["host"], g["path"], g["sha256"]), "name": _basename(g["path"]),
                      "recorded_path": g["path"], "host": g["host"], "sha256": sha, "kinds": sorted(g["kinds"]),
                      "first": g["first"], "last": g["last"], "times": g["times"], "match": match,
                      "local": local, "inspectable": bool(local),
                      # EVIDENCE = the exact content that ran: an exact SHA-256 match, or the unchanged file at its
                      # recorded place on this laptop. A same-name rebuild ("name") is never evidence.
                      "evidence": match in ("sha256", "path")})
    for sha, p in sorted(by_sha.items(), key=lambda kv: kv[1].lower()):
        if os.path.abspath(p).lower() in used or not EXEC_EXT.search(p):
            continue                       # only programs and scripts of the lab are listed (no notes, no logs)
        items.append({"id": sha, "name": os.path.basename(p), "recorded_path": None, "host": None, "sha256": sha,
                      "kinds": ["lab file"], "first": None, "last": None, "times": 0, "match": "lab", "evidence": False,
                      "local": p, "inspectable": True})
    return items


def resolve(items, file_id_):
    """The catalogue item with this id, or None. A "path" item (a laptop file at its recorded place) is checked
    here: when the recording holds a SHA-256 and the file's differs now, it becomes "changed" (not inspectable)."""
    item = next((i for i in items if i["id"] == file_id_), None)
    if item and item["match"] == "path":
        now = sha256_of(item["local"])
        if now is None or (item["sha256"] and now != item["sha256"]):
            item = {**item, "match": "changed", "local": None, "inspectable": False, "evidence": False}
        elif not item["sha256"]:
            item = {**item, "sha256": now}
    return item


def ctx_catalogue(ctx):
    """catalogue() over a Labs context (the store may be missing: then only the lab's own files)."""
    try:
        with ctx.reading() as con:
            return catalogue(con, getattr(ctx, "recordings", None))
    except (FileNotFoundError, sqlite3.OperationalError):
        return catalogue(None, getattr(ctx, "recordings", None))


# --- one alert's own programs and files (wave 3: the alert travels through the labs) -------------------------
NOT_IN_RECORDING = "This alert isn't in this recording."
NOT_YET = "The replay hasn't reached this alert yet; it will appear in a few seconds."
REPLAY_FRESH_S = 60          # a replay whose feed or stores were written this recently is still playing


class NotYet(LookupError):
    """The alert is not in the store yet, and the store is a replay that is still playing."""


def replay_playing(ctx, now=None):
    """Is this store a replay that is still playing? A replay (tools/demo_replay.py, demo/dash_rehearse.py) keeps
    its store next to the `feed` folder it plays into; while it plays, the feed and the stores are written every
    few seconds (quiet gaps are capped at 5 s). A live or batch store has no feed folder: always False."""
    db = getattr(ctx, "events_db", None)
    if not db:
        return False
    feed = os.path.join(os.path.dirname(os.path.abspath(db)), "feed")
    if not os.path.isdir(feed):
        return False
    paths = [os.path.join(feed, n) for n in os.listdir(feed)] + [db, getattr(ctx, "alerts_db", None) or ""]
    times = [os.path.getmtime(p) for p in paths if p and os.path.isfile(p)]
    return bool(times) and ((now or time.time()) - max(times)) < REPLAY_FRESH_S


def alert_scope(ctx, alert_id):
    """What an alert's own story names, from the report the Story screen tells: {alert, host, guids (lower case),
    paths (lower case), shas}. Programs come with their image path and SHA-256 from their start event. Raises
    LookupError when the alert is not in this recording (or not on an allowed machine); NotYet (a LookupError)
    when it is not there YET because the store is a replay still playing (right after a dashboard restart)."""
    a = ctx.alert(alert_id)
    if a is None and replay_playing(ctx):
        raise NotYet(NOT_YET)
    if a is None or not ctx.allows(a.host):
        raise LookupError(NOT_IN_RECORDING)
    rep = ctx.report(a) or {}
    guids, paths, shas = set(), set(), set()
    for f in rep.get("facts") or []:
        for node in (f.get("u"), f.get("v")):
            m = re.match(r"^proc:[^:]+:(\{[0-9A-Fa-f-]+\})$", node or "")
            if m:
                guids.add(m.group(1).lower())
                continue
            m = re.match(r"^file:[^:]+:(.+?)(?:\|([0-9A-Fa-f]{64}))?$", node or "")
            if m:
                paths.add(m.group(1).lower())
                if m.group(2):
                    shas.add(m.group(2).lower())
    if guids:
        q = ",".join("?" for _ in guids)
        try:
            with ctx.reading() as con:
                for image, hashes in con.execute(f"SELECT Image, Hashes FROM events WHERE event_id = 1 AND "
                                                 f"lower(ProcessGuid) IN ({q})", sorted(guids)):
                    if image:
                        paths.add(image.lower())
                    s = _sha_from_hashes(hashes)
                    if s:
                        shas.add(s)
        except (FileNotFoundError, sqlite3.OperationalError):
            pass
    return {"alert": {"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time, "host": a.host},
            "host": a.host, "guids": guids, "paths": paths, "shas": shas}


def in_scope(item, scope):
    """Is a catalogue item one of the alert's own programs or files (same SHA-256, or same machine and path)?"""
    if item.get("sha256") and item["sha256"] in scope["shas"]:
        return True
    return bool(item.get("recorded_path")) and (item.get("host") or "").lower() == (scope["host"] or "").lower() \
        and item["recorded_path"].lower() in scope["paths"]

