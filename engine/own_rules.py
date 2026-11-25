"""Analyst Lab rules that Sigma can't express (package B, DESIGN 4.6). Same alert format as Sigma
rules (engine/alerts.py), same exclusions (Sysmon events only, never our own tools or paused
rows), same time (when the event happened: UtcTime).

fetch_write_run: a program connects out, writes an executable file, and THAT file is started
(by anyone) within `window` seconds of the connection. Sigma's correlations can group events by
one shared value, but this needs two joins with different values (the writer's ProcessGuid for
connection -> file, the file's path for file -> start), so it is written here, in plain Python
over the store. Loopback connections (the machine talking to itself) don't count. Each start of
the file is its own alert. Known limit: an 8.3 short path (ADMINI~1) on one side and the long
path on the other don't match (as in engine/graph.py).

file_churn and lookalike_name (version 2), embedded_system_name and drop_run_delete (version 3):
see their docstrings.

new_shell_parent and new_listener: learned-normal rules (engine/baseline.py), see their docstrings.
"""

import ipaddress
import sqlite3
from datetime import timedelta

from .alerts import Alert
from .detect import SYSMON_CHANNEL, iso
from .graph import norm_path, parse_time

NORMAL = (f"channel = '{SYSMON_CHANNEL}' AND COALESCE(origin, '') <> 'project' AND COALESCE(paused, 0) = 0")
EXECUTABLE = (".exe", ".scr", ".com")
def is_loopback(ip) -> bool:
    """127.x, ::1 in any spelling, IPv4-mapped loopback (::ffff:127.0.0.1, ::ffff:7f00:1)."""
    try:
        a = ipaddress.ip_address(str(ip or "").split("%")[0].strip("[]"))
    except ValueError:
        return False
    return a.is_loopback or bool(getattr(a, "ipv4_mapped", None) and a.ipv4_mapped.is_loopback)


def _when(utc, logged):
    return parse_time(utc) or parse_time(logged)


def fetch_write_run(con: sqlite3.Connection, window: float = 60.0, level: str = "medium") -> list:
    writes = {}
    q = (f"SELECT host, ProcessGuid, TargetFilename, UtcTime, time, dedup_key FROM events "
         f"WHERE event_id = 11 AND {NORMAL} AND (" + " OR ".join("lower(TargetFilename) LIKE ?" for _ in EXECUTABLE) + ")")
    for host, guid, path, utc, logged, key in con.execute(q, [f"%{e}" for e in EXECUTABLE]):
        t = _when(utc, logged)
        if t and guid and path:
            writes.setdefault((host, norm_path(path)), []).append((t, guid, key))
    if not writes:
        return []
    alerts = []
    q = f"SELECT host, Image, UtcTime, time, dedup_key FROM events WHERE event_id = 1 AND {NORMAL}"
    for host, image, utc, logged, start_key in con.execute(q).fetchall():
        cands = writes.get((host, norm_path(image))) if image else None
        t_start = _when(utc, logged) if cands else None
        if not t_start:
            continue
        before = [w for w in cands if 0 <= (t_start - w[0]).total_seconds() <= window]
        if not before:
            continue
        for t_write, writer, write_key in sorted(before, reverse=True):
            # newest write first, but a later write by a program that didn't connect out (an
            # antivirus scan, a copier) must not hide the downloader's write (review 2026-10-23)
            conn = _last_connection(con, host, writer, t_start, t_write, window)
            if conn is not None:
                break
        if conn is None:
            continue
        t_conn, conn_key, dest = conn
        took = (t_start - t_conn).total_seconds()
        alerts.append(Alert(
            "analystlab.fetch_write_run", "Program connected out, wrote an executable, and it was started",
            "analystlab", level, iso(t_start), host or "",
            f"A program connected out, wrote an executable file {(t_write - t_conn).total_seconds():.1f} s later, "
            f"and that file was started {(t_start - t_write).total_seconds():.1f} s after being written "
            f"({took:.1f} s in all; the rule allows {window:g} s).",
            (conn_key, write_key, start_key),
            {"destination": dest, "seconds_connect_to_start": round(took, 3), "window": window},
            incident=start_key))       # one alert per start, even if more evidence arrives later
    return alerts


def _last_connection(con, host, writer, t_start, t_write, window):
    """The writer's last outgoing, non-loopback connection at most `window` s before the start
    and no later than the write."""
    best = None
    q = (f"SELECT UtcTime, time, dedup_key, DestinationIp, DestinationPort FROM events "
         f"WHERE event_id = 3 AND {NORMAL} AND host = ? AND ProcessGuid = ? AND lower(Initiated) = 'true'")
    for utc, logged, key, ip, port in con.execute(q, (host, writer)):
        t = _when(utc, logged)
        if not t or is_loopback(ip):
            continue
        if t <= t_write and (t_start - t).total_seconds() <= window and (best is None or t > best[0]):
            best = (t, key, f"{ip}:{port}")
    return best


def file_churn(con: sqlite3.Connection, window: float = 60.0, created: int = 30, deleted: int = 30,
               level: str = "medium") -> list:
    """One program creates at least `created` files AND deletes at least `deleted` files within
    `window` seconds: the "make new copies, remove the originals" shape (ransomware-like).
    Expressible in Sigma (two event_count correlations inside a temporal one), but the
    backend's SQL for that took > 10 min on 43 k events, so it is a sliding window here.
    Overlapping qualifying windows of one program are one burst = one alert. Our Sysmon config
    records file events only for executables/scripts and Downloads, Startup and \\AnalystLab\\,
    so churn elsewhere is invisible (a stated limitation)."""
    groups = {}
    q = f"SELECT host, ProcessGuid, event_id, UtcTime, time, dedup_key FROM events WHERE event_id IN (11, 26) AND {NORMAL}"
    for host, guid, eid, utc, logged, key in con.execute(q):
        t = _when(utc, logged)
        if t and guid:
            groups.setdefault((host, guid), []).append((t.timestamp(), eid, key))
    alerts = []
    for (host, guid), evs in groups.items():
        if len(evs) < created + deleted:
            continue
        evs.sort()
        bursts, n, j = [], {11: 0, 26: 0}, 0
        for i, (t, eid, _) in enumerate(evs):
            n[eid] += 1
            while t - evs[j][0] > window:
                n[evs[j][1]] -= 1
                j += 1
            if n[11] >= created and n[26] >= deleted:
                if bursts and evs[j][0] <= bursts[-1][1]:
                    bursts[-1][1] = t                       # overlaps the burst so far: extend it
                else:
                    bursts.append([evs[j][0], t, t])        # start, end, when it first qualified
        for start, end, first in bursts:
            inside = [e for e in evs if start <= e[0] <= end]
            nc, nd = sum(1 for e in inside if e[1] == 11), sum(1 for e in inside if e[1] == 26)
            alerts.append(Alert(
                "analystlab.file_churn", "One program created many files and deleted many files within a minute",
                "analystlab", level, _iso_epoch(first), host or "",
                f"One program created {nc} files and deleted {nd} files between {_iso_epoch(start)} and "
                f"{_iso_epoch(end)} (the rule needs {created} and {deleted} within {window:g} s).",
                tuple(e[2] for e in inside), {"created": nc, "deleted": nd, "window": window},
                incident=f"{guid}|{first}"))   # a burst that keeps growing stays ONE alert
    return alerts


def _iso_epoch(seconds):
    from datetime import datetime, timezone
    return iso(datetime.fromtimestamp(seconds, timezone.utc))


def new_shell_parent(con: sqlite3.Connection, baseline: dict, level: str = "medium") -> list:
    """A command shell (cmd, PowerShell, script hosts) started by a program that never started
    that shell on this machine during its learning period (engine/baseline.py). Machines without
    a baseline are skipped: without a learned normal, everything would look new."""
    from .baseline import SHELLS, base
    out = []
    q = f"SELECT host, Image, ParentImage, UtcTime, time, dedup_key FROM events WHERE event_id = 1 AND {NORMAL}"
    for host, image, parent, utc, logged, key in con.execute(q):
        shell = base(image)
        b = baseline.get(str(host).lower())
        if shell not in SHELLS or b is None:
            continue
        pair = (base(parent) or "?", shell)
        t = _when(utc, logged)
        if pair in b["shell_pairs"] or t is None:
            continue
        out.append(Alert("analystlab.new_shell_parent", "A program started a command shell it never started here before",
                         "analystlab", level, iso(t), host or "",
                         f"{pair[0]} started {shell}; on this machine {pair[0]} never started {shell} during its "
                         f"learning period ({len(b['shell_pairs'])} known program -> shell pairs).",
                         (key,), {"parent": pair[0], "shell": shell}))
    return out


def new_listener(con: sqlite3.Connection, baseline: dict, level: str = "medium",
                 loopback_level: str = "low") -> list:
    """A program opens a listening port, and that program never listened on this machine during
    its learning period (agent PORT_LISTEN_START records; Sysmon has no listening event).
    v4 (F5): a port on a loopback address (127.x, ::1) is reachable only from this machine (unless
    something forwards it), so on its own it is no door for outsiders; it gets `loopback_level`
    (low = kept and shown, not raised).
    Ports on any other address (0.0.0.0, a network card's address) keep `level`."""
    from .baseline import base
    out = []
    q = (f"SELECT host, Image, LocalIp, LocalPort, time, dedup_key FROM events WHERE type = 'PORT_LISTEN_START' "
         f"AND COALESCE(origin, '') <> 'project' AND COALESCE(paused, 0) = 0")
    for host, image, ip, port, logged, key in con.execute(q):
        b = baseline.get(str(host).lower())
        prog = base(image)
        t = parse_time(logged)
        if b is None or not prog or prog in b["listeners"] or t is None:
            continue
        local = is_loopback(ip)
        out.append(Alert("analystlab.new_listener", "A program that never listened here opened a listening port",
                         "analystlab", loopback_level if local else level, iso(t), host or "",
                         f"{prog} started listening on port {port}; it never listened on this machine during its "
                         f"learning period ({len(b['listeners'])} known listening programs)"
                         + ("; loopback address: reachable only from this machine unless something forwards it."
                            if local else "."),
                         (key,), {"program": prog, "address": f"{ip}:{port}"}))
    return out


def _stem(path):
    name = path.rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[0] if "." in name else name


# Folders inside C:\Windows that ordinary users can write to (the well-known AppLocker-bypass list,
# api0cradle/UltimateAppLockerByPassList "Generic-AppLockerbypasses"): a program there is NOT a
# Windows program; it is checked like any other, and never becomes a reference name.
WRITABLE_IN_WINDOWS = tuple("c:\\windows\\" + d + "\\" for d in (
    "tasks", "temp", "tracing", "registration\\crmlog", "debug\\wia", "pla",
    "system32\\fxstmp", "system32\\com\\dmp", "system32\\microsoft\\crypto\\rsa\\machinekeys",
    "system32\\spool\\printers", "system32\\spool\\servers", "system32\\spool\\drivers\\color",
    "system32\\tasks", "system32\\tasks_migrated",
    "syswow64\\fxstmp", "syswow64\\com\\dmp", "syswow64\\tasks"))


def lookalike_name(con: sqlite3.Connection, edits: int = 1, min_length: int = 5,
                   windows_dir: str = "c:\\windows\\", level: str = "medium", extra_references=()) -> list:
    """A program outside the Windows folder whose name is `edits` edits (Damerau-Levenshtein:
    insert, delete, replace, swap two neighbours) from a Windows program that runs on this machine,
    e.g. scvhost.exe for svchost.exe (version 2, docs/plans/v2-plan.md B1). The method is the
    published one (Schoenfeld, Red Canary 2021): count edits, not a percentage, and combine it
    with where the file sits. Reference names = programs started from the Windows folder (minus
    its user-writable folders, WRITABLE_IN_WINDOWS) on the same machine (what an attacker wants
    to hide among), at least `min_length` letters without the extension: shorter names (cmd, sc)
    are one edit from too much. Exact Windows names in the wrong folder are left to SigmaHQ's
    masquerading rules, Unicode look-alike letters to its homoglyph rules. One alert per
    program file (path text; its earliest start is the evidence). Not caught: 8.3 short names
    (SCVHOS~1.EXE), double extensions (svchost.exe.exe, a Sigma topic)."""
    from rapidfuzz.distance import DamerauLevenshtein
    windows, outside = {}, {}
    q = f"SELECT host, Image, UtcTime, time, dedup_key FROM events WHERE event_id = 1 AND {NORMAL} AND Image IS NOT NULL"
    for host, image, utc, logged, key in con.execute(q):
        p, host = norm_path(image), host or ""
        if not p:
            continue                               # an empty path must not stop the other rules (review 2026-11-07)
        if p.startswith(windows_dir) and not p.startswith(WRITABLE_IN_WINDOWS):
            windows.setdefault(host, set()).add(_stem(p))
            continue
        t = _when(utc, logged)
        if t and ((host, p) not in outside or (t, key) < outside[(host, p)]):
            outside[(host, p)] = (t, key)
    alerts = []
    for (host, p), (t, key) in sorted(outside.items()):
        stem = _stem(p)
        refs = windows.get(host, set()) | {str(r).lower() for r in extra_references}   # v3 1.7
        if stem in refs:
            continue
        near = sorted((DamerauLevenshtein.distance(stem, r), r) for r in refs
                      if len(r) >= min_length and abs(len(r) - len(stem)) <= edits)
        near = [(d, r) for d, r in near if d <= edits]
        if not near:
            continue
        d, ref = near[0]
        name = p.rsplit("\\", 1)[-1]
        alerts.append(Alert(
            "analystlab.lookalike_name", "A program's name is a small typo away from a Windows program",
            "analystlab", level, iso(t), host,
            f"{name} was started from outside the Windows folder; its name is {d} edit(s) from {ref}, "
            f"a Windows program that runs on this machine (the rule allows {edits}).",
            (key,), {"program": name, "looks_like": ref, "edits": d},
            incident=p))      # one alert per program file, even if an earlier start is loaded later
    return alerts


def _windows_refs_and_outside(con, windows_dir):
    """({host: Windows program stems}, {(host, path): (earliest start time, its dedup_key)} outside
    the Windows folder), as lookalike_name builds them."""
    windows, outside = {}, {}
    q = f"SELECT host, Image, UtcTime, time, dedup_key FROM events WHERE event_id = 1 AND {NORMAL} AND Image IS NOT NULL"
    for host, image, utc, logged, key in con.execute(q):
        p, host = norm_path(image), host or ""
        if not p:
            continue
        if p.startswith(windows_dir) and not p.startswith(WRITABLE_IN_WINDOWS):
            windows.setdefault(host, set()).add(_stem(p))
            continue
        t = _when(utc, logged)
        if t and ((host, p) not in outside or (t, key) < outside[(host, p)]):
            outside[(host, p)] = (t, key)
    return windows, outside


def embedded_system_name(con: sqlite3.Connection, min_ref_length: int = 6,
                         windows_dir: str = "c:\\windows\\", level: str = "medium", extra_references=(),
                         use_running: bool = False) -> list:
    """Version 3 (docs/plans/v3-prereg.md 1.1, 1.7, 1.8): a program started from outside the Windows
    folder whose name (without extension) CONTAINS the name of a system binary attackers imitate, plus
    at least one more character: winsvchost contains svchost. The reference names are
    `extra_references` (SigmaHQ e4a6b256's published list, frozen in config/frozen.yaml): v3 1.8
    dropped "every Windows program that ran here" (use_running) because ordinary names contain them
    (notepad++ contains notepad; vendor companions of DriverStore programs), and because a short run
    window may hold no start of the real program. Extends lookalike_name (small typos) and SigmaHQ's
    masquerading rules (exact names in the wrong folder). Reference names need `min_ref_length`
    letters. One alert per program file. A name that is also one edit from a reference raises
    lookalike_name too (two alerts on one file; scoring counts flagged steps, not alerts)."""
    listed = {str(r).lower() for r in extra_references}
    if not listed and not use_running:
        raise ValueError("embedded_system_name needs its reference names (config/frozen.yaml extra_references)")
    windows, outside = _windows_refs_and_outside(con, windows_dir)
    alerts = []
    for (host, p), (t, key) in sorted(outside.items()):
        stem = _stem(p)
        if stem in listed:              # an exact listed name in the wrong folder: SigmaHQ e4a6b256's own case
            continue
        refs = (windows.get(host, set()) | listed) if use_running else listed      # v3 1.8: the list only
        inside = sorted((r for r in refs if len(r) >= min_ref_length and r != stem and r in stem),
                        key=lambda r: (-len(r), r))
        if not inside:                  # (the exact Windows name is excluded by r != stem: SigmaHQ's case)
            continue
        ref, name = inside[0], p.rsplit("\\", 1)[-1]
        alerts.append(Alert(
            "analystlab.embedded_system_name", "A program's name hides a Windows program's name",
            "analystlab", level, iso(t), host,
            f"{name} was started from outside the Windows folder; its name contains {ref}, a Windows "
            f"program that runs on this machine.",
            (key,), {"program": name, "contains": ref}, incident=p))
    return alerts


def drop_run_delete(con: sqlite3.Connection, run_window: float = 300.0, delete_window: float = 900.0,
                    writers: str = "any", level: str = "medium") -> list:
    """Version 3 (docs/plans/v3-prereg.md 1.2), a story-shaped rule: a process writes an executable,
    the file is started within `run_window` s, the started process connects out (non-loopback),
    and the file is deleted within `delete_window` s of the start. The chain the evidence graph
    draws as facts (created, start from that file, connected_to, deleted), asked for as a whole.
    writers = "any" (variant A) or "shells" (variant B: the writer is a shell / script host).
    The connection may come before or after the deletion (a program may delete its own file while it
    runs), anywhere from the start to start + delete_window (v3 1.8). Connections count only to
    ordinary unicast addresses (not loopback, link-local, multicast; the beacon rule's notion).
    One alert per start (one story started twice = two alerts); evidence = write, start, first
    connection, deletion. Not caught: 8.3 short paths on one side, the connection made by a CHILD of
    the started program, a drop by rename (.tmp -> .exe gives no event 11 for the .exe), non-ASCII
    names that SQLite's ASCII-only lower() spells differently. Known false-alarm shapes: build tools
    that write, run and delete a temporary program that connects out (go run / go test), installer
    and updater stubs."""
    from .baseline import SHELLS, base
    writes = {}
    q = (f"SELECT host, ProcessGuid, Image, TargetFilename, UtcTime, time, dedup_key FROM events "
         f"WHERE event_id = 11 AND {NORMAL} AND (" + " OR ".join("lower(TargetFilename) LIKE ?" for _ in EXECUTABLE) + ")")
    for host, guid, image, path, utc, logged, key in con.execute(q, [f"%{e}" for e in EXECUTABLE]):
        t = _when(utc, logged)
        if t and path and (writers == "any" or base(image) in SHELLS):
            writes.setdefault((host, norm_path(path)), []).append((t, key))
    if not writes:
        return []
    deletes = {}
    q = f"SELECT host, TargetFilename, UtcTime, time, dedup_key FROM events WHERE event_id = 26 AND {NORMAL}"
    for host, path, utc, logged, key in con.execute(q):
        t = _when(utc, logged)
        if t and path and (host, norm_path(path)) in writes:
            deletes.setdefault((host, norm_path(path)), []).append((t, key))
    alerts = []
    q = f"SELECT host, Image, ProcessGuid, UtcTime, time, dedup_key FROM events WHERE event_id = 1 AND {NORMAL}"
    for host, image, guid, utc, logged, start_key in con.execute(q).fetchall():
        p = norm_path(image) if image else None
        if not p or (host, p) not in writes or (host, p) not in deletes or not guid:
            continue
        t_start = _when(utc, logged)
        if not t_start:
            continue
        before = [w for w in writes[(host, p)] if 0 <= (t_start - w[0]).total_seconds() <= run_window]
        after = sorted(d for d in deletes[(host, p)] if 0 < (d[0] - t_start).total_seconds() <= delete_window)
        if not before or not after:
            continue
        conn = _first_connection(con, host, guid, t_start, t_start + timedelta(seconds=delete_window))
        if conn is None:
            continue
        t_write, write_key = max(before)
        t_conn, conn_key, dest = conn
        t_del, del_key = after[0]
        alerts.append(Alert(
            "analystlab.drop_run_delete", "A program was written, run, connected out, and deleted again",
            "analystlab", level, iso(max(t_del, t_conn)), host or "",     # when the whole chain was complete
            f"An executable was written, started {(t_start - t_write).total_seconds():.1f} s later, connected out "
            f"{(t_conn - t_start).total_seconds():.1f} s after starting, and its file was deleted "
            f"{(t_del - t_start).total_seconds():.1f} s after the start (the rule allows {run_window:g} s and "
            f"{delete_window:g} s).",
            (write_key, start_key, conn_key, del_key),
            {"destination": dest, "writers": writers}, incident=start_key))
    return alerts


def _ordinary_destination(ip) -> bool:
    """A real other party: exactly engine/beacon.is_unicast's judgement (not loopback, link-local,
    multicast, unspecified or broadcast, an IPv4 .255 counting as a subnet broadcast), so the two
    rules never disagree (v3 reviews 2026-11-14). (Imported here: beacon imports this module.)"""
    from .beacon import is_unicast
    return is_unicast(str(ip or "").split("%")[0].strip("[]"))


def _first_connection(con, host, guid, t_start, t_end):
    """The process's first outgoing connection to an ordinary destination between its start and t_end."""
    best = None
    q = (f"SELECT UtcTime, time, dedup_key, DestinationIp, DestinationPort FROM events "
         f"WHERE event_id = 3 AND {NORMAL} AND host = ? AND ProcessGuid = ? AND lower(Initiated) = 'true'")
    for utc, logged, key, ip, port in con.execute(q, (host, guid)):
        t = _when(utc, logged)
        if not t or not _ordinary_destination(ip) or not (t_start <= t <= t_end):
            continue
        if best is None or t < best[0]:
            best = (t, key, f"{ip}:{port}")
    return best


def create_send_wipe(con: sqlite3.Connection, baseline: dict, **settings) -> list:
    """Version 4 (F3), LEARNED-NORMAL like new_listener: the episodes of wipe_episodes (below),
    only for programs that never did this on the machine during its learning period (baseline
    "wipers", engine/baseline.learn_wipers). A machine without a baseline gets no alerts.
    Why (2026-11-15): on the laptop's 29 learn days the plain rule raised 65 medium alerts (about
    2 a day), all ordinary programs updating themselves (download, unpack, phone home, delete their
    temp files); learned per program, a simulated test week (learn <= 11-07, test 11-08..11-14) went
    from 6 to 0. Known limit (as the other learned rules): learned by program NAME, so code hiding
    inside a program that normally does this (an updater, svchost.exe) is not flagged."""
    from .baseline import base
    out = []
    for a in wipe_episodes(con, **settings):
        b = baseline.get(str(a.host).lower())
        prog = base(a.details.get("program"))
        if b is None or (prog not in NEVER_NORMAL_WIPERS and prog in b.get("wipers", ())):
            continue
        out.append(a)
    return out


# Never learned as normal and never silenced (review 2026-11-15): shells and script hosts (the
# attacker's most likely tools; the laptop's learn period had powershell.exe doing this) and
# creators whose program is unknown (one learned "?" would silence every unknown creator).
from .baseline import SHELLS  # noqa: E402  (baseline imports nothing from here at load time)
NEVER_NORMAL_WIPERS = tuple(SHELLS) + ("?", "<unknown process>")


def wipe_episodes(con: sqlite3.Connection, min_files: int = 3, window: float = 900.0,
                  level: str = "medium", level_without_connection: str = "low",
                  max_connections: int = 20) -> list:
    """Version 4 (F3, docs/plans/v4-prereg.md 5), self-cleanup in one episode: within `window` s
    (from the first creation to the deletion that completes the set) a process creates at least
    `min_files` different files that are deleted again by that process or by a process it started
    directly (`cmd /c del ...`). `level` if the process (or such a child) connected out to an ordinary
    destination inside that same span (stage, send, wipe: ATT&CK T1074, T1041, T1070.004), otherwise
    `level_without_connection` (installers and builds clean up their own temp files too).
    No published rule covers this sequence (closest: Elastic's EQL "Process Termination followed by
    Deletion", deprecated); it needs per-file create -> delete joins plus a process-tree join, so it is
    plain Python like drop_run_delete. A deletion is matched to the LATEST creation of that path
    before it (whoever made it). One alert per creating process: its first episode with a connection,
    else its first episode; time = when that episode first qualifies; evidence = every create/delete
    pair of the episode (made at or after its first creation and deleted within `window` s of it, as
    file_churn keeps a growing burst as one alert; a path made and wiped twice counts once as a file,
    both pairs are evidence) plus up to `max_connections` connections inside that span. Review 2026-11-14: bounded episode (a browser
    must not collect a "set" over days), zero GUIDs skipped (parent unknown), children looked up once,
    connections fetched in chunks (SQLite's variable limit) and by time.
    Limits: Sysmon records file events only for executables/scripts and in Downloads, Startup and
    \\AnalystLab\\ (staging elsewhere is invisible); a deletion by a grandchild or by the parent, a
    rename instead of a delete, and an upload by an unrelated program are not seen."""
    from .baseline import base
    from .graph import ZERO_GUID
    parent, children = {}, {}
    q = f"SELECT host, ProcessGuid, ParentProcessGuid FROM events WHERE event_id = 1 AND {NORMAL}"
    for host, guid, pguid in con.execute(q):
        if guid and pguid and ZERO_GUID not in (guid, pguid):
            parent[(host, guid)] = pguid
            children.setdefault((host, pguid), []).append(guid)
    created, program = {}, {}                      # (host, path) -> [(t, creator guid, key)]; (host, guid) -> Image
    q = (f"SELECT host, ProcessGuid, Image, TargetFilename, UtcTime, time, dedup_key FROM events "
         f"WHERE event_id = 11 AND {NORMAL}")
    for host, guid, image, path, utc, logged, key in con.execute(q):
        t = _when(utc, logged)
        if t and guid and guid != ZERO_GUID and path:
            created.setdefault((host, norm_path(path)), []).append((t, guid, key))
            if image:
                program[(host, guid)] = image      # the creator's own program (event 11 names it)
    if not created:
        return []
    cycles = {}                                    # (host, creator) -> [(t_create, t_delete, ckey, dkey, path)]
    q = f"SELECT host, ProcessGuid, TargetFilename, UtcTime, time, dedup_key FROM events WHERE event_id = 26 AND {NORMAL}"
    for host, dguid, path, utc, logged, dkey in con.execute(q):
        t_del = _when(utc, logged)
        p = norm_path(path) if path else None
        if not t_del or not dguid or dguid == ZERO_GUID or (host, p) not in created:
            continue
        before = [c for c in created[(host, p)] if 0 <= (t_del - c[0]).total_seconds() <= window]
        if not before:
            continue
        t_c, creator, ckey = max(before)           # the latest creation of that path before the delete
        if dguid == creator or parent.get((host, dguid)) == creator:       # itself or its direct child
            cycles.setdefault((host, creator), []).append((t_c, t_del, ckey, dkey, p))
    alerts = []
    for (host, creator), items in cycles.items():
        if len({it[4] for it in items}) < min_files:
            continue
        items.sort(key=lambda x: (x[1], x[0]))
        family = [creator] + children.get((host, creator), [])
        conns = _connections_between(con, host, family, min(it[0] for it in items), items[-1][1])
        found, j = None, 0
        for i in range(len(items)):                # each deletion, in order, as the possible completion
            t_end = items[i][1]
            lo = t_end - timedelta(seconds=window)
            while items[j][1] < lo:                # deleted before the span began: cannot be inside it
                j += 1
            members = [it for it in items[j:i + 1] if it[0] >= lo]
            if len({it[4] for it in members}) < min_files:
                continue
            t0 = min(it[0] for it in members)
            inside = [c for c in conns if t0 <= c[0] <= t_end]
            if inside:
                found = (True, t_end, members, inside)
                break
            if found is None:
                found = (False, t_end, members, [])
        if found is None:
            continue
        with_conn, when, members, inside = found
        t0 = min(it[0] for it in members)          # the episode = every pair inside [t0, t0 + window] (as
        members = [it for it in items if it[0] >= t0 and (it[1] - t0).total_seconds() <= window]   # file_churn's
        if with_conn:                              # growing burst: time = when it first qualified)
            inside = [c for c in conns if t0 <= c[0] <= max(it[1] for it in members)]
        n_files = len({it[4] for it in members})
        dests = sorted({c[2] for c in inside})
        alerts.append(Alert(
            "analystlab.create_send_wipe",
            "A program created files and deleted them again" + (", after connecting out" if with_conn else ""),
            "analystlab", level if with_conn else level_without_connection, iso(when), host or "",
            f"Within {window:g} s one program created {n_files} files that it (or a program it started) "
            f"deleted again"
            + (f"; in between it connected out {len(inside)} time(s) to {', '.join(dests[:3])}"
               f"{' and more' if len(dests) > 3 else ''}." if with_conn else "; it made no outgoing connection in between."),
            tuple(k for it in members for k in (it[2], it[3])) + tuple(c[1] for c in inside[:max_connections]),
            {"files": n_files, "connections": len(inside), "destinations": dests[:10],
             "program": base(program.get((host, creator))) or "?"},
            incident=f"{host}|{creator}"))
    return alerts


_CHUNK = 500                                       # ProcessGuids per query (SQLite allows 32,766 variables)


def _connections_between(con, host, guids, t0, t1):
    """Outgoing connections to ordinary destinations by any of `guids` between t0 and t1 (when they
    happened), oldest first. The logged time bounds the query with an hour's slack either side."""
    out = []
    lo, hi = iso(t0 - timedelta(hours=1)), iso(t1 + timedelta(hours=1))
    for k in range(0, len(guids), _CHUNK):
        part = guids[k:k + _CHUNK]
        q = (f"SELECT UtcTime, time, dedup_key, DestinationIp, DestinationPort FROM events "
             f"WHERE event_id = 3 AND {NORMAL} AND host = ? AND lower(Initiated) = 'true' "
             f"AND time BETWEEN ? AND ? AND ProcessGuid IN ({', '.join('?' for _ in part)})")
        for utc, logged, key, ip, port in con.execute(q, (host, lo, hi, *part)):
            t = _when(utc, logged)
            if t and t0 <= t <= t1 and _ordinary_destination(ip):
                out.append((t, key, f"{ip}:{port}"))
    return sorted(out)


RULES = {"analystlab.fetch_write_run": fetch_write_run, "analystlab.file_churn": file_churn,
         "analystlab.lookalike_name": lookalike_name,
         "analystlab.embedded_system_name": embedded_system_name, "analystlab.drop_run_delete": drop_run_delete}
BASELINE_RULES = {"analystlab.new_shell_parent": new_shell_parent, "analystlab.new_listener": new_listener,
                  "analystlab.create_send_wipe": create_send_wipe}


def run_all(con, params=None, baseline=None) -> list:
    """Every own rule; params = {rule_id: {argument: value}} (from config/frozen.yaml own_rules).
    baseline = engine.baseline.load(...) result; without one the learned-normal rules (BASELINE_RULES) are skipped."""
    from .config import own_rule_params      # the chosen numbers live in config/frozen.yaml (own_rules:)
    # v3: settings given for some rules override the frozen ones for THOSE rules; every other rule keeps
    # its frozen settings (before, a partial dict silently left e.g. the name rules without their list)
    params = {**own_rule_params(), **(params or {})}
    out = []
    for rid, fn in RULES.items():
        out.extend(fn(con, **((params or {}).get(rid) or {})))
    if baseline:
        for rid, fn in BASELINE_RULES.items():
            out.extend(fn(con, baseline, **((params or {}).get(rid) or {})))
    return out
