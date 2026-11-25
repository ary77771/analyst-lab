"""Follow-through (v4 F1, docs/plans/v4-prereg.md 5): what a FLAGGED process did next.

v3 flagged a launch and then lost the story: the flagged PowerShell's connections, the files it
saved, the programs the flagged shell started were cited by no alert (blind round 3: B14, B15,
B17). Follow-through is the industry's answer to that (EDR "storylines" / incident grouping; MITRE's
ATT&CK Evaluations grade it apart from rule detections, as "telemetry" tied to an alert): for
every RAISED alert, the later recorded actions of the process the alert is about and of the
processes it started, for a bounded time.

It is a DERIVED VIEW, never new alerts and never part of an alert's evidence:
  - `Alert.evidence` stays the rule's own trigger events (alert ids, the ART scoring and the strict
    blind verdict all read it, so they stay comparable with v3);
  - nothing is stored: `follow_through(con, alerts)` is computed when alerts are read.

Definitions (all frozen in config/frozen.yaml `follow_through`):
  - subject of an alert = the acting process of each evidence event (its ProcessGuid; for a
    process start that is the STARTED process, never its parent). Agent records (ports, hashes)
    have no process identity and give no subject.
  - family = the subject and every process descended from it (any depth).
  - followed events = Sysmon events (normal use only: not our tools, not paused) whose acting
    process is in the family, from the subject's first evidence event up to `window` seconds later,
    oldest first, at most `max_events` per alert, the alert's own evidence left out.
  - only alerts at or above the raised floor are followed (a low alert earns nothing).
  - hubs (engine/hubs.py: programs that start many different programs, e.g. the desktop shell) are
    never followed as a subject and never walked through as a descendant (their own start is kept):
    an alert on a hub must not pull the whole machine into its story. Shells are never hubs.
  - a zero GUID is "process unknown" and is never a subject or a parent.
Limits: a process that the family started through a broker (a scheduled task, WMI, a service) has
another parent in Sysmon's eyes and is not followed; an alert whose evidence is only agent records
(a listening port) or rows of our own tools has no subject and nothing to follow; `max_events` keeps
the oldest events across all of an alert's subjects (a chatty subject can crowd out another).
Protection against "everything is one incident": rows of our own tools (the scenario runner) are
neither subjects nor tree links, and hubs are not walked; an alert on a non-hub, non-lab ancestor of
a scenario WOULD reach it, which tools/check_alerts.py counts separately (review 2026-11-15).
"""

import sqlite3
from datetime import timedelta

from . import config
from .detect import LEVELS, SYSMON_CHANNEL, iso
from .graph import is_zero_guid, norm_guid, norm_path, parse_time

NORMAL = f"channel = '{SYSMON_CHANNEL}' AND COALESCE(origin, '') <> 'project' AND COALESCE(paused, 0) = 0"
_CHUNK = 500                      # ProcessGuids / keys per query (SQLite allows 32,766 variables)
DEFAULTS = {"window": 600.0, "max_events": 200}


def settings(path=config.FROZEN) -> dict:
    """config/frozen.yaml `follow_through` (window seconds, max_events), defaults filled in."""
    return {**DEFAULTS, **(config.load(path).get("follow_through") or {})}


def _when(utc, logged):
    return parse_time(utc) or parse_time(logged)


def _tree(con):
    """({(host, parent guid): [(child guid, child image)]}, built once from every process start)."""
    children = {}
    q = f"SELECT host, ProcessGuid, ParentProcessGuid, Image FROM events WHERE event_id = 1 AND {NORMAL}"
    for host, guid, pguid, image in con.execute(q):
        if guid and pguid and not is_zero_guid(guid) and not is_zero_guid(pguid):
            children.setdefault((host, norm_guid(pguid)), []).append((guid, image))   # GUID case/braces vary
    return children


def _family(children, host, subject, hubs):
    """The subject and its descendants; a hub descendant is in (its start is an action of its parent's
    story) but is not walked through."""
    seen, queue, stop = {subject}, [subject], set()
    while queue:
        g = queue.pop()
        if g in stop:
            continue
        for child, image in children.get((host, norm_guid(g)), ()):
            if child in seen:
                continue
            seen.add(child)
            if norm_path(image) in hubs:
                stop.add(child)
            queue.append(child)
    return seen, stop


def _subjects(con, alert):
    """{(host, guid): (first evidence time, image)} of the alert's evidence events."""
    out = {}
    keys = list(alert.evidence)
    for k in range(0, len(keys), _CHUNK):
        part = keys[k:k + _CHUNK]
        q = (f"SELECT host, ProcessGuid, Image, UtcTime, time FROM events WHERE {NORMAL} "
             f"AND dedup_key IN ({', '.join('?' for _ in part)})")
        for host, guid, image, utc, logged in con.execute(q, part):
            t = _when(utc, logged)
            if not guid or is_zero_guid(guid) or t is None:
                continue
            cur = out.get((host, guid))
            if cur is None:
                out[(host, guid)] = (t, image)
            else:                                   # earliest time; an image from whichever row has one
                out[(host, guid)] = (min(t, cur[0]), cur[1] or image)
    return out


def follow_through(con: sqlite3.Connection, alerts, window: float = None, max_events: int = None,
                   hubs=None, min_level: str = None) -> dict:
    """{alert_id: (dedup keys, oldest first)} for every raised alert that has something to follow
    (alerts with nothing are left out). hubs: frozenset of normalized program paths (default: the
    frozen hub list, none on a machine without one)."""
    cfg = settings()
    window = cfg["window"] if window is None else window
    max_events = cfg["max_events"] if max_events is None else max_events
    if hubs is None:
        hubs = config.hubs(allow_missing=True) or frozenset()
    floor = LEVELS.index(min_level or config.min_level())
    todo = [a for a in alerts if LEVELS.index(a.level) >= floor]
    if not todo:
        return {}
    children = _tree(con)
    out = {}
    for a in todo:
        own = set(a.evidence)
        found = {}                                  # key -> time
        for (host, guid), (t0, image) in _subjects(con, a).items():
            if norm_path(image) in hubs:
                continue
            family, stop = _family(children, host, guid, hubs)
            t1 = t0 + timedelta(seconds=window)
            lo, hi = iso(t0 - timedelta(hours=1)), iso(t1 + timedelta(hours=1))   # logged time, with slack
            members = sorted(family)
            for k in range(0, len(members), _CHUNK):
                part = members[k:k + _CHUNK]
                q = (f"SELECT dedup_key, ProcessGuid, event_id, UtcTime, time FROM events WHERE {NORMAL} "
                     f"AND host = ? AND time BETWEEN ? AND ? AND ProcessGuid IN ({', '.join('?' for _ in part)})")
                for key, g, eid, utc, logged in con.execute(q, (host, lo, hi, *part)):
                    t = _when(utc, logged)
                    if t is None or not (t0 <= t <= t1) or key in own:
                        continue
                    if g in stop and eid != 1:      # a hub descendant: only its start belongs to the story
                        continue
                    found.setdefault(key, t)
        if found:
            out[a.alert_id] = tuple(k for k, _ in sorted(found.items(), key=lambda kv: (kv[1], kv[0]))[:max_events])
    return out
