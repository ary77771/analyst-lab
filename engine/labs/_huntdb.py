"""Shared helpers for the threat-hunting Labs pages (night-hunt): hunts, rarity, persistence,
network, gaps. No router here: this file only reads.

Everything here READS the event store (engine/store.py) and never writes:
- the store is opened with SQLite's read-only mode (`mode=ro`), the same way the dashboard does;
- every query is bounded by a time window anchored to the store's NEWEST event (not the wall
  clock: replay stores are weeks old), because a laptop store can be several GB;
- a store may lack columns (a store recorded before the registry config has no TargetObject):
  callers ask `has()` first and say "not recorded" instead of failing;
- VM DATA ONLY by default (night rule 11): every query is limited to the machines the running
  dashboard allows (`labs.context().hosts`: the test machine only, unless the dashboard was started
  with --labs-all-hosts, which the dashboard announces at start-up). There is no other switch: no
  environment variable, nothing in the page. Without a running dashboard: the lab VM's names
  (engine.dashboard.demo_mode.VM_HOSTS), never every machine.
"""

import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

SYSMON = "Microsoft-Windows-Sysmon/Operational"
ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
# rows of the lab's own programs (origin 'project') and rows recorded during a user pause
# (number/time/type only) are left out of every hunt unless asked for
OWN_FILTER = "(origin IS NULL OR origin != 'project') AND COALESCE(paused, 0) = 0"
WINDOWS = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24),
           "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None}
DEFAULT_WINDOW = "24h"
FALLBACK_VM_HOSTS = frozenset({"analystlab-vm"})


def _running_context():
    """The dashboard's Labs context when one runs in this process, else None."""
    try:
        from engine import labs                                    # noqa: PLC0415
        return labs.context()
    except Exception:
        return None


def allowed_hosts():
    """The hosts these pages may show: exactly the running dashboard's `ctx.hosts` (the test machine
    only, unless it was started with --labs-all-hosts). Without a dashboard: the lab VM's names."""
    ctx = _running_context()
    if ctx is not None and hasattr(ctx, "hosts"):
        return ctx.hosts
    try:
        from engine.dashboard.demo_mode import VM_HOSTS          # noqa: PLC0415  (read when asked, never at import)
        return frozenset(VM_HOSTS)
    except Exception:
        return FALLBACK_VM_HOSTS


def scope_sql(col="host"):
    """(' AND host IN (?, ...)', params) for the allowed hosts that have rows in the store; ' AND 0' when none
    has (SQLite answers that at once, before reading a row); ('', []) when every host is allowed."""
    allowed = allowed_hosts()
    if allowed is None:
        return "", []
    present = present_hosts(allowed)
    if not present:
        return " AND 0", []
    return f" AND {col} IN ({','.join('?' for _ in present)})", sorted(present)


_PRESENT = {}                     # (store file, newest row id, allowed hosts) -> the allowed hosts with rows


def _keys_start_with_host(con):
    """The guard of present_hosts: the oldest and newest rows' dedup_key start with '<their host>|' (checked row by
    row on the laptop store, demo-1101, vm-all, vm-to-1114 and the S1 replay: 0 of 2.3 million rows differ). A store
    keyed otherwise must not lose its rows: it keeps the slow way."""
    rows = con.execute("SELECT host, dedup_key FROM (SELECT host, dedup_key FROM events ORDER BY id LIMIT 1) "
                       "UNION ALL SELECT host, dedup_key FROM (SELECT host, dedup_key FROM events ORDER BY id DESC LIMIT 1)").fetchall()
    return all(h is not None and str(k or "").startswith(f"{h}|") for h, k in rows)


def present_hosts(allowed, path=None):
    """The allowed hosts that have at least one row in the dashboard's store. Speed audit (2026-11-24): there is
    no index on `host`, so `host IN (...)` on a store holding none of those hosts (the 2.4 GB laptop store seen
    VM-only) read every row: network 65 s, gaps 20 s, hunts 9 s, all to say "nothing". But every row's dedup_key
    starts with '<host>|' (engine/store.py EventStore.dedup_key) and dedup_key is UNIQUE, so its index answers
    "does host H have any row?" at once. Kept per store version (the store only grows). A store without
    dedup_key, or any error: every allowed host is kept (the old, slower, still correct way)."""
    path = path or events_path()
    if not allowed or not path or not os.path.exists(path):
        return allowed
    try:
        con = sqlite3.connect("file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro", uri=True)
        try:
            if "dedup_key" not in columns(con):
                return allowed
            key = (os.path.abspath(path), store_version(con), tuple(sorted(allowed)))
            if key not in _PRESENT:
                if not _keys_start_with_host(con):
                    return allowed                                      # a store keyed some other way: the old path
                if len(_PRESENT) > 256:
                    _PRESENT.clear()
                _PRESENT[key] = frozenset(h for h in allowed if con.execute(
                    "SELECT 1 FROM events WHERE dedup_key >= ? AND dedup_key < ? AND host = ? LIMIT 1",
                    (h + "|", h + "}", h)).fetchone())                  # '}' is the character after '|'
            return _PRESENT[key]
        finally:
            con.close()
    except sqlite3.Error:
        return allowed


def scope_words():
    allowed = allowed_hosts()
    return ("every machine in the store (started with --labs-all-hosts)" if allowed is None
            else "the lab VM only (" + ", ".join(sorted(allowed)) + ")")


def events_path():
    """Where the dashboard's event store is: the running dashboard's `labs.context().events_db`
    (engine/labs/__init__.py), else None. No other source: no environment variable."""
    ctx = _running_context()
    path = getattr(ctx, "events_db", None) if ctx is not None else None
    return str(path) if path else None

def connect(path=None):
    """A read-only connection (rows as sqlite3.Row). Raises FileNotFoundError when no store."""
    path = path or events_path()
    if not path or not os.path.exists(path):
        raise FileNotFoundError("no event store is open (start the dashboard with --events)")
    con = sqlite3.connect("file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro", uri=True,
                          check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def columns(con) -> set:
    """Lower-case column names of the events table (empty when there is no table)."""
    try:
        return {r[1].lower() for r in con.execute("PRAGMA table_info(events)")}
    except sqlite3.DatabaseError:
        return set()


def has(con, *names) -> bool:
    cols = columns(con)
    return bool(cols) and all(n.lower() in cols for n in names)


def has_index(con, name) -> bool:
    return any(r[1] == name for r in con.execute("PRAGMA index_list(events)"))


def store_version(con):
    """Newest row id: the store only grows, so a new event always raises it (cache key)."""
    try:
        return con.execute("SELECT MAX(id) FROM events").fetchone()[0]
    except sqlite3.OperationalError:
        return None


_EDGES = {}                       # (store file, newest row id, allowed hosts, "newest"/"oldest") -> time


def _edge(con, newest):
    """The newest/oldest event of the allowed hosts. The time index is walked to the first such row, which on a
    store holding few of them (a laptop store seen VM-only) can mean the whole index, so the answer is kept per
    store and store version (the store only grows: a new event raises MAX(id))."""
    sw, sp = scope_sql()
    try:
        if not sw:
            return con.execute(f"SELECT {'MAX' if newest else 'MIN'}(time) FROM events").fetchone()[0]
        path = store_path(con)
        key = (path, store_version(con), sw, tuple(sp), newest)
        if not path or key not in _EDGES:
            if len(_EDGES) > 256:
                _EDGES.clear()
            row = con.execute(f"SELECT time FROM events WHERE time IS NOT NULL{sw} ORDER BY time {'DESC' if newest else ''} "
                              f"LIMIT 1", sp).fetchone()
            _EDGES[key] = row[0] if row else None
        return _EDGES[key]
    except sqlite3.OperationalError:
        return None


def store_path(con):
    """The connection's own store file ('' for an in-memory store: then nothing is cached)."""
    try:
        return next((r[2] for r in con.execute("PRAGMA database_list") if r[1] == "main"), "") or ""
    except sqlite3.Error:
        return ""


_STARTS = {}                      # (store file, newest row id, scope) -> ProcessGuids with a recorded start


def started_guids(con):
    """Every ProcessGuid with a recorded start (Sysmon event 1) of the allowed hosts, anywhere in the store. One
    pass over the event_id index (1.2 s for 331 000 starts on the 2.4 GB laptop store), kept per store version.
    Speed audit (2026-11-24): looking each process up by ProcessGuid instead reads EVERY row of that process, and
    the processes without a recorded start (the very ones the gap page looks for) are often busy ones started
    before Sysmon: 24.6 s for one day of the laptop store."""
    sw, sp = scope_sql()
    path = store_path(con)
    key = (path, store_version(con), sw, tuple(sp))
    if path and key in _STARTS:
        return _STARTS[key]
    found = frozenset(g for (g,) in con.execute(
        f"SELECT ProcessGuid FROM events WHERE event_id = 1 AND ProcessGuid IS NOT NULL{sw}", sp))
    if path:
        if len(_STARTS) > 4:
            _STARTS.clear()
        _STARTS[key] = found
    return found


def start_rows(con, guids, cols):
    """{guid: its start row (event 1)} for the guids that have one (started_guids), each found through the
    ProcessGuid index and stopping at its first start (one per process): a busy process's other rows are not read."""
    sw, sp = scope_sql()
    started = started_guids(con)
    frm = "events INDEXED BY idx_events_ProcessGuid" if has_index(con, "idx_events_ProcessGuid") else "events"
    out = {}
    for g in {g for g in guids if g and g in started}:
        r = con.execute(f"SELECT {cols} FROM {frm} WHERE ProcessGuid = ? AND event_id = 1{sw} LIMIT 1", [g] + sp).fetchone()
        if r is not None:
            out[g] = r
    return out


def newest_time(con):
    """The newest event of the allowed hosts (cached per store version)."""
    return _edge(con, True)


def oldest_time(con):
    """The oldest event of the allowed hosts (cached per store version)."""
    return _edge(con, False)


_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)")


def parse_iso(text):
    """'2026-10-17T15:43:34.6006083Z' (or '2026-10-17 15:43:34.395') -> aware datetime, or None."""
    if not text:
        return None
    m = _ISO.match(str(text).strip())
    if not m:
        return None
    hms = m.group(2) if m.group(2).count(":") == 2 else m.group(2) + ":00"
    frac = re.match(r"^\.(\d+)", str(text).strip()[len(m.group(0)):])
    dt = datetime.strptime(f"{m.group(1)}T{hms}", "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    if frac:
        dt += timedelta(microseconds=int((frac.group(1) + "000000")[:6]))
    return dt


def iso(dt) -> str:
    """The store's own spelling (7 fraction digits, Z), so text comparison orders correctly."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"


_MINUTES = {}


def fast_seconds(text):
    """seconds() for millions of rows: the minute is parsed once and cached, the seconds are
    added as a number ('2026-10-17T15:43:34.6006083Z' and '2026-10-17 15:43:34.395' alike)."""
    try:
        base = _MINUTES.get(text[:16])
        if base is None:
            if len(_MINUTES) > 200000:
                _MINUTES.clear()
            base = _MINUTES[text[:16]] = parse_iso(text[:16]).timestamp()
        return base + float(text[17:].rstrip("Z"))
    except (TypeError, ValueError, AttributeError):
        return seconds(text)


def iso_from(sec) -> str:
    """Seconds since the epoch -> the store's spelling."""
    return iso(datetime.fromtimestamp(sec, timezone.utc))


def seconds(text):
    dt = parse_iso(text)
    return dt.timestamp() if dt else None


class Window:
    """A time window [since, until] as store-spelled ISO text. `bounded` = False for "all"."""

    def __init__(self, since, until, name, bounded=True):
        self.since, self.until, self.name, self.bounded = since, until, name, bounded

    def sql(self, col="time"):
        """(' AND time >= ? AND time <= ?', params) - empty when unbounded."""
        parts, params = [], []
        if self.since:
            parts.append(f"{col} >= ?")
            params.append(self.since)
        if self.until:
            parts.append(f"{col} <= ?")
            params.append(self.until)
        return ("".join(" AND " + p for p in parts), params)

    def as_dict(self):
        return {"name": self.name, "since": self.since, "until": self.until}


def window(con, name=DEFAULT_WINDOW, start=None, end=None) -> Window:
    """The chosen window. `start`/`end` (ISO) win over `name`; otherwise `name` counts back from
    the store's newest event. An empty store gives an empty window (since = until = None)."""
    if start or end:
        s, e = parse_iso(start), parse_iso(end)
        if (start and s is None) or (end and e is None):
            raise ValueError("start/end must be ISO times like 2026-10-17T15:43:00Z")
        until = (iso(e)[:19] + ".9999999Z") if e else None
        return Window(iso(s) if s else None, until, "custom")
    if name not in WINDOWS:
        raise ValueError(f"window must be one of {sorted(WINDOWS)}")
    newest = newest_time(con)
    span = WINDOWS[name]
    if newest is None or span is None:
        return Window(None, None, name, bounded=False)
    return Window(iso(parse_iso(newest) - span), newest, name)


def events_from(con, w: Window) -> str:
    """`events` with the time index forced for a bounded window: event_id alone is a poor index
    on laptop stores (network events are ~70 % of rows), the time range is the narrow one."""
    if not (w.since and has_index(con, "idx_events_time")):
        return "events"
    # a window over most of the store reads faster as a plain scan than through the index (measured
    # on a 1 GB laptop store: 7 days of 3.5 took 5.4 s through the index, 3.4 s without it)
    first, last = seconds(oldest_time(con)), seconds(w.until or newest_time(con))
    since = seconds(w.since)
    if first is None or last is None or since is None or last <= first or (last - since) / (last - first) > 0.5:
        return "events"
    return "events INDEXED BY idx_events_time"


def basename(path) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1]


def low(path) -> str:
    return str(path or "").lower()


def is_zero_guid(guid) -> bool:
    g = str(guid or "").strip("{}").replace("-", "")
    return bool(g) and set(g) == {"0"}


def when_col(con) -> str:
    """The shared clock (_shared_defs.when) as SQL: Sysmon's UtcTime when the store has it, else the record time."""
    from . import _shared_defs as sd                       # noqa: PLC0415
    return sd.when_sql(columns(con))


def own_filter(con, include_own: bool = False) -> str:
    """Leave out the lab's own test machinery (shared definition: _shared_defs.is_harness - the lab's own
    tools, the VM's run starter and launchers, VirtualBox's helpers, the report back to the laptop) and
    paused rows. `include_own` = the page's "show the test machinery" switch. Old stores may lack columns."""
    from . import _shared_defs as sd                       # noqa: PLC0415
    cols = columns(con)
    parts = []
    if not include_own:
        harness = sd.harness_sql_literal(cols)
        if harness:
            parts.append(harness[len(" AND "):])
    if "paused" in cols:
        parts.append("COALESCE(paused, 0) = 0")
    return " AND ".join(parts) or "1=1"


def host_filter(host):
    """The host part of every query: the one host asked for (if it is allowed; otherwise nothing at all
    matches), else the allowed hosts (VM only by default)."""
    allowed = allowed_hosts()
    if host:
        if (allowed is not None and host not in allowed) or not present_hosts(frozenset({host})):
            return " AND 0", []
        return " AND host = ?", [host]
    return scope_sql()


def hosts(con):
    """Allowed hosts among the newest 20 000 rows (a DISTINCT over a multi-GB store would scan it all)."""
    allowed = allowed_hosts()
    try:
        found = [r[0] for r in con.execute(
            "SELECT DISTINCT host FROM (SELECT host FROM events ORDER BY id DESC LIMIT 20000) WHERE host IS NOT NULL")]
    except sqlite3.OperationalError:
        return []
    return [h for h in found if allowed is None or h in allowed]


# Autostart places the Sysmon config records (tools/sysmon/sysmon-config.xml, group
# analystlab-v0.3-autostart), in plain words, checked in this order (first match wins).
AUTOSTART_KINDS = [
    ("\\policies\\explorer\\run", "Run key (policy)"),
    ("\\currentversion\\runonce", "RunOnce key"),
    ("\\currentversion\\runservices", "RunServices key"),
    ("\\currentversion\\run", "Run key"),
    ("\\windows nt\\currentversion\\windows\\run", "Windows 'run' value"),
    ("shell folders\\startup", "Startup folder location"),
    ("shell folders\\common startup", "Startup folder location"),
    ("\\command processor\\autorun", "cmd.exe AutoRun"),
    ("\\winlogon\\", "Winlogon helper"),
    ("\\session manager\\", "Boot-time setting"),
    ("\\group policy\\scripts", "Logon/boot script"),
    ("\\windows\\system\\scripts", "Logon/boot script"),
    ("\\accessibility\\ats\\", "Accessibility tool start"),
    ("\\drivers32", "Driver list (Drivers32)"),
    ("\\services\\", "Service"),
]


def autostart_kind(target_object) -> str:
    t = low(target_object)
    for needle, word in AUTOSTART_KINDS:
        if needle in t:
            return word
    return "Other autostart place"


def startup_folder(path) -> bool:
    return "\\start menu\\programs\\startup\\" in low(path)


def run_window(con, host, at):
    """(start, end, how): the boot-to-boot stretch around `at` on `host` (Sysmon event 4 State=Started =
    a machine start: one test run on the VM). end is None when no later start was recorded."""
    t = parse_iso(at)
    at = iso(t) if t else at                                  # alerts spell times '...667Z', the store '...6670000Z'
    hw, hp = host_filter(host)
    has_state = has(con, "State")
    before = con.execute(f"SELECT MAX(time) FROM events WHERE event_id = 4 AND State = 'Started' AND time <= ?{hw}",
                         [at] + hp).fetchone()[0] if has_state else None
    after = con.execute(f"SELECT MIN(time) FROM events WHERE event_id = 4 AND State = 'Started' AND time > ?{hw}",
                        [at] + hp).fetchone()[0] if has_state else None
    if before:
        return before, after, "boot"
    first = con.execute(f"SELECT MIN(time) FROM events WHERE 1=1{hw}", hp).fetchone()[0]
    return first, None, "records"


def alert_scope(con, alert_id):
    """What "this alert" narrows a page to (network, persistence: wave 3's ?alert=<id>):
    {id, title, time, host, window (its run, a Window), programs (lower-case Images of its evidence),
    how} - or {id, missing: True} when this dashboard has no such alert on the machines it shows."""
    ctx = _running_context()
    try:
        a = ctx.alert(alert_id) if ctx is not None else None
    except PermissionError:                                   # another machine's alert: not shown here
        a = None
    allowed = allowed_hosts()
    if a is None or (allowed is not None and a.host not in allowed):
        return {"id": alert_id, "missing": True}
    start, end, how = run_window(con, a.host, a.time)
    until = (end and iso(parse_iso(end) - timedelta(microseconds=1))) or newest_time(con)
    keys = list(a.evidence or ())
    programs, guids = set(), set()
    hw, hp = host_filter(a.host)
    for i in range(0, len(keys), 400):
        chunk = keys[i:i + 400]
        for img, guid in con.execute(f"SELECT Image, ProcessGuid FROM events WHERE dedup_key IN "
                                     f"({','.join('?' * len(chunk))}){hw}", chunk + hp):
            if img:
                programs.add(low(img))
            if guid:
                guids.add(guid)
    return {"id": a.alert_id, "title": a.title, "time": a.time, "host": a.host, "how": how,
            "window": Window(start, until, "alert"), "programs": sorted(programs), "guids": sorted(guids)}


def scoped_window(con, name, start, end, host, alert, only_alert=True):
    """(Window, host, alert for the page) for the pages that limit by TIME only (hunts, rarity, gaps):
    with ?alert= and only_alert, the alert's run on its machine ("limit to this alert's time window");
    otherwise the chosen window. Raises ValueError for a bad window name or time."""
    scope = alert_scope(con, alert) if alert else None
    if scope and not scope.get("missing"):
        if only_alert:                                       # by TIME only: the banner names no programs
            return scope["window"], scope["host"], alert_public(scope, False, limited=True)
        return window(con, name, start, end), host, alert_public(scope, False, limited=False)
    return window(con, name, start, end), host, alert_public(scope, False)


def alert_public(scope, narrowed, limited=None):
    """The part of alert_scope() a page shows. `limited`: the page shows only this alert's run (None: not said)."""
    if scope is None:
        return None
    if scope.get("missing"):
        return {"id": scope["id"], "missing": True}
    out = {"id": scope["id"], "title": scope["title"], "time": scope["time"], "host": scope["host"], "how": scope["how"],
           "programs": scope["programs"], "narrowed": bool(narrowed and scope["programs"])}
    if limited is not None:
        out["limited"] = bool(limited)
    return out


def result_meta(con, w: Window, host=None) -> dict:
    """What every answer carries: the window read, the store's own span, which machines are shown, and the one
    family of scope sentences every lab's banner uses (_shared_defs.WORDS["scope"])."""
    from . import _shared_defs as sd                       # noqa: PLC0415
    return {"window": w.as_dict(), "store": {"newest": newest_time(con), "hosts": hosts(con)}, "host": host,
            "scope": scope_words(), "scope_words": sd.WORDS["scope"]}
