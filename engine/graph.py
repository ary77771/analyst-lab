"""Evidence graph (DESIGN 4.7): layers 0-1 (FACTS and GAPS) and, when switched on, layer 2
(HYPOTHESES graded by engine/confidence.py).

    python -m engine.graph --db recordings/scratch/graph.db                      # counts only (privacy rule)
    python -m engine.graph --db ... --pool recordings/confidence/pool.json      # with layer 2

Built from the event store (engine/store.py) with NetworkX (a MultiDiGraph: several edges may
join the same two nodes, e.g. a process connecting to one server many times).

Nodes (every id starts with its kind and the host, because correlation never crosses machines):
  proc:<host>:<ProcessGuid>              a process. Sysmon's GUID, never the reusable PID.
  file:<host>:<path>|<SHA256>            a file whose content is known (path + fingerprint)
  file:<host>:<path>                     a file whose content is unknown
  net:<host>:<ip>:<port>                 a remote endpoint this machine connected to
  net:<host>:<ip>                        a remote address that connected in (its port is random)
                                         (IPv6 addresses are written in brackets: [2001:db8::1])
  dns:<host>:<name>                      a name that was looked up
  port:<host>:<ip>:<port>                a port a program listened on (agent port snapshots)
  reg:<host>:<registry value, lower case> an autostart entry (a registry value, event 13)

Edges (all grade "fact"; each carries `time`, `evidence` = the store rows it came from, and
`primary` = the row that states it):
  layer 0, one recorded event each:
    proc -started-> proc          event 1 (ParentProcessGuid -> ProcessGuid)
    proc -connected_to-> net      event 3, Initiated=true (DestinationIp:DestinationPort)
    proc -accepted_from-> net     event 3, Initiated=false (the remote side is the Source)
    proc -created-> file          event 11 (content known only from a timely FILE_HASH)
    proc -deleted-> file          event 26 (Sysmon hashes the deleted file: content known)
    proc -looked_up-> dns         event 22
    proc -listen_started/listen_stopped-> port   agent PORT_LISTEN_* records, see _port_owner
    proc -set_autostart-> autostart   event 13 (version 2: config v0.3 records registry values
                                  only in autostart places, e.g. Run keys, services, Winlogon)
    autostart -will_start-> file  the same event 13: its value (Details) names that program file
                                  by full path. Only what the entry SAYS; it never ran here.
  layer 1, an exact identifier match between two records:
    file -ran_as-> proc           the process's Image path (event 1) and SHA256 equal the path
                                  and content of a file node whose content is known. Same path
                                  alone is NOT a fact.

Gaps (stored in G.graph["gaps"] and on the node's "gaps" list; never turned into fake nodes):
  parent_unknown   event 1 with an all-zero (or missing) ParentProcessGuid: the parent started
                   before Sysmon was running. No parent node is created.
  origin_unknown   a process whose start was never recorded (only seen as a parent or acting in
                   other events): its identity is known (a real GUID), how it started is not.
  actor_unknown    an event whose acting ProcessGuid is all zeros (kernel/System activity Sysmon
                   could not attribute): the object node is kept, no process is invented.
  content_unknown  a new program/script file (agent/filetypes.should_hash) without a FILE_HASH,
                   a FILE_HASH whose hash_status is not "ok", or one taken too late / after the
                   file changed again (it would not prove what the creator wrote).
  owner_unknown    a listening-port record whose program cannot be pinned to exactly one process.

Layer 2 (package F, 2026-10-24; `build_graph(..., hypotheses=Layer2(pool, cfg))`): exactly the
approved link-type table of DESIGN 4.7, graded ONLY through engine/confidence.py. Every layer-2
edge carries `layer=2`, `row` (T1..F1), `via` (the process the link goes through), `claim`,
`reason`, `alternative` (the innocent explanation, always), `basis`, `evidence`/`primary`/`support`:
  hypotheses (grade "hypothesis", drawn dashed):
    net -content_from-> file              T1: the file's content probably came from that endpoint
    net -remote_command-> proc            T2: the inbound connection probably made P start C
    net -fetched_then_ran-> proc          T3: P probably started C because of what it fetched
    file -same_path_unknown_content-> proc  R1: the program ran from a path created earlier, content unproven
    file -copy_of-> file                  R2: the program's file is probably a copy of that one
    dns -name_for_connection-> net        R3: the connection was probably for that name
    file -started_with_file_argument-> proc R4: the program was started with that file as an argument
  facts (exact matches, grade "fact"):
    file -same_content-> proc             R2: the same SHA256 (never an empty/placeholder hash)
    proc -download_marker-> file          F1: the program marked the file as downloaded (event 15)
  Timing rows (T1-T3) carry `p` (chance of coincidence), `p1`, `lam`, `lam_source`, `n_causes`,
  `life_seconds`, `assessable` and `timing_band` (never changed afterwards); a download marker can
  raise T1's shown `band` to "high" (basis "download marker"), never to a fact. `provisional` is
  True for every timing grade while config/frozen.yaml's burst_factor is null.
  G.graph["layer2"] holds the summary: counts by row and band, effects tested/linked, sigma_p
  (the number of chance links to expect), what was NOT drawn and why.
  A wrong fact is worse than a missing one: when the exact cause row is not in the graph, or a
  process/effect is not in the Activity, nothing is drawn and the case is counted.
Layer 3 hub suppression (package G) is built: engine/hubs.py learns the frozen hub list and plugs
into subgraph_around's `expand` hook; engine/report.view applies it for the report, the dashboard
and the graph checker.
"""

import argparse
import bisect
import hashlib
import ntpath
import re
import sqlite3
import time as _time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

import networkx as nx

from agent.filetypes import should_hash

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"
CLOCK_SLACK = timedelta(seconds=2)
# agent/main.py waits up to HASH_WAIT_SECONDS (120 s) for a new file's writer to finish; an "ok"
# fingerprint later than this after the event 11 was not taken right after the creator wrote it
# (e.g. the agent caught up after downtime), so it can't prove what the creator wrote.
FILE_HASH_MAX_DELAY = timedelta(seconds=130)
DEV_TOOLS = {"claude.exe"}            # = agent/enrich.py DEV_TOOLS (checked by a test)

COLUMNS = ["id", "dedup_key", "host", "session", "channel", "record_id", "seq", "event_id", "type",
           "time", "origin", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ParentProcessGuid",
           "ParentProcessId", "ParentImage", "Hashes", "TargetFilename", "Protocol", "Initiated",
           "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "QueryName", "QueryStatus",
           "LocalIp", "LocalPort", "hash_status", "sha256", "ref_record_id", "ref_time",
           "ProcessStartUtc", "final_path", "paused", "CommandLine", "QueryResults", "Contents", "Hash",
           "EventType", "TargetObject", "Details"]
GRAPH_EVENTS = (1, 3, 4, 5, 11, 13, 15, 22, 26)
ZONE_SUFFIX = ":zone.identifier"      # Windows' mark-of-the-web stream (event 15 TargetFilename)
TIMING_KINDS = {"T1": "content_from", "T2": "remote_command", "T3": "fetched_then_ran"}
# the approved alternative explanations (DESIGN 4.7, plain-words table), shown on every hypothesis
ALTERNATIVES = {
    "T1": "the program would have written that file anyway (unpacked from itself, a log, a cache)",
    "T2": "the program starts helpers on its own schedule",
    "T3": "a launcher that always connects first (an update check) and then starts its real work",
    "R1": "the file was changed in between without a new 'created' event",
    "R2": "a common file (an updater keeps copies; many files share this content); or the copy went "
          "the other way, e.g. a system program that existed before the recording began",
    "R3": "several names share that address (content networks)",
    "R4": "a same-named file elsewhere (name-only match); a relative path that points somewhere else; "
          "the program only opened, scanned or deleted the file",
}
# agent port records carry the owner's start time (psutil, same clock as Sysmon's UtcTime, which
# has millisecond precision): a match within this slack is the same process
START_MATCH_SLACK = timedelta(seconds=1)
AGENT_TYPES = ("FILE_HASH", "PORT_LISTEN_START", "PORT_LISTEN_STOP")


# -- small helpers ---------------------------------------------------------------------------
def parse_time(text):
    """Sysmon UtcTime ('2026-10-16 14:00:00.123') or record time ('...T14:00:00.1234567Z')
    -> timezone-aware UTC datetime (None if missing or unreadable)."""
    if not text:
        return None
    t = str(text).strip().replace("T", " ").rstrip("Z").removesuffix("+00:00")
    whole, _, frac = t.partition(".")
    try:
        dt = datetime.strptime(whole, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    micro = int((frac + "000000")[:6]) if frac.isdigit() else 0
    return dt.replace(microsecond=micro, tzinfo=timezone.utc)


def norm_guid(guid):
    return guid.strip().upper() if guid and guid.strip() else None


def is_zero_guid(guid):
    """All-zero GUID in any spelling ({0000...}, 0000..., lower case): 'Sysmon doesn't know'."""
    hexdigits = (guid or "").strip().strip("{}").replace("-", "")
    return bool(hexdigits) and set(hexdigits) == {"0"}


def norm_path(path):
    """Windows paths ignore case; the \\\\?\\ and \\??\\ prefixes don't change the file.
    (8.3 short names such as ADMINI~1 can't be expanded from text; see layer2_candidates.)"""
    if not path:
        return None
    p = path.strip()
    for prefix in ("\\\\?\\", "\\??\\"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return ntpath.normcase(p)


def ip_key(ip):
    """An address as written in node ids: IPv4-mapped IPv6 as plain IPv4, IPv6 in brackets."""
    ip = (ip or "").strip()
    if ip.lower().startswith("::ffff:") and ip.count(".") == 3:
        ip = ip[7:]
    return f"[{ip.lower()}]" if ":" in ip else ip


def sha256_from_hashes(hashes):
    """Sysmon's Hashes field, e.g. 'SHA256=AB12...' or 'MD5=..,SHA256=..' -> 'AB12...'."""
    for part in (hashes or "").split(","):
        name, _, value = part.partition("=")
        if name.strip().upper() == "SHA256" and value.strip() not in ("", "-"):
            return value.strip().upper()
    return None


def event_time(row):
    """When it happened: Sysmon's UtcTime for Sysmon events, the record time for agent records."""
    return parse_time(row.get("UtcTime")) or parse_time(row.get("time"))


def evidence(row):
    """The citation for one stored row: enough to find it again (dedup_key) and to quote it."""
    return {"key": row["dedup_key"], "id": row["id"], "record_id": row.get("record_id"),
            "seq": row.get("seq"), "event": row.get("event_id") or row.get("type"),
            "time": row["_t"].isoformat() if row.get("_t") else None}


def _basename(path):
    return ntpath.basename(path or "") or None


_RUNNABLE = re.compile(r"^([a-z]:\\.+?\.(?:exe|com|scr|bat|cmd|ps1|vbs|js|dll))(?=$|[\s,])", re.I)


def autostart_target(details):
    """The program file an autostart value names by FULL path: '"C:\\x\\a.exe" -arg' or
    'C:\\x\\a.exe -arg'. None for a bare name (ctfmon.exe: which file is unknown), a number
    (a service's Start mode) or anything else."""
    s = str(details or "").strip()
    if s.startswith('"'):
        s = s[1:].split('"', 1)[0]
    m = _RUNNABLE.match(s)
    return m.group(1) if m else None


# -- reading -----------------------------------------------------------------------------------
def read_rows(source, host=None):
    """Rows the graph needs, as dicts. `source`: an EventStore, a sqlite3 connection or a path."""
    if hasattr(source, "db"):
        db = source.db
    elif isinstance(source, sqlite3.Connection):
        db = source
    else:
        db = sqlite3.connect(source)
        try:
            return read_rows(db, host)
        finally:
            db.close()
    cols = {r[1].lower(): r[1] for r in db.execute("PRAGMA table_info(events)")}
    select = ", ".join(f'"{cols[c.lower()]}"' if c.lower() in cols else f"NULL AS {c}" for c in COLUMNS)
    sql = (f"SELECT {select} FROM events WHERE ((channel = ? AND event_id IN ({','.join(map(str, GRAPH_EVENTS))})) "
           f"OR type IN ({','.join('?' * len(AGENT_TYPES))}))")
    params = [SYSMON_CHANNEL, *AGENT_TYPES]
    if host is not None:
        sql += " AND host = ?"
        params.append(host)
    return [dict(zip(COLUMNS, r)) for r in db.execute(sql, params)]


# -- building ----------------------------------------------------------------------------------
def _connect(source):
    """(sqlite3 connection, whether we opened it) for an EventStore, a connection or a path."""
    if hasattr(source, "db"):
        return source.db, False
    if isinstance(source, sqlite3.Connection):
        return source, False
    return sqlite3.connect(source), True


class Layer2:
    """The switch for layer 2: the frozen pool of normal rates (engine/confidence.Pool) and the
    confidence config (config/frozen.yaml). Nothing in the graph is graded without them."""

    def __init__(self, pool, cfg=None, pool_sha256=None):
        from engine import confidence as C
        self.pool, self.cfg, self.pool_sha256 = pool, cfg or C.load_config(), pool_sha256

    @classmethod
    def from_pool_file(cls, path, cfg=None):
        """Refuses a pool whose SHA256 is not the frozen one (when set) or that was built with
        other confidence settings than `cfg` (engine/confidence.Pool.check_config)."""
        from engine import confidence as C
        cfg = cfg or C.load_config()
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        return cls(C.Pool.load(path, expect_sha256=cfg.pool_sha256, cfg=cfg), cfg, sha)


def build_graph(source, include_project=True, host=None, hypotheses=None):
    """Build the evidence graph from the store: layers 0-1 always; layer 2 when `hypotheses` is a
    Layer2 (pool + config). include_project=False leaves out our own development activity
    (origin=project): every event of a process tagged project in any of its events, and agent
    records tagged project."""
    db, owned = _connect(source)
    try:
        builder = _Builder(read_rows(db, host), include_project)
        G = builder.build()
        if hypotheses is not None:
            G = _Layer2Builder(G, builder, db, hypotheses).build()
        return G
    finally:
        if owned:
            db.close()


class _Builder:
    def __init__(self, rows, include_project):
        self.rows = rows
        self.include_project = include_project
        self.G = nx.MultiDiGraph(layers=(0, 1), include_project=include_project)
        self.gaps = []
        self.candidates = []          # layer 2 material, never facts
        self.stats = Counter()
        self.mentions = {}            # stub process node -> first row that mentioned it
        self.hash_rows = {}           # file node with known content -> the row that proves it
        self.project_procs = set()
        self.port_owners = {}         # (host, session, ip, port, pid) -> owner of the open port
        self.created_node = {}        # event 11 dedup_key -> the file node it created (layer 2)
        self.creation_of_hash = {}    # FILE_HASH dedup_key -> the event 11 row it proved (layer 2)
        self.folder_keys = set()      # event 11 dedup_keys that are new folders
        self.latest_file = {}         # (host, normalised path) -> the newest file node for it
        self.all_rows = []            # every row (before the origin filter): blockers come from here
        self.visible_rows = []        # rows the graph shows (after the origin filter)

    # nodes ---------------------------------------------------------------------------------
    def proc(self, host, guid, pid=None, image=None, row=None):
        """The process node; a stub (start not recorded) if its event 1 is not in the data."""
        node = f"proc:{host}:{guid}"
        if node not in self.G:
            self.G.add_node(node, kind="process", host=host, guid=guid, pid=pid, image=image,
                            label=_basename(image), start=None, end=None, start_recorded=False,
                            sha256=None, origin=None, gaps=[])
            if row is not None:
                self.mentions[node] = row
        data = self.G.nodes[node]
        if data["pid"] is None and pid is not None:
            data["pid"] = pid
        if data["image"] is None and image:
            data["image"], data["label"] = image, _basename(image)
        return node

    def file(self, host, path, sha=None, source=None, row=None):
        """A file node; with `sha` it is 'this path with this content', proven by `row`
        (a timely FILE_HASH, or an event 26 that Sysmon hashed)."""
        node = f"file:{host}:{norm_path(path)}" + (f"|{sha}" if sha else "")
        if node not in self.G:
            self.G.add_node(node, kind="file", host=host, path=path, label=_basename(path),
                            sha256=sha, hash_sources=set(), gaps=[])
        self.latest_file[(host, norm_path(path))] = node      # rows come in time order
        if source:
            self.G.nodes[node]["hash_sources"].add(source)
            self.hash_rows.setdefault(node, row)
        return node

    def other(self, kind, node, **attrs):
        if node not in self.G:
            self.G.add_node(node, kind=kind, gaps=[], **attrs)
        return node

    def fact(self, u, v, kind, row_or_rows, layer=0, primary=None, **attrs):
        rows = row_or_rows if isinstance(row_or_rows, list) else [row_or_rows]
        primary = primary or rows[-1]
        self.G.add_edge(u, v, kind=kind, grade="fact", layer=layer, time=primary["_t"],
                        evidence=[evidence(r) for r in rows], primary=evidence(primary), **attrs)
        self.stats[f"fact_{kind}"] += 1

    def gap(self, node, kind, reason, rows, t=None):
        g = {"kind": kind, "node": node, "reason": reason,
             "time": t or (rows[0]["_t"] if rows else None), "evidence": [evidence(r) for r in rows]}
        self.gaps.append(g)
        self.G.nodes[node]["gaps"].append(g)
        self.stats[f"gap_{kind}"] += 1

    # main ----------------------------------------------------------------------------------
    def build(self):
        # events recorded during a user pause carry no content (agent/control.py): nothing to link
        paused = sum(1 for r in self.rows if r.get("paused"))
        if paused:
            self.stats["paused_rows_skipped"] = paused
            self.rows = [r for r in self.rows if not r.get("paused")]
        rows = self.rows
        for r in rows:
            r["_t"] = event_time(r)
            zero = is_zero_guid(r.get("ProcessGuid"))
            r["_zero"] = zero
            r["_guid"] = None if zero else norm_guid(r.get("ProcessGuid"))
        rows.sort(key=lambda r: (r["_t"] is None, r["_t"] or datetime.min.replace(tzinfo=timezone.utc), r["id"]))
        self._index_all(rows)            # from ALL rows: lifetimes, Sysmon restarts, file changes
        self.all_rows = rows
        rows = self._apply_origin_filter(rows)
        self.visible_rows = rows

        sysmon = [r for r in rows if r.get("channel") == SYSMON_CHANNEL and r.get("event_id")]
        self.file_hashes = defaultdict(list)       # dedup key of the event 11 -> FILE_HASH rows
        for r in rows:
            if r.get("type") == "FILE_HASH":
                try:
                    ref = f"{r['host']}|{SYSMON_CHANNEL}|{int(r['ref_record_id'])}|{r.get('ref_time')}"
                except (TypeError, ValueError):
                    self.stats["file_hash_bad_reference"] += 1
                    continue
                self.file_hashes[ref].append(r)

        # pass 1: every recorded process start and end, so parents are known before children
        for r in sysmon:
            if r["event_id"] == 1 and r["_guid"]:
                node = self.proc(r["host"], r["_guid"], r.get("ProcessId"), r.get("Image"))
                data = self.G.nodes[node]
                if not data["start_recorded"]:
                    data.update(start=r["_t"], start_recorded=True, origin=r.get("origin"),
                                sha256=sha256_from_hashes(r.get("Hashes")), start_evidence=evidence(r),
                                pid=r.get("ProcessId"), image=r.get("Image"), label=_basename(r.get("Image")))
                    self.mentions.pop(node, None)
                    self.start_rows[node] = r
            elif r["event_id"] in (1, 5) and not r["_guid"]:
                self.stats[f"event{r['event_id']}_without_process_guid"] += 1
        for r in sysmon:
            if r["event_id"] == 5 and r["_guid"]:
                node = self.proc(r["host"], r["_guid"], r.get("ProcessId"), r.get("Image"), r)
                self.G.nodes[node].update(end=r["_t"], end_evidence=evidence(r))

        # pass 2: relationships, in time order
        handlers = {1: self._started, 3: self._network, 11: self._created, 13: self._autostart,
                    22: self._dns, 26: self._deleted}
        for r in rows:
            if r.get("channel") == SYSMON_CHANNEL and r.get("event_id") in handlers:
                handlers[r["event_id"]](r)
            elif r.get("type") in ("PORT_LISTEN_START", "PORT_LISTEN_STOP"):
                self._port(r)
        self._ran_as()

        for node, row in self.mentions.items():
            if not self.G.nodes[node]["start_recorded"]:
                self.gap(node, "origin_unknown", "process start never recorded (started before "
                         "Sysmon or outside the recording), so how it started is unknown", [row])
        self.G.graph.update(gaps=self.gaps, layer2_candidates=self.candidates, stats=dict(self.stats))
        return self.G

    def _index_all(self, rows):
        """From ALL rows (before the origin filter): recorded process lifetimes by (host, PID),
        the times Sysmon (re)started (event 4, e.g. after a reboot), and when each path was
        created/deleted (to tell whether a file changed before it was fingerprinted)."""
        self.lifetimes = {}
        self.by_pid = defaultdict(list)
        self.sysmon_starts = defaultdict(list)
        self.path_changes = defaultdict(list)      # (host, path) -> sorted times of events 11/26
        self.start_rows = {}
        for r in rows:
            if r.get("channel") != SYSMON_CHANNEL:
                continue
            eid = r.get("event_id")
            node = f"proc:{r['host']}:{r['_guid']}"
            if eid == 1 and r["_guid"] and node not in self.lifetimes and r.get("ProcessId") is not None:
                self.lifetimes[node] = {"image": norm_path(r.get("Image")), "start": r["_t"], "end": None,
                                        "start_row": r}
                self.by_pid[(r["host"], int(r["ProcessId"]))].append(node)
            elif eid == 5 and node in self.lifetimes:
                self.lifetimes[node]["end"] = r["_t"]
            elif eid == 4:
                self.sysmon_starts[r["host"]].append(r["_t"])
            elif eid in (11, 26) and r.get("TargetFilename") and r["_t"]:
                self.path_changes[(r["host"], norm_path(r["TargetFilename"]))].append(r["_t"])

    def _apply_origin_filter(self, rows):
        if self.include_project:
            return rows
        project = {(r["host"], r["_guid"]) for r in rows if r.get("origin") == "project" and r["_guid"]}
        self.project_procs = project
        kept = []
        for r in rows:
            if r.get("origin") == "project" or (r["_guid"] and (r["host"], r["_guid"]) in project):
                self.stats["filtered_project_rows"] += 1
                continue
            kept.append(r)
        return kept

    # layer 0 -----------------------------------------------------------------------------------
    def _started(self, r):
        if not r["_guid"]:
            return
        child = f"proc:{r['host']}:{r['_guid']}"
        if self.G.nodes[child].get("start_evidence", {}).get("key") != r["dedup_key"]:
            return                                       # a second event 1 for the same GUID
        parent_guid = norm_guid(r.get("ParentProcessGuid"))
        if not parent_guid or is_zero_guid(parent_guid):
            self.gap(child, "parent_unknown", "parent not recorded: ParentProcessGuid is all zeros "
                     "(the parent started before Sysmon was running)", [r])
            return
        if not self.include_project:
            parent = f"proc:{r['host']}:{parent_guid}"
            unseen = parent not in self.G
            if (r["host"], parent_guid) in self.project_procs or (
                    unseen and (_basename(r.get("ParentImage")) or "").lower() in DEV_TOOLS):
                self.G.nodes[child]["parent_hidden"] = "project activity (filtered out)"
                return
        parent = self.proc(r["host"], parent_guid, r.get("ParentProcessId"), r.get("ParentImage"), r)
        self.fact(parent, child, "started", r)

    def _actor(self, r, obj=None):
        """The acting process; None (and an actor_unknown gap on `obj`) if Sysmon recorded none."""
        if r["_guid"]:
            return self.proc(r["host"], r["_guid"], r.get("ProcessId"), r.get("Image"), r)
        if obj is not None:
            self.gap(obj, "actor_unknown", "Sysmon recorded no acting process (all-zero ProcessGuid)", [r])
        return None

    def _network(self, r):
        initiated = str(r.get("Initiated") or "").strip().lower()
        if initiated == "true":
            ip, port = r.get("DestinationIp"), r.get("DestinationPort")
            node, kind, extra = f"net:{r['host']}:{ip_key(ip)}:{port}", "connected_to", {}
        elif initiated == "false":
            ip, port = r.get("SourceIp"), None
            node, kind, extra = f"net:{r['host']}:{ip_key(ip)}", "accepted_from", {"local_port": r.get("DestinationPort")}
        else:
            self.stats["event3_direction_unknown"] += 1     # never guess which side is remote
            return
        if not ip:
            self.stats["event3_without_address"] += 1
            return
        ep = self.other("endpoint", node, host=r["host"], ip=ip, port=port)
        actor = self._actor(r, ep)
        if actor is not None:
            self.fact(actor, ep, kind, r, protocol=r.get("Protocol"), **extra)

    def _fingerprint(self, r, hashes):
        """(sha, FILE_HASH row) if exactly one timely 'ok' fingerprint proves what the creator
        wrote, else (None, reason). Timely = taken within FILE_HASH_MAX_DELAY of the event 11,
        with no other create/delete of the same path in between."""
        ok = [h for h in hashes if h.get("hash_status") == "ok" and h.get("sha256")]
        if not hashes:
            return None, None
        if not ok:
            status = ",".join(sorted({str(h.get("hash_status")) for h in hashes}))
            return None, f"fingerprint failed (hash_status={status})"
        if len({h["sha256"].upper() for h in ok}) > 1:
            return None, "conflicting fingerprints for one new file"
        h = ok[0]
        if r["_t"] is None or h["_t"] is None or not (
                -CLOCK_SLACK <= h["_t"] - r["_t"] <= FILE_HASH_MAX_DELAY):
            return None, "fingerprint not taken right after creation (agent busy or caught up later)"
        changes = self.path_changes.get((r["host"], norm_path(r["TargetFilename"])), [])
        i = bisect.bisect_right(changes, r["_t"])
        if i < len(changes) and changes[i] <= h["_t"]:
            return None, "the file was created/deleted again before it was fingerprinted"
        return (h["sha256"].upper(), h), None

    def _created(self, r):
        path = r.get("TargetFilename")
        if not path:
            return
        hashes = self.file_hashes.get(r["dedup_key"], [])
        if any(h.get("hash_status") == "directory" for h in hashes):
            # a new folder: a created fact, but no content to fingerprint, so no gap
            node = self.file(r["host"], path)
            self.created_node[r["dedup_key"]] = node
            self.folder_keys.add(r["dedup_key"])
            actor = self._actor(r, node)
            if actor is not None:
                self.fact(actor, node, "created", r)
            return
        proof, why = self._fingerprint(r, hashes)
        if proof:
            sha, h = proof
            node = self.file(r["host"], path, sha, "FILE_HASH", h)
            self.creation_of_hash[h["dedup_key"]] = r
        else:
            node = self.file(r["host"], path)
        self.created_node[r["dedup_key"]] = node
        actor = self._actor(r, node)
        if actor is not None:
            if proof:
                self.fact(actor, node, "created", r, fingerprint=evidence(proof[1]))
            else:
                self.fact(actor, node, "created", r)
        if why:
            self.gap(node, "content_unknown", why, [r, *hashes])
        elif not proof and should_hash(path):
            why = ("not fingerprinted: project activity" if r.get("origin") == "project"
                   else "no FILE_HASH recorded for this new program/script file")
            self.gap(node, "content_unknown", why, [r])

    def _deleted(self, r):
        path = r.get("TargetFilename")
        if not path:
            return
        sha = sha256_from_hashes(r.get("Hashes"))
        node = self.file(r["host"], path, sha, "sysmon_delete" if sha else None, r)
        self.latest_file.pop((r["host"], norm_path(path)), None)   # that content is gone from the path
        actor = self._actor(r, node)
        if actor is not None:
            self.fact(actor, node, "deleted", r)

    def _autostart(self, r):
        """Event 13: a registry value was set in an autostart place (config v0.3 records only
        those). The entry's own node, and, when its value names a program by full path, a
        will_start fact to that file (the newest node for the path: the file as it was then)."""
        key = r.get("TargetObject")
        if not key:
            self.stats["event13_without_target"] += 1
            return
        node = self.other("autostart", f"reg:{r['host']}:{key.lower()}", host=r["host"], key=key,
                          label=key.rsplit("\\", 1)[-1])
        actor = self._actor(r, node)
        if actor is not None:
            self.fact(actor, node, "set_autostart", r, value=r.get("Details"))
        target = autostart_target(r.get("Details"))
        if target:
            f = self.latest_file.get((r["host"], norm_path(target))) or self.file(r["host"], target)
            self.fact(node, f, "will_start", r)

    def _dns(self, r):
        name = r.get("QueryName")
        if not name:
            return
        node = self.other("dns", f"dns:{r['host']}:{name.lower()}", host=r["host"], name=name)
        actor = self._actor(r, node)
        if actor is not None:
            self.fact(actor, node, "looked_up", r, status=r.get("QueryStatus"))

    def _port(self, r):
        ip, port = r.get("LocalIp"), r.get("LocalPort")
        node = self.other("port", f"port:{r['host']}:{ip_key(ip)}:{port}", host=r["host"], ip=ip, port=port)
        owner, why, start_row = self._port_owner(r)
        kind = "listen_started" if r["type"] == "PORT_LISTEN_START" else "listen_stopped"
        if owner is not None and owner not in self.G:
            self.stats["filtered_project_port_records"] += 1     # its owner is project activity
            if not self.G.in_degree(node) and not self.G.out_degree(node) and not self.G.nodes[node]["gaps"]:
                self.G.remove_node(node)
            return
        if owner is None:
            self.gap(node, "owner_unknown", f"{kind}: {why}", [r])
            return
        basis = "pid+image+start time" if r.get("ProcessStartUtc") else "pid+image+lifetime"
        self.fact(owner, node, kind, [start_row, r], basis=basis)

    def _port_owner(self, r):
        """The agent's port records carry a process number (PID) and program path, not Sysmon's
        GUID. A PID is unique only among processes running at the same moment, so:
        START: tied to a process only when exactly ONE recorded process (start recorded by
        event 1) has that PID and program, had started by then and was still running, with no
        Sysmon restart (a reboot) in between.
        STOP: tied to the owner of the latest resolved START of the same port and PID in the
        same agent session (the agent reports an owner change as STOP old + START new).
        Anything else is a gap, never a guess."""
        pid, image, t = r.get("ProcessId"), norm_path(r.get("Image")), r["_t"]
        key = (r["host"], r.get("session"), r.get("LocalIp"), r.get("LocalPort"), pid)
        if r["type"] == "PORT_LISTEN_STOP":
            owner = self.port_owners.pop(key, None)
            if owner is None:
                return None, "no resolved start of this port in the same agent session", None
            return owner, None, self.lifetimes[owner]["start_row"]
        if pid is None or t is None:
            return None, "no process number or time", None
        if not image:
            return None, "no program path in the port record", None
        found = []
        for node in self.by_pid.get((r["host"], int(pid)), []):
            d = self.lifetimes[node]
            if d["start"] is None or d["start"] > t:
                continue
            if d["end"] is not None and d["end"] < t - CLOCK_SLACK:
                continue
            if d["image"] != image:
                continue
            if any(d["start"] < s <= t for s in self.sysmon_starts.get(r["host"], [])):
                continue                     # Sysmon restarted (reboot?) since: can't assume alive
            found.append(node)
        started_at = parse_time(r.get("ProcessStartUtc"))
        if started_at is not None:
            # newer agents record the owner's start time: PID + program + start time is exact,
            # so keep only the process whose own event 1 has that start (decided 2026-10-17)
            found = [n for n in self.by_pid.get((r["host"], int(pid)), [])
                     if self.lifetimes[n]["image"] == image and self.lifetimes[n]["start"] is not None
                     and abs(self.lifetimes[n]["start"] - started_at) <= START_MATCH_SLACK]
            if len(found) != 1:
                return None, f"{len(found)} recorded processes match PID, program and start time", None
            self.port_owners[key] = found[0]
            return found[0], None, self.lifetimes[found[0]]["start_row"]
        if len(found) != 1:
            return None, f"{len(found)} recorded processes match PID, program and lifetime", None
        self.port_owners[key] = found[0]
        return found[0], None, self.lifetimes[found[0]]["start_row"]

    # layer 1 -----------------------------------------------------------------------------------
    def _ran_as(self):
        from engine.confidence import constant_hash     # (confidence imports this module: lazy)
        known = defaultdict(list)                     # (host, sha) -> file nodes with that content
        paths = set()
        for n, d in self.G.nodes(data=True):
            if d["kind"] == "file":
                paths.add((d["host"], norm_path(d["path"])))
                # an empty-file or placeholder hash proves nothing (DESIGN R1; package F, 2026-10-24)
                if d["sha256"] and d["hash_sources"] and not constant_hash(d["sha256"]):
                    known[(d["host"], d["sha256"])].append(n)
        for node, d in list(self.G.nodes(data=True)):
            if d["kind"] != "process" or not d["start_recorded"] or not d["image"]:
                continue
            path = norm_path(d["image"])
            same_content = known.get((d["host"], d["sha256"]), []) if d["sha256"] and not constant_hash(d["sha256"]) else []
            # the file's recorded path, or Windows' full spelling of it from the FILE_HASH
            # (an 8.3 short name like ADMINI~1 then still matches the program's long path)
            exact = [f for f in same_content
                     if path in (norm_path(self.G.nodes[f]["path"]), norm_path((self.hash_rows.get(f) or {}).get("final_path")))]
            if exact:
                f = exact[0]
                self.fact(f, node, "ran_as", [self.hash_rows[f], self.start_rows[node]], layer=1,
                          primary=self.start_rows[node])
                continue
            # TODO layer 2: grade these as hypotheses (or drop them); never facts here
            if (d["host"], path) in paths:
                self.candidates.append({"process": node, "reason": "same path, content different or unknown"})
                self.stats["layer2_same_path_no_hash_match"] += 1
            elif same_content:
                self.candidates.append({"process": node, "files": same_content,
                                        "reason": "same content, different path spelling (e.g. an 8.3 short name)"})
                self.stats["layer2_same_content_other_path"] += 1


# -- layer 2 --------------------------------------------------------------------------------------
def _contains(sorted_values, x):
    i = bisect.bisect_left(sorted_values, x)
    return i < len(sorted_values) and sorted_values[i] == x


def _tokens(command_line):
    """A command line's tokens: quoted strings whole, the rest split on whitespace, '=' and ','."""
    return [g for m in re.finditer(r'"([^"]*)"|\'([^\']*)\'|([^\s"\'=,]+)', command_line or "")
            for g in m.groups() if g]


def _label(G, node):
    d = G.nodes[node]
    kind = d.get("kind")
    if kind == "process":
        return d.get("label") or d.get("guid") or node
    if kind == "file":
        return d.get("label") or d.get("path") or node
    if kind == "endpoint":
        return f"{d['ip']}:{d['port']}" if d.get("port") else str(d.get("ip"))
    if kind == "dns":
        return d.get("name") or node
    if kind == "autostart":
        return d.get("label") or node
    return node


class _Layer2Builder:
    """Adds the layer-2 edges to a built layer 0-1 graph. Edges come only from rows the graph
    shows; the blockers ("latest creation", deletions, Sysmon restarts, "changed in between")
    come from ALL rows, as the layer 0-1 indexes do. Grades come from engine/confidence.py."""

    def __init__(self, G, builder, db, layer2):
        self.G, self.b, self.db, self.l2 = G, builder, db, layer2
        self.cfg = layer2.cfg
        self.span = float(self.cfg.competing_span_seconds)       # the rule rows' look-back = the graph window
        self.not_drawn, self.tested, self.linked, self.stats = Counter(), Counter(), Counter(), Counter()
        self.r1_replaced, self.r2_no_direction = 0, Counter()
        self.acts, self.until = {}, {}
        self.timing_by_effect = defaultdict(list)     # (effect row key, via node) -> [(u, v, edge key)]
        self.r3_high = defaultdict(set)               # connection row key -> names a HIGH R3 edge tied to it

    def build(self):
        from engine import confidence as C
        self.C = C
        for r in self.b.all_rows:
            r["_ts"] = r["_t"].timestamp() if r["_t"] else None
        self.visible = {r["dedup_key"] for r in self.b.visible_rows}
        self._index()
        for host in sorted({r["host"] for r in self.b.visible_rows if r.get("host")}):
            # the graph's end time = the latest row of this host the graph read; every rate,
            # lifetime and count comes from data up to it (DESIGN 4.7)
            times = [r["_ts"] for r in self.b.all_rows if r["host"] == host and r["_ts"] is not None]
            if not times:
                continue
            self.until[host] = max(times)
            self.acts[host] = C.load_activity(self.db, self.cfg, host, self.until[host])
        self._timing()
        self._r1_r2()
        self._r3()
        self._r4()
        self._f1()
        self.G.graph["layers"] = (0, 1, 2)
        self.G.graph["layer2"] = layer2_summary(self.G, {
            "until": {h: datetime.fromtimestamp(t, timezone.utc).isoformat() for h, t in self.until.items()},
            "tested": {row: self.tested.get(row, 0) for row in TIMING_KINDS},
            "linked": {row: self.linked.get(row, 0) for row in TIMING_KINDS}, "not_drawn": dict(self.not_drawn),
            "r1_replaced": self.r1_replaced, "r2_no_direction": dict(self.r2_no_direction),
            "stats": dict(self.stats), "pool_sha256": self.l2.pool_sha256,
            "burst_factor": self.cfg.burst_factor})
        return self.G

    # indexes ----------------------------------------------------------------------------------
    def _index(self):
        b = self.b
        from engine.confidence import LISTEN_SNAPSHOT_SLACK, constant_hash
        self.creations = defaultdict(list)          # (host, path) -> [(ts, row)], all rows (event 11)
        self.creations_by_name = defaultdict(list)  # (host, file name) -> [(ts, row, path)], folders left out
        self.deletions = defaultdict(list)          # (host, path) -> [ts], all rows (event 26)
        self.holders = defaultdict(set)             # (host, sha) -> paths that held that content, ALL rows
        self.listens = defaultdict(list)            # host -> [(ts, port, program)] agent listen records, all rows
        self.restarts = {h: sorted(t.timestamp() for t in ts if t) for h, ts in b.sysmon_starts.items()}
        for r in b.all_rows:
            if r["_ts"] is None:
                continue
            if r.get("type") == "FILE_HASH":
                if r.get("hash_status") == "ok" and r.get("sha256") and not constant_hash(r["sha256"]):
                    for p in (r.get("TargetFilename"), r.get("final_path")):
                        if norm_path(p):
                            self.holders[(r["host"], r["sha256"].upper())].add(norm_path(p))
                continue
            if r.get("type") == "PORT_LISTEN_START":
                if r.get("LocalPort") is not None:
                    self.listens[r["host"]].append((r["_ts"], int(r["LocalPort"]), (_basename(r.get("Image")) or "").lower()))
                continue
            if r.get("channel") != SYSMON_CHANNEL:
                continue
            sha = sha256_from_hashes(r.get("Hashes"))
            if sha and not constant_hash(sha):
                if r.get("event_id") == 1 and norm_path(r.get("Image")):
                    self.holders[(r["host"], sha)].add(norm_path(r["Image"]))
                elif r.get("event_id") == 26 and norm_path(r.get("TargetFilename")):
                    self.holders[(r["host"], sha)].add(norm_path(r["TargetFilename"]))
            path = norm_path(r.get("TargetFilename"))
            if not path:
                continue
            if r.get("event_id") == 11:
                self.creations[(r["host"], path)].append((r["_ts"], r))
                if r["dedup_key"] not in b.folder_keys:
                    self.creations_by_name[(r["host"], ntpath.basename(path))].append((r["_ts"], r, path))
                for h in b.file_hashes.get(r["dedup_key"], []):      # Windows' full spelling of the path
                    fp = norm_path(h.get("final_path"))
                    if fp and fp != path:
                        self.creations[(r["host"], fp)].append((r["_ts"], r))
            elif r.get("event_id") == 26:
                self.deletions[(r["host"], path)].append(r["_ts"])
        for v in self.creations.values():
            v.sort(key=lambda x: x[0])
        self.creation_ts = {k: [t for t, _ in v] for k, v in self.creations.items()}   # for bisect
        for v in self.creations_by_name.values():
            v.sort(key=lambda x: x[0])
        for v in self.deletions.values():
            v.sort()
        self.listen_slack = LISTEN_SNAPSHOT_SLACK
        self.fact_by_primary = {}                  # (row key, kind) -> (u, v, key, data) of layer 0-1 facts
        for u, v, k, d in self.G.edges(keys=True, data=True):
            if d["layer"] < 2:
                self.fact_by_primary[(d["primary"]["key"], d["kind"])] = (u, v, k, d)
        self.out_rows = defaultdict(lambda: defaultdict(list))   # (host, guid) -> ts -> [(row, endpoint)]
        self.in_rows = defaultdict(lambda: defaultdict(list))
        self.lookups = defaultdict(list)                         # (host, guid) -> [(ts, name, ips, row)]
        for r in b.visible_rows:
            if r.get("channel") != SYSMON_CHANNEL or r["_ts"] is None or not r["_guid"]:
                continue
            if r.get("event_id") == 3:
                f = self.fact_by_primary.get((r["dedup_key"], "connected_to"))
                if f:
                    self.out_rows[(r["host"], r["_guid"])][r["_ts"]].append((r, f[1]))
                f = self.fact_by_primary.get((r["dedup_key"], "accepted_from"))
                if f and self._t2_qualifies(r):
                    # only a cause the Activity could have graded (review of the build, finding 3):
                    # TCP to a port this program listened on, or a non-ephemeral port
                    self.in_rows[(r["host"], r["_guid"])][r["_ts"]].append((r, f[1]))
            elif r.get("event_id") == 22 and r.get("QueryName"):
                ips = self.C.parse_query_results(r.get("QueryResults"))
                self.lookups[(r["host"], r["_guid"])].append((r["_ts"], r["QueryName"].lower(), ips, r))
        for v in self.lookups.values():
            v.sort(key=lambda x: x[0])

    def _t2_qualifies(self, r):
        """The same rule confidence.load_activity applies to an inbound connection (T2's cause)."""
        program = (_basename(r.get("Image")) or "").lower()
        ports = {port for ts, port, prog in self.listens.get(r["host"], ())
                 if ts <= r["_ts"] + self.listen_slack and prog == program}
        return self.C.t2_cause_qualifies(r.get("Protocol"), r.get("DestinationPort"), ports)

    def _latest_creation(self, host, path, t, span=None, inclusive=False):
        """The latest recorded creation of `path` before `t` (at or before it when inclusive), no
        older than `span` seconds: (ts, row) or None. From ALL rows."""
        ts = self.creation_ts.get((host, path))
        if not ts:
            return None
        i = (bisect.bisect_right if inclusive else bisect.bisect_left)(ts, t) - 1
        if i < 0 or (span is not None and ts[i] < t - span):
            return None
        return self.creations[(host, path)][i]

    def _deleted_between(self, host, path, a, b):
        d = self.deletions.get((host, path), [])
        return bisect.bisect_right(d, b) > bisect.bisect_right(d, a)

    def _changed_between(self, host, path, a, b):
        """A creation or deletion of `path` in (a, b]."""
        c = self.creation_ts.get((host, path), [])
        return self._deleted_between(host, path, a, b) or bisect.bisect_right(c, b) > bisect.bisect_right(c, a)

    def _edge(self, row, u, v, via, rows, primary, kind, grade, band, claim, reason, basis, time, **extra):
        attrs = dict(kind=kind, grade=grade, layer=2, row=row, via=via, time=time, band=band, basis=basis,
                     claim=claim, reason=reason, alternative=ALTERNATIVES.get(row),
                     evidence=[evidence(r) for r in rows], primary=evidence(primary), support=[], **extra)
        if grade == "hypothesis":
            attrs.setdefault("p", None)
            attrs.setdefault("provisional", False)
            attrs.setdefault("provisional_reason", None)
        return self.G.add_edge(u, v, **attrs)

    # T1-T3 ----------------------------------------------------------------------------------------
    def _timing(self):
        for r in self.b.visible_rows:
            if r.get("channel") != SYSMON_CHANNEL or r["_ts"] is None:
                continue
            if r.get("event_id") == 11:
                f = self.fact_by_primary.get((r["dedup_key"], "created"))
                if f is None:
                    continue
                if r["dedup_key"] in self.b.folder_keys:
                    self.stats["folders_not_effects"] += 1          # a folder carries no content
                    continue
                self._grade(("T1",), f[0], f[1], r)
            elif r.get("event_id") == 1:
                f = self.fact_by_primary.get((r["dedup_key"], "started"))
                if f is not None:
                    self._grade(("T2", "T3"), f[0], f[1], r)

    def _grade(self, rows, via, effect_node, effect_row):
        C = self.C
        host, guid = effect_row["host"], self.G.nodes[via]["guid"]
        act = self.acts.get(host)
        if act is None or guid not in act.procs:
            self.not_drawn["process_not_in_activity"] += 1          # e.g. our own tools' processes
            return
        t_effect = effect_row["_ts"]
        if not _contains(act.events["file" if rows == ("T1",) else "child"].get(guid, []), t_effect):
            self.not_drawn["effect_not_in_activity"] += 1           # e.g. a project child
            return
        for row in rows:
            self.tested[row] += 1
            res = C.grade_process_link(row, guid, t_effect, act, self.l2.pool, self.cfg)
            if res is None:
                self.stats[f"{row}_no_cause_in_window"] += 1
                continue
            t_cause, g = res
            table = self.in_rows if row == "T2" else self.out_rows
            cause_rows = table[(host, guid)].get(t_cause, [])
            if not cause_rows:
                # the Activity's cause (a paused row, an event 3 without an address) is not a
                # graph row: nothing is drawn, never a nearby row instead
                self.not_drawn["cause_not_in_graph"] += 1
                continue
            self.linked[row] += 1
            endpoints = list(dict.fromkeys(ep for _, ep in cause_rows))
            for ep in endpoints:
                cause_row = next(r for r, e in cause_rows if e == ep)
                self._timing_edge(row, ep, effect_node, via, cause_row, effect_row, g,
                                  act.procs[guid]["life"], tied=len(endpoints) > 1)

    def _timing_edge(self, row, u, v, via, cause_row, effect_row, g, life, tied):
        dt = effect_row["_ts"] - cause_row["_ts"]
        ep, eff, p = _label(self.G, u), _label(self.G, v), _label(self.G, via)
        if row == "T1":
            claim = f"the content of {eff} probably came from {ep}"
            what = f"{p} created {eff} {dt:+.1f} s after connecting to {ep}"
        elif row == "T2":
            claim = f"the connection from {ep} probably made {p} start {eff}"
            what = f"{p} started {eff} {dt:+.1f} s after accepting a connection from {ep}"
        else:
            claim = f"{p} probably started {eff} because of what it fetched from {ep}"
            what = f"{p} started {eff} {dt:+.1f} s after connecting to {ep}"
        provisional = self.cfg.burst_factor is None
        why = None
        if provisional:
            why = ("the burst factor is still open (config/frozen.yaml burst_factor: null), so every timing "
                   "grade is provisional until package J sets it")
            if row in ("T2", "T3"):
                why += ("; on the dev laptop chance coincidences of child starts were 1.9-4.7x more common "
                        "than predicted (per process, medium band)")
        key = self._edge(row, u, v, via, [cause_row, effect_row], effect_row, TIMING_KINDS[row], "hypothesis",
                         g.band, claim, f"{what}; {g.reason}", "formula", effect_row["_t"],
                         timing_band=g.band, p=g.p, p1=g.p1, lam=g.lam, lam_source=g.source, n_causes=g.n_causes,
                         life_seconds=life, assessable=g.source != "not assessable", provisional=provisional,
                         provisional_reason=why, tied=tied, cause=evidence(cause_row), effect=evidence(effect_row))
        self.timing_by_effect[(effect_row["dedup_key"], via)].append((u, v, key))

    # R1, R2 -----------------------------------------------------------------------------------------
    def _processes(self):
        return [(n, d) for n, d in self.G.nodes(data=True)
                if d["kind"] == "process" and d["start_recorded"] and d["image"] and n in self.b.start_rows]

    def _r1_r2(self):
        G, C, b = self.G, self.C, self.b
        content_nodes = defaultdict(list)                        # (host, sha) -> visible file nodes with that content
        for n, d in G.nodes(data=True):
            if d["kind"] == "file" and d.get("sha256") and d["hash_sources"] and not C.constant_hash(d["sha256"]):
                content_nodes[(d["host"], d["sha256"])].append(n)
        # the path count (a caution input) comes from ALL rows, hidden copies included (review finding 5)
        holders = self.holders
        for node, d in self._processes():
            host, path, start_row = d["host"], norm_path(d["image"]), b.start_rows[node]
            t_start = start_row["_ts"]
            if t_start is None:
                continue
            self._r1(node, d, host, path, start_row, t_start)
            sha = d["sha256"]
            if not sha or C.constant_hash(sha):
                continue
            for xnode in content_nodes.get((host, sha), []):
                self._r2(node, d, host, path, start_row, t_start, xnode, sha, holders[(host, sha)])

    def _r1(self, node, d, host, path, start_row, t_start):
        G, C, b = self.G, self.C, self.b
        c = self._latest_creation(host, path, t_start, self.span)
        if c is None:
            return
        c_ts, c_row = c
        if c_row["dedup_key"] not in self.visible:
            self.not_drawn["latest_creation_hidden"] += 1
            return
        fnode = b.created_node[c_row["dedup_key"]]
        g = C.grade_r1(file_hash=G.nodes[fnode]["sha256"], process_hash=d["sha256"],
                       deleted_between=self._deleted_between(host, path, c_ts, t_start))
        if g.link == "none":
            self.r1_replaced += 1                 # same path, different content: no link at all
        elif g.link == "hypothesis":
            self._edge("R1", fnode, node, node, [c_row, start_row], start_row, "same_path_unknown_content",
                       "hypothesis", g.band, f"{_label(G, node)} probably ran the file created at its path "
                       f"{t_start - c_ts:.1f} s earlier (content never proven)", g.reason, "rule", start_row["_t"])
        # "fact": layer 1 drew it (same path and content)

    def _r2(self, node, d, host, y, start_row, t_start, xnode, sha, holders):
        G, C, b = self.G, self.C, self.b
        xd = G.nodes[xnode]
        xpath = norm_path(xd["path"])
        hrow = b.hash_rows.get(xnode)
        if hrow is None or xpath == y or norm_path(hrow.get("final_path")) == y:
            return                                  # the same file (8.3 spelling): layer 1's business
        if hrow.get("type") == "FILE_HASH":
            crow, only_deletion = b.creation_of_hash.get(hrow["dedup_key"]), False
            if crow is None or crow["_ts"] is None or crow["_ts"] >= t_start:
                self.stats["r2_source_created_after_start"] += 1
                return
        else:
            crow, only_deletion = None, True        # content known only from its deletion (event 26)
        y_creations = self.creations.get((host, y), [])
        latest_y = self._latest_creation(host, y, t_start)
        y_fp = None
        if latest_y and latest_y[1]["dedup_key"] in self.visible:
            y_fp = G.nodes[b.created_node[latest_y[1]["dedup_key"]]]["sha256"]
        res = C.grade_r2(content=sha, x_fingerprint_time=hrow["_ts"], y_creation_times=[t for t, _ in y_creations],
                         start_time=t_start, x_deletion_times=self.deletions.get((host, xpath), ()),
                         y_deletion_times=self.deletions.get((host, y), ()), sysmon_restart_times=self.restarts.get(host, ()),
                         y_fingerprint=y_fp, n_other_paths=max(len(holders - {y}), 1),
                         x_known_only_from_deletion=only_deletion)
        if res["fact"]:
            self._edge("R2", xnode, node, node, [hrow, start_row], start_row, "same_content", "fact", None,
                       f"{_label(G, node)} has exactly the content of the file at {xd['path']}",
                       "the same SHA256 fingerprint (an exact identifier match)", "exact match", start_row["_t"])
        direction = res["direction"]
        if direction is None:
            self.r2_no_direction[res["reason"]] += 1
            return
        # the creation of Y that grade_r2 accepted: the latest one between X's fingerprint and the start
        ys = [(t, r) for t, r in y_creations if hrow["_ts"] < t < t_start]
        y_ts, y_row = ys[-1]
        if y_row["dedup_key"] not in self.visible:
            self.not_drawn["latest_creation_hidden"] += 1
            return
        ynode = b.created_node[y_row["dedup_key"]]
        self._edge("R2", xnode, ynode, node, [hrow, y_row, start_row], y_row, "copy_of", "hypothesis", direction.band,
                   f"{_label(G, ynode)} is probably a copy of the file at {xd['path']}", direction.reason, "rule", y_row["_t"])

    # R3 ------------------------------------------------------------------------------------------------
    def _r3(self):
        G, C = self.G, self.C
        for (host, guid), by_ts in self.out_rows.items():
            lk = self.lookups.get((host, guid))
            if not lk:
                continue
            ts_list = [x[0] for x in lk]
            via = f"proc:{host}:{guid}"
            for t_conn, rows in sorted(by_ts.items()):
                window = lk[bisect.bisect_left(ts_list, t_conn - self.span):bisect.bisect_right(ts_list, t_conn)]
                for conn_row, endpoint in rows:
                    ip = conn_row.get("DestinationIp")
                    names = C.names_for_connection([(t, n, ips) for t, n, ips, _ in window], t_conn, ip, self.span)
                    g = C.grade_r3(len(names))
                    if g.link != "hypothesis":
                        continue
                    if g.band == "high":
                        self.r3_high[conn_row["dedup_key"]] |= names
                    key = ip_key(ip)
                    for name in sorted(names):
                        lrow = next(r for t, n, ips, r in reversed(window) if n == name and key in ips)
                        dns = self.b.other("dns", f"dns:{host}:{name}", host=host, name=name)
                        self._edge("R3", dns, endpoint, via, [lrow, conn_row], conn_row, "name_for_connection",
                                   "hypothesis", g.band, f"the connection to {_label(G, endpoint)} was probably for the name {name}",
                                   f"{_label(G, via)} looked up {name} {t_conn - lrow['_ts']:.1f} s before connecting; {g.reason}",
                                   "rule", conn_row["_t"])

    # R4 ------------------------------------------------------------------------------------------------
    def _r4(self):
        G, C, b = self.G, self.C, self.b
        for node, d in self._processes():
            start_row = b.start_rows[node]
            cmd, t_start = start_row.get("CommandLine"), start_row["_ts"]
            if not cmd or t_start is None:
                continue
            host, own = d["host"], norm_path(d["image"])
            matched = {}                            # created path -> named by its full path?
            for tok in _tokens(cmd):
                tn = norm_path(tok)
                name = ntpath.basename(tn) if tn else None
                if not name:
                    continue
                absolute = bool(re.match(r"^([a-z]:\\|\\\\)", tn))      # a full path that differs is evidence AGAINST
                for ts, _, path in self.creations_by_name.get((host, name), []):
                    if path != own and t_start - self.span <= ts < t_start and (tn == path or not absolute):
                        matched[path] = matched.get(path, False) or tn == path
            for path, full in matched.items():
                c = self._latest_creation(host, path, t_start, self.span)
                if c is None or c[1]["dedup_key"] in b.folder_keys:
                    continue
                c_ts, c_row = c
                if c_row["dedup_key"] not in self.visible:
                    self.not_drawn["latest_creation_hidden"] += 1
                    continue
                g = C.grade_r4(full_path=full, deleted_between=self._deleted_between(host, path, c_ts, t_start))
                fnode = b.created_node[c_row["dedup_key"]]
                self._edge("R4", fnode, node, node, [c_row, start_row], start_row, "started_with_file_argument",
                           "hypothesis", g.band, f"{_label(G, node)} was started with {_label(G, fnode)} as an argument",
                           g.reason, "rule", start_row["_t"])

    # F1 ------------------------------------------------------------------------------------------------
    def _f1(self):
        G, C, b = self.G, self.C, self.b
        for r in b.visible_rows:
            if r.get("channel") != SYSMON_CHANNEL or r.get("event_id") != 15 or r["_ts"] is None:
                continue
            target = r.get("TargetFilename") or ""
            if not target.lower().endswith(ZONE_SUFFIX):
                self.stats["markers_other_stream"] += 1
                continue
            path_text = target[:-len(ZONE_SUFFIX)]
            host, path = r["host"], norm_path(path_text)
            actor = f"proc:{host}:{r['_guid']}" if r["_guid"] else None
            if actor is None or actor not in G:
                self.stats["markers_by_unknown_process"] += 1       # layer 2 never invents a process node
                continue
            hostname, port = C.marker_host(r.get("Contents")), C.marker_port(r.get("Contents"))
            marker_sha = sha256_from_hashes(r.get("Hash"))           # Sysmon: the hash of the file's own content
            c = self._latest_creation(host, path, r["_ts"], inclusive=True)
            crow = None
            if c is not None and c[1]["dedup_key"] in self.visible and not self._changed_between(host, path, c[0], r["_ts"]):
                node = b.created_node[c[1]["dedup_key"]]
                # the record vouches for a content node only when its own hash is that content
                # (review finding 1); in-place overwrites leave no event 11
                if G.nodes[node]["sha256"] and marker_sha == G.nodes[node]["sha256"]:
                    crow, fnode = c[1], node
            if crow is None:
                fnode = b.file(host, path_text)      # the marker describes the path at marker time
            self._edge("F1", actor, fnode, actor, [r], r, "download_marker", "fact", None,
                       f"{_label(G, actor)} marked {_label(G, fnode)} as downloaded from {hostname or 'an unnamed source'}",
                       "Windows' mark-of-the-web, written by the program itself (its own statement, not proof of the source)",
                       "one record", r["_t"], marker_host=hostname, marker_port=port, marker_sha256=marker_sha)
            if crow is None or not hostname or port is None:
                continue                              # no known port: the "address AND port" check cannot pass
            for u, v, key in self.timing_by_effect.get((crow["dedup_key"], actor), []):
                e = G.edges[u, v, key]
                if e["row"] != "T1":
                    continue
                ep = G.nodes[u]
                g = C.grade_f1(host=hostname, endpoint_ip=ep.get("ip"), r3_high_names=self.r3_high.get(e["cause"]["key"], ()),
                               endpoint_port=ep.get("port"), marker_port=port)
                e["support"].append(evidence(r))
                e["reason"] += "; " + g.reason
                if g.link == "hypothesis":
                    e.update(band=g.band, basis="download marker + lookup" if "lookup" in g.reason else "download marker",
                             provisional=False, provisional_reason=None)


def layer2_summary(G, extra=None):
    """Counts of the layer-2 edges by row and band, the layer-2 facts by kind, sigma_p over the timing
    hypotheses (all, and the assessable ones only; tied causes count once per effect), how many are
    provisional / not assessable. `extra` adds the build-time counts (tested, linked, not drawn...)."""
    counts, fct = defaultdict(Counter), Counter()
    sigma, sigma_assessable, provisional, not_assessable = 0.0, 0.0, 0, 0
    seen = set()
    for _, _, d in G.edges(data=True):
        if d.get("layer") != 2:
            continue
        if d["grade"] == "fact":
            fct[d["kind"]] += 1
            continue
        counts[d["row"]][d["band"]] += 1
        if d.get("provisional"):
            provisional += 1
        if d.get("p") is None:
            continue
        effect = (d["row"], d["effect"]["key"])
        if effect in seen:
            continue
        seen.add(effect)
        sigma += d["p"]
        if d["assessable"]:
            sigma_assessable += d["p"]
        else:
            not_assessable += 1
    s = {"counts": {r: dict(c) for r, c in counts.items()}, "facts": dict(fct), "sigma_p": sigma,
         "sigma_p_assessable": sigma_assessable, "provisional": provisional, "not_assessable": not_assessable}
    s.update(extra or {})
    return s


# -- reading the graph ---------------------------------------------------------------------------
def facts(G):
    """All fact edges as (src, dst, data)."""
    return [(u, v, d) for u, v, d in G.edges(data=True) if d.get("grade") == "fact"]


def hypotheses(G):
    """All hypothesis edges (layer 2) as (src, dst, data)."""
    return [(u, v, d) for u, v, d in G.edges(data=True) if d.get("grade") == "hypothesis"]


def node_time(G, node):
    d = G.nodes[node]
    if d.get("start"):
        return d["start"]
    times = [e["time"] for _, _, e in G.in_edges(node, data=True)] + \
            [e["time"] for _, _, e in G.out_edges(node, data=True)]
    times = [t for t in times if t is not None]
    return min(times) if times else None


def timeline(G):
    """Everything in time order: fact edges, process ends and gaps (time, what, src, dst, ...)."""
    items = [{"time": d["time"], "what": d["kind"], "src": u, "dst": v, "grade": d["grade"],
              "evidence": d["evidence"]} for u, v, d in G.edges(data=True)]
    items += [{"time": d["end"], "what": "ended", "src": n, "dst": None, "grade": "fact",
               "evidence": [d["end_evidence"]]} for n, d in G.nodes(data=True)
              if d.get("kind") == "process" and d.get("end") is not None]
    items += [{"time": g["time"], "what": "gap:" + g["kind"], "src": g["node"], "dst": None,
               "grade": "gap", "evidence": g["evidence"]} for g in G.graph.get("gaps", [])
              if g["node"] in G]
    far = datetime.max.replace(tzinfo=timezone.utc)
    return sorted(items, key=lambda i: (i["time"] or far, i["what"], i["src"]))


def _resolve_seed(G, seed):
    """seed = a node id, a ProcessGuid, or a store dedup_key -> ([(node, phase)], seed time).
    An event seed starts at the node(s) that event is about: a process's own start/end, or an
    edge's acting side (walks back and forward) and object side (walks forward only)."""
    if seed in G:
        return [(seed, "back")], node_time(G, seed)
    guid = norm_guid(seed)
    nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "process" and d.get("guid") == guid]
    if nodes:
        return [(n, "back") for n in nodes], min((node_time(G, n) for n in nodes if node_time(G, n)), default=None)
    for n, d in G.nodes(data=True):
        if seed == d.get("start_evidence", {}).get("key"):
            return [(n, "back")], d["start"]
        if seed == d.get("end_evidence", {}).get("key"):
            return [(n, "back")], d["end"]
    for u, v, d in G.edges(data=True):
        if d["layer"] < 2 and d["primary"]["key"] == seed:      # a hypothesis shares its effect row with a fact
            return [(u, "back"), (v, "fwd")], d["time"]
    for u, v, d in G.edges(data=True):
        if d["layer"] == 2 and d["grade"] == "fact" and d["primary"]["key"] == seed:   # a download marker
            return [(u, "back"), (v, "fwd")], d["time"]
    for g in G.graph.get("gaps", []):
        if any(e["key"] == seed for e in g["evidence"]):
            return [(g["node"], "back")], g["time"]
    raise KeyError("seed not found in the graph")


def subgraph_around(G, seed, at=None, window=timedelta(minutes=15), max_depth=5, max_nodes=60,
                    expand=None):
    """The bounded neighbourhood of a seed (DESIGN 4.7 steps 1-3): breadth-first BACKWARDS to
    origins (parents, the file a process ran, its creator...) and FORWARDS to effects (children,
    connections, files...). Walking backwards may turn forwards (the parent's other effects);
    walking forwards never turns back, so unrelated users of a shared node are not pulled in.
    Only edges within +-window of the seed time are followed; depth <= max_depth; at most
    max_nodes nodes, nearest (in steps) first and, among one node's neighbours, closest in time
    first (H.graph["truncated"] says if the cap was hit).
    Only layer 0-1 FACTS are walked. Layer-2 edges (hypotheses, and the layer-2 facts) are shown
    when both ends are in the view, plus ONE hop: a node reached only through a layer-2 edge of a
    shown node is added (`hop=True`, inside the node cap) but never walked from, so a guess never
    pulls in a shared server's other users (package F, 2026-10-24).
    `expand(G, node) -> bool` decides whether a node is walked through: hub suppression (layer 3,
    engine/hubs.expander over the frozen list) plugs in here. The defaults below are this library
    function's own; every view the project shows goes through engine/report.view, which always
    passes the frozen bounds (config.graph_view)."""
    starts, seed_time = _resolve_seed(G, seed)
    t0 = at or seed_time
    if t0 is None:
        raise ValueError("seed has no time; pass at=")
    lo, hi = t0 - window, t0 + window
    expand = expand or (lambda graph, node: True)

    def in_window(d):
        return d.get("time") is not None and lo <= d["time"] <= hi

    included = list(dict.fromkeys(n for n, _ in starts))
    depth = {n: 0 for n in included}
    queue = deque(starts)
    queued = set(starts)
    truncated = False
    while queue:
        node, phase = queue.popleft()
        d = depth[node]
        if d >= max_depth or (d > 0 and not expand(G, node)):
            continue
        steps = []
        if phase == "back":
            steps += [(abs(e["time"] - t0), u, "back") for u, _, e in G.in_edges(node, data=True)
                      if e.get("layer", 0) < 2 and in_window(e)]
        steps += [(abs(e["time"] - t0), v, "fwd") for _, v, e in G.out_edges(node, data=True)
                  if e.get("layer", 0) < 2 and in_window(e)]
        for _, nxt, ph in sorted(steps):
            if nxt not in depth:
                if len(included) >= max_nodes:
                    truncated = True
                    continue
                depth[nxt] = d + 1
                included.append(nxt)
            if (nxt, ph) not in queued:
                queued.add((nxt, ph))
                queue.append((nxt, ph))
    hops = []
    walked = set(included)
    # a layer-2 edge belongs to the view only when the process it goes through (`via`) was walked:
    # a T1 edge out of a shared server made by ANOTHER user of that server stays out (review finding 4)
    mine = lambda e: e.get("layer") == 2 and e.get("via") in walked and in_window(e)     # noqa: E731
    for node in list(included):                   # one hop over layer-2 edges, never walked further
        others = [(abs(e["time"] - t0), u) for u, _, e in G.in_edges(node, data=True) if mine(e)]
        others += [(abs(e["time"] - t0), v) for _, v, e in G.out_edges(node, data=True) if mine(e)]
        for _, other in sorted(others):
            if other in depth:
                continue
            if len(included) >= max_nodes:
                truncated = True
                continue
            depth[other] = depth[node] + 1
            included.append(other)
            hops.append(other)

    H = nx.MultiDiGraph(seed=seed, at=t0, window=window, max_depth=max_depth, max_nodes=max_nodes,
                        truncated=truncated)
    hop = set(hops)
    for n in included:
        H.add_node(n, **G.nodes[n], depth=depth[n], hop=n in hop)
    keep = set(included)
    for u, v, k, e in G.out_edges(included, keys=True, data=True):
        if v in keep and in_window(e) and (e.get("layer", 0) < 2 or e.get("via") in walked):
            H.add_edge(u, v, key=k, **e)
    H.graph["gaps"] = [g for g in G.graph.get("gaps", []) if g["node"] in keep
                       and (g["time"] is None or lo <= g["time"] <= hi)]
    if "layer2" in G.graph:
        H.graph["layer2"] = layer2_summary(H)
    return H


def main(argv=None):
    p = argparse.ArgumentParser(description="Build the evidence graph and print counts only.")
    p.add_argument("--db", required=True)
    p.add_argument("--no-project", action="store_true", help="leave out origin=project activity")
    p.add_argument("--pool", help="pool file of normal rates (engine.confidence --build-pool): adds layer 2")
    a = p.parse_args(argv)
    started = _time.perf_counter()
    G = build_graph(a.db, include_project=not a.no_project,
                    hypotheses=Layer2.from_pool_file(a.pool) if a.pool else None)
    took = _time.perf_counter() - started
    kinds = Counter(d["kind"] for _, d in G.nodes(data=True))
    print(f"built in {took:.1f} s: {G.number_of_nodes()} nodes {dict(kinds)}, {len(facts(G))} fact edges, "
          f"{len(hypotheses(G))} hypotheses, {len(G.graph['gaps'])} gaps")
    print(dict(sorted(G.graph["stats"].items())))
    if "layer2" in G.graph:
        s = G.graph["layer2"]
        print(f"layer 2: {s['counts']} facts {s['facts']} tested {s['tested']} linked {s['linked']} "
              f"sigma_p {s['sigma_p']:.3f} (assessable {s['sigma_p_assessable']:.3f}) provisional {s['provisional']} "
              f"not assessable {s['not_assessable']} not drawn {s['not_drawn']} r1_replaced {s['r1_replaced']} "
              f"r2_no_direction {s['r2_no_direction']}")


if __name__ == "__main__":
    main()
