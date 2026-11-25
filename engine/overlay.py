"""Noise overlay (package J part 1; docs/plans/package-j-design.md section 1, DESIGN 8).

The VM is almost idle during a scenario run, so correlation looks artificially easy. The overlay
builds a FRESH event store that holds one recorded VM run (exactly the rows the graph checker
replays: the run window, re-tagged over the whole stream and then cut) plus `volume` slices of
REAL laptop activity from the dev snapshot, time-shifted into the run window and re-hosted onto
the VM's host under disjoint identities. The graph then sees a busy machine, but no overlay
event can ever state a fact about a scenario node:

  identity / time rewriting, per slice k (1..volume), seed s:
    ProcessGuid, ParentProcessGuid   {FEkk xxxx-....}  = SHA256(s|k|guid), the zero GUID stays zero
    ProcessId, ParentProcessId       + k * 10^7
    record_id, ref_record_id         + k * 10^9
    session                          overlay-<s>-<k>
    time, UtcTime, ref_time, ProcessStartUtc, CreationUtcTime   all shifted by the same whole ms
    SHA256 (Hashes, Hash, sha256)    SHA256(s|k|value); the empty-file / placeholder hashes stay
    SourceIp, DestinationIp, LocalIp, QueryResults   -> 100.64/10 (IPv4), 2001:db8::/32 (IPv6)
    QueryName, marker HostUrl host   -> n<hex>.overlay.invalid
    User, ParentUser, LogonGuid, LogonId, *Hostname  blanked
  unchanged: program images (so hubs and pools still apply), command lines, file paths; a file
  path that exists in the VM window is rewritten under C:\\overlay<k>\\ (the file name stays).
  dropped and counted: rows of a process named like a scenario program (or whose command line
  names one), paused rows, our own tools (origin project), events 4 and 16.
  grafting (decision Q4): an overlay process whose parent started before the slice is attached
  to a live VM process with the same program path (never a role program of any answer sheet),
  so views can reach overlay nodes; off with graft=False.

Slices: `volume` non-overlapping windows of the run's length, each inside ONE active stretch of
the laptop (confidence.ActiveTime), starts drawn uniformly over the eligible positions with
numpy's seeded generator, so a build is reproducible by (seed, volume).

Only laptop rows before the frozen dev cutoff are used (checked on the snapshot's own table AND
in every SQL filter). The output store is written under recordings/ (laptop names inside: privacy
rule 7); this module prints nothing. `overlay_meta` records how the store was built.
"""

import hashlib
import ipaddress
import json
import math
import ntpath
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import numpy as np
import yaml

from engine import config as _config
from engine.confidence import ActiveTime, constant_hash, load_config
from engine.graph import SYSMON_CHANNEL, is_zero_guid, norm_guid, norm_path, parse_time, sha256_from_hashes
from engine.store import CORE_NAMES, EventStore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "scenarios")
OVERLAY_EVENTS = (1, 3, 5, 11, 15, 22, 26)              # Sysmon events taken from the laptop (4 and 16 dropped)
AGENT_TYPES = ("FILE_HASH", "PORT_LISTEN_START", "PORT_LISTEN_STOP")
PID_STEP = 10_000_000
RECORD_STEP = 1_000_000_000
LABEL = "overlay"
ZONE_SUFFIX = ":zone.identifier"
TIME_FIELDS = ("UtcTime", "ref_time", "ProcessStartUtc", "CreationUtcTime")
USER_FIELDS = ("User", "ParentUser", "LogonGuid", "LogonId", "SourceHostname", "DestinationHostname")
IP_FIELDS = ("SourceIp", "DestinationIp", "LocalIp")
PATH_FIELDS = ("TargetFilename", "final_path")
MAX_VOLUME = 255                                          # two hex digits in the GUID prefix
META_VERSION = 1

_TIME_TEXT = re.compile(r"^(\d{4}-\d\d-\d\d)([ T])(\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|\+00:00)?$")


# -- small helpers ---------------------------------------------------------------------------------
def _basename(path):
    return (ntpath.basename(str(path or "")) or "").lower()


def _ms(dt):
    return int(round(dt.timestamp() * 1000))


def _text_ms(text):
    """A time text -> whole milliseconds since the epoch (None if unreadable)."""
    dt = parse_time(text)
    return _ms(dt) if dt else None


def shift_text(text, delta_ms):
    """Shift a recorded time text by whole milliseconds, keeping its spelling: the separator
    (' ' or 'T'), the number of fraction digits (at least 3 when a shift needs them) and the
    zone suffix. Sysmon's "2026-10-16 14:00:00.123", the agent's "2026-10-16T14:00:00.1234567Z".
    Raises ValueError for anything else: a time left unshifted would break the slice's coherence."""
    m = _TIME_TEXT.match(str(text).strip())
    if not m:
        raise ValueError(f"unrecognised time text {text!r}")
    date, sep, clock, frac, zone = m.groups()
    whole = datetime.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    frac = frac or ""
    frac7 = int((frac + "0000000")[:7])
    total = int(whole.timestamp()) * 10**7 + frac7 + int(delta_ms) * 10**4
    secs, rem = divmod(total, 10**7)
    out = datetime.fromtimestamp(secs, timezone.utc).strftime(f"%Y-%m-%d{sep}%H:%M:%S")
    digits = len(frac)
    if digits < 3 and rem % 10**(7 - digits):
        digits = 3                           # a whole-second text shifted by a fraction needs digits
    if digits:
        out += "." + (f"{rem:07d}" + "0" * max(digits - 7, 0))[:digits]
    return out + (zone or "")


def scenario_programs(scenarios_dir=SCENARIOS_DIR):
    """(own, roles): lower-case program file names of every answer sheet. `own` = the scenarios'
    own programs (an overlay process named like one is dropped); `roles` = every role program,
    Windows' shared ones included (never a grafting target)."""
    own, roles = set(), set()
    for name in sorted(os.listdir(scenarios_dir)):
        path = os.path.join(scenarios_dir, name, "ground_truth.yaml")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            truth = yaml.safe_load(f) or {}
        progs = truth.get("programs") or {}
        shared = {_basename(progs[r]) for r in truth.get("windows_programs", []) if r in progs}
        for exe in progs.values():
            b = _basename(exe)
            roles.add(b)
            if b not in shared:
                own.add(b)
    return own, roles


# -- the laptop snapshot ---------------------------------------------------------------------------
def _ro(path):
    return sqlite3.connect("file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro", uri=True)


def open_laptop(path, frozen_cutoff=None):
    """A read-only connection to the dev laptop snapshot and its `snapshot` table, refused unless
    it IS a dev snapshot whose cutoff day is the frozen one or earlier (fairness, section 4)."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"laptop dev snapshot missing: {path}")
    con = _ro(path)
    if not con.execute("SELECT 1 FROM sqlite_master WHERE name = 'snapshot'").fetchone():
        con.close()
        raise ValueError(f"{os.path.basename(path)} is not a dev snapshot (no `snapshot` table): only the dev "
                         "snapshot built by tools/build_dev_snapshot.py may be overlaid")
    meta = dict(con.execute("SELECT key, value FROM snapshot"))
    frozen = frozen_cutoff or _config.load()["data"]["dev_cutoff_day_utc"]
    cutoff = meta.get("cutoff_day_utc")
    if not cutoff or str(cutoff) > str(frozen):
        con.close()
        raise ValueError(f"snapshot cutoff day {cutoff!r} is later than the frozen dev cutoff {frozen!r}: refusing")
    meta["_cutoff_end"] = (datetime.strptime(str(cutoff), "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    meta["_frozen_cutoff"] = str(frozen)
    return con, meta


def laptop_host(con, cutoff_end):
    hs = [h for (h,) in con.execute("SELECT DISTINCT host FROM events WHERE host IS NOT NULL AND time < ?", (cutoff_end,))]
    if not hs:
        raise ValueError(f"the laptop snapshot holds no rows before the cutoff ({cutoff_end}): no active stretch to slice")
    if len(hs) != 1:
        raise ValueError(f"the laptop snapshot holds {len(hs)} machines; the overlay needs exactly one")
    return hs[0]


def laptop_active_time(con, host, cutoff_end, cfg):
    """The laptop's active stretches from ALL its rows before the cutoff (our own tools included:
    the machine was on), as engine/confidence.active_time measures them."""
    times = []
    for u, t in con.execute("SELECT UtcTime, time FROM events WHERE host = ? AND time < ?", (host, cutoff_end)):
        dt = parse_time(u) or parse_time(t)
        if dt:
            times.append(dt.timestamp())
    return ActiveTime(times, cfg.sleep_gap_seconds)


def choose_slices(active, length_ms, k, rng, tries=1000):
    """`k` slice starts (ms since the epoch) of `length_ms` each: every slice inside ONE active
    stretch, no two overlapping, starts uniform over the eligible whole-ms positions."""
    segs = []
    for s, e in zip(active.starts, active.ends):
        lo_ms, hi_ms = math.ceil(s * 1000), math.floor(e * 1000) - length_ms
        if hi_ms >= lo_ms:
            segs.append((lo_ms, hi_ms))
    total = sum(hi - lo + 1 for lo, hi in segs)
    if k > 0 and total <= 0:
        raise ValueError(f"no active stretch of the laptop is as long as the run window ({length_ms / 1000:.0f} s)")
    chosen = []
    for _ in range(k):
        for _attempt in range(tries):
            u = int(rng.integers(0, total))
            for lo, hi in segs:
                if u <= hi - lo:
                    start = lo + u
                    break
                u -= hi - lo + 1
            if all(start + length_ms < c or start > c + length_ms for c in chosen):
                chosen.append(start)
                break
        else:
            raise ValueError(f"could not place {k} non-overlapping slices of {length_ms / 1000:.0f} s in the laptop's "
                             f"active time ({active.total / 3600:.1f} h)")
    return chosen


def laptop_rows(con, host, start_ms, end_ms, cutoff_end):
    """Normal-use rows of the slice [start, end] (by record time): Sysmon OVERLAY_EVENTS and the
    agent's FILE_HASH / port records; never our own tools, paused rows or events 4/16. Rows at or
    after the cutoff are refused by the SQL filter too (the cutoff is enforced twice)."""
    cols = [r[1] for r in con.execute("PRAGMA table_info(events)")]
    lo = datetime.fromtimestamp(start_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    hi = datetime.fromtimestamp(end_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    marks = ",".join("?" * len(AGENT_TYPES))
    sql = (f"SELECT * FROM events WHERE host = ? AND time >= ? AND time <= ? AND time < ? "
           f"AND (origin IS NULL OR origin != 'project') AND (paused IS NULL OR paused = 0) AND parse_error IS NULL "
           f"AND ((channel = ? AND event_id IN ({','.join(map(str, OVERLAY_EVENTS))})) OR type IN ({marks})) "
           f"ORDER BY time, id")
    params = [host, lo, hi, cutoff_end, SYSMON_CHANNEL, *AGENT_TYPES]
    out = []
    for row in con.execute(sql, params):
        d = dict(zip(cols, row))
        t = _text_ms(d.get("time"))
        if t is None or t < start_ms or t > end_ms:
            continue                           # text order and time order can differ in the last digits
        out.append(d)
    return out


# -- identities -----------------------------------------------------------------------------------
class Namespace:
    """The identity and time rewriting of ONE slice (the table in the module docstring)."""

    def __init__(self, seed, k, delta_ms):
        if not 1 <= k <= MAX_VOLUME:
            raise ValueError(f"slice number {k} out of range 1..{MAX_VOLUME}")
        self.seed, self.k, self.delta_ms = int(seed), int(k), int(delta_ms)
        self.session = f"overlay-{self.seed}-{self.k}"

    def _h(self, kind, value):
        return hashlib.sha256(f"{self.seed}|{self.k}|{kind}|{value}".encode("utf-8", "backslashreplace")).hexdigest().upper()

    def guid(self, g):
        if not g or is_zero_guid(g):
            return g
        h = self._h("guid", norm_guid(g))
        return f"{{FE{self.k:02X}{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}-{h[16:28]}}}"

    def pid(self, p):
        try:
            return int(p) + self.k * PID_STEP
        except (TypeError, ValueError):
            return None if p in (None, "") else p

    def record_id(self, r):
        try:
            return int(r) + self.k * RECORD_STEP
        except (TypeError, ValueError):
            return None if r in (None, "") else r

    def time(self, text):
        return None if text in (None, "") else shift_text(text, self.delta_ms)

    def sha(self, s):
        if s in (None, ""):
            return s
        s = str(s).strip().upper()
        return s if constant_hash(s) else self._h("sha", s)

    def hashes(self, text):
        """Sysmon's Hashes/Hash field: only the SHA256 part survives, rewritten ('-' if none)."""
        if text in (None, ""):
            return text
        sha = sha256_from_hashes(text)
        return f"SHA256={self.sha(sha)}" if sha else "-"

    def ip(self, text):
        if text in (None, "") or str(text).strip() == "-":
            return text
        s = str(text).strip()
        plain = s.lower()
        if plain.startswith("::ffff:") and plain.count(".") == 3:
            plain = plain[7:]
        try:
            addr = ipaddress.ip_address(plain)
        except ValueError:
            return "n" + self._h("ip", plain)[:12].lower() + ".overlay.invalid"
        h = self._h("ip", str(addr))
        if addr.version == 4:
            return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("100.64.0.0")) + (int(h[:8], 16) & ((1 << 22) - 1))))
        return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("2001:db8::")) + int(h[:24], 16)))

    def dns(self, name):
        if name in (None, ""):
            return name
        return "n" + self._h("dns", str(name).strip().lower().rstrip(".")) [:12].lower() + ".overlay.invalid"

    def query_results(self, text):
        out = []
        for tok in str(text or "").split(";"):
            tok = tok.strip()
            if not tok or tok == "-" or tok.lower().startswith("type:"):
                continue                       # CNAME lines name hosts: dropped (the graph skips them too)
            out.append(self.ip(tok))
        return ";".join(out) + (";" if out else "")

    def contents(self, text):
        """A download marker's text: ZoneId kept, the HostUrl's host replaced by its placeholder
        (an address through the IP map, a name through the DNS map), path dropped."""
        if text in (None, ""):
            return text
        zone = re.search(r"(?i)ZoneId=(\d+)", str(text))
        m = re.search(r"(?i)(?:^|\s)HostUrl=(\S+)", str(text))
        parts = ["[ZoneTransfer]"]
        if zone:
            parts.append(f"ZoneId={zone.group(1)}")
        if m:
            from urllib.parse import urlsplit
            u = urlsplit(m.group(1))
            host = u.hostname or ""
            try:
                ipaddress.ip_address(host)
                new_host = self.ip(host)
            except ValueError:
                new_host = self.dns(host) if host else ""
            if new_host and ":" in new_host:
                new_host = f"[{new_host}]"
            try:
                port = u.port
            except ValueError:
                port = None
            parts.append(f"HostUrl={u.scheme or 'http'}://{new_host}{':' + str(port) if port else ''}/")
        return "  ".join(parts)

    def path(self, p, collisions):
        """A file path that exists in the VM window moves under C:\\overlay<k>\\ (file name kept)."""
        if p in (None, "") or norm_path(p) not in collisions:
            return p
        q = str(p).strip()
        for prefix in ("\\\\?\\", "\\??\\"):
            if q.startswith(prefix):
                q = q[len(prefix):]
        if len(q) > 2 and q[1:3] == ":\\":
            q = q[0] + "\\" + q[3:]
        elif q.startswith("\\\\"):
            q = "UNC\\" + q[2:]
        return f"C:\\overlay{self.k}\\{q}"


# -- the VM side ----------------------------------------------------------------------------------
class VMFacts:
    """What the overlay must know about the VM window: its host, every file/program path in it
    (collisions), and its processes with their lifetimes (grafting targets)."""

    def __init__(self, records):
        hosts = {r.get("host") for r in records if r.get("host")}
        if len(hosts) != 1:
            raise ValueError(f"the run window holds {len(hosts)} VM hosts; exactly one is needed")
        self.host = hosts.pop()
        self.file_paths, self.program_paths = set(), set()
        self.procs = {}                       # guid -> {image, pid, start, end, seen}
        for r in records:
            d = r.get("data") or {}
            t = parse_time(d.get("UtcTime")) or parse_time(r.get("time"))
            ts = t.timestamp() if t else None
            if r.get("type") == "FILE_HASH":
                for p in (d.get("TargetFilename"), d.get("final_path")):
                    if norm_path(p):
                        self.file_paths.add(norm_path(p))
                continue
            if r.get("channel") != SYSMON_CHANNEL or r.get("event_id") is None:
                continue
            eid = r["event_id"]
            target = d.get("TargetFilename")
            if target and eid == 15 and str(target).lower().endswith(ZONE_SUFFIX):
                target = str(target)[:-len(ZONE_SUFFIX)]
            if norm_path(target) and eid in (11, 15, 26):
                self.file_paths.add(norm_path(target))
            for p in (d.get("Image"), d.get("ParentImage")):
                if norm_path(p):
                    self.program_paths.add(norm_path(p))
            g = norm_guid(d.get("ProcessGuid")) if not is_zero_guid(d.get("ProcessGuid")) else None
            if g:
                p = self.procs.setdefault(g, {"image": None, "pid": None, "start": None, "end": None, "seen": []})
                if d.get("Image") and not p["image"]:
                    p["image"] = d["Image"]
                if d.get("ProcessId") is not None and p["pid"] is None:
                    p["pid"] = d["ProcessId"]
                if ts is not None:
                    p["seen"].append(ts)
                    if eid == 1:
                        p["start"] = ts if p["start"] is None else min(p["start"], ts)
                    elif eid == 5:
                        p["end"] = ts
            pg = norm_guid(d.get("ParentProcessGuid")) if eid == 1 and not is_zero_guid(d.get("ParentProcessGuid")) else None
            if pg:
                p = self.procs.setdefault(pg, {"image": None, "pid": None, "start": None, "end": None, "seen": []})
                if d.get("ParentImage") and not p["image"]:
                    p["image"] = d["ParentImage"]
                if d.get("ParentProcessId") is not None and p["pid"] is None:
                    p["pid"] = d["ParentProcessId"]
                if ts is not None:
                    p["seen"].append(ts)
        for p in self.procs.values():
            p["seen"].sort()
        self.collisions = self.file_paths | self.program_paths

    def graft_target(self, image, t, roles):
        """A live VM process with program path `image` at time t (epoch seconds): started at or
        before t (or seen alive without a recorded start) and not ended before t; never a role
        program of any answer sheet. The one most recently seen before t wins (ties: by GUID)."""
        want = norm_path(image)
        if not want or _basename(image) in roles:
            return None
        best = None
        for g, p in self.procs.items():
            if norm_path(p["image"]) != want or _basename(p["image"]) in roles:
                continue
            if p["start"] is not None and p["start"] > t:
                continue
            if p["end"] is not None and p["end"] < t:
                continue
            recent = max((s for s in p["seen"] if s <= t), default=-math.inf)
            key = (recent, g)
            if best is None or key > best[0]:
                best = (key, g, p)
        return None if best is None else (best[1], best[2])


# -- building ---------------------------------------------------------------------------------------
def _slice_record(row, ns, vm, drop_names, roles, graft, starts_in_slice, counts, grafts, acting_in_slice=frozenset()):
    """One laptop store row -> the record to insert, or None (dropped and counted).
    `starts_in_slice`: GUIDs whose event 1 is in the slice; `acting_in_slice`: GUIDs with any row in it
    (a grafted child whose laptop parent also acted in the slice is counted: that parent stays an
    overlay stub with its own activity while the child hangs under the VM process)."""
    data = {k: v for k, v in row.items() if k not in CORE_NAMES and k not in ("id", "dedup_key") and v is not None}
    for name in ("Image", "ParentImage", "TargetFilename"):
        if _basename(data.get(name)) in drop_names:
            counts[f"dropped_scenario_name_{name}"] += 1
            return None
    for name in ("CommandLine", "ParentCommandLine"):
        text = str(data.get(name) or "").lower()
        if text and any(n in text for n in drop_names):
            counts[f"dropped_scenario_name_{name}"] += 1
            return None
    eid, kind = row.get("event_id"), row.get("type")
    rec = {"host": vm.host, "label": LABEL, "session": ns.session, "source": row.get("source"),
           "channel": row.get("channel"), "record_id": ns.record_id(row.get("record_id")), "seq": row.get("seq"),
           "event_id": eid, "type": kind, "provider": row.get("provider"), "time": ns.time(row.get("time")),
           "origin": row.get("origin"), "origin_recorded": row.get("origin_recorded")}
    rec = {k: v for k, v in rec.items() if v is not None}
    for name in ("ProcessGuid", "ParentProcessGuid"):
        if name in data:
            data[name] = ns.guid(data[name])
    for name in ("ProcessId", "ParentProcessId"):
        if name in data:
            data[name] = ns.pid(data[name])
    for name in TIME_FIELDS:
        if name in data:
            data[name] = ns.time(data[name])
    if "ref_record_id" in data:
        data["ref_record_id"] = ns.record_id(data["ref_record_id"])
    for name in ("Hashes", "Hash"):
        if name in data:
            data[name] = ns.hashes(data[name])
    if "sha256" in data:
        data["sha256"] = ns.sha(data["sha256"])
    for name in IP_FIELDS:
        if name in data:
            data[name] = ns.ip(data[name])
    if "QueryName" in data:
        data["QueryName"] = ns.dns(data["QueryName"])
    if "QueryResults" in data:
        data["QueryResults"] = ns.query_results(data["QueryResults"])
    if "Contents" in data:
        data["Contents"] = ns.contents(data["Contents"])
    for name in USER_FIELDS:
        data.pop(name, None)
    # file paths: a path that exists in the VM window moves under C:\overlay<k>\
    renamed = {}
    for name in PATH_FIELDS:
        p = data.get(name)
        if not p:
            continue
        suffix = ""
        if eid == 15 and str(p).lower().endswith(ZONE_SUFFIX):
            p, suffix = str(p)[:-len(ZONE_SUFFIX)], str(p)[-len(ZONE_SUFFIX):]
        q = ns.path(p, vm.collisions)
        if q != p:
            counts["path_collisions_rewritten"] += 1
            renamed[norm_path(p)] = q
            data[name] = q + suffix
    # a program whose path the VM CREATED in the window would meet R1 across the two worlds
    for name in ("Image", "ParentImage"):
        p = data.get(name)
        if p and norm_path(p) in vm.file_paths:
            data[name] = ns.path(p, vm.file_paths)
            counts["image_collisions_rewritten"] += 1
    for name in ("CommandLine", "ParentCommandLine"):
        text = data.get(name)
        if text and renamed:
            for old, new in renamed.items():
                text = re.sub(re.escape(old), new.replace("\\", "\\\\"), text, flags=re.IGNORECASE)
            data[name] = text
    data["overlay_slice"] = ns.k
    # grafting: a boundary orphan's parent (started before the slice) becomes a live VM process
    if eid == 1 and graft:
        original_parent = row.get("ParentProcessGuid")
        if original_parent and not is_zero_guid(original_parent) and norm_guid(original_parent) not in starts_in_slice:
            t = parse_time(data.get("UtcTime")) or parse_time(rec.get("time"))
            found = vm.graft_target(row.get("ParentImage"), t.timestamp(), roles) if t else None
            if found:
                g, p = found
                data["ParentProcessGuid"] = g
                if p.get("pid") is not None:
                    data["ParentProcessId"] = p["pid"]
                if p.get("image"):
                    data["ParentImage"] = p["image"]
                data.pop("ParentCommandLine", None)
                data["overlay_grafted"] = 1
                counts["grafted"] += 1
                if norm_guid(original_parent) in acting_in_slice:
                    counts["grafted_parent_also_acts_in_slice"] += 1
                grafts.append({"child": data.get("ProcessGuid"), "parent": g, "slice": ns.k})
            else:
                counts["orphans_not_grafted"] += 1
    elif eid == 1:
        original_parent = row.get("ParentProcessGuid")
        if original_parent and not is_zero_guid(original_parent) and norm_guid(original_parent) not in starts_in_slice:
            counts["orphans_not_grafted"] += 1
    rec["data"] = data
    return rec


def build(vm_records, lo, hi, laptop_path, volume, seed, out_path, *, graft=True, run_info=None,
          scenarios_dir=SCENARIOS_DIR, cfg=None, frozen_cutoff=None):
    """Write the overlay store to `out_path` (a fresh file) and return its meta (counts only).
    vm_records = the run window's records exactly as the graph checker replays them
    (check_graph_scenario.window_records); lo, hi = the window (check_scenario.run_window)."""
    if isinstance(volume, bool) or int(volume) != volume or volume < 0 or volume > MAX_VOLUME:
        raise ValueError(f"volume must be a whole number 0..{MAX_VOLUME}, got {volume!r}")
    volume, seed = int(volume), int(seed)
    if not vm_records:
        raise ValueError("the run window holds no VM records")
    cfg = cfg or load_config()
    vm = VMFacts(vm_records)
    own, roles = scenario_programs(scenarios_dir)
    lo_ms, hi_ms = _ms(lo), _ms(hi)
    if hi_ms <= lo_ms:
        raise ValueError("the run window is empty")
    length_ms = hi_ms - lo_ms

    con, snap = open_laptop(laptop_path, frozen_cutoff)
    counts, grafts, slices, overlay = Counter(), [], [], []
    try:
        host = laptop_host(con, snap["_cutoff_end"])
        active = laptop_active_time(con, host, snap["_cutoff_end"], cfg)
        rng = np.random.default_rng(seed)
        starts = choose_slices(active, length_ms, volume, rng)
        for k, start_ms in enumerate(starts, 1):
            ns = Namespace(seed, k, lo_ms - start_ms)
            rows = laptop_rows(con, host, start_ms, start_ms + length_ms, snap["_cutoff_end"])
            starts_in_slice = {norm_guid(r["ProcessGuid"]) for r in rows
                               if r.get("event_id") == 1 and r.get("ProcessGuid") and not is_zero_guid(r["ProcessGuid"])
                               and _basename(r.get("Image")) not in own}
            acting = {norm_guid(r["ProcessGuid"]) for r in rows if r.get("ProcessGuid") and not is_zero_guid(r["ProcessGuid"])}
            n_before = len(overlay)
            for row in rows:
                rec = _slice_record(row, ns, vm, own, roles, graft, starts_in_slice, counts, grafts, acting)
                if rec is not None:
                    overlay.append(rec)
            slices.append({"k": k, "session": ns.session, "shift_seconds": (lo_ms - start_ms) / 1000,
                           "laptop_rows": len(rows), "rows_kept": len(overlay) - n_before,
                           "laptop_start_utc": datetime.fromtimestamp(start_ms / 1000, timezone.utc).isoformat(timespec="milliseconds"),
                           "laptop_end_utc": datetime.fromtimestamp((start_ms + length_ms) / 1000, timezone.utc).isoformat(timespec="milliseconds")})
    finally:
        con.close()
    vm_guids = {norm_guid(g) for g in vm.procs}
    leaked = [r for r in overlay if norm_guid((r["data"].get("ProcessGuid"))) in vm_guids]
    if leaked:
        raise RuntimeError(f"{len(leaked)} overlay GUID(s) collide with VM GUIDs (hash prefix clash): refusing to write")
    for r in overlay:
        counts[f"rows_{r.get('type') or 'event' + str(r.get('event_id'))}"] += 1

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(out_path + suffix):
            os.remove(out_path + suffix)
    store = EventStore(out_path)
    ins_vm, dup_vm = store.insert(vm_records)
    overlay.sort(key=lambda r: (r.get("time") or "", r.get("record_id") or 0, r.get("seq") or 0))
    ins_ov, dup_ov = store.insert(overlay)
    store.close()
    if dup_ov:
        raise RuntimeError(f"{dup_ov} overlay rows collided with existing dedup keys")
    run_info = run_info or {}
    meta = {"version": META_VERSION, "built_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scenario": run_info.get("scenario"), "run_id": run_info.get("run_id"),
            "run_start": run_info.get("start"), "run_end": run_info.get("end"), "server": run_info.get("server"),
            "window_lo": lo.isoformat(), "window_hi": hi.isoformat(), "window_seconds": length_ms / 1000,
            "host": vm.host, "volume": volume, "seed": seed, "graft": graft,
            "laptop_db": os.path.basename(laptop_path), "laptop_cutoff_day_utc": snap.get("cutoff_day_utc"),
            "laptop_snapshot_built_utc": snap.get("built_utc"), "frozen_cutoff_day_utc": snap["_frozen_cutoff"],
            "sleep_gap_seconds": cfg.sleep_gap_seconds, "vm_records": ins_vm, "vm_duplicates": dup_vm,
            "overlay_rows": ins_ov, "slices": slices, "counts": dict(sorted(counts.items())), "grafts": grafts,
            "scenario_programs_dropped": sorted(own), "role_programs_never_grafted": sorted(roles)}
    db = sqlite3.connect(out_path)
    db.execute("CREATE TABLE overlay_meta (key TEXT PRIMARY KEY, value TEXT)")
    db.executemany("INSERT INTO overlay_meta VALUES (?, ?)",
                   [(k, v if isinstance(v, str) else json.dumps(v)) for k, v in meta.items()])
    db.commit()
    db.execute("PRAGMA journal_mode=DELETE")       # one plain file: read-only opens need no -wal/-shm
    db.close()
    return meta


def read_meta(path):
    """The overlay_meta of a store (JSON values decoded)."""
    con = _ro(path)
    try:
        out = {}
        for k, v in con.execute("SELECT key, value FROM overlay_meta"):
            try:
                out[k] = json.loads(v)
            except (TypeError, json.JSONDecodeError):
                out[k] = v
        return out
    finally:
        con.close()


# -- reading an overlay graph back (tests and the experiment) -------------------------------------
def row_classes(path):
    """{dedup_key: slice number or None (a VM row)} and the set of overlay process GUIDs."""
    con = _ro(path)
    try:
        cols = {r[1].lower() for r in con.execute("PRAGMA table_info(events)")}
        if "overlay_slice" not in cols:
            rows = {k: None for (k,) in con.execute("SELECT dedup_key FROM events")}
            return rows, set()
        rows, guids = {}, set()
        grafted = "overlay_grafted" in cols
        sql = "SELECT dedup_key, overlay_slice, ProcessGuid, ParentProcessGuid" + (", overlay_grafted" if grafted else ", NULL") + " FROM events"
        for key, k, g, pg, gr in con.execute(sql):
            rows[key] = k
            if k is not None:
                if g and not is_zero_guid(g):
                    guids.add(norm_guid(g))
                if pg and not is_zero_guid(pg) and not gr:
                    guids.add(norm_guid(pg))
        return rows, guids
    finally:
        con.close()


def node_classes(G, path):
    """{node: 'overlay' | 'vm' | 'shared'}: a process by its GUID; any other node by the rows of
    its facts (any layer: an F1 download marker can be the only fact on a bare file node; review
    2026-10-24) and gaps ('shared' = both worlds state something about it: a leak)."""
    rows, guids = row_classes(path)
    out = {}
    for n, d in G.nodes(data=True):
        if d.get("kind") == "process":
            out[n] = "overlay" if norm_guid(d.get("guid")) in guids else "vm"
            continue
        keys = [e["primary"]["key"] for _, _, e in list(G.in_edges(n, data=True)) + list(G.out_edges(n, data=True))
                if e.get("grade") == "fact" and e.get("primary")]
        keys += [ev["key"] for g in d.get("gaps", []) for ev in g.get("evidence", [])]
        worlds = {"overlay" if rows.get(k) is not None else "vm" for k in keys}
        out[n] = "shared" if len(worlds) > 1 else (worlds.pop() if worlds else "vm")
    return out


def edge_class(u, v, d, classes, roles=(), grafts=()):
    """The source class of a layer-2 edge: scenario-story, scenario-vm, vm-background,
    overlay-internal, cross/graft (through a grafted parent or child), cross-r4 (a file named on
    a command line in one world and created in the other: the measured false link) or cross (a leak)."""
    cu, cv = classes.get(u, "vm"), classes.get(v, "vm")
    if "shared" in (cu, cv):
        return "cross"
    if cu == cv == "overlay":
        return "overlay-internal"
    if cu == cv == "vm":
        n_roles = (u in roles) + (v in roles)
        return "scenario-story" if n_roles == 2 else ("scenario-vm" if n_roles == 1 else "vm-background")
    if d.get("row") == "R4":
        return "cross-r4"
    if d.get("via") in grafts:
        return "cross/graft"
    return "cross"


def cross_summary(G, path, role_nodes=(), grafts=None):
    """Counts the design's promises rest on: facts joining the two worlds (only grafted `started`
    edges may), layer-2 edges by class/row/band, cross T2/T3 observed vs their sigma-p, and the
    cross R4 (name-only / full-path) links, which are provably false."""
    classes = node_classes(G, path)
    graft_pairs = {(norm_guid(g["parent"]), norm_guid(g["child"])) for g in (grafts or [])}
    graft_guids = {g for pair in graft_pairs for g in pair}
    graft_nodes = {n for n, d in G.nodes(data=True) if d.get("kind") == "process" and norm_guid(d.get("guid")) in graft_guids}
    roles = set(role_nodes)
    out = {"shared_nodes": sorted(n for n, c in classes.items() if c == "shared"),
           "cross_facts": [], "graft_started": 0, "graft_started_to_role": 0,
           "hypotheses": Counter(), "cross_t_observed": 0, "cross_t_sigma_p": 0.0,
           "cross_r4": Counter(), "cross_r4_on_scenario": 0, "overlay_scenario_edges": 0}
    for u, v, d in G.edges(data=True):
        cu, cv = classes.get(u), classes.get(v)
        if d.get("grade") == "fact":
            if cu != cv:
                pair = (norm_guid(G.nodes[u].get("guid")), norm_guid(G.nodes[v].get("guid")))
                if d.get("kind") == "started" and cu == "vm" and cv == "overlay" and pair in graft_pairs:
                    out["graft_started"] += 1
                    if u in roles:
                        out["graft_started_to_role"] += 1
                else:
                    out["cross_facts"].append((u, d.get("kind"), v))
            if (u in roles) != (v in roles) and "overlay" in (cu, cv):
                out["overlay_scenario_edges"] += 1
            continue
        if d.get("grade") != "hypothesis":
            continue
        c = edge_class(u, v, d, classes, roles, graft_nodes)
        out["hypotheses"][(c, d.get("row"), d.get("band"))] += 1
        if (u in roles or v in roles) and "overlay" in (cu, cv):
            # a cross R4 onto a scenario node is the measured false name-only link (design section 0,
            # decided before the run 2026-10-24), counted apart; any OTHER overlay-scenario edge is a leak
            if c == "cross-r4":
                out["cross_r4_on_scenario"] += 1
            else:
                out["overlay_scenario_edges"] += 1
        if c.startswith("cross") and d.get("row") in ("T2", "T3"):
            out["cross_t_observed"] += 1
            out["cross_t_sigma_p"] += float(d.get("p") or 0.0)
        if c.startswith("cross") and d.get("row") == "R4":
            out["cross_r4"]["full-path" if "full path" in str(d.get("reason")) else "name-only"] += 1
    out["classes"] = Counter(classes.values())
    return out
