"""Coincidence-based confidence for the evidence graph's hypotheses (DESIGN 4.7, package E).

A timing hypothesis says "effect B happened within t seconds of cause A in the same process,
so they are probably related". This module answers: **how likely is that closeness by pure
chance?** (the link-type table T1-T3, approved by Yousif 2026-10-23), and grades the rule
rows R1-R4 and the download-marker fact F1 that are not about timing.

    python -m engine.confidence --build-pool --db <dev-laptop.db> --out recordings/.../pool.json
    python -m engine.confidence --a16 --db <dev-laptop.db> --pool <pool.json> --out <folder>

Both print counts only (privacy rule 9.1); the pool file holds program names and stays in the
git-ignored recordings/ folder.

The maths, in DESIGN's words:
  1. lambda = the rate of the EFFECT, the larger ("stricter") of
       - the pool rate: laptop processes of the same program (>= min_pool_events effects there),
         otherwise laptop processes whose active lifetime falls in the same lifetime band;
       - the within-life rate: this process's effects (the one under test included) per second
         of its own active lifetime. A process that lived less than the window is not
         assessable by timing at all.
  2. one cause's chance  p1 = 1 - exp(-lambda * t)       (Poisson; t = window length)
  3. N competing causes  p  = 1 - (1 - p1) ** N           (N = the process's causes within
                                                            +-competing_span of the linked cause)
  4. bands: p < band_high -> high, p < band_medium -> medium, else low (an edge value goes to
     the weaker band).
"Active time" (per machine) is the time between consecutive recorded events that are at most
sleep_gap_seconds apart; a longer silence (asleep, switched off) is left out.

All numbers live in config/frozen.yaml (`confidence:`), read by `load_config`.
"""

import argparse
import bisect
import hashlib
import json
import math
import ntpath
import numbers
import os
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, fields, replace
from urllib.parse import urlsplit

import numpy as np

from engine.graph import SYSMON_CHANNEL, ip_key, is_zero_guid, norm_guid, parse_time

FROZEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "frozen.yaml")
REQUIRED = ("band_high", "band_medium", "window_before_seconds", "window_after_seconds", "sleep_gap_seconds",
            "min_pool_events", "competing_span_seconds", "lifetime_bands_seconds")
OFFICIAL_ONLY = ("burst_factor", "pool_sha256")     # may be null while developing, never in an official run
KINDS = ("out", "in", "file", "child")              # outgoing / qualifying inbound connections, files, children
TIMING_ROWS = {"T1": ("out", "file"), "T2": ("in", "child"), "T3": ("out", "child")}   # cause kind, effect kind
EPHEMERAL_PORT = 49152                               # Windows' dynamic port range starts here
# the agent's port snapshots share its loop with event reading: a new listener was first seen up to
# ~25 s after it opened (DESIGN 6, S3), so a listen record up to this long AFTER an inbound
# connection still shows the program was listening on that port
LISTEN_SNAPSHOT_SLACK = 30.0
UNKNOWN_PROGRAM = "?"                                # no image path: never pooled as a "program"
EMPTY_SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


@dataclass(frozen=True)
class ConfidenceConfig:
    band_high: float                     # p below this -> "high"
    band_medium: float                   # p below this -> "medium"; otherwise "low"
    window_before_seconds: float         # the effect may be stamped this long BEFORE the cause (event ordering)
    window_after_seconds: float          # ... and this long after it
    sleep_gap_seconds: float             # a silence longer than this is not active time
    min_pool_events: int                 # a program's own pool rate needs this many effects on the laptop
    competing_span_seconds: float        # competing causes are counted within +- this of the linked cause
    lifetime_bands_seconds: tuple        # edges of the lifetime bands of the fallback pool, e.g. (60, 3600)
    burst_factor: float = None           # open until A16 / package J; null = 1 while developing
    pool_sha256: str = None              # SHA256 of the frozen pool file; null while developing
    leads_only: tuple = ()               # timing rows never graded above "low" (package J, 2026-10-24: T2, T3)

    def __post_init__(self):
        object.__setattr__(self, "lifetime_bands_seconds", tuple(self.lifetime_bands_seconds))
        object.__setattr__(self, "leads_only", tuple(self.leads_only or ()))
        unknown_rows = [r for r in self.leads_only if r not in TIMING_ROWS]
        if unknown_rows:
            raise ValueError(f"confidence: leads_only names no timing row: {unknown_rows} (rows: {sorted(TIMING_ROWS)})")
        if not 0 < self.band_high < self.band_medium < 1:
            raise ValueError("confidence: need 0 < band_high < band_medium < 1")
        if self.window_before_seconds < 0 or self.window_after_seconds <= 0:
            raise ValueError("confidence: window_before_seconds >= 0 and window_after_seconds > 0")
        if self.sleep_gap_seconds <= 0 or self.competing_span_seconds <= 0 or self.min_pool_events < 1:
            raise ValueError("confidence: sleep gap, competing span and min_pool_events must be positive")
        edges = self.lifetime_bands_seconds
        if not edges or any(e <= 0 for e in edges) or list(edges) != sorted(set(edges)):
            raise ValueError("confidence: lifetime_bands_seconds must be increasing positive numbers")
        if self.burst_factor is not None and self.burst_factor < 1:
            raise ValueError("confidence: burst_factor must be at least 1 (it can only add caution)")

    @property
    def window(self) -> float:
        """t in the formula: the length of the window an effect must fall in."""
        return self.window_before_seconds + self.window_after_seconds

    @property
    def burst(self) -> float:
        return 1.0 if self.burst_factor is None else float(self.burst_factor)


def load_config(path: str = FROZEN, official: bool = False) -> ConfidenceConfig:
    """The `confidence:` block of config/frozen.yaml. Refuses unknown keys (a typo would silently
    fall back to a default) and null required values; `official=True` also refuses the values
    that may stay open while developing (the burst factor, the pool's fingerprint)."""
    import yaml
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    block = doc.get("confidence") or {}
    known = {f.name for f in fields(ConfidenceConfig)}
    unknown = sorted(k for k in block if k not in known)
    if unknown:
        raise ValueError(f"config/frozen.yaml confidence: unknown keys {', '.join(unknown)}")
    missing = [k for k in REQUIRED if block.get(k) is None]
    if official:
        missing += [k for k in OFFICIAL_ONLY if block.get(k) is None]
    if missing:
        raise ValueError(f"config/frozen.yaml confidence: not chosen yet (null): {', '.join(sorted(missing))}")
    # competing causes are counted over the graph window, so the graph shows what was counted
    # (DESIGN 4.7): the two numbers must agree whenever the file sets the window
    window_minutes = (doc.get("graph") or {}).get("window_minutes")
    if window_minutes is not None and float(block["competing_span_seconds"]) != float(window_minutes) * 60:
        raise ValueError(f"config/frozen.yaml: confidence.competing_span_seconds ({block['competing_span_seconds']}) "
                         f"must equal graph.window_minutes * 60 ({float(window_minutes) * 60:g})")
    return ConfidenceConfig(**block)


# -- the formula -------------------------------------------------------------------------------
def _check(name, value, finite=False):
    """A real number >= 0 (numpy numbers too; True/False and NaN refused; inf only if allowed)."""
    if isinstance(value, bool) or not isinstance(value, numbers.Real) or math.isnan(value) or value < 0 \
            or (finite and math.isinf(value)):
        raise ValueError(f"{name} must be a {'finite ' if finite else ''}number >= 0, got {value!r}")


def chance(lam: float, t: float) -> float:
    """p = 1 - e^(-lambda*t): the chance that at least one event of a Poisson stream with rate
    `lam` (per second) lands in a window of `t` seconds. expm1 keeps tiny values exact
    (1 - exp(-1e-12) would round to 0 in plain floating point)."""
    _check("lambda", lam)
    _check("t", t)
    if lam == 0 or t == 0:
        return 0.0
    return -math.expm1(-lam * t)          # exp(-inf) = 0, so an infinite product gives exactly 1


def competing(p1: float, n: int) -> float:
    """p = 1 - (1 - p1)^N: the chance that at least one of N independent causes has an effect
    in its window by luck. Computed as -expm1(N * log1p(-p1)) so tiny p1 and large N stay exact.
    (Windows of dense causes overlap, so the true chance is a little lower: cautious.)"""
    _check("p1", p1)
    if p1 > 1:
        raise ValueError(f"p1 must be <= 1, got {p1!r}")
    if isinstance(n, bool) or not isinstance(n, numbers.Real) or math.isinf(n) or math.isnan(n) \
            or int(n) != n or n < 1:
        raise ValueError(f"N must be a whole number >= 1, got {n!r}")
    if p1 >= 1:
        return 1.0
    return -math.expm1(int(n) * math.log1p(-p1))


def band(p: float, cfg: ConfidenceConfig) -> str:
    """'high' if p < band_high, 'medium' if p < band_medium, else 'low' (edge -> weaker band)."""
    _check("p", p)
    if p < cfg.band_high:
        return "high"
    if p < cfg.band_medium:
        return "medium"
    return "low"


@dataclass(frozen=True)
class TimingGrade:
    band: str            # high / medium / low
    p: float             # chance of coincidence with N competing causes (what sets the band)
    p1: float            # one cause's chance
    lam: float           # effect rate used (per second), burst factor included
    source: str          # which picture of normal set lambda: "pool:<...>" or "within-life"
    n_causes: int
    reason: str


def timing_grade(cfg: ConfidenceConfig, *, pool_rate: float, pool_source: str, n_effects: int,
                 life_seconds: float, n_causes: int) -> TimingGrade:
    """Grade one timing hypothesis (T1-T3). `n_effects` = the process's effects of this kind in
    its recorded life up to the graph's end, the one under test INCLUDED (so >= 1);
    `life_seconds` = its active lifetime; `n_causes` = competing causes within +-competing_span
    of the linked cause."""
    _check("pool_rate", pool_rate, finite=True)
    _check("life_seconds", life_seconds, finite=True)
    if isinstance(n_effects, bool) or int(n_effects) != n_effects or n_effects < 1:
        raise ValueError("n_effects counts the effect under test, so it must be >= 1")
    if life_seconds < cfg.window:
        return TimingGrade("low", 1.0, 1.0, math.inf, "not assessable", int(n_causes),
                           f"not assessable by timing: the process was active {life_seconds:.1f} s, "
                           f"shorter than the {cfg.window:g} s window, so everything it did is 'close'")
    within = n_effects / life_seconds
    lam, source = (pool_rate, f"pool:{pool_source}") if pool_rate >= within else (within, "within-life")
    lam *= cfg.burst
    p1 = chance(lam, cfg.window)
    p = competing(p1, n_causes)
    return TimingGrade(band(p, cfg), p, p1, lam, source, int(n_causes),
                       f"{n_causes} competing cause(s); effect rate {lam:.5f}/s ({source}); "
                       f"chance of a coincidence {p:.2%}")


# -- windows and pairs (T1-T3) -------------------------------------------------------------------
def in_window(t_cause: float, t_effect: float, cfg: ConfidenceConfig) -> bool:
    """Effect within [cause - before, cause + after], both ends included."""
    d = t_effect - t_cause
    return -cfg.window_before_seconds <= d <= cfg.window_after_seconds


def link_cause(cause_times: list, t_effect: float, cfg: ConfidenceConfig):
    """The cause an effect is linked to: the LATEST cause whose window contains it (sorted
    `cause_times`); None if no window contains it."""
    i = bisect.bisect_right(cause_times, t_effect + cfg.window_before_seconds) - 1
    if i >= 0 and in_window(cause_times[i], t_effect, cfg):
        return cause_times[i]
    return None


def n_competing(cause_times: list, t_cause: float, cfg: ConfidenceConfig) -> int:
    """Causes of the same process within +-competing_span of the linked cause, itself included
    (at least 1)."""
    lo = bisect.bisect_left(cause_times, t_cause - cfg.competing_span_seconds)
    hi = bisect.bisect_right(cause_times, t_cause + cfg.competing_span_seconds)
    return max(hi - lo, 1)


def timing_pairs(causes, effects, cfg: ConfidenceConfig) -> list:
    """causes, effects: iterables of (process_id, time). Returns one hypothesis per effect that
    falls in a cause window of the SAME process: (process_id, t_effect, t_cause, N)."""
    by_proc = defaultdict(list)
    for pid, t in causes:
        by_proc[pid].append(t)
    for v in by_proc.values():
        v.sort()
    out = []
    for pid, te in sorted(effects, key=lambda e: (str(e[0]), e[1])):
        ct = by_proc.get(pid)
        if not ct:
            continue
        tc = link_cause(ct, te, cfg)
        if tc is not None:
            out.append((pid, te, tc, n_competing(ct, tc, cfg)))
    return out


def t1_effect_qualifies(hash_status) -> bool:
    """A new folder (agent FILE_HASH status 'directory') has no content: not a T1 effect."""
    return hash_status != "directory"


def t2_cause_qualifies(protocol, local_port, listened_ports=()) -> bool:
    """T2's cause: an inbound TCP connection to a port the process's program listened on
    (`listened_ports`), or to a non-ephemeral port. UDP 'inbound' records are replies to the
    process's own requests."""
    if str(protocol or "").strip().lower() != "tcp":
        return False
    try:
        port = int(local_port)
    except (TypeError, ValueError):
        return False
    return port < EPHEMERAL_PORT or port in {int(p) for p in listened_ports}


# -- rule rows (R1-R4) and the download marker (F1) -----------------------------------------------
@dataclass(frozen=True)
class RuleGrade:
    link: str            # "fact", "hypothesis" or "none"
    band: str            # high / medium / low for a hypothesis; None otherwise
    reason: str


def constant_hash(sha) -> bool:
    """The empty file's SHA256, or a hash of one repeated character (a placeholder)."""
    s = (sha or "").strip().upper()
    return not s or s == EMPTY_SHA256 or len(set(s)) <= 1


def grade_r1(*, file_hash, process_hash, deleted_between: bool) -> RuleGrade:
    """The latest creation of the program's path before it started (taken first), then:
    both fingerprints known and equal -> the layer-1 fact; known and different -> no link
    ("replaced"); either unknown (or a placeholder) -> R1 medium, low if the path was deleted in
    between."""
    usable = lambda h: h and not constant_hash(h)          # noqa: E731
    if usable(file_hash) and usable(process_hash):
        if file_hash.upper() == process_hash.upper():
            return RuleGrade("fact", None, "same path and same content (layer 1)")
        return RuleGrade("none", None, "file replaced before it ran: same path, different content")
    if deleted_between:
        return RuleGrade("hypothesis", "low", "same path, content unknown; the file was deleted in between")
    return RuleGrade("hypothesis", "medium", "same path, content unknown (no usable fingerprint)")


def grade_r2(*, content: str, x_fingerprint_time: float, y_creation_times, start_time: float,
             x_deletion_times=(), y_deletion_times=(), sysmon_restart_times=(), y_fingerprint=None,
             n_other_paths: int = 1, x_known_only_from_deletion: bool = False) -> dict:
    """R2 for a process starting at path Y with content H that equals file X's content.
    Returns {"fact": "same content" or None, "direction": RuleGrade or None, "reason"}.
    The direction "Y is a copy of X" needs ALL of: a RECORDED creation of Y after X's fingerprint
    time and before the start; no recorded deletion of X between X's fingerprint and that
    creation; no Sysmon restart between X's fingerprint and the start and no deletion of Y between
    its creation and the start (otherwise the Y that ran may not be the file that was created);
    Y's own fingerprint (if recorded) equal to H. On a fresh recording "never seen before" only
    means "since the recording began", hence "recorded"."""
    if constant_hash(content):
        return {"fact": None, "direction": None, "reason": "empty or constant content: no link"}
    if x_known_only_from_deletion:
        return {"fact": "same content", "direction": None,
                "reason": "X's content is known only from its deletion (creation time unknown): no direction"}
    ys = sorted(t for t in y_creation_times if x_fingerprint_time < t < start_time)
    if not ys:
        early = any(t < start_time for t in y_creation_times)
        why = ("Y was created before X's content was complete (before X's fingerprint), possibly before X existed"
               if early else "no recorded creation of Y since X: Y may have existed before the recording")
        return {"fact": "same content", "direction": None, "reason": why}
    cy = ys[-1]
    if any(x_fingerprint_time < t <= cy for t in x_deletion_times):
        return {"fact": "same content", "direction": None, "reason": "X was deleted before Y was created"}
    if any(x_fingerprint_time < t <= start_time for t in sysmon_restart_times):
        return {"fact": "same content", "direction": None, "reason": "Sysmon restarted between X and the start (e.g. a snapshot restore)"}
    if any(cy <= t < start_time for t in y_deletion_times):
        return {"fact": "same content", "direction": None, "reason": "Y was deleted after its creation and before the start"}
    if y_fingerprint and y_fingerprint.upper() != content.upper():
        return {"fact": "same content", "direction": None, "reason": "Y's own fingerprint differs from X's content"}
    if isinstance(n_other_paths, bool) or int(n_other_paths) != n_other_paths or n_other_paths < 1:
        raise ValueError("n_other_paths counts X, so it must be >= 1")
    b = "high" if n_other_paths == 1 else ("medium" if n_other_paths <= 4 else "low")
    return {"fact": "same content",
            "direction": RuleGrade("hypothesis", b, f"Y created after X with the same content; "
                                                    f"{n_other_paths} other path(s) hold it"),
            "reason": "direction supported"}


def parse_query_results(text) -> set:
    """Sysmon event 22 QueryResults ('type: 5 cname;1.2.3.4;::ffff:5.6.7.8;') -> addresses as
    written in graph node ids (CNAME entries skipped, IPv4-mapped IPv6 unwrapped)."""
    out = set()
    for tok in str(text or "").split(";"):
        tok = tok.strip()
        if tok and not tok.lower().startswith("type:") and tok != "-":
            out.add(ip_key(tok))
    return out


def names_for_connection(lookups, t_conn: float, ip: str, span: float) -> set:
    """lookups: (time, name, answer addresses) of the SAME process. Names whose answer held `ip`
    and that were looked up BEFORE the connection, within `span` seconds."""
    key = ip_key(ip)
    return {name.lower() for t, name, ips in lookups if t_conn - span <= t <= t_conn and key in ips}


def grade_r3(n_names: int) -> RuleGrade:
    """How many names the process resolved to this address before connecting."""
    if n_names < 1:
        return RuleGrade("none", None, "no lookup by this process led to this address")
    b = "high" if n_names == 1 else ("medium" if n_names <= 4 else "low")
    return RuleGrade("hypothesis", b, f"{n_names} name(s) resolved to this address before the connection")


def grade_r4(*, full_path: bool, deleted_between: bool) -> RuleGrade:
    """The command line names a file created before the start (not the program itself).
    It says P was started WITH the file as an argument, not what P did with it."""
    if deleted_between:
        return RuleGrade("hypothesis", "low", "named on the command line, but the file was deleted in between")
    if full_path:
        return RuleGrade("hypothesis", "medium", "the command line names the file's full path")
    return RuleGrade("hypothesis", "low", "the command line names only the file's name (partial match)")


def marker_host(contents) -> str:
    """The host in a download marker's text (event 15 `Contents`, 'HostUrl=https://h:p/x').
    Sysmon renders the marker's line breaks as spaces (real laptop markers: two spaces between
    '[ZoneTransfer]', 'ZoneId=3', 'HostUrl=...'; found by package F's data check 2026-10-23), so
    the key is searched anywhere in the text, not at the start of a line."""
    m = re.search(r"(?i)(?:^|\s)HostUrl=(\S+)", str(contents or ""))
    if not m:
        return None
    host = urlsplit(m.group(1)).hostname
    return host.lower() if host else None


MARKER_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


def marker_port(contents):
    """The port in a download marker's HostUrl (explicit, else the scheme's default), or None."""
    m = re.search(r"(?i)(?:^|\s)HostUrl=(\S+)", str(contents or ""))
    if not m:
        return None
    u = urlsplit(m.group(1))
    try:
        port = u.port                      # an explicit :0 stays 0 (never a real endpoint), not the default
        return MARKER_DEFAULT_PORTS.get((u.scheme or "").lower()) if port is None else port
    except ValueError:                     # a malformed port
        return None


def grade_f1(*, host, endpoint_ip, r3_high_names=(), endpoint_port=None, marker_port=None) -> RuleGrade:
    """What a download marker does to T1. The marker is written by the downloading program itself,
    so it is that program's own statement, never proof (decided cautiously 2026-10-24, pending
    Yousif's confirmation; the approved table had "fact"): the marker's host is R's literal address
    AND its port is R's port -> T1 becomes a HIGH hypothesis; a name tied to R by a high-grade R3
    link (and the port matching) -> also high; anything else -> only support, T1 keeps its grade.
    The port check (found by package F's plan review): graph endpoints are ip:port, and a marker
    naming 10.0.2.2:8080 must not upgrade a link whose cause was 10.0.2.2:53."""
    ports_match = endpoint_port is None or marker_port is None or int(endpoint_port) == int(marker_port)
    if host and endpoint_ip and ip_key(host) == ip_key(endpoint_ip) and ports_match:
        return RuleGrade("hypothesis", "high", "the program's own download marker names the address and port it connected to")
    if host and host.lower() in {n.lower() for n in r3_high_names} and ports_match:
        return RuleGrade("hypothesis", "high", "the download marker names a host that a high-grade lookup ties to this address")
    return RuleGrade("none", None, "the download marker names another host or port: support only")


# -- active time ---------------------------------------------------------------------------------
class ActiveTime:
    """One machine's active stretches: consecutive recorded events at most `gap` seconds apart
    belong to one stretch (exactly `gap` included); a longer silence (sleep, switched off) is
    left out. A stretch ends at its last event."""

    def __init__(self, times, gap: float):
        t = np.sort(np.asarray([x for x in times if x is not None], dtype=float))
        if t.size == 0:
            self.starts = self.ends = np.zeros(0)
            self.cum = np.zeros(1)
            self.total, self.last = 0.0, None
            return
        cut = np.where(np.diff(t) > gap)[0]
        self.starts = np.concatenate(([t[0]], t[cut + 1]))
        self.ends = np.concatenate((t[cut], [t[-1]]))
        self.cum = np.concatenate(([0.0], np.cumsum(self.ends - self.starts)))
        self.total = float(self.cum[-1])
        self.last = float(t[-1])

    def position(self, t):
        """Active seconds from the first event up to time t (vectorised; a time inside a sleep
        maps to the end of the stretch before it)."""
        t = np.asarray(t, dtype=float)
        if self.starts.size == 0:
            return np.zeros_like(t)
        i = np.clip(np.searchsorted(self.starts, t, side="right") - 1, 0, len(self.starts) - 1)
        return self.cum[i] + np.clip(t - self.starts[i], 0.0, self.ends[i] - self.starts[i])

    def seconds(self, a: float, b: float) -> float:
        """Active seconds between times a and b."""
        return max(float(self.position(b) - self.position(a)), 0.0)

    def at_position(self, pos):
        """Inverse of position(): the time at which `pos` active seconds had passed."""
        if self.starts.size == 0:
            raise ValueError("no active time")
        pos = np.asarray(pos, dtype=float)
        i = np.clip(np.searchsorted(self.cum, pos, side="right") - 1, 0, len(self.starts) - 1)
        return self.starts[i] + (pos - self.cum[i])

    def stretch_end(self, t: float) -> float:
        """The end of the active stretch that time t falls in (or the last one before it)."""
        if self.starts.size == 0:
            return t
        i = max(int(np.searchsorted(self.starts, t, side="right")) - 1, 0)
        return float(self.ends[i])


def _ts(text):
    dt = parse_time(text)
    return dt.timestamp() if dt else None


def _not_project(alias=""):
    a = f"{alias}." if alias else ""
    return f"({a}origin IS NULL OR {a}origin != 'project')"


def hosts(db: sqlite3.Connection) -> list:
    return sorted(h for (h,) in db.execute("SELECT DISTINCT host FROM events WHERE host IS NOT NULL"))


def _one_host(db, host):
    """Active time and processes are per machine: a store with several machines needs `host`."""
    if host is not None:
        return host
    hs = hosts(db)
    if len(hs) > 1:
        raise ValueError(f"this store holds {len(hs)} machines: pass host= (active time is per machine)")
    return hs[0] if hs else None


def active_time(db: sqlite3.Connection, cfg: ConfidenceConfig, host=None, until=None) -> ActiveTime:
    """Active time of ONE machine from all its records (our own tools included: the machine is
    on), up to `until` (the graph's end time) if given."""
    host = _one_host(db, host)
    sql, params = "SELECT UtcTime, time FROM events", []
    if host is not None:
        sql += " WHERE host = ?"
        params.append(host)
    times = (_ts(u) or _ts(t) for u, t in db.execute(sql, params))
    if until is not None:
        times = (t for t in times if t is not None and t <= until)
    return ActiveTime(times, cfg.sleep_gap_seconds)


def event_times(db: sqlite3.Connection, where: str, params=(), host=None, until=None) -> list:
    """Times of the events matching `where` (an SQL condition written by OUR code; every value
    goes in `params`, never into the text), our own tools excluded."""
    sql = f"SELECT UtcTime, time FROM events WHERE {_not_project()} AND ({where})"
    params = list(params)
    if host is not None:
        sql += " AND host = ?"
        params.append(host)
    times = (t for t in (_ts(u) or _ts(r) for u, r in db.execute(sql, params)) if t is not None)
    return sorted(t for t in times if until is None or t <= until)


def machine_rate(db: sqlite3.Connection, where: str, params=(), active: ActiveTime = None,
                 cfg: ConfidenceConfig = None, host=None, until=None) -> tuple:
    """lambda for ANY filter on ONE machine: matching events per active second.
    Returns (rate, count, active seconds); (0, 0, 0) when the machine was never active."""
    host = _one_host(db, host)
    active = active or active_time(db, cfg, host, until)
    if active.total <= 0:
        return 0.0, 0, 0.0
    times = event_times(db, where, params, host, until)
    # every recorded event lies inside an active stretch by construction (stretches are built from them)
    return len(times) / active.total, len(times), active.total


def sysmon_configs(db: sqlite3.Connection, host=None) -> list:
    """Sysmon configuration hashes (event 16) of one machine, in time order: the pool and the
    machine under investigation must use the same file filter (it sets file-creation rates)."""
    sql, params = "SELECT ConfigurationFileHash FROM events WHERE channel = ? AND event_id = 16", [SYSMON_CHANNEL]
    if host is not None:
        sql += " AND host = ?"
        params.append(host)
    return [h for (h,) in db.execute(sql + " ORDER BY time", params) if h]


# -- processes, their effects and the pool ---------------------------------------------------------
@dataclass
class Activity:
    """What the rates need from ONE machine's recording (up to a cut-off time)."""
    active: ActiveTime
    procs: dict           # guid -> {"program", "t0", "t1", "life"} (life in active seconds)
    events: dict          # kind -> guid -> sorted times
    counts: dict          # bookkeeping (counts only)
    host: str = None
    until: float = None   # nothing after this time was read (the graph's end time); None = everything


def load_activity(db: sqlite3.Connection, cfg: ConfidenceConfig, host=None, until=None) -> Activity:
    """Processes of one machine (our own tools' processes left out) with their active lifetimes,
    and their causes/effects by kind: 'out' (outgoing connections), 'in' (inbound connections that
    qualify for T2), 'file' (created files, folders excluded), 'child' (children started).
    `until` = the graph's end time: nothing later is read (rates, lifetimes and N then match
    what was known at that moment).
    A process's life ends at its event 5; without one, at the earliest of the next Sysmon start
    (a reboot or snapshot restore), the end of the active stretch holding its last event, and
    `until`: it is never assumed alive through a shutdown."""
    host = _one_host(db, host)
    active = active_time(db, cfg, host, until)
    hostq, hp = ("AND host = ?", [host]) if host is not None else ("", [])
    project = {norm_guid(g) for (g,) in db.execute(
        f"SELECT DISTINCT ProcessGuid FROM events WHERE origin = 'project' AND ProcessGuid IS NOT NULL {hostq}", hp)}
    def known(t):                       # a record the graph could have seen at its end time
        return t is not None and (until is None or t <= until)

    boots = sorted(t for t in (_ts(u) or _ts(r) for u, r in db.execute(
        f"SELECT UtcTime, time FROM events WHERE channel = ? AND event_id = 4 {hostq}", [SYSMON_CHANNEL, *hp])) if known(t))
    listens = defaultdict(list)         # port -> [(time, program)] from the agent's listen records
    for port, image, u, r in db.execute(
            f"SELECT LocalPort, Image, UtcTime, time FROM events WHERE type = 'PORT_LISTEN_START' {hostq}", hp):
        t = _ts(u) or _ts(r)
        if port is not None and known(t):
            listens[int(port)].append((t, (ntpath.basename(image or "") or "").lower()))
    folders = set()
    for rid, rt, u, r in db.execute(
            f"SELECT ref_record_id, ref_time, UtcTime, time FROM events "
            f"WHERE type = 'FILE_HASH' AND hash_status = 'directory' {hostq}", hp):
        if not known(_ts(u) or _ts(r)):
            continue
        try:
            folders.add((int(rid), rt))
        except (TypeError, ValueError):
            pass
    procs, events = {}, {k: defaultdict(list) for k in KINDS}
    counts = defaultdict(int)

    def proc(guid, image, t):
        p = procs.get(guid)
        if p is None:
            p = procs[guid] = {"image": image, "start": None, "end": None, "first": t, "last": t}
        if p["image"] is None and image:
            p["image"] = image
        p["first"], p["last"] = min(p["first"], t), max(p["last"], t)
        return p

    def program(image):
        return (ntpath.basename(image or "") or UNKNOWN_PROGRAM).lower()

    sql = (f"SELECT event_id, UtcTime, time, ProcessGuid, Image, ParentProcessGuid, ParentImage, Initiated, "
           f"Protocol, DestinationPort, record_id, origin FROM events WHERE channel = ? "
           f"AND event_id IN (1, 3, 5, 11) {hostq}")
    for eid, utc, rtime, guid, image, pguid, pimage, ini, proto, dport, rid, origin in db.execute(sql, [SYSMON_CHANNEL, *hp]):
        t = _ts(utc) or _ts(rtime)
        if t is None:
            counts["no_time"] += 1
            continue
        if until is not None and t > until:
            continue
        g = None if is_zero_guid(guid) else norm_guid(guid)
        if g is None or origin == "project" or g in project:
            counts["skipped_project_or_no_process"] += 1
            continue
        p = proc(g, image, t)
        if eid == 1:
            if p["start"] is None:
                p["start"] = t
            pg = None if is_zero_guid(pguid) else norm_guid(pguid)
            if pg and pg not in project:
                proc(pg, pimage, t)
                events["child"][pg].append(t)
        elif eid == 5:
            p["end"] = t
        elif eid == 3:
            d = str(ini or "").strip().lower()
            if d == "true":
                events["out"][g].append(t)
            elif d == "false":
                prog = program(p["image"] or image)
                ports = {port for port, recs in listens.items()
                         if any(tl <= t + LISTEN_SNAPSHOT_SLACK and pr == prog for tl, pr in recs)}
                if t2_cause_qualifies(proto, dport, ports):
                    events["in"][g].append(t)
                else:
                    counts["inbound_not_qualifying"] += 1
        elif eid == 11:
            try:
                key = (int(rid), rtime)
            except (TypeError, ValueError):
                key = None
            if key in folders:
                counts["folders_not_effects"] += 1
            else:
                events["file"][g].append(t)
    for p in procs.values():
        p["t0"] = p["start"] if p["start"] is not None else p["first"]
        if p["end"] is not None:
            t1 = p["end"]
        else:
            t1 = active.stretch_end(p["last"])
            i = bisect.bisect_right(boots, p["t0"])
            if i < len(boots):
                t1 = min(t1, boots[i])
            counts["no_recorded_end"] += 1
        if until is not None:
            t1 = min(t1, until)
        p["t1"] = max(t1, p["t0"])
        p["life"] = active.seconds(p["t0"], p["t1"])
        p["program"] = program(p.pop("image"))
    for k in KINDS:
        for v in events[k].values():
            v.sort()
    counts["processes"] = len(procs)
    return Activity(active, procs, events, dict(counts), host, until)


def lifetime_band(life: float, cfg: ConfidenceConfig) -> str:
    """'<60', '60-3600', '>=3600' style label of the lifetime band a process falls in."""
    edges = cfg.lifetime_bands_seconds
    if life < edges[0]:
        return f"<{edges[0]:g}"
    for lo, hi in zip(edges, edges[1:]):
        if life < hi:
            return f"{lo:g}-{hi:g}"
    return f">={edges[-1]:g}"


def lifetime_bands(cfg: ConfidenceConfig) -> list:
    """Every lifetime band label of this config, shortest lives first."""
    edges = cfg.lifetime_bands_seconds
    return [f"<{edges[0]:g}"] + [f"{lo:g}-{hi:g}" for lo, hi in zip(edges, edges[1:])] + [f">={edges[-1]:g}"]


# the confidence settings a pool depends on: a pool built with other values is refused (Pool.load)
POOL_SETTINGS = ("sleep_gap_seconds", "lifetime_bands_seconds", "min_pool_events")


def pool_settings(cfg: ConfidenceConfig) -> dict:
    """The part of a pool's meta that must match the config it is used with."""
    return {"sleep_gap_seconds": cfg.sleep_gap_seconds, "lifetime_bands_seconds": list(cfg.lifetime_bands_seconds),
            "min_pool_events": cfg.min_pool_events}


class Pool:
    """Effect rates of normal use (the laptop's dev recording): per program and per lifetime
    band, each as (events, active process-seconds)."""

    def __init__(self, per_program: dict, per_band: dict, meta: dict = None):
        self.per_program, self.per_band, self.meta = per_program, per_band, meta or {}

    @classmethod
    def build(cls, activities, cfg: ConfidenceConfig, sysmon_config=None) -> "Pool":
        """From one Activity or a list of them (one per machine)."""
        if isinstance(activities, Activity):
            activities = [activities]
        per_program = {k: defaultdict(lambda: [0, 0.0]) for k in KINDS}
        per_band = {k: defaultdict(lambda: [0, 0.0]) for k in KINDS}
        for k in KINDS:                  # every band is written, even an empty one: never a silent 0
            for b in lifetime_bands(cfg):
                per_band[k][b]
        for act in activities:
            for g, p in act.procs.items():
                b = lifetime_band(p["life"], cfg)
                for k in KINDS:
                    n = len(act.events[k].get(g, ()))
                    tables = [(per_band[k], b)]
                    if p["program"] != UNKNOWN_PROGRAM:
                        tables.append((per_program[k], p["program"]))
                    for table, key in tables:
                        table[key][0] += n
                        table[key][1] += p["life"]
        conv = lambda d: {k: {key: tuple(v) for key, v in t.items()} for k, t in d.items()}   # noqa: E731
        meta = {"processes": sum(len(a.procs) for a in activities), "machines": len(activities),
                "active_hours": round(sum(a.active.total for a in activities) / 3600, 2),
                **pool_settings(cfg), "sysmon_config": sysmon_config}
        return cls(conv(per_program), conv(per_band), meta)

    def check_config(self, cfg: ConfidenceConfig):
        """Refuse (ValueError) a pool built with other confidence settings than `cfg`, or one that
        lacks a lifetime band of `cfg`: its rates would be measured in other units (another sleep
        gap = other active time; other bands = other process groups)."""
        want = pool_settings(cfg)
        missing = [k for k in POOL_SETTINGS if k not in self.meta]
        if missing:
            raise ValueError(f"pool file does not record the settings it was built with ({', '.join(missing)}): "
                             f"rebuild it (python -m engine.confidence --build-pool)")
        differ = [f"{k} pool {self.meta[k]!r} vs config {want[k]!r}" for k in POOL_SETTINGS
                  if (list(self.meta[k]) if k == "lifetime_bands_seconds" else self.meta[k]) != want[k]]
        if differ:
            raise ValueError("pool was built with other confidence settings than config/frozen.yaml: "
                             + "; ".join(differ) + " (rebuild the pool)")
        for k in KINDS:
            lost = [b for b in lifetime_bands(cfg) if b not in self.per_band.get(k, {})]
            if lost:
                raise ValueError(f"pool has no '{k}' rate for lifetime band(s) {lost}")

    def rate(self, kind: str, program: str, life: float, cfg: ConfidenceConfig) -> tuple:
        """(rate per active process-second, source): the LARGER of the pool of the process's
        lifetime band (always) and its program's own pool (when that has at least
        min_pool_events effects of this kind). The band pool is always in the max, so a name
        borrowed from a quiet laptop program can only add caution, never remove it (Yousif's
        decision 2026-10-23, after re-check finding 3: a program name is just a file name)."""
        b = lifetime_band(life, cfg)
        if b not in self.per_band.get(kind, {}):
            # a missing band would silently drop the band floor (rate 0): refuse instead
            raise ValueError(f"pool has no '{kind}' rate for lifetime band {b} (built with other bands?)")
        n, secs = self.per_band[kind][b]
        best = ((n / secs if secs > 0 else 0.0), f"lifetime {b} s")
        n, secs = self.per_program[kind].get((program or UNKNOWN_PROGRAM).lower(), (0, 0.0))
        if n >= cfg.min_pool_events and secs > 0 and n / secs > best[0]:
            best = (n / secs, "program")
        return best

    def save(self, path: str) -> str:
        """Write the pool as JSON; returns its SHA256 (what goes into frozen.yaml at the freeze)."""
        body = json.dumps({"meta": self.meta, "per_program": self.per_program, "per_band": self.per_band},
                          sort_keys=True, indent=1).encode()
        with open(path, "wb") as f:
            f.write(body)
        return hashlib.sha256(body).hexdigest()

    @classmethod
    def load(cls, path: str, expect_sha256: str = None, cfg: ConfidenceConfig = None) -> "Pool":
        """Read a pool file. expect_sha256: refuse another file. cfg: refuse a pool built with
        other confidence settings (check_config); every caller that grades with it passes one."""
        with open(path, "rb") as f:
            body = f.read()
        if expect_sha256 and hashlib.sha256(body).hexdigest() != expect_sha256.strip().lower():
            raise ValueError("pool file does not match the frozen SHA256 (pool_sha256)")
        d = json.loads(body)
        tup = lambda t: {k: {key: tuple(v) for key, v in m.items()} for k, m in t.items()}   # noqa: E731
        pool = cls(tup(d["per_program"]), tup(d["per_band"]), d.get("meta"))
        if cfg is not None:
            pool.check_config(cfg)
        return pool


def grade_process_link(row: str, guid, t_effect: float, activity: Activity, pool: Pool,
                       cfg: ConfidenceConfig):
    """Grade the timing hypothesis of row T1/T2/T3 for one effect of process `guid` at
    `t_effect`: (t_cause, TimingGrade), or None if no cause window of that process contains it.
    `activity` must be loaded with until = the graph's end time."""
    if activity.until is not None and t_effect > activity.until:
        raise ValueError("the effect is after the time the activity was loaded up to (until)")
    kc, ke = TIMING_ROWS[row]
    causes = activity.events[kc].get(guid, [])
    tc = link_cause(causes, t_effect, cfg)
    if tc is None:
        return None
    p = activity.procs[guid]
    rate, src = pool.rate(ke, p["program"], p["life"], cfg)
    n_eff = max(len(activity.events[ke].get(guid, ())), 1)
    g = timing_grade(cfg, pool_rate=rate, pool_source=src, n_effects=n_eff, life_seconds=p["life"],
                     n_causes=n_competing(causes, tc, cfg))
    if row in cfg.leads_only and g.band != "low":
        # package J (2026-10-24): on real use this kind of coincidence is far more common than the
        # formula says (quiet programs connect and launch in one burst), so it is a lead only
        g = replace(g, band="low", reason=g.reason + "; shown as a lead only: on normal use, programs often "
                                                       "connect and start another program in one burst (package J)")
    return tc, g


# -- A16: predicted vs observed chance on real data (counts only) -----------------------------------
def a16_check(activity: Activity, pool: Pool, cfg: ConfidenceConfig, shifts=(-60.0, -30.0, 30.0, 60.0),
              seed=20261023) -> dict:
    """For every cause event of every timing row, in processes active at least one window long
    that made at least one effect of that kind (production only ever grades those): the
    PREDICTED one-cause chance p1 (the production rule, N = 1) against two OBSERVED chance rates
    that cannot contain this cause's own effect:
      control: an effect of the same process in a same-length window shifted by +-30 s / +-60 s of
               ACTIVE time, kept only when the shifted window lies inside the process's life
               (keeps the process's bursts; same-burst coincidences shorter than the shift are
               still missed: only the noise overlay, package J, measures those);
      rotate:  the process's effects rotated by a random offset within its own active life
               (keeps their clumping, destroys any link to the causes).
    Also the real rate (an effect in the true window). Grouped by the band p1 falls in, weighted
    per cause and per process."""
    rng = np.random.default_rng(seed)
    act = activity.active
    out = {}
    for row, (kc, ke) in TIMING_ROWS.items():
        recs = []                                   # (process index, p1, real, control or nan, rotate)
        graded = {"high": 0, "medium": 0, "low": 0}
        for pi, (g, causes) in enumerate(activity.events[kc].items()):
            p = activity.procs[g]
            effects = activity.events[ke].get(g, [])
            if p["life"] < cfg.window or not effects:
                continue
            rate, _ = pool.rate(ke, p["program"], p["life"], cfg)
            lam = max(rate, len(effects) / p["life"]) * cfg.burst
            p1 = chance(lam, cfg.window)
            p0 = float(act.position(p["t0"]))
            eff_pos = np.asarray(act.position(effects)) - p0
            rot = np.sort((eff_pos + rng.uniform(0, p["life"])) % p["life"])
            cause_pos = np.asarray(act.position(causes)) - p0
            for a, pa in zip(causes, cause_pos):
                lo, hi = a - cfg.window_before_seconds, a + cfg.window_after_seconds
                real = bisect.bisect_right(effects, hi) > bisect.bisect_left(effects, lo)
                plo, phi = pa - cfg.window_before_seconds, pa + cfg.window_after_seconds
                ctrl = [np.searchsorted(eff_pos, phi + s, side="right") > np.searchsorted(eff_pos, plo + s, side="left")
                        for s in shifts if plo + s >= 0 and phi + s <= p["life"]]
                r = np.searchsorted(rot, phi, side="right") > np.searchsorted(rot, plo, side="left")
                recs.append((pi, p1, real, (sum(ctrl) / len(ctrl)) if ctrl else math.nan, float(r)))
            # what the graph would show: each effect linked to its latest cause, graded with N
            for te in effects:
                tc = link_cause(causes, te, cfg)
                if tc is not None:
                    graded[band(competing(p1, n_competing(causes, tc, cfg)), cfg)] += 1
        arr = np.array(recs, dtype=float) if recs else np.zeros((0, 5))

        def mean_or_none(x):
            x = x[~np.isnan(x)]
            return float(x.mean()) if x.size else None

        def summary(sel):
            """Means per cause and per process. The control is compared with the prediction over
            the SAME causes (those whose shifted window fitted inside the life)."""
            if not len(sel):
                return None
            has_ctrl = ~np.isnan(sel[:, 3])
            per_proc = []        # each process weighs once: (predicted, predicted where controlled, control, rotate)
            for q in np.unique(sel[:, 0]):
                s = sel[sel[:, 0] == q]
                c = ~np.isnan(s[:, 3])
                per_proc.append((s[:, 1].mean(), s[c, 1].mean() if c.any() else math.nan,
                                 s[c, 3].mean() if c.any() else math.nan, s[:, 4].mean()))
            per_proc = np.array(per_proc)
            return {"causes": int(len(sel)), "processes": int(len(per_proc)),
                    "controlled_causes": int(has_ctrl.sum()),
                    "predicted": float(sel[:, 1].mean()), "real": float(sel[:, 2].mean()),
                    "predicted_controlled": float(sel[has_ctrl, 1].mean()) if has_ctrl.any() else None,
                    "control": mean_or_none(sel[:, 3]), "rotate": float(sel[:, 4].mean()),
                    "per_process": {"predicted": float(per_proc[:, 0].mean()),
                                    "predicted_controlled": mean_or_none(per_proc[:, 1]),
                                    "control": mean_or_none(per_proc[:, 2]), "rotate": float(per_proc[:, 3].mean())}}

        bands_ = {}
        for b in ("high", "medium", "low"):
            mask = np.array([band(x, cfg) == b for x in arr[:, 1]], dtype=bool) if len(arr) else np.zeros(0, bool)
            s = summary(arr[mask])
            if s:
                bands_[b] = s
        out[row] = {"causes": int(len(arr)), "bands": bands_, "all": summary(arr), "graded_pairs": graded}
    return out


def _chart(result: dict, path: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels, series = [], {"predicted p1": [], "observed: shifted window": [], "observed: rotated effects": [],
                          "real window": []}
    for row, r in result.items():
        for b, d in r["bands"].items():
            labels.append(f"{row}\n{b}\n(n={d['causes']},\n{d['processes']} proc.)")
            series["predicted p1"].append(d["predicted"])
            series["observed: shifted window"].append(d["control"] or 0.0)
            series["observed: rotated effects"].append(d["rotate"])
            series["real window"].append(d["real"])
    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(10, 4.8))
    w = 0.2
    for i, (name, vals) in enumerate(series.items()):
        ax.bar(x + (i - 1.5) * w, [max(v, 1e-5) for v in vals], w, label=name)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("share of cause events")
    ax.set_title("A16 (dev laptop): predicted one-cause chance vs observed chance, by band (bars at 1e-5 = zero)",
                 fontsize=9)
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(path, dpi=130)


def _open_ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{os.path.abspath(path).replace(os.sep, '/')}?mode=ro", uri=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Confidence model: build the pool of normal rates, or run the A16 check (counts only).")
    ap.add_argument("--db", required=True, help="event store, opened read-only")
    ap.add_argument("--build-pool", action="store_true")
    ap.add_argument("--a16", action="store_true")
    ap.add_argument("--pool", help="pool file (A16); built from --db if missing")
    ap.add_argument("--out", required=True, help="pool file (--build-pool) or output folder (--a16)")
    ap.add_argument("--config", default=FROZEN)
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    db = _open_ro(a.db)
    acts = []
    for h in hosts(db) or [None]:
        act = load_activity(db, cfg, h)
        acts.append(act)
        print(f"machine {len(acts)}: processes {len(act.procs)}, active {act.active.total / 3600:.1f} h, "
              + ", ".join(f"{k} {sum(len(v) for v in act.events[k].values())}" for k in KINDS)
              + f"; {dict(sorted(act.counts.items()))}")
    configs = sorted({c for h in (hosts(db) or [None]) for c in sysmon_configs(db, h)[-1:]})
    if a.build_pool:
        pool = Pool.build(acts, cfg, sysmon_config=configs)
        sha = pool.save(a.out)
        print(f"pool written ({len(pool.per_program['file'])} programs), Sysmon config(s) {configs}, SHA256 {sha}")
        for k in KINDS:
            print(f"  {k}: " + ", ".join(f"{b} {n}/{s / 3600:.1f} h = {n / s if s else 0:.6f}/s"
                                         for b, (n, s) in sorted(pool.per_band[k].items())))
    if a.a16:
        if a.pool and os.path.exists(a.pool):
            pool = Pool.load(a.pool, expect_sha256=cfg.pool_sha256, cfg=cfg)
        else:
            pool = Pool.build(acts, cfg, sysmon_config=configs)
        pool_cfg = pool.meta.get("sysmon_config")
        if pool_cfg is not None and sorted(pool_cfg) != configs:
            print(f"WARNING: Sysmon config differs between the pool {pool_cfg} and this store {configs}")
        os.makedirs(a.out, exist_ok=True)
        for i, act in enumerate(acts, 1):
            res = a16_check(act, pool, cfg)
            suffix = "" if len(acts) == 1 else f"-{i}"
            with open(os.path.join(a.out, f"a16{suffix}.json"), "w", encoding="utf-8") as f:
                json.dump(res, f, indent=1)
            _chart(res, os.path.join(a.out, f"a16{suffix}.png"))
            for row, r in res.items():
                al = r["all"] or {}
                print(f"{row}: {r['causes']} causes in {al.get('processes', 0)} processes; "
                      f"pairs as the graph grades them (with N): {r['graded_pairs']}")
                for b, d in r["bands"].items():
                    ctrl, pc = d["control"], d["predicted_controlled"]
                    pp = d["per_process"]
                    print(f"  {b:6s} n={d['causes']:6d} ({d['processes']:4d} proc., {d['controlled_causes']} with a control) "
                          f"predicted {d['predicted']:.4f}  shifted "
                          + ("n/a" if ctrl is None else f"{ctrl:.4f} vs {pc:.4f} predicted on the same causes (x{ctrl / pc:.2f})")
                          + f"  rotated {d['rotate']:.4f} (x{d['rotate'] / d['predicted']:.2f})  real {d['real']:.4f}"
                          + "  | per process: shifted "
                          + ("n/a" if pp["control"] is None else
                             f"{pp['control']:.4f} vs {pp['predicted_controlled']:.4f} (x{pp['control'] / pp['predicted_controlled']:.2f})")
                          + f", rotated {pp['rotate']:.4f} vs {pp['predicted']:.4f}")


if __name__ == "__main__":
    main()
