"""Check-in rhythm ("beacon") detection: DESIGN 4.6, periodicity.

A program that contacts the same destination again and again at a steady rhythm is scored
with the beacon-scoring method of **RITA v5.1.2** (Active Countermeasures, GPL v3), re-implemented
here from its published description (docs/plans/reports/beacon.md), not copied. Adapted to
Sysmon and to short recordings:

* a series = the outgoing connections (Sysmon event 3, `Initiated = true`) of one program image
  to one unicast destination IP and port on one host (broadcast and multicast are the operating
  system's own announcements, and RITA too only pairs hosts), split wherever the host was
  asleep (a silence longer than `sleep_gap_seconds`) or rebooted (Sysmon's "service started");
* RITA's data-size score needs bytes, which Sysmon does not record: dropped;
* RITA measures time in hours over a 24 h day. We measure it in the series' own rhythm
  ("beats" = its median gap): the histogram bins are at least `beats_per_bin` beats wide, at
  most 24 of them, over the host's awake window. A subscore that has too little data to mean
  anything is left out (RITA's own minimums: 6 busy bins for consistency, 11 for the histogram)
  and the beacon score is the mean of the subscores that could be computed;
* the ALERT is gated on the timestamp (gap regularity) score, not on the blended beacon score:
  on an endpoint every background service is persistent (RITA's duration and histogram scores
  are near 1 for it), so the blend cannot tell a rhythm from a chatty service. The blend is kept
  as the reported beacon score (ranking, confidence, report).

All numbers the rule uses live in config/frozen.yaml (`beacon:`), read by `load_config`.
"""

import ipaddress
import math
import os
import statistics
from dataclasses import dataclass, fields
from datetime import datetime

import numpy as np

from engine.alerts import Alert

RULE_ID = "beacon"
TITLE = "Regular check-in rhythm"
CREDIT = "RITA v5.1.2, Active Countermeasures (GPL v3): method re-implemented, no code copied"
FROZEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "frozen.yaml")
REQUIRED = ("min_timestamps", "sleep_gap_seconds", "rhythm_threshold", "level")


@dataclass(frozen=True)
class BeaconConfig:
    min_timestamps: int             # distinct connection times a series needs before it is scored
    sleep_gap_seconds: float        # a host silence longer than this = asleep: series are split there
    rhythm_threshold: float         # timestamp (gap regularity) score at or above this raises an alert
    unicast_only: bool = True       # ignore broadcast, multicast, link-local, loopback destinations
    split_at_boot: bool = True      # a Sysmon "service started" event (4) also ends the window
    beats_per_bin: int = 5          # a histogram bin holds at least this many median gaps
    max_bins: int = 24              # RITA: 24 one-hour bins
    histogram_min_busy_bins: int = 11   # RITA: histogram needs 11 busy hours
    consistency_min_busy_bins: int = 6  # RITA: consistency needs 6 busy hours
    window_cap_seconds: float = 86400   # RITA: the analysis window is at most 24 h
    skew_min_iqr_seconds: float = 10    # RITA: skew counts as 0 unless Q3 - Q1 >= 10
    min_median_gap_seconds: float = 10  # adaptation: a series whose median gap is below RITA's skew scale (the
                                        # 10 s above) lives entirely where the method has no skew information and
                                        # is judged by the MAD term alone; such fast traffic is not judged at all
    mad_min_median_seconds: float = 1   # RITA: MAD score only when the median gap >= 1
    max_connections: int = 86400        # RITA: bigger series are skipped
    time_resolution_seconds: float = 1  # RITA's unit (it stores Unix seconds). Adaptation: a connection less than
                                        # this after the PREVIOUS connection belongs to the same check-in, and the
                                        # quartiles in RITA's "Q2 differs from Q1 and Q3" guard are compared at
                                        # this resolution (exact float equality never fires on millisecond gaps)
    short_series_rule: str = ""         # prose, kept for the record
    # expected rhythms (C1, decided 2026-10-23): (program file name, destination ip:port, reason) of
    # updaters the lab lists before the freeze; such a series is still alerted, at level informational,
    # labelled "expected", never hidden
    expected: tuple = ()
    level: str = "medium"                # the alert level of a rhythm (frozen.yaml beacon.level; listed updaters:
                                        # informational)
    # version 3 (docs/plans/v3-prereg.md 1.3): v2 package B2's short test (Greenwood's statistic, per-count
    # cut-offs from docs/plans/b2/b2_crit.json, alpha 1 %), ONLY for series of a freshly dropped program.
    # short_min = None switches it off (v2 behaviour).
    short_min: int = None               # m: the shortest prefix (check-ins) the short test judges
    short_cutoffs: dict = None          # {k: Greenwood cut-off} for k = m ... 9
    fresh_window_seconds: float = 86400  # the program file was written at most this long before the first check-in
    # v4 F2 (docs/plans/v4-prereg.md section 5): the short test ALSO judges series of a program this machine
    # never saw opening an outgoing connection during its learning period (learned-normal "connectors",
    # engine/baseline.py learn_connectors). Off = v3 behaviour. Same cut-offs.
    short_unseen: bool = False

    def __post_init__(self):
        if self.min_timestamps < 4:
            raise ValueError("beacon: min_timestamps must be at least 4 (RITA's minimum)")
        if self.short_min is not None:
            if not 4 <= int(self.short_min) <= 9:
                raise ValueError("beacon: short_min must be between 4 and 9")
            cut = {int(k): float(v) for k, v in (self.short_cutoffs or {}).items()}
            if sorted(cut) != list(range(int(self.short_min), 10)) or not all(0 < v < 1 for v in cut.values()):
                raise ValueError("beacon: short_cutoffs needs one cut-off in (0, 1) for every k from short_min to 9")
            object.__setattr__(self, "short_cutoffs", cut)
        if not 0 <= self.rhythm_threshold <= 1:
            raise ValueError("beacon: rhythm_threshold must be between 0 and 1")
        if self.sleep_gap_seconds <= 0 or self.beats_per_bin < 1 or self.max_bins < 1 or self.time_resolution_seconds <= 0:
            raise ValueError("beacon: sleep_gap_seconds, beats_per_bin, max_bins and time_resolution_seconds must be positive")


def load_config(path: str = FROZEN) -> BeaconConfig:
    """The `beacon:` block of config/frozen.yaml; refuses while any required value is null,
    and refuses unknown keys (a typo would otherwise silently fall back to a default)."""
    import yaml
    with open(path, encoding="utf-8") as f:
        block = (yaml.safe_load(f) or {}).get("beacon") or {}
    known = {f.name for f in fields(BeaconConfig)}
    unknown = sorted(k for k in block if k not in known)
    if unknown:
        raise ValueError(f"config/frozen.yaml beacon: unknown keys {', '.join(unknown)}")
    missing = [name for name in REQUIRED if block.get(name) is None]
    missing += [k for k, v in block.items() if v is None and k not in missing]
    if missing:
        raise ValueError(f"config/frozen.yaml beacon: not chosen yet (null): {', '.join(sorted(missing))}")
    block = dict(block)
    block["expected"] = tuple((str(e["program"]).lower(), str(e["destination"]).lower(), str(e.get("reason", "listed"))) for e in block.get("expected") or ())
    return BeaconConfig(**block)


# -- time helpers -----------------------------------------------------------------------------
def to_seconds(text: str) -> float:
    """Sysmon UtcTime ('2026-10-19 11:01:09.142') or record time ('2026-10-19T11:01:09.1425271Z')
    -> seconds since the epoch (UTC). Raises ValueError on an unreadable time."""
    dt = datetime.fromisoformat(str(text).strip())
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def awake_segments(times, sleep_gap: float, boots=(), cap=None) -> list:
    """[(start, end)] stretches in which no two consecutive events are more than `sleep_gap`
    seconds apart. Between them the host was asleep (or not recording). A boot time (the first
    event of a new boot) also starts a new segment, even without a silence before it. With
    `cap`, a longer stretch is cut into pieces of at most `cap` seconds (RITA: one 24 h day)."""
    ts = sorted(times)
    if not ts:
        return []
    boot_set = set(boots)
    segments, start, prev = [], ts[0], ts[0]
    for t in ts[1:]:
        if t - prev > sleep_gap or (t in boot_set and t != start) or (cap and t - start > cap):
            segments.append((start, prev))
            start = t
        prev = t
    segments.append((start, prev))
    return segments


def checkin_groups(times, resolution: float) -> list:
    """Connections grouped into check-ins: a connection less than `resolution` after the
    PREVIOUS connection belongs to the same check-in (the chain: a burst of connections 0.5 s
    apart is one check-in however long it runs). So equal times count once (RITA drops zero
    gaps) and a "double tap" (two connections a few ms apart) is one check-in."""
    groups = []
    for t in sorted(times):
        if groups and t - groups[-1][-1] < resolution:
            groups[-1].append(t)
        else:
            groups.append([t])
    return groups


def checkin_times(times, resolution: float) -> list:
    """The time of each check-in (its first connection), millisecond precision kept: whole
    seconds (RITA's storage) would turn fast random traffic into small-integer gaps with a
    MAD of 0, i.e. "perfectly regular" (measured: 24-36 % of random series with 1.5-5 s gaps)."""
    return [g[0] for g in checkin_groups(times, resolution)]


def is_unicast(ip) -> bool:
    """A real host-to-host destination: not multicast, broadcast, link-local, loopback or
    unspecified. An IPv4 address ending in .255 is taken as a subnet broadcast (a simplification:
    the subnet mask is not recorded)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
        return False
    if a.version == 4 and (str(a) == "255.255.255.255" or str(a).endswith(".255")):
        return False
    return True


# -- RITA's subscores -------------------------------------------------------------------------
def timestamp_score(gaps, cfg: BeaconConfig) -> dict:
    """Skew score (1 - |Bowley skew|) and MAD score ((median - MAD) / median) of the gaps.
    Quartiles: numpy's default (linear interpolation). RITA's "Q2 differs from Q1 and Q3" is
    exact equality on its whole-second timestamps; ours have milliseconds, where exact equality
    never happens (a beacon missing a quarter of its beats would score 0.5 instead of 1), so
    the quartiles are compared at RITA's resolution (rounded to `time_resolution_seconds`)."""
    g = np.asarray(sorted(gaps), dtype=float)
    q1, q2, q3 = np.percentile(g, [25, 50, 75])
    res = cfg.time_resolution_seconds
    r1, r2, r3 = (round(q / res) for q in (q1, q2, q3))
    skew = 0.0
    if (q3 - q1) >= cfg.skew_min_iqr_seconds and r2 != r1 and r2 != r3:
        skew = (q3 + q1 - 2 * q2) / (q3 - q1)
    skew_score = 1 - abs(skew)
    median = float(q2)
    mad = float(np.median(np.abs(g - median)))
    mad_score = max(0.0, (median - mad) / median) if median >= cfg.mad_min_median_seconds else 0.0
    return {"skew": float(skew), "skew_score": float(skew_score), "mad": mad, "mad_score": float(mad_score),
            "median_gap": median, "timestamp": (float(skew_score) + float(mad_score)) / 2}


def bin_counts(times, window, median_gap: float, cfg: BeaconConfig):
    """Connections per bin over the awake window. Bins are at least beats_per_bin median gaps
    wide and at most max_bins in number -> (counts, bin width in seconds)."""
    start, end = window
    length = max(end - start, 0.0)
    beat = median_gap if (math.isfinite(median_gap) and median_gap > 0) else 1e-9
    n_bins = max(1, min(cfg.max_bins, int(length // (cfg.beats_per_bin * beat))))
    width = length / n_bins if length > 0 else 1.0
    counts = [0] * n_bins
    for t in times:
        i = min(n_bins - 1, max(0, int((t - start) // width)))
        counts[i] += 1
    return counts, width


def consistency_score(counts, cfg: BeaconConfig):
    """Longest run of consecutive busy bins over half the bins (RITA: hours / 12); None when
    fewer than consistency_min_busy_bins bins are busy."""
    busy = [c > 0 for c in counts]
    if sum(busy) < cfg.consistency_min_busy_bins:
        return None
    longest = run = 0
    for b in busy:
        run = run + 1 if b else 0
        longest = max(longest, run)
    return min(1.0, longest / (len(counts) / 2))


def bimodal_fit(counts) -> float:
    """RITA's bimodal fit: busy-bin counts are grouped into buckets of ceil(max * 0.05); the two
    most populated buckets over max(busy - 1, 1), capped at 1."""
    busy = [c for c in counts if c > 0]
    if not busy:
        return 0.0
    size = math.ceil(max(busy) * 0.05)
    pop = {}
    for c in busy:
        pop[c // size] = pop.get(c // size, 0) + 1
    top = sorted(pop.values(), reverse=True)[:2]
    return min(1.0, sum(top) / max(len(busy) - 1, 1))


def histogram_score(counts, cfg: BeaconConfig):
    """max(1 - CV, bimodal fit) over all bins, empty ones included; None when fewer than
    histogram_min_busy_bins bins are busy."""
    if sum(1 for c in counts if c > 0) < cfg.histogram_min_busy_bins:
        return None
    mean = statistics.fmean(counts)
    cv = statistics.pstdev(counts) / mean if mean > 0 else 0.0
    return max(max(0.0, 1 - cv), bimodal_fit(counts))


@dataclass(frozen=True)
class Scores:
    n: int                   # connections
    distinct: int            # check-in times (connections closer than the resolution folded into one)
    first: float
    last: float
    span: float              # last - first, seconds
    window: float            # awake window length, seconds (before the 24 h cap)
    median_gap: float
    skew: float
    skew_score: float
    mad: float
    mad_score: float
    timestamp: float
    coverage: float
    consistency: float | None
    duration: float
    n_bins: int
    bin_seconds: float
    busy_bins: int
    histogram: float | None
    final: float


def score_series(times, window, cfg: BeaconConfig):
    """RITA-style scores for one series of connection times (seconds) inside one awake window
    (start, end). None when the series is too small to judge or too big to bother (RITA)."""
    ts = sorted(float(t) for t in times)
    n = len(ts)
    if n == 0 or n >= cfg.max_connections:
        return None
    distinct = checkin_times(ts, cfg.time_resolution_seconds)
    if len(distinct) < cfg.min_timestamps:
        return None
    gaps = [b - a for a, b in zip(distinct, distinct[1:])]
    if float(np.median(gaps)) < cfg.min_median_gap_seconds:
        return None
    t = timestamp_score(gaps, cfg)
    span = ts[-1] - ts[0]
    length = max(window[1] - window[0], 0.0)
    capped = min(length, cfg.window_cap_seconds)
    coverage = min(1.0, span / capped) if capped > 0 else 0.0
    counts, width = bin_counts(ts, window, t["median_gap"], cfg)
    consistency = consistency_score(counts, cfg)
    duration = max(coverage, consistency or 0.0)
    histogram = histogram_score(counts, cfg)
    parts = [t["timestamp"], duration] + ([histogram] if histogram is not None else [])
    return Scores(n=n, distinct=len(distinct), first=ts[0], last=ts[-1], span=span, window=length,
                  median_gap=t["median_gap"], skew=t["skew"], skew_score=t["skew_score"], mad=t["mad"],
                  mad_score=t["mad_score"], timestamp=t["timestamp"], coverage=coverage,
                  consistency=consistency, duration=duration, n_bins=len(counts), bin_seconds=width,
                  busy_bins=sum(1 for c in counts if c > 0), histogram=histogram,
                  final=sum(parts) / len(parts))


def first_crossing(times, cfg: BeaconConfig):
    """The check-in time at which the series FIRST reached the rhythm threshold (scoring every
    prefix from min_timestamps check-ins on), or None. The gate only looks at the gaps so far,
    so this is what the live loop would have seen; it gives the alert a time and an evidence
    set that do not change when the series keeps growing."""
    groups = checkin_groups((float(t) for t in times), cfg.time_resolution_seconds)
    checkins = [g[0] for g in groups]
    for k in range(cfg.min_timestamps, len(checkins) + 1):
        gaps = [b - a for a, b in zip(checkins[:k], checkins[1:k])]
        if float(np.median(gaps)) < cfg.min_median_gap_seconds:
            continue
        if timestamp_score(gaps, cfg)["timestamp"] >= cfg.rhythm_threshold:
            return groups[k - 1][-1]            # the last connection of the k-th check-in
    return None


# -- from the event store to alerts ------------------------------------------------------------
SYSMON = "Microsoft-Windows-Sysmon/Operational"
# Sysmon's own clock (UtcTime) first: the log's TimeCreated can lag it by seconds to minutes.
SERIES_SQL = f"""SELECT host, Image, DestinationIp, DestinationPort, COALESCE(UtcTime, time), dedup_key, ProcessGuid
FROM events WHERE channel = '{SYSMON}' AND event_id = 3 AND Initiated = 'true'
AND (origin IS NULL OR origin != 'project') AND COALESCE(paused, 0) = 0
AND Image IS NOT NULL AND COALESCE(UtcTime, time) IS NOT NULL"""


def _seconds_or_none(text):
    try:
        return to_seconds(text)
    except (ValueError, TypeError):
        return None


def iso_utc(seconds: float) -> str:
    """Seconds since the epoch -> ISO-8601 UTC with milliseconds ('2026-10-19T11:01:09.142Z'),
    the spelling every alert uses (engine/detect.py writes the same), so AlertStore's text
    ordering by time is consistent across rules."""
    from datetime import timezone
    dt = datetime.fromtimestamp(seconds, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def series_from_store(db, host=None, unicast_only=True, unreadable=None) -> dict:
    """{(host, image, ip, port): [(seconds, dedup_key, process_guid, time_text), ...]} for the
    outgoing connections, our own tools excluded. Rows whose time cannot be read are skipped
    (their dedup_keys are appended to `unreadable` when a list is given)."""
    sql, params = SERIES_SQL, ()
    if host is not None:
        sql, params = sql + " AND host = ?", (host,)
    series = {}
    for h, image, ip, port, time_text, key, guid in db.execute(sql, params):
        if unicast_only and not is_unicast(ip):
            continue
        seconds = _seconds_or_none(time_text)
        if seconds is None:
            if unreadable is not None:
                unreadable.append(key)
            continue
        series.setdefault((h, image, ip, port), []).append((seconds, key, guid, time_text))
    return series


def host_segments(db, host, sleep_gap: float, split_at_boot=True, cap=None) -> list:
    """Awake segments of a host from ALL its events (our own tools included: they prove it was
    up), also split where Sysmon's service started (event 4, State = Started: normally a boot)
    and, with `cap`, into pieces of at most `cap` seconds (RITA's 24 h day)."""
    times = [s for (t,) in db.execute(
        "SELECT COALESCE(UtcTime, time) FROM events WHERE host = ? AND COALESCE(UtcTime, time) IS NOT NULL", (host,))
        if (s := _seconds_or_none(t)) is not None]
    boots = ()
    if split_at_boot:
        boots = [s for (t,) in db.execute(
            f"SELECT COALESCE(UtcTime, time) FROM events WHERE host = ? AND channel = '{SYSMON}' AND event_id = 4 "
            "AND State = 'Started' AND COALESCE(paused, 0) = 0 AND COALESCE(UtcTime, time) IS NOT NULL", (host,))
            if (s := _seconds_or_none(t)) is not None]
    return awake_segments(times, sleep_gap, boots, cap)


def split_by_segment(connections, segments) -> list:
    """Group a series' connections by the awake segment they fall in -> [(segment, connections)]."""
    out = []
    conns = sorted(connections)
    i = 0
    for seg in segments:
        chunk = []
        while i < len(conns) and conns[i][0] <= seg[1]:
            if conns[i][0] >= seg[0]:
                chunk.append(conns[i])
            i += 1
        if chunk:
            out.append((seg, chunk))
    return out


def describe(scores: Scores, image: str, ip: str, port, detected_after: int) -> str:
    name = str(image).replace("/", "\\").rsplit("\\", 1)[-1]
    dest = f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
    span = f"{scores.span / 60:.1f} min" if scores.span >= 120 else f"{scores.span:.0f} s"
    evenness = f"{scores.histogram:.2f}" if scores.histogram is not None else "not measurable"
    return (f"{name} connected to {dest} {scores.n} times over {span} at a median gap of "
            f"{scores.median_gap:.1f} s, regular from check-in {detected_after} on; beacon score {scores.final:.2f} "
            f"(gap regularity {scores.timestamp:.2f}, persistence {scores.duration:.2f}, evenness {evenness}).")


def score_store(db, cfg: BeaconConfig, host=None, series=None, segments=None) -> list:
    """Every scored series as (key, segment, Scores, connections). Below-minimum series are left out.
    `series` / `segments` may be passed in when already read (v3: the short gate shares them)."""
    series = series_from_store(db, host, cfg.unicast_only) if series is None else series
    segments = {} if segments is None else segments
    out = []
    for key, conns in sorted(series.items(), key=lambda kv: tuple(map(str, kv[0]))):
        h = key[0]
        if h not in segments:
            segments[h] = host_segments(db, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds)
        for seg, chunk in split_by_segment(conns, segments[h]):
            s = score_series([c[0] for c in chunk], seg, cfg)
            if s is not None:
                out.append((key, seg, s, chunk))
    return out


def expected_reason(cfg: BeaconConfig, image, ip, port):
    """The reason text if (program file name, ip:port) is on the expected-rhythms list, else None."""
    name = str(image or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    dest = (f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}").lower()
    for prog, where, why in cfg.expected:
        if prog == name and where == dest:
            return why
    return None


def greenwood(gaps) -> float:
    """Greenwood's statistic G = sum(d^2) / (sum d)^2 of the gaps (Greenwood 1946): small = too even
    for random arrivals. 1/n for perfectly even gaps."""
    g = np.asarray(gaps, dtype=float)
    return float((g ** 2).sum() / g.sum() ** 2)


def short_crossing(times, cfg: BeaconConfig):
    """v3 short test (B2's registered test): (k, the last connection of the k-th check-in) for the
    FIRST prefix of k = short_min ... 9 check-ins whose median gap is >= min_median_gap_seconds and
    whose Greenwood statistic is <= its cut-off; None if no prefix passes (or the test is off)."""
    if not cfg.short_min:
        return None
    groups = checkin_groups((float(t) for t in times), cfg.time_resolution_seconds)
    checkins = [g[0] for g in groups]
    for k in range(int(cfg.short_min), min(9, len(checkins)) + 1):
        gaps = np.diff(checkins[:k])
        if float(np.median(gaps)) >= cfg.min_median_gap_seconds and greenwood(gaps) <= cfg.short_cutoffs[k]:
            return k, groups[k - 1][-1]
    return None


# Program folders a dropped program is NOT in: Windows (minus its user-writable folders) and Program Files.
from engine.own_rules import WRITABLE_IN_WINDOWS  # noqa: E402  (one list of user-writable Windows folders)
INSTALLED = ("c:\\program files\\", "c:\\program files (x86)\\")


def fresh_drop(db, host, image, first_seconds, cfg: BeaconConfig):
    """Seconds between the newest write of the program file (Sysmon event 11, same path, same machine)
    and the series' first check-in, if it is at most fresh_window_seconds and the file is outside
    Windows and Program Files; else None. Not caught: a drop by rename (no event 11 for the .exe),
    8.3 short paths on one side, non-ASCII names that SQLite's ASCII-only lower() spells differently.
    AppData and ProgramData are eligible (e.g. per-user apps, Defender platform updates)."""
    from engine.graph import norm_path
    p = norm_path(image)
    if not p or p.startswith(INSTALLED) or (p.startswith("c:\\windows\\") and not p.startswith(WRITABLE_IN_WINDOWS)):
        return None
    name = p.rsplit("\\", 1)[-1]
    best = None
    q = (f"SELECT TargetFilename, COALESCE(UtcTime, time) FROM events WHERE host = ? AND channel = '{SYSMON}' "
         "AND event_id = 11 AND lower(TargetFilename) LIKE ? AND (origin IS NULL OR origin != 'project') "
         "AND COALESCE(paused, 0) = 0")
    for path, t in db.execute(q, (host, "%" + name)):
        s = _seconds_or_none(t)
        if s is None or norm_path(path) != p:
            continue
        if 0 <= first_seconds - s <= cfg.fresh_window_seconds and (best is None or s > best):
            best = s
    return None if best is None else first_seconds - best


def program_name(image) -> str:
    return str(image or "").replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def f2_eligibility(connectors, host, image):
    """v4 F2: why the short test may judge this program's series, or None. "never_seen_connecting": the
    machine's learned list exists and does not hold this program's file name; "never_normal_program": a
    shell / script host / unknown process, never treated as learned even when on the list (as F3's
    NEVER_NORMAL_WIPERS; laptop hold-out 10-23..11-14: the same alerts with or without this). A machine
    WITHOUT a learned list -> None (never "everything is new")."""
    from engine.own_rules import NEVER_NORMAL_WIPERS
    known = (connectors or {}).get(str(host or "").lower())
    if known is None:
        return None
    name = program_name(image)
    if not name:
        return None
    if name not in known:
        return "never_seen_connecting"
    return "never_normal_program" if name in NEVER_NORMAL_WIPERS else None


def never_seen_connecting(connectors, host, image):
    """True when F2 may judge this program's series (f2_eligibility gives a reason)."""
    return f2_eligibility(connectors, host, image) is not None


F2_WHY = {"never_seen_connecting": "this machine never saw this program open an outgoing connection during its "
                                   "learning period (learned normal, by program name).",
          "never_normal_program": "shells, script hosts and unknown processes are never treated as learned "
                                  "(they are the likeliest tools of an attacker)."}


def _cap_f2(alerts):
    """Review 2026-11-17: F2 raises ONE alert per (machine, program): the earliest. Its later series stay
    as alerts at level informational with details.repeat_of (a new program polling for days would
    otherwise raise one alert per destination per awake window)."""
    from dataclasses import replace
    first, out = {}, []
    for a in sorted(alerts, key=lambda a: a.time):
        key = (str(a.host).lower(), program_name(a.details["image"]))
        if key not in first:
            first[key] = a
            out.append(a)
            continue
        out.append(replace(a, level="informational", details=dict(a.details, repeat_of=first[key].alert_id),
                           reason=f"Already alerted for this program on this machine (alert {first[key].alert_id}). "
                                  + a.reason))
    return out


def _short_alerts(db, cfg: BeaconConfig, host, rita_alerts, series, segments, connectors=None):
    """v3: series of freshly dropped programs judged by the short test; v4 F2 (`short_unseen`): also
    series of a program the machine never saw connecting during learning (`connectors`: {host: set
    of program names}, engine/baseline.py). A series the RITA gate also alerted keeps ONE alert,
    stamped at whichever gate fired first (B2's counting rule). Uses the series and awake segments
    the RITA pass already read (one pass over the store, v3 review).
    Known false-alarm shapes: a per-user app (AppData) that rewrites its own program file and then
    checks in on an exact timer; (F2) a program new to the machine that polls on an exact timer."""
    by_series = {(a.host, a.details["image"], a.details["destination_ip"], a.details["destination_port"],
                  a.details["window_start"]): i for i, a in enumerate(rita_alerts)}
    out, new_f2 = list(rita_alerts), []
    for (h, image, ip, port), conns in sorted(series.items(), key=lambda kv: tuple(map(str, kv[0]))):
        if h not in segments:
            segments[h] = host_segments(db, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds)
        for seg, chunk in split_by_segment(conns, segments[h]):
            hit = short_crossing([c[0] for c in chunk], cfg)
            if hit is None:
                continue
            age = fresh_drop(db, h, image, min(c[0] for c in chunk), cfg)
            eligible = "fresh_drop" if age is not None else (
                f2_eligibility(connectors, h, image) if cfg.short_unseen else None)
            if eligible is None:
                continue
            k, crossing = hit
            seen = [c for c in chunk if c[0] <= crossing]
            ci = checkin_times([c[0] for c in seen], cfg.time_resolution_seconds)
            gaps = np.diff(ci)
            details = {"image": image, "destination_ip": ip, "destination_port": port, "window_start": seg[0],
                       "gate": "short", "detected_after_checkins": k, "connections_at_detection": len(seen),
                       "greenwood": greenwood(gaps), "cutoff": cfg.short_cutoffs[k], "median_gap": float(np.median(gaps)),
                       "eligible": eligible, "credit": CREDIT}
            if age is not None:
                details["written_seconds_before_first_checkin"] = round(age, 1)
                why = f"its program file was written {age / 60:.1f} min before the first check-in (a freshly dropped program)."
            else:
                why = F2_WHY[eligible]
            name = str(image).replace("/", "\\").rsplit("\\", 1)[-1]
            dest = f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
            reason = (f"{name} connected to {dest} at {k} check-ins with near-even gaps (median {np.median(gaps):.1f} s; "
                      f"Greenwood {greenwood(gaps):.3f} <= {cfg.short_cutoffs[k]:.3f}, a 1 % chance for random timing); "
                      + why)
            level = cfg.level
            listed = expected_reason(cfg, image, ip, port)
            if listed is not None:
                level, details["expected"] = "informational", listed
                reason = f"Expected (listed updater: {listed}). " + reason
            alert = Alert(rule_id=RULE_ID, title=TITLE, source="beacon", level=level, time=iso_utc(max(seen)[0]),
                          host=h, reason=reason, evidence=tuple(c[1] for c in seen), details=details)
            i = by_series.get((h, image, ip, port, seg[0]))
            if i is None:
                (new_f2 if eligible != "fresh_drop" else out).append(alert)
            elif iso_utc(max(seen)[0]) < out[i].time:     # same ISO spelling, so text order = time order
                out[i] = alert                       # the short test fired first: stamped there (the RITA
                                                     # gate alerts this series anyway: never capped)
    return out + _cap_f2(new_f2)


def beacon_alerts(db, cfg: BeaconConfig, host=None, connectors=None) -> list:
    """Alerts for every series whose gap regularity (timestamp score) reaches the threshold.
    The alert is stamped at the check-in where the threshold was first reached, with the
    connections up to there as evidence (so its id is stable as the series grows); the whole
    series' numbers are in `details`. Version 3: with `short_min` set, series of freshly dropped
    programs are also judged by the short test (`details.gate` = short / rita). v4 F2: with
    `short_unseen` and `connectors` ({host: set of program names} learned per machine), so are
    series of programs the machine never saw connecting (`details.eligible`)."""
    series, segments = series_from_store(db, host, cfg.unicast_only), {}
    alerts = _rita_alerts(db, cfg, host, series, segments)
    return _short_alerts(db, cfg, host, alerts, series, segments, connectors) if cfg.short_min else alerts


def _rita_alerts(db, cfg: BeaconConfig, host=None, series=None, segments=None) -> list:
    alerts = []
    for (h, image, ip, port), seg, s, chunk in score_store(db, cfg, host, series, segments):
        if s.timestamp < cfg.rhythm_threshold:
            continue
        crossing = first_crossing([c[0] for c in chunk], cfg)
        if crossing is None:            # cannot happen: the full series passed; kept as a guard
            crossing = max(c[0] for c in chunk)
        seen = [c for c in chunk if c[0] <= crossing]
        detected_after = len(checkin_times([c[0] for c in seen], cfg.time_resolution_seconds))
        details = {"image": image, "destination_ip": ip, "destination_port": port,
                   "window_start": seg[0], "window_seconds": s.window, "process_guids": len({c[2] for c in chunk}),
                   "detected_after_checkins": detected_after, "connections_at_detection": len(seen),
                   "gate": "rita", "credit": CREDIT}
        details.update({f.name: getattr(s, f.name) for f in fields(Scores)})
        reason, level = describe(s, image, ip, port, detected_after), cfg.level
        listed = expected_reason(cfg, image, ip, port)
        if listed is not None:
            level, details["expected"] = "informational", listed
            reason = f"Expected (listed updater: {listed}). " + reason
        alerts.append(Alert(rule_id=RULE_ID, title=TITLE, source="beacon", level=level,
                            time=iso_utc(max(seen)[0]), host=h, reason=reason,
                            evidence=tuple(c[1] for c in seen), details=details))
    return alerts


if __name__ == "__main__":        # counts only: python -m engine.beacon <events.db> [host]
    import sqlite3
    import sys
    cfg = load_config()
    conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    scored = score_store(conn, cfg, sys.argv[2] if len(sys.argv) > 2 else None)
    print(f"series scored: {len(scored)}; regularity at or above {cfg.rhythm_threshold}: "
          f"{sum(1 for _, _, s, _ in scored if s.timestamp >= cfg.rhythm_threshold)}")
