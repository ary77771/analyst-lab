"""Network view (Labs, night-hunt): who talked to whom, and the check-in rhythm of each pair.

    GET /api/labs/network/?window=24h[&host=&include_own=false]
        programs -> destinations (outgoing connections), each pair with its connection count and,
        when it has enough check-ins, its rhythm score
    GET /api/labs/network/rhythm?image=&ip=&port=&window=24h
        one pair's check-in times and the gaps between them (for the chart)

The rhythm score is the project's own beacon method (engine/beacon.py: RITA's gap-regularity
score, re-implemented), imported read-only with the frozen settings from config/frozen.yaml: the
same number the beacon rule uses, shown for every pair. This page raises no alerts. A regular
rhythm is not proof of malware: time sync, update checks and chat apps keep rhythms too.
"""

import os
import re
import sqlite3
import threading
import time

from fastapi import APIRouter, HTTPException

from . import _huntdb as db


class _Lazy:
    """engine.beacon, imported on first use: a problem there leaves this page without rhythm scores,
    never stops the lab (or the dashboard) from loading."""

    def __getattr__(self, name):
        from .. import beacon as real                          # noqa: PLC0415
        return getattr(real, name)


beacon = _Lazy()

router = APIRouter(prefix="/api/labs/network", tags=["labs: network"])

GRAPH_PROGRAMS = 18          # the picture shows the busiest programs plus every program with a regular rhythm
GRAPH_DESTS = 28
RHYTHM_MAX_SPAN = 8 * 86400  # rhythm scores only for windows up to 8 days (the awake-time read grows with the window)
_cache, _lock = {}, threading.Lock()


def _cfg():
    try:
        return beacon.load_config(), None
    except Exception as e:                       # frozen block missing (e.g. a test checkout): pairs without scores
        return None, f"The beacon settings could not be read ({e}); rhythm scores are left out."


GUEST_SETUP = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "tools", "vm", "vm_guest_setup.ps1")


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def vm_firewall(path=GUEST_SETUP):
    """What the test VM's firewall lets out, read from the project's own VM setup script (not typed here):
    {"host": "10.0.2.2", "ports": [8770, 18765], "source": "tools/vm/vm_guest_setup.ps1"}, or None when the
    script can't be read or does not block outgoing traffic by default."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError:
        return None
    host = re.search(r"\[string\]\$HostAddr\s*=\s*'([^']+)'", text)
    ports = re.search(r"\$LabPorts\s*=\s*@\(([^)]*)\)", text)
    if not (host and ports and re.search(r"DefaultOutboundAction\s+Block", text)
            and re.search(r"-Direction\s+Outbound\s+-Action\s+Allow\s+-RemoteAddress\s+\$HostAddr", text)):
        return None
    return {"host": host.group(1), "ports": sorted(int(p) for p in re.findall(r"\d+", ports.group(1))),
            "source": "tools/vm/vm_guest_setup.ps1"}


def _segments(con, w, host, cfg):
    """Awake stretches of the window (beacon.awake_segments over every event's time + boots)."""
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    frm = db.events_from(con, w)
    cur = con.cursor()
    cur.row_factory = None                           # plain tuples: every event of the window is read
    times = [s for (t,) in cur.execute(f"SELECT time FROM {frm} WHERE 1=1{tw}{hw}", tp + hp) if (s := db.fast_seconds(t)) is not None]
    boots = [s for (t,) in con.execute(f"SELECT time FROM {frm} WHERE event_id = 4 AND State = 'Started'{tw}{hw}", tp + hp)
             if (s := db.fast_seconds(t)) is not None] if cfg.split_at_boot and db.has(con, "State") else []
    return beacon.awake_segments(times, cfg.sleep_gap_seconds, boots, cfg.window_cap_seconds)


def _series(con, w, host, include_own, programs=None):
    """{(program, ip, port): connection times}. `programs` (lower-case Images) is asked of SQLite, not filtered
    afterwards (speed audit 2026-11-24: an alert's two programs read all 1.4 million connections, 9.7 s)."""
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    if programs is not None:
        programs = sorted(programs)
        hw += f" AND lower(Image) IN ({','.join('?' for _ in programs)})" if programs else " AND 0"
        hp = hp + programs
    frm = db.events_from(con, w)
    t_col = db.when_col(con)                         # the one clock (_shared_defs.when_sql)
    series = {}
    cur = con.cursor()
    cur.row_factory = None                           # plain tuples: a million rows read faster
    for li, image, ip, port, t, name, guid in cur.execute(
            f"SELECT lower(Image), Image, DestinationIp, DestinationPort, {t_col}, DestinationHostname, ProcessGuid FROM {frm} "
            f"WHERE event_id = 3 AND Initiated = 'true' AND Image IS NOT NULL AND {db.own_filter(con, include_own)}{tw}{hw}", tp + hp):
        s = series.setdefault((li, ip, port), {"image": image, "times": [], "name": None, "guid": None})
        sec = db.fast_seconds(t)
        if sec is not None:
            s["times"].append(sec)
        s["name"] = s["name"] or (name if name and name.strip() != "-" else None)     # Sysmon writes "-" for "no name"
        s["guid"] = guid or s["guid"]
    return series


def score(times, segments, cfg):
    """The best-scoring awake stretch of one pair's connection times -> dict, or None (too few check-ins)."""
    best = None
    for seg, chunk in beacon.split_by_segment([(t,) for t in times], segments):
        s = beacon.score_series([c[0] for c in chunk], seg, cfg)
        if s is not None and (best is None or s.timestamp > best.timestamp):
            best = s
    if best is None:
        return None
    return {"regularity": round(best.timestamp, 3), "beacon_score": round(best.final, 3), "checkins": best.distinct,
            "median_gap": round(best.median_gap, 1), "span_s": round(best.span), "regular": best.timestamp >= cfg.rhythm_threshold}


def view(con, w, host=None, include_own=False, programs=None) -> dict:
    """`programs` (lower-case Images): keep only their connections (an alert's own programs), or None for all."""
    t0 = time.perf_counter()
    notes = []
    try:
        series = _series(con, w, host, include_own, programs)
    except sqlite3.OperationalError as e:
        if "no such column" not in str(e):
            raise
        series = {}
        notes.append("This store did not record network connections.")
    cfg, why = _cfg()
    if why:
        notes.append(why)
    first, last = (db.seconds(w.since), db.seconds(w.until)) if w.since else (db.seconds(db.oldest_time(con)), db.seconds(db.newest_time(con)))
    can_score = cfg is not None and first is not None and last is not None and last - first <= RHYTHM_MAX_SPAN
    if cfg is not None and not can_score:
        notes.append("Rhythm scores are worked out for windows of up to 8 days: choose a shorter window to see them.")
    segments = _segments(con, w, host, cfg) if can_score and series else []
    # the test VM's firewall lets out only the host's lab ports (read from the VM setup); any other connection
    # Sysmon logged there was an attempt. Only judged when this page shows the test machine alone.
    fw = vm_firewall() if db.allowed_hosts() is not None else None
    pairs = []
    for (li, ip, port), s in series.items():
        ts = sorted(s["times"])
        unicast = beacon.is_unicast(ip) if cfg else None
        r = score(ts, segments, cfg) if can_score and unicast and len(ts) >= cfg.min_timestamps else None
        expected = beacon.expected_reason(cfg, s["image"], ip, port) if (cfg and r and r["regular"]) else None
        dest = f"[{ip}]:{port}" if ":" in str(ip or "") else f"{ip}:{port}"
        pairs.append({"program": s["image"], "program_key": li, "ip": ip, "port": port, "dest": dest, "name": s["name"],
                      "connections": len(s["times"]), "first": db.iso_from(ts[0]) if ts else None,
                      "last": db.iso_from(ts[-1]) if ts else None, "rhythm": r, "expected": expected,
                      "unicast": unicast, "guid": s["guid"],
                      "attempted": bool(fw and not (str(ip) == fw["host"] and _int(port) in fw["ports"]))})
    pairs.sort(key=lambda p: (not (p["rhythm"] or {}).get("regular"), p["attempted"],
                              -((p["rhythm"] or {}).get("regularity") or 0), -p["connections"]))
    if not include_own:
        from . import _shared_defs as sd                   # noqa: PLC0415
        notes.append(f"The lab's own test machinery is hidden (its launchers, their reports back to the laptop at "
                     f"{sd.RECEIVER_HOST}:{sd.RECEIVER_PORT}, VirtualBox's helpers): switch '{sd.WORDS['harness_switch']}' "
                     f"to see it.")
    if fw:
        notes.insert(0,f"The test machine's firewall (set up by {fw['source']}) lets out only {fw['host']} on TCP "
                        f"{', '.join(map(str, fw['ports']))}. Every other connection here is shown as ATTEMPTED: it was "
                        f"blocked if that setup was in force.")
    programs = {}
    for p in pairs:
        g = programs.setdefault(p["program_key"], {"program": p["program"], "connections": 0, "destinations": 0, "regular": 0})
        g["connections"] += p["connections"]
        g["destinations"] += 1
        g["regular"] += bool((p["rhythm"] or {}).get("regular"))
    prog_list = sorted(programs.values(), key=lambda g: (-g["regular"], -g["connections"]))
    notes.append("A regular rhythm is not proof of malware: time sync, update checks and chat apps keep rhythms too. "
                 "The same score is used by the beacon rule; this page raises no alerts.")
    if cfg:
        notes.append(f"Regular = gap regularity at least {cfg.rhythm_threshold} with at least {cfg.min_timestamps} check-ins "
                     f"(frozen settings); pairs whose median gap is under {cfg.min_median_gap_seconds:g} s are not judged.")
    return {"pairs": pairs, "programs": prog_list, "graph": graph(pairs, prog_list), "notes": notes,
            "threshold": cfg.rhythm_threshold if cfg else None, "scored": can_score,
            "totals": {"connections": sum(p["connections"] for p in pairs), "pairs": len(pairs), "programs": len(prog_list),
                       "destinations": len({(p["ip"], p["port"]) for p in pairs}),
                       "regular": sum(1 for p in pairs if (p["rhythm"] or {}).get("regular")),
                       "attempted": sum(1 for p in pairs if p["attempted"])},
            "firewall": fw,
            "ms": round((time.perf_counter() - t0) * 1000)}


def graph(pairs, programs):
    """A two-column picture: programs (left) -> destinations (right). Busiest programs plus every
    program with a regular rhythm; the rest is counted, never dropped silently."""
    keep_p = [g["program"] for g in programs if g["regular"]][:GRAPH_PROGRAMS]
    for g in programs:
        if len(keep_p) >= GRAPH_PROGRAMS:
            break
        if g["program"] not in keep_p:
            keep_p.append(g["program"])
    sel = [p for p in pairs if p["program"] in keep_p]
    dest_weight = {}
    for p in sel:
        k = p["dest"]
        dest_weight[k] = dest_weight.get(k, 0) + p["connections"] + (10 ** 6 if (p["rhythm"] or {}).get("regular") else 0)
    keep_d = [d for d, _ in sorted(dest_weight.items(), key=lambda kv: -kv[1])[:GRAPH_DESTS]]
    edges = [{"program": p["program"], "dest": p["dest"], "connections": p["connections"],
              "regular": bool((p["rhythm"] or {}).get("regular")), "regularity": (p["rhythm"] or {}).get("regularity"),
              "attempted": p["attempted"]}
             for p in sel if p["dest"] in keep_d]
    return {"programs": keep_p, "destinations": keep_d, "edges": edges,
            "left_out": {"programs": max(0, len(programs) - len(keep_p)),
                         "pairs": len(pairs) - len(edges)}}


def rhythm(con, w, image, ip, port, host=None) -> dict:
    """One pair's check-in times (first connection of each check-in) and the gaps between them."""
    tw, tp = w.sql()
    hw, hp = db.host_filter(host)
    t_col = db.when_col(con)                         # the one clock (_shared_defs.when_sql)
    rows = con.execute(f"SELECT {t_col} FROM {db.events_from(con, w)} WHERE event_id = 3 AND Initiated = 'true' "
                       f"AND lower(Image) = lower(?) AND DestinationIp = ? AND DestinationPort = ?{tw}{hw}",
                       [image, ip, port] + tp + hp).fetchall()
    times = sorted(s for (t,) in rows if (s := db.fast_seconds(t)) is not None)
    cfg, why = _cfg()
    res = cfg.time_resolution_seconds if cfg else 1.0
    checkins = beacon.checkin_times(times, res) if cfg else times
    gaps = [round(b - a, 3) for a, b in zip(checkins, checkins[1:])]
    out = {"image": image, "ip": ip, "port": port, "connections": len(times), "checkins": len(checkins),
           "points": [{"t": db.iso_from(a), "gap": g} for a, g in zip(checkins[1:], gaps)][-2000:],
           "truncated": len(gaps) > 2000, "threshold": cfg.rhythm_threshold if cfg else None, "note": why}
    if gaps:
        s = sorted(gaps)
        med = s[len(s) // 2] if len(s) % 2 else (s[len(s) // 2 - 1] + s[len(s) // 2]) / 2
        out["median_gap"] = med
        out["spread"] = round(sorted(abs(g - med) for g in gaps)[len(gaps) // 2], 3)       # median absolute deviation
        out["histogram"] = _histogram(gaps)
    if cfg and len(checkins) >= cfg.min_timestamps and gaps and float(sorted(gaps)[len(gaps) // 2]) >= cfg.min_median_gap_seconds:
        t = beacon.timestamp_score(gaps, cfg)
        out["regularity"] = round(t["timestamp"], 3)
        out["regular"] = t["timestamp"] >= cfg.rhythm_threshold
    return out


def _histogram(gaps, bins=24):
    lo, hi = min(gaps), max(gaps)
    if hi - lo < 1e-9:
        return [{"from": lo, "to": hi, "n": len(gaps)}]
    # log-spaced when the gaps cover more than a factor of 20 (a beacon with long sleeps), else linear
    if lo > 0 and hi / lo > 20:
        edges = [lo * (hi / lo) ** (i / bins) for i in range(bins + 1)]
    else:
        edges = [lo + (hi - lo) * i / bins for i in range(bins + 1)]
    counts = [0] * bins
    for g in gaps:
        i = min(bins - 1, max(0, next((k for k in range(bins) if g < edges[k + 1]), bins - 1)))
        counts[i] += 1
    return [{"from": round(edges[i], 3), "to": round(edges[i + 1], 3), "n": counts[i]} for i in range(bins)]


def _open():
    path = db.events_path()
    try:
        return path, db.connect(path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/")
def network(window: str = "24h", start: str = None, end: str = None, host: str = None, include_own: bool = False,
            limit: int = 400, alert: str = None, only_alert: bool = True):
    """With `alert`: the alert's run (machine start before it to the next start) and, unless only_alert is
    false, only its own programs (those of its evidence events): wave 3's "?alert=<id>"."""
    path, con = _open()
    try:
        scope = db.alert_scope(con, alert) if alert else None
        programs = None
        try:
            if scope and not scope.get("missing") and only_alert:   # this alert's run and its own programs
                w = scope["window"]
                programs = scope["programs"] or None
                host = scope["host"]
            else:                                                     # "show the whole recording": the page's own window
                w = db.window(con, window, start, end)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        key = (path, db.store_version(con), w.since, w.until, host, include_own, tuple(programs or ()))
        with _lock:
            out = _cache.get(key)
        if out is None:
            out = view(con, w, host, include_own, programs)
            with _lock:
                if len(_cache) > 32:
                    _cache.clear()
                _cache[key] = out
        limit = max(1, min(int(limit), 3000))
        return {**out, **db.result_meta(con, w, host), "pairs": out["pairs"][:limit], "truncated": len(out["pairs"]) > limit,
                "alert": db.alert_public(scope, programs is not None, limited=only_alert)}
    finally:
        con.close()


@router.get("/rhythm")
def pair_rhythm(image: str, ip: str, port: int, window: str = "24h", start: str = None, end: str = None, host: str = None):
    _, con = _open()
    try:
        try:
            w = db.window(con, window, start, end)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {**rhythm(con, w, image, ip, port, host), **db.result_meta(con, w, host)}
    finally:
        con.close()
