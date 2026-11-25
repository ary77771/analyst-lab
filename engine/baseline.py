"""Each machine's learned NORMAL (package B part 2, decided by Yousif 2026-10-23).

Two rules flag what a machine has never done before, instead of using a fixed list (a fixed
list of "usual" launchers gave ~120 false alarms per active hour on the laptop's dev week,
docs/results/options-b-c-dev.md):
  - which program -> command-shell pairs occur (parent program name, shell name), and
  - which programs open listening ports.
A baseline is learned once, from a period known to be free of scenarios, and then FROZEN
(its file's SHA256 goes into config/frozen.yaml at freeze-v1):
  - the laptop: its dev recording (normal use up to the dev cutoff day);
  - the VM: its baseline boots (scenario S0: a clean boot in which nothing runs), the whole
    recorder session of each such boot.
It is static: what happens later is never added to it (online learning would make the second
official run of a scenario look "normal" because the first one taught it).

    python -m engine.baseline --db recordings/scratch/dev/dev-laptop.db --until 2026-10-23 --out recordings/baselines/laptop.json
    python -m engine.baseline --db <VM store> --scenario-runs S0 --out recordings/baselines/vm.json

Baseline files hold program names (from the user's laptop): they live under recordings/
(git-ignored, privacy rule 7); only counts are printed.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from .detect import SYSMON_CHANNEL

NORMAL = f"COALESCE(origin, '') <> 'project' AND COALESCE(paused, 0) = 0"
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def base(path) -> str:
    """Lower-case program file name ('' for none)."""
    return str(path or "").replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def _where(host=None, until=None, sessions=None):
    parts, params = [], []
    if host is not None:
        parts.append("lower(host) = ?")
        params.append(host.lower())
    if until:
        parts.append("time < ?")
        params.append(until)
    if sessions is not None:
        parts.append(f"session IN ({','.join('?' * len(sessions))})" if sessions else "0")
        params.extend(sessions)
    return (" AND " + " AND ".join(parts)) if parts else "", params


def learn(con, host=None, until=None, sessions=None) -> dict:
    """{host: {"shell_pairs": [[parent, shell], ...], "listeners": [program, ...], "events": n}}.
    host / until (ISO, exclusive) / sessions (recorder session ids) narrow what is learned from."""
    extra, params = _where(host, until, sessions)
    out = {}
    q = (f"SELECT host, Image, ParentImage FROM events WHERE event_id = 1 AND channel = '{SYSMON_CHANNEL}' "
         f"AND {NORMAL}{extra}")
    for h, image, parent in con.execute(q, params):
        if base(image) in SHELLS:
            out.setdefault(str(h).lower(), {"shell_pairs": set(), "listeners": set()})["shell_pairs"].add((base(parent) or "?", base(image)))
    q = f"SELECT host, Image FROM events WHERE type = 'PORT_LISTEN_START' AND {NORMAL}{extra}"
    for h, image in con.execute(q, params):
        if image:
            out.setdefault(str(h).lower(), {"shell_pairs": set(), "listeners": set()})["listeners"].add(base(image))
    q = f"SELECT lower(host), COUNT(*) FROM events WHERE {NORMAL}{extra} GROUP BY 1"
    counts = dict(con.execute(q, params))
    return {h: {"shell_pairs": sorted(map(list, v["shell_pairs"])), "listeners": sorted(v["listeners"]),
                "events": counts.get(h, 0)} for h, v in out.items()} | \
           {h: {"shell_pairs": [], "listeners": [], "events": n} for h, n in counts.items() if h not in out}


def learn_wipers(con, host=None, until=None, sessions=None) -> dict:
    """v4 (F3): {host: {"shell_pairs": [], "listeners": [], "wipers": [program, ...], "events": n}}:
    the programs that created files and deleted them again (own_rules.wipe_episodes with the frozen
    settings, ANY level) during the learning period. Written to its OWN file, so the shell-pair and
    listener baselines (and their pinned hashes) stay as they are. host / until (ISO, exclusive, on
    the episode's time) / sessions (the creator's recorder session) narrow what is learned from."""
    from .config import own_rule_params
    from .own_rules import NEVER_NORMAL_WIPERS, wipe_episodes
    settings = own_rule_params().get("analystlab.create_send_wipe") or {}
    out = {}
    for a in wipe_episodes(con, **settings):
        h = str(a.host).lower()
        # until is checked on the ONE episode wipe_episodes picked per process (its first with a
        # connection, else its first): with a store that runs past `until`, a process whose low episode
        # came before and medium episode after is not learned. The frozen files use stores that end
        # with the learn period, so nothing is cut there (review 2026-11-15).
        if (host is not None and h != host.lower()) or (until and a.time >= until):
            continue
        if a.details["program"] in NEVER_NORMAL_WIPERS:
            continue
        if sessions is not None:
            ahost, guid = a.incident.split("|", 1)
            row = con.execute("SELECT session FROM events WHERE host = ? AND ProcessGuid = ? AND session IS NOT NULL "
                              "LIMIT 1", (ahost, guid)).fetchone()
            if not row or row[0] not in sessions:
                continue
        out.setdefault(h, set()).add(a.details["program"])
    extra, params = _where(host, until, sessions)
    counts = dict(con.execute(f"SELECT lower(host), COUNT(*) FROM events WHERE {NORMAL}{extra} GROUP BY 1", params))
    return {h: {"shell_pairs": [], "listeners": [], "wipers": sorted(out.get(h, ())), "events": n}
            for h, n in counts.items()}


def learn_connectors(con, host=None, until=None, sessions=None, unicast_only=True) -> dict:
    """v4 (F2): {host: {"shell_pairs": [], "listeners": [], "connectors": [program, ...], "events": n}}:
    the programs that opened an outgoing connection to a unicast address during the learning period,
    exactly the connections the beacon rule builds its series from (engine/beacon.py SERIES_SQL +
    is_unicast when `unicast_only`, as the beacon config). Written to its OWN file. host / until
    (ISO, exclusive, on WHEN the connection happened: COALESCE(UtcTime, time), the series' clock) /
    sessions narrow it."""
    from .beacon import SERIES_SQL, is_unicast
    extra, params = _where(host, None, sessions)
    if until:
        extra, params = extra + " AND COALESCE(UtcTime, time) < ?", [*params, until]
    out = {}
    for h, image, ip, *_ in con.execute(SERIES_SQL + extra, params):
        if (is_unicast(ip) or not unicast_only) and base(image):
            out.setdefault(str(h).lower(), set()).add(base(image))
    extra, params = _where(host, until, sessions)
    counts = dict(con.execute(f"SELECT lower(host), COUNT(*) FROM events WHERE {NORMAL}{extra} GROUP BY 1", params))
    return {h: {"shell_pairs": [], "listeners": [], "connectors": sorted(out.get(h, ())), "events": n}
            for h, n in counts.items()}


def sessions_of_runs(con, runs) -> list:
    """Recorder sessions that recorded during the given runs (dicts with start, end, host)."""
    found = set()
    for r in runs:
        q = "SELECT DISTINCT session FROM events WHERE session IS NOT NULL AND time >= ? AND time <= ?"
        found.update(s for (s,) in con.execute(q, (r["start"], r["end"])))
    return sorted(found)


def save(baseline: dict, path: str, learned_from: str) -> str:
    doc = {"version": 1, "learned_from": learned_from,
           "built_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "hosts": baseline}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(doc, indent=1, sort_keys=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:     # the hash is of the exact file bytes
        f.write(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load(paths) -> dict:
    """Merge baseline files into {host: {"shell_pairs": set of tuples, "listeners": set, "wipers": set,
    "connectors": set or None}} ("wipers": v4 F3, "connectors": v4 F2, each from its own file; older
    files have none). "connectors" stays None for a host no file has a connector list for, which is
    NOT the same as an empty list: no list = the F2 rule does not run for that host (it would
    otherwise call every program "never seen connecting")."""
    merged = {}
    for p in paths:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
        if not isinstance(doc, dict) or not isinstance(doc.get("hosts"), dict):
            raise ValueError(f"{p} is not a learned-normal baseline file (no 'hosts'): keep other files out of "
                             "recordings/baselines/ (the live loop loads every *.json there)")
        for h, v in doc["hosts"].items():
            m = merged.setdefault(h.lower(), {"shell_pairs": set(), "listeners": set(), "wipers": set(),
                                              "connectors": None})
            m["shell_pairs"].update(tuple(x) for x in v["shell_pairs"])
            m["listeners"].update(v["listeners"])
            m["wipers"].update(v.get("wipers") or ())
            if v.get("connectors") is not None:          # null = no list (review 2026-11-17), [] = an empty list
                m["connectors"] = (m["connectors"] or set()) | set(v["connectors"])
    return merged


def main(argv=None):
    import sqlite3
    ap = argparse.ArgumentParser(description="Learn each machine's normal (counts printed only)")
    ap.add_argument("--db", required=True, help="event store (opened read-only)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--host", help="only this machine")
    ap.add_argument("--until", help="learn only from events before this UTC day/time (e.g. 2026-10-23)")
    ap.add_argument("--scenario-runs", help="learn only from the recorder sessions of these runs, e.g. S0")
    ap.add_argument("--runs-since", help="with --scenario-runs: only runs that started at or after this UTC time "
                                         "(e.g. the boots of the current VM snapshot)")
    ap.add_argument("--wipers", action="store_true",
                    help="v4 (F3): learn ONLY the programs that create files and delete them again, into a separate file")
    ap.add_argument("--connectors", action="store_true",
                    help="v4 (F2): learn ONLY the programs that open outgoing connections, into a separate file")
    ap.add_argument("--recordings", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recordings"))
    a = ap.parse_args(argv)
    con = sqlite3.connect("file:" + os.path.abspath(a.db).replace("\\", "/") + "?mode=ro", uri=True)
    sessions, src = None, f"{os.path.basename(a.db)}"
    if a.scenario_runs:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
        from check_scenario import all_runs
        runs = [r for r in all_runs(a.recordings) if str(r.get("scenario", "")).upper() == a.scenario_runs.upper()
                and r.get("exit_code") == 0 and (not a.runs_since or str(r.get("start", "")) >= a.runs_since)]
        sessions = sessions_of_runs(con, runs)
        src += f", sessions of {len(runs)} {a.scenario_runs.upper()} run(s): {len(sessions)} session(s)"
        if not sessions:
            print(f"no recorder session found for {a.scenario_runs.upper()} runs")
            return 1
    if a.until:
        src += f", events before {a.until}"
    if a.wipers and a.connectors:
        print("--wipers and --connectors each write their own file: choose one")
        return 2
    if a.wipers:
        b, note = learn_wipers(con, a.host, a.until, sessions), ", wipers only (v4 F3)"
    elif a.connectors:
        from .beacon import load_config
        b, note = (learn_connectors(con, a.host, a.until, sessions, unicast_only=load_config().unicast_only),
                   ", connecting programs only (v4 F2)")
    else:
        b, note = learn(con, a.host, a.until, sessions), ""
    digest = save(b, a.out, src + note)
    for h, v in sorted(b.items()):
        print(f"{h[:4]}…: {len(v['shell_pairs'])} shell pairs, {len(v['listeners'])} listening programs, "
              f"{len(v.get('wipers', []))} wiping programs, {len(v.get('connectors', []))} connecting programs, "
              f"from {v['events']:,} events")
    print(f"saved {a.out} · sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
