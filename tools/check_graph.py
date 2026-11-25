"""Stage 9 real-data check: build the evidence graph from a store of real recordings and trace
every fact edge back to the stored events it cites, using plain SQL (not the graph code).

    python tools/check_graph.py --db recordings/scratch/graph.db [--seeds 3]

PRIVACY RULE (DESIGN 9.1): prints counts, timings and program names only. Never folders, file
names, command lines, domains or IP addresses.
"""

import argparse
import ntpath
import os
import random
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.graph import build_graph, facts, subgraph_around  # noqa: E402
from engine.jsonl import iter_jsonl  # noqa: E402
from engine.store import EventStore  # noqa: E402

# Deliberately NOT imported from engine.graph, so a bug there can't hide in the check too.
ZERO_HEX = "0" * 32
FILE_HASH_MAX_SECONDS = 130

COLS = ["event_id", "type", "UtcTime", "time", "session", "ProcessGuid", "ProcessId", "Image",
        "ParentProcessGuid", "Initiated", "SourceIp", "DestinationIp", "DestinationPort",
        "TargetFilename", "Hashes", "QueryName", "LocalIp", "LocalPort", "sha256", "hash_status",
        "ref_record_id", "ref_time", "host", "channel", "record_id", "dedup_key", "TargetObject", "Details"]


def when(r):
    """Event time from the raw text: UtcTime ('YYYY-MM-DD HH:MM:SS.fff') or record time."""
    text = r.get("UtcTime") or r.get("time")
    if not text:
        return None
    text = text.replace("T", " ").rstrip("Z")
    base, _, frac = text.partition(".")
    return datetime.strptime(base, "%Y-%m-%d %H:%M:%S").replace(
        microsecond=int((frac + "000000")[:6]) if frac else 0, tzinfo=timezone.utc)


def zero(guid):
    return (guid or "").strip("{} ").replace("-", "") == ZERO_HEX


def same_path(a, b):
    strip = lambda p: (p or "").strip().removeprefix("\\\\?\\").removeprefix("\\??\\").lower()
    return bool(a) and strip(a) == strip(b)


def named_program(details):
    """The program an autostart value names, parsed here on its own (not engine.graph's parser):
    the quoted part if it starts with a quote, else everything up to the first space after a
    runnable file ending."""
    s = (details or "").strip()
    if s.startswith('"'):
        return s[1:].split('"', 1)[0]
    low = s.lower()
    ends = [low.find(e) + len(e) for e in (".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll")
            if low.find(e) > 0 and (len(low) == low.find(e) + len(e) or low[low.find(e) + len(e)] in " ,")]
    return s[:min(ends)] if ends else None


def db_lookup(db):
    have = {r[1].lower() for r in db.execute("PRAGMA table_info(events)")}
    # a store made before a column existed (registry fields, config v0.3): empty, not an error
    select = ", ".join(c if c.lower() in have else f"NULL AS {c}" for c in COLS)

    def row(key):
        r = db.execute(f"SELECT {select} FROM events WHERE dedup_key = ?", (key,)).fetchone()
        return dict(zip(COLS, r)) if r else None
    return row


def jsonl_lookup(paths, keys):
    """The same rows read straight from the recording files (the agent's copy of Sysmon's log),
    flattened like the store does, so the trace does not depend on the loader or the database."""
    found = {}
    for path in paths:
        for rec in iter_jsonl(path):
            key = EventStore.dedup_key(rec)
            if key in keys:
                flat = {c: rec.get(c) for c in COLS}
                flat.update({c: v for c, v in (rec.get("data") or {}).items() if c in COLS})
                flat["dedup_key"] = key
                for c in ("ProcessId", "DestinationPort", "LocalPort", "ref_record_id"):
                    if flat.get(c) not in (None, ""):
                        flat[c] = int(flat[c])
                found[key] = flat
    return found.get


def guid_of(node):
    return node.split(":", 2)[2].upper()


def acted(r, node):
    """The row's acting process is exactly this (non-zero) process node."""
    return node.startswith("proc:") and not zero(guid_of(node)) and (r["ProcessGuid"] or "").upper() == guid_of(node)


def sha_in(hashes):
    return {p.split("=", 1)[1].strip().upper() for p in (hashes or "").split(",") if p.upper().startswith("SHA256=")}


def check_edge(row, G, u, v, d):
    """Return None if the cited rows say exactly what the edge claims, else a reason."""
    rows = [row(e["key"]) for e in d["evidence"]]
    primary = row(d["primary"]["key"])
    if any(r is None for r in rows) or primary is None:
        return "cited row missing from the store"
    if when(primary) != d["time"]:
        return "edge time differs from the event time"
    k, r = d["kind"], rows[0]
    if k == "started":
        ok = r["event_id"] == 1 and acted(r, v) and not zero(r["ParentProcessGuid"]) and \
            (r["ParentProcessGuid"] or "").upper() == guid_of(u)
    elif k in ("connected_to", "accepted_from"):
        n = G.nodes[v]
        ok = r["event_id"] == 3 and acted(r, u) and (
            (k == "connected_to" and r["Initiated"] == "true" and r["DestinationIp"] == n["ip"]
             and r["DestinationPort"] == n["port"])
            or (k == "accepted_from" and r["Initiated"] == "false" and r["SourceIp"] == n["ip"]))
    elif k in ("created", "deleted"):
        n = G.nodes[v]
        ok = r["event_id"] == (11 if k == "created" else 26) and acted(r, u) and same_path(r["TargetFilename"], n["path"])
        if ok and n.get("sha256") and k == "deleted":
            ok = n["sha256"] in sha_in(r["Hashes"])
        if ok and n.get("sha256") and k == "created":
            fh = row(d["fingerprint"]["key"])
            ok = (fh is not None and fh["type"] == "FILE_HASH" and fh["hash_status"] == "ok"
                  and (fh["sha256"] or "").upper() == n["sha256"]
                  and f"{fh['host']}|{r['channel']}|{fh['ref_record_id']}|{fh['ref_time']}" == r["dedup_key"]
                  and 0 <= (when(fh) - when(r)).total_seconds() + 2 <= FILE_HASH_MAX_SECONDS + 2)
    elif k == "looked_up":
        ok = r["event_id"] == 22 and acted(r, u) and (r["QueryName"] or "").lower() == G.nodes[v]["name"].lower()
    elif k == "set_autostart":
        ok = r["event_id"] == 13 and acted(r, u) and (r["TargetObject"] or "").lower() == G.nodes[v]["key"].lower()
    elif k == "will_start":                          # the value's text names that file's full path
        n = G.nodes[v]
        ok = (r["event_id"] == 13 and (r["TargetObject"] or "").lower() == G.nodes[u]["key"].lower()
              and n["kind"] == "file" and same_path(named_program(r["Details"]), n["path"]))
    elif k in ("listen_started", "listen_stopped"):
        start, port = rows
        n = G.nodes[v]
        ok = port["dedup_key"] == primary["dedup_key"] and (start["event_id"] == 1 and acted(start, u)
                     and port["type"] == ("PORT_LISTEN_START" if k == "listen_started" else "PORT_LISTEN_STOP")
                     and port["ProcessId"] == start["ProcessId"] and same_path(port["Image"], start["Image"])
                     and when(start) <= when(port) and port["LocalIp"] == n["ip"] and port["LocalPort"] == n["port"])
    elif k == "ran_as":
        proof, start = rows
        n = G.nodes[u]
        ok = start["event_id"] == 1 and acted(start, v) and same_path(start["Image"], n["path"]) and \
            n["sha256"] in sha_in(start["Hashes"]) and same_path(proof["TargetFilename"], n["path"]) and (
                (proof["type"] == "FILE_HASH" and proof["hash_status"] == "ok" and (proof["sha256"] or "").upper() == n["sha256"])
                or (proof["event_id"] == 26 and n["sha256"] in sha_in(proof["Hashes"])))
    else:
        return f"unknown edge kind {k}"
    return None if ok else f"{k}: cited event does not say this"


def trace_all(row, G):
    bad = Counter()
    for u, v, d in facts(G):
        why = check_edge(row, G, u, v, d)
        if why:
            bad[why] += 1
    bad["process node with an all-zero GUID"] += sum(1 for n, d in G.nodes(data=True)
                                                     if d["kind"] == "process" and zero(d["guid"]))
    for g in G.graph["gaps"]:
        r = row(g["evidence"][0]["key"])
        if g["kind"] == "parent_unknown" and not zero(r["ParentProcessGuid"] or ZERO_HEX):
            bad["parent_unknown gap on a non-zero parent"] += 1
        if g["kind"] == "actor_unknown" and not zero(r["ProcessGuid"]):
            bad["actor_unknown gap on a known actor"] += 1
    return +bad

def completeness(db, G, include_project):
    """Every eligible event must give exactly one edge, or one gap that says why not."""
    where = "" if include_project else (" AND origin != 'project' AND upper(ProcessGuid) NOT IN "
                                         "(SELECT upper(ProcessGuid) FROM events WHERE origin='project' AND ProcessGuid IS NOT NULL "
                                         "AND replace(trim(ProcessGuid, '{}'), '-', '') != '00000000000000000000000000000000')")
    q = lambda cond: db.execute(f"SELECT COUNT(*) FROM events WHERE channel='Microsoft-Windows-Sysmon/Operational' AND {cond}{where}").fetchone()[0]
    kinds = Counter(d["kind"] for *_, d in facts(G))
    no_actor = Counter(g["evidence"][0]["event"] for g in G.graph["gaps"] if g["kind"] == "actor_unknown")
    stats = G.graph["stats"]
    hidden = sum(1 for _, n in G.nodes(data=True) if n.get("parent_hidden"))
    rows = {
        "event 3 -> connected_to + accepted_from (+ no-actor gaps, unknown direction)":
            (q("event_id=3"), kinds["connected_to"] + kinds["accepted_from"] + no_actor[3]
             + stats.get("event3_direction_unknown", 0) + stats.get("event3_without_address", 0)),
        "event 11 -> created (+ no-actor gaps)": (q("event_id=11"), kinds["created"] + no_actor[11]),
        "event 26 -> deleted (+ no-actor gaps)": (q("event_id=26"), kinds["deleted"] + no_actor[26]),
        "event 22 -> looked_up (+ no-actor gaps)": (q("event_id=22"), kinds["looked_up"] + no_actor[22]),
        "event 13 -> set_autostart (+ no-actor gaps, no value named)":
            (q("event_id=13"), kinds["set_autostart"] + no_actor[13] + stats.get("event13_without_target", 0)),
        "event 1 -> started + parent gaps + hidden parents":
            (q("event_id=1"), kinds["started"] + sum(1 for g in G.graph["gaps"] if g["kind"] == "parent_unknown") + hidden),
    }
    return rows

def pick_seeds(G, n, rng):
    """Real seeds from normal use, chosen by shape (never by name): a process tree with
    children, a process that created a program/script file, a process with network activity."""
    normal = [x for x, d in G.nodes(data=True) if d["kind"] == "process" and d.get("origin") == "normal"
              and d["start_recorded"]]
    shapes = {
        "process tree (has children)": lambda x: sum(1 for *_, e in G.out_edges(x, data=True) if e["kind"] == "started") >= 2,
        "created a program/script file": lambda x: any(e["kind"] == "created" and G.nodes[t]["path"].lower().endswith(
            (".exe", ".dll", ".ps1", ".js", ".py", ".bat", ".cmd", ".msi")) for _, t, e in G.out_edges(x, data=True)),
        "network activity (DNS + connection)": lambda x: {"looked_up", "connected_to"} <= {e["kind"] for *_, e in G.out_edges(x, data=True)},
    }
    seeds = []
    for shape, test in list(shapes.items())[:n]:
        pool = sorted(x for x in normal if test(x))
        if pool:
            seeds.append((shape, rng.choice(pool), len(pool)))
    return seeds


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--db", required=True)
    p.add_argument("--seeds", type=int, default=3)
    p.add_argument("--random-seed", type=int, default=20261016)
    p.add_argument("--jsonl", nargs="*", help="recording files to trace the seed subgraphs against")
    a = p.parse_args(argv)
    db = sqlite3.connect(a.db)
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"store: {total} events")

    for include_project in (True, False):
        t = time.perf_counter()
        G = build_graph(a.db, include_project=include_project)
        took = time.perf_counter() - t
        kinds = Counter(d["kind"] for _, d in G.nodes(data=True))
        edges = Counter(d["kind"] for *_, d in facts(G))
        gaps = Counter(g["kind"] for g in G.graph["gaps"])
        label = "everything" if include_project else "normal use only (project filtered out)"
        print(f"\n== full graph, {label}: built in {took:.1f} s")
        print(f"nodes {G.number_of_nodes()} {dict(kinds)}")
        print(f"fact edges {G.number_of_edges()} {dict(edges)}")
        print(f"gaps {sum(gaps.values())} {dict(gaps)}; layer-2 candidates (not facts) {len(G.graph['layer2_candidates'])}")
        comp = completeness(db, G, include_project)
        for k, (exp, got) in comp.items():
            print(f"completeness {k}: events {exp} -> {got} {'OK' if exp == got else 'MISMATCH'}")
        t = time.perf_counter()
        bad = trace_all(db_lookup(db), G)
        print(f"trace: {G.number_of_edges()} fact edges re-checked against their stored events in "
              f"{time.perf_counter() - t:.1f} s -> {sum(bad.values())} problems {dict(bad)}")

    # seeds from normal use (G is the filtered graph here)
    rng = random.Random(a.random_seed)
    print("\n== 3 real seeds (normal use); program names only")
    for shape, seed, pool in pick_seeds(G, a.seeds, rng):
        t = time.perf_counter()
        H = subgraph_around(G, seed)
        took = time.perf_counter() - t
        progs = Counter(d.get("label") for _, d in H.nodes(data=True) if d["kind"] == "process")
        bad = trace_all(db_lookup(db), H)
        if a.jsonl:
            keys = {e["key"] for *_, e in facts(H) for e in e["evidence"]}
            keys |= {e["fingerprint"]["key"] for *_, e in facts(H) if e.get("fingerprint")}
            keys |= {ev["key"] for g in H.graph["gaps"] for ev in g["evidence"]}
            lookup = jsonl_lookup(a.jsonl, keys)
            raw_bad = trace_all(lookup, H)
            missing = sum(1 for k in keys if lookup(k) is None)
        print(f"seed [{shape}] program {G.nodes[seed]['label']} (1 of {pool} candidates): subgraph in {took * 1000:.0f} ms; "
              f"nodes {H.number_of_nodes()} {dict(Counter(d['kind'] for _, d in H.nodes(data=True)))}; "
              f"facts {H.number_of_edges()} {dict(Counter(d['kind'] for *_, d in facts(H)))}; "
              f"gaps {len(H.graph['gaps'])}; truncated {H.graph['truncated']}; max depth "
              f"{max(dd for _, dd in H.nodes(data='depth'))}; traced in store -> {sum(bad.values())} problems")
        if a.jsonl:
            print(f"   traced in the raw recording: {len(keys)} cited events, {missing} not found, "
                  f"{sum(raw_bad.values())} problems {dict(raw_bad)}")
        print(f"   programs in it: {dict(progs.most_common(8))}")


if __name__ == "__main__":
    main()
