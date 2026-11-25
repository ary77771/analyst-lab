"""Hub suppression for the evidence graph (package G, DESIGN 4.7 layer 3; decided by Yousif
2026-10-23: "the best one" of the measured options = the distinct-children list, O2b in
docs/results/options-g-hubs-dev.md).

A hub is a program that starts MANY DIFFERENT programs in normal use (a service host, the
desktop shell): walking through it pulls unrelated stories into a view. The list is learned
once from the laptop's dev week (normal use: event-1 starts; our own tools, what they start
and paused rows left out): the top `top_share` of programs by number of distinct child program
names, at least `min_children` (both in config/frozen.yaml graph.hub_rule). It is static and
frozen like the learned-normal baselines (its file's SHA256 is in config/frozen.yaml).

- A program is identified by its FULL path (case-insensitive), not its file name: a copy named
  like a service host in a user folder is not a hub (names are the classic disguise).
- Command shells (baseline.SHELLS) are never hubs: a shell started by an unusual program is
  exactly the story a view must show (O2a's loss in the options measurement).
- Counting distinct child NAMES means a program that starts many copies of one child is not a hub.

In a view a hub is KEPT as a node (marked `hub`) but not walked through; the seed itself is
always walked.

    python -m engine.hubs --db recordings/scratch/dev/dev-laptop.db --until 2026-10-23 --out recordings/hubs/hubs.json

The list holds program paths from the user's laptop: it lives under recordings/ (git-ignored,
privacy rule 7); only counts are printed.
"""

import argparse
import hashlib
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timezone

from .baseline import NORMAL, SHELLS, base
from .detect import SYSMON_CHANNEL
from .graph import DEV_TOOLS, is_zero_guid, norm_guid, norm_path

METHOD = "distinct_children"


def distinct_children(con, until=None) -> dict:
    """{normalized program path: number of distinct child program names} over normal-use starts
    (every program seen, as parent or child, is counted; one that starts nothing has 0)."""
    project = {(str(h).lower(), norm_guid(g)) for h, g in con.execute(
        "SELECT DISTINCT host, ProcessGuid FROM events WHERE origin = 'project' AND ProcessGuid IS NOT NULL")}
    q = (f"SELECT host, ParentImage, Image, ParentProcessGuid FROM events WHERE event_id = 1 "
         f"AND channel = '{SYSMON_CHANNEL}' AND {NORMAL}" + (" AND time < ?" if until else ""))
    children, programs = defaultdict(set), set()
    for host, parent, image, pguid in con.execute(q, (until,) if until else ()):
        p, c = norm_path(parent), norm_path(image)
        if not p or not c or not pguid or is_zero_guid(pguid):
            continue                     # parent unknown (started before Sysmon): a gap, not a parent
        if (str(host).lower(), norm_guid(pguid)) in project or base(parent) in DEV_TOOLS:
            continue                     # started by our own tools: the graph hides these links too
        children[p].add(base(image))
        programs |= {p, c}
    return {n: len(children.get(n, ())) for n in programs}


def top_share(counts: dict, share: float, floor: int):
    """(programs whose count is at least the cut, cut): the cut is the count of the program
    ranked at the top `share` of all programs, never below `floor`. Ties at the cut are in."""
    if not counts:
        return set(), None
    k = max(1, math.ceil(share * len(counts)))
    cut = max(sorted(counts.values(), reverse=True)[k - 1], floor)
    return {n for n, c in counts.items() if c >= cut}, cut


def learn(con, top_share_: float, min_children: int, until=None) -> dict:
    counts = distinct_children(con, until)
    hubs, cut = top_share(counts, top_share_, min_children)
    shells = {h for h in hubs if base(h) in SHELLS}
    return {"method": METHOD, "top_share": top_share_, "min_children": min_children, "cut": cut,
            "programs": len(counts), "hubs": sorted(hubs - shells), "shells_left_out": len(shells)}


def save(learned: dict, path: str, learned_from: str) -> str:
    doc = {"version": 2, "learned_from": learned_from,
           "built_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), **learned}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(doc, indent=1, sort_keys=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:     # the hash is of the exact file bytes
        f.write(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load(path) -> frozenset:
    """The hub programs as normalized paths (shells are refused even if a file lists one)."""
    return frozenset(norm_path(p) for p in read(path)["hubs"] if base(p) not in SHELLS)


def is_hub(G, node, hubs) -> bool:
    d = G.nodes[node]
    return d.get("kind") == "process" and norm_path(d.get("image")) in hubs


def expander(hubs):
    """The `expand` hook for graph.subgraph_around: hubs are not walked through."""
    return lambda G, node: not is_hub(G, node, hubs)


def mark(H, hubs):
    """Flag the hubs a view kept but did not walk through (the seed is always walked)."""
    for n, d in H.nodes(data=True):
        if d.get("depth", 0) > 0 and is_hub(H, n, hubs):
            d["hub"] = True
    return H


def main(argv=None):
    import sqlite3
    from . import config
    ap = argparse.ArgumentParser(description="Learn the hub list (counts printed only)")
    ap.add_argument("--db", required=True, help="event store (opened read-only)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--until", help="learn only from events before this UTC day/time (e.g. 2026-10-23)")
    a = ap.parse_args(argv)
    rule = config.hub_rule()
    con = sqlite3.connect("file:" + os.path.abspath(a.db).replace("\\", "/") + "?mode=ro", uri=True)
    learned = learn(con, rule["top_share"], rule["min_children"], a.until)
    src = os.path.basename(a.db) + (f", events before {a.until}" if a.until else "")
    digest = save(learned, a.out, src)
    print(f"{len(learned['hubs'])} hub program(s) of {learned['programs']} programs (cut: >= {learned['cut']} "
          f"distinct children; shells left out: {learned['shells_left_out']})")
    print(f"saved {a.out} · sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
