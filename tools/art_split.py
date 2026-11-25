"""v4: split the X4 Atomic Red Team tests into a LEARN half and a held-out TEST half (docs/plans/v4-prereg.md).

    python tools/art_split.py --seed S [--art-dir ..\\art\\docs\\plans\\art]

Made 2026-11-14, before any official ART boot was scored. The unit is the PARENT technique
(T1059.001 -> T1059): every test of one parent lands in the same half, so v4 is never "tested" on
a near-twin of something it learned from. The three spike techniques (seen, art-prereg section 8)
go to LEARN. The other parents are shuffled with the seed and dealt, one by one, to whichever half
has fewer tests so far (phase 1 + phase 2 together), so the halves are of similar size.
Only the two reviewed lists are read, by their pinned SHA-256 (art-prereg sections 7 and 9).
Writes docs/plans/v4/art-split.json.
"""
import argparse
import csv
import hashlib
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = {  # file -> (phase, pinned SHA-256)
    "final.csv": (1, "0d92bd8b79dd372c1fbfeb73c0d15b5388a656effbf56295c36e025f08022231"),
    "final-admin.csv": (2, "6ed6f81e2d1f97b1f32fd02fc5946af44bcae6b23b24559ef632f1ae4eec080f"),
}
SEEN_PARENTS = ("T1036", "T1082", "T1105")   # the spike's techniques (T1036.003, T1082, T1105)
OUT = os.path.join(ROOT, "docs", "plans", "v4", "art-split.json")


def parent(technique):
    return str(technique).split(".")[0].strip().upper()


def read_lists(art_dir, lists=LISTS):
    tests = []
    for name, (phase, sha) in lists.items():
        path = os.path.join(art_dir, name)
        with open(path, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != sha:
            raise SystemExit(f"{name}: SHA-256 {got[:16]} is not the pinned {sha[:16]}")
        with open(path, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                tests.append({"phase": phase, "technique": r["technique"], "guid": r["guid"]})
    return tests


def split(tests, seed, seen=SEEN_PARENTS):
    by_parent = {}
    for t in tests:
        by_parent.setdefault(parent(t["technique"]), []).append(t)
    halves = {"learn": [], "test": []}
    size = {"learn": 0, "test": 0}
    for p in sorted(by_parent):
        if p in seen:
            halves["learn"].append(p)
            size["learn"] += len(by_parent[p])
    rest = sorted(p for p in by_parent if p not in seen)
    random.Random(seed).shuffle(rest)
    for p in rest:
        side = "learn" if size["learn"] < size["test"] else "test" if size["test"] < size["learn"] else ("learn", "test")[len(halves["learn"]) > len(halves["test"])]
        halves[side].append(p)
        size[side] += len(by_parent[p])
    guid_side = {t["guid"]: side for side, ps in halves.items() for p in ps for t in by_parent[p]}
    return {side: sorted(ps) for side, ps in halves.items()}, guid_side


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--art-dir", default=os.path.join(os.path.dirname(ROOT), "art", "docs", "plans", "art"))
    a = ap.parse_args(argv)
    tests = read_lists(a.art_dir)
    halves, guid_side = split(tests, a.seed)
    counts = {side: {f"phase{ph}": sum(1 for t in tests if t["phase"] == ph and guid_side[t["guid"]] == side) for ph in (1, 2)}
              for side in halves}
    doc = {"what": "v4 ART split (docs/plans/v4-prereg.md section 2)", "seed": a.seed, "unit": "parent technique",
           "seen_to_learn": list(SEEN_PARENTS), "lists": {n: s for n, (_, s) in LISTS.items()},
           "parents": halves, "counts": counts,
           "tests": {side: sorted(g for g, s in guid_side.items() if s == side) for side in halves}}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
    for side in halves:
        print(f"{side}: {len(halves[side])} parent techniques, tests {counts[side]}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
