"""Build docs/results/v4/art-map.json for the dashboard's "Attack coverage" screen (debate 12 E11).

Reads only committed results (nothing re-scored):
  - docs/results/v4/art-official-phase1.md, -phase2.md: v4's verdict per executed test (frozen v4,
    official 2026-11-14/15 boots), with and without the community rules that cite ART tests;
  - docs/results/v4/art-v3-vs-v4.md: the TEST-half tests v4 newly caught (all through command-line
    "declared" alerts, README section 1);
  - docs/plans/v4/art-split.json: which tests are the sealed TEST half (unseen by v4);
and the technique / test names from the Atomic Red Team copy in downloads/atomic-full-* (MIT).

    .venv\\Scripts\\python.exe demo\\build_art_map.py
"""

import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "docs", "results", "v4")
OUT = os.path.join(RES, "art-map.json")
ROW = re.compile(r"^\| (T\d{4}(?:\.\d{3})?) \| ([0-9a-f]{8}) \| (DETECTED|MISSED) \| (DETECTED|MISSED) \|", re.M)
GAINED = re.compile(r"- TEST Q1 gained: (.+)")
ITEM = re.compile(r"(T\d{4}(?:\.\d{3})?) \(([0-9a-f]{8})\)")


def art_names():
    names, tests = {}, {}
    pattern = os.path.join(ROOT, "downloads", "atomic-full-*", "**", "T*.yaml")
    import yaml
    for p in glob.glob(pattern, recursive=True):
        try:
            with open(p, encoding="utf-8") as f:
                y = yaml.safe_load(f) or {}
        except Exception:
            continue
        tid = y.get("attack_technique")
        if not tid:
            continue
        names[tid] = y.get("display_name", tid)
        for t in y.get("atomic_tests") or []:
            g = (t.get("auto_generated_guid") or "")[:8]
            if g:
                tests[g] = t.get("name", "")
    return names, tests


def build():
    with open(os.path.join(ROOT, "docs", "plans", "v4", "art-split.json"), encoding="utf-8") as f:
        test_half = {g[:8] for g in json.load(f)["tests"]["test"]}
    with open(os.path.join(RES, "art-v3-vs-v4.md"), encoding="utf-8") as f:
        gained = {g for line in GAINED.findall(f.read()) for _, g in ITEM.findall(line)}
    names, test_names = art_names()
    rows = []
    for phase in (1, 2):
        with open(os.path.join(RES, f"art-official-phase{phase}.md"), encoding="utf-8") as f:
            for tech, guid, q1, q2 in ROW.findall(f.read()):
                if guid not in test_half:
                    continue
                kind = "missed" if q1 == "MISSED" else ("declared" if guid in gained else "recorded")
                rows.append({"technique": tech, "guid": guid, "phase": phase, "result": kind,
                             "without_citing_rules": q2 == "DETECTED",
                             "technique_name": names.get(tech) or names.get(tech.split(".")[0], ""),
                             "test_name": test_names.get(guid, "")})
    rows.sort(key=lambda r: (r["technique"], r["guid"]))
    out = {"source": ["docs/results/v4/art-official-phase1.md", "docs/results/v4/art-official-phase2.md",
                      "docs/results/v4/art-v3-vs-v4.md", "docs/plans/v4/art-split.json"],
           "half": "TEST (sealed: unseen by v4 before the freeze)", "tests": rows}
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    n = len(rows)
    caught = sum(r["result"] != "missed" for r in rows)
    print(f"{n} tests; caught {caught} (declared {sum(r['result'] == 'declared' for r in rows)}), "
          f"without ART-citing rules {sum(r['without_citing_rules'] for r in rows)}; names found for "
          f"{sum(bool(r['technique_name']) for r in rows)}")
    return out


if __name__ == "__main__":
    sys.exit(0 if build() else 1)
