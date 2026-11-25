"""v1 vs v2 on the SAME official data: the regression of the v2 pre-registration (docs/plans/v2-prereg.md,
section 5). Reads only aggregate JSON written by tools/experiments.py:

    v1: recordings/experiments/official/{detection,story,blind-detection,blind-story,false-alerts}.json
        (made at freeze-v1, never rewritten; their SHA-256 are checked against V1_SHA256)
    v2: recordings/experiments/v2/official-v1runs/<same names>.json
        (`experiments.py <question> --label official --of v1` with v2's FROZEN code: checked)

    python tools/compare_v1_v2.py      # writes docs/results/v2/v1-vs-v2.md

Rules (pre-registered, section 5):
  - a run v1 DETECTED that v2 does not is LOST; a run of v1 missing from v2's scoring is LOST;
  - in a run, an expected hypothesis v1 found correct (by its claim) that v2 does not is LOST;
    fewer expected facts found than v1 is LOST (facts are compared by count per run: the JSON holds
    no per-fact identity; v1 found every expected fact of its own scenarios, 790/790); a checker
    PASS in v1 that is a FAIL in v2 is LOST;
  - every loss is listed and REPORTED, never patched (a fix would be a new freeze and every v2
    result redone).
Gains, changes in other alerts per run and the raised false-alert rate per rule (by rule id) are
listed as measured. Both J4 scorings must cover the same snapshot (days and event count).
Exit codes: 0 = nothing lost; 1 = something LOST; 2 = NOT COMPARED (an input is missing, v1's
files changed, v2's scoring was not made by the frozen code, or the snapshots differ).
Prints and writes run ids, scenario ids, rule ids/titles, levels and counts only (privacy rule 7).
"""

import argparse
import hashlib
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V1_DIR = os.path.join(PROJECT_ROOT, "recordings", "experiments", "official")
V2_DIR = os.path.join(PROJECT_ROOT, "recordings", "experiments", "v2", "official-v1runs")
OUT = os.path.join(PROJECT_ROOT, "docs", "results", "v2", "v1-vs-v2.md")
NAMES = ("detection", "blind-detection", "story", "blind-story", "false-alerts")
# v1's official JSON as made at freeze-v1 (also written in docs/plans/v2-prereg.md before the tag):
# the baseline must be exactly that, never a re-made or overwritten file (review 2026-11-13)
V1_SHA256 = {
    "detection": "e7228b5e6a23b0711eb5cdf338bedf4df34c3559709d53abca27f71dedbfbbcb",
    "blind-detection": "0375b83908f51e7fd17aade0cb84fde4650bec5d888801bbaaa10df784154f33",
    "story": "16356550ad304e8705b83ac012d01aafff60826cc2f3dd525d5c8c49f0baf1c0",
    "blind-story": "7e6bdd03a672e79d94dc2ed02bea1a7492458b3f5279e20fcbb1506da96b54d1",
    "false-alerts": "991efa0c7cda2092096309bde0a5d971c1651aa75f9f8c3ef31554bdacd8828a"}


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(folder, name):
    path = os.path.join(folder, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def problems(v1_dir, v2_dir, docs, check_hashes=True):
    """Why the two sides cannot be compared ([] = they can)."""
    out = []
    for n in NAMES:
        if docs["v1"][n] is None:
            out.append(f"v1 {n}.json is missing")
        elif check_hashes and sha256(os.path.join(v1_dir, f"{n}.json")) != V1_SHA256[n]:
            out.append(f"v1 {n}.json is not the file made at freeze-v1 (SHA-256 differs)")
        d = docs["v2"][n]
        if d is None:
            out.append(f"v2 {n}.json is missing (run `experiments.py {n.replace('blind-', 'blind') if n.startswith('blind') else n} "
                       f"--label official --of v1`)")
        elif check_hashes and not ((d.get("code") or {}).get("frozen") and d.get("of") == "v1"):
            out.append(f"v2 {n}.json was not made by the frozen v2 code over v1's runs (code/of fields)")
    a, b = docs["v1"]["false-alerts"], docs["v2"]["false-alerts"]
    if a and b:
        keys = ("from_day_utc", "cutoff_day_utc", "events")
        if {k: a["snapshot"].get(k) for k in keys} != {k: b["snapshot"].get(k) for k in keys}:
            out.append("the two false-alert scorings did not cover the same snapshot (days or event count differ)")
    return out


def runs_by_id(doc):
    return {r["run_id"]: r for r in (doc or {}).get("runs", [])}


def compare_detection(v1, v2):
    """[{scenario, run, v1 verdict, v2 verdict, kind}] kind = LOST | gained | same | MISSING IN V2; plus
    per-run changes of other alerts."""
    a, b = runs_by_id(v1), runs_by_id(v2)
    rows = []
    for rid, r1 in a.items():
        r2 = b.get(rid)
        v2v = r2["verdict"] if r2 else None
        if r2 is None:
            kind = "MISSING IN V2"
        elif r1["verdict"] == "DETECTED" and v2v != "DETECTED":
            kind = "LOST"
        elif r1["verdict"] != "DETECTED" and v2v == "DETECTED":
            kind = "gained"
        else:
            kind = "same"
        new_other = sorted(set((r2 or {}).get("other_by_rule", {})) - set(r1.get("other_by_rule", {})))
        rows.append({"scenario": r1["scenario"], "run_id": rid, "v1": r1["verdict"], "v2": v2v, "kind": kind,
                     "other_v1": r1.get("other_alerts", 0), "other_v2": r2.get("other_alerts", 0) if r2 else None,
                     "new_other_rules": new_other})
    return rows, sorted(set(b) - set(a))


def correct_claims(run):
    return {h["claim"] for h in (run or {}).get("hypotheses", []) if h.get("correct")}


def compare_story(v1, v2):
    a, b = runs_by_id(v1), runs_by_id(v2)
    rows = []
    for rid, r1 in a.items():
        r2 = b.get(rid)
        t1, t2 = r1.get("tally", {}), (r2 or {}).get("tally", {})
        lost_hyps = sorted(correct_claims(r1) - correct_claims(r2)) if r2 else []
        lost_facts = max(0, t1.get("facts_found", 0) - t2.get("facts_found", 0)) if r2 else 0
        if r2 is None:
            kind = "MISSING IN V2"
        elif lost_facts or lost_hyps or (r1.get("pass") and not r2.get("pass")):
            kind = "LOST"
        else:
            kind = "same"
        rows.append({"scenario": r1["scenario"], "run_id": rid, "pass_v1": r1.get("pass"), "pass_v2": (r2 or {}).get("pass"),
                     "facts_v1": t1.get("facts_found", 0), "facts_v2": t2.get("facts_found") if r2 else None,
                     "hyps_v1": len(correct_claims(r1)), "hyps_v2": len(correct_claims(r2)) if r2 else None,
                     "lost_hypotheses": lost_hyps, "kind": kind})
    return rows, sorted(set(b) - set(a))


def compare_false_alerts(v1, v2):
    rules = {}
    for side, doc in (("v1", v1), ("v2", v2)):
        for r in doc.get("raised_rules", []):
            entry = rules.setdefault(r.get("rule_id") or r["title"], {"source": r["source"], "level": r["level"], "title": r["title"],
                                                                     "v1": 0, "v2": 0})
            entry[side] = r["n"]
    changed = sorted((v for v in rules.values() if v["v1"] != v["v2"]), key=lambda v: -abs(v["v2"] - v["v1"]))
    return {"v1": v1["raised"], "v2": v2["raised"], "changed": changed}


def markdown(det, bdet, story, bstory, fa):
    L = ["# v1 vs v2 on the same official data (regression)", "",
         "*Made by `python tools/compare_v1_v2.py` from the aggregate JSON of v1's official scoring (freeze-v1, SHA-256 "
         "checked) and of the same runs and test week re-scored with v2's frozen code (`experiments.py ... --label official "
         "--of v1`). Pre-registered in `docs/plans/v2-prereg.md` section 5: every LOST item is reported, never patched. "
         "B1/B2 are SEEN (v2's look-alike rule was designed after B1's miss was known).*", ""]
    for title, (rows, extra) in (("Detection (own scenarios)", det), ("Detection (B1/B2, seen)", bdet)):
        lost = [r for r in rows if r["kind"] in ("LOST", "MISSING IN V2")]
        L += [f"## {title}", "",
              f"{len(rows)} runs; same verdict {sum(r['kind'] == 'same' for r in rows)}, LOST {sum(r['kind'] == 'LOST' for r in rows)}, "
              f"gained {sum(r['kind'] == 'gained' for r in rows)}, missing in v2 {sum(r['kind'] == 'MISSING IN V2' for r in rows)}"
              + (f"; runs only in v2: {len(extra)}" if extra else "") + ".", "",
              f"Other alerts (>= floor, not involving the scenario) summed over the runs: v1 {sum(r['other_v1'] or 0 for r in rows)}, "
              f"v2 {sum(r['other_v2'] or 0 for r in rows)}.", ""]
        changed = [r for r in rows if r["kind"] != "same" or r["other_v1"] != r["other_v2"]]
        if changed:
            L += ["| scenario | run | v1 | v2 | kind | other alerts v1 / v2 | rules new in v2's other alerts |", "|---|---|---|---|---|---|---|"]
            L += [f"| {r['scenario']} | {r['run_id']} | {r['v1']} | {r['v2']} | {r['kind']} | {r['other_v1']} / {r['other_v2']} | "
                  f"{', '.join(r['new_other_rules']) or '-'} |" for r in changed]
            L.append("")
        if lost:
            L += [f"**LOST: {len(lost)} run(s)** (listed above; reported, not patched).", ""]
    for title, (rows, extra) in (("Story (own scenarios)", story), ("Story (B1/B2, seen)", bstory)):
        L += [f"## {title}", "",
              f"{len(rows)} runs; expected facts found v1 {sum(r['facts_v1'] for r in rows)}, v2 {sum(r['facts_v2'] or 0 for r in rows)}; "
              f"correct expected hypotheses v1 {sum(r['hyps_v1'] for r in rows)}, v2 {sum(r['hyps_v2'] or 0 for r in rows)}; "
              f"checker PASS v1 {sum(bool(r['pass_v1']) for r in rows)}, v2 {sum(bool(r['pass_v2']) for r in rows)}; "
              f"LOST {sum(r['kind'] != 'same' for r in rows)}.", ""]
        bad = [r for r in rows if r["kind"] != "same"]
        if bad:
            L += ["| scenario | run | PASS v1 / v2 | facts v1 / v2 | hyps v1 / v2 | hypotheses lost | kind |", "|---|---|---|---|---|---|---|"]
            L += [f"| {r['scenario']} | {r['run_id']} | {r['pass_v1']} / {r['pass_v2']} | {r['facts_v1']} / {r['facts_v2']} | "
                  f"{r['hyps_v1']} / {r['hyps_v2']} | {'; '.join(r['lost_hypotheses']) or '-'} | {r['kind']} |" for r in bad]
            L.append("")
    L += ["## False alerts on v1's laptop test week", "",
          f"Raised per active hour: v1 {fa['v1']['per_active_hour']:.2f} ({fa['v1']['alerts']} alerts), "
          f"v2 {fa['v2']['per_active_hour']:.2f} ({fa['v2']['alerts']} alerts), over {fa['v2']['active_hours']} active hours.", ""]
    if fa["changed"]:
        L += ["| source | level | rule | v1 | v2 |", "|---|---|---|---:|---:|"]
        L += [f"| {v['source']} | {v['level']} | {v['title']} | {v['v1']} | {v['v2']} |" for v in fa["changed"]]
    else:
        L.append("No rule raised a different number of alerts.")
    L.append("")
    return L


def main(argv=None, check_hashes=True):
    """Any unexpected error is NOT COMPARED (exit 2), never "something LOST" (review 2026-11-13)."""
    try:
        return _main(argv, check_hashes)
    except Exception as e:                       # noqa: BLE001
        print(f"  FAIL  error while comparing: {type(e).__name__}: {str(e)[:160]}\nNOT COMPARED: nothing written")
        return 2


def _main(argv=None, check_hashes=True):
    ap = argparse.ArgumentParser(description="v1 vs v2 on the same official data (aggregate JSON only)")
    ap.add_argument("--v1", default=V1_DIR)
    ap.add_argument("--v2", default=V2_DIR)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    docs = {side: {n: load(folder, n) for n in NAMES} for side, folder in (("v1", a.v1), ("v2", a.v2))}
    bad = problems(a.v1, a.v2, docs, check_hashes)
    if bad:
        for p in bad:
            print(f"  FAIL  {p}")
        print("NOT COMPARED: nothing written")
        return 2
    det, bdet = (compare_detection(docs["v1"][n], docs["v2"][n]) for n in ("detection", "blind-detection"))
    story, bstory = (compare_story(docs["v1"][n], docs["v2"][n]) for n in ("story", "blind-story"))
    fa = compare_false_alerts(docs["v1"]["false-alerts"], docs["v2"]["false-alerts"])
    L = markdown(det, bdet, story, bstory, fa)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    lost = sum(r["kind"] in ("LOST", "MISSING IN V2") for rows, _ in (det, bdet) for r in rows) + \
        sum(r["kind"] != "same" for rows, _ in (story, bstory) for r in rows)
    print(f"written: {a.out}; LOST items: {lost}")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
