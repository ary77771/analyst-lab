"""v3 vs v4 on the Atomic Red Team series (v4 pre-registration section 3, item 1), written AFTER freeze-v4.

Reads the two art_score.py outputs per phase:
  v3: recordings/experiments/art/official/art-phase{1,2}.json   (made with freeze-v3, 2026-11-15)
  v4: recordings/v4-art/experiments/art/official/art-phase{1,2}.json (made with freeze-v4, 2026-11-19)
and the pinned split docs/plans/v4/art-split.json (via tools/art_view.py, SHA-256 checked).

Per phase and half (TEST = the sealed half = v4's result; LEARN = seen, for reference only):
executed, Q1 (verdict DETECTED), Q2 (verdict_without_art_citing DETECTED), and the tests v4 newly
detects / newly misses at Q1 and at Q2. The pre-registered rule (3.1): BETTER = v4's Q2 on the TEST
half above v3's AND no more than 2 tests lost. "Lost" is read strictly here: counted at Q1 and at Q2,
and the rule must hold for both (the pre-registration does not say which; the stricter reading is used).

Not in engine/ or tools/ (frozen); outside the code gate on purpose. Counts and technique ids only.

    python analysis/compare_art_v3_v4.py [--out docs/results/v4/art-v3-vs-v4.md] [--json out.json]
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import art_view  # noqa: E402

REC = os.path.join(ROOT, "recordings")
V3 = os.path.join(REC, "experiments", "art", "official", "art-phase{}.json")
V4 = os.path.join(REC, "v4-art", "experiments", "art", "official", "art-phase{}.json")
OUT = os.path.join(ROOT, "docs", "results", "v4", "art-v3-vs-v4.md")
MAX_LOST = 2


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def rows_by_test(doc):
    """{guid: row}; one row per test (art_score already chose one row per test)."""
    out = {}
    for r in doc.get("rows") or []:
        g = str(r.get("guid") or "").lower()
        if g in out:
            raise ValueError(f"test {g[:8]} appears twice in one art_score output")
        out[g] = r
    return out


def executed(r):
    return r is not None and r.get("verdict") != "NOT EXECUTED"


def q1(r):
    return executed(r) and r.get("verdict") == "DETECTED"


def q2(r):
    return executed(r) and r.get("verdict_without_art_citing") == "DETECTED"


def half_of(r, learn_parents, learn_guids):
    shown = art_view.parent(r.get("technique")) in learn_parents and str(r.get("guid") or "").lower() in learn_guids
    return "learn" if shown else "test"


def compare(v3doc, v4doc, learn_parents, learn_guids):
    a, b = rows_by_test(v3doc), rows_by_test(v4doc)
    if set(a) != set(b):
        raise ValueError(f"the two scorings cover different tests ({len(set(a) ^ set(b))} differ): not comparable")
    out = {}
    for half in ("test", "learn"):
        guids = sorted(g for g in a if half_of(a[g], learn_parents, learn_guids) == half)
        both_ex = [g for g in guids if executed(a[g]) and executed(b[g])]
        res = {"tests": len(guids), "executed_v3": sum(executed(a[g]) for g in guids),
               "executed_v4": sum(executed(b[g]) for g in guids),
               "executed_differs": sum(executed(a[g]) != executed(b[g]) for g in guids)}
        for name, fn in (("q1", q1), ("q2", q2)):
            res[f"{name}_v3"] = sum(fn(a[g]) for g in guids)
            res[f"{name}_v4"] = sum(fn(b[g]) for g in guids)
            res[f"{name}_gained"] = sorted((a[g]["technique"], g[:8]) for g in both_ex if fn(b[g]) and not fn(a[g]))
            res[f"{name}_lost"] = sorted((a[g]["technique"], g[:8]) for g in both_ex if fn(a[g]) and not fn(b[g]))
        out[half] = res
    return out


def verdict(t):
    better = t["q2_v4"] > t["q2_v3"]
    ok_lost = len(t["q1_lost"]) <= MAX_LOST and len(t["q2_lost"]) <= MAX_LOST
    return better and ok_lost, better, ok_lost


def pct(n, d):
    return f"{n}/{d} = {100 * n / d:.1f} %" if d else f"{n}/0"


def markdown(results):
    L = ["# Atomic Red Team: v3 vs v4 (v4 pre-registration 3.1)", "",
         "*Made by `analysis/compare_art_v3_v4.py` after `freeze-v4`. Same official recordings (20 boots, "
         "2026-11-14/15), scored by `tools/art_score.py` with the frozen v3 engine and with the frozen v4 engine. "
         "TEST half = the sealed half, never seen by v4 before the freeze: **v4's result**. LEARN half = seen by v4 "
         "(practice), shown for reference only.*", ""]
    total = {k: 0 for k in ("ex3", "ex4", "q13", "q14", "q23", "q24", "l1", "l2", "g1", "g2")}
    for ph, res in results.items():
        t = res["test"]
        ok, better, ok_lost = verdict(t)
        L += [f"## Phase {ph} ({'normal user' if ph == 1 else 'administrator'})", "",
              "| half | tests | executed v3 / v4 | Q1 v3 | Q1 v4 | Q2 v3 | Q2 v4 | Q1 gained / lost | Q2 gained / lost |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for half in ("test", "learn"):
            h = res[half]
            L.append(f"| {half.upper()}{' (seen)' if half == 'learn' else ''} | {h['tests']} | {h['executed_v3']} / {h['executed_v4']} | "
                     f"{pct(h['q1_v3'], h['executed_v3'])} | {pct(h['q1_v4'], h['executed_v4'])} | "
                     f"{pct(h['q2_v3'], h['executed_v3'])} | {pct(h['q2_v4'], h['executed_v4'])} | "
                     f"+{len(h['q1_gained'])} / -{len(h['q1_lost'])} | +{len(h['q2_gained'])} / -{len(h['q2_lost'])} |")
        L += ["", f"Pre-registered rule on the TEST half: Q2 above v3's: **{'yes' if better else 'no'}**; "
                  f"at most {MAX_LOST} lost (Q1 and Q2): **{'yes' if ok_lost else 'no'}** -> **{'BETTER' if ok else 'NOT BETTER'}**.", ""]
        for name in ("q1", "q2"):
            for kind in ("lost", "gained"):
                items = t[f"{name}_{kind}"]
                if items:
                    L.append(f"- TEST {name.upper()} {kind}: " + ", ".join(f"{tech} ({g})" for tech, g in items))
        if t["executed_differs"]:
            L.append(f"- {t['executed_differs']} TEST test(s) count as executed in one scoring but not the other (compared only where both executed).")
        L.append("")
        total["ex3"] += t["executed_v3"]; total["ex4"] += t["executed_v4"]
        total["q13"] += t["q1_v3"]; total["q14"] += t["q1_v4"]; total["q23"] += t["q2_v3"]; total["q24"] += t["q2_v4"]
        total["l1"] += len(t["q1_lost"]); total["l2"] += len(t["q2_lost"]); total["g1"] += len(t["q1_gained"]); total["g2"] += len(t["q2_gained"])
    L += ["## Both phases, TEST half", "",
          f"- Q1: v3 {pct(total['q13'], total['ex3'])}, v4 {pct(total['q14'], total['ex4'])} (gained {total['g1']}, lost {total['l1']})",
          f"- Q2: v3 {pct(total['q23'], total['ex3'])}, v4 {pct(total['q24'], total['ex4'])} (gained {total['g2']}, lost {total['l2']})", ""]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--json")
    ap.add_argument("--v3", default=V3)
    ap.add_argument("--v4", default=V4)
    a = ap.parse_args(argv)
    learn_parents, _ = art_view.load_split()
    learn_guids = art_view.learn_guids()
    results = {}
    for ph in (1, 2):
        d3, d4 = load(a.v3.format(ph)), load(a.v4.format(ph))
        if (d4.get("engine") or {}).get("tag") != "freeze-v4" or not (d4.get("engine") or {}).get("frozen"):
            print(f"NOT COMPARED: the v4 file of phase {ph} was not made by the frozen v4 engine")
            return 2
        if (d3.get("engine") or {}).get("tag") != "freeze-v3":
            print(f"NOT COMPARED: the v3 file of phase {ph} was not made by the v3 engine")
            return 2
        results[ph] = compare(d3, d4, learn_parents, learn_guids)
    md = markdown(results)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(md + "\n")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=1)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
