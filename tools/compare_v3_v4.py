"""v3 vs v4 on the SAME official data: the regression of the v4 pre-registration (docs/plans/v4-prereg.md
section 3, item 4). The rules of tools/compare_v1_v2.py / compare_v2_v3.py: a run DETECTED before and not
now is LOST, a flagged suspicious step no longer flagged is LOST, fewer expected facts / a correct
hypothesis gone / a checker PASS turned FAIL is LOST; every loss reported, never patched.

Three comparisons, each from aggregate JSON written by tools/experiments.py:
  A. v3's own official runs (blind round 3, B10-B17): v3's official scoring (recordings/experiments/v3/official/,
     made at freeze-v3, SHA-256 pinned below) vs v4's re-scoring (`... --label official --of v3` -> v4/official-v3runs/);
  B. v2's official runs as v3 re-scored them (v3/official-v2runs/, pinned) vs v4's (`--of v2` -> v4/official-v2runs/);
  C. v1's official runs and test week (v3/official-v1runs/, pinned) vs v4's (`--of v1` -> v4/official-v1runs/).
B10-B17 are SEEN for v4 (its F1-F5 were designed after them): a gain there is "on data v4 learned from".
v4's own laptop week and the ART sealed half are judged elsewhere (pre-registration items 1 and 3).

    python tools/compare_v3_v4.py        # writes docs/results/v4/v3-vs-v4.md
Exit 0 = nothing lost; 1 = something LOST; 2 = NOT COMPARED. Run ids, scenario ids, rule ids, counts only.
Written 2026-11-17, BEFORE freeze-v4 (the pins are v3's files as they were then).
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_v1_v2 as C  # noqa: E402
from compare_v2_v3 import lost_steps  # noqa: E402

PROJECT_ROOT = os.path.dirname(HERE)
EXP = os.path.join(PROJECT_ROOT, "recordings", "experiments")
OUT = os.path.join(PROJECT_ROOT, "docs", "results", "v4", "v3-vs-v4.md")
OLD, NEW = "v3", "v4"
# v3's official JSON as it was on 2026-11-17 (made at / after freeze-v3), pinned before freeze-v4
OLD_SHA256 = {
    ("official", "blind-detection"): "422abfeca4599f5988efef6d1932a509357c14ee6825e7394bb0a2dc2acb7c88",
    ("official", "blind-story"): "dc89716291aa93eed87b26b9471ee92d6316a8fdb3748de78c8cca90bbaf4ddc",
    ("official-v2runs", "blind-detection"): "e76a8018bfdc4668a7063575bf8871972f917eb8c574a4128325b3334eabeaf5",
    ("official-v2runs", "blind-story"): "3bc582e46da5b4c6bd362a96a420b90e05d0a46b6e068f80385ec3aebef18595",
    ("official-v2runs", "detection"): "f82027c0c33707e4af5ec7a8ba0d9ef69095956f03772ca06c9041995240cdde",
    ("official-v2runs", "story"): "db32f2d8c777eba76ffe60df11966c0dd7b3c44953907d33e4a62249e009468c",
    ("official-v1runs", "blind-detection"): "995077067f27a08e0097cbb3f04a793799f6337d583db86a2debf7f830641be8",
    ("official-v1runs", "blind-story"): "e31a06454bab6907d76b342c53dd72717f4b9390315aae32d926d799839e573e",
    ("official-v1runs", "detection"): "154d962cd85a4416c4057934a9b945ee71c3d9f36753845f688ec97472c43bb3",
    ("official-v1runs", "false-alerts"): "acc0d6c706055dc5ec1eb748631b2c16ccac7ad4dc0ac6ad0919197073986d85",
    ("official-v1runs", "story"): "4db9133fb25ff00240237600ab90f3463c1f6070f4732f58070f2c1822a2df8c",
}
# part: (v3 folder, v4 folder, --of, documents)
PARTS = {"A": ("official", "official-v3runs", "v3", ("blind-detection", "blind-story")),
         "B": ("official-v2runs", "official-v2runs", "v2", ("detection", "blind-detection", "story", "blind-story")),
         "C": ("official-v1runs", "official-v1runs", "v1", ("detection", "blind-detection", "story", "blind-story", "false-alerts"))}
LABELS = {"A": "A. v3's own official runs (blind round 3, B10-B17; SEEN for v4)",
          "B": "B. v2's official runs (S6, B3-B5)", "C": "C. v1's official runs and test week"}


def problems(exp, docs, check_hashes=True):
    out = []
    for part, (old_dir, new_dir, of, names) in PARTS.items():
        for n in names:
            if docs[part]["old"][n] is None:
                out.append(f"{part}: {OLD} {old_dir}/{n}.json is missing")
            elif check_hashes and C.sha256(os.path.join(exp, OLD, old_dir, f"{n}.json")) != OLD_SHA256[(old_dir, n)]:
                out.append(f"{part}: {OLD} {old_dir}/{n}.json is not the pinned file (SHA-256 differs)")
            d = docs[part]["new"][n]
            if d is None:
                out.append(f"{part}: {NEW} {new_dir}/{n}.json is missing (run `experiments.py "
                           f"{'blind' if n.startswith('blind') else n} --label official --of {of}`)")
            elif check_hashes and not ((d.get("code") or {}).get("frozen") and d.get("of") == of):
                out.append(f"{part}: {NEW} {new_dir}/{n}.json was not made by the frozen {NEW} code over {of}'s runs")
        if "false-alerts" in names and docs[part]["old"]["false-alerts"] and docs[part]["new"]["false-alerts"]:
            keys = ("from_day_utc", "cutoff_day_utc", "events")
            a, b = docs[part]["old"]["false-alerts"]["snapshot"], docs[part]["new"]["false-alerts"]["snapshot"]
            if {k: a.get(k) for k in keys} != {k: b.get(k) for k in keys}:
                out.append(f"{part}: the two false-alert scorings did not cover the same snapshot")
    return out


def section(title, rows_extra, story=False):
    rows, extra = rows_extra
    if story:
        return [f"### {title}", "",
                f"{len(rows)} runs; expected facts found {OLD} {sum(r['facts_v1'] for r in rows)}, {NEW} "
                f"{sum(r['facts_v2'] or 0 for r in rows)}; correct expected hypotheses {OLD} {sum(r['hyps_v1'] for r in rows)}, "
                f"{NEW} {sum(r['hyps_v2'] or 0 for r in rows)}; checker PASS {OLD} {sum(bool(r['pass_v1']) for r in rows)}, "
                f"{NEW} {sum(bool(r['pass_v2']) for r in rows)}; LOST {sum(r['kind'] != 'same' for r in rows)}.", ""] + \
            [f"- LOST: {r['scenario']} {r['run_id']} (PASS {r['pass_v1']} -> {r['pass_v2']}, facts {r['facts_v1']} -> "
             f"{r['facts_v2']}, hypotheses lost: {'; '.join(r['lost_hypotheses']) or '-'})" for r in rows if r["kind"] != "same"] + [""]
    return [f"### {title}", "",
            f"{len(rows)} runs; same {sum(r['kind'] == 'same' for r in rows)}, LOST {sum(r['kind'] == 'LOST' for r in rows)}, "
            f"gained {sum(r['kind'] == 'gained' for r in rows)}, missing in {NEW} {sum(r['kind'] == 'MISSING IN V2' for r in rows)}"
            + (f"; runs only in {NEW}: {len(extra)}" if extra else "") + f"; other alerts summed: {OLD} "
            f"{sum(r['other_v1'] or 0 for r in rows)}, {NEW} {sum(r['other_v2'] or 0 for r in rows)}.", ""] + \
        [f"- {r['kind']}: {r['scenario']} {r['run_id']} ({r['v1']} -> {r['v2']}; other alerts {r['other_v1']} -> {r['other_v2']}; "
         f"new rules in other alerts: {', '.join(r['new_other_rules']) or '-'})" for r in rows
         if r["kind"] != "same" or r["other_v1"] != r["other_v2"]] + [""]


def main(argv=None, check_hashes=True):
    try:
        return _main(argv, check_hashes)
    except Exception as e:                       # noqa: BLE001  (any error: NOT COMPARED, never "LOST")
        print(f"  FAIL  error while comparing: {type(e).__name__}: {str(e)[:160]}\nNOT COMPARED: nothing written")
        return 2


def _main(argv=None, check_hashes=True):
    ap = argparse.ArgumentParser(description=f"{OLD} vs {NEW} on the same official data (aggregate JSON only)")
    ap.add_argument("--experiments", default=EXP)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    docs = {part: {"old": {n: C.load(os.path.join(a.experiments, OLD, old_dir), n) for n in names},
                   "new": {n: C.load(os.path.join(a.experiments, NEW, new_dir), n) for n in names}}
            for part, (old_dir, new_dir, of, names) in PARTS.items()}
    bad = problems(a.experiments, docs, check_hashes)
    if bad:
        for p in bad:
            print(f"  FAIL  {p}")
        print("NOT COMPARED: nothing written")
        return 2
    L = [f"# {OLD} vs {NEW} on the same official data (regression)", "",
         f"*Made by `python tools/compare_v3_v4.py`: {OLD}'s official JSON (SHA-256 pinned before freeze-v4) vs the same "
         f"runs re-scored by {NEW}'s frozen code. Rules of `tools/compare_v1_v2.py`; pre-registered in "
         "`docs/plans/v4-prereg.md` section 3 item 4. B10-B17 are SEEN for v4. The strict verdict only (v4's "
         "incident column is not compared: v3 has none).*", ""]
    lost = 0
    for part in PARTS:
        old, new = docs[part]["old"], docs[part]["new"]
        L += [f"## {LABELS[part]}", ""]
        for n in PARTS[part][3]:
            if n == "false-alerts":
                continue
            story = "story" in n
            rows = (C.compare_story if story else C.compare_detection)(old[n], new[n])
            L += section(n, rows, story)
            lost += sum((r["kind"] != "same") if story else (r["kind"] in ("LOST", "MISSING IN V2")) for r in rows[0])
            if n == "blind-detection":
                steps = lost_steps(old[n], new[n])
                L += [f"Flagged suspicious steps lost ({OLD} flagged, {NEW} not): {len(steps)}"] + \
                     [f"- LOST step: {sc} {rid} step {s}" for sc, rid, s in steps] + [""]
                lost += len(steps)
        if "false-alerts" in PARTS[part][3]:
            fa = C.compare_false_alerts(old["false-alerts"], new["false-alerts"])
            L += ["### false alerts", "", f"Raised per active hour: {OLD} {fa['v1']['per_active_hour']:.2f} ({fa['v1']['alerts']}), "
                  f"{NEW} {fa['v2']['per_active_hour']:.2f} ({fa['v2']['alerts']})."]
            L += [f"- {v['source']} {v['level']} {v['title']}: {OLD} {v['v1']}, {NEW} {v['v2']}" for v in fa["changed"]] \
                or ["- no rule changed"]
            L.append("")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"written: {a.out}; LOST items: {lost}")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
