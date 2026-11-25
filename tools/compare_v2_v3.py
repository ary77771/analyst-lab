"""v2 vs v3 on the SAME official data: the regression of the v3 pre-registration (docs/plans/v3-prereg.md
section 3). Reuses tools/compare_v1_v2.py's rules (a run DETECTED before and not now is LOST, fewer expected
facts / a correct hypothesis gone / a checker PASS turned FAIL is LOST, every loss reported, never patched).

Two comparisons, each from aggregate JSON written by tools/experiments.py:
  A. v2's own official runs (S6, B3-B5): v2's official scoring (recordings/experiments/v2/official/, made at
     freeze-v2, SHA-256 pinned below) vs v3's re-scoring (`... --label official --of v2` -> v3/official-v2runs/);
  B. v1's official runs and test week: v2's re-scoring (v2/official-v1runs/, pinned) vs v3's
     (`... --of v1` -> v3/official-v1runs/).
(v2's own laptop week is scored by v2 after 2026-11-21; it is not part of this comparison.)

    python tools/compare_v2_v3.py        # writes docs/results/v3/v2-vs-v3.md
Exit 0 = nothing lost; 1 = something LOST; 2 = NOT COMPARED. Run ids, scenario ids, rule ids, counts only.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compare_v1_v2 as C  # noqa: E402

PROJECT_ROOT = os.path.dirname(HERE)
EXP = os.path.join(PROJECT_ROOT, "recordings", "experiments")
OUT = os.path.join(PROJECT_ROOT, "docs", "results", "v3", "v2-vs-v3.md")
# v2's official JSON as made at freeze-v2 (2026-11-14), pinned before freeze-v3 (v3 prereg section 3)
V2_SHA256 = {
    ("official", "detection"): "4139089b19aa312260210bb1248fc47044027eac9491b12889c76db5bc55fbc8",
    ("official", "blind-detection"): "59408380ee8cc8de3b081ca8044a8efbbc7120874eccc0dcd205d88f9e4a939e",
    ("official", "story"): "5ff544e2a555c06ebc675f6ed4acec2a8de93415297af30d40f2d683bc598cb4",
    ("official", "blind-story"): "25e0d6a409998b4393ecdb68397958ac77aab460aae9eb801a528f3ccff0cb98",
    ("official-v1runs", "detection"): "ed5f0c5a86d9b3dc934cfdca7b27bf539c4c56f92752408ddc221c0abcbb7790",
    ("official-v1runs", "blind-detection"): "08a40ac47230ee936a67b293a75e6ddc61f31d2ed3404ecc99edfbf7ec5e9623",
    ("official-v1runs", "story"): "872faf6c732035e93c3cf51dd5125d4351ee0beb631d64464a97eee13175359e",
    ("official-v1runs", "blind-story"): "78b10e9ac89ab5f0e83045ac10101a4aee251448a8a5af4609343bfdcc58b373",
    ("official-v1runs", "false-alerts"): "91c5bef1fa9cddb61bdb4618a234481e313e2a743d988eca9f6f172c1bd3598d",
}
PARTS = {"A": ("official", "official-v2runs", "v2", ("detection", "blind-detection", "story", "blind-story")),
         "B": ("official-v1runs", "official-v1runs", "v1", ("detection", "blind-detection", "story", "blind-story", "false-alerts"))}


def problems(exp, docs, check_hashes=True):
    out = []
    for part, (old_dir, new_dir, of, names) in PARTS.items():
        for n in names:
            if docs[part]["old"][n] is None:
                out.append(f"{part}: v2 {old_dir}/{n}.json is missing")
            elif check_hashes and C.sha256(os.path.join(exp, "v2", old_dir, f"{n}.json")) != V2_SHA256[(old_dir, n)]:
                out.append(f"{part}: v2 {old_dir}/{n}.json is not the file made at freeze-v2 (SHA-256 differs)")
            d = docs[part]["new"][n]
            if d is None:
                out.append(f"{part}: v3 {new_dir}/{n}.json is missing (run `experiments.py "
                           f"{'blind' if n.startswith('blind') else n} --label official --of {of}`)")
            elif check_hashes and not ((d.get("code") or {}).get("frozen") and d.get("of") == of):
                out.append(f"{part}: v3 {new_dir}/{n}.json was not made by the frozen v3 code over {of}'s runs")
        if "false-alerts" in names and docs[part]["old"]["false-alerts"] and docs[part]["new"]["false-alerts"]:
            keys = ("from_day_utc", "cutoff_day_utc", "events")
            a, b = docs[part]["old"]["false-alerts"]["snapshot"], docs[part]["new"]["false-alerts"]["snapshot"]
            if {k: a.get(k) for k in keys} != {k: b.get(k) for k in keys}:
                out.append(f"{part}: the two false-alert scorings did not cover the same snapshot")
    return out


def lost_steps(old, new):
    """Blind runs: suspicious steps v2 FLAGGED that v3 does not ([(scenario, run id, step)]). A run can stay
    MISSED -> MISSED while losing a flagged step, which the run verdict alone would hide (review 2026-11-14)."""
    a, b = C.runs_by_id(old), C.runs_by_id(new)
    out = []
    for rid, r1 in a.items():
        r2 = b.get(rid)
        if r2 is None:
            continue                                # a missing run is already LOST by compare_detection
        before = set((r1.get("steps") or {}).get("flagged") or [])
        after = set((r2.get("steps") or {}).get("flagged") or [])
        out += [(r1["scenario"], rid, s) for s in sorted(before - after)]
    return out


def section(title, rows_extra, story=False):
    rows, extra = rows_extra
    if story:
        return [f"### {title}", "",
                f"{len(rows)} runs; expected facts found v2 {sum(r['facts_v1'] for r in rows)}, v3 {sum(r['facts_v2'] or 0 for r in rows)}; "
                f"correct expected hypotheses v2 {sum(r['hyps_v1'] for r in rows)}, v3 {sum(r['hyps_v2'] or 0 for r in rows)}; "
                f"checker PASS v2 {sum(bool(r['pass_v1']) for r in rows)}, v3 {sum(bool(r['pass_v2']) for r in rows)}; "
                f"LOST {sum(r['kind'] != 'same' for r in rows)}.", ""] + \
            [f"- LOST: {r['scenario']} {r['run_id']} (PASS {r['pass_v1']} -> {r['pass_v2']}, facts {r['facts_v1']} -> {r['facts_v2']}, "
             f"hypotheses lost: {'; '.join(r['lost_hypotheses']) or '-'})" for r in rows if r["kind"] != "same"] + [""]
    return [f"### {title}", "",
            f"{len(rows)} runs; same {sum(r['kind'] == 'same' for r in rows)}, LOST {sum(r['kind'] == 'LOST' for r in rows)}, "
            f"gained {sum(r['kind'] == 'gained' for r in rows)}, missing in v3 {sum(r['kind'] == 'MISSING IN V2' for r in rows)}"
            + (f"; runs only in v3: {len(extra)}" if extra else "") + "; other alerts summed: v2 "
            f"{sum(r['other_v1'] or 0 for r in rows)}, v3 {sum(r['other_v2'] or 0 for r in rows)}.", ""] + \
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
    ap = argparse.ArgumentParser(description="v2 vs v3 on the same official data (aggregate JSON only)")
    ap.add_argument("--experiments", default=EXP)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    docs = {part: {"old": {n: C.load(os.path.join(a.experiments, "v2", old_dir), n) for n in names},
                   "new": {n: C.load(os.path.join(a.experiments, "v3", new_dir), n) for n in names}}
            for part, (old_dir, new_dir, of, names) in PARTS.items()}
    bad = problems(a.experiments, docs, check_hashes)
    if bad:
        for p in bad:
            print(f"  FAIL  {p}")
        print("NOT COMPARED: nothing written")
        return 2
    L = ["# v2 vs v3 on the same official data (regression)", "",
         "*Made by `python tools/compare_v2_v3.py`: v2's official JSON (freeze-v2, SHA-256 pinned) vs the same runs re-scored "
         "by v3's frozen code. Rules of `tools/compare_v1_v2.py`; pre-registered in `docs/plans/v3-prereg.md` section 3. "
         "B1-B5 are SEEN for v3 (its rules were designed after them).*", ""]
    lost = 0
    for part, label in (("A", "A. v2's own official runs (S6, B3-B5)"), ("B", "B. v1's official runs and test week")):
        old, new = docs[part]["old"], docs[part]["new"]
        L += [f"## {label}", ""]
        for n, story in (("detection", False), ("blind-detection", False), ("story", True), ("blind-story", True)):
            rows = (C.compare_story if story else C.compare_detection)(old[n], new[n])
            L += section(n, rows, story)
            lost += sum((r["kind"] != "same") if story else (r["kind"] in ("LOST", "MISSING IN V2")) for r in rows[0])
            if n == "blind-detection":
                steps = lost_steps(old[n], new[n])
                L += [f"Flagged suspicious steps lost (v2 flagged, v3 not): {len(steps)}"] + \
                     [f"- LOST step: {sc} {rid} step {s}" for sc, rid, s in steps] + [""]
                lost += len(steps)
        if "false-alerts" in old:
            fa = C.compare_false_alerts(old["false-alerts"], new["false-alerts"])
            L += ["### false alerts", "", f"Raised per active hour: v2 {fa['v1']['per_active_hour']:.2f} ({fa['v1']['alerts']}), "
                  f"v3 {fa['v2']['per_active_hour']:.2f} ({fa['v2']['alerts']})."]
            L += [f"- {v['source']} {v['level']} {v['title']}: v2 {v['v1']}, v3 {v['v2']}" for v in fa["changed"]] or ["- no rule changed"]
            L.append("")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")
    print(f"written: {a.out}; LOST items: {lost}")
    return 1 if lost else 0


if __name__ == "__main__":
    sys.exit(main())
