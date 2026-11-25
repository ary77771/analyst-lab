"""Replay ONLY the LEARN-half ART tests' time windows through this branch's detectors (v4 work,
docs/plans/v4-prereg.md sections 1-2: the learn half's recordings and per-test results may be
studied; the TEST half's must not be).

For every learn test (parent technique AND GUID in the pinned split's learn lists, as
tools/art_view.py), the VM recording between the test's logged start - 2 s and stop + 30 s is cut
out; nothing outside learn windows is loaded into the store, so no alert can come from a test-half
test. Attribution is the official scorer's (wt/art tools/art_score.py roots_and_trees/attribute).

    python tools/art_learn_replay.py --out <folder>     # writes learn-replay.json (per learn test)

Per test: v3's official verdict (from the sealed JSON, learn rows only), this branch's raised
alerts attributed to the test's process tree, raised alerts in the window that are NOT attributed,
and the recorded process starts of the tree (image names + command lines: lab VM, ART's public
test commands, no personal data). Practice tool: never an official result.
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import art_view  # noqa: E402
from engine import detect, score  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402
from engine.replay import parse_time as _parse_time, read_recordings  # noqa: E402
from engine.store import EventStore  # noqa: E402

BEFORE, AFTER = timedelta(seconds=2), timedelta(seconds=30)


def parse_time(text):
    """None for a missing time (a test stopped at the deadline may log no stop)."""
    return _parse_time(text) if isinstance(text, str) and text.strip() else None


def learn_tests(records, official):
    """{run id: [ART_TEST records]} for the tests whose (run id, GUID) is a LEARN row of the
    official results; every other test (the sealed test half) is dropped here."""
    out = {}
    for r in records:
        if r.get("type") == "ART_TEST" and (r.get("run_id"), str(r.get("guid", "")).lower()) in official:
            out.setdefault(r["run_id"], []).append(dict(r, index=int(r["index"])))
    return out


def run_windows(tests_by_run):
    """{run id: [(start - 2 s, stop + 30 s, host)]} for the learn tests that logged both times."""
    out = {}
    for rid, tests in tests_by_run.items():
        spans = []
        for t in tests:
            lo, hi = parse_time(t.get("start")), parse_time(t.get("stop"))
            if lo and hi:
                spans.append((lo - BEFORE, hi + AFTER, str(t.get("host") or "").lower()))
        out[rid] = spans
    return out


def cut(records, windows):
    """{run id: [records]}: a record is kept only when its time lies inside one of a run's learn
    windows on the same host (first matching run wins, so no record is loaded twice)."""
    out = {rid: [] for rid in windows}
    for r in records:
        t = parse_time(r.get("time"))
        if not t:
            continue
        h = str(r.get("host") or "").lower()
        for rid, sp in windows.items():
            if any(lo <= t <= hi and h == host for lo, hi, host in sp):
                out[rid].append(r)
                break
    return out


def shown(alerts, art_rules):
    """(rule id, level, title, cites ART?, read from a command line? [v4 F7]) per distinct alert rule."""
    return sorted({(x.rule_id, x.level, x.title, x.rule_id in art_rules, (x.details or {}).get("derived_from") or "")
                   for x in alerts})


def summarize(rows, control_rules):
    """Per phase and in all: executed, Q1, Q2 (art-prereg: a test is detected when a raised alert NOT
    from a control rule is attributed to it; Q2 also leaves out rules that cite ART), and how many of
    those detections come ONLY through declared alerts (v4-prereg 5, F7/F8: alerts read from a command
    line, `derived_from`). Rows as written by main()."""
    control = set(control_rules)
    out = {}
    for key in ("1", "2", "all"):
        sel = [r for r in rows if r["has_root"] and (key == "all" or str(r["phase"]) == key)]
        q1 = q2 = q1_dec = q2_dec = 0
        for r in sel:
            al = [a for a in r["attributed"] if a[0] not in control]
            al2 = [a for a in al if not a[3]]
            if al:
                q1 += 1
                q1_dec += all(a[4] for a in al)
            if al2:
                q2 += 1
                q2_dec += all(a[4] for a in al2)
        out[key] = {"executed": len(sel), "q1": q1, "q2": q2, "q1_only_declared": q1_dec, "q2_only_declared": q2_dec}
    return out


def freeze_tag_exists(root=ROOT, tag="freeze-v4") -> bool:
    """The seal (v4-prereg section 2): the TEST half may be replayed only once `freeze-v4` exists."""
    import subprocess
    p = subprocess.run(["git", "-C", root, "tag", "-l", tag], capture_output=True, text=True)
    return p.returncode == 0 and p.stdout.strip() == tag


def test_half_rows(doc, split_path=None):
    """The TEST half's rows of one art_score JSON document (parent technique AND GUID in the split's
    test lists). Only called after freeze-v4 (main refuses before reading anything otherwise)."""
    split_path = split_path or art_view.SPLIT
    art_view.load_split(split_path)                                  # the hash check
    with open(split_path, encoding="utf-8") as f:
        split = json.load(f)
    parents = {str(p).upper() for p in split["parents"]["test"]}
    guids = {str(g).lower() for g in split["tests"]["test"]}
    return [r for r in doc.get("rows") or []
            if art_view.parent(r.get("technique")) in parents and str(r.get("guid") or "").lower() in guids]


def load_scorer(art_root):
    """The official scorer's attribution functions (branch art-harness), imported by path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("art_score_official", os.path.join(art_root, "tools", "art_score.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--recordings", default=os.path.join(ROOT, "recordings"))
    ap.add_argument("--art-root", default=os.path.join(os.path.dirname(ROOT), "art"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--half", choices=["learn", "test"], default="learn",
                    help="test: ONLY after the freeze-v4 tag exists (the seal, v4-prereg section 2); refused before")
    ap.add_argument("--official-dir", help="the art_score output folder whose rows and control rules are used "
                                           "(default recordings/experiments/art/official = v3's official scoring)")
    a = ap.parse_args(argv)
    if a.half == "test" and not freeze_tag_exists():
        print("Refusing: the TEST half stays sealed until the freeze-v4 tag exists (v4-prereg section 2).")
        return 2
    learn, _ = art_view.load_split()
    guids = art_view.learn_guids()
    official, control_rules = {}, set()
    folder = a.official_dir or os.path.join(a.recordings, "experiments", "art", "official")
    for ph in (1, 2):
        p = os.path.join(folder, f"art-phase{ph}.json")
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
        v = art_view.view(doc, learn, guids)
        control_rules |= set(v["control_rules"])
        for r in (v["learn_rows"] if a.half == "learn" else test_half_rows(doc)):
            official[(r["run_id"], r["guid"].lower())] = dict(r, phase=ph)
    S = load_scorer(a.art_root)
    tests_by_run = learn_tests(read_recordings(recording_files(os.path.join(a.recordings, "vmruns")), retag=False),
                               official)
    by_run_records = cut(read_recordings(recording_files(os.path.join(a.recordings, "vm")), retag=True),
                         run_windows(tests_by_run))
    rules, baseline = score.load_rules(), score.load_baseline()
    art_rules = S.cites_art({r.rule_id: r.path for r in rules if getattr(r, "source", "") == "sigma"})   # prereg Q2

    out = []
    for rid, tests in sorted(tests_by_run.items()):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "learn.db")
            st = EventStore(db)
            st.insert(by_run_records[rid])
            st.close()
            con = detect.open_store(db)
            try:
                errors = []
                alerts = score.raised(score.score(con, rules, baseline, errors=errors))
                trees = S.roots_and_trees(con, tests)
                attributed = S.attribute(con, alerts, tests, trees)
                for t in tests:
                    lo, hi = parse_time(t.get("start")), parse_time(t.get("stop"))
                    if not lo or not hi:
                        continue
                    mine = attributed.get(t["index"], [])
                    ids = {id(x) for x in mine}
                    near = [x for x in alerts if id(x) not in ids and parse_time(x.time) and lo <= parse_time(x.time) <= hi + AFTER]
                    tree = trees.get(t["index"], set())
                    starts = []
                    for g, img, cl in con.execute("SELECT ProcessGuid, Image, CommandLine FROM events WHERE event_id = 1 "
                                                  "ORDER BY COALESCE(UtcTime, time)"):
                        if str(g).lower() in tree:
                            starts.append([str(img).rsplit("\\", 1)[-1], str(cl)[:600]])
                    kinds = {}
                    for g, eid in con.execute("SELECT ProcessGuid, event_id FROM events WHERE ProcessGuid IS NOT NULL"):
                        if str(g).lower() in tree:
                            kinds[eid] = kinds.get(eid, 0) + 1
                    o = official[(rid, str(t["guid"]).lower())]
                    out.append({"technique": t["technique"], "guid": t["guid"], "phase": o["phase"], "run_id": rid,
                                "v3_verdict": o["verdict"], "v3_without_art_citing": o["verdict_without_art_citing"],
                                "has_root": t["index"] in trees, "errors": len(errors),
                                "attributed": shown(mine, art_rules), "in_window_not_attributed": shown(near, art_rules),
                                "tree_starts": starts, "tree_events_by_id": kinds})
            finally:
                con.close()
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"{a.half}-replay.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    summary = {"control_rules": sorted(control_rules), "by_phase": summarize(out, control_rules)}
    with open(os.path.join(a.out, f"{a.half}-summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
    print(f"{len(out)} {a.half} tests replayed from {len(tests_by_run)} boots -> {path}")
    for k, s in summary["by_phase"].items():
        print(f"  phase {k}: executed {s['executed']} | Q1 {s['q1']} (only declared {s['q1_only_declared']}) | "
              f"Q2 {s['q2']} (only declared {s['q2_only_declared']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
