"""The v4 SEAL on the official v3 ART results (docs/plans/v4-prereg.md section 2).

Until `freeze-v4` exists, v4 work may read the official ART results ONLY through this tool:
  - LEARN-half tests (docs/plans/v4/art-split.json, pinned by SHA-256): every row, as scored;
  - TEST-half tests: totals only (tests, executed, detected, detected without ART-citing rules),
    never a technique, a test GUID or a rule name;
  - a test whose parent technique is in neither half is treated as TEST (sealed: the safe side).
Phase-wide facts that name no test (Q4's control rules, boots) are shown as they are.

    python tools/art_view.py                          # both phases, from recordings/experiments/art/official/
    python tools/art_view.py --phase 1 --out docs/results/v4/art-learn-phase1.md

It reads the scorer's JSON (tools/art_score.py on branch art-harness writes it), never the markdown
tables next to it (those list every test)."""
import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLIT = os.path.join(ROOT, "docs", "plans", "v4", "art-split.json")
SPLIT_SHA256 = "0f395a70b1e52a740347cbce8936878514d081448c4188c3a9c2312f433d7fee"   # v4-prereg section 2


def load_split(path=SPLIT, expect=SPLIT_SHA256):
    with open(path, "rb") as f:
        raw = f.read()
    got = hashlib.sha256(raw).hexdigest()
    if expect and got != expect:
        raise ValueError(f"{os.path.basename(path)} has SHA-256 {got[:12]}..., the pre-registered one is {expect[:12]}...: "
                         "the split changed, so nothing is shown")
    doc = json.loads(raw.decode("utf-8"))
    return set(doc["parents"]["learn"]), set(doc["parents"]["test"])


def learn_guids(path=SPLIT, expect=SPLIT_SHA256):
    """The learn half's test GUIDs (lower case), from the same pinned file."""
    load_split(path, expect)                                       # the hash check
    with open(path, encoding="utf-8") as f:
        return {str(g).lower() for g in json.load(f)["tests"]["learn"]}


def parent(technique):
    return str(technique or "").split(".")[0].upper()


def totals(rows):
    ex = [r for r in rows if r.get("verdict") != "NOT EXECUTED"]
    return {"tests": len(rows), "executed": len(ex),
            "detected": sum(r.get("verdict") == "DETECTED" for r in ex),
            "detected_without_art_citing": sum(r.get("verdict_without_art_citing") == "DETECTED" for r in ex)}


def view(doc, learn, guids=None):
    """{phase-wide facts, learn rows, learn totals, sealed totals} from one art_score JSON document.
    A row is shown only if its parent technique is a LEARN parent and (when `guids` is given) its test
    GUID is in the split's learn list too (review 2026-11-15: a plan/split mismatch shows nothing)."""
    rows = doc.get("rows") or []

    def shown(r):
        return parent(r.get("technique")) in learn and (guids is None or str(r.get("guid") or "").lower() in guids)
    lrn = [r for r in rows if shown(r)]
    sealed = [r for r in rows if not shown(r)]                     # TEST half + anything unknown
    return {"label": doc.get("label"), "phase": doc.get("phase"), "boots": len(doc.get("runs") or []),
            "engine_tag": (doc.get("engine") or {}).get("tag"), "control_rules": doc.get("control_rules") or [],
            "learn_rows": lrn, "learn": totals(lrn), "sealed": totals(sealed)}


def markdown(views):
    pct = lambda a, b: f"{a}/{b} = {100 * a / b:.1f} %" if b else f"{a}/0"   # noqa: E731
    L = ["# Official v3 ART results through the v4 seal", "",
         "*Made by `python tools/art_view.py` (v4-prereg section 2). LEARN-half tests are shown row by row; "
         "TEST-half tests only as totals (no technique, GUID or rule) until `freeze-v4`. Learn-half rows are "
         "SEEN data for v4.*", ""]
    for v in views:
        lt, st = v["learn"], v["sealed"]
        L += [f"## {v['label']} (detectors {v['engine_tag']}, {v['boots']} boots)", "",
              "| half | tests | executed | Q1 detected | Q2 without ART-citing rules |", "|---|---|---|---|---|",
              f"| LEARN | {lt['tests']} | {lt['executed']} | {pct(lt['detected'], lt['executed'])} | "
              f"{pct(lt['detected_without_art_citing'], lt['executed'])} |",
              f"| TEST (sealed) | {st['tests']} | {st['executed']} | {pct(st['detected'], st['executed'])} | "
              f"{pct(st['detected_without_art_citing'], st['executed'])} |", "",
              f"Q4 rules firing on the harness controls (phase-wide): {', '.join(v['control_rules']) or 'none'}.", "",
              "| technique | test GUID | verdict | without ART-citing rules | exit | timeout | rules (level) |",
              "|---|---|---|---|---|---|---|"]
        for r in sorted(v["learn_rows"], key=lambda r: (str(r.get("technique")), str(r.get("guid")))):
            rules = "; ".join(f"{x[0][:36]} ({x[1]})" for x in r.get("rules") or []) or "-"
            L.append(f"| {r['technique']} | {str(r.get('guid'))[:8]} | {r['verdict']} | {r['verdict_without_art_citing']} | "
                     f"{r.get('exit_code')} | {'yes' if r.get('timed_out') else ''} | {rules} |")
        L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Official ART results through the v4 seal")
    ap.add_argument("--phase", type=int, choices=[1, 2], action="append", help="default: both")
    ap.add_argument("--label", default="official")
    ap.add_argument("--recordings", default=os.path.join(ROOT, "recordings"))
    ap.add_argument("--out", help="also write the markdown here")
    a = ap.parse_args(argv)
    if a.out and os.path.basename(a.out).lower().startswith("official-"):
        print("NOT SHOWN: --out must not be (or overwrite) an official results page; choose e.g. docs/results/v4/...")
        return 2
    try:
        learn, _ = load_split()
        guids = learn_guids()
    except (OSError, ValueError, KeyError) as e:
        print(f"NOT SHOWN: {e}")
        return 2
    views = []
    for ph in a.phase or [1, 2]:
        path = os.path.join(a.recordings, "experiments", "art", a.label, f"art-phase{ph}.json")
        if not os.path.exists(path):
            print(f"(no {a.label} phase {ph} results yet: {os.path.relpath(path, ROOT)})")
            continue
        with open(path, encoding="utf-8") as f:
            views.append(view(json.load(f), learn, guids))
    if not views:
        return 1
    text = markdown(views)
    print(text)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
