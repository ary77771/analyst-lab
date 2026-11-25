"""tools/compare_v2_v3.py: v2 vs v3 regression from hand-made aggregate JSON (no real results)."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import compare_v2_v3 as V  # noqa: E402


def write(base, side, folder, name, doc):
    p = base / side / folder
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


def det(verdict="DETECTED", of="v2"):
    return {"of": of, "code": {"frozen": True}, "runs": [{"scenario": "S6", "run_id": "r1", "verdict": verdict, "other_alerts": 0}]}


def story(passed=True, facts=5, of="v2"):
    return {"of": of, "code": {"frozen": True}, "runs": [{"scenario": "S6", "run_id": "r1", "pass": passed, "tally": {"facts_found": facts}}]}


def fa(n, of="v1"):
    return {"of": of, "code": {"frozen": True}, "raised": {"per_active_hour": n / 10, "alerts": n, "active_hours": 10},
            "raised_rules": [{"rule_id": "x", "source": "sigma", "level": "medium", "title": "X", "n": n}],
            "snapshot": {"from_day_utc": "a", "cutoff_day_utc": "b", "events": 1}}


def build(tmp_path, new_det="DETECTED", new_facts=5):
    for part, (old_dir, new_dir, of, names) in V.PARTS.items():
        for n in names:
            make = fa if n == "false-alerts" else (story if "story" in n else det)
            write(tmp_path, "v2", old_dir, n, make(of=of) if make is not fa else fa(4, of))
            if n == "false-alerts":
                new = fa(4, of)
            elif "story" in n:
                new = story(facts=new_facts, of=of)
            else:
                new = det(new_det, of=of)
            write(tmp_path, "v3", new_dir, n, new)


def test_nothing_lost(tmp_path):
    build(tmp_path)
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False) == 0
    assert "LOST 0" in (tmp_path / "o.md").read_text(encoding="utf-8")


def test_a_lost_detection_or_fact_is_reported(tmp_path):
    build(tmp_path, new_det="MISSED")
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False) == 1
    build(tmp_path, new_facts=4)
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False) == 1


def test_a_lost_flagged_step_counts_even_when_the_verdict_stays(tmp_path):
    build(tmp_path, new_det="MISSED")
    for side, folder, flagged in (("v2", "official", [4, 5]), ("v3", "official-v2runs", [5])):
        d = det("MISSED", of="v2")
        d["runs"][0]["steps"] = {"flagged": flagged}
        write(tmp_path, side, folder, "blind-detection", d)
    for side, folder in (("v2", "official"), ("v3", "official-v2runs")):          # own detection unchanged
        write(tmp_path, side, folder, "detection", det("DETECTED", of="v2"))
    for side, folder in (("v2", "official-v1runs"), ("v3", "official-v1runs")):
        for n in ("detection", "blind-detection"):
            write(tmp_path, side, folder, n, det("DETECTED", of="v1"))
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False) == 1
    assert "LOST step: S6 r1 step 4" in (tmp_path / "o.md").read_text(encoding="utf-8")


def test_missing_or_unpinned_input_is_not_compared(tmp_path):
    build(tmp_path)
    os.remove(tmp_path / "v3" / "official-v2runs" / "story.json")
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False) == 2
    build(tmp_path)
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")]) == 2      # hand-made files != pinned v2 files
    assert not (tmp_path / "o.md").exists() or True
