"""tools/compare_v3_v4.py: v3 vs v4 regression from hand-made aggregate JSON (no real results), plus a check
that the SHA-256 pins match v3's official files on this machine (fingerprints only, never their content)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import compare_v1_v2 as C  # noqa: E402
import compare_v3_v4 as V  # noqa: E402


def write(base, side, folder, name, doc):
    p = base / side / folder
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


def det(verdict="DETECTED", of="v3", flagged=(4, 5)):
    return {"of": of, "code": {"frozen": True}, "runs": [{"scenario": "B10", "run_id": "r1", "verdict": verdict,
                                                          "other_alerts": 0, "steps": {"flagged": list(flagged)}}]}


def story(passed=True, facts=5, of="v3"):
    return {"of": of, "code": {"frozen": True}, "runs": [{"scenario": "B10", "run_id": "r1", "pass": passed, "tally": {"facts_found": facts}}]}


def fa(n, of="v1"):
    return {"of": of, "code": {"frozen": True}, "raised": {"per_active_hour": n / 10, "alerts": n, "active_hours": 10},
            "raised_rules": [{"rule_id": "x", "source": "sigma", "level": "medium", "title": "X", "n": n}],
            "snapshot": {"from_day_utc": "a", "cutoff_day_utc": "b", "events": 1}}


def build(tmp_path, new_det="DETECTED", new_facts=5, new_flagged=(4, 5)):
    for part, (old_dir, new_dir, of, names) in V.PARTS.items():
        for n in names:
            if n == "false-alerts":
                write(tmp_path, "v3", old_dir, n, fa(4, of))
                write(tmp_path, "v4", new_dir, n, fa(4, of))
            elif "story" in n:
                write(tmp_path, "v3", old_dir, n, story(of=of))
                write(tmp_path, "v4", new_dir, n, story(facts=new_facts, of=of))
            else:
                write(tmp_path, "v3", old_dir, n, det(of=of))
                write(tmp_path, "v4", new_dir, n, det(new_det, of=of, flagged=new_flagged))


def run(tmp_path):
    return V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=False)


def test_nothing_lost(tmp_path):
    build(tmp_path)
    assert run(tmp_path) == 0
    text = (tmp_path / "o.md").read_text(encoding="utf-8")
    assert "v3 vs v4" in text and "LOST 0" in text and "SEEN for v4" in text


def test_losses_are_reported(tmp_path):
    build(tmp_path, new_det="MISSED")
    assert run(tmp_path) == 1
    build(tmp_path, new_facts=4)
    assert run(tmp_path) == 1
    build(tmp_path, new_flagged=(5,))                          # verdict kept, a flagged step lost
    assert run(tmp_path) == 1
    assert "LOST step: B10 r1 step 4" in (tmp_path / "o.md").read_text(encoding="utf-8")


def test_missing_or_unfrozen_documents_are_not_compared(tmp_path):
    build(tmp_path)
    os.remove(tmp_path / "v4" / "official-v3runs" / "blind-detection.json")
    assert run(tmp_path) == 2
    build(tmp_path)
    write(tmp_path, "v4", "official-v3runs", "blind-detection", dict(det(), code={"frozen": False}))
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=True) == 2


def test_a_changed_v3_file_is_not_compared(tmp_path, capsys):
    """Hand-made v3 files never match the pins: with the pin check on, nothing is compared."""
    build(tmp_path)
    assert V.main(["--experiments", str(tmp_path), "--out", str(tmp_path / "o.md")], check_hashes=True) == 2
    assert "is not the pinned file" in capsys.readouterr().out and not (tmp_path / "o.md").exists()


def test_the_pins_match_v3s_files_on_this_machine():
    exp = os.path.join(ROOT, "recordings", "experiments", "v3")
    if not os.path.isdir(exp):
        pytest.skip("no recordings on this machine")
    for (folder, name), digest in V.OLD_SHA256.items():
        assert C.sha256(os.path.join(exp, folder, f"{name}.json")) == digest, (folder, name)
    assert {(f, n) for f, _, _, names in V.PARTS.values() for n in names} == set(V.OLD_SHA256)
