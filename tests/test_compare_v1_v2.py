"""tools/compare_v1_v2.py: the v2 regression (v1's official scoring vs the same data re-scored with v2's
code). Hand-made JSON only; nothing here reads recordings/."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import compare_v1_v2 as V  # noqa: E402

FROZEN = {"code": {"frozen": True}, "of": "v1"}
SNAP = {"from_day_utc": "2026-10-23", "cutoff_day_utc": "2026-10-29", "events": 100}


def det_run(rid, verdict, other=0, rules=None, sc="S1"):
    return {"scenario": sc, "run_id": rid, "verdict": verdict, "other_alerts": other, "other_by_rule": rules or {}}


def story_run(rid, facts, claims=(), ok=True, sc="S1"):
    return {"scenario": sc, "run_id": rid, "pass": ok, "tally": {"facts_found": facts},
            "hypotheses": [{"claim": c, "correct": True} for c in claims]}


def fa(n, rules, snap=SNAP):
    return {"snapshot": dict(snap), "raised": {"per_active_hour": n / 10, "alerts": n, "active_hours": 10},
            "raised_rules": [{"source": "sigma", "level": "medium", "title": t, "rule_id": rid, "n": k} for rid, t, k in rules]}


def write_all(tmp_path, v1=None, v2=None):
    base = {"detection": {"runs": [det_run("a", "DETECTED")]}, "blind-detection": {"runs": []},
            "story": {"runs": [story_run("a", 4, ["T1 x"])]}, "blind-story": {"runs": []},
            "false-alerts": fa(50, [("r1", "A", 30)])}
    for side, over in (("v1", v1 or {}), ("v2", v2 or {})):
        folder = tmp_path / side
        folder.mkdir(exist_ok=True)
        for name, doc in {**base, **over}.items():
            if doc is None:
                continue
            doc = dict(doc, **(FROZEN if side == "v2" else {}))
            (folder / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    return ["--v1", str(tmp_path / "v1"), "--v2", str(tmp_path / "v2"), "--out", str(tmp_path / "out.md")]


def test_a_lost_detection_is_reported_and_fails_the_exit_code(tmp_path):
    argv = write_all(tmp_path, v1={"detection": {"runs": [det_run("a", "DETECTED"), det_run("b", "MISSED", sc="S2J"), det_run("c", "DETECTED")]}},
                     v2={"detection": {"runs": [det_run("a", "DETECTED", other=1, rules={"analystlab.lookalike_name[medium]": 1}),
                                                det_run("b", "DETECTED", sc="S2J")]}})
    assert V.main(argv, check_hashes=False) == 1
    text = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "LOST 0, gained 1, missing in v2 1" in text and "analystlab.lookalike_name[medium]" in text
    assert "**LOST: 1 run(s)**" in text


def test_lost_hypotheses_are_compared_by_claim_not_by_count():
    rows, extra = V.compare_story({"runs": [story_run("a", 4, ["T1 p->q"]), story_run("b", 4)]},
                                  {"runs": [story_run("a", 4, ["T1 r->s"]), story_run("b", 4), story_run("z", 1)]})
    assert rows[0]["kind"] == "LOST" and rows[0]["lost_hypotheses"] == ["T1 p->q"] and rows[1]["kind"] == "same" and extra == ["z"]
    assert V.compare_story({"runs": [story_run("a", 4)]}, {"runs": [story_run("a", 3)]})[0][0]["kind"] == "LOST"     # a fact
    assert V.compare_story({"runs": [story_run("a", 4)]}, {"runs": [story_run("a", 4, ok=False)]})[0][0]["kind"] == "LOST"


def test_nothing_lost_exits_zero_and_lists_rule_changes_by_rule_id(tmp_path):
    argv = write_all(tmp_path, v1={"false-alerts": fa(50, [("r1", "Same title", 30), ("r2", "B", 20)])},
                     v2={"false-alerts": fa(53, [("r1", "Same title", 30), ("r2", "B", 20), ("r3", "Same title", 3)])})
    assert V.main(argv, check_hashes=False) == 0
    text = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert "v1 5.00 (50 alerts), v2 5.30 (53 alerts)" in text and "| sigma | medium | Same title | 0 | 3 |" in text
    assert "| sigma | medium | B |" not in text                       # unchanged rules are not listed


def test_missing_or_unfrozen_or_different_inputs_are_not_compared(tmp_path, capsys):
    argv = write_all(tmp_path, v2={"story": None})
    assert V.main(argv, check_hashes=False) == 2 and "v2 story.json is missing" in capsys.readouterr().out
    assert not (tmp_path / "out.md").exists()
    argv = write_all(tmp_path, v2={"false-alerts": fa(50, [("r1", "A", 30)], snap=dict(SNAP, events=99))})
    assert V.main(argv, check_hashes=False) == 2 and "same snapshot" in capsys.readouterr().out
    argv = write_all(tmp_path)
    assert V.main(argv) == 2                                          # hand-made v1 files are not freeze-v1's
    out = capsys.readouterr().out
    assert "not the file made at freeze-v1" in out
    (tmp_path / "v2" / "detection.json").write_text(json.dumps({"runs": [], "code": {"frozen": False}, "of": "v1"}), encoding="utf-8")
    assert V.main(argv) == 2 and "not made by the frozen v2 code" in capsys.readouterr().out


def test_an_unexpected_error_is_not_compared(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(V, "_main", lambda argv=None, check_hashes=True: 1 / 0)
    assert V.main([]) == 2 and "NOT COMPARED" in capsys.readouterr().out