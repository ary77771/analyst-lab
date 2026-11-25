"""v4 seal (tools/art_view.py): learn-half rows shown, test-half (and unknown) tests only as totals."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import art_view  # noqa: E402


def row(tech, guid, verdict="DETECTED", fair="DETECTED", rules=(("rule-for-" + "x", "medium", "sigma"),)):
    return {"technique": tech, "guid": guid, "run_id": "r1", "verdict": verdict, "verdict_without_art_citing": fair,
            "reported": True, "exit_code": "0", "timed_out": False, "rules": [list(r) for r in rules]}


DOC = {"label": "official phase 1", "phase": 1, "runs": ["r1", "r2"], "engine": {"tag": "freeze-v3"},
       "control_rules": ["analystlab.new_shell_parent"],
       "rows": [row("T1082", "aaaaaaaa-learn-1"),
                row("T1036.003", "bbbbbbbb-learn-2", fair="MISSED"),
                row("T1003.001", "cccccccc-test-1", rules=(("SECRET-TEST-RULE", "high", "sigma"),)),
                row("T1059", "dddddddd-test-2", verdict="MISSED", fair="MISSED", rules=()),
                row("T1003.002", "eeeeeeee-test-3", verdict="NOT EXECUTED", fair="NOT EXECUTED", rules=()),
                row("T9999", "ffffffff-unknown", rules=(("SECRET-UNKNOWN-RULE", "medium", "sigma"),))]}
LEARN = {"T1082", "T1036"}


def test_learn_rows_shown_test_half_only_as_totals():
    v = art_view.view(DOC, LEARN)
    assert [r["guid"] for r in v["learn_rows"]] == ["aaaaaaaa-learn-1", "bbbbbbbb-learn-2"]
    assert v["learn"] == {"tests": 2, "executed": 2, "detected": 2, "detected_without_art_citing": 1}
    assert v["sealed"] == {"tests": 4, "executed": 3, "detected": 2, "detected_without_art_citing": 2}  # unknown sealed
    text = art_view.markdown([v])
    assert "aaaaaaaa" in text and "bbbbbbbb" in text and "rule-for-x" in text
    for secret in ("T1003", "T1059", "T9999", "cccccccc", "dddddddd", "eeeeeeee", "ffffffff",
                   "SECRET-TEST-RULE", "SECRET-UNKNOWN-RULE"):
        assert secret not in text, secret


def test_a_changed_split_shows_nothing(tmp_path):
    p = tmp_path / "split.json"
    p.write_text(json.dumps({"parents": {"learn": ["T1082"], "test": ["T1003"]}}), encoding="utf-8")
    with pytest.raises(ValueError):
        art_view.load_split(str(p))                                # not the pre-registered file
    assert art_view.load_split(str(p), expect=None) == ({"T1082"}, {"T1003"})


def test_the_pinned_split_loads_and_main_writes(tmp_path, capsys):
    learn, test = art_view.load_split()                            # the real, pinned file
    assert learn and test and not (learn & test)
    folder = tmp_path / "experiments" / "art" / "official"
    folder.mkdir(parents=True)
    lg = sorted(art_view.learn_guids())[0]
    doc = dict(DOC, rows=[row(sorted(learn)[0], lg), row(sorted(test)[0], "22222222-t"),
                          row(sorted(learn)[0], "33333333-not-in-the-learn-list")])
    (folder / "art-phase1.json").write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / "view.md"
    assert art_view.main(["--phase", "1", "--recordings", str(tmp_path), "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    for text in (printed, out.read_text(encoding="utf-8")):
        assert lg[:8] in text and "22222222" not in text and "33333333" not in text and sorted(test)[0] not in text


@pytest.mark.parametrize("tech,shown", [("T1082", True), ("t1082", True), ("T1082.001", True), (" T1082", False),
                                        ("T1003.001", False), ("", False), (None, False)])
def test_technique_spellings_never_leak(tech, shown):
    r = row(tech, "aaaaaaaa-x", rules=(("RULE-OF-THIS-ROW", "medium", "sigma"),))
    if tech is None:
        r.pop("technique")
    v = art_view.view(dict(DOC, rows=[r]), LEARN)
    assert (len(v["learn_rows"]) == 1) is shown
    assert ("RULE-OF-THIS-ROW" in art_view.markdown([v])) is shown


def test_a_learn_technique_with_a_guid_outside_the_learn_list_stays_sealed():
    v = art_view.view(dict(DOC, rows=[row("T1082", "AAAAAAAA-LISTED"), row("T1082", "bbbbbbbb-unlisted")]),
                      LEARN, guids={"aaaaaaaa-listed"})
    assert [r["guid"] for r in v["learn_rows"]] == ["AAAAAAAA-LISTED"] and v["sealed"]["tests"] == 1


def test_out_never_overwrites_an_official_page(tmp_path):
    assert art_view.main(["--out", str(tmp_path / "official-phase1.md")]) == 2
    assert not (tmp_path / "official-phase1.md").exists()


def test_the_pinned_hash_is_the_preregistered_one():
    with open(os.path.join(art_view.ROOT, "docs", "plans", "v4-prereg.md"), encoding="utf-8") as f:
        assert art_view.SPLIT_SHA256 in f.read()
