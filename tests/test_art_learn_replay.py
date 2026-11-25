"""tools/art_learn_replay.py: the practice replay may load ONLY the learn half's time windows
(v4 pre-registration, sections 1-2). These tests pin the selection and the output row shape."""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import art_learn_replay as R  # noqa: E402

LEARN = ("run-a", "aaaa-learn")
OFFICIAL = {LEARN: {"verdict": "missed"}, ("run-b", "bbbb-learn"): {"verdict": "detected"}}


def test(run, guid, start, stop, index=1, host="VM1"):
    return {"type": "ART_TEST", "run_id": run, "guid": guid, "index": str(index), "start": start, "stop": stop,
            "host": host}


test.__test__ = False   # a helper, not a pytest test


def ev(time, host="vm1", n=0):
    return {"type": "SYSMON", "time": time, "host": host, "n": n}


def test_only_learn_rows_are_kept():
    recs = [test("run-a", "AAAA-LEARN", "2026-11-10T10:00:00Z", "2026-11-10T10:00:10Z"),
            test("run-a", "cccc-sealed", "2026-11-10T11:00:00Z", "2026-11-10T11:00:10Z", index=2),
            test("run-x", "aaaa-learn", "2026-11-10T12:00:00Z", "2026-11-10T12:00:10Z"),   # same GUID, other run
            {"type": "SYSMON", "run_id": "run-a", "guid": "aaaa-learn", "index": "9"}]
    got = R.learn_tests(recs, OFFICIAL)
    assert list(got) == ["run-a"]
    assert [t["guid"] for t in got["run-a"]] == ["AAAA-LEARN"]
    assert got["run-a"][0]["index"] == 1                     # index becomes a number


def test_windows_are_start_minus_2s_to_stop_plus_30s_and_need_both_times():
    tests = {"run-a": [dict(test(*LEARN, "2026-11-10T10:00:00Z", "2026-11-10T10:00:10Z"), index=1),
                       dict(test(*LEARN, "2026-11-10T10:05:00Z", None), index=2),
                       dict(test(*LEARN, "", "2026-11-10T10:06:00Z"), index=3)]}
    w = R.run_windows(tests)
    assert len(w["run-a"]) == 1
    lo, hi, host = w["run-a"][0]
    assert (hi - lo).total_seconds() == 10 + 2 + 30
    assert lo.second == 58 and host == "vm1"


def test_cut_keeps_only_records_inside_a_window_on_the_same_host():
    tests = {"run-a": [dict(test(*LEARN, "2026-11-10T10:00:00Z", "2026-11-10T10:00:10Z"), index=1)]}
    w = R.run_windows(tests)
    recs = [ev("2026-11-10T09:59:57Z", n=1),           # 3 s before start: out
            ev("2026-11-10T09:59:58Z", n=2),           # exactly start - 2 s: in
            ev("2026-11-10T10:00:40Z", n=3),           # exactly stop + 30 s: in
            ev("2026-11-10T10:00:41Z", n=4),           # out
            ev("2026-11-10T10:00:05Z", host="OTHER", n=5),
            ev("2026-11-10T10:00:05Z", host="VM1", n=6),   # host compared case-insensitively
            ev(None, n=7), ev("", n=8)]
    got = R.cut(recs, w)
    assert [r["n"] for r in got["run-a"]] == [2, 3, 6]


def test_cut_loads_a_record_only_once_when_runs_overlap():
    a = {"run-a": [dict(test(*LEARN, "2026-11-10T10:00:00Z", "2026-11-10T10:00:10Z"), index=1)],
         "run-b": [dict(test("run-b", "bbbb-learn", "2026-11-10T10:00:00Z", "2026-11-10T10:00:10Z"), index=1)]}
    got = R.cut([ev("2026-11-10T10:00:05Z")], R.run_windows(a))
    assert sum(len(v) for v in got.values()) == 1


def test_a_sealed_test_never_opens_a_window():
    recs = [test("run-a", "cccc-sealed", "2026-11-10T11:00:00Z", "2026-11-10T11:00:10Z")]
    w = R.run_windows(R.learn_tests(recs, OFFICIAL))
    assert w == {}
    assert R.cut([ev("2026-11-10T11:00:05Z")], w) == {}


def row(phase, attributed, has_root=True):
    return {"phase": phase, "has_root": has_root, "attributed": attributed}


def test_summary_counts_q1_q2_and_declared_only():
    # (rule id, level, title, cites ART?, derived_from)
    rows = [row(1, [("ctl", "medium", "c", False, "")]),                          # control only: missed
            row(1, [("r1", "high", "a", False, "command_line")]),                  # Q1+Q2, declared only
            row(1, [("r2", "high", "b", True, "command_line"), ("r3", "medium", "x", False, "")]),
            row(2, [("r2", "high", "b", True, "command_line")]),                   # Q1 only (cites ART), declared
            row(2, [], has_root=False),                                            # not executed
            row(2, [])]
    s = R.summarize(rows, {"ctl"})
    assert s["1"] == {"executed": 3, "q1": 2, "q2": 2, "q1_only_declared": 1, "q2_only_declared": 1}
    assert s["2"] == {"executed": 2, "q1": 1, "q2": 0, "q1_only_declared": 1, "q2_only_declared": 0}
    assert s["all"]["q1"] == 3 and s["all"]["q1_only_declared"] == 2


def test_the_test_half_is_refused_without_the_freeze_tag(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(R, "freeze_tag_exists", lambda *a, **k: False)
    code = R.main(["--half", "test", "--out", str(tmp_path / "o"), "--recordings", str(tmp_path / "nothing-here")])
    assert code == 2 and "sealed" in capsys.readouterr().out
    assert not (tmp_path / "o").exists()                                  # nothing read, nothing written


def test_the_freeze_tag_check_looks_for_that_exact_tag(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert R.freeze_tag_exists(str(tmp_path)) is False
    assert R.freeze_tag_exists(str(tmp_path / "not-a-repo")) is False


def test_test_half_rows_select_by_parent_and_guid():
    import json
    import art_view
    split = json.load(open(art_view.SPLIT, encoding="utf-8"))
    t_guid, l_guid = split["tests"]["test"][0], split["tests"]["learn"][0]
    t_parent = sorted(split["parents"]["test"])[0]
    doc = {"rows": [{"technique": t_parent, "guid": t_guid.upper()},          # test half: kept
                    {"technique": t_parent, "guid": l_guid},                  # parent/GUID mismatch: out
                    {"technique": "T0000", "guid": t_guid}]}                  # a control: out
    assert R.test_half_rows(doc) == [doc["rows"][0]]


def test_shown_row_shape():
    a = SimpleNamespace(rule_id="r1", level="high", title="T", details={"derived_from": "command_line"})
    b = SimpleNamespace(rule_id="r2", level="low", title="U", details={})
    c = SimpleNamespace(rule_id="r2", level="low", title="U", details=None)
    assert R.shown([a, b, c, a], {"r1"}) == [("r1", "high", "T", True, "command_line"), ("r2", "low", "U", False, "")]
