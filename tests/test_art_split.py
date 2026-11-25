import hashlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import art_split as S  # noqa: E402


def mk():
    out = []
    for i, tech in enumerate(["T1059.001", "T1059.003", "T1082", "T1105", "T1036.003", "T1112", "T1112",
                              "T1547.001", "T1547.004", "T1218.011", "T1003", "T1016", "T1007", "T1560.001"]):
        out.append({"phase": 1 + i % 2, "technique": tech, "guid": f"g{i:02d}"})
    return out


def test_every_test_in_exactly_one_half_and_a_parent_never_split():
    tests = mk()
    halves, side = S.split(tests, 7)
    assert set(side) == {t["guid"] for t in tests}
    assert not set(halves["learn"]) & set(halves["test"])
    for p in {S.parent(t["technique"]) for t in tests}:
        assert len({side[t["guid"]] for t in tests if S.parent(t["technique"]) == p}) == 1


def test_seen_techniques_always_learn_and_the_seed_decides_the_rest():
    tests = mk()
    for seed in range(20):
        halves, _ = S.split(tests, seed)
        assert set(S.SEEN_PARENTS) <= set(halves["learn"])
    assert S.split(tests, 1) == S.split(tests, 1)
    assert len({tuple(S.split(tests, s)[0]["test"]) for s in range(20)}) > 1


def test_halves_are_balanced_by_test_count():
    tests = [{"phase": 1, "technique": f"T{1000 + i}", "guid": f"g{i}"} for i in range(40)]
    _, side = S.split(tests, 3, seen=())
    n = sum(1 for s in side.values() if s == "learn")
    assert abs(n - (40 - n)) <= 1


def test_a_list_that_is_not_the_pinned_one_is_refused(tmp_path):
    (tmp_path / "a.csv").write_text("technique,test,guid,name,prereq,input_args\nT1007,1,g1,x,0,{}\n", encoding="utf-8")
    good = hashlib.sha256((tmp_path / "a.csv").read_bytes()).hexdigest()
    assert len(S.read_lists(str(tmp_path), {"a.csv": (1, good)})) == 1
    with pytest.raises(SystemExit):
        S.read_lists(str(tmp_path), {"a.csv": (1, "0" * 64)})
