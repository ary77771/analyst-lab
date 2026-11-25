"""analysis/compare_art_v3_v4.py: v3 vs v4 per test on hand-made art_score outputs."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
import compare_art_v3_v4 as C  # noqa: E402

LEARN_P, LEARN_G = {"T1000"}, {"aaaa0001"}


def row(tech, guid, q1, q2=None, executed=True):
    v = "NOT EXECUTED" if not executed else ("DETECTED" if q1 else "MISSED")
    w = "NOT EXECUTED" if not executed else ("DETECTED" if (q1 if q2 is None else q2) else "MISSED")
    return {"technique": tech, "guid": guid, "verdict": v, "verdict_without_art_citing": w}


def doc(*rows):
    return {"rows": list(rows)}


def test_gains_and_losses_per_half():
    v3 = doc(row("T1000", "aaaa0001", False), row("T2000.001", "bbbb0001", True), row("T2000.001", "bbbb0002", False),
             row("T3000", "cccc0001", True, q2=True))
    v4 = doc(row("T1000", "aaaa0001", True), row("T2000.001", "bbbb0001", False), row("T2000.001", "bbbb0002", True, q2=False),
             row("T3000", "cccc0001", True, q2=True))
    r = C.compare(v3, v4, LEARN_P, LEARN_G)
    t, l = r["test"], r["learn"]
    assert l["tests"] == 1 and l["q1_gained"] == [("T1000", "aaaa0001")]           # the learn row stays apart
    assert t["tests"] == 3 and t["q1_v3"] == 2 and t["q1_v4"] == 2
    assert t["q1_gained"] == [("T2000.001", "bbbb0002")] and t["q1_lost"] == [("T2000.001", "bbbb0001")]
    assert t["q2_lost"] == [("T2000.001", "bbbb0001")] and t["q2_gained"] == []


def test_a_learn_parent_with_a_guid_outside_the_learn_list_is_test():
    v = doc(row("T1000", "zzzz9999", True))
    r = C.compare(v, v, LEARN_P, LEARN_G)
    assert r["test"]["tests"] == 1 and r["learn"]["tests"] == 0


def test_not_executed_in_either_is_not_compared():
    v3 = doc(row("T2000", "bbbb0001", True))
    v4 = doc(row("T2000", "bbbb0001", False, executed=False))
    t = C.compare(v3, v4, LEARN_P, LEARN_G)["test"]
    assert t["q1_lost"] == [] and t["executed_differs"] == 1 and t["executed_v4"] == 0


def test_different_test_sets_are_refused():
    with pytest.raises(ValueError, match="different tests"):
        C.compare(doc(row("T2000", "b1", True)), doc(row("T2000", "b2", True)), LEARN_P, LEARN_G)


def test_a_duplicate_test_is_refused():
    with pytest.raises(ValueError, match="twice"):
        C.rows_by_test(doc(row("T2000", "b1", True), row("T2000", "B1", False)))


@pytest.mark.parametrize("q2_v3, q2_v4, lost, ok", [(5, 6, 0, True), (5, 5, 0, False), (5, 9, 3, False), (5, 6, 2, True)])
def test_the_preregistered_rule(q2_v3, q2_v4, lost, ok):
    t = {"q2_v3": q2_v3, "q2_v4": q2_v4, "q1_lost": [("T", str(i)) for i in range(lost)], "q2_lost": []}
    assert C.verdict(t)[0] is ok


def test_lost_at_q2_alone_also_counts():
    t = {"q2_v3": 5, "q2_v4": 9, "q1_lost": [], "q2_lost": [("T", "1"), ("T", "2"), ("T", "3")]}
    assert C.verdict(t)[0] is False
