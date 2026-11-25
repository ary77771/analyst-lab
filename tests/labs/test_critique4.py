"""VISION's critique-4 (2026-11-24): on the live store the alert's own programs included VirtualBox's helper started
by the test launcher. The checklist leaves the lab's own test machinery out of "What ran?" and its count."""

from engine.labs import checklist

A, B, H = "proc:vm:{A}", "proc:vm:{B}", "proc:vm:{H}"
CONTENT = {"facts": [
    {"id": "f1", "kind": "started", "u": A, "v": B, "sentence": "a.exe started b.exe", "citations": []},
    {"id": "f2", "kind": "started", "u": A, "v": H, "sentence": "a.exe started VBoxControl.exe", "citations": []}],
    "hypotheses": [], "gaps": []}


def what(out):
    return next(q for q in out["questions"] if q["key"] == "what")


def test_the_test_machinery_is_not_what_ran_and_not_counted():
    plain = what(checklist.answer(CONTENT, {"{A}"}))
    assert [l["text"] for l in plain["lines"]] == ["a.exe started b.exe", "a.exe started VBoxControl.exe"]
    out = checklist.answer(CONTENT, {"{A}"}, machinery_nodes={H})
    q = what(out)
    assert [l["text"] for l in q["lines"]] == ["a.exe started b.exe"]
    assert "(2 in all)" in q["note"]                       # a.exe and b.exe; VBoxControl not counted
    assert H in out["scope"]                               # still there, behind "show the test machinery"


def test_the_switch_words_are_there():
    assert "{n}" in checklist.WORDS["programs_hidden"] and checklist.WORDS["harness_switch"]
