"""Analyst Lab's reading of its own rules in ATT&CK terms (engine/labs/_own_tags.py): every rule it names exists,
every technique it names exists in MITRE's data, and the pages say it is our reading, never the rule's tag."""

import pytest

from engine import own_rules
from engine.alerts import Alert
from engine.labs import _attack, _own_tags, respond
from tests.labs.test_techniques import RULES, attack  # noqa: F401  (the fixture bundle: T1059 is in it)


def test_every_mapped_rule_exists_and_unmapped_ones_say_why():
    ours = set(own_rules.RULES) | set(own_rules.BASELINE_RULES) | {"beacon"}
    assert set(_own_tags.READING) <= ours
    assert set(_own_tags.UNMAPPED) <= ours and not set(_own_tags.UNMAPPED) & set(_own_tags.READING)
    assert ours == set(_own_tags.READING) | set(_own_tags.UNMAPPED)            # every own rule is decided, one way or the other
    assert all(why for pairs in _own_tags.READING.values() for _, why in pairs)


def test_every_mapped_technique_is_current_in_the_downloaded_attack_release():
    a = _attack.load()
    if a is None:
        pytest.skip("ATT&CK data not on this machine (python -m engine.labs._fetch_attack)")
    for rule, pairs in _own_tags.READING.items():
        for tid, _ in pairs:
            assert a.resolve(tid) == (tid, None), (rule, tid)


def test_a_rules_own_tags_win_and_our_reading_is_marked(attack):  # noqa: F811
    techs, source, reasons = _own_tags.techniques_for_alert(attack, "analystlab.new_shell_parent", [])
    assert (techs, source) == (["T1059"], "reading") and "shell" in reasons["T1059"]
    assert _own_tags.techniques_for_alert(attack, "analystlab.new_shell_parent", ["attack.t1497"])[1] == "tags"
    assert _own_tags.techniques_for_alert(attack, "analystlab.file_churn", []) == ([], None, {})


def test_respond_gives_our_own_rule_its_steps_said_as_our_reading(attack):  # noqa: F811
    a = Alert("analystlab.new_shell_parent", "shell", "analystlab", "medium", "2026-10-22T10:00:00.000Z", "h1", "r", ("k",))
    s = respond.steps(a, attack, None, {r["id"]: r for r in RULES})
    assert [t["id"] for t in s] == ["T1059"] and s[0]["source"] == "reading" and s[0]["reason"]
    tagged = Alert("r-ps", "ps", "sigma", "high", "2026-10-22T10:00:00.000Z", "h1", "r", ("k",))
    assert respond.steps(tagged, attack, None, {r["id"]: r for r in RULES})[0]["source"] == "tags"
