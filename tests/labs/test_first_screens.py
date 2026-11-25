"""The e2e review of the professor's path (2026-11-24): plain first screens on night-explain's labs."""

from engine.labs import _explain_common as xc
from engine.labs import checklist, prove, why


def test_the_checklists_top_answers_carry_their_own_status_not_the_dimmed_nothing_ink():
    q = checklist.with_triage([], [{"key": "fired", "status": "raised", "line": "L", "lab": "why"}])[0]
    assert q["lines"][0]["ink"] == "raised" and len(q["note"]) < 100


def test_hidden_machinery_counts_read_right_for_one_line():
    for words in (why.WORDS, prove.WORDS):
        assert words["harness_hidden"].format(n=1).endswith(": 1.")


def test_the_noise_line_never_says_every_alert_is_a_false_alarm():
    assert "counts as a false alarm" not in why.WORDS["noise_normal"] and "No attack ran" in why.WORDS["noise_normal"]


def test_prove_says_what_suspected_means_and_labels_the_other_explanation():
    assert prove.WORDS["intro"].startswith("Suspected means") and prove.WORDS["alternative"]


def test_short_forms_keep_the_start_of_a_fingerprint_and_the_shared_helper_is_the_checklists():
    assert xc.short_sha("A" * 64) == "AAAAAAAA\u2026" and xc.short_sha(None) is None
    assert checklist.short_cmd is xc.short_cmd
