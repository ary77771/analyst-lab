"""Evil twin: what the screen says equals the committed results, and every claim in the hand-written
"difference" sentence is checked against twin.json (debate 12, VISION on the twin wording)."""

import json

from fastapi.testclient import TestClient

from engine.dashboard import twin as TW
from engine.dashboard.app import create_app


def data():
    with open(TW.TWIN, encoding="utf-8") as f:
        return json.load(f)


def difference_holds(d):
    """The sentence's claims: the innocent story raised nothing and its wipe match has no connection
    in it; the attack raised the cmdkey rule and the wipe rule's 'after connecting out' version."""
    sides = {s["kind"]: s for s in d["sides"]}
    inn, att = sides["innocent"], sides["attack"]
    inn_wipe = [a for a in inn["below_floor"] if a["rule"] == TW.WIPE_RULE]
    att_rules = {a["rule"]: a for a in att["raised"]}
    return (inn["raised"] == [] and inn_wipe and all(TW.CONNECTED_MARK not in a["title"] for a in inn_wipe)
            and TW.CMDKEY_RULE in att_rules and att_rules[TW.CMDKEY_RULE]["level"] == "high"
            and TW.WIPE_RULE in att_rules and TW.CONNECTED_MARK in att_rules[TW.WIPE_RULE]["title"])


def test_twin_matches_the_scored_verdicts(tmp_path):
    d = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"))).get("/api/twin").json()
    sides = {s["kind"]: s for s in d["sides"]}
    assert sides["innocent"]["raised"] == [] and sides["innocent"]["verdicts"]["v4"] == "no false alarm"
    assert sides["attack"]["raised"] and sides["attack"]["verdicts"] == {"v3": "missed", "v4": "right alert raised", "runs": 3}
    assert all(a["level"] in ("informational", "low") for s in d["sides"] for a in s["below_floor"])
    assert all(a.get("plain") for a in sides["attack"]["raised"])


def test_the_difference_sentence_is_true_for_this_data():
    assert difference_holds(data())


def test_the_difference_check_can_fail():
    d = data()
    for s in d["sides"]:
        if s["kind"] == "innocent":
            s["below_floor"][0]["title"] += " " + TW.CONNECTED_MARK      # as if the backup also connected in between
    assert not difference_holds(d)


def test_the_page_attributes_the_stories_to_their_writer():
    assert "Their writer says" in TW.WORDS["intro"] and "not what was sent" in TW.WORDS["difference"]


def test_the_headline_is_built_from_the_counts_and_changes_with_them():
    """The one-sentence point of the pair says only what the data shows: it counts each side's raised alerts."""
    from engine.dashboard import twin as T
    side = lambda kind, n: {"kind": kind, "raised": [{"rule": str(k)} for k in range(n)]}
    assert T.headline([side("innocent", 0), side("attack", 2)]).endswith("raised 2 alerts on the attack and none on the innocent one.")
    assert T.headline([side("innocent", 0), side("attack", 1)]).endswith("raised 1 alert on the attack and none on the innocent one.")
    both = T.headline([side("innocent", 1), side("attack", 2)])
    assert "none on the innocent" not in both and both.endswith("1 on the innocent one, 2 on the attack.")
    assert T.headline([side("innocent", 0), side("attack", 0)]).endswith("0 on the innocent one, 0 on the attack.")
    assert T.headline([side("attack", 2)]) is None                      # not a pair: no sentence
    real = T.view()
    counts = {s["kind"]: len(s["raised"]) for s in real["sides"]}
    assert real["headline"] == T.headline(real["sides"]) and str(counts["attack"]) in real["headline"]

