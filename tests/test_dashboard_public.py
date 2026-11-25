"""The "Two machines (public data)" tab and the shared dashboard words (debate 11).

The tab displays docs/results/linker/{summary,showcase}.json (made once on branch two-machines by
tools/linker_export.py from the scored test.json). These tests check that the API passes them on
without inventing anything: every number comes from the files, no "probably" reaches the page, and
every fact edge keeps evidence from both machines.
"""

import json
import os
import re

import pytest
from fastapi.testclient import TestClient

from engine.dashboard import public, words
from engine.dashboard.app import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINKER = os.path.join(ROOT, "docs", "results", "linker")
BANNED = re.compile(r"\b(probably|likely|safe|all clear|clean bill)\b", re.I)


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))


def load(name):
    with open(os.path.join(LINKER, name), encoding="utf-8") as f:
        return json.load(f)


def test_public_tab_numbers_come_from_the_pooled_result(client):
    pooled = load("summary.json")["pooled"]
    d = client.get("/api/public/two-machines").json()
    vals = [h["value"] for h in d["headline"]]
    guesses = sum(pooled["hypotheses"].values())
    assert vals == [pooled["cross_machine_outgoing"], pooled["facts"], pooled["ambiguous"],
                    pooled["control1_problems"], guesses]
    assert vals[:2] == [208, 197]                                  # the scored result (test.md, 2026-11-14)
    assert str(pooled["control1_facts_checked"]) in d["headline"][3]["label"]


def test_public_tab_never_shows_crosshost_claim_or_probably(client):
    d = client.get("/api/public/two-machines").json()
    assert all("claim" not in e for e in d["edges"])
    shown = json.dumps({k: d[k] for k in ("words", "story", "sentences", "limit", "headline")}) + \
        json.dumps([e["sentence"] for e in d["edges"]])
    assert not BANNED.search(shown), BANNED.search(shown)


def test_public_tab_facts_have_both_machines_and_guesses_stay_guesses(client):
    d = client.get("/api/public/two-machines").json()
    show = load("showcase.json")
    assert len(d["edges"]) == len(show["edges"]) and len(d["nodes"]) == len(show["nodes"])
    for e in d["edges"]:
        assert e["grade"] in ("fact", "hypothesis")
        if e["kind"] == "same_connection":
            assert e["grade"] == "fact" and len({ev["machine"] for ev in e["evidence"]}) == 2
        if e["kind"] == "remote_start":
            assert e["grade"] == "hypothesis" and e["band"] in ("low", "not assessable")


def test_limit_sentence_is_the_honest_limit(client):
    d = client.get("/api/public/two-machines").json()
    assert "'not assessable' or 'low'" in d["limit"]
    assert d["limit"] not in d["sentences"]


def test_the_routine_traffic_sentence_is_kept_apart(client):
    d = client.get("/api/public/two-machines").json()
    show = load("showcase.json")
    assert d["story"] + d["story_others"] == [s for s in show["story"] if not s.startswith("The other ")] + \
        [s for s in show["story"] if s.startswith("The other ")]
    assert len(d["story_others"]) == 1 and "wsmprovhost.exe" in " ".join(d["story"])


def test_words_endpoint_keeps_debate_10_inks(client):
    w = client.get("/api/words").json()
    assert w["inks"]["hypothesis"]["explain"] == "may be true, not proven"
    assert w["bands"] == {"high": "strong link", "medium": "possible link", "low": "weak lead"}
    assert not BANNED.search(json.dumps(w)), BANNED.search(json.dumps(w))


def test_public_words_and_module_words_have_no_banned_claims():
    assert not BANNED.search(json.dumps(public.WORDS)) and not BANNED.search(json.dumps(words.WORDS))
