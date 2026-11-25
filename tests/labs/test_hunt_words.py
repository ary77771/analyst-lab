"""No overclaiming word in anything the night-hunt labs send to the page (the dashboard's own rule:
tests/test_dashboard_frontend.py and tests/test_dashboard_words_scan.py; the wider front-end list)."""

import json

import pytest
import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import _huntdb as db, gaps, hunts, network, persistence, rarity
from tests.labs import hunt_fixtures as fx

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    """No dashboard context left by another test decides which machines these tests see."""
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


def test_no_lab_endpoint_sends_an_overclaiming_word(tmp_path, monkeypatch):
    fx.use_store(monkeypatch, fx.build(tmp_path / "e.db"))
    app = FastAPI()
    for m in (hunts, rarity, persistence, network, gaps):
        app.include_router(m.router)
    c = TestClient(app)
    paths = ["/api/labs/hunts/", "/api/labs/hunts/summary?window=all", "/api/labs/persistence/?window=all&show_unchanged=true",
             "/api/labs/network/?window=24h", "/api/labs/gaps/?window=all", "/api/labs/gaps/?window=1h"]
    paths += [f"/api/labs/hunts/run/{h['id']}?window=all" for h in hunts.HUNTS]
    paths += [f"/api/labs/rarity/?kind={k}&window={w}" for k in rarity.KINDS for w in ("24h", "all")]
    hits = {}
    for p in paths:
        r = c.get(p)
        assert r.status_code == 200, p
        found = BANNED.findall(json.dumps(r.json(), ensure_ascii=False))
        if found:
            hits[p] = found
    # words that exist only in code paths the fixture does not reach
    from engine.labs import noise, reading, sweep
    for words in (gaps.KINDS.values(), [persistence.NOT_SEEN], [[gaps._holes_note([{"count": 2}] * 150)]],
                  [noise.WORDS], [reading.WORDS], [sweep.WORDS]):
        for w in words:
            assert not BANNED.findall(json.dumps(w)), w
    assert not hits, hits


def test_the_scan_can_fail():
    assert BANNED.findall("records were most likely written") and BANNED.findall("a malicious program")
