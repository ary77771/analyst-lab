"""Every word the dashboard's API sends to the screens is scanned for the overclaiming words
(fresh review 2026-11-20, item 14): not only the front-end source, but what Python serves."""

import json
import re

from fastapi.testclient import TestClient

from engine.dashboard.app import create_app

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)
ENDPOINTS = ["/api/words", "/api/public/two-machines", "/api/twin", "/api/coverage", "/api/scoreboard",
             "/api/checks", "/api/health", "/api/mode", "/api/run/steps"]


def scan(text):
    return [m.group(0) for m in BANNED.finditer(text)]


def test_no_endpoint_sends_an_overclaiming_word(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    hits = {}
    for path in ENDPOINTS:
        r = c.get(path)
        assert r.status_code == 200, path
        found = scan(json.dumps(r.json(), ensure_ascii=False))
        if found:
            hits[path] = found
    assert not hits, hits


def test_the_scan_can_fail():
    assert scan(json.dumps({"x": "The machine is safe"})) and scan("probably came from")
