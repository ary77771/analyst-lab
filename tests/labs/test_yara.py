"""Lab: YARA scan (engine/labs/yara.py). A stand-in engine understands a tiny subset of YARA (text strings,
`any of them`), so these tests run without yara-x; a real-engine test runs when yara-x is installed."""

import json
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import yara as Y
from nighttools_fixtures import configure, lab_folder, sha256, store_with, write_pe

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)


class FakeRule:
    def __init__(self, text, origin):
        self.identifier = re.search(r"rule\s+(\w+)", text).group(1)
        self.meta = re.findall(r'(\w+)\s*=\s*"([^"]*)"', text.split("strings:")[0])
        self.strings = re.findall(r'(\$\w+)\s*=\s*"([^"]*)"', text.split("strings:")[-1])
        self.namespace = origin.replace("\\", "/").split("/")[0]


class FakeEngine:
    """add(): fails on any rule containing BROKEN; scan(): text strings, `any of them`."""
    version = "fake"
    mod = object()

    def compiler(self):
        return []

    def add(self, comp, source, origin):
        if "BROKEN" in source:
            raise ValueError("syntax error: BROKEN")
        for part in re.split(r"(?m)^(?=rule\s)", source):
            if part.strip().startswith("rule"):
                comp.append(FakeRule(part, origin))

    def build(self, comp):
        return list(comp)

    def scan(self, rules, data):
        out = []
        for r in rules:
            pats = [{"id": sid, "hits": data.count(s.encode()), "offsets": [data.find(s.encode())], "preview": s}
                    for sid, s in r.strings if s.encode() in data]
            if pats:
                out.append({"rule": r.identifier, "namespace": r.namespace, "tags": [], "meta": dict(r.meta), "patterns": pats})
        return out


RULES_A = '''import "pe"
rule NightTest_Dropper {
  meta:
    description = "Test rule: the fixture's download address"
    author = "fixture author"
    license = "DRL 1.1"
    score = "70"
  strings:
    $a = "http://10.0.2.2:18765/drop"
  condition: any of them
}
rule NightTest_Other {
  meta:
    description = "never in the fixture"
  strings:
    $a = "zzzz-not-there"
  condition: any of them
}
'''
RULES_BROKEN = '''rule Good_One {
  meta:
    description = "kept although its neighbour fails"
    author = "b"
  strings:
    $a = "payload-marker"
  condition: any of them
}
rule Bad_One { BROKEN }
'''


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    root = tmp_path / "yara"
    (root / "set-a").mkdir(parents=True)
    (root / "set-b").mkdir()
    (root / "set-a" / "a.yar").write_text(RULES_A, encoding="utf-8")
    (root / "set-a" / "SOURCE.txt").write_text("url: https://example.invalid/a.zip\nversion: v1\nlicense: DRL 1.1\n", encoding="utf-8")
    (root / "set-b" / "b.yara").write_text(RULES_BROKEN, encoding="utf-8")
    (root / "set-b" / "README.md").write_text("not a rule file", encoding="utf-8")
    monkeypatch.setenv("ANALYSTLAB_YARA_RULES", str(root))
    monkeypatch.setattr(Y, "engine", lambda: FakeEngine())
    Y._cache.update(key=None, rules=None, info=None)
    return root


def client():
    app = FastAPI()
    app.include_router(Y.router)
    return TestClient(app)


def test_split_rules_cuts_at_each_rule_and_keeps_imports():
    header, parts = Y.split_rules(RULES_A)
    assert header == 'import "pe"' and len(parts) == 2 and parts[1].startswith("rule NightTest_Other")
    assert len(Y.split_rules("private rule a { condition: true }\nglobal private rule b { condition: true }")[1]) == 2


def test_a_file_that_fails_is_retried_rule_by_rule(rules_dir):
    rules, info = Y.compile_sets(FakeEngine(), str(rules_dir))
    names = sorted(r.identifier for r in rules)
    assert names == ["Good_One", "NightTest_Dropper", "NightTest_Other"]
    assert info["rules"] == 3 and info["skipped"] == 1 and info["skipped_examples"][0]["rule"] == "Bad_One"
    a = next(s for s in info["sets"] if s["name"] == "set-a")
    assert a["source"]["version"] == "v1" and a["source"]["license"] == "DRL 1.1"


def test_status_says_why_it_cannot_scan(tmp_path, monkeypatch):
    configure(tmp_path, tmp_path / "missing.db")
    lab_folder(tmp_path, monkeypatch)
    monkeypatch.setattr(Y, "engine", lambda: None)
    Y._cache.update(key=None)
    r = client().get("/api/labs/yara")
    assert r.status_code == 200 and r.json()["status"]["state"] == "no_engine"
    assert client().get("/api/labs/yara/scan/x").status_code == 503
    monkeypatch.setattr(Y, "engine", lambda: FakeEngine())
    monkeypatch.setenv("ANALYSTLAB_YARA_RULES", str(tmp_path / "nothing-here"))
    Y._cache.update(key=None)
    assert client().get("/api/labs/yara").json()["status"]["state"] == "no_rules"


def test_scan_one_file_and_every_recorded_file(tmp_path, monkeypatch, rules_dir):
    lab = lab_folder(tmp_path, monkeypatch)
    hit = write_pe(str(lab / "s9_fetch.exe"), sections=[(".text", b"GET http://10.0.2.2:18765/drop HTTP/1.1\x00", 0x60000020)])
    two = write_pe(str(lab / "s9_payload.exe"), sections=[(".text", b"payload-marker\x00", 0x60000020)])
    miss = write_pe(str(lab / "s9_quiet.exe"), sections=[(".text", b"nothing to see\x00", 0x60000020)])
    write_pe(str(lab / "unrelated.exe"), sections=[(".text", b"payload-marker", 0x60000020)])
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_fetch.exe", "Hashes": "SHA256=" + sha256(hit)}},
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_payload.exe", "Hashes": "SHA256=" + sha256(two)}},
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_quiet.exe", "Hashes": "SHA256=" + sha256(miss)}},
    ])
    configure(tmp_path, db)
    c = client()
    st = c.get("/api/labs/yara").json()
    assert st["status"]["state"] == "ready" and st["status"]["rules"] == 3 and st["status"]["skipped"] == 1
    assert len(st["files"]) == 4
    r = c.get(f"/api/labs/yara/scan/{sha256(hit)}").json()
    m = r["matches"]
    assert [x["rule"] for x in m] == ["NightTest_Dropper"]
    assert m[0]["description"].startswith("Test rule") and m[0]["author"] == "fixture author"
    assert m[0]["license"] == "DRL 1.1" and m[0]["set"] == "set-a" and m[0]["patterns"][0]["hits"] == 1
    assert c.get(f"/api/labs/yara/scan/{sha256(miss)}").json()["matches"] == []
    assert c.get("/api/labs/yara/scan/C:%5Cx.exe").status_code == 404
    allr = c.get("/api/labs/yara/scan-all").json()
    assert allr["scanned"] == 3 and allr["matched_files"] == 2              # the lab-only file is not included
    assert {x["file"]["name"] for x in allr["results"] if x["matches"]} == {"s9_fetch.exe", "s9_payload.exe"}
    assert c.get("/api/labs/yara/scan-all?only_recorded=false").json()["scanned"] == 4


def test_rules_are_compiled_once_and_again_when_a_file_changes(rules_dir):
    calls = []

    class Counting(FakeEngine):
        def build(self, comp):
            calls.append(1)
            return super().build(comp)

    eng = Counting()
    Y.loaded(eng=eng)
    Y.loaded(eng=eng)
    assert len(calls) == 1
    p = rules_dir / "set-a" / "a.yar"
    p.write_text(RULES_A + "\n// edited\n", encoding="utf-8")
    os.utime(p, (1, 1))
    Y.loaded(eng=eng)
    assert len(calls) == 2


def test_preview_is_text_when_readable_else_hex():
    assert Y._preview(b"xxhello worldxx", 2, 11) == "hello world"
    assert Y._preview(b"\x00\x01\x02\x03", 0, 4) == "00 01 02 03"


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(Y.WORDS)), BANNED.search(json.dumps(Y.WORDS))


def test_real_yara_x_engine_if_installed(tmp_path):
    yx = pytest.importorskip("yara_x")
    eng = Y.YaraX(yx)
    comp = eng.compiler()
    eng.add(comp, RULES_A, origin="set-a/a.yar")
    with pytest.raises(ValueError):
        eng.add(comp, "rule broken { condition: nope }", origin="x")
    rules = eng.build(comp)
    m = eng.scan(rules, b"..GET http://10.0.2.2:18765/drop ..")
    assert [x["rule"] for x in m] == ["NightTest_Dropper"] and m[0]["meta"]["author"] == "fixture author"
    assert m[0]["patterns"][0]["preview"] == "http://10.0.2.2:18765/drop"


def test_technical_names_have_plain_words():
    """W3-6: every technical name on the page has a one-line plain meaning (served by Python)."""
    from engine.labs import yara as M
    assert sorted(M.WORDS["jargon"]) == sorted(['YARA', 'YARA-X', 'YARA-Forge'])
    assert all(len(v) > 20 and not BANNED.search(v) for v in M.WORDS["jargon"].values())
