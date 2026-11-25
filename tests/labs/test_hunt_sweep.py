"""Indicator sweep (engine/labs/sweep.py) on the hand-made store plus a few fingerprints and name lookups."""

import json
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import sweep, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx

SHA = "ab" * 32
FILE_SHA = "cd" * 32


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    path = fx.build(tmp_path / "events.db")
    b = fx.Builder()
    b.rid = 5000
    t = fx.T_END - timedelta(hours=2, minutes=50)
    b.sysmon(1, t, ProcessGuid=fx.guid(70), Image="C:\\Users\\analyst\\Downloads\\dropper.exe", ParentProcessGuid=fx.guid(1),
             ParentImage="C:\\Windows\\explorer.exe", Hashes=f"SHA256={SHA.upper()}", CommandLine="dropper.exe")
    b.sysmon(22, t + timedelta(seconds=2), ProcessGuid=fx.guid(70), Image="C:\\Users\\analyst\\Downloads\\dropper.exe",
             QueryName="update.example-bad.net", QueryStatus="0")
    b.agent("FILE_HASH", t + timedelta(seconds=3), TargetFilename="C:\\Users\\analyst\\Downloads\\stage2.dll",
            hash_status="ok", sha256=FILE_SHA, ProcessGuid=fx.guid(70))
    s = EventStore(path)
    s.insert(b.records)
    s.close()
    fx.use_store(monkeypatch, path)                  # as a running dashboard hands it over
    return path


def run(store, text, window="all"):
    con = db.connect(store)
    try:
        return sweep.sweep(con, text, db.window(con, window))
    finally:
        con.close()


def verdicts(out):
    return {r["raw"]: r["verdict"] for r in out["rows"]}


def test_classify():
    c = sweep.classify
    assert c("d41d8cd98f00b204e9800998ecf8427e") == ("md5", "d41d8cd98f00b204e9800998ecf8427e")
    assert c("A" * 40)[0] == "sha1" and c(SHA.upper()) == ("sha256", SHA)
    assert c("10[.]0[.]2[.]2") == ("ip", "10.0.2.2") and c("[2001:db8::1]") == ("ip", "2001:db8::1")
    assert c("hxxps://update[.]example-bad[.]net/a/b") == ("domain", "update.example-bad.net")
    assert c("evil.com") == ("domain", "evil.com") and c("Evil.EXE") == ("file", "evil.exe")
    assert c("C:/Users/x/evil.exe") == ("file", "c:\\users\\x\\evil.exe")
    assert c("HKEY_CURRENT_USER\\Software\\X") == ("registry", "hkcu\\software\\x")
    assert c("# a comment")[0] is None and c("hello world")[0] is None


def test_every_kind_seen_or_not(store):
    text = "\n".join([SHA, FILE_SHA, "10[.]0[.]2[.]2", "update.example-bad.net", "evil.exe", fx.EVIL,
                      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "never-ran.exe",
                      "203.0.113.9", "198.51.100.7", "not an indicator at all"])
    out = run(store, text)
    v = verdicts(out)
    assert v[SHA] == "seen" and v[FILE_SHA] == "seen"                     # Sysmon's Hashes + the agent's fingerprint
    assert v["10[.]0[.]2[.]2"] == "seen" and v["update.example-bad.net"] == "seen"
    assert v["evil.exe"] == "seen" and v[fx.EVIL] == "seen"
    assert v["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"] == "seen"   # recorded as HKU\<SID>\...
    assert v["never-ran.exe"] == "not_seen" and v["198.51.100.7"] == "not_seen"
    assert v["203.0.113.9"] == "not_seen"                                  # only on the other machine: never shown
    ip = next(r for r in out["rows"] if r["value"] == "10.0.2.2")
    assert ip["count"] == 12 and ip["programs"][0] == {"program": fx.EVIL, "count": 12} and ip["hosts"] == [fx.HOST]
    assert ip["pivot"] == {"kind": "ip", "value": "10.0.2.2"}
    # a bare name or an HKCU key pivots on the value AS RECORDED (full path, HKU\<SID>\...)
    by_raw = {r["raw"]: r for r in out["rows"]}
    assert by_raw["evil.exe"]["pivot"] == {"kind": "file", "value": fx.EVIL}
    assert by_raw["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"]["pivot"]["value"] == fx.RUN_KEY
    assert out["skipped_total"] == 1 and out["counts"]["seen"] == 7
    assert [r["verdict"] for r in out["rows"]][:7] == ["seen"] * 7               # seen first


def test_not_seen_that_cannot_be_trusted_is_said(store):
    out = run(store, "d41d8cd98f00b204e9800998ecf8427e\nreport.docx\nHKLM\\SOFTWARE\\SomeVendor\\Settings")
    rows = {r["value"]: r for r in out["rows"]}
    assert all(r["verdict"] == "cant_tell" for r in rows.values())
    assert "SHA256" in rows["d41d8cd98f00b204e9800998ecf8427e"]["why_uncertain"]       # read from the Sysmon config
    assert "only if it ran" in rows["report.docx"]["why_uncertain"]
    assert "autostart" in rows["hklm\\software\\somevendor\\settings"]["why_uncertain"]
    assert out["coverage"]["hashes"] == ["sha256"] and out["coverage"]["config_read"] is True


def test_a_stix_bundle_like_the_case_board_exports(store):
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "file", "id": "file--1", "hashes": {"SHA-256": SHA}},
        {"type": "file", "id": "file--2", "name": "evil.exe", "x_analystlab_path": fx.EVIL},
        {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "10.0.2.2"},
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'update.example-bad.net' OR ipv4-addr:value = '198.51.100.7']"}]}
    out = run(store, json.dumps(bundle))
    v = {r["value"]: r["verdict"] for r in out["rows"]}
    assert v == {SHA: "seen", fx.EVIL.lower(): "seen", "10.0.2.2": "seen", "update.example-bad.net": "seen",
                 "198.51.100.7": "not_seen"}


def test_the_time_window_counts(store):
    assert verdicts(run(store, SHA, window="1h"))[SHA] == "not_seen"        # the start was ~2 h 50 min before the end
    assert verdicts(run(store, SHA, window="6h"))[SHA] == "seen"


def test_duplicates_fold_and_the_list_is_capped(store, monkeypatch):
    monkeypatch.setattr(sweep, "MAX_INDICATORS", 2)
    out = run(store, "10.0.2.2\n10[.]0[.]2[.]2\n1.1.1.1\n8.8.8.8")
    assert len(out["rows"]) == 2 and out["truncated"] is True


def test_api(store):
    app = FastAPI()
    app.include_router(sweep.router)
    c = TestClient(app)
    r = c.post("/api/labs/sweep/", json={"text": "10.0.2.2\nnever-ran.exe", "window": "all"}).json()
    assert r["counts"] == {"seen": 1, "cant_tell": 0, "not_seen": 1} and "lab VM only" in r["scope"]
    assert c.post("/api/labs/sweep/", json={"text": "x", "window": "forever"}).status_code == 400
    assert "internet" in c.get("/api/labs/sweep/").json()["words"]["intro"]
