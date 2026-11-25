"""Lab: File inspector (engine/labs/fileinspect.py + engine/labs/_files.py). Fixtures only."""

import json
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import _files, fileinspect as F
from nighttools_fixtures import build_pe, configure, lab_folder, sha256, store_with, write_pe

# the dashboard's overclaiming words (tests/test_dashboard_frontend.py): our own words never use them
BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)


def no_signature(*a, **k):
    raise OSError("not in tests")


@pytest.fixture(autouse=True)
def _no_powershell(monkeypatch):
    """Tests never start PowerShell: the signature check gets a stand-in."""
    monkeypatch.setattr(F, "signature", lambda path, sha=None, runner=None: {"checked": False, "reason": "test"})
    F._inspect_cache.clear()


def client():
    app = FastAPI()
    app.include_router(F.router)
    return TestClient(app)


# --- pure parts --------------------------------------------------------------------------------------------
def test_imports_are_grouped_by_what_they_make_possible():
    g = {x["key"]: x["functions"] for x in F.group_imports(["CreateRemoteThread", "WriteProcessMemory",
                                                             "InternetOpenW", "RegSetValueExA", "lstrlenW"])}
    assert g["injection"] == ["CreateRemoteThread", "WriteProcessMemory"]
    assert g["network"] == ["InternetOpenW"] and g["autostart"] == ["RegSetValueExA"]
    assert "lstrlenW" not in json.dumps(g)


def test_entropy_bounds():
    assert F.entropy(b"\x00" * 1000) == 0
    assert F.entropy(bytes(range(256)) * 8) == pytest.approx(8.0)


def test_interesting_text_finds_urls_ips_paths_and_registry_keys_and_counts_library_noise():
    found = F.interesting(F.strings_in(
        b"xx http://10.0.2.2:18765/drop.bin yy\x00C:\\Users\\Public\\run.ps1\x00"
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00https://golang.org/doc\x00"
        + "\\\\server\\share\\a.txt".encode("utf-16le") + b"\x00\x00version 1.0.0.0 here"))
    assert found["urls"]["items"] == ["http://10.0.2.2:18765/drop.bin"] and found["urls"]["noise"] == 1
    assert "10.0.2.2:18765" in found["ips"]["items"] and "1.0.0.0" not in found["ips"]["items"]
    assert "C:\\Users\\Public\\run.ps1" in found["paths"]["items"]
    assert "\\\\server\\share\\a.txt" in found["paths"]["items"]
    assert found["registry"]["items"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]


def test_pe_header_imports_sections_and_packing_hint():
    rnd = os.urandom(4096)
    data = build_pe(sections=[(".text", b"\x90" * 2000, 0x60000020), ("UPX1", rnd, 0xE0000040)],
                    imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                             "wininet.dll": ["InternetOpenUrlA"]}, timestamp=0x60000000)
    pe = F.pe_info(data)
    assert pe["pe"] is True and pe["machine"] == "64-bit (x64)" and pe["kind"] == "console program"
    assert pe["built"] == "2021-01-14 08:25:36Z" and pe["built_note"] is None
    assert {d["dll"] for d in pe["dlls"]} == {"kernel32.dll", "wininet.dll"} and pe["import_count"] == 4
    assert [g["key"] for g in pe["groups"]] == ["network", "injection"]
    upx = next(s for s in pe["sections"] if s["name"] == "UPX1")
    assert upx["entropy"] > 7.5 and upx["high"] and upx["executable"]
    assert pe["packer_sections"] == ["UPX1"] and pe["packed_hint"] is True
    text = next(s for s in pe["sections"] if s["name"] == ".text")
    assert text["entropy"] < 1 and not text["high"]


def test_build_time_zero_and_dll_and_not_a_pe():
    pe = F.pe_info(build_pe(timestamp=0, dll=True))
    assert pe["built"] is None and "not set" in pe["built_note"] and pe["kind"].startswith("DLL")
    assert F.pe_info(b"#!/bin/sh\necho hi\n") == {"pe": False}
    assert F.pe_info(b"MZ" + b"\x00" * 10)["pe"] is False          # MZ but broken: said, not raised


def test_go_runtime_imports_are_left_out_of_the_groups():
    data = build_pe(imports={"kernel32.dll": ["SuspendThread", "ResumeThread", "GetThreadContext", "SetThreadContext",
                                              "LoadLibraryExW", "GetProcAddress", "WriteFile"]},
                    extra=b"\xff Go buildinf:\x08\x02")
    pe = F.pe_info(data)
    assert pe["go"] is True and pe["groups"] == [] and pe["go_runtime_left_out"] == 7
    # the same imports in a non-Go program DO show up
    assert [g["key"] for g in F.pe_info(build_pe(imports={"kernel32.dll": ["SetThreadContext"]}))["groups"]] == ["injection"]


def test_summary_is_plain_and_never_overclaims(tmp_path):
    p = write_pe(str(tmp_path / "t.exe"), imports={"ws2_32.dll": ["connect", "send"]},
                 sections=[(".text", b"http://10.0.2.2:18765/x\x00", 0x60000020)])
    info = F.inspect_file(p)
    assert info["sha256"] == sha256(p) and len(info["md5"]) == 32 and info["size"] == os.path.getsize(p)
    s = info["summary"]
    assert "64-bit (x64) console program" in s and "can talk over the network" in s and "1 web address" in s
    assert not BANNED.search(s)
    info["signature"] = {"checked": True, "status": "NotSigned", "valid": False}
    assert F.summary(info).startswith("Not signed;")
    info["signature"] = {"checked": True, "status": "Valid", "valid": True, "type": "Catalog", "signer": "Microsoft Windows"}
    assert F.summary(info).startswith("Signed by Microsoft Windows (catalog signature, valid)")


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(F.WORDS)), BANNED.search(json.dumps(F.WORDS))
    assert not BANNED.search(json.dumps({k: v[:2] for k, v in F.IMPORT_GROUPS.items()}))


def test_the_banned_word_check_can_fail():
    assert BANNED.search("this file is clean") and BANNED.search("Malicious")


def test_signature_path_goes_through_the_environment_never_the_command(monkeypatch):
    monkeypatch.undo()                                   # the real function, with a stand-in for PowerShell
    real = F
    real._sig_cache.clear()
    seen = {}

    class R:
        stdout = json.dumps({"status": "Valid", "type": "Catalog", "signer": "CN=Microsoft Windows, O=Microsoft",
                             "issuer": "CN=Microsoft Windows Production PCA 2011", "timestamped": False, "os_binary": True})

    def run(cmd, **kw):
        seen.update(cmd=cmd, env=kw["env"])
        return R()

    weird = "C:\\x\\a'; Remove-Item C:\\ -Recurse; '.exe"
    out = real.signature(weird, sha="abc", runner=run)
    if os.name == "nt":
        assert out["valid"] and out["signer"] == "Microsoft Windows" and out["type"] == "Catalog"
        assert weird not in " ".join(seen["cmd"]) and seen["env"]["AL_SIG_PATH"] == weird
    else:
        assert out["checked"] is False


# --- linking recorded files to local copies ----------------------------------------------------------------
def test_catalogue_links_by_sha256_and_a_same_name_lookalike_only_as_the_labs_copy(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    real = write_pe(str(lab / "s9_payload.exe"), sections=[(".text", b"payload-v1" * 50, 0x60000020)])
    write_pe(str(lab / "s9_other.exe"), sections=[(".text", b"other" * 50, 0x60000020)])
    look = write_pe(str(lab / "s9_tool.exe"), sections=[(".text", b"tool-v2" * 50, 0x60000020)])
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_payload.exe", "Hashes": "SHA256=" + sha256(real).upper()}},
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_payload.exe", "Hashes": "SHA256=" + sha256(real).upper()}},
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_tool.exe", "Hashes": "SHA256=" + "0" * 64}},   # other content
        {"event_id": 1, "data": {"Image": "C:\\Windows\\System32\\whoami.exe", "Hashes": "SHA256=" + "1" * 64}},
        {"type": "FILE_HASH", "data": {"TargetFilename": "C:\\T\\drop.ps1", "sha256": "2" * 64, "hash_status": "ok"}},
        {"type": "FILE_HASH", "data": {"TargetFilename": "C:\\T\\newdir", "hash_status": "directory"}},
        {"event_id": 11, "data": {"TargetFilename": "C:\\T\\drop.ps1"}},          # covered by its FILE_HASH
        {"event_id": 11, "data": {"TargetFilename": "C:\\T\\notes.txt"}},         # not a program: not listed
    ])
    import sqlite3
    con = sqlite3.connect(db)
    allitems = _files.catalogue(con, machine="laptop-that-is-not-testvm")
    con.close()
    items = {i["name"]: i for i in allitems if i["match"] != "lab"}
    assert items["s9_payload.exe"]["match"] == "sha256" and items["s9_payload.exe"]["inspectable"]
    assert items["s9_payload.exe"]["times"] == 2 and items["s9_payload.exe"]["kinds"] == ["started"]
    # same name, other content: it may be opened, but only ever as the lab's own copy ("name"), never as what ran
    assert items["s9_tool.exe"]["match"] == "name" and items["s9_tool.exe"]["inspectable"]
    assert items["s9_tool.exe"]["local"].endswith("s9_tool.exe") and items["s9_tool.exe"]["sha256"] == "0" * 64
    assert items["whoami.exe"]["match"] is None and not items["whoami.exe"]["inspectable"]
    assert items["drop.ps1"]["kinds"] == ["written"] and items["drop.ps1"]["sha256"] == "2" * 64
    assert "newdir" not in items and "notes.txt" not in items
    # the lab's own file the recording never mentions is listed as a lab file; the lookalike too (its own id)
    labs_ = [i for i in allitems if i["match"] == "lab"]
    # the lookalike's lab copy is not listed a second time as "a lab test file" (critique-2 #17)
    assert {i["name"] for i in labs_} == {"s9_other.exe"} and all(i["inspectable"] for i in labs_)
    assert look and items["s9_tool.exe"]["local"] == look
    assert len({i["id"] for i in allitems}) == len(allitems)          # every item has its own id


def test_only_the_test_machine_is_shown_unless_the_dashboard_allows_every_machine(tmp_path, monkeypatch):
    lab_folder(tmp_path, monkeypatch)
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "data": {"Image": "C:\\T\\vmprog.exe", "Hashes": "SHA256=" + "5" * 64}},
        {"host": "MYLAPTOP", "event_id": 1, "data": {"Image": "C:\\P\\laptopprog.exe", "Hashes": "SHA256=" + "6" * 64}},
        {"host": "MYLAPTOP", "type": "FILE_HASH", "data": {"TargetFilename": "C:\\P\\x.ps1", "sha256": "7" * 64, "hash_status": "ok"}},
    ])
    import sqlite3
    con = sqlite3.connect(db)
    configure(tmp_path, db)                                                   # the dashboard's default: the VM only
    monkeypatch.setenv("ANALYSTLAB_LABS_LAPTOP", "1")                         # an old switch: has no effect any more
    assert [i["name"] for i in _files.catalogue(con, machine="mylaptop")] == ["vmprog.exe"]
    configure(tmp_path, db, hosts=None)                                       # --labs-all-hosts
    assert sorted(i["name"] for i in _files.catalogue(con, machine="mylaptop")) == ["laptopprog.exe", "vmprog.exe", "x.ps1"]
    con.close()


def test_a_laptop_file_still_at_its_place_is_linked_by_path_and_a_changed_one_is_not(tmp_path, monkeypatch):
    lab_folder(tmp_path, monkeypatch)
    configure(tmp_path, tmp_path / "events.db", hosts=None)                  # --labs-all-hosts
    here = write_pe(str(tmp_path / "here.exe"))
    changed = write_pe(str(tmp_path / "changed.exe"))
    db = store_with(str(tmp_path / "events.db"), [
        {"host": "MYLAPTOP", "event_id": 1, "data": {"Image": here, "Hashes": "SHA256=" + sha256(here)}},
        {"host": "MYLAPTOP", "event_id": 1, "data": {"Image": changed, "Hashes": "SHA256=" + "3" * 64}},
    ])
    import sqlite3
    con = sqlite3.connect(db)
    all_ = _files.catalogue(con, machine="mylaptop")
    con.close()
    items = {i["name"]: i for i in all_}
    # listing does not read the files; opening one compares its content with the recording
    assert items["here.exe"]["match"] == "path" and items["changed.exe"]["match"] == "path"
    here = _files.resolve(all_, items["here.exe"]["id"])
    assert here["match"] == "path" and here["inspectable"] and here["sha256"] == sha256(str(tmp_path / "here.exe"))
    changed = _files.resolve(all_, items["changed.exe"]["id"])
    assert changed["match"] == "changed" and not changed["inspectable"] and changed["local"] is None


# --- the routes --------------------------------------------------------------------------------------------
def test_routes_list_and_inspect_by_id_only(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    p = write_pe(str(lab / "s9_payload.exe"), imports={"wininet.dll": ["InternetOpenA"]})
    db = store_with(str(tmp_path / "events.db"), [
        {"event_id": 1, "data": {"Image": "C:\\T\\s9_payload.exe", "Hashes": "SHA256=" + sha256(p)}},
        {"event_id": 1, "data": {"Image": "C:\\T\\gone.exe", "Hashes": "SHA256=" + "4" * 64}},
    ])
    configure(tmp_path, db)
    c = client()
    r = c.get("/api/labs/fileinspect")
    assert r.status_code == 200
    body = r.json()
    assert body["words"]["title"] == "File inspector"
    by = {f["name"]: f for f in body["files"]}
    assert by["s9_payload.exe"]["match"] == "sha256" and by["gone.exe"]["match"] == "none"
    assert "local" not in by["s9_payload.exe"]                      # no local paths go to the page
    r = c.get(f"/api/labs/fileinspect/inspect/{by['s9_payload.exe']['id']}")
    assert r.status_code == 200 and r.json()["info"]["sha256"] == sha256(p)
    assert [g["key"] for g in r.json()["info"]["pe"]["groups"]] == ["network"]
    assert c.get(f"/api/labs/fileinspect/inspect/{by['gone.exe']['id']}").status_code == 409
    assert c.get("/api/labs/fileinspect/inspect/not-an-id").status_code == 404
    # a path is never accepted as an address
    assert c.get("/api/labs/fileinspect/inspect/" + "C:%5CWindows%5Cwin.ini").status_code == 404


def test_lab_folders_include_the_run_cd_and_the_newest_warm_machine_cds(tmp_path, monkeypatch):
    monkeypatch.delenv("ANALYSTLAB_LAB_FILES", raising=False)
    root = tmp_path / "checkout"
    (root / "build" / "run" / "cd" / "s1").mkdir(parents=True)
    for i in range(5):
        (root / "build" / "warm" / f"2026112{i}-000000-aaaa" / "warm" / "cd").mkdir(parents=True)
    (root / "build" / "warm" / "20261124-000000-aaaa" / "20261124-000100-bbbb" / "cd").mkdir(parents=True)
    monkeypatch.setenv("ANALYSTLAB_LAB_ROOTS", str(root))
    # never the blind rounds' folders (a sealed round must not become browsable in Labs)
    assert not any("analystlab-blind" in d.lower() for d in _files.lab_dirs())
    dirs = [os.path.relpath(d, root).replace("\\", "/") for d in _files.lab_dirs() if d.startswith(str(root))]
    assert "build/run/cd" in dirs
    warm = [d for d in dirs if d.startswith("build/warm/")]
    assert {d.split("/")[2] for d in warm} == {"20261124-000000-aaaa", "20261123-000000-aaaa", "20261122-000000-aaaa"}
    assert "build/warm/20261124-000000-aaaa/20261124-000100-bbbb/cd" in warm


def test_lab_file_fingerprints_are_kept_between_starts_and_laptop_paths_are_not(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    p = write_pe(str(lab / "a.exe"))
    outside = write_pe(str(tmp_path / "laptop.exe"))
    _files._hash_cache.clear()
    _files.sha256_of(outside)                              # a laptop file hashed for the "path" link
    _files.local_index([str(lab)])
    saved = json.load(open(_files.CACHE_FILE, encoding="utf-8"))
    assert [os.path.basename(r[0]) for r in saved] == ["a.exe"] and saved[0][3] == sha256(p)
    _files._hash_cache.clear()
    monkeypatch.setitem(_files._disk, "loaded", False)
    _files._load_disk_cache()
    assert list(_files._hash_cache.values()) == [sha256(p)]


def test_works_without_an_event_store(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    write_pe(str(lab / "x.exe"))
    configure(tmp_path, tmp_path / "missing.db")
    r = client().get("/api/labs/fileinspect")
    assert r.status_code == 200 and [f["name"] for f in r.json()["files"]] == ["x.exe"]


def test_the_lab_is_discovered_by_the_registry():
    from engine import labs
    good, bad = labs.discover()
    assert "fileinspect" in [n for n, _ in good]
    assert not [b for b in bad if b["name"] in ("fileinspect", "_files")]


def test_night_tools_css_never_styles_the_shared_screens():
    """Review fix 3: every selector in the night-tools labs' CSS starts with one of their own prefixes, so
    visiting a lab never restyles the rehearsed screens (CSS is global once loaded)."""
    import re as _re
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "dashboard", "src", "labs")
    own = ("ft-", "sd-", "wn-", "rc-", "tr-")
    bad = []
    for lab in ("fileinspect", "yara", "lolbas", "secondopinion", "storydiff", "receipts", "whatsnew", "tree"):
        d = os.path.join(root, lab)
        for name in os.listdir(d) if os.path.isdir(d) else []:
            if not name.endswith(".css"):
                continue
            text = _re.sub(r"/\*.*?\*/", "", open(os.path.join(d, name), encoding="utf-8").read(), flags=_re.S)
            text = _re.sub(r"@media[^{]*\{", "", text)
            for sel in _re.findall(r"([^{}]+)\{", text):
                for one in sel.split(","):
                    one = one.strip()
                    if one and not one.startswith(tuple("." + p for p in own)):
                        bad.append(f"{lab}/{name}: {one}")
    assert not bad, bad


def test_the_signature_is_checked_by_windows_only_when_asked(tmp_path, monkeypatch):
    """Review fix 4: Windows' check may go online (certificate revocation), so it never runs by itself."""
    calls = []
    monkeypatch.setattr(F, "signature", lambda path, sha=None, runner=None: calls.append(path) or
                        {"checked": True, "status": "NotSigned", "valid": False})
    lab = lab_folder(tmp_path, monkeypatch)
    p = write_pe(str(lab / "s9.exe"))
    info = F.inspect_file(p)
    assert calls == [] and info["signature"]["checked"] is False and "may contact the internet" in info["signature"]["reason"]
    assert info["pe"]["embedded_signature"] is False
    assert info["summary"].startswith("No embedded signature (a catalog signature is not checked);")
    db = store_with(str(tmp_path / "events.db"), [{"event_id": 1, "data": {"Image": "C:\\T\\s9.exe", "Hashes": "SHA256=" + sha256(p)}}])
    configure(tmp_path, db)
    c = client()
    assert c.get(f"/api/labs/fileinspect/inspect/{sha256(p)}").json()["info"]["signature"]["checked"] is False and calls == []
    r = c.get(f"/api/labs/fileinspect/inspect/{sha256(p)}?signature=true").json()
    assert r["info"]["signature"]["checked"] is True and len(calls) == 1


def test_a_lookalike_is_inspected_with_the_flag_and_its_own_fingerprint(tmp_path, monkeypatch):
    lab = lab_folder(tmp_path, monkeypatch)
    p = write_pe(str(lab / "s9_tool.exe"), sections=[(".text", b"rebuilt" * 50, 0x60000020)])
    db = store_with(str(tmp_path / "events.db"), [{"event_id": 1, "data": {"Image": "D:\\s9\\s9_tool.exe", "Hashes": "SHA256=" + "0" * 64}}])
    configure(tmp_path, db)
    c = client()
    item = next(f for f in c.get("/api/labs/fileinspect").json()["files"] if f["match"] == "name")
    assert item["match_words"].startswith("Not the file that ran")
    r = c.get(f"/api/labs/fileinspect/inspect/{item['id']}").json()
    assert r["info"]["lookalike"] is True and r["info"]["sha256"] == sha256(p) != "0" * 64

