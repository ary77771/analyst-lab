"""Lab: Process tree (engine/labs/tree.py). Fixture rows shaped like Sysmon event 1; the route on a fixture store
with a stand-in report."""

import json
import os
import re
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import labs
from engine.alerts import Alert, AlertStore
from engine.labs import _files
from engine.labs import tree as T
from nighttools_fixtures import store_with

BANNED = re.compile(r"\b(probably|likely|safe|secure|all clear|all good|no threats?|clean|proven|detected|caught|"
                    r"malicious|attack(?:er)?)\b", re.I)
# GUID-shaped like Sysmon's (hex), as the report's node ids are
PS, FETCH, PAY, RUNNER, OTHER, LATE = "{aaaa-0001}", "{aaaa-0002}", "{aaaa-0003}", "{aaaa-0004}", "{aaaa-0005}", "{aaaa-0006}"
SHA = "5277F0EFBFBC90BB27768D3CD1E9F36A84DA43DB5CD6C2F4B92" + "0" * 13


def row(g, parent, image, cmd, t, **kw):
    return {"ProcessGuid": g, "ParentProcessGuid": parent, "Image": image, "CommandLine": cmd, "time": t, "User": "VM\\analyst",
            "ProcessId": 1, "origin": "normal", **kw}


ROWS = [
    row(FETCH, PS, "D:\\s1\\s1_fetch.exe", f'"D:\\s1\\s1_fetch.exe" -server http://10.0.2.2:18765 -sha256 {SHA}', "2026-11-01T10:00:00Z",
        ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentCommandLine='"powershell.exe" -NoProfile -File D:\\run_scenario.ps1 s1'),
    row(PAY, FETCH, "C:\\T\\s1_payload.exe", "C:\\T\\s1_payload.exe", "2026-11-01T10:00:10Z"),
    row(RUNNER, PS, "C:\\Windows\\System32\\VBoxControl.exe", 'VBoxControl.exe --nologo guestproperty set /AnalystLab/Runner "x done"',
        "2026-11-01T10:00:20Z"),
    row(OTHER, "{bbbb-0009}", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "2026-11-01T10:00:05Z"),
    row(LATE, PS, "C:\\Windows\\System32\\whoami.exe", "whoami", "2026-11-01T11:30:00Z"),      # outside the window
]


def test_marks_point_at_addresses_fingerprints_switches_and_encoded_commands():
    cmd = f'"D:\\s1\\s1_fetch.exe" -server http://10.0.2.2:18765 -sha256 {SHA}'
    kinds = [m[2] for m in T.marks(cmd)]
    assert kinds == ["switch", "url", "switch", "hash"]
    assert [m[2] for m in T.marks("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")] == ["encoded"]
    assert [m[2] for m in T.marks("ping 10.0.2.2")] == ["ip"] and T.marks("notepad.exe a.txt") == []


def test_the_tree_goes_up_to_a_parent_not_recorded_and_down_within_the_window():
    t = T.build(ROWS, {FETCH, PAY}, "2026-11-01T10:00:12Z", T.harness_check(object()))
    by = {n["guid"]: n for n in t["nodes"]}
    assert t["roots"] == [PS] and [n["guid"] for n in t["nodes"]] == [PS, FETCH, PAY, RUNNER]
    root = by[PS]
    assert root["recorded"] is False and root["name"] == "powershell.exe" and "run_scenario.ps1" in root["cmd"]
    assert root["harness"] is True and root["ancestor"] is True                   # the lab's launcher, said so
    assert by[FETCH]["own"] and by[FETCH]["depth"] == 1 and by[PAY]["depth"] == 2 and by[FETCH]["children"] == [PAY]
    assert by[RUNNER]["harness"] is True and not by[RUNNER]["own"]                # our runner, dimmed
    assert OTHER not in by and LATE not in by                                     # another tree; too late
    assert t["focus"] == FETCH                                                    # the line with most to read


def test_the_test_machinery_is_the_one_shared_definition():
    from engine.labs import _shared_defs as sd
    assert T.harness_check() is sd.is_harness
    starter = row("{aaaa-0007}", "{bbbb-0001}", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                  "powershell.exe -File C:\\LabRunner\\start_run_cd.ps1", "2026-11-01T09:59:50Z")
    t = T.build([starter, row(FETCH, "{aaaa-0007}", "D:\\s1\\s1_fetch.exe", "s1_fetch.exe", "2026-11-01T10:00:00Z")],
                {FETCH}, "2026-11-01T10:00:00Z", T.harness_check())
    by = {n["guid"]: n for n in t["nodes"]}
    assert by["{aaaa-0007}"]["harness"] is True and by[FETCH]["harness"] is False   # what the starter starts is the test


def test_the_page_opens_on_the_alerts_own_branch_and_folds_the_system_chain():
    # live-machine shape (critique 3 #9): services.exe > svchost.exe > explorer.exe > powershell.exe > s1_fetch.exe >
    # s1_payload.exe, plus a sibling the shell also started and an unrelated program under svchost
    SVC, HOST, EXP, SH, SIB, OTH = "{c0-01}", "{c0-02}", "{c0-03}", "{c0-04}", "{c0-05}", "{c0-06}"
    t = "2026-11-01T10:00:0{}Z"
    rows = [
        row(SVC, "{00000000-0000-0000-0000-000000000000}", "C:\\Windows\\System32\\services.exe", "services.exe", t.format(0)),
        row(HOST, SVC, "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k x", t.format(1)),
        row(EXP, HOST, "C:\\Windows\\explorer.exe", "explorer.exe", t.format(2)),
        row(SH, EXP, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe", t.format(3)),
        row(FETCH, SH, "D:\\s1\\s1_fetch.exe", "s1_fetch.exe -server http://10.0.2.2:18765", t.format(4)),
        row(PAY, FETCH, "C:\\T\\s1_payload.exe", "C:\\T\\s1_payload.exe", t.format(5)),
        row(SIB, SH, "C:\\Windows\\System32\\whoami.exe", "whoami", t.format(6)),
        row(OTH, HOST, "C:\\Windows\\System32\\notepad.exe", "notepad.exe", t.format(7)),
    ]
    tr = T.build(rows, {FETCH}, t.format(5))
    by = {n["guid"]: n for n in tr["nodes"]}
    assert by[SVC]["depth"] == 0 and by[FETCH]["depth"] == 4                      # the full tree is still all there
    assert {g for g, n in by.items() if n["branch"]} == {SH, FETCH, PAY}          # one level up, the alert's own, below
    assert (by[SH]["branch_depth"], by[FETCH]["branch_depth"], by[PAY]["branch_depth"]) == (0, 1, 2)
    assert by[SIB]["branch"] is False and by[OTH]["branch"] is False and by[SVC]["branch_depth"] is None
    assert tr["folded"] == 5                                                      # services, svchost, explorer, whoami, notepad
    # S1 on the replay: the shell's start was not recorded, so it is the root and the branch is the whole own chain
    s1 = T.build(ROWS, {FETCH, PAY}, "2026-11-01T10:00:12Z", T.harness_check())
    sb = {n["guid"]: n for n in s1["nodes"]}
    assert {g for g, n in sb.items() if n["branch"]} == {PS, FETCH, PAY} and s1["folded"] == 1   # the runner is folded
    # the story also names an ANCESTOR (svchost.exe): its other children stay folded, only the own chain shows
    wide = T.build(rows, {HOST, FETCH, PAY}, t.format(5))
    wb = {n["guid"]: n for n in wide["nodes"]}
    # services.exe (one up from svchost), the shell (one up from s1_fetch), the alert's own; never notepad or explorer
    assert {g for g, n in wb.items() if n["branch"]} == {SVC, HOST, SH, FETCH, PAY}
    assert wb[OTH]["branch"] is False and wb[EXP]["branch"] is False and wb[SH]["branch_depth"] == 0
    # no program of the alert's own in the tree: nothing to fold
    none = T.build(rows, {"{ff-ff}"}, t.format(5))
    assert none["folded"] == 0


def test_red_is_for_alerts_only():
    # Fable's visual pass: "look here first", the marks and the first program are pointers, not alerts; File
    # check's rebuild warnings are a caution. None of them may use the alert red.
    root = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard", "src", "labs")
    for rel in (("tree", "tree.css"), ("fileinspect", "fileinspect.css")):
        with open(os.path.join(root, *rel), encoding="utf-8") as f:
            assert "var(--alert)" not in f.read(), rel


def test_a_zero_parent_is_a_root_never_a_process():
    rows = [row(FETCH, "{00000000-0000-0000-0000-000000000000}", "D:\\x.exe", "x.exe", "2026-11-01T10:00:00Z")]
    t = T.build(rows, {FETCH}, "2026-11-01T10:00:00Z")
    assert t["roots"] == [FETCH] and len(t["nodes"]) == 1 and t["nodes"][0]["recorded"] is True


def test_route_takes_an_alert_and_says_when_it_is_not_here(tmp_path):
    db = store_with(str(tmp_path / "events.db"), [{"event_id": 1, "time": r["time"], "data": {k: v for k, v in r.items() if k != "time"}}
                                                  for r in ROWS])
    al = tmp_path / "alerts.db"
    s = AlertStore(str(al))
    s.write([Alert(rule_id="r", title="Fetch, write, run", source="analystlab", level="medium", time="2026-11-01T10:00:12.000Z",
                   host="analystlab-vm", reason="r", evidence=("k",))])
    aid = s.read()[0].alert_id
    s.close()
    report = {"facts": [{"kind": "started", "sentence": "s1_fetch.exe started s1_payload.exe",
                         "u": f"proc:analystlab-vm:{FETCH}", "v": f"proc:analystlab-vm:{PAY}"}]}
    labs.configure(labs.Context(str(db), str(al), recordings=str(tmp_path / "rec"), report=lambda a: report, hosts=("analystlab-vm",),
                                min_level="medium"))
    app = FastAPI()
    app.include_router(T.router)
    c = TestClient(app)
    lst = c.get("/api/labs/tree").json()
    assert [a["id"] for a in lst["alerts"]] == [aid] and lst["tree"] is None
    body = c.get(f"/api/labs/tree?alert={aid}").json()
    assert body["alert"]["title"] == "Fetch, write, run"
    names = [n["name"] for n in body["tree"]["nodes"]]
    assert names[:3] == ["powershell.exe", "s1_fetch.exe", "s1_payload.exe"]
    assert body["first"]["guid"] == FETCH and "a fingerprint (SHA-256)" in body["first"]["why"]
    assert c.get("/api/labs/tree?alert=nope").json() == {"detail": "This alert isn't in this recording."}
    # the same store as a replay that is still playing (a `feed` folder written just now): not there YET, said
    # in a 200 body the page shows while it asks again; once the replay is quiet, the plain "not here" again
    feed = tmp_path / "feed"
    feed.mkdir()
    (feed / "replay.jsonl").write_text("{}\n", encoding="utf-8")
    body = c.get("/api/labs/tree?alert=nope").json()
    assert body["waiting"] == _files.NOT_YET and body["tree"] is None and [a["id"] for a in body["alerts"]] == [aid]
    assert c.get(f"/api/labs/tree?alert={aid}").json()["tree"]["nodes"]          # an alert already there: its tree
    old = time.time() - 2 * _files.REPLAY_FRESH_S
    for p in (feed / "replay.jsonl", db, al):
        os.utime(p, (old, old))
    assert c.get("/api/labs/tree?alert=nope").json() == {"detail": "This alert isn't in this recording."}


def test_only_a_replay_still_playing_counts_as_playing(tmp_path):
    db, al = tmp_path / "events.db", tmp_path / "alerts.db"
    db.write_bytes(b""), al.write_bytes(b"")
    ctx = labs.Context(str(db), str(al))
    assert _files.replay_playing(ctx) is False                                    # live or batch store: no feed folder
    (tmp_path / "feed").mkdir()
    assert _files.replay_playing(ctx) is True                                     # stores written just now
    assert _files.replay_playing(ctx, now=time.time() + 2 * _files.REPLAY_FRESH_S) is False
    assert _files.replay_playing(labs.Context(None, None)) is False


def test_our_words_never_overclaim():
    assert not BANNED.search(json.dumps(T.WORDS)), BANNED.search(json.dumps(T.WORDS))
