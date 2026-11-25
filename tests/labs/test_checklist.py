"""Lab "Investigation checklist" (engine/labs/checklist.py): every answer comes from the story's own lines, or says
plainly that it can't be known / nothing is recorded, never "clean". Fixtures only."""

import json

from fastapi.testclient import TestClient

from engine.labs import checklist

A, B, C, X = "proc:vm:{AAAA}", "proc:vm:{BBBB}", "proc:vm:{CCCC}", "proc:vm:{XXXX}"
CONTENT = {
    "facts": [
        {"kind": "started", "u": X, "v": A, "sentence": "x.exe started a.exe"},
        {"kind": "started", "u": A, "v": B, "sentence": "a.exe started b.exe"},
        {"kind": "created", "u": B, "v": "file:vm:c:\\t\\drop.exe", "sentence": "b.exe created drop.exe"},
        {"kind": "created", "u": C, "v": "file:vm:c:\\t\\other.txt", "sentence": "c.exe created other.txt"},  # not "it"
        {"kind": "connected_to", "u": A, "v": "net:vm:10.0.2.2:8770", "sentence": "a.exe connected to 10.0.2.2:8770"},
    ],
    "hypotheses": [{"kind": "name_for_connection", "u": "dns:vm:example.invalid", "v": "net:vm:10.0.2.2:8770",
                    "sentence": "the connection may have been for example.invalid"}],
    "gaps": [{"kind": "content_unknown", "node_id": "file:vm:c:\\t\\drop.exe", "plain": "drop.exe: its content is unknown"}],
}
START = {"event_id": 1, "Image": r"C:\t\a.exe", "User": r"VM\analyst", "ProcessGuid": "{aaaa}"}


def by_key(out):
    return {q["key"]: q for q in out["questions"]}


def test_every_answer_is_the_storys_own_line_about_it():
    out = checklist.answer(CONTENT, {"{AAAA}"}, START, {"program": "a.exe", "ended": None, "last": "T"}, cfg={})
    q = by_key(out)
    assert set(out["scope"]) == {A, B} and out["own"] == [A]                 # a.exe and what it started; not c.exe
    assert [l["text"] for l in q["who"]["lines"]] == ["x.exe started a.exe"] and q["who"]["status"] == "fact"
    assert [l["text"] for l in q["what"]["lines"]] == ["a.exe started b.exe"]
    assert [l["text"] for l in q["files"]["lines"]] == ["b.exe created drop.exe", "drop.exe: its content is unknown"]
    assert [l["ink"] for l in q["files"]["lines"]] == ["fact", "gap"]
    assert [l["text"] for l in q["network"]["lines"]] == ["a.exe connected to 10.0.2.2:8770",
                                                          "the connection may have been for example.invalid"]
    assert q["user"]["lines"][0]["text"].endswith("VM\\analyst.")
    assert q["running"]["status"] == "gap" and "(T)" in q["running"]["lines"][0]["text"]
    story = {f["sentence"] for f in CONTENT["facts"] + CONTENT["hypotheses"]} | {g["plain"] for g in CONTENT["gaps"]}
    for key in ("who", "what", "files", "network", "persist", "deleted"):
        assert all(l["text"] in story for l in q[key]["lines"]), key


def test_nothing_recorded_says_how_much_is_recorded_never_clean():
    out = checklist.answer(CONTENT, {"{AAAA}"}, START, {"program": "a.exe", "ended": "2026-10-22 10:00:05.000", "last": "T"},
                           cfg={"FileDeleteDetected": {"state": "some", "rules": 22}, "RegistryEvent": {"state": "none", "rules": 0}})
    q = by_key(out)
    assert q["deleted"]["status"] == "none" and "only some file deletions" in q["deleted"]["note"]
    assert q["persist"]["status"] == "none" and "does not record autostart changes" in q["persist"]["note"]
    assert q["running"]["status"] == "fact" and "2026-10-22 10:00:05.000" in q["running"]["lines"][0]["text"]
    text = json.dumps(out).lower() + json.dumps(checklist.WORDS).lower()
    assert "clean" not in text and "safe" not in text


def test_a_missing_parent_is_a_gap_with_its_witness():
    content = {"facts": [], "hypotheses": [], "gaps": [{"kind": "parent_unknown", "node_id": A, "plain": "who started a.exe is unknown"}]}
    q = by_key(checklist.answer(content, {"{AAAA}"}, START, None, cfg={"ProcessCreate": {"state": "all", "rules": 0}}))
    assert q["who"]["status"] == "gap" and q["who"]["witness"]["kind"] == "parent_unknown"
    assert q["running"]["status"] == "none"


def test_through_the_dashboard_the_answers_match_the_report(tmp_path):
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun(),
                              labs_hosts=None))
    r = c.get(f"/api/labs/checklist/{a.alert_id}").json()
    assert r["story"] and len(r["questions"]) == 13 and all(q["status"] for q in r["questions"])
    assert [q["key"] for q in r["questions"]] == ["fired", "what", "who", "user", "around", "files", "network", "persist",
                                                  "deleted", "running", "sure", "unknown", "todo"]
    assert all(q["section"] in ("happened", "far", "sure", "now") for q in r["questions"])
    st = {q["key"]: q["status"] for q in r["questions"]}
    assert st["fired"] == "raised" and st["todo"] in ("listed", "none", "unchecked")      # never stronger than evidence
    report = c.get(f"/api/alerts/{a.alert_id}").json()["report"]                       # the Story screen's own content
    story = {f["sentence"] for f in report["facts"] + report["hypotheses"]} | {g["plain"] for g in report["gaps"]}
    for q in r["questions"]:
        if q["key"] in ("who", "what", "files", "network", "persist", "deleted") and q["status"] != "none":
            assert all(l["text"] in story or q["key"] == "what" for l in q["lines"]), q["key"]
    assert any(q["status"] in ("fact", "hypothesis") for q in r["questions"] if q["key"] in ("files", "network"))
    assert c.get("/api/labs/checklist").json()["alerts"] and c.get("/api/labs/checklist/nope").status_code == 404


def test_a_programs_end_is_found_whatever_the_case_of_its_guid(tmp_path):
    """The store and the graph don't always spell a ProcessGuid in the same case (found by night-tools):
    the end lookup must not miss event 5 because of it."""
    import contextlib
    import sqlite3
    from engine.alerts import Alert
    from engine.store import EventStore
    from tests.test_detect import ev
    start = ev(1, 0, ProcessGuid="{ABCDEF01-0000-0000-0000-000000001000}", Image=r"C:\t\a.exe", host="analystlab-vm")
    end = ev(5, 9, ProcessGuid="{abcdef01-0000-0000-0000-000000001000}", Image=r"C:\t\a.exe", host="analystlab-vm")
    db = str(tmp_path / "e.db")
    s = EventStore(db)
    s.insert([start, end])
    s.close()

    class Ctx:
        @contextlib.contextmanager
        def reading(self):
            con = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)
            try:
                yield con
            finally:
                con.close()

    a = Alert("r", "t", "sigma", "high", "2026-10-22T10:00:00.000Z", "analystlab-vm", "x", (EventStore.dedup_key(start),))
    info = checklist._end_info(Ctx(), a, dict(start["data"], event_id=1))
    assert info["ended"] is not None and info["program"] == "a.exe"


def test_a_created_folder_is_said_as_a_folder_not_a_written_file():
    """Analyst critique 2026-11-24: directory creations ("payload", "s1") were listed as created files."""
    content = {"facts": CONTENT["facts"] + [{"kind": "created", "u": B, "v": "file:vm:c:\\t\\payload", "sentence": "b.exe created payload"}],
               "hypotheses": [], "gaps": []}
    q = by_key(checklist.answer(content, {"{AAAA}"}, START, None, cfg={}, folders={"c:\\t\\payload"}))
    texts = [l["text"] for l in q["files"]["lines"]]
    assert "b.exe created drop.exe" in texts and "b.exe created the folder payload" in texts
    assert "b.exe created payload" not in texts


def test_what_ran_lists_each_program_with_its_command_line_parent_and_children(tmp_path, monkeypatch):
    import functools
    from tests import test_report
    from tests.labs.test_registry import NoRun
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    from engine.dashboard.demo_mode import VM_HOSTS
    monkeypatch.setattr(test_report, "ev", functools.partial(test_report.ev, host=sorted(VM_HOSTS)[0]))
    con, a, _ = test_report.s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun()))
    q = {x["key"]: x for x in c.get(f"/api/labs/checklist/{a.alert_id}").json()["questions"]}
    progs = q["what"]["programs"]
    assert progs and all({"image", "command_line", "parent", "parent_command_line", "children"} <= set(p) for p in progs)
    assert any(p["image"] and p["image"].endswith("fetch.exe") for p in progs)          # the alert's own program is listed
    fetch = next(p for p in progs if p["image"] and p["image"].endswith("fetch.exe"))
    assert fetch["recorded"] and fetch["pid"] == 10


def test_the_test_machinery_is_left_out_of_how_far_and_named_in_who_started_it():
    content = {"facts": CONTENT["facts"] + [{"id": "e-flush", "kind": "connected_to", "u": A, "v": "net:vm:10.0.2.2:8770",
                                             "sentence": "a.exe connected to 10.0.2.2:8770"}],
               "hypotheses": [], "gaps": []}
    content["facts"][0] = dict(content["facts"][0], id="e-parent")
    q = by_key(checklist.answer(content, {"{AAAA}"}, START, None, cfg={},
                                harness={"e-flush": "the test machine reporting back to the laptop", "e-parent": "the test launcher"}))
    texts = [l["text"] for l in q["network"]["lines"]]
    assert "a.exe connected to 10.0.2.2:8770" in texts                 # the alert's own connection (fixture fact) stays
    assert q["network"]["harness_hidden"] == 1                          # the flush is left out, and counted
    assert "test launcher" in q["who"]["lines"][0]["text"]             # the parent is named as machinery, not hidden
