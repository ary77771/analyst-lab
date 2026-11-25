"""The lab's own test launcher named as a parent in a story (PROOF 2026-11-24): on S1 the launcher powershell.exe
(run_scenario.ps1) is the recorded parent of s1_fetch. The fact stays; why, checklist and prove say in plain words
that it is the lab's own test launcher, not a user (engine/labs/_explain_common.py: machinery_notes)."""

import contextlib
import sqlite3

from engine.labs import _explain_common as xc
from engine.labs import checklist
from engine.store import EventStore
from tests.test_detect import ev

LAUNCHER = "{AAAAAAAA-0000-0000-0000-000000000001}"
FETCH = "{AAAAAAAA-0000-0000-0000-000000000002}"
USERSHELL = "{AAAAAAAA-0000-0000-0000-000000000003}"
CHILD = "{AAAAAAAA-0000-0000-0000-000000000004}"


def store(tmp_path):
    db = str(tmp_path / "e.db")
    s = EventStore(db)
    s.insert([   # the launcher's own start is NOT recorded (it began before the recording): only its child names it
        ev(1, 0, host="vm", Image=r"C:\t\s1_fetch.exe", ProcessId=2780, ProcessGuid=FETCH, ParentProcessGuid=LAUNCHER,
           ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           ParentCommandLine=r"powershell.exe -File D:\run_scenario.ps1 -Scenario s1", CommandLine="s1_fetch.exe"),
        ev(1, 1, host="vm", Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ProcessId=5,
           ProcessGuid=USERSHELL, CommandLine="powershell.exe -NoProfile", ParentImage=r"C:\Windows\explorer.exe"),
        ev(1, 2, host="vm", Image=r"C:\t\child.exe", ProcessId=6, ProcessGuid=CHILD, ParentProcessGuid=USERSHELL,
           CommandLine="child.exe", ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           ParentCommandLine="powershell.exe -NoProfile")])
    s.close()
    return db


class Ctx:
    def __init__(self, db):
        self.db = db

    @contextlib.contextmanager
    def reading(self):
        con = sqlite3.connect("file:" + self.db.replace("\\", "/") + "?mode=ro", uri=True)
        try:
            yield con
        finally:
            con.close()


def node(g):
    return f"proc:vm:{g.lower()}"          # the graph may spell the GUID in another case


def test_the_launcher_parent_is_named_in_plain_words_and_a_users_shell_is_not(tmp_path):
    ctx = Ctx(store(tmp_path))
    items = [{"id": "f1", "kind": "started", "u": node(LAUNCHER), "v": node(FETCH)},
             {"id": "f2", "kind": "started", "u": node(USERSHELL), "v": node(CHILD)},
             {"id": "g1", "kind": "origin_unknown", "node_id": node(LAUNCHER)},
             {"id": "g2", "kind": "origin_unknown", "node_id": node(USERSHELL)},
             {"id": "f3", "kind": "connected_to", "u": node(LAUNCHER), "v": "net:vm:10.0.2.2:18765"}]
    notes = xc.machinery_notes(ctx, "vm", items)
    assert notes == {"f1": xc.MACHINERY_WORDS["started_by"], "g1": xc.MACHINERY_WORDS["is"]}
    assert "not by a user" in notes["f1"] and "test launcher" in notes["g1"]
    assert xc.machinery_notes(ctx, "other-host", items) == {}            # another machine's records say nothing here


def test_a_store_that_cannot_be_read_gives_no_notes():
    class Broken:
        @contextlib.contextmanager
        def reading(self):
            raise RuntimeError("no store")
            yield
    assert xc.machinery_notes(Broken(), "vm", [{"id": "f1", "kind": "started", "u": node(LAUNCHER)}]) == {}


def test_checklist_who_started_it_keeps_the_fact_and_adds_the_plain_words():
    content = {"facts": [{"id": "f1", "kind": "started", "u": node(LAUNCHER), "v": node(FETCH),
                          "sentence": "powershell.exe (PID 4160) started s1_fetch.exe (PID 2780)", "citations": []}],
               "hypotheses": [], "gaps": []}
    out = checklist.answer(content, {FETCH.upper()}, machinery={"f1": xc.MACHINERY_WORDS["started_by"]})
    who = next(q for q in out["questions"] if q["key"] == "who")
    assert who["status"] == "fact"
    assert who["lines"][0]["text"].startswith("powershell.exe (PID 4160) started s1_fetch.exe (PID 2780): started by")
    plain = checklist.answer(content, {FETCH.upper()})
    assert next(q for q in plain["questions"] if q["key"] == "who")["lines"][0]["text"].endswith("(PID 2780)")
