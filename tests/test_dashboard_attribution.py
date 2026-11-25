"""Whose alert is it? (engine/dashboard/attribution.py and its use in the live view)

A warm machine is busy with its own housekeeping. On 2026-11-21 Windows' compatibility telemetry started
two shells 15 s and 22 s after a test's program was started: inside any time window, and not the test's.
The records say whose they are: the launcher starts each test with the run's own id on the command line,
so the test's programs are that program and everything started from it."""

import dataclasses
import sqlite3
from datetime import timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.alerts import AlertStore
from engine.dashboard import attribution as A
from engine.dashboard import live_status as L
from engine.dashboard import warm as WM
from engine.store import EventStore
from tests.test_detect import T0, ev
from tests.test_report import s1_like

RUN_A, RUN_B = "20261121-144321-7de6", "20261121-144604-613e"


def store(tmp_path, extra=()):
    """A made-up warm session: the launcher {L} starts test A's script {RA} (its command line names RUN_A),
    which starts a program {TA} that does things; later test B the same way ({RB}, {TB}). Meanwhile a service
    host {S} starts a telemetry program {C}, which starts a shell {P}: nobody's test."""
    recs = [ev(1, 0, ProcessGuid="{L}", ParentProcessGuid="{00000000-0000-0000-0000-000000000000}", Image=r"C:\w\launcher.exe"),
            ev(1, 10, ProcessGuid="{RA}", ParentProcessGuid="{L}", Image=r"C:\w\script.exe", CommandLine=f"script -Scenario s5 -RunId {RUN_A}"),
            ev(1, 12, ProcessGuid="{TA}", ParentProcessGuid="{RA}", Image=r"C:\t\a.exe"),
            ev(11, 13, ProcessGuid="{TA}", Image=r"C:\t\a.exe", TargetFilename=r"C:\t\note.txt"),
            ev(1, 40, ProcessGuid="{C}", ParentProcessGuid="{S}", Image=r"C:\w\telemetry.exe"),
            ev(1, 45, ProcessGuid="{P}", ParentProcessGuid="{C}", Image=r"C:\w\shell.exe"),
            ev(1, 60, ProcessGuid="{RB}", ParentProcessGuid="{L}", Image=r"C:\w\script.exe", CommandLine=f"script -Scenario s1 -RunId {RUN_B}"),
            ev(1, 62, ProcessGuid="{TB}", ParentProcessGuid="{RB}", Image=r"C:\t\b.exe"),
            ev(3, 63, ProcessGuid="{TB}", Image=r"C:\t\b.exe", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765),
            ev(1, 64, ProcessGuid="{TB2}", ParentProcessGuid="{TB}", Image=r"C:\t\b2.exe"),
            *extra]
    path = str(tmp_path / "e.db")
    st = EventStore(path)
    st.insert(recs)
    st.close()
    return path


def keys_of(path, guid, event_id=None):
    con = sqlite3.connect(path)
    q = "SELECT dedup_key FROM events WHERE ProcessGuid = ?" + (" AND event_id = ?" if event_id else "")
    out = [k for (k,) in con.execute(q, (guid, event_id) if event_id else (guid,))]
    con.close()
    return out


def alert_on(template, name, keys, seconds):
    t = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return dataclasses.replace(template, incident=name, evidence=tuple(keys), time=t)


def template(tmp_path):
    (tmp_path / "x").mkdir()
    con, alert, _ = s1_like(tmp_path / "x")
    con.close()
    return alert


def test_a_runs_tree_is_the_program_that_carries_its_id_and_everything_started_from_it(tmp_path):
    path = store(tmp_path)
    trees = A.Trees(path)
    assert trees.tree(RUN_A) == frozenset({"{RA}", "{TA}"})
    assert trees.tree(RUN_B) == frozenset({"{RB}", "{TB}", "{TB2}"})            # a grandchild too
    assert "{L}" not in trees.tree(RUN_A) and "{P}" not in trees.tree(RUN_A) | trees.tree(RUN_B)
    assert trees.tree("20261121-000000-ffff") is None                           # its first program was never recorded: nothing can be said
    for not_an_id in ("", None, "%", "s5", "20261121-144321-7de6%", "x' OR '1'='1"):
        assert trees.tree(not_an_id) is None                                    # only a real run id is ever looked for
    assert A.Trees(str(tmp_path / "missing.db")).tree(RUN_A) is None


def test_an_alert_is_a_runs_when_a_program_of_its_evidence_is_in_the_runs_tree(tmp_path):
    path = store(tmp_path)
    trees, t = A.Trees(path), template(tmp_path)
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    own_b = alert_on(t, "B's own", keys_of(path, "{TB}", 3) + keys_of(path, "{TB2}"), 63)
    shell = alert_on(t, "the telemetry's shell", keys_of(path, "{P}"), 45)
    assert trees.owns(RUN_A, own_a) is True and trees.owns(RUN_B, own_a) is False
    assert trees.owns(RUN_B, own_b) is True and trees.owns(RUN_A, own_b) is False
    assert trees.owns(RUN_A, shell) is False and trees.owns(RUN_B, shell) is False
    assert trees.owns("20261121-000000-ffff", own_a) is None                    # unknown tree: no answer, never a guess
    nowhere = alert_on(t, "evidence not in this store", ["no-such-key"], 13)
    assert trees.owns(RUN_A, nowhere) is False and trees.programs(nowhere) == frozenset()


def test_an_unknown_parent_never_links_anything_into_a_tree(tmp_path):
    """A zero ParentProcessGuid means "the parent was not recorded": a gap, never a real process. Every program
    whose start was not seen carries it, so if it ever counted as a parent (or as a program) it would gather
    unrelated programs into one family. PROOF's condition for the tree rule."""
    zero, run_c, run_d = "{00000000-0000-0000-0000-000000000000}", "20261121-150000-cccc", "20261121-150500-dddd"
    path = store(tmp_path, extra=[
        ev(1, 5, ProcessGuid="{U1}", ParentProcessGuid=zero, Image=r"C:\w\one.exe"),
        ev(1, 6, ProcessGuid="{U2}", ParentProcessGuid=zero, Image=r"C:\w\two.exe"),
        ev(1, 80, ProcessGuid="{RC}", ParentProcessGuid=zero, Image=r"C:\w\script.exe", CommandLine=f"script -RunId {run_c}"),   # its own parent unknown: still the run's first program
        ev(1, 81, ProcessGuid="{TC}", ParentProcessGuid="{RC}", Image=r"C:\t\c.exe"),
        ev(1, 82, ProcessGuid=zero, ParentProcessGuid="{TC}", Image=r"C:\t\c-child.exe"),                                    # a child whose own id was not recorded
        ev(1, 90, ProcessGuid=zero, ParentProcessGuid="{L}", Image=r"C:\w\script.exe", CommandLine=f"script -RunId {run_d}"),   # a run whose first program has no id
    ])
    trees, t = A.Trees(path), template(tmp_path)
    assert trees.tree(run_c) == frozenset({"{RC}", "{TC}"})           # not the launcher, not {U1} or {U2}, not the zero id
    assert zero not in trees.tree(RUN_A) | trees.tree(RUN_B) | trees.tree(run_c)
    assert trees.tree(run_d) is None                                  # no id for its first program: nothing can be said, so nothing is
    unrelated = alert_on(t, "a program whose parent was not recorded", keys_of(path, "{U1}"), 5)
    idless = alert_on(t, "evidence with no program id", keys_of(path, zero), 82)
    for run in (RUN_A, RUN_B, run_c):
        assert trees.owns(run, unrelated) is False and trees.owns(run, idless) is False
    assert trees.programs(idless) == frozenset()
    for nothing in (zero, "", None, "{0}", "00000000-0000-0000-0000-000000000000"):
        assert A.unknown(nothing)
    assert not A.unknown("{F}") and not A.unknown("{1b2c3d4e-0000-0000-0000-000000000000}")


def test_the_quiet_lines_never_say_the_other_programs_are_harmless():
    """PROOF: "not part of this test" is all that is claimed. Nothing about what those programs are."""
    for key in ("other_programs", "after_test", "before_test"):
        text = L.WORDS[key].lower()
        for word in ("harmless", "safe", "benign", "normal", "innocent", "nothing to worry", "ignore", "false alarm", "fine", "expected", "legitimate"):
            assert word not in text, (key, word)
    assert "not part of this test" in L.WORDS["other_programs"] and "see why" in L.WORDS["other_programs"]


def test_the_tree_grows_with_the_store(tmp_path):
    path = store(tmp_path)
    trees = A.Trees(path)
    assert trees.tree(RUN_A) == frozenset({"{RA}", "{TA}"})
    st = EventStore(path)
    st.insert([ev(1, 14, ProcessGuid="{TA2}", ParentProcessGuid="{TA}", Image=r"C:\t\a2.exe")])
    st.close()
    assert trees.tree(RUN_A) == frozenset({"{RA}", "{TA}", "{TA2}"})


class Run:
    """A warm test as the live view sees it (engine/dashboard/warm.py Current): a progress file, the click's
    time, the run id, and "this machine was already on"."""

    def __init__(self, tmp_path, run_id, started, running_line=True):
        self.log = str(tmp_path / f"run-{run_id}.log")
        with open(self.log, "w", encoding="utf-8") as f:
            f.write(WM.MARKS["building"] + "\n" + WM.MARKS["inserted"] + "\n" + (WM.MARKS["running"] + "\n" if running_line else ""))
        self.started, self.run_id, self.carries_over, self.lock = started, run_id, True, None
        self.clock_margin, self.test_ended_at = WM.WARM_CLOCK_MARGIN_S, None

    def status(self):
        return type("S", (), {"running": True, "scenario": "s1", "started": self.started, "exit_code": None, "log_tail": []})()


def view(tmp_path, path, runner, alerts, now, existing=()):
    """The live view on the store. It looks once at the click (as the warm button makes it do: the alerts
    that `existing` then are history); `alerts` are raised after that."""
    s = AlertStore(str(tmp_path / "a.db"))
    s.write(list(existing))
    s.close()
    clock = type("C", (), {"t": now, "__call__": lambda self: self.t})()
    api = FastAPI()
    api.include_router(L.make_router(path, str(tmp_path / "a.db"), runner, clock=clock, watch_log=False))
    c = TestClient(api)
    c.get("/api/health")
    s = AlertStore(str(tmp_path / "a.db"))
    s.write(alerts)
    s.close()
    return c, clock


def test_the_live_view_gives_a_test_its_own_alerts_and_names_the_others_as_other_programs(tmp_path):
    """The real case: the telemetry's shell is raised AFTER test B's program started and before it ended.
    By the clock it is B's. By the records it is another program's: a quiet line, never B's banner."""
    path, t = store(tmp_path, extra=[ev(1, 70, ProcessGuid="{P2}", ParentProcessGuid="{C}", Image=r"C:\w\shell.exe")]), template(tmp_path)
    base = T0.timestamp()
    own_b = alert_on(t, "B's own", keys_of(path, "{TB}", 3), 63)
    during = alert_on(t, "the telemetry's shell, while B runs", keys_of(path, "{P2}"), 70)
    runner = Run(tmp_path, RUN_B, started=base + 55)
    c, clock = view(tmp_path, path, runner, [own_b, during], now=base + 61)       # the laptop sees "running" at +61
    h = c.get("/api/health").json()
    assert h["view_ids"] == [own_b.alert_id] and h["alerts"] == 1
    assert h["other_alerts"] == {"count": 1, "id": during.alert_id, "text": L.WORDS["other_programs"].format(n=1, s="")}
    assert "not part of this test" in h["other_alerts"]["text"] and h["before_test"] is None and h["after_test"] is None
    # the clock alone would have said otherwise: with the run id unknown, both stand under the test
    runner.run_id = None
    h = c.get("/api/health").json()
    assert sorted(h["view_ids"]) == sorted([own_b.alert_id, during.alert_id]) and h["other_alerts"] is None


def test_a_tests_own_alert_is_its_own_whenever_it_was_raised(tmp_path):
    """An own alert stamped before the laptop saw "running", or after the test's end, is still the test's:
    the tree decides, not the window. And an earlier test's own alert is never this test's."""
    path, t = store(tmp_path), template(tmp_path)
    base = T0.timestamp()
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    own_b_early = alert_on(t, "B's own, stamped before the laptop saw the start", keys_of(path, "{TB}", 3), 63)
    own_b_late = alert_on(t, "B's own, raised by a child after the end", keys_of(path, "{TB2}"), 200)
    runner = Run(tmp_path, RUN_B, started=base + 55)
    runner.test_ended_at = base + 120
    c, clock = view(tmp_path, path, runner, [own_b_early, own_b_late], now=base + 150, existing=[own_a])      # "running" seen 87 s after B's alert
    h = c.get("/api/health").json()
    assert sorted(h["view_ids"]) == sorted([own_b_early.alert_id, own_b_late.alert_id])
    assert own_a.alert_id not in h["view_ids"] and h["after_test"] is None and h["other_alerts"] is None


def test_until_the_tests_first_program_is_recorded_the_clock_rules_stay(tmp_path):
    path, t = store(tmp_path), template(tmp_path)
    base = T0.timestamp()
    shell = alert_on(t, "the telemetry's shell", keys_of(path, "{P}"), 45)
    runner = Run(tmp_path, "20261121-150000-aaaa", started=base + 40, running_line=False)    # clicked; nothing of it recorded yet
    c, clock = view(tmp_path, path, runner, [shell], now=base + 50)
    h = c.get("/api/health").json()
    assert h["view_ids"] == [] and h["before_test"]["count"] == 1 and h["other_alerts"] is None


def test_after_a_take_back_the_view_follows_the_last_test_again_by_its_own_programs(tmp_path):
    """PROOF 2026-11-21: after a restart Watch showed the plain store (5 alerts under one banner). With the
    session's last run id from its notes, the test's own alerts are found again from the records alone."""
    path, t = store(tmp_path), template(tmp_path)
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    own_b = alert_on(t, "B's own", keys_of(path, "{TB}", 3), 63)
    shell = alert_on(t, "the telemetry's shell", keys_of(path, "{P}"), 45)
    s = AlertStore(str(tmp_path / "a.db"))
    s.write([own_a, own_b, shell])
    s.close()
    runs = WM.WarmRuns(str(tmp_path / "rec"), clock=lambda: T0.timestamp() + 500)
    runs.resume({"scenario": "s1", "run_id": RUN_B, "step": "done"}, running=False)      # (notes of before 2026-11-21: no times in them)

    class NoRun:
        log, started, lock = None, None, None

        def status(self):
            return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()

    cur = WM.Current(NoRun(), runs)
    assert cur.run_id == RUN_B and cur.status().running is False and cur.status().exit_code == 0
    clock = type("C", (), {"t": T0.timestamp() + 501, "__call__": lambda self: self.t})()
    api = FastAPI()
    api.include_router(L.make_router(path, str(tmp_path / "a.db"), cur, clock=clock, watch_log=False))
    c = TestClient(api)
    h = c.get("/api/health").json()
    assert h["view_ids"] == [own_b.alert_id] and h["alerts"] == 1                 # not A's, not the telemetry's: B's own
    d = c.get("/api/run/steps").json()
    assert d["scenario"] == "s1" and d["finished"] is True and [x["state"] for x in d["steps"]] == ["done"] * 4 and d["outcome"] == WM.WORDS["run_done"]
    assert h["other_alerts"] is None and d["started"] == T0.timestamp() + 500      # without the click's time: everything else is history
    runs.resume({"scenario": "s1", "run_id": RUN_B}, running=True)                # ...or it was still running at the restart
    d = c.get("/api/run/steps").json()
    assert d["running"] is True and [x["state"] for x in d["steps"]] == ["done", "done", "current", "todo"]
    runs.step(RUN_B, "done")                                                     # it finishes after the restart: every step is checked
    d = c.get("/api/run/steps").json()
    assert d["finished"] is True and [x["state"] for x in d["steps"]] == ["done"] * 4 and d["outcome"] == WM.WORDS["run_done"]


def test_after_a_take_back_the_clock_goes_on_and_other_programs_alerts_keep_their_line(tmp_path):
    """PROOF 2026-11-21, after a take-back: the elapsed clock started again at the restart, and the alerts
    other programs had raised since the test's click were on no line at all. The session's notes keep the
    click's time (and the end's): "already there" is then what is stamped before the click."""
    path, t = store(tmp_path, extra=[ev(1, 70, ProcessGuid="{P2}", ParentProcessGuid="{C}", Image=r"C:\w\shell.exe")]), template(tmp_path)
    base = T0.timestamp()
    own_a = alert_on(t, "A's own", keys_of(path, "{TA}", 11), 13)
    own_b = alert_on(t, "B's own", keys_of(path, "{TB}", 3), 63)
    during = alert_on(t, "the telemetry's shell, while B ran", keys_of(path, "{P2}"), 70)
    s = AlertStore(str(tmp_path / "a.db"))
    s.write([own_a, own_b, during])                                              # all three exist when the dashboard comes back
    s.close()
    runs = WM.WarmRuns(str(tmp_path / "rec"), clock=lambda: base + 500)
    note = {"scenario": "s1", "run_id": RUN_B, "step": "done", "clicked": base + 55, "running_at": base + 61, "finished": base + 120}
    runs.resume(note, running=False)

    class NoRun:
        log, started, lock = None, None, None

        def status(self):
            return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()

    cur = WM.Current(NoRun(), runs)
    clock = type("C", (), {"t": base + 501, "__call__": lambda self: self.t})()
    api = FastAPI()
    api.include_router(L.make_router(path, str(tmp_path / "a.db"), cur, clock=clock, watch_log=False))
    c = TestClient(api)
    h = c.get("/api/health").json()
    assert h["view_ids"] == [own_b.alert_id]                                     # B's own, as before
    assert h["other_alerts"] == {"count": 1, "id": during.alert_id, "text": L.WORDS["other_programs"].format(n=1, s="")}
    assert h["before_test"] is None and h["after_test"] is None                  # A's alert was there before B's click: history, on no line
    d = c.get("/api/run/steps").json()
    assert d["started"] == base + 55 and d["ended"] == base + 120 and d["now"] == base + 501      # 1:05 on the clock, not counting from the restart
    # the run id unknown (nothing can be said by the test's own programs): the clock's rules, from the moment its program was seen running
    runs.run_id = None
    h = c.get("/api/health").json()
    assert sorted(h["view_ids"]) == sorted([own_b.alert_id, during.alert_id]) and h["before_test"] is None
    # a test that never ran, shown again after a restart: not "finished", and the step it never passed is marked
    runs.resume({"scenario": "s4", "run_id": RUN_A, "step": "failed", "not_started": True, "clicked": base + 300, "finished": base + 480}, running=False)
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_not_run"] and [x["state"] for x in d["steps"]] == ["done", "failed", "todo", "todo"] and d["exit_code"] == 1
    # one that failed after it may have started is never shown as done (before 2026-11-21 it was)
    runs.resume({"scenario": "s4", "run_id": RUN_A, "step": "failed", "clicked": base + 300, "finished": base + 480}, running=False)
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_stopped"] and d["finished"] is False
