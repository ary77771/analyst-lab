"""The warm test machine on the dashboard (engine/dashboard/warm.py): the buttons' rules, the words, and
that the live view follows a warm test. A made-up VirtualBox throughout (tests/test_warm_vm.py's)."""

import json
import os
import re
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from engine.dashboard import live_status as L
from engine.dashboard import warm as WM
from engine.dashboard.app import Runner, create_app
from tests.test_warm_vm import Machine, session

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)   # tests/test_dashboard_words_scan.py


@pytest.fixture(autouse=True)
def no_real_programs(monkeypatch):
    """No test here may start a program: not VBoxManage, not run_in_vm, not PowerShell."""
    started = []

    def trap(*args, **kwargs):
        started.append(args[0] if args else kwargs.get("args"))
        raise AssertionError(f"a test tried to start a real program: {started[-1]!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    monkeypatch.setattr(os, "system", trap)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    from engine.dashboard import checks
    monkeypatch.setattr(checks, "vm_running", lambda *a, **k: False)
    monkeypatch.setattr(checks.Checks, "count_once", lambda self: None)
    yield started


class OneBoot:
    """Stands in for the one-boot Runner: it only remembers whether it was asked to start."""

    def __init__(self, running=False):
        self.running, self.asked, self.log, self.started, self.scenario = running, [], None, None, None

    def start(self, scenario):
        self.asked.append(scenario)

    def status(self):
        return type("S", (), {"running": self.running, "scenario": self.scenario, "started": self.started, "exit_code": None, "log_tail": []})()


def app(tmp_path, mode="live", machine=None, runner=None, **kw):
    w, m, clock = session(tmp_path, machine, **kw)
    w.watch = lambda *a, **k: None      # no background shutdown racing a test; the watcher has its own test below
    runner = runner or OneBoot()
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=runner,
                              mode=mode, warm=w, clock=clock))
    return c, w, m, clock, runner


def until(c, cond, limit=10):
    t = time.time()
    while time.time() - t < limit:
        s = c.get("/api/warm").json()
        if cond(s):
            return s
        time.sleep(0.05)
    raise AssertionError(f"never happened; last: {json.dumps(s)[:300]}")


def test_a_dashboard_without_a_warm_machine_says_so_and_refuses_every_action(tmp_path):
    for mode in ("replay", None):
        c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode=mode))
        assert c.get("/api/warm").json()["enabled"] is False
        for path in ("/api/warm/start", "/api/warm/run/s1", "/api/warm/stop"):
            assert c.post(path).status_code == 409
    c, w, m, _, _ = app(tmp_path, mode="replay")                    # a session handed to a replay is still not offered
    assert c.get("/api/warm").json()["enabled"] is False and c.post("/api/warm/start").status_code == 409 and m.calls == []


def test_start_then_one_click_per_test_then_shut_down(tmp_path):
    c, w, m, clock, _ = app(tmp_path)
    s = c.get("/api/warm").json()
    assert s["enabled"] and s["state"] == "off" and s["can_start"] and not s["can_stop"] and s["practice"] is True
    assert [t["id"] for t in s["tests"]] == ["s1", "s4", "s5"] and not any(t["can_run"] for t in s["tests"])
    assert c.post("/api/warm/start").status_code == 200
    s = until(c, lambda x: x["state"] == "ready")
    assert s["text"] == WM.WORDS["states"]["ready"] and all(t["can_run"] for t in s["tests"]) and s["can_stop"] and not s["can_start"]
    assert s["ready_text"] == WM.WORDS["ready_until"].format(time=time.strftime("%H:%M", time.localtime(clock.t + 600)), minutes=10)
    assert "warning" not in s
    assert c.post("/api/warm/run/s1").status_code == 200
    s = until(c, lambda x: x["state"] == "ready" and x["used"] == ["s1"])
    by = {t["id"]: t for t in s["tests"]}
    assert by["s1"]["used"] and not by["s1"]["can_run"] and by["s4"]["can_run"]
    assert c.post("/api/warm/run/s1").status_code == 409 and "already ran" in c.post("/api/warm/run/s1").json()["detail"]
    assert c.post("/api/warm/run/s2").status_code == 409
    assert c.post("/api/warm/stop").status_code == 200
    s = until(c, lambda x: x["state"] == "off")
    assert s["ended_text"] == WM.WORDS["ended"]["asked"] and m.state_now == "poweroff"


def test_the_last_minutes_are_said_plainly_and_the_machine_shuts_down_by_itself(tmp_path):
    c, w, m, clock, _ = app(tmp_path, machine=Machine(left=170))
    c.post("/api/warm/start")
    s = until(c, lambda x: x["state"] == "ready")
    assert s["warning"] == WM.WORDS["last_minutes"].format(minutes=3)
    clock.t += 171
    s = c.get("/api/warm").json()
    assert s["warning"] == WM.WORDS["time_up"] and not any(t["can_run"] for t in s["tests"])
    assert w.due()
    w.stop("time is up")                                             # what the watcher thread does within seconds
    s = c.get("/api/warm").json()
    assert s["state"] == "off" and s["ended_text"] == WM.WORDS["ended"]["time is up"] and "shutdown" in m.calls


def test_a_one_boot_run_and_the_warm_machine_refuse_each_other(tmp_path):
    c, w, m, _, runner = app(tmp_path, runner=OneBoot(running=True))
    r = c.post("/api/warm/start")
    assert r.status_code == 409 and r.json()["detail"] == WM.WORDS["other_run"] and m.calls == []
    assert c.get("/api/warm").json()["can_start"] is False
    runner.running = False
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    for path in ("/api/scenarios/s1/run", "/api/run/three"):
        r = c.post(path)
        assert r.status_code == 409 and "warm test machine is in use" in r.json()["detail"]
    assert runner.asked == []                                        # the one-boot run was never started
    c.post("/api/warm/stop")
    until(c, lambda x: x["state"] == "off")
    assert c.post("/api/run/three").status_code == 200 and runner.asked == [["s1", "s4", "s5"]]


def test_the_live_view_follows_a_warm_test_with_its_own_steps_and_words(tmp_path):
    c, w, m, clock, _ = app(tmp_path)
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    before = c.get("/api/run/steps").json()
    assert before["scenario"] is None and [s["text"] for s in before["steps"]] == [t for _, t in L.STEPS]    # no test yet: the one-boot words
    c.post("/api/warm/run/s4")
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4"])
    d = c.get("/api/run/steps").json()
    assert d["scenario"] == "s4" and d["running"] is False and d["finished"] is True and d["exit_code"] == 0
    assert [s["text"] for s in d["steps"]] == WM.WORDS["run_steps"] and all(s["state"] == "done" for s in d["steps"])
    assert d["outcome"] == WM.WORDS["run_done"] and d["ended"] is not None and d["started"] is not None


def test_a_warm_test_the_launcher_refused_ends_as_not_finished(tmp_path):
    c, w, m, _, _ = app(tmp_path, machine=Machine(refuse="too little time left (100 s; a test may need 435 s)"))
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    c.post("/api/warm/run/s1")
    s = until(c, lambda x: x["state"] == "ready" and x.get("error"))
    assert "refused too little time left" in s["error"]
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_stopped"] and d["finished"] is False and d["exit_code"] == 1


def test_a_cd_the_machine_never_noticed_is_said_plainly_and_the_test_can_be_clicked_again(tmp_path):
    """PROOF 2026-11-21. The screen said "timed out after 60.0 s waiting for the test machine to notice the
    new CD" and the test was lost for the session, although its program had never started."""
    from tests.test_warm_vm import W
    c, w, m, clock, _ = app(tmp_path, machine=Machine(miss=99))
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    c.post("/api/warm/run/s4")
    s = until(c, lambda x: x["state"] == "ready" and x.get("error"))
    assert s["error"] == W.NOT_RUN["cd_not_seen"].format(tries=3, minutes=4) and "timed out" not in s["error"] and "60.0" not in s["error"]
    assert "did not notice this test's CD (3 tries" in s["error"] and "The test did not run" in s["error"]
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_not_run"] == "The test did not run." and d["running"] is False and d["exit_code"] == 1
    assert [x["state"] for x in d["steps"]] == ["done", "failed", "todo", "todo"]          # it stopped at "the test machine reads it"
    s4 = next(t for t in s["tests"] if t["id"] == "s4")
    assert s4["used"] is False and s4["can_run"] is True and s["used"] == [] and s["can_stop"] is True and m.cd == "emptydrive"
    m.miss = 0
    assert c.post("/api/warm/run/s4").status_code == 200                                   # clicked again: it runs
    s = until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4"])
    d = c.get("/api/run/steps").json()
    assert s["error"] is None and d["outcome"] == WM.WORDS["run_done"] and all(x["state"] == "done" for x in d["steps"])
    assert len({r["run_id"] for r in s["runs"]}) == 2 and [r["step"] for r in s["runs"]] == ["failed", "done"]


def test_while_the_launcher_says_a_test_is_going_the_screen_offers_neither_a_test_nor_the_shutdown(tmp_path):
    """The hole of 2026-11-21: this side had given up, the session said "ready" with Stop and tests offered,
    and the launcher was about to start the test. The launcher's own words decide."""
    m = Machine()
    m.script = lambda rid, scenario, n: (m.say(rid, "seen-cd"), m.say(rid, f"found-cd {scenario}")) and True     # found, then silence
    c, w, m, clock, _ = app(tmp_path, machine=m, timeouts={"run": 30})
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    c.post("/api/warm/run/s1")
    s = until(c, lambda x: x["state"] == "ready" and x.get("error"))
    rid = s["runs"][0]["run_id"]
    assert s["busy_inside"] == 1 and s["hint"] == WM.WORDS["busy_inside"] and s["can_stop"] is False and not any(t["can_run"] for t in s["tests"])
    assert c.post("/api/warm/stop").status_code == 409 and c.post("/api/warm/stop").json()["detail"] == WM.WORDS["busy_inside"]
    r = c.post("/api/warm/run/s4")
    assert r.status_code == 409 and "still going inside" in r.json()["detail"] and "shutdown" not in m.calls
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_stopped"]                                         # "did not finish": never "did not run" here
    m.say(rid, "failed run_scenario exit 1")                                               # the launcher's own end of it
    w.due()                                                                                # (the watcher's look takes it in)
    s = c.get("/api/warm").json()
    assert s["busy_inside"] == 0 and "hint" not in s and s["can_stop"] is True and [t["id"] for t in s["tests"] if t["can_run"]] == ["s4", "s5"]


def test_the_screen_shows_the_real_end_of_the_time_for_tests_and_says_why_in_measured_words(tmp_path):
    """The stop-gap (PROOF 2026-11-21): tests only in the first minutes; the screen shows the real end time,
    and its words say what was measured, not a cause nobody has proven."""
    from tests.test_warm_vm import W, slow_start
    m = Machine(left=900)
    c, w, m, clock, _ = app(tmp_path, machine=m)
    slow_start(m, clock, 480)
    t_start = clock.t
    assert "few minutes" in c.get("/api/warm").json()["words"]["start_hint"] and "quarter of an hour" not in json.dumps(WM.WORDS)
    c.post("/api/warm/start")
    s = until(c, lambda x: x["state"] == "ready")
    limit = t_start + W.START_TESTS_FOR_S
    assert s["ready_until"] == limit and s["seconds_left"] == pytest.approx(240, abs=5)
    assert s["ready_text"] == WM.WORDS["ready_until"].format(time=time.strftime("%H:%M", time.localtime(limit)), minutes=s["seconds_left"] // 60)
    assert s["hint"] == WM.WORDS["early_limit"].format(minutes=12) and "first 12 minutes after the machine was switched on" in s["hint"]
    for word in ("defender", "antivirus", "virus", "scan", "windows update"):                        # what is measured, never a blamed cause
        assert word not in json.dumps(WM.WORDS).lower(), word
    assert not BANNED.search(s["hint"]) and not BANNED.search(WM.WORDS["start_hint"])
    clock.t = limit - 100
    s = c.get("/api/warm").json()
    assert s["warning"] == WM.WORDS["last_minutes"].format(minutes=2) and all(t["can_run"] for t in s["tests"])
    clock.t = limit + 1
    s = c.get("/api/warm").json()
    assert s["warning"] == WM.WORDS["time_up"] and not any(t["can_run"] for t in s["tests"])
    assert c.post("/api/warm/run/s1").status_code == 409 and not any(x.startswith("cd run:") for x in m.calls)
    # with the launcher's own (shorter) time as the limit, the line about the first minutes is not shown
    (tmp_path / "b").mkdir()
    c2, w2, m2, clock2, _ = app(tmp_path / "b", machine=Machine(left=120))
    c2.post("/api/warm/start")
    s2 = until(c2, lambda x: x["state"] == "ready")
    assert "hint" not in s2 and s2["seconds_left"] == 120


def test_after_the_last_test_the_screen_does_not_say_the_machine_stays_on_for_the_next_one(tmp_path):
    """Seen in Yousif's own run (2026-11-22): the machine was shutting down under "stays on for the next test"."""
    c, w, m, clock, _ = app(tmp_path, machine=Machine(left=600, after_run_left=600))
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    c.post("/api/warm/run/s1")
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s1"])
    assert c.get("/api/run/steps").json()["outcome"] == WM.WORDS["run_done"]             # two more tests can start: it does stay on for them
    clock.t = w.status()["ready_until"] + 1                                              # the time for starting tests is over
    assert c.get("/api/run/steps").json()["outcome"] == WM.WORDS["run_done_last"] == "Test finished. No further test can start in this session."
    c.post("/api/warm/stop")
    until(c, lambda x: x["state"] == "off")
    assert c.get("/api/run/steps").json()["outcome"] == WM.WORDS["run_done_last"]        # ... and when the machine is off
    # every test of the session has run: the same
    (tmp_path / "b").mkdir()
    c2, w2, m2, clock2, _ = app(tmp_path / "b", machine=Machine(left=600, after_run_left=600))
    c2.post("/api/warm/start")
    until(c2, lambda x: x["state"] == "ready")
    for i, s in enumerate(("s1", "s4", "s5")):
        c2.post(f"/api/warm/run/{s}")
        until(c2, lambda x, n=i + 1: x["state"] == "ready" and len(x["used"]) == n)
        want = WM.WORDS["run_done"] if i < 2 else WM.WORDS["run_done_last"]
        assert c2.get("/api/run/steps").json()["outcome"] == want, s
    assert not BANNED.search(WM.WORDS["run_done_last"])


def test_asking_for_the_state_never_reaches_virtualbox(tmp_path):
    c, w, m, _, _ = app(tmp_path)
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    before = list(m.calls)
    for _ in range(40):
        assert c.get("/api/warm").status_code == 200
        c.get("/api/run/steps")
        c.get("/api/health")
    assert m.calls == before


def test_the_live_view_takes_whichever_run_is_newer(tmp_path):
    runner, runs = OneBoot(), WM.WarmRuns(str(tmp_path / "rec"))
    cur = WM.Current(runner, runs)
    assert cur.log is None and cur.step_words is None and cur.outcome_words is None
    runner.log, runner.started = "one-boot.log", 100.0
    assert cur.log == "one-boot.log" and cur.step_words is None
    runs.clock = lambda: 200.0
    runs.begin("s1")
    assert cur.log == runs.log and cur.started == 200.0 and cur.step_words == WM.STEP_MARKERS and cur.status().running is True
    runs.step("x", "running")
    runs.step("x", "done")
    text = open(runs.log, encoding="utf-8").read()
    assert L.LAUNCHER.search(text) and "RUN x: warm test done" in text and cur.status().running is False and cur.status().exit_code == 0
    runner.started = 300.0                                           # a one-boot run started later: it is the newer one again
    assert cur.log == "one-boot.log" and cur.step_words is None


def test_two_clicks_at_once_start_one_machine_and_one_test(tmp_path):
    import threading
    c, w, m, _, _ = app(tmp_path)
    hold, real_start, real_run = threading.Event(), w.start, w.run
    w.start = lambda *a, **k: (hold.wait(5), real_start(*a, **k))        # the work waits; the claim was made in the request
    assert c.post("/api/warm/start").status_code == 200
    again = c.post("/api/warm/start")
    assert again.status_code == 409 and again.json()["detail"] == WM.WORDS["states"]["starting"]
    hold.set()
    until(c, lambda x: x["state"] == "ready")
    assert [x for x in m.calls if x.startswith("restore")] == ["restore lived-in"]
    hold.clear()
    w.run = lambda *a, **k: (hold.wait(5), real_run(*a, **k))
    assert c.post("/api/warm/run/s1").status_code == 200
    for other in ("s1", "s4"):                                           # the same test again, or another: one at a time
        r = c.post(f"/api/warm/run/{other}")
        assert r.status_code == 409 and "is running" in r.json()["detail"]
    assert c.post("/api/warm/stop").status_code == 409                   # and never shut down in the middle of a test
    hold.set()
    s = until(c, lambda x: x["state"] == "ready" and x["used"] == ["s1"])
    assert len([x for x in m.calls if x.startswith("cd run:")]) == 1 and len(s["runs"]) == 1
    assert len([f for f in os.listdir(tmp_path / "rec" / "live") if f.startswith("warm-run-")]) == 1


def test_the_start_is_shown_as_steps_with_the_time_since_the_click(tmp_path):
    import threading
    c, w, m, clock, _ = app(tmp_path)
    hold, real_start = threading.Event(), w.start
    w.start = lambda *a, **k: (hold.wait(5), real_start(*a, **k))
    c.post("/api/warm/start")
    clock.t += 75
    s = c.get("/api/warm").json()
    assert s["state"] == "starting" and s["starting_seconds"] == 75 and s["practice"] is True
    steps = [WM.WORDS["boot_steps"]["booting"], WM.WORDS["boot_steps"]["settling"], WM.WORDS["states"]["ready"]]
    assert [(x["text"], x["state"]) for x in s["boot_list"]] == list(zip(steps, ["current", "todo", "todo"]))
    with w.lock:
        w.boot_step = "settling"
    assert [x["state"] for x in c.get("/api/warm").json()["boot_list"]] == ["done", "current", "todo"]
    hold.set()
    s = until(c, lambda x: x["state"] == "ready")
    assert "boot_list" not in s and s["starting_seconds"] is None and s["words"]["practice_tag"] == "Practice runs"


def test_the_session_itself_gives_a_start_or_a_test_to_one_caller_only(tmp_path):
    from tests.test_warm_vm import W
    w, m, _ = session(tmp_path)
    w.claim_start()
    with pytest.raises(W.WarmError, match="already starting"):
        w.claim_start()
    w.start(True)
    run = w.claim_run("S4")
    assert run["scenario"] == "s4" and w.status()["state"] == "running"
    for s in ("s4", "s1"):
        with pytest.raises(W.WarmError, match="is running"):
            w.claim_run(s)
    assert w.run("s4", run)["step"] == "done" and w.status()["used"] == ["s4"]


def test_a_test_whose_thread_dies_is_shown_as_not_finished_not_as_running_for_ever(tmp_path):
    c, w, m, _, _ = app(tmp_path)
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")

    def dies(*a, **k):
        raise RuntimeError("something unforeseen")
    w.run = dies
    assert c.post("/api/warm/run/s5").status_code == 200
    t = time.time()
    while c.get("/api/run/steps").json()["running"] and time.time() - t < 5:
        time.sleep(0.05)
    d = c.get("/api/run/steps").json()
    assert d["running"] is False and d["exit_code"] == 1 and d["finished"] is False and d["outcome"] == WM.WORDS["run_stopped"]
    s = until(c, lambda x: x["state"] == "ready")                       # and the machine is not left "running": it can be shut down
    assert s["used"] == ["s5"] and "stopped unexpectedly" in s["error"] and s["can_stop"]


def _alert_at(alert, name, t):
    """The made-up alert again under another name, stamped at laptop-clock time t (as the VM would stamp it)."""
    import dataclasses
    from datetime import datetime, timezone
    return dataclasses.replace(alert, incident=name, time=datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")


def _alerts(tmp_path):
    from engine.alerts import AlertStore
    from tests.test_report import s1_like
    (tmp_path / "x").mkdir()
    con, alert, _ = s1_like(tmp_path / "x")
    con.close()
    return alert, AlertStore(str(tmp_path / "a.db"))


def _held(w):
    """Make the next test wait at its very beginning until the returned event is set (the click is already claimed)."""
    import threading
    hold, real_run = threading.Event(), w.run
    w.run = lambda *a, **k: (hold.wait(5), real_run(*a, **k))
    return hold


def test_a_warm_tests_view_holds_only_what_was_raised_from_its_own_start(tmp_path):
    """A warm machine is not fresh. Each test's view shows what was raised from that test's own start. The
    machine's start-up alerts stay as the quiet line for the whole session (as a one-boot run shows its
    own); an earlier test's alerts and older ones are history; the machine's own housekeeping between the
    click and the test program's start is never counted as the test's."""
    alert, store = _alerts(tmp_path)
    c, w, m, clock, _ = app(tmp_path)
    old = _alert_at(alert, "from an earlier run", clock.t - 600)
    store.write([old])
    assert c.get("/api/health").json()["view_ids"] == [old.alert_id]       # nothing started here yet: the store as it is
    c.post("/api/warm/start")                                           # from this click on, what existed is history
    until(c, lambda x: x["state"] == "ready")
    h = c.get("/api/health").json()
    assert h["view_ids"] == [] and h["before_test"] is None
    boot = _alert_at(alert, "while the machine started up", clock.t + 5)
    store.write([boot])
    h = c.get("/api/health").json()                                     # a start-up alert: the quiet line, never the banner
    assert h["view_ids"] == [] and h["state"] != "alert" and h["before_test"]["count"] == 1
    assert h["before_test"]["text"] == L.WORDS["before_test"].format(n=1, s="") and h["before_test"]["id"] == boot.alert_id
    clock.t += 300                                                      # the first test is clicked five minutes later
    hold = _held(w)
    click = clock.t
    c.post("/api/warm/run/s4")
    h = c.get("/api/health").json()                                     # clicked: the start-up line is still there (PROOF 2026-11-21)
    assert h["view_ids"] == [] and h["before_test"]["count"] == 1 and h["before_test"]["text"] == L.WORDS["before_test"].format(n=1, s="")
    housekeeping = _alert_at(alert, "the machine's own housekeeping", click + 10)   # after the click, long before the program
    store.write([housekeeping])
    h = c.get("/api/health").json()
    assert h["view_ids"] == [] and h["before_test"]["count"] == 2
    assert h["before_test"]["text"] == WM.WORDS["before_mixed"].format(n=2, s="s") and h["state"] != "alert"
    clock.t += 90                                                       # the test program starts a minute and a half after the click
    hold.set()
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4"])
    own = _alert_at(alert, "raised by this test", clock.t - 1)          # stamped while the test was still going
    store.write([own])
    h = c.get("/api/health").json()
    assert h["view_ids"] == [own.alert_id] and h["alerts"] == 1 and h["after_test"] is None
    assert h["before_test"]["count"] == 2                               # housekeeping was NOT pulled into the test (20 s, not a minute)
    # the next test of the session: the first test's alerts are history, the start-up line stays
    clock.t += 30
    c.post("/api/warm/run/s1")
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4", "s1"])
    h = c.get("/api/health").json()
    assert h["view_ids"] == [] and h["before_test"]["count"] == 1 and h["before_test"]["id"] == boot.alert_id
    assert h["before_test"]["text"] == L.WORDS["before_test"].format(n=1, s="")
    newer = _alert_at(alert, "raised by the second test", clock.t - 1)
    store.write([newer])
    store.close()
    assert c.get("/api/health").json()["view_ids"] == [newer.alert_id]


def test_a_tests_view_closes_at_its_end_and_a_later_alert_is_its_own_quiet_line(tmp_path):
    """The real case (2026-11-21): 33 s after a test finished, with no test running, Windows' own
    CompatTelRunner started two shells. Had the next test not been clicked 8 s earlier, they would have
    stood under the finished test as a full "Alert raised". The end is the launcher's own "done" time, on
    the test machine's clock (the clock alerts are stamped with): 8 s after it is after it."""
    from datetime import datetime, timezone
    alert, store = _alerts(tmp_path)
    m = Machine()
    c, w, m, clock, _ = app(tmp_path, machine=m)
    m.stamp = lambda: datetime.fromtimestamp(clock.t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"     # seven decimals, as Windows writes
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    hold = _held(w)
    c.post("/api/warm/run/s5")
    c.get("/api/health")
    clock.t += 60
    hold.set()
    s = until(c, lambda x: x["used"] == ["s5"])
    end = WM.vm_seconds(s["runs"][0]["ended_vm"])
    assert end is not None and abs(end - clock.t) < 30                  # the launcher's own time of "done" came through
    during = _alert_at(alert, "the test's own", end - 2)
    store.write([during])
    h = c.get("/api/health").json()
    assert h["view_ids"] == [during.alert_id] and h["after_test"] is None
    clock.t += 40                                                       # nobody clicks; the machine idles
    later = _alert_at(alert, "8 s after the end", end + 8)
    much_later = _alert_at(alert, "33 s after the end", end + 33)
    store.write([later, much_later])
    h = c.get("/api/health").json()
    assert h["view_ids"] == [during.alert_id] and h["alerts"] == 1      # the test keeps its own; the banner is not raised again for them
    assert h["after_test"] == {"count": 2, "id": much_later.alert_id, "text": L.WORDS["after_test"].format(n=2, s="s")}
    assert "not part of it" in h["after_test"]["text"]
    store.close()


def test_a_one_boot_runs_view_closes_when_the_run_is_over(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient as TC
    alert, store = _alerts(tmp_path)

    class Done:                                                       # a one-boot run that started its test and has finished
        log, started, lock = str(tmp_path / "run.log"), 1_000_000.0, None

        def status(self):
            return type("S", (), {"running": False, "scenario": "s1", "started": 1_000_000.0, "exit_code": 0, "log_tail": []})()

    (tmp_path / "run.log").write_text("--> 3. x\nVM: running (calm)\nRUN x: PASS\n", encoding="utf-8")
    clock = type("C", (), {"t": 1_000_100.0, "__call__": lambda self: self.t})()
    api = FastAPI()
    api.include_router(L.make_router(str(tmp_path / "s.db"), str(tmp_path / "a.db"), Done(), clock=clock, watch_log=False))
    c = TC(api)
    own = _alert_at(alert, "the run's own", 1_000_090.0)
    store.write([own])
    assert c.get("/api/health").json()["view_ids"] == [own.alert_id]    # (this look is also when the run is seen over: 1,000,100)
    clock.t += 500
    other = _alert_at(alert, "something else, later", 1_000_400.0)
    store.write([other])
    store.close()
    h = c.get("/api/health").json()
    assert h["view_ids"] == [own.alert_id] and h["after_test"]["count"] == 1 and h["after_test"]["id"] == other.alert_id


def test_an_alert_stamped_just_before_the_laptop_saw_the_start_still_counts_as_the_tests(tmp_path):
    """The VM's clock and the polling lag a few seconds: the margin for a warm test is WARM_CLOCK_MARGIN_S."""
    alert, store = _alerts(tmp_path)
    c, w, m, clock, _ = app(tmp_path)
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    hold = _held(w)
    c.post("/api/warm/run/s1")
    c.get("/api/health")
    clock.t += 200
    hold.set()
    until(c, lambda x: x["used"] == ["s1"])
    c.get("/api/health")
    seen_start = clock.t                                                # the start was seen at most a few made-up seconds ago
    inside = _alert_at(alert, "a little before the seen start", seen_start - WM.WARM_CLOCK_MARGIN_S + 12)
    outside = _alert_at(alert, "well before the seen start", seen_start - WM.WARM_CLOCK_MARGIN_S - 30)
    store.write([inside, outside])
    store.close()
    h = c.get("/api/health").json()
    assert h["view_ids"] == [inside.alert_id] and h["before_test"]["count"] == 1 and h["before_test"]["id"] == outside.alert_id
    assert h["before_test"]["text"] == WM.WORDS["before_test"].format(n=1, s="") and WM.WARM_CLOCK_MARGIN_S < L.CLOCK_MARGIN_S


def test_after_a_warm_test_that_never_started_later_alerts_are_in_view_again(tmp_path):
    """Seen on 2026-11-21: a disc change was missed, the test never started, and from then on every alert
    stayed "before the test" for ever (the command-line cycles after it saw no alert on Watch)."""
    alert, store = _alerts(tmp_path)
    c, w, m, clock, _ = app(tmp_path, machine=Machine(refuse="note unreadable"))
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    hold = _held(w)
    click = clock.t
    c.post("/api/warm/run/s1")
    c.get("/api/health")
    during = _alert_at(alert, "while the test was still expected", click + 10)
    store.write([during])
    clock.t += 120
    hold.set()
    until(c, lambda x: x["state"] == "ready" and x.get("error"))
    h = c.get("/api/health").json()                                     # the test is over without ever starting
    assert h["view_ids"] == [] and h["before_test"]["count"] == 1 and h["watch_note"] is None
    clock.t += 600
    later = _alert_at(alert, "raised long after", clock.t - 5)
    store.write([later])
    store.close()
    h = c.get("/api/health").json()
    assert h["view_ids"] == [later.alert_id] and h["before_test"]["count"] == 1 and h["before_test"]["id"] == during.alert_id


def test_the_command_line_cycle_times_the_alert_from_the_alert_list_not_the_watch_view(tmp_path, monkeypatch):
    import types
    import urllib.request
    from tests.test_warm_vm import W
    w, m, clock = session(tmp_path)
    asked = []

    class Answer:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    def urlopen(url, timeout=None):
        asked.append(url)
        return Answer(json.dumps([{"id": i} for i in range(3 if len(asked) == 1 else 4)]).encode())   # one more alert after the click

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    real_sleep = time.sleep
    monkeypatch.setattr(W, "time", types.SimpleNamespace(time=time.time, strftime=time.strftime, localtime=time.localtime,
                                                         sleep=lambda s: real_sleep(0.3 if s >= 10 else 0.01)))
    assert W.cycle(["s1"], session=w) == 0
    run = w.status()["runs"][0]
    assert run["step"] == "done" and run["times"]["click_to_alert"] is not None and run["times"]["click_to_alert"] >= 0
    assert asked and all(u == "http://127.0.0.1:8780/api/alerts" for u in asked)
    assert w.status()["state"] == "off" and m.state_now == "poweroff"


def test_a_machine_this_dashboard_did_not_start_can_never_be_shut_down_from_here(tmp_path):
    """Something else has the test machine on (a command-line cycle, a one-boot run from another window).
    The start is refused, and "shut down" is neither offered nor obeyed: it could stop that run mid-test."""
    c, w, m, _, _ = app(tmp_path, machine=Machine(state="running"))
    assert c.post("/api/warm/start").status_code == 200
    s = until(c, lambda x: x.get("error"))
    assert s["state"] == "off" and "must be switched off first" in s["error"] and s["can_stop"] is False and s["can_start"] is True
    assert c.post("/api/warm/stop").status_code == 409
    assert w.stop() is None                                             # nor by the session itself
    assert m.calls == ["state"] and m.state_now == "running"             # asked once, changed nothing


def test_the_watcher_shuts_the_machine_down_when_no_further_test_can_start(tmp_path):
    import threading
    w, m, clock = session(tmp_path, Machine(left=60))
    w.start()
    stop = threading.Event()
    t = threading.Thread(target=w.watch, kwargs={"every": 0.01, "stop": stop}, daemon=True)
    t.start()
    time.sleep(0.1)
    assert w.status()["state"] == "ready" and "shutdown" not in m.calls       # time left: left alone
    clock.t += 61
    limit = time.time() + 5
    while w.status()["state"] != "off" and time.time() < limit:
        time.sleep(0.02)
    stop.set()
    t.join(2)
    st = w.status()
    assert st["state"] == "off" and st["ended"] == "time is up" and m.calls.count("shutdown") == 1


# ---------------------------------------------------------------- after a restart of the dashboard

def _iso(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _write_records(tmp_path, lines):
    """The launcher's states as the laptop's receiver wrote them into recordings/vmruns (the made-up machine
    only hands them to the session that is listening; a restarted dashboard has to read the files)."""
    folder = tmp_path / "rec" / "vmruns"
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "2026-11-21.jsonl", "a", encoding="utf-8") as f:
        for run_id, state, received in lines:
            f.write(json.dumps({"type": "LAUNCHER_STATE", "run_id": run_id, "state": state, "time": _iso(received - 2), "received_utc": _iso(received)}) + "\n")


def _restarted(tmp_path, m, clock, owner="dashboard"):
    from tests.test_warm_vm import W
    return W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0, servers=lambda: (0, ""),
                         build_warm=lambda sid: f"warm:{sid}", build_run=lambda sid, rid, s: f"run:{sid}:{rid}:{s}", owner=owner)


def test_a_restarted_dashboard_takes_back_the_machine_it_started(tmp_path):
    """The risk (PROOF 2026-11-21): the dashboard crashes or is restarted while the warm machine is on. Before,
    the new dashboard knew nothing: no Stop button, no shutdown by itself."""
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.start()
    t_ready = clock.t
    run = w1.run("s1")
    t_done = clock.t
    sid = w1.status()["session_id"]
    with open(w1.notes, encoding="utf-8") as f:
        notes = json.load(f)
    assert notes["owner"] == "dashboard" and notes["state"] == "ready" and notes["session_id"] == sid
    _write_records(tmp_path, [(sid, "launcher-started", t_ready - 30), (sid, "warm-ready (calm) left=600", t_ready),
                              (run["run_id"], "found-cd s1", t_done - 20), (run["run_id"], "running (calm)", t_done - 15),
                              (run["run_id"], "done ok left=300", t_done)])
    before = list(m.calls)
    clock.t += 45                                                    # the dashboard is down for a while; the machine keeps running
    w2 = _restarted(tmp_path, m, clock)
    assert w2.adopt() == "adopted"
    assert m.calls == before + ["state"]                             # VirtualBox was asked once, and nothing was changed
    st = w2.status()
    assert st["state"] == "ready" and st["adopted"] is True and st["session_id"] == sid and st["used"] == ["s1"]
    assert st["ready_until"] == pytest.approx(t_done + 300, abs=1) and st["seconds_left"] == pytest.approx(255, abs=2)   # from the launcher's own last count
    assert "already ran" in w2.can_run("s1") and w2.can_run("s4") is None
    # on screen: the buttons are back, with the time left and Stop
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode="live", warm=w2, clock=clock))
    v = c.get("/api/warm").json()
    assert v["state"] == "ready" and v["can_stop"] and "min left" in v["ready_text"] and [t["id"] for t in v["tests"] if t["can_run"]] == ["s4", "s5"]
    assert c.post("/api/scenarios/s1/run").status_code == 409          # and a one-boot run is refused, as for any warm session
    # the shutdown by itself still happens
    assert not w2.due()
    clock.t = t_done + 301
    assert w2.due() and w2.stop("time is up") is True
    assert w2.status()["state"] == "off" and m.state_now == "poweroff" and m.calls.count("shutdown") == 1


def test_no_test_and_no_shutdown_while_a_test_that_was_running_at_the_restart_is_unfinished(tmp_path):
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.start()
    sid, t0 = w1.status()["session_id"], clock.t
    run = w1.claim_run("s4")                                         # the dashboard dies right after the click
    w1._save()
    _write_records(tmp_path, [(sid, "warm-ready (calm) left=600", t0), (run["run_id"], "found-cd s4", t0 + 5), (run["run_id"], "running (calm)", t0 + 9)])
    clock.t += 20
    w2 = _restarted(tmp_path, m, clock)
    assert w2.adopt() == "adopted"
    st = w2.status()
    assert st["state"] == "recovering" and st["unfinished"] == 1 and st["used"] == ["s4"]
    assert "recovering" in w2.can_run("s1")                          # no test until the launcher's own records say it is free
    with pytest.raises(Exception, match="when it has finished"):
        w2.stop()                                                    # and never shut down in the middle of a test
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode="live", warm=w2, clock=clock))
    v = c.get("/api/warm").json()
    assert v["state"] == "recovering" and v["text"] == WM.WORDS["states"]["recovering"] and v["hint"] == WM.WORDS["unfinished"]
    assert "can be shut down now" not in v["hint"]                   # the words never offer what the buttons refuse
    assert v["can_stop"] is False and not any(t["can_run"] for t in v["tests"]) and "min left" in v["ready_text"]
    assert c.post("/api/warm/stop").status_code == 409 and c.post("/api/warm/run/s1").status_code == 409 and "shutdown" not in m.calls
    assert not w2.due()
    m.say(run["run_id"], "done ok left=240")                         # the test finishes; its last state arrives while we listen
    assert not w2.due()                                              # (this look also takes the state in)
    st = w2.status()
    assert st["state"] == "ready" and st["seconds_left"] == 240 and st["runs"][0]["step"] == "done" and w2.can_run("s1") is None
    assert c.get("/api/warm").json()["can_stop"] is True


def test_a_machine_that_is_on_but_not_ours_is_said_plainly_and_left_alone(tmp_path):
    """The notes are a command-line cycle's (or there are none), and the machine is on: this dashboard says so
    and offers no Stop. It is not ours to shut down."""
    for case, owner in (("a command-line session", "cli"), ("no notes at all", None)):
        root = tmp_path / case.replace(" ", "-")
        root.mkdir()
        m = Machine()
        if owner:
            w1, m, clock = session(root, m, owner=owner)
            w1.start()
        else:
            w1, m, clock = session(root, m)
            m.state_now = "running"
        before = list(m.calls)
        w2 = _restarted(root, m, clock)
        assert w2.adopt() == "foreign", case
        st = w2.status()
        assert st["state"] == "off" and st["foreign"] is True and st["adopted"] is False and st["session_id"] is None
        c = TestClient(create_app(str(root / "s.db"), str(root / "a.db"), recordings=str(root / "rec"), runner=OneBoot(), mode="live", warm=w2, clock=clock))
        v = c.get("/api/warm").json()
        assert v["foreign_text"] == WM.WORDS["foreign"] and v["can_stop"] is False and "did not start it" in v["foreign_text"]
        assert v["text"] == WM.WORDS["states"]["foreign"] and "is off" not in v["text"]        # never "is off" beside "is on"
        assert c.post("/api/warm/stop").status_code == 409 and w2.stop() is None
        assert not w2.due() and m.calls == before + ["state"] and m.state_now == "running"     # asked once, changed nothing


def test_nothing_is_taken_back_when_the_machine_is_off_or_the_session_had_ended(tmp_path):
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.start()
    w1.stop()
    w2 = _restarted(tmp_path, m, clock)
    assert w2.adopt() == "off" and w2.status()["state"] == "off" and w2.status()["foreign"] is False
    m.state_now = "running"                                          # on again, by someone else: the notes say our session was ended
    w3 = _restarted(tmp_path, m, clock)
    assert w3.adopt() == "foreign" and w3.status()["adopted"] is False


def test_stale_notes_never_make_this_dashboard_take_a_later_boot_of_the_machine(tmp_path):
    """The dangerous case: the dashboard dies with notes saying "ready"; the machine is switched off another
    way (the notes stay as they were); later the machine is on again for something else (a one-boot run, a
    command-line cycle). The notes still say "ours, not ended" but it is ANOTHER boot: not ours to stop."""
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.start()
    sid, t0 = w1.status()["session_id"], clock.t
    _write_records(tmp_path, [(sid, "warm-ready (calm) left=600", t0)])
    del w1                                                           # the dashboard dies; the notes say "ready"
    m.request_shutdown()                                             # switched off some other way: nobody rewrites the notes
    m.calls.clear()
    m.state_now = "running"                                          # ...and on again, a new boot, for something else
    m.changed += 1
    clock.t += 700                                                   # the old session's time is long over
    w2 = _restarted(tmp_path, m, clock)
    assert w2.adopt() == "foreign"
    assert not w2.due() and w2.stop() is None and w2.stop("time is up") is None
    st = w2.status()
    assert st["state"] == "off" and st["foreign"] is True and st["adopted"] is False and "shutdown" not in m.calls
    # and a machine found OFF ends the stale notes, so they can never be believed later
    m.state_now = "poweroff"
    m.changed += 1
    w3 = _restarted(tmp_path, m, clock)
    assert w3.adopt() == "off"
    with open(w3.notes, encoding="utf-8") as f:
        notes = json.load(f)
    assert notes["state"] == "off" and notes["ended"] and notes["session_id"] == sid


def test_a_session_caught_while_still_starting_gets_its_time_when_the_launcher_says_ready(tmp_path):
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.claim_start()
    w1._set(session_id="20261121-000000-abcd", boot_mark=m.mark_after_next_start())    # as start() notes it, right after the machine is started
    m.cd = "warm:20261121-000000-abcd"
    m.state_now, m.changed = "running", m.changed + 1
    w2 = _restarted(tmp_path, m, clock)                              # the dashboard died during the start
    assert w2.adopt() == "adopted" and w2.status()["state"] == "recovering" and "recovering" in w2.can_run("s1")
    clock.t += 200
    m.say("20261121-000000-abcd", "warm-ready (calm) left=500")
    assert not w2.due()
    st = w2.status()
    assert st["state"] == "ready" and st["seconds_left"] == 500 and w2.can_run("s1") is None


def test_a_launcher_that_ended_while_the_dashboard_was_down_means_shut_down(tmp_path):
    w1, m, clock = session(tmp_path, owner="dashboard")
    w1.start()
    sid, t0 = w1.status()["session_id"], clock.t
    _write_records(tmp_path, [(sid, "warm-ready (calm) left=600", t0), (sid, "warm-ended (time is up; no test was running)", t0 + 700)])
    clock.t += 720
    w2 = _restarted(tmp_path, m, clock)
    assert w2.adopt() == "adopted" and w2.status()["state"] == "recovering"       # never "ready": its launcher is gone
    assert "recovering" in w2.can_run("s1")
    assert w2.due() and w2.stop("time is up") is True and m.state_now == "poweroff"


def test_every_warm_word_passes_the_word_scan_and_says_practice(tmp_path):
    def texts(x):
        if isinstance(x, str):
            yield x
        elif isinstance(x, dict):
            for v in x.values():
                yield from texts(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                yield from texts(v)

    for t in texts(WM.WORDS):
        assert not BANNED.search(t), t
    from tests.test_warm_vm import W
    for t in W.NOT_RUN.values():                                     # the session's own words for a test that did not run
        assert not BANNED.search(t) and "The test did not run" in t, t
    assert "Practice runs" in WM.WORDS["practice"]
    c, *_ = app(tmp_path)
    assert not BANNED.search(json.dumps(c.get("/api/warm").json()))
