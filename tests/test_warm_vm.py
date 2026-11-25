"""The warm test machine (demo/warm_vm.py + demo/warm/warm_launcher.ps1): practice runs in one boot.

Every test here uses a made-up VirtualBox and made-up record files. PROOF's conditions (2026-11-21):
no test may reach the real VBoxManage (an autouse trap proves it), the launcher may only ever start a
CD's own run_scenario.ps1, runs are practice runs, and the frozen code is used, never edited."""

import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo"))
import warm_vm as W  # noqa: E402

LAUNCHER = os.path.join(ROOT, "demo", "warm", "warm_launcher.ps1")


@pytest.fixture(autouse=True)
def no_real_programs(monkeypatch):
    """Booby-trap every way of starting a program, and the frozen VBox helper itself: a test that
    reaches for the real VBoxManage (or PowerShell, or anything) fails loudly instead of touching the VM."""
    started = []

    def trap(*args, **kwargs):
        started.append(args[0] if args else kwargs.get("args"))
        raise AssertionError(f"a test tried to start a real program: {started[-1]!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    monkeypatch.setattr(os, "system", trap)
    monkeypatch.setattr(W.R.VBox, "call", trap)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    yield started
    assert started == []


class Clock:
    def __init__(self):
        self.t = 1_000_000.0
        self.todo = []                        # (time, what happens then): the made-up machine's own pace

    def __call__(self):
        return self.t

    def at(self, t, fn):
        self.todo.append((t, fn))

    def sleep(self, seconds):
        self.t += seconds
        due = sorted((x for x in self.todo if x[0] <= self.t), key=lambda x: x[0])
        self.todo = [x for x in self.todo if x[0] > self.t]
        for _, fn in due:
            fn()


class Tail:
    """Stands in for run_in_vm.Tail: records are pushed by the made-up machine, read once."""

    def __init__(self, folder):
        self.folder, self.queue = folder, []

    def new_records(self):
        out, self.queue = self.queue, []
        return out


class Machine:
    """A made-up VirtualBox with the lab VM in it. It answers like the real one and plays the warm
    launcher's part: after a start it reports ready; after a run CD is inserted it runs that test."""

    vm = "AnalystLab-Win11"

    def __init__(self, left=600, state="poweroff", refuse=None, after_run_left=300, miss=0):
        self.calls, self.state_now, self.cd = [], state, None
        self.miss = miss                      # how many run-CD insertions "Windows" fails to notice
        self.left, self.refuse, self.after_run_left = left, refuse, after_run_left
        self.tails = {}
        self.changed = 0                                     # counts the machine's changes of state (VirtualBox stamps each one)
        self.script = None                                   # (run id, scenario, which insertion of it) -> True: the test plays the launcher itself
        self.inserted = {}

    def info(self):
        """What `VBoxManage showvminfo --machinereadable` would say, as far as warm_vm reads it."""
        return f'VMState="{self.state_now}"\nVMStateChangeTime="2026-01-01T00:{self.changed // 60:02d}:{self.changed % 60:02d}.000000000"\n'

    def mark_after_next_start(self):
        return f"2026-01-01T00:{(self.changed + 1) // 60:02d}:{(self.changed + 1) % 60:02d}.000000000"

    def tail(self, folder):
        t = Tail(folder)
        self.tails[os.path.basename(folder)] = t
        return t

    def say(self, run_id, state):
        rec = {"type": "LAUNCHER_STATE", "run_id": run_id, "state": state}
        if getattr(self, "stamp", None):                     # a test may give the made-up machine its own clock
            rec["time"] = self.stamp()
        self.tails["vmruns"].queue.append(rec)

    # -- the VBox methods warm_vm uses --
    def state(self):
        self.calls.append("state")
        return self.state_now

    def snapshots(self):
        self.calls.append("snapshots")
        return ["clean", "lived-in"]

    def unlocked(self):
        return True

    def restore(self, name):
        self.calls.append(f"restore {name}")

    def set_cpus(self, n):
        self.calls.append(f"cpus {n}")

    def logged_in_since(self, after):
        return self.state_now == "running"

    def start(self, headless=False):
        self.calls.append(f"start headless={headless}")
        self.state_now = "running"
        self.changed += 1
        sid = self.cd.split(":")[1]
        self.say("-", "starter: started, looking for a run CD (lab folder locked for users: True)")
        self.say(sid, "launcher-started")
        self.say(sid, "settling")
        self.say(sid, f"warm-ready (calm) left={self.left}")

    def insert_cd(self, path):
        self.calls.append(f"cd {path}")
        self.cd = path
        if path.startswith("run:") and self.state_now == "running":
            _, sid, rid, scenario = path.split(":")
            self.inserted[rid] = self.inserted.get(rid, 0) + 1
            if self.script and self.script(rid, scenario, self.inserted[rid]):
                return
            if self.miss:
                self.miss -= 1
                return
            if self.refuse:
                self.say(rid, f"refused {self.refuse}")
                return
            self.say(rid, "seen-cd")
            self.runs_it(rid, scenario)

    def runs_it(self, rid, scenario):
        """The launcher's words for a CD it found, and the test it then ran to the end."""
        self.say(rid, f"found-cd {scenario}")
        self.say(rid, "running (calm)")
        self.tails["vmruns"].queue.append({"type": "SCENARIO_RUN", "run_id": rid, "start": "a", "end": "b", "exit_code": 0})
        self.say(rid, "flushing")
        self.say(rid, f"done ok left={self.after_run_left}")
        self.tails["vm"].queue.append({"type": "FILE_HASH", "data": {"TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{rid}-ok.txt"}})

    def request_shutdown(self):
        self.calls.append("shutdown")
        self.state_now = "poweroff"
        self.changed += 1


def session(tmp_path, machine=None, **kw):
    m = machine or Machine()
    clock = Clock()
    w = W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0,
                      servers=lambda: (0, ""), build_warm=lambda sid: f"warm:{sid}",
                      build_run=lambda sid, rid, s: f"run:{sid}:{rid}:{s}", **kw)
    return w, m, clock


# ---------------------------------------------------------------- the session's rules

def test_start_restores_the_prepared_snapshot_and_becomes_ready_with_a_clock_time(tmp_path):
    w, m, clock = session(tmp_path)
    w.start()
    st = w.status()
    assert st["state"] == "ready" and st["seconds_left"] == 600 and st["ready_until"] == clock.t + 600 and st["practice"] is True
    sid = st["session_id"]
    assert m.calls == ["state", "snapshots", "restore lived-in", "cpus 1", f"cd warm:{sid}", "start headless=True"]


def test_a_test_runs_once_and_the_ready_time_follows_the_launchers_own_count(tmp_path):
    w, m, clock = session(tmp_path)
    w.start()
    run = w.run("S1")
    st = w.status()
    assert run["step"] == "done" and run["barrier"] == "ok" and run["practice"] is True and run["run_record"]["exit_code"] == 0
    assert st["state"] == "ready" and st["used"] == ["s1"] and st["seconds_left"] == 300       # the launcher's "left=300" after the test
    assert m.calls[-2:] == ["cd emptydrive", f"cd run:{st['session_id']}:{run['run_id']}:s1"]     # the old disc out, then the new one
    assert "already ran" in w.can_run("s1") and w.can_run("s4") is None
    with pytest.raises(W.WarmError, match="already ran"):
        w.run("s1")
    second = w.run("s4")
    assert second["run_id"] != run["run_id"] and w.status()["used"] == ["s1", "s4"]


def test_a_missed_disc_change_gets_the_same_cd_again(tmp_path):
    # 2026-11-21: Windows sometimes misses the swap and says "device not ready" for good
    w, m, clock = session(tmp_path, Machine(miss=2))
    w.start()
    run = w.run("s1")
    swaps = [c for c in m.calls if c.startswith("cd run:")]
    assert run["step"] == "done" and len(swaps) == 3 and len(set(swaps)) == 1      # the same CD, three times
    assert m.calls.count("cd emptydrive") == 3


def test_a_disc_never_noticed_fails_in_plain_words_is_taken_out_and_the_test_can_be_clicked_again(tmp_path):
    w, m, clock = session(tmp_path, Machine(miss=99))
    w.start()
    t0 = clock.t
    with pytest.raises(W.WarmError) as e:
        w.run("s1")
    # PROOF 2026-11-21: not "timed out after 60.0 s waiting for the test machine to notice the new CD"
    assert str(e.value) == W.NOT_RUN["cd_not_seen"].format(tries=3, minutes=4) and "timed out" not in str(e.value) and e.value.why == "cd_not_seen"
    assert len([c for c in m.calls if c.startswith("cd run:")]) == W.SWAP_TRIES
    assert clock.t - t0 <= W.TIMEOUTS["noticed"] + W.SWAP_TRIES * (W.SWAP_PAUSE + 2) + W.TAKE_BACK_S + 5
    assert m.calls[-1] == "cd emptydrive" and m.cd == "emptydrive"            # given up: the disc is OUT, nothing can start unwatched
    st = w.status()
    run = st["runs"][0]
    assert st["state"] == "ready" and st["error"] == str(e.value) and run["step"] == "failed" and run["not_started"] is True and run["why"] == "cd_not_seen"
    # its program never started, so the test is not "used": it can be clicked again (a new run id, a new CD)
    assert st["used"] == [] and w.can_run("s1") is None
    m.miss = 0
    n = len(m.calls)
    again = w.run("s1")
    assert again["step"] == "done" and again["run_id"] != run["run_id"] and w.status()["used"] == ["s1"]
    assert [c for c in m.calls[n:] if c.startswith("cd ")] == [f"cd run:{st['session_id']}:{again['run_id']}:s1"]    # the empty drive is not emptied twice


def test_the_recorded_s4_disc_change_once_the_launcher_has_seen_the_cd_it_is_never_pulled_again(tmp_path):
    """2026-11-21, S4 (ids made up here). The first insertion was not noticed in 60 s. The second was seen
    only after 58 s, about 2 s before the third try pulled the disc; the launcher then needed 4 min 42 s
    more to find it, long after this side had given up. Here the launcher's "seen-cd" ARRIVES before the
    third try is due: it stops the retries, and this side waits while the disc is read. (When the word
    arrives too late, see the next test.)"""
    m = Machine()
    w, m, clock = session(tmp_path, m)

    def launcher(rid, scenario, n):
        if n == 1:
            return True                                                      # not noticed at all
        clock.at(clock.t + 58, lambda: m.say(rid, "seen-cd"))               # seen 2 s before the next try was due
        clock.at(clock.t + 58 + 282, lambda: m.runs_it(rid, scenario))       # and read 4 min 42 s later
        return True

    m.script = launcher
    w.start()
    said = []
    w.say = said.append
    run = w.run("s4")
    assert run["step"] == "done" and w.status()["used"] == ["s4"]
    assert len([c for c in m.calls if c.startswith("cd run:")]) == 2 and m.calls.count("cd emptydrive") == 2   # two insertions, never a third
    assert m.cd.startswith("run:") and any("not taken out again" in x for x in said)
    assert run["times"]["swap_to_noticed"] >= 60 + 58 + 282


def test_a_seen_word_that_arrives_after_the_last_retry_costs_one_more_insertion_and_the_test_still_runs(tmp_path):
    """The same day's timeline as it most likely was on the wire: the launcher's words reach the laptop up to
    6.8 s late, so its "seen-cd" (2 s before the third try) arrives only after the disc was pulled and put
    in again. Nothing can prevent that one pull. What matters: no fourth insertion, no giving up while the
    launcher reads, and the test runs when the disc is read at last (282 s later that day)."""
    m = Machine()
    w, m, clock = session(tmp_path, m)

    def launcher(rid, scenario, n):
        if n == 3:                                                           # the third insertion is already in ...
            clock.at(clock.t + 4, lambda: m.say(rid, "seen-cd"))            # ... when the word about the second arrives
            clock.at(clock.t + 4 + 282, lambda: m.runs_it(rid, scenario))
        return True

    m.script = launcher
    w.start()
    run = w.run("s4")
    assert run["step"] == "done" and w.status()["used"] == ["s4"]
    assert len([c for c in m.calls if c.startswith("cd run:")]) == 3 and m.cd.startswith("run:")     # three insertions, then only waiting
    assert W.TIMEOUTS["read"] >= 282 + 15                                     # the one measured read fits, by little: said plainly in the docstring


def test_the_drive_is_never_emptied_twice_and_a_restarted_dashboard_remembers_it(tmp_path):
    """After this side gave up on a CD the drive is empty. Neither the next test's disc change nor the
    shutdown empties it again (VirtualBox is never asked to take a disc out of an empty drive), also when
    the dashboard was restarted in between."""
    import json
    w, m, clock = session(tmp_path, Machine(miss=99), owner="dashboard")
    w.start()
    with pytest.raises(W.WarmError):
        w.run("s1")
    assert m.calls[-1] == "cd emptydrive" and w.status()["drive_empty"] is True
    with open(w.notes, encoding="utf-8") as f:
        assert json.load(f)["drive_empty"] is True
    n = len(m.calls)
    w2 = W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0, servers=lambda: (0, ""),
                       build_warm=lambda sid: f"warm:{sid}", build_run=lambda sid, rid, s: f"run:{sid}:{rid}:{s}", owner="dashboard")
    assert w2.adopt() == "adopted" and w2.status()["drive_empty"] is True
    with w2.lock:
        w2.state = "ready"
    assert w2.stop() is True and "cd emptydrive" not in m.calls[n:] and "shutdown" in m.calls[n:]
    # and the usual case is unchanged: a disc that is in comes out after the shutdown
    w3, m3, _ = session(tmp_path / "c")
    w3.start()
    w3.run("s1")
    assert w3.status()["drive_empty"] is False and w3.stop() is True and m3.calls[-1] == "cd emptydrive"


def test_a_cd_that_was_seen_but_never_read_is_taken_out_and_said_plainly(tmp_path):
    m = Machine()
    w, m, clock = session(tmp_path, m)
    m.script = lambda rid, scenario, n: m.say(rid, "seen-cd") or True          # seen at once, its files never readable
    w.start()
    t0 = clock.t
    with pytest.raises(W.WarmError, match="saw this test's CD but could not read it") as e:
        w.run("s5")
    assert e.value.why == "cd_unreadable" and str(e.value) == W.NOT_RUN["cd_unreadable"].format(minutes=5)
    assert len([c for c in m.calls if c.startswith("cd run:")]) == 1 and m.calls[-1] == "cd emptydrive"       # never pulled to retry; out at the end
    assert W.TIMEOUTS["read"] <= clock.t - t0 <= W.TIMEOUTS["read"] + W.SWAP_PAUSE + W.TAKE_BACK_S + 10
    assert w.status()["used"] == [] and w.can_run("s5") is None


def test_a_cd_found_while_it_is_being_taken_out_ends_in_the_launchers_own_not_started(tmp_path):
    """The launcher had read the CD just as this side gave up. It says "found-cd"; then, right before starting,
    it looks at the drive once more (demo/warm/warm_launcher.ps1), finds the disc gone and starts nothing."""
    m = Machine()
    w, m, clock = session(tmp_path, m)

    def launcher(rid, scenario, n):
        if n == W.SWAP_TRIES:                                                # found at the very end of the last try's time ...
            clock.at(clock.t + 60 + 3, lambda: m.say(rid, f"found-cd {scenario}"))
            clock.at(clock.t + 60 + 30, lambda: m.say(rid, "failed not-started (the CD was taken out or changed before the test started)"))
        return True

    m.script = launcher
    w.start()
    with pytest.raises(W.WarmError) as e:
        w.run("s1")
    assert str(e.value) == W.NOT_RUN["cd_gone"] and "launcher reported" not in str(e.value)
    st = w.status()
    assert m.cd == "emptydrive" and st["used"] == [] and st["runs"][0]["not_started"] is True and st["runs"][0]["why"] == "cd_gone"
    assert st["busy_inside"] == 0 and w.can_run("s1") is None


def test_a_test_the_launcher_says_is_still_going_blocks_a_new_test_and_the_shutdown(tmp_path):
    """The hole of 2026-11-21: this side gave up on S4 and called the session ready; 3.5 minutes later the
    launcher said "found-cd", and about two minutes after that the machine was shut down by itself: seconds
    from the middle of a test. Whatever this side thinks, the launcher's own words decide."""
    m = Machine(left=300)
    w, m, clock = session(tmp_path, m, timeouts={"run": 40})
    m.script = lambda rid, scenario, n: (m.say(rid, "seen-cd"), m.say(rid, f"found-cd {scenario}")) and True   # found, then silence
    w.start()
    with pytest.raises(W.WarmError, match="timed out"):
        w.run("s4")                                                          # this side stops waiting for "running"
    st = w.status()
    rid = st["runs"][0]["run_id"]
    assert st["state"] == "ready" and st["used"] == ["s4"] and not st["runs"][0].get("not_started")     # it may have started: not offered again
    assert st["busy_inside"] == 1 and m.cd.startswith("run:")               # found: its disc is NOT taken out
    assert "still going inside" in w.can_run("s1")
    with pytest.raises(W.WarmError, match="still going inside"):
        w.run("s1")
    with pytest.raises(W.WarmError, match="still going inside the test machine"):
        w.stop()
    clock.t = st["ready_until"] + 5                                          # the session's time is up ...
    assert not w.due() and "shutdown" not in m.calls                         # ... and still no shutdown into the test
    with pytest.raises(W.WarmError, match="still going inside"):
        w.stop("time is up")
    m.say(rid, "running (calm)")
    assert not w.due() and w.status()["busy_inside"] == 1
    m.say(rid, "done ok left=0")                                             # the launcher says the test is over
    assert w.due() and w.status()["busy_inside"] == 0
    assert w.stop("time is up") is True and m.state_now == "poweroff"


def test_a_launcher_that_never_says_the_end_does_not_keep_the_machine_on_for_ever(tmp_path):
    m = Machine(left=300)
    w, m, clock = session(tmp_path, m, timeouts={"run": 40})
    m.script = lambda rid, scenario, n: (m.say(rid, "seen-cd"), m.say(rid, f"found-cd {scenario}")) and True
    w.start()
    with pytest.raises(W.WarmError):
        w.run("s4")
    until = w.status()["ready_until"]
    clock.t = until + W.WORST_TEST_S - 5
    assert not w.due()
    clock.t = until + W.WORST_TEST_S + 1                                     # the longest a test may take has passed: nothing can be cut off
    assert w.due() and w.stop("time is up") is True
    w2, m2, clock2 = session(tmp_path / "b", Machine(left=300), timeouts={"run": 40})
    m2.script = lambda rid, scenario, n: (m2.say(rid, "seen-cd"), m2.say(rid, f"found-cd {scenario}")) and True
    w2.start()
    with pytest.raises(W.WarmError):
        w2.run("s4")
    m2.say(w2.status()["session_id"], "warm-ended (time is up; no test was running)")      # or the launcher itself says it ended
    assert w2.due() and w2.stop("time is up") is True


def test_only_the_three_batch_scenarios_and_only_when_ready(tmp_path):
    w, m, _ = session(tmp_path)
    assert "is off" in w.can_run("s1")
    with pytest.raises(W.WarmError):
        w.run("s1")
    w.start()
    for bad in ("s2", "s3", "b18", "c1", "../x", ""):
        assert "only S1, S4, S5" in w.can_run(bad)
    with w.lock:
        w.state = "running"
    assert "is running" in w.can_run("s4")                                    # one test at a time
    assert not any(c.startswith("cd run:") for c in m.calls)


def test_no_test_starts_when_the_time_is_up_and_the_machine_is_shut_down_by_itself(tmp_path):
    w, m, clock = session(tmp_path, Machine(left=120))
    w.start()
    assert w.can_run("s1") is None and not w.due()
    clock.t += 121
    assert "too little time" in w.can_run("s1") and w.due()
    with pytest.raises(W.WarmError, match="too little time"):
        w.run("s1")
    assert w.stop("time is up") is True
    st = w.status()
    assert st["state"] == "off" and st["ended"] == "time is up" and st["seconds_left"] is None
    assert [c for c in m.calls if c != "state"][-2:] == ["shutdown", "cd emptydrive"] and m.state_now == "poweroff"


def slow_start(m, clock, seconds):
    """The made-up machine takes `seconds` from its start to the launcher's "ready" (a real one: 8 to 10 minutes)."""
    real = m.start
    m.start = lambda headless=False: (real(headless), clock.sleep(seconds))[0]


def test_tests_can_be_started_only_in_the_first_minutes_after_the_machine_was_started(tmp_path):
    """THE STOP-GAP (2026-11-21). Every disc change made up to 14 minutes after the machine's start was read
    in 15 to 45 s; both made later hung for minutes. So no test is started later than START_TESTS_FOR_S
    after the start, whatever time the launcher itself still has."""
    assert W.START_TESTS_FOR_S == 12 * 60                                       # PROOF 2026-11-21: 12, not 13 (77 s of margin, not 17)
    m = Machine(left=900, after_run_left=800)                                 # the launcher's own count: a quarter of an hour
    w, m, clock = session(tmp_path, m)
    slow_start(m, clock, 480)                                                # ready 8 minutes after the start
    t_start = clock.t
    w.start()
    st = w.status()
    limit = t_start + W.START_TESTS_FOR_S
    assert st["tests_until"] == limit and st["ready_until"] == limit and st["early_limit"] is True and st["tests_for_min"] == 12
    assert st["seconds_left"] == pytest.approx(240, abs=3)                    # four minutes for starting tests, not the launcher's fifteen
    run = w.run("s1")                                                        # after it the launcher says "left=800": the limit stays
    st = w.status()
    assert run["step"] == "done" and st["ready_until"] == limit and st["early_limit"] is True
    clock.t = limit - 1
    assert w.can_run("s4") is None and not w.due()
    clock.t = limit + 1
    assert "too little time" in w.can_run("s4") and w.due()                   # the end: no test starts, and the machine is shut down by itself
    with pytest.raises(W.WarmError, match="too little time"):
        w.run("s4")
    assert not any(c.startswith("cd run:") and c.endswith(":s4") for c in m.calls)
    assert w.stop("time is up") is True and m.state_now == "poweroff"


def test_the_launchers_own_shorter_time_still_counts_and_a_late_start_leaves_no_time(tmp_path):
    w, m, clock = session(tmp_path, Machine(left=120))                       # the launcher has less time than the early limit: its count wins
    w.start()
    st = w.status()
    assert st["seconds_left"] == 120 and st["early_limit"] is False and st["tests_until"] is not None
    m2 = Machine(left=900)
    w2, m2, clock2 = session(tmp_path / "b", m2)
    slow_start(m2, clock2, W.START_TESTS_FOR_S + 30)                         # a start so slow that the limit has passed at "ready"
    w2.start()
    st = w2.status()
    assert st["state"] == "ready" and st["seconds_left"] == 0 and "too little time" in w2.can_run("s1") and w2.due()


def test_the_early_limit_survives_a_restart_of_the_dashboard(tmp_path):
    import json
    m = Machine(left=900)
    w, m, clock = session(tmp_path, m, owner="dashboard")
    slow_start(m, clock, 480)
    t_start = clock.t
    w.start()
    limit = t_start + W.START_TESTS_FOR_S
    with open(w.notes, encoding="utf-8") as f:
        assert json.load(f)["tests_until"] == limit
    w2 = W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0, servers=lambda: (0, ""),
                       build_warm=lambda sid: f"warm:{sid}", build_run=lambda sid, rid, s: f"run:{sid}:{rid}:{s}", owner="dashboard")
    assert w2.adopt() == "adopted" and w2.status()["tests_until"] == limit
    m.say(w.status()["session_id"], "warm-ready (calm) left=900")            # the launcher's count arrives again while the new dashboard listens
    w2.due()
    st = w2.status()
    assert st["state"] == "ready" and st["ready_until"] == limit and st["early_limit"] is True
    # ... and a session's notes of before the stop-gap (no limit in them) are taken as they are: nothing is invented
    w2.tests_until = None
    assert w2._capped(limit + 500) == limit + 500


def test_the_launcher_ending_itself_is_noticed(tmp_path):
    w, m, _ = session(tmp_path)
    w.start()
    assert not w.due()
    m.say(w.status()["session_id"], "warm-ended (time is up; no test was running)")
    assert w.due()


def test_a_refusal_by_the_launcher_is_shown_in_its_own_words_and_the_machine_stays_up(tmp_path):
    w, m, _ = session(tmp_path, Machine(refuse="a file differs from the warm CD's: run_scenario.ps1"))
    w.start()
    with pytest.raises(W.WarmError, match="refused a file differs from the warm CD's: run_scenario.ps1"):
        w.run("s1")
    st = w.status()
    assert st["state"] == "ready" and "refused" in st["error"] and st["used"] == ["s1"] and st["runs"][0]["step"] == "failed"
    assert m.state_now == "running" and "shutdown" not in m.calls


def test_stop_is_refused_only_while_a_test_runs_or_the_machine_starts(tmp_path):
    w, m, _ = session(tmp_path)
    w.start()
    for busy in ("running", "starting"):
        with w.lock:
            w.state = busy
        with pytest.raises(W.WarmError):
            w.stop()
    with w.lock:
        w.state = "ready"
    assert w.stop() is True and m.state_now == "poweroff"


def test_an_official_run_environment_is_refused_before_the_machine_is_touched(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    w, m, _ = session(tmp_path)
    with pytest.raises(W.WarmError, match="practice runs only"):
        w.start()
    st = w.status()
    assert m.calls == [] and st["state"] == "off" and "practice runs only" in st["error"]     # untouched: nothing of ours to shut down


def test_a_machine_that_is_not_off_is_left_alone(tmp_path):
    w, m, _ = session(tmp_path, Machine(state="running"))
    with pytest.raises(W.WarmError, match="must be switched off first"):
        w.start()
    assert m.calls == ["state"]                                               # asked once, changed nothing
    assert w.status()["state"] == "off" and w.stop() is None                  # and "stop" leaves that machine alone too
    assert m.calls == ["state"] and m.state_now == "running"


def test_a_start_that_fails_after_the_restore_shuts_the_machine_down(tmp_path):
    m = Machine()
    m.start_real = m.start

    def never_ready(headless=False):
        m.calls.append("start")
        m.state_now = "running"
        m.say("-", "starter: no run CD, nothing to do")

    m.start = never_ready
    w, m, _ = session(tmp_path, m, timeouts={"launcher": 5, "ready": 5})
    with pytest.raises(W.WarmError, match="timed out"):
        w.start()
    assert w.status()["state"] == "failed" and "shutdown" in m.calls and m.state_now == "poweroff"


def test_the_screen_can_ask_as_often_as_it_likes_without_a_virtualbox_call(tmp_path):
    w, m, _ = session(tmp_path)
    w.start()
    before = list(m.calls)
    for _ in range(50):
        w.status()
        w.can_run("s1")
        w.due()
    assert m.calls == before


def test_warm_runs_leave_no_official_run_summary(tmp_path):
    w, m, _ = session(tmp_path)
    w.start()
    w.run("s5")
    w.stop()
    rec = tmp_path / "rec"
    assert not (rec / "scenario_runs").exists()
    notes = (rec / "live" / "warm" / "session.json").read_text(encoding="utf-8")
    assert '"practice": true' in notes and '"s5"' in notes


# ---------------------------------------------------------------- the CDs

def test_a_cd_copy_is_frozen_in_its_own_folder_with_only_the_named_files_replaced(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name, text in (("run_scenario.ps1", "RUN"), ("note.txt", "scenario=s1"), ("launcher.ps1", "FROZEN"), ("fetch.exe", "EXE")):
        (src / name).write_text(text, encoding="ascii")
    mine = tmp_path / "warm_launcher.ps1"
    mine.write_text("WARM", encoding="ascii")
    viso = tmp_path / "run.viso"
    viso.write_text("--iprt-iso-maker-file-marker-bourne-sh 1234 --file-mode=0444 --dir-mode=0555 "
                    f"'/run_scenario.ps1={src / 'run_scenario.ps1'}' '/AUTORUN_SCENARIO.txt={src / 'note.txt'}' "
                    f"'/scenario_launcher.ps1={src / 'launcher.ps1'}' '/s1/s1_fetch.exe={src / 'fetch.exe'}'", encoding="ascii")
    out = W.copy_cd(str(viso), str(tmp_path / "w"), "warm.viso", files={W.LAUNCHER_ON_CD: str(mine)},
                    texts={W.NOTE: "scenario=s1\r\nrun_id=20261121-000000-abcd\r\nwarm=1\r\npractice=1"})
    cd = tmp_path / "w" / "cd"
    assert (cd / "run_scenario.ps1").read_text() == "RUN" and (cd / "s1" / "s1_fetch.exe").read_text() == "EXE"     # unchanged copies
    assert (cd / "scenario_launcher.ps1").read_text() == "WARM"                                                    # ours, under the starter's name
    assert "warm=1" in (cd / "AUTORUN_SCENARIO.txt").read_text() and "practice=1" in (cd / "AUTORUN_SCENARIO.txt").read_text()
    text = open(out, encoding="ascii").read()
    assert str(src) not in text and text.count(str(cd)) == 4 and "1234" not in text      # points only at the copies; a new disc id
    (src / "run_scenario.ps1").write_text("CHANGED LATER", encoding="ascii")
    assert (cd / "run_scenario.ps1").read_text() == "RUN"                                # a mounted CD never changes under the VM


def test_the_warm_cd_is_built_by_the_frozen_builder_and_refuses_its_failure(tmp_path, monkeypatch):
    asked = []
    monkeypatch.setattr(W, "copy_cd", lambda *a, **k: asked.append((a, k)) or "warm.viso")
    assert W.build_warm_cd("20261121-000000-abcd", powershell=lambda *a: (asked.append(a), (0, "ok"))[1]) == "warm.viso"
    assert asked[0] == ("make_scenario_cd.ps1", "-RunId", "20261121-000000-abcd", "-Scenario", "s1")
    assert asked[1][1]["files"] == {"/scenario_launcher.ps1": W.LAUNCHER} and "warm=1" in asked[1][1]["texts"]["/AUTORUN_SCENARIO.txt"]
    with pytest.raises(W.WarmError, match="building the warm CD failed"):
        W.build_warm_cd("x", powershell=lambda *a: (1, "boom"))
    with pytest.raises(W.WarmError, match="building the run CD failed"):
        W.build_run_cd("x", "y", "s1", powershell=lambda *a: (1, "boom"))


# ---------------------------------------------------------------- the launcher (read as text: it only runs in the VM)

def launcher_code():
    with open(LAUNCHER, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)                           # the header comment
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines())


def test_the_launcher_starts_exactly_one_thing_a_cds_own_run_scenario():
    code = launcher_code()
    calls = [l.strip() for l in code.splitlines() if re.search(r"(^|[\s;{(])&\s", l)]
    assert calls == ["& powershell.exe -NoProfile -File (Join-Path $Root 'run_scenario.ps1') -Scenario $scenario -RunId $runId"]
    for banned in ("Start-Process", "Invoke-Expression", "iex ", "Invoke-Command", "Start-Job", "cmd.exe", "cmd /c", "wmic", "schtasks",
                   "Diagnostics.Process]::Start", "Invoke-WmiMethod", "Invoke-CimMethod", "Invoke-WebRequest", "DownloadString", "DownloadFile",
                   "Add-Type", "EncodedCommand", "guestproperty", "VBoxControl"):
        assert banned.lower() not in code.lower(), banned
    assert "powershell" not in code.replace(calls[0], "").lower()             # no second PowerShell anywhere


def test_the_launcher_talks_only_to_the_laptops_receiver_and_never_on_a_timer():
    code = launcher_code()
    urls = re.findall(r"http://[^\s\"']+", code)
    assert urls and all(u.startswith("http://${hostAddr}:8770/") for u in urls)
    assert "$hostAddr = '10.0.2.2'" in code
    loop = code[code.index("$refused = @{}"):]
    states = re.findall(r"State\s+[\"(']+([\w-]+)", loop)
    # every word the loop can say, each at most once per run CD (or once per change of the waiting reason): no heartbeat.
    # 2026-11-21 added "seen-cd" and "failed not-started" (once per run CD each).
    assert sorted(states) == sorted(["waiting", "warm-ended", "seen-cd", "refused", "found-cd", "failed", "running", "failed", "flushing", "done"])
    assert "Invoke-RestMethod" not in loop                                    # the loop itself posts only through State


def test_the_launcher_checks_before_it_runs_and_refuses_everything_else():
    code = launcher_code()
    run_at = code.index("& powershell.exe")
    for must in ("Get-Service -Name VBoxService", "Test-Path 'C:\\LabTools'", "$note.warm -ne '1'", "$allowed -notcontains $scenario",
                 "elseif ($n.batch)", "$trusted[$rel]", "Get-FileHash", "(SecondsLeft) -lt $worstSec", "$doneList"):
        assert must in code and code.index(must) < run_at, must              # every guard comes before the one start
    assert re.search(r"\$allowed = @\('s1', 's4', 's5'\)", code) and tuple(re.findall(r"'(s\d)'", re.search(r"\$allowed = @\(([^)]*)\)", code).group(1))) == W.ALLOWED
    assert re.search(r"param\(\[Parameter\(Mandatory\)\]\[string\]\$Root\)", code)                    # one parameter: no switch that skips a guard
    assert "$endAfterMin = 27" in code and "if ((SecondsLeft) -le 0)" in code                         # it ends itself before Windows stops the task
    assert "if ($why) {" in code and code.index("if ($why) {") < run_at                               # a refusal never falls through to the run


def test_the_launcher_says_it_has_seen_a_cd_before_reading_it_and_looks_again_before_starting():
    """The two rules the laptop side leans on (demo/warm_vm.py _await_found), in the launcher's own text."""
    code = launcher_code()
    seen, first_read, found, look, start = (code.index(x) for x in (
        "State 'seen-cd'", "Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction Stop", 'State "found-cd $scenario"',
        "$still = [string](ReadNote $noteFile).run_id", "& powershell.exe"))
    assert seen < first_read < found < look < start                           # said before the files are read; looked again right before the start
    assert "-not $seenIds.ContainsKey($id)" in code and "$seenIds[$id] = $true" in code                 # once per run CD
    gone = code[look:start]
    assert "if ($still -ne $runId) { State 'failed not-started" in gone and "continue }" in gone         # a gone or changed disc: nothing starts
    assert "try { $still = [string](ReadNote $noteFile).run_id } catch {}" in code                      # a drive that can't be read counts as gone
    assert W.BEGUN == ("found-cd", "running", "flushing") and "failed not-started".startswith(W.OVER[1])


def test_the_launchers_clock_counts_from_the_starter_tasks_own_start_and_ends_before_windows_would():
    """Checked against the real session of 2026-11-21 (17:24 local), where only 354 s were left at "ready":
    the launcher counts from its own process's start, and that process IS the scheduled task's (the frozen
    starter runs the launcher inside itself; the task starts 3 minutes after logon). Windows stops the task
    30 minutes after that same moment. So the count is the right one; the time was lost because the whole
    laptop was in Modern Standby for 9 min 38 s (the test machine stood still for 581 s), not to the clock."""
    with open(LAUNCHER, encoding="utf-8") as f:
        text = f.read()
    assert "$startedAt = (Get-Process -Id $PID).StartTime" in text and "$endAt = $startedAt.AddMinutes($endAfterMin)" in text
    minutes = int(re.search(r"\$endAfterMin = (\d+)", text).group(1))
    assert minutes == W.LAUNCHER_LIFE_S // 60 and 20 <= minutes < 30                 # the laptop side counts the same, and it ends before the task's 30
    with open(os.path.join(ROOT, "tools", "vm", "launcher_stub.ps1"), encoding="utf-8") as f:
        stub = f.read()
    assert "& (Join-Path $root 'scenario_launcher.ps1') -Root $root" in stub           # called inside the starter's own process: same $PID
    with open(os.path.join(ROOT, "tools", "vm", "vm_guest_setup.ps1"), encoding="utf-8") as f:
        setup = f.read()
    assert "-ExecutionTimeLimit (New-TimeSpan -Minutes 30)" in setup                   # the limit the launcher stays under
    worst = re.search(r"\$worstSec = \$calmCapSec \+ (\d+) \+ (\d+) \+ (\d+)", text)
    assert worst and 120 + sum(int(x) for x in worst.groups()) <= W.WORST_TEST_S      # the laptop waits at least as long as a test may take

