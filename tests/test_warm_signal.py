"""The warm test machine's NO-DISC-CHANGE path (demo/warm_vm.py with the switch on, demo/warm/warm_launcher_signal.ps1).

A trial behind a switch, OFF BY DEFAULT (PROOF and Yousif, 2026-11-21). The default stays "a CD per test"
with its stop-gap; that path's tests are in tests/test_warm_vm.py and are not touched by this file.

The rule this path is built to (PROOF): "The only thing the laptop can send the test machine is the name of
one of this session's three pre-checked tests." Here: the warm CD stays in the drive, its note carries one
run id per test and the SHA-256 of its files, and a click sets ONE VirtualBox guest property to that test's
run id. Every test here uses a made-up VirtualBox; none reaches the real VBoxManage (an autouse trap)."""

import hashlib
import json
import os
import re
import subprocess

import pytest
from fastapi.testclient import TestClient

from engine.dashboard import warm as WM
from engine.dashboard.app import create_app
from tests.test_dashboard_warm import BANNED, OneBoot, until
from tests.test_warm_vm import ROOT, Clock, Machine, W, session as cd_session, slow_start

LAUNCHER = os.path.join(ROOT, "demo", "warm", "warm_launcher_signal.ps1")


@pytest.fixture(autouse=True)
def no_real_programs(monkeypatch):
    """No test here may start a program or reach the real VBoxManage."""
    started = []

    def trap(*args, **kwargs):
        started.append(args[0] if args else kwargs.get("args"))
        raise AssertionError(f"a test tried to start a real program: {started[-1]!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    monkeypatch.setattr(os, "system", trap)
    monkeypatch.setattr(W.R.VBox, "call", trap)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    monkeypatch.delenv(W.NO_DISC_ENV, raising=False)
    from engine.dashboard import checks
    monkeypatch.setattr(checks, "vm_running", lambda *a, **k: False)
    monkeypatch.setattr(checks.Checks, "count_once", lambda self: None)
    yield started
    assert started == []


class SignalMachine(Machine):
    """The made-up VirtualBox of tests/test_warm_vm.py, plus the ONE VBoxManage call this path adds: the signal.
    It plays the signal launcher's part: when the signal names a test, it runs it (once per run id)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.ids, self.signalled, self.done, self.signal = {}, {}, set(), None
        self.fail_unset, self.fail_set = False, 0            # VBoxManage itself failing: every take-away / the next n namings

    def call(self, *args, check=True):
        """Only `guestproperty set <vm> <SIGNAL> <run id> --flags TRANSIENT` and `guestproperty unset <vm> <SIGNAL>`."""
        if args[:2] == ("guestproperty", "unset"):
            assert args[2:] == (self.vm, W.SIGNAL) and check is True, args      # a take-away that fails must be NOTICED (never check=False)
            if self.fail_unset:
                self.calls.append("signal off FAILED")
                raise W.R.StepFailed("VBoxManage guestproperty unset failed (exit 1): made up")
            self.calls.append("signal off")
            self.signal = None
            return 0, ""
        assert args[:4] == ("guestproperty", "set", self.vm, W.SIGNAL) and args[5:] == ("--flags", "TRANSIENT") and len(args) == 7, args
        value = args[4]
        assert value in self.ids.values(), f"a signal that is not one of the session's three run ids: {value!r}"
        scenario = next(s for s, i in self.ids.items() if i == value)
        if self.fail_set:
            self.fail_set -= 1
            self.calls.append(f"signal {scenario} FAILED")
            raise W.R.StepFailed("VBoxManage guestproperty set failed (exit 1): made up")
        self.calls.append(f"signal {scenario}")
        self.signal = value
        if self.state_now != "running":
            return 0, ""
        self.signalled[value] = self.signalled.get(value, 0) + 1
        if self.script and self.script(value, scenario, self.signalled[value]):
            return 0, ""
        if self.miss:
            self.miss -= 1
        elif self.refuse:
            self.say(value, f"refused {self.refuse}")
        elif value not in self.done:                         # (the launcher starts a run id once)
            self.runs_it(value, scenario)
        return 0, ""

    def runs_it(self, rid, scenario):
        """The launcher's words for a test it picked up, and the test it then ran to the end."""
        self.done.add(rid)
        self.say(rid, f"picked-up {scenario}")
        self.say(rid, "running (calm)")
        self.tails["vmruns"].queue.append({"type": "SCENARIO_RUN", "run_id": rid, "start": "a", "end": "b", "exit_code": 0})
        self.say(rid, "flushing")
        self.say(rid, f"done ok left={self.after_run_left}")
        self.tails["vm"].queue.append({"type": "FILE_HASH", "data": {"TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{rid}-ok.txt"}})


def never(*a, **k):
    raise AssertionError("the CD path's builder was called on the no-disc-change path")


def session(tmp_path, machine=None, no_disc=True, **kw):
    m = machine or SignalMachine()
    clock = Clock()

    def build_signal(sid, ids):                              # the note's run ids reach the made-up launcher the way the CD carries them
        m.ids = dict(ids)
        return f"warm:{sid}"

    w = W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0, servers=lambda: (0, ""),
                      build_warm=never, build_run=never, build_signal=build_signal, no_disc=no_disc, **kw)
    return w, m, clock


# ---------------------------------------------------------------- the switch

def test_the_switch_is_off_by_default_and_the_default_path_never_touches_the_signal(tmp_path, monkeypatch):
    w, m, clock = cd_session(tmp_path)                                         # exactly what tests/test_warm_vm.py uses: no switch given
    assert w.no_disc is False and w.status()["no_disc"] is False
    w.start()
    run = w.run("s1")
    assert run["step"] == "done" and any(c.startswith("cd run:") for c in m.calls) and not any("signal" in c for c in m.calls)
    assert not hasattr(m, "call") and w.status()["run_ids"] == {} and w.status()["tests_until"] is not None     # a CD per test, with its early limit
    # the switch: the environment variable (only "1"), or the argument, which wins
    assert W.NO_DISC_ENV == "ANALYSTLAB_WARM_NO_DISC"
    for value, want in (("1", True), ("0", False), ("", False), ("yes", False)):
        monkeypatch.setenv(W.NO_DISC_ENV, value)
        assert W.WarmSession(vbox=m, recordings=str(tmp_path / "x"), tail=m.tail).no_disc is want, value
    assert W.WarmSession(vbox=m, recordings=str(tmp_path / "x"), tail=m.tail, no_disc=False).no_disc is False
    monkeypatch.delenv(W.NO_DISC_ENV)
    assert W.WarmSession(vbox=m, recordings=str(tmp_path / "x"), tail=m.tail, no_disc=True).no_disc is True


# ---------------------------------------------------------------- the session's rules on this path

def test_start_puts_the_one_cd_in_and_makes_a_run_id_per_test(tmp_path):
    w, m, clock = session(tmp_path)
    w.start()
    st = w.status()
    sid = st["session_id"]
    assert st["state"] == "ready" and st["no_disc"] is True and st["seconds_left"] == 600
    assert m.calls == ["state", "snapshots", "restore lived-in", "cpus 1", f"cd warm:{sid}", "start headless=True"]     # nothing is signalled at the start
    ids = st["run_ids"]
    assert tuple(ids) == W.ALLOWED and len({sid, *ids.values()}) == 4 and m.ids == ids         # one run id per test, made at the start, on the CD's note
    assert all(re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{4}", i) for i in ids.values())
    assert st["tests_until"] is not None and st["early_limit"] is False                      # the early limit is set on this path too; here the launcher's own time is the shorter one


def test_a_test_runs_once_and_no_disc_is_changed(tmp_path):
    w, m, clock = session(tmp_path)
    w.start()
    n = len(m.calls)
    run = w.run("S1")
    st = w.status()
    assert run["step"] == "done" and run["barrier"] == "ok" and run["practice"] is True and run["run_record"]["exit_code"] == 0
    assert run["run_id"] == st["run_ids"]["s1"]                                 # the id the CD's note carries, not a new one
    assert st["state"] == "ready" and st["used"] == ["s1"] and st["seconds_left"] == 300
    assert m.calls[n:] == ["signal s1", "signal off"] and m.signal is None      # the test is named, then the signal is taken away: no CD is touched
    assert "already ran" in w.can_run("s1") and w.can_run("s4") is None
    with pytest.raises(W.WarmError, match="already ran"):
        w.run("s1")
    second = w.run("s4")
    assert second["run_id"] == st["run_ids"]["s4"] != run["run_id"] and w.status()["used"] == ["s1", "s4"]
    assert not any(c.startswith("cd ") for c in m.calls[n:])                   # the warm CD stays in for the whole session


def test_the_signal_can_only_be_one_of_the_sessions_three_run_ids(tmp_path):
    """PROOF's condition: the value can only be one of this session's three run ids, or nothing."""
    w, m, clock = session(tmp_path)
    w.start()
    n = len(m.calls)
    sid = w.status()["session_id"]
    for bad in ("s1", "S1", "none", sid, "20261121-000000-ffff", "s1;calc", "..\\x", "run_scenario.ps1", "", w.status()["run_ids"]["s1"] + " x"):
        with pytest.raises(W.WarmError, match="can only be one of this session's three run ids"):
            w._signal(bad)
    assert m.calls[n:] == [] and m.signal is None                               # none of that reached VirtualBox
    assert W.SIGNAL == "/AnalystLab/Warm/Run" and W.SIGNAL_FLAGS == ("--flags", "TRANSIENT")     # a fixed name; the flag as two words (see _signal)


def test_a_signal_the_launcher_missed_is_taken_away_and_set_again(tmp_path):
    # the launcher sleeps in a wait that only a CHANGE of the property ends; one that falls between its look and its wait is missed
    w, m, clock = session(tmp_path, SignalMachine(miss=2))
    w.start()
    n, t0 = len(m.calls), clock.t
    run = w.run("s1")
    assert run["step"] == "done" and m.signalled[run["run_id"]] == 3
    assert m.calls[n:] == ["signal s1", "signal off", "signal s1", "signal off", "signal s1", "signal off"]
    assert 2 * W.SIGNAL_EVERY <= clock.t - t0 <= 2 * W.SIGNAL_EVERY + 12


def test_a_test_never_picked_up_fails_in_plain_words_is_called_off_and_can_be_clicked_again(tmp_path):
    w, m, clock = session(tmp_path, SignalMachine(miss=9999))
    w.start()
    t0 = clock.t
    listening = []                                                           # what the signal says while this side listens for a late pick-up
    clock.at(t0 + W.TIMEOUTS["picked"] + W.SIGNAL_EVERY + 8, lambda: listening.append(m.signal))
    with pytest.raises(W.WarmError) as e:
        w.run("s1")
    assert listening == [None]                                               # taken away FIRST, then listened: never "did not run" with the signal standing
    assert str(e.value) == W.NOT_RUN["not_picked"].format(minutes=4) and "timed out" not in str(e.value) and e.value.why == "not_picked"
    assert W.TIMEOUTS["picked"] <= clock.t - t0 <= W.TIMEOUTS["picked"] + W.SIGNAL_EVERY + W.TAKE_BACK_S + 12
    assert m.calls[-1] == "signal off" and m.signal is None
    st = w.status()
    run = st["runs"][0]
    assert st["state"] == "ready" and st["error"] == str(e.value) and run["step"] == "failed" and run["not_started"] is True and run["why"] == "not_picked"
    assert st["used"] == [] and w.can_run("s1") is None                       # its program never started: it can be clicked again
    m.miss = 0
    again = w.run("s1")
    assert again["step"] == "done" and again["run_id"] == run["run_id"] and w.status()["used"] == ["s1"] and len(w.status()["runs"]) == 2


def test_a_signal_that_cannot_be_taken_back_is_never_called_did_not_run(tmp_path):
    """The take-back is not assumed. If VBoxManage fails to take the signal away, the signal may still stand,
    the launcher's last look would pass, and the test could start later: so nothing is claimed, the test is
    not offered again, and the words say it may still start."""
    w, m, clock = session(tmp_path, SignalMachine(miss=9999))
    m.fail_unset = True
    w.start()
    with pytest.raises(W.WarmError) as e:
        w.run("s1")
    msg = str(e.value)
    assert "could not take back the signal" in msg and "may still start" in msg and "did not run" not in msg and e.value.why is None
    st = w.status()
    assert st["used"] == ["s1"] and not st["runs"][0].get("not_started") and "already ran" in w.can_run("s1")     # not offered again
    assert m.signal == st["run_ids"]["s1"] and "signal off FAILED" in m.calls                                      # it does still stand
    # the same when it fails at the very end of the waiting (the give-up), after every earlier take-away worked
    (tmp_path / "b").mkdir()
    w2, m2, clock2 = session(tmp_path / "b", SignalMachine(miss=9999))
    w2.start()
    clock2.at(clock2.t + W.TIMEOUTS["picked"] - 2, lambda: setattr(m2, "fail_unset", True))
    with pytest.raises(W.WarmError) as e2:
        w2.run("s4")
    assert "may still start" in str(e2.value) and "did not run" not in str(e2.value) and w2.status()["used"] == ["s4"]
    # and when the launcher then does pick it up, the guard holds as for any test that is going
    m2.say(w2.status()["run_ids"]["s4"], "picked-up s4")
    w2.due()
    assert w2.status()["busy_inside"] == 1 and "still going inside" in w2.can_run("s1")


def test_a_first_naming_that_virtualbox_refuses_is_did_not_run_only_when_the_signal_is_known_clear(tmp_path):
    m = SignalMachine()
    w, m, clock = session(tmp_path, m)
    w.start()
    n = len(m.calls)
    m.fail_set = 1
    with pytest.raises(W.WarmError) as e:
        w.run("s5")
    assert str(e.value) == W.NOT_RUN["not_named"] and e.value.why == "not_named"
    assert m.calls[n:] == ["signal s5 FAILED", "signal off"] and m.signal is None      # nothing was ever said, and the property is known to be clear
    st = w.status()
    assert st["used"] == [] and st["runs"][0]["not_started"] is True and w.can_run("s5") is None
    assert w.run("s5")["step"] == "done"                                             # clicked again: it runs
    # VirtualBox refusing the naming AND the take-away: nothing is known, nothing is claimed
    m.fail_set, m.fail_unset = 1, True
    with pytest.raises(W.WarmError) as e:
        w.run("s4")
    assert "may still start" in str(e.value) and "did not run" not in str(e.value) and "s4" in w.status()["used"]


def test_a_test_picked_up_while_it_is_called_off_ends_in_the_launchers_own_not_started_and_can_run_later(tmp_path):
    """The launcher woke just as this side gave up. It says "picked-up"; then, right before starting, it looks
    at the signal once more, finds the test called off and starts nothing."""
    m = SignalMachine()
    w, m, clock = session(tmp_path, m)

    def launcher(rid, scenario, n):
        if n == 1:                                                           # picked up 3 s after this side stopped waiting ...
            clock.at(clock.t + W.TIMEOUTS["picked"] + 12, lambda: m.say(rid, f"picked-up {scenario}"))
            clock.at(clock.t + W.TIMEOUTS["picked"] + 40, lambda: m.say(rid, "failed not-started (the laptop called the test off, or the warm CD was gone, before the test started)"))
        return True

    m.script = launcher
    w.start()
    with pytest.raises(W.WarmError) as e:
        w.run("s1")
    assert str(e.value) == W.NOT_RUN["taken_back"] and "launcher reported" not in str(e.value) and e.value.why == "taken_back"
    st = w.status()
    assert m.signal is None and st["used"] == [] and st["runs"][0]["not_started"] is True and st["runs"][0]["why"] == "taken_back"
    assert st["busy_inside"] == 0 and w.can_run("s1") is None
    m.script = None                                                          # clicked again: the same run id, and the first try's words are history
    again = w.run("s1")
    assert again["step"] == "done" and again["run_id"] == st["runs"][0]["run_id"] and w.status()["used"] == ["s1"] and w.status()["error"] is None


def test_a_test_the_launcher_says_is_still_going_blocks_a_new_test_and_the_shutdown(tmp_path):
    m = SignalMachine(left=300)
    w, m, clock = session(tmp_path, m, timeouts={"run": 40})
    m.script = lambda rid, scenario, n: (m.say(rid, f"picked-up {scenario}"), True)[1]       # picked up, then silence
    w.start()
    with pytest.raises(W.WarmError, match="timed out"):
        w.run("s4")                                                          # this side stops waiting for "running"
    st = w.status()
    rid = st["runs"][0]["run_id"]
    assert st["state"] == "ready" and st["used"] == ["s4"] and not st["runs"][0].get("not_started")     # it may have started: not offered again
    assert st["busy_inside"] == 1 and m.calls[-1] == "signal off"            # and the signal is taken away, whatever went wrong
    assert "still going inside" in w.can_run("s1")
    with pytest.raises(W.WarmError, match="still going inside"):
        w.stop()
    clock.t = st["ready_until"] + 5
    assert not w.due() and "shutdown" not in m.calls                         # the session's time is up, and still no shutdown into the test
    m.say(rid, "running (calm)")
    assert not w.due() and w.status()["busy_inside"] == 1
    m.say(rid, "done ok left=0")
    assert w.due() and w.status()["busy_inside"] == 0 and w.stop("time is up") is True and m.state_now == "poweroff"


def test_a_session_keeps_its_own_path_across_a_restart_whatever_the_new_dashboards_switch_says(tmp_path):
    w, m, clock = session(tmp_path, owner="dashboard")
    w.start()
    w.run("s5")
    ids = w.status()["run_ids"]
    with open(w.notes, encoding="utf-8") as f:
        notes = json.load(f)
    assert notes["run_ids"] == ids and notes["no_disc"] is True
    # the dashboard comes back with the switch OFF: the session it takes back is still a no-disc-change session
    w2 = W.WarmSession(vbox=m, recordings=str(tmp_path / "rec"), tail=m.tail, clock=clock, sleep=clock.sleep, poll=1.0, servers=lambda: (0, ""),
                       build_warm=never, build_run=never, build_signal=never, owner="dashboard", no_disc=False)
    assert w2.adopt() == "adopted" and w2.status()["no_disc"] is True and w2.status()["run_ids"] == ids
    with w2.lock:
        w2.state = "ready"
    run = w2.run("s1")
    assert run["step"] == "done" and run["run_id"] == ids["s1"] and not any(c.startswith("cd run:") for c in m.calls)
    assert w2.stop() is True
    w2.claim_start()                                                         # ... and the NEXT session it starts follows its own switch again
    assert w2.no_disc is False
    # the other way round: a CD-path session taken back by a dashboard whose switch is on stays a CD-path session
    (tmp_path / "b").mkdir()
    wc, mc, clockc = cd_session(tmp_path / "b", owner="dashboard")
    wc.start()
    w3 = W.WarmSession(vbox=mc, recordings=str(tmp_path / "b" / "rec"), tail=mc.tail, clock=clockc, sleep=clockc.sleep, poll=1.0, servers=lambda: (0, ""),
                       build_warm=never, build_run=lambda sid, rid, s: f"run:{sid}:{rid}:{s}", build_signal=never, owner="dashboard", no_disc=True)
    assert w3.adopt() == "adopted" and w3.status()["no_disc"] is False and w3.status()["tests_until"] == wc.status()["tests_until"]


def test_the_early_limit_holds_on_this_path_too(tmp_path):
    """PROOF, 2026-11-23. The first real trial: a test NAMED about 15 minutes after the machine's start (no
    disc changed) began and then did nothing. So the stop-gap of the CD path counts here as well: no test is
    named later than START_TESTS_FOR_S after the start, whatever time the launcher itself still has."""
    m = SignalMachine(left=900, after_run_left=800)
    w, m, clock = session(tmp_path, m)
    slow_start(m, clock, 480)                                                # ready 8 minutes after the start
    t_start = clock.t
    w.start()
    st = w.status()
    limit = t_start + W.START_TESTS_FOR_S
    assert st["tests_until"] == limit and st["ready_until"] == limit and st["early_limit"] is True and st["no_disc"] is True
    assert st["seconds_left"] == pytest.approx(240, abs=3)                    # four minutes for naming tests, not the launcher's fifteen
    assert w.run("s1")["step"] == "done" and w.status()["ready_until"] == limit     # after it the launcher says "left=800": the limit stays
    clock.t = limit - 1
    assert w.can_run("s4") is None and not w.due()
    clock.t = limit + 1
    n = len(m.calls)
    assert "too little time" in w.can_run("s4") and w.due()                   # the end: no test is named, and the machine is shut down by itself
    with pytest.raises(W.WarmError, match="too little time"):
        w.run("s4")
    assert not any("signal" in c for c in m.calls[n:]) and m.calls.count("signal s4") == 0
    # the limit survives a restart of the dashboard on this path as well
    (tmp_path / "b").mkdir()
    wa, ma, clocka = session(tmp_path / "b", SignalMachine(left=900), owner="dashboard")
    slow_start(ma, clocka, 480)
    ta = clocka.t
    wa.start()
    wb = W.WarmSession(vbox=ma, recordings=str(tmp_path / "b" / "rec"), tail=ma.tail, clock=clocka, sleep=clocka.sleep, poll=1.0, servers=lambda: (0, ""),
                       build_warm=never, build_run=never, build_signal=never, owner="dashboard", no_disc=True)
    assert wb.adopt() == "adopted" and wb.status()["no_disc"] is True and wb.status()["tests_until"] == ta + W.START_TESTS_FOR_S


# ---------------------------------------------------------------- the CD of this path

def test_the_cds_note_carries_the_run_ids_and_the_sha256_of_every_file(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "s1").mkdir(parents=True)
    for name, text in (("run_scenario.ps1", "RUN"), ("note.txt", "scenario=s1"), ("launcher.ps1", "FROZEN"), ("s1/s1_fetch.exe", "EXE")):
        (src / name).write_text(text, encoding="ascii")
    mine = tmp_path / "launcher_signal.ps1"
    mine.write_text("SIGNAL", encoding="ascii")
    viso = tmp_path / "run.viso"
    viso.write_text("--iprt-iso-maker-file-marker-bourne-sh 1234 --file-mode=0444 --dir-mode=0555 "
                    f"'/run_scenario.ps1={src / 'run_scenario.ps1'}' '/AUTORUN_SCENARIO.txt={src / 'note.txt'}' "
                    f"'/scenario_launcher.ps1={src / 'launcher.ps1'}' '/s1/s1_fetch.exe={src / 's1' / 's1_fetch.exe'}'", encoding="ascii")
    out = W.copy_cd(str(viso), str(tmp_path / "w"), "warm.viso", files={W.LAUNCHER_ON_CD: str(mine)},
                    texts={W.NOTE: "scenario=s1\r\nrun_id=20261121-000000-abcd\r\nwarm=1"}, list_into=W.NOTE, unlisted=(W.LAUNCHER_ON_CD,))
    cd = tmp_path / "w" / "cd"
    lines = (cd / "AUTORUN_SCENARIO.txt").read_bytes().decode("ascii").split("\r\n")
    assert lines[:3] == ["scenario=s1", "run_id=20261121-000000-abcd", "warm=1"] and lines[3] == "files=2"
    assert lines[4:] == [f"file_1={hashlib.sha256(b'RUN').hexdigest().upper()}:run_scenario.ps1",
                         f"file_2={hashlib.sha256(b'EXE').hexdigest().upper()}:s1\\s1_fetch.exe"]           # every file but the note and the launcher
    assert all(re.fullmatch(r"\w+=\S+", line) for line in lines)                                            # the launcher's note reader takes every line
    assert open(out, encoding="ascii").read().count(str(cd)) == 4                                           # no extra file on the CD
    # the builder of this path: the frozen builder, the SIGNAL launcher, the run ids on the note
    asked = []
    monkeypatch.setattr(W, "copy_cd", lambda *a, **k: asked.append((a, k)) or "warm.viso")
    ids = {"s1": "20261121-000001-aaaa", "s4": "20261121-000002-bbbb", "s5": "20261121-000003-cccc"}
    assert W.build_signal_cd("20261121-000000-abcd", ids, powershell=lambda *a: (asked.append(a), (0, "ok"))[1]) == "warm.viso"
    assert asked[0] == ("make_scenario_cd.ps1", "-RunId", "20261121-000000-abcd", "-Scenario", "s1")
    kw = asked[1][1]
    note = kw["texts"]["/AUTORUN_SCENARIO.txt"]
    assert kw["files"] == {"/scenario_launcher.ps1": W.LAUNCHER_SIGNAL} and W.LAUNCHER_SIGNAL.endswith("warm_launcher_signal.ps1") and "warm=1" in note
    assert all(f"\r\nrun_{s}={i}" in note for s, i in ids.items()) and kw["list_into"] == "/AUTORUN_SCENARIO.txt" and kw["unlisted"] == ("/scenario_launcher.ps1",)
    with pytest.raises(W.WarmError, match="building the warm CD failed"):
        W.build_signal_cd("x", ids, powershell=lambda *a: (1, "boom"))
    # and the default path's warm CD is built exactly as before: its own launcher, no list, no run ids
    asked.clear()
    W.build_warm_cd("20261121-000000-abcd", powershell=lambda *a: (asked.append(a), (0, "ok"))[1])
    assert asked[1][1]["files"] == {"/scenario_launcher.ps1": W.LAUNCHER} and "list_into" not in asked[1][1] and "run_s1" not in asked[1][1]["texts"]["/AUTORUN_SCENARIO.txt"]


# ---------------------------------------------------------------- the launcher of this path (read as text: it only runs in the VM)

def launcher_code():
    with open(LAUNCHER, encoding="utf-8") as f:
        text = f.read()
    assert text.isascii()
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines())


def test_the_signal_launcher_starts_only_the_cds_own_run_scenario_and_reads_the_signal():
    code = launcher_code()
    calls = [l.strip() for l in code.splitlines() if re.search(r"(^|[\s;{(])&\s", l)]
    assert calls == ["$out = & $vboxControl --nologo guestproperty get $signalName 2>$null",
                     "try { & $vboxControl --nologo guestproperty wait $signalName --timeout ([int]$seconds * 1000) 2>$null | Out-Null } catch {}",
                     "try { $ErrorActionPreference = 'Continue'; $out = & $vboxControl --nologo guestproperty get $hostInfoName 2>$null } catch { $out = @() } "
                     "finally { $ErrorActionPreference = 'Stop' }",
                     "& powershell.exe -NoProfile -File (Join-Path $Root 'run_scenario.ps1') -Scenario $scenario -RunId $runId"]
    for banned in ("Start-Process", "Invoke-Expression", "iex ", "Invoke-Command", "Start-Job", "cmd.exe", "cmd /c", "wmic", "schtasks",
                   "Diagnostics.Process]::Start", "Invoke-WmiMethod", "Invoke-CimMethod", "Invoke-WebRequest", "DownloadString", "DownloadFile",
                   "Add-Type", "EncodedCommand", "guestproperty set", "guestproperty delete", "guestproperty unset", "guestproperty enumerate"):
        assert banned.lower() not in code.lower(), banned
    assert "powershell" not in code.replace(calls[3], "").lower()             # no second PowerShell anywhere
    # VBoxControl is the Guest Additions' own tool at its two fixed places (as the frozen one-boot launcher finds it): read and wait, never set
    assert ("$vboxControl = @(\"$env:SystemRoot\\System32\\VBoxControl.exe\", 'C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxControl.exe')") in code
    with open(os.path.join(ROOT, "tools", "vm", "scenario_launcher.ps1"), encoding="utf-8") as f:
        assert "$env:SystemRoot\\System32\\VBoxControl.exe" in f.read()
    assert code.count("guestproperty") == 3 and code.count("$vboxControl =") == 1
    # the property names are fixed: ours, and VirtualBox's own version property for the self-test
    assert f"$signalName = '{W.SIGNAL}'" in code and "$hostInfoName = '/VirtualBox/HostInfo/VBoxVer'" in code
    assert code.count("$signalName") == 3 and code.count("$hostInfoName") == 2


def test_no_part_of_the_signals_value_is_ever_executed_used_as_a_path_or_passed_on():
    """PROOF's condition. The value is read into one variable, and that variable is only COMPARED."""
    code = launcher_code()
    fn = code[code.index("function Signal {"):code.index("function WaitForSignal")]
    uses = [l.strip() for l in fn.splitlines() if "$value" in l]
    assert uses == ["$value = ''",
                    "foreach ($l in @($out)) { if ([string]$l -match '^\\s*Value:\\s*(\\S.*?)\\s*$') { $value = $Matches[1] } }",
                    "if ($value -eq '') { return '' }",
                    "foreach ($a in $allowed) { if ($runIds[$a] -ceq $value) { return $a } }"]
    assert "$value" not in code.replace(fn, "")                               # it never leaves the function: only '', '?' or one of $allowed comes out
    assert fn.rstrip().endswith("return '?'\n}") and "State" not in fn and "Say" not in fn and "Join-Path" not in fn and "&" not in fn.replace("& $vboxControl --nologo guestproperty get $signalName", "")
    # outside it, the test's name is one of $allowed and its run id comes from the CD's note
    assert "if ($allowed -contains $scenario) { $id = [string]$runIds[$scenario] }" in code
    assert "$rid = [string]$note[\"run_$a\"]" in code
    # anything else is refused in plain words, once, and nothing is started
    assert "State \"refused a signal that is not one of this session's three run ids (nothing was started)\"" in code
    assert "if (-not $strange) { $strange = $true;" in code and "} else { $strange = $false }" in code


def test_the_signal_launcher_never_runs_on_a_timer_unless_the_wait_does_not_hold_and_then_says_so():
    code = launcher_code()
    urls = re.findall(r"http://[^\s\"']+", code)
    assert urls and all(u.startswith("http://${hostAddr}:8770/") for u in urls) and "$hostAddr = '10.0.2.2'" in code
    loop = code[code.index("$refused = @{}"):]
    states = re.findall(r"State\s+[\"(']+([\w-]+)", loop)
    assert sorted(states) == sorted(["waiting", "warm-ended", "refused", "refused", "picked-up", "failed", "running", "failed", "flushing", "done"])
    assert "Invoke-RestMethod" not in loop
    idle = loop[:loop.index('State "picked-up $scenario"')]
    assert idle.count("WaitForSignal") == 1 and "[Math]::Min((SecondsLeft), 1800)" in idle          # ONE call, however long nothing is asked
    # the only sleep of the idle loop is the fall-back, reached only when the wait returned at once four times in a row, and said in words first
    assert idle.count("Start-Sleep") == 1 and "if ($quick -ge 4) {" in idle
    fallback = idle[idle.index("if ($quick -ge 4) {"):]
    assert fallback.index("Waiting 'the wait for the signal returns at once: looking every 10 seconds instead'") < fallback.index("Start-Sleep -Seconds 10")
    assert "if (((Get-Date) - $before).TotalSeconds -lt 3) { $quick++ } else { $quick = 0 }" in idle


def test_the_signal_launcher_checks_the_cd_and_the_channel_before_ready_and_looks_again_before_starting():
    code = launcher_code()
    run_at = code.index("& powershell.exe")
    for must in ("Get-Service -Name VBoxService", "Test-Path 'C:\\LabTools'", "$note.warm -ne '1'", "$allowed -contains $scenario",
                 "$trusted[$rel]", "Get-FileHash", "(SecondsLeft) -lt $worstSec", "$doneList", "if (-not $reads)"):
        assert must in code and code.index(must) < run_at, must
    assert re.search(r"\$allowed = @\('s1', 's4', 's5'\)", code) and re.search(r"param\(\[Parameter\(Mandatory\)\]\[string\]\$Root\)", code)
    assert "$endAfterMin = 27" in code and "if ((SecondsLeft) -le 0)" in code
    ids, files, channel, ready, picked, look, done, start = (code.index(x) for x in (
        "$rid = [string]$note[\"run_$a\"]", "foreach ($f in Get-ChildItem -LiteralPath $Root -Recurse -File)", "if (-not $reads)",
        'State ("warm-ready', 'State "picked-up $scenario"', "if ((Signal) -ne $scenario -or $still -ne $sessionId) {",
        "Add-Content -Path $doneList -Value $runId", "& powershell.exe"))
    assert ids < files < channel < ready < picked < look < done < start
    for must in ("[string]$note[\"file_$i\"] -notmatch '^([0-9A-F]{64}):(\\S+)$'",
                 "if (-not $trusted.ContainsKey($rel)) { State \"failed the warm CD holds a file its list does not name",
                 ".Hash -ne $trusted[$rel]) { State \"failed a file on the warm CD differs from the laptop's list",
                 "if ($onCd -ne $trusted.Count) { State \"failed the warm CD holds"):
        assert must in code and code.index(must) < ready, must
    gone = code[look:start]
    assert "State 'failed not-started" in gone and "$runId = $sessionId; continue" in gone.split("Add-Content")[0]       # called off: nothing starts, the run id is not spent
    refusal = next(l for l in code.splitlines() if 'State "refused too little time left' in l)
    assert refusal.rstrip().endswith("continue")
    assert "picked-up" in W.BEGUN_ANY and "failed not-started".startswith(W.OVER[1])
    text = open(LAUNCHER, encoding="utf-8").read()
    minutes = int(re.search(r"\$endAfterMin = (\d+)", text).group(1))
    assert minutes == W.LAUNCHER_LIFE_S // 60 and "$startedAt = (Get-Process -Id $PID).StartTime" in text
    worst = re.search(r"\$worstSec = \$calmCapSec \+ (\d+) \+ (\d+) \+ (\d+)", text)
    assert worst and 120 + sum(int(x) for x in worst.groups()) <= W.WORST_TEST_S


# ---------------------------------------------------------------- on the dashboard

def app(tmp_path, machine=None, **kw):
    w, m, clock = session(tmp_path, machine, **kw)
    w.watch = lambda *a, **k: None
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode="live", warm=w, clock=clock))
    return c, w, m, clock


def test_the_screen_says_it_is_the_trial_and_shows_its_own_step_words(tmp_path):
    c, w, m, clock = app(tmp_path)
    c.post("/api/warm/start")
    s = until(c, lambda x: x["state"] == "ready")
    assert s["no_disc"] is True and s["hint"] == WM.WORDS["no_disc"] == "Trial: tests are named to the running machine and no CD is changed."
    c.post("/api/warm/run/s4")
    s = until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4"])
    d = c.get("/api/run/steps").json()
    assert [x["text"] for x in d["steps"]] == WM.WORDS["run_steps_no_disc"] and all(x["state"] == "done" for x in d["steps"]) and d["outcome"] == WM.WORDS["run_done"]
    assert "CD" not in " ".join(WM.WORDS["run_steps_no_disc"]) and "CD" in WM.WORDS["run_steps"][0]         # each path's words say what really happens
    assert not BANNED.search(json.dumps(s)) and not any(BANNED.search(t) for t in W.NOT_RUN.values())


def test_the_screen_shows_the_early_limit_on_the_trial_too_and_still_says_it_is_the_trial(tmp_path):
    m = SignalMachine(left=900)
    c, w, m, clock = app(tmp_path, machine=m)
    slow_start(m, clock, 480)
    t_start = clock.t
    c.post("/api/warm/start")
    s = until(c, lambda x: x["state"] == "ready")
    limit = t_start + W.START_TESTS_FOR_S
    assert s["no_disc"] is True and s["ready_until"] == limit and s["seconds_left"] == pytest.approx(240, abs=5)
    assert s["hint"] == WM.WORDS["no_disc"] + " " + WM.WORDS["early_limit_no_disc"].format(minutes=12)       # the trial's own line is never left out
    assert "first 12 minutes after the machine was switched on" in s["hint"] and "2026-11-23" in s["hint"] and not BANNED.search(s["hint"])
    clock.t = limit + 1
    s = c.get("/api/warm").json()
    assert s["warning"] == WM.WORDS["time_up"] and not any(t["can_run"] for t in s["tests"])
    assert c.post("/api/warm/run/s1").status_code == 409 and not any("signal" in x for x in m.calls)


def test_a_test_the_machine_never_picked_up_is_said_plainly_on_the_screen_and_can_be_clicked_again(tmp_path):
    c, w, m, clock = app(tmp_path, machine=SignalMachine(miss=9999))
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    c.post("/api/warm/run/s4")
    s = until(c, lambda x: x["state"] == "ready" and x.get("error"))
    assert s["error"] == W.NOT_RUN["not_picked"].format(minutes=4) and "did not pick this test up (4 min)" in s["error"] and "The test did not run" in s["error"]
    d = c.get("/api/run/steps").json()
    assert d["outcome"] == WM.WORDS["run_not_run"] and [x["state"] for x in d["steps"]] == ["done", "failed", "todo", "todo"]
    s4 = next(t for t in s["tests"] if t["id"] == "s4")
    assert s4["used"] is False and s4["can_run"] is True and m.signal is None
    m.miss = 0
    assert c.post("/api/warm/run/s4").status_code == 200
    s = until(c, lambda x: x["state"] == "ready" and x["used"] == ["s4"])
    assert s["error"] is None and len({r["run_id"] for r in s["runs"]}) == 1 and [r["step"] for r in s["runs"]] == ["failed", "done"]


def test_the_default_dashboard_shows_nothing_of_the_trial(tmp_path):
    w, m, clock = cd_session(tmp_path)
    w.watch = lambda *a, **k: None
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode="live", warm=w, clock=clock))
    c.post("/api/warm/start")
    s = until(c, lambda x: x["state"] == "ready")
    assert s["no_disc"] is False and s.get("hint") != WM.WORDS["no_disc"]
    c.post("/api/warm/run/s1")
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s1"])
    assert [x["text"] for x in c.get("/api/run/steps").json()["steps"]] == WM.WORDS["run_steps"]
