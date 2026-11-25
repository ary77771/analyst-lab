"""Keeping the laptop awake while the test machine works (engine/dashboard/awake.py), and the preflight's
notes about dozing off (demo/preflight.py power_notes).

The real case, 2026-11-21: the laptop went into Modern Standby in the middle of a warm start and the test
machine stood still for 581 seconds. PROOF's conditions: the request is made only while a one-boot run or
a warm session is going, it is cleared at the end AND on failure, nothing persistent is changed, and the
preflight only warns."""

import inspect
import os
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from engine.dashboard import awake as A
from engine.dashboard.app import create_app
from tests.test_dashboard_warm import OneBoot, until
from tests.test_warm_vm import Machine, session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo"))
import preflight as P  # noqa: E402

ASK, CLEAR = A.ES_CONTINUOUS | A.ES_SYSTEM_REQUIRED | A.ES_DISPLAY_REQUIRED, A.ES_CONTINUOUS


@pytest.fixture(autouse=True)
def no_real_programs(monkeypatch):
    def trap(*args, **kwargs):
        raise AssertionError(f"a test tried to start a real program: {args[:1]!r}")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    from engine.dashboard import checks
    monkeypatch.setattr(checks, "vm_running", lambda *a, **k: False)
    monkeypatch.setattr(checks.Checks, "count_once", lambda self: None)


def test_the_request_is_made_when_work_starts_and_cleared_when_it_ends():
    calls, working = [], [False]
    k = A.Keeper(lambda: working[0], calls.append)
    assert k.asked is None
    k.step()
    assert calls == [CLEAR] and k.asked is False                     # first look, nothing going: explicitly nothing asked
    working[0] = True
    k.step(); k.step(); k.step()
    assert calls == [CLEAR, ASK] and k.asked is True                 # asked once, not on every look
    working[0] = False
    k.step(); k.step()
    assert calls == [CLEAR, ASK, CLEAR] and k.asked is False


def test_not_knowing_what_is_going_on_never_keeps_the_laptop_awake():
    calls, state = [], {"boom": False}

    def working():
        if state["boom"]:
            raise RuntimeError("the run's state can't be read")
        return True

    k = A.Keeper(working, calls.append)
    k.step()
    assert calls == [ASK]
    state["boom"] = True
    k.step()
    assert calls == [ASK, CLEAR] and k.asked is False                # a failure clears; it never leaves the request standing

    def broken(_):
        raise OSError("Windows said no")
    k2 = A.Keeper(lambda: True, broken)
    assert k2.step() is None and k2.asked is None                    # a setter that fails: nothing is claimed as asked, nothing raises
    k2.clear()


def test_the_keepers_own_thread_makes_the_request_and_takes_it_back_when_it_ends():
    """Windows ties the request to the thread that made it: one thread asks and clears, and its end clears."""
    seen = []
    k = A.Keeper(lambda: True, lambda flags: seen.append((flags, threading.current_thread().name)), every=0.01).start()
    t = time.time()
    while not seen and time.time() - t < 3:
        time.sleep(0.01)
    assert seen[0] == (ASK, "keep-awake")
    k.stop()
    t = time.time()
    while len(seen) < 2 and time.time() - t < 3:
        time.sleep(0.01)
    assert seen[-1] == (CLEAR, "keep-awake") and {name for _, name in seen} == {"keep-awake"} and k.asked is False


def app(tmp_path, machine=None, runner=None, **kw):
    w, m, clock = session(tmp_path, machine, **kw)
    w.watch = lambda *a, **k: None
    calls = []
    runner = runner or OneBoot()
    api = create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=runner,
                     mode="live", warm=w, clock=clock, keep_awake=calls.append)
    keeper = api.state.awake
    keeper.stop()                                                    # the tests look themselves, step by step
    time.sleep(0.05)
    calls.clear()
    keeper.asked = None
    return TestClient(api), keeper, calls, w, m, runner


def test_a_warm_session_is_kept_awake_from_start_to_shutdown_and_no_longer(tmp_path):
    c, keeper, calls, w, m, _ = app(tmp_path)
    keeper.step()
    assert calls == [CLEAR]                                          # the machine is off: nothing asked
    c.post("/api/warm/start")
    until(c, lambda x: x["state"] == "ready")
    keeper.step()
    assert calls[-1] == ASK
    c.post("/api/warm/run/s1")
    until(c, lambda x: x["state"] == "ready" and x["used"] == ["s1"])
    keeper.step()
    assert calls == [CLEAR, ASK]                                     # through the test and between tests: still the one request
    c.post("/api/warm/stop")
    until(c, lambda x: x["state"] == "off")
    keeper.step()
    assert calls == [CLEAR, ASK, CLEAR] and keeper.asked is False    # the machine is off again: cleared


def test_a_start_that_fails_does_not_leave_the_laptop_kept_awake(tmp_path):
    m = Machine()

    def never_ready(headless=False):
        m.state_now = "running"
        m.changed += 1
        m.say("-", "starter: no run CD, nothing to do")
    m.start = never_ready
    c, keeper, calls, w, m, _ = app(tmp_path, machine=m, timeouts={"launcher": 3, "ready": 3})
    c.post("/api/warm/start")
    keeper.step()
    s = until(c, lambda x: x["state"] in ("failed", "off") and x.get("error"))
    keeper.step()
    assert s["state"] == "failed" and calls[-1] == CLEAR and keeper.asked is False
    # refused before anything was touched (the machine is someone else's): never asked at all
    (tmp_path / "b").mkdir()
    c2, keeper2, calls2, *_ = app(tmp_path / "b", machine=Machine(state="running"))
    c2.post("/api/warm/start")
    until(c2, lambda x: x.get("error"))
    keeper2.step()
    assert ASK not in calls2[-1:] and keeper2.asked is False


def test_a_one_boot_run_is_kept_awake_only_while_it_runs(tmp_path):
    runner = OneBoot(running=True)
    c, keeper, calls, *_ = app(tmp_path, runner=runner)
    keeper.step()
    assert calls == [ASK]
    runner.running = False
    keeper.step()
    assert calls == [ASK, CLEAR]


def test_only_the_live_demo_dashboard_ever_asks_and_nothing_persistent_is_touched(tmp_path, monkeypatch):
    plain = create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=OneBoot(), mode="live")
    assert not hasattr(plain.state, "awake")                         # no setter given: no keeper at all (tests, replay, rehearsal)
    import engine.dashboard.app as dash
    seen = {}
    monkeypatch.setattr(dash.report_mod, "official_or_exit", lambda *a: None)
    monkeypatch.setattr(dash.report_mod, "layer2_from", lambda pool: None)
    monkeypatch.setattr(dash, "create_app", lambda *a, **kw: seen.update(kw) or object())
    monkeypatch.setattr(A, "windows_setter", lambda: "the real setter")
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from engine.dashboard import demo_mode
    monkeypatch.setattr(demo_mode, "projector_problems", lambda store: [])
    dash.main(["--events", str(tmp_path / "s.db"), "--alerts", str(tmp_path / "a.db"), "--no-hubs"])
    assert seen["keep_awake"] is None                                # a plain dashboard never asks
    dash.main(["--events", str(tmp_path / "s.db"), "--alerts", str(tmp_path / "a.db"), "--no-hubs", "--demo", "live", "--no-warm"])
    assert seen["keep_awake"] == "the real setter"
    code = "\n".join(line.split("#")[0] for line in inspect.getsource(A).split('"""')[2::2])
    for word in ("powercfg", "winreg", "subprocess", "schtasks", "PowerSetRequest", "os.system"):
        assert word not in code, word                                # a request of this process only: no setting, no task, no registry
    assert A.ES_CONTINUOUS == 0x80000000 and A.ES_SYSTEM_REQUIRED == 1 and A.ES_DISPLAY_REQUIRED == 2


# ---------------------------------------------------------------- the preflight's notes

def notes(sleep=(0, 0), screen=(0, 0), mains=True):
    table = {("SUB_SLEEP", "STANDBYIDLE"): sleep, ("SUB_VIDEO", "VIDEOIDLE"): screen}
    return P.power_notes(query=lambda sub, setting: table[(sub, setting)], on_mains=lambda: mains)


def test_the_preflight_notes_a_laptop_that_would_doze_off_during_the_demo():
    assert notes() == []                                             # never / never, plugged in: nothing to say
    assert notes(sleep=(3600, 600), screen=(2400, 300)) == []        # 40 min and more when plugged in is enough (battery timers don't matter then)
    n = notes(sleep=(900, 0), screen=(600, 0))
    assert len(n) == 2 and "go to sleep after 15 min" in n[0] and "'Sleep after'" in n[0] and "turn its screen off after 10 min" in n[1]
    assert all("Settings > System > Power" in x and "plugged in" in x for x in n)      # what Yousif can do himself
    n = notes(sleep=(0, 300), screen=(0, 10800), mains=False)        # the real case: on battery
    assert len(n) == 2 and "running on battery: plug it in" in n[0] and "on battery, the laptop would go to sleep after 5 min" in n[1]
    assert notes(mains=None) == []                                   # the power source can't be told: no claim either way
    n = P.power_notes(query=lambda sub, setting: None, on_mains=lambda: True)
    assert len(n) == 2 and all("could not read" in x and "yourself" in x for x in n)


def test_the_notes_never_change_ready_and_the_preflight_changes_nothing(monkeypatch, capsys):
    monkeypatch.setattr(P, "before_checks", lambda: [P.check("a check that holds", True)])
    monkeypatch.setattr(P, "power_notes", lambda: ["the laptop is running on battery: plug it in for the demo"])
    assert P.main(["--before"]) == 0                                 # READY: a note is not a failed check
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "READY" and "  NOTE the laptop is running on battery" in out
    code = inspect.getsource(P.power_notes) + inspect.getsource(P._powercfg) + inspect.getsource(P._on_mains)
    assert "/query" in code and not any(word in code for word in ("/change", "/setacvalueindex", "/setdcvalueindex", "/setactive", "/hibernate", "-x "))
    assert "SetThreadExecutionState" not in inspect.getsource(P)     # the preflight looks; only the running dashboard asks
