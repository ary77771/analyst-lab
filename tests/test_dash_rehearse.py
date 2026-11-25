"""The rehearsal dashboard (demo/dash_rehearse.py; in demo/, not tools/: tools/ is frozen code) must never start the test machine: its "Run" button
plays a recorded run. PROOF's condition before first use (2026-11-20): prove there is no path to
run_in_vm, VBoxManage or the real Runner, and that its badge words come from Python and pass the word scan."""

import os
import re
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "demo"))
import dash_rehearse as R  # noqa: E402
from engine.dashboard import demo_mode as D  # noqa: E402
from engine.dashboard import live_status as L  # noqa: E402
from engine.dashboard.app import Runner, create_app  # noqa: E402

BANNED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)   # tests/test_dashboard_words_scan.py


class FakeLoop:
    """Stands in for the scoring loop: the test is about what the runner starts, not about scoring."""

    def __init__(self):
        self.ticks = 0

    def tick(self):
        self.ticks += 1
        return 0, []


def rehearsal(tmp_path, monkeypatch):
    """A rehearsal runner on three made-up records, with every way of starting a process booby-trapped."""
    started = []

    def trap(*args, **kwargs):
        started.append(args[0] if args else kwargs.get("args"))
        raise AssertionError(f"the rehearsal tried to start a process: {started[-1]!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, trap)
    monkeypatch.setattr(os, "system", trap)
    monkeypatch.setattr(Runner, "start", lambda self, scenario: (_ for _ in ()).throw(AssertionError("the real Runner.start was called")))
    feed = tmp_path / "feed"
    (feed / R.FEED).mkdir(parents=True)
    records = [{"time": f"2026-10-30T20:01:3{i}.000Z", "n": i} for i in range(3)]
    loop, clock = FakeLoop(), R.RecordingClock()
    runner = R.RehearsalRunner(str(tmp_path / "rec"), clock, records, str(feed), loop, boot=1.0, speed=0, pace=0.01)
    return runner, clock, loop, feed, started


def wait_done(runner, limit=20):
    t = time.time()
    while runner.status().running:
        assert time.time() - t < limit, "the rehearsal run did not finish"
        time.sleep(0.05)


def test_a_rehearsal_run_starts_no_process_at_all(tmp_path, monkeypatch):
    runner, clock, loop, feed, started = rehearsal(tmp_path, monkeypatch)
    runner.start("s1")
    wait_done(runner)
    assert started == [] and runner.exit_code == 0, started
    lines = (feed / R.FEED / "replay.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and loop.ticks >= 1                     # the recorded records were fed and scored
    log = open(runner.log, encoding="utf-8").read()
    assert L.run_steps(runner.log)["finished"] and L.LAUNCHER.search(log)   # the live screen reads it like a real run


def test_the_three_test_button_and_a_second_click_start_no_process_either(tmp_path, monkeypatch):
    runner, clock, loop, feed, started = rehearsal(tmp_path, monkeypatch)
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"),
                              runner=runner, mode="rehearsal", clock=clock))
    assert c.post("/api/run/three").status_code == 200             # "Run 3 tests in one boot"
    assert c.post("/api/run/three").status_code == 409             # a second click: refused, nothing started
    wait_done(runner)
    assert c.post("/api/run/three").status_code == 409             # one rehearsal per start
    assert started == []


def test_the_rehearsal_command_is_never_a_real_program():
    runner = R.RehearsalRunner("x", R.RecordingClock(), [], "x", FakeLoop())
    joined = " ".join(runner.command).lower()
    assert "run_in_vm" not in joined and "vboxmanage" not in joined and not os.path.exists(runner.command[0])


def test_the_clock_moves_to_the_recording_so_its_alerts_count_as_this_runs(tmp_path, monkeypatch):
    runner, clock, loop, feed, _ = rehearsal(tmp_path, monkeypatch)
    runner.start("s1")
    first = L._epoch("2026-10-30T20:01:30.000Z")
    assert first - 60 < runner.started < first                      # the run "starts" shortly before its first record
    wait_done(runner)


def test_the_rehearsal_badge_comes_from_python_and_passes_the_word_scan(tmp_path):
    assert "REHEARSAL" in D.WORDS["rehearsal"] and "no test machine" in D.WORDS["rehearsal"]
    for text in D.WORDS.values():
        assert not BANNED.search(text), text
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), mode="rehearsal"))
    m = c.get("/api/mode").json()
    assert m["badge"] == D.WORDS["rehearsal"] and not BANNED.search(str(m))
