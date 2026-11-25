"""The live "honesty checks" button: counts pytest's own results, refuses during a VM run."""

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.dashboard import checks as C


class FakeRunner:
    def __init__(self, running):
        self._r = running

    def status(self):
        return type("S", (), {"running": self._r})()


def wait_done(c, limit=120):
    t = time.time()
    while time.time() - t < limit:
        s = c.get("/api/checks").json()
        if not s["running"] and s["exit_code"] is not None:
            return s
        time.sleep(0.3)
    raise AssertionError("checks did not finish")


def app_with(runner, files, vm_busy=lambda: False):
    app = FastAPI()
    app.include_router(C.make_router(runner, C.Checks(runner, files=files, vm_busy=vm_busy)))
    return TestClient(app)


def test_refuses_while_any_vm_run_is_going():
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"], vm_busy=lambda: True)
    assert c.post("/api/checks/run").status_code == 409


def test_counts_a_real_small_run(tmp_path):
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"])
    assert c.post("/api/checks/run").status_code == 200
    s = wait_done(c)
    assert s["total"] == 3 and s["passed"] == 3 and s["failed"] == 0 and s["exit_code"] == 0
    assert s["text"] == C.WORDS["done_ok"].format(passed=3, failed=0, skipped=0)


def test_a_failing_test_is_counted_as_failed(tmp_path):
    (tmp_path / "test_broken_on_purpose.py").write_text("def test_ok():\n    assert True\n\ndef test_bad():\n    assert False\n", encoding="utf-8")
    c = app_with(FakeRunner(False), [str(tmp_path / "test_broken_on_purpose.py")])
    c.post("/api/checks/run")
    s = wait_done(c)
    assert (s["passed"], s["failed"]) == (1, 1) and s["exit_code"] != 0 and "failed" in s["text"]


def test_refuses_while_the_test_machine_runs():
    c = app_with(FakeRunner(True), ["tests/test_demo_preflight.py"])
    r = c.post("/api/checks/run")
    assert r.status_code == 409 and r.json()["detail"] == C.WORDS["busy"]
    assert c.get("/api/checks").json()["busy"] is True


def test_a_coloured_terminal_does_not_break_the_count(monkeypatch):
    """The 2026-11-20 bug: a server started with FORCE_COLOR set showed '0 passed' of 118, because
    the count came from pytest's printed dots and colour codes wrapped each dot."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("PY_COLORS", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"])
    c.post("/api/checks/run")
    s = wait_done(c)
    assert (s["total"], s["passed"], s["failed"]) == (3, 3, 0) and s["ok"] is True


def test_each_result_carries_the_tests_own_plain_name():
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"])
    c.post("/api/checks/run")
    s = wait_done(c)
    assert len(s["items"]) == 3 and all(i["outcome"] == "passed" and "test_" not in i["name"] and "::" not in i["name"] for i in s["items"])
    assert C.plain_name("tests/test_x.py::test_no_guess_is_shown[low]") == "no guess is shown"


def test_results_that_cannot_be_counted_are_shown_as_not_passed():
    """Without the plugin nothing is counted although pytest exits 0: that must never read as a pass."""
    app = FastAPI()
    app.include_router(C.make_router(FakeRunner(False), C.Checks(FakeRunner(False), files=["tests/test_demo_preflight.py"],
                                                                 vm_busy=lambda: False, plugin=None)))
    c = TestClient(app)
    c.post("/api/checks/run")
    s = wait_done(c)
    assert s["exit_code"] == 0 and s["passed"] == 0 and s["ok"] is False
    assert s["text"] == C.WORDS["done_uncounted"].format(counted=0, total=0)


def test_the_screen_is_told_how_many_checks_are_ready_before_any_run():
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"])
    t = time.time()
    while time.time() - t < 60:
        s = c.get("/api/checks").json()
        if s["total"] is not None:
            break
        time.sleep(0.3)
    assert s["total"] == 3 and s["passed"] == 0 and s["exit_code"] is None and s["ok"] is None
    assert s["ready_text"] == C.WORDS["ready"].format(total=3) and s["items"] == []      # counted, nothing run


def test_nothing_is_counted_while_the_test_machine_runs(monkeypatch):
    """Counting starts a pytest process, so it must not happen while the test machine runs. The count is
    watched directly (fresh review 2026-11-20: the earlier version only waited 0.6 s and could not fail)."""
    calls = []
    monkeypatch.setattr(C.Checks, "_count", lambda self: calls.append("counted"))
    c = app_with(FakeRunner(True), ["tests/test_demo_preflight.py"])
    for _ in range(3):
        s = c.get("/api/checks").json()
    time.sleep(0.2)
    assert s["busy"] is True and s["total"] is None and "ready_text" not in s and calls == []
    idle = app_with(FakeRunner(False), ["tests/test_demo_preflight.py"])
    for _ in range(3):
        idle.get("/api/checks")
    time.sleep(0.2)
    assert calls == ["counted"]                                   # when idle it is counted, once, however often the page asks


def test_a_check_named_after_a_forbidden_word_shows_that_word_in_quotes():
    assert C.plain_name("tests/test_x.py::test_public_tab_never_shows_crosshost_claim_or_probably") == \
        'public tab never shows crosshost claim or "probably"'
    assert C.plain_name("tests/test_x.py::test_build_is_json_safe") == 'build is json "safe"'
    assert C.plain_name("tests/test_x.py::test_no_guess_is_shown_as_fact") == "no guess is shown as fact"


def test_the_screen_gets_plain_group_lines_with_their_counts(tmp_path):
    """Instead of raw test names the strip shows one plain line per check file, with how many passed."""
    bad = tmp_path / "test_broken_on_purpose.py"
    bad.write_text("def test_ok():\n    assert True\n\ndef test_bad():\n    assert False\n", encoding="utf-8")
    c = app_with(FakeRunner(False), ["tests/test_demo_preflight.py", str(bad)])
    idle = c.get("/api/checks").json()["groups"]
    assert [g["name"] for g in idle] == ["demo preflight", "broken on purpose"] and all(g["total"] is None for g in idle)
    c.post("/api/checks/run")
    s = wait_done(c)
    g = {x["name"]: x for x in s["groups"]}
    assert (g["demo preflight"]["total"], g["demo preflight"]["passed"], g["demo preflight"]["failed"]) == (3, 3, 0)
    assert (g["broken on purpose"]["total"], g["broken on purpose"]["passed"], g["broken on purpose"]["failed"]) == (2, 1, 1)
    assert sum(x["total"] for x in s["groups"]) == s["total"] == 5


def test_every_listed_check_file_has_a_plain_name_and_the_names_pass_the_word_scan():
    import re
    banned = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)
    for f in C.FILES:
        assert f in C.GROUPS, f
        assert not banned.search(C.GROUPS[f]) and len(C.GROUPS[f]) <= 40, C.GROUPS[f]
    assert set(C.GROUPS) == set(C.FILES)
    assert C.group_of("tests\\test_report.py::test_x", C.FILES) == "tests/test_report.py"

