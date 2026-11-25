"""The Live screen's feeds: the arrival-based heartbeat (never "all clear") and the plain run steps."""

import os

from fastapi.testclient import TestClient

from engine.alerts import AlertStore
from engine.dashboard import live_status as L
from engine.dashboard.app import Runner, create_app
from tests.test_report import s1_like


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def client(tmp_path, with_alert, clock):
    con, alert, G = s1_like(tmp_path)
    con.close()
    if with_alert:
        s = AlertStore(str(tmp_path / "alerts.db"))
        s.write([alert])
        s.close()
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(L.make_router(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"),
                                     Runner(str(tmp_path / "rec"), command=["x"]), clock=clock))
    return TestClient(app), alert


def test_heartbeat_counts_from_arrival_not_from_the_events_own_time(tmp_path):
    clock = Clock()
    c, _ = client(tmp_path, False, clock)
    first = c.get("/api/health").json()
    assert first["state"] == "watching" and first["seconds"] == 0     # the store's events are from the past
    clock.t += 30
    assert c.get("/api/health").json()["text"] == L.WORDS["watching"].format(n=30)
    clock.t += L.QUIET_AFTER_S
    q = c.get("/api/health").json()
    assert q["state"] == "quiet" and str(30 + L.QUIET_AFTER_S) in q["text"]


def test_no_store_means_starting_and_an_alert_wins_with_its_title(tmp_path):
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(L.make_router(str(tmp_path / "none.db"), str(tmp_path / "none-alerts.db"),
                                     Runner(str(tmp_path / "rec"), command=["x"]), clock=Clock()))
    assert TestClient(app).get("/api/health").json()["state"] == "waiting"        # nothing is starting
    busy = Runner(str(tmp_path / "rec2"), command=["python", "-c", "import time; time.sleep(5)"])
    busy.start("s1")
    app2 = FastAPI()
    app2.include_router(L.make_router(str(tmp_path / "none.db"), str(tmp_path / "none-alerts.db"), busy, clock=Clock()))
    assert TestClient(app2).get("/api/health").json()["state"] == "starting"     # this dashboard's run is going
    busy.proc.kill()
    (tmp_path / "a").mkdir()
    c, alert = client(tmp_path / "a", True, Clock())
    h = c.get("/api/health").json()
    assert h["state"] == "alert" and h["alert"]["title"] == alert.title and h["alert"]["level"] == alert.level


def test_start_up_alert_is_kept_out_of_the_banner_but_shown_as_a_quiet_line(tmp_path):
    """Debate 12 option (c): during this dashboard's run, an alert before the test program started is
    not the banner's alert; it is counted in before_test (with its id, so its story stays one click
    away). Once the test starts, later alerts are in view."""
    from datetime import datetime, timezone
    con, alert, G = s1_like(tmp_path)
    con.close()
    t_alert = datetime.fromisoformat(alert.time.replace("Z", "+00:00")).timestamp()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert])
    s.close()
    runner = Runner(str(tmp_path / "rec"), command=["x"])
    runner.log, runner.started = str(tmp_path / "run.log"), t_alert - 240     # the run began 4 min before the alert
    (tmp_path / "run.log").write_text("--> 1. Checks\n--> 2. Restore\n--> 3. Scenario running\nVM: launcher-started\n", encoding="utf-8")
    clock = Clock(t_alert + 600)                                   # the test will start 10 min after this alert
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(L.make_router(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), runner, clock=clock, watch_log=False))
    c = TestClient(app)
    h = c.get("/api/health").json()                                # still booting: the alert is start-up
    assert h["state"] != "alert" and h["before_test"]["count"] == 1 and h["before_test"]["id"] == alert.alert_id
    (tmp_path / "run.log").write_text((tmp_path / "run.log").read_text() + "VM: running (calm)\n", encoding="utf-8")
    h = c.get("/api/health").json()                                # the test has started, the alert is older
    assert h["state"] != "alert" and h["view_ids"] == [] and h["watch_note"] == L.WORDS["watch_note"]
    clock.t = t_alert + 30                                          # a BATCH whose first test started 30 s after the alert
    runner.log = str(tmp_path / "run2.log")
    (tmp_path / "run2.log").write_text("Batch of 3 in one boot\n    VM: S1: running (calm)\n", encoding="utf-8")
    h = c.get("/api/health").json()                                # batch line recognised; within the clock margin: in view
    assert h["state"] == "alert" and h["view_ids"] == [alert.alert_id] and h["before_test"] is None
    runner.log, runner.started = str(tmp_path / "run3.log"), t_alert + 3600    # a later run: this alert is history
    (tmp_path / "run3.log").write_text("--> 1. Checks\n", encoding="utf-8")
    h = c.get("/api/health").json()
    assert h["state"] != "alert" and h["view_ids"] == [] and h["before_test"] is None


def test_the_start_time_is_taken_when_the_line_is_written_not_when_the_page_asks(tmp_path):
    import time as _t
    runner = Runner(str(tmp_path / "rec"), command=["x"])
    runner.log, runner.started = str(tmp_path / "run.log"), 0
    (tmp_path / "run.log").write_text("--> 1. Checks\n", encoding="utf-8")
    clock = Clock(1000.0)
    r = L.make_router(str(tmp_path / "s.db"), str(tmp_path / "a.db"), runner, clock=clock)   # background watcher on
    (tmp_path / "run.log").write_text("--> 1. Checks\n    VM: S1: running (calm)\n", encoding="utf-8")
    _t.sleep(2.5)                                                   # nobody calls /api/health meanwhile
    clock.t = 5000.0                                                # the page is opened much later
    assert r.view["from"] == 1000.0                                 # the watcher took the time when the line appeared



def test_heartbeat_words_never_claim_the_machine_is_fine():
    text = " ".join(L.WORDS.values()).lower()
    for banned in ("all clear", "safe", "secure", "clean", "no threat"):
        assert banned not in text


def test_run_steps_follow_the_frozen_log_markers(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("--> 1. Checks\n--> 2. Restore 'lived-in'\n--> 3. Scenario running\n", encoding="utf-8")
    d = L.run_steps(str(log))
    assert [s["state"] for s in d["steps"]] == ["done", "done", "current", "todo", "todo"] and not d["finished"]
    log.write_text(log.read_text() + "--> 4. Check\n--> 5. Shutting the VM down\nRUN x: PASS\n", encoding="utf-8")
    d = L.run_steps(str(log))
    assert all(s["state"] == "done" for s in d["steps"]) and d["finished"]
    assert L.run_steps(None)["steps"][0]["state"] == "todo"
    assert d["outcome"] == L.OUTCOME_WORDS["done"]


def test_a_refused_run_says_so_in_plain_words(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("--> 1. Checks\nNOT STARTED: building the run CD failed:\nRUN x: not started · 0 s\n", encoding="utf-8")
    d = L.run_steps(str(log), 2)
    assert d["steps"][0]["state"] == "failed" and d["outcome"] == L.OUTCOME_WORDS["not_started"]
    assert all(s["state"] == "todo" for s in d["steps"][1:])


def test_batch_steps_say_which_test_is_running(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("Batch of 3 in one boot: S1, S4, S5\n--> 1. Checks\n--> 2. Restore\n--> 3. Scenarios\n"
                   "    VM: S1: running (calm)\n    VM: S4: running (no calm-down wait: the answer sheet allows it)\n", encoding="utf-8")
    d = L.run_steps(str(log))
    assert d["steps"][2]["text"].endswith("(2 of 3)") and d["steps"][2]["state"] == "current"


def test_three_in_one_boot_passes_all_three(tmp_path):
    from engine.dashboard.app import create_app
    r = Runner(str(tmp_path), command=["python", "-c", "pass"])
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"), runner=r))
    assert c.post("/api/run/three").status_code == 200
    r.proc.wait()
    assert r.proc.args[-6:] == ["s1", "s4", "s5", "--headless", "--snapshot", "lived-in"]
    assert TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"),
                                 mode="replay")).post("/api/run/three").status_code == 409


def test_the_run_button_boots_the_prepared_snapshot(tmp_path):
    r = Runner(str(tmp_path), command=["python", "-c", "pass"])
    r.start("s1")
    r.proc.wait()
    assert r.proc.args[-3:] == ["--headless", "--snapshot", "lived-in"]


def test_app_serves_health_and_steps(tmp_path):
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    assert c.get("/api/health").json()["state"] == "waiting"
    assert len(c.get("/api/run/steps").json()["steps"]) == len(L.STEPS)


def test_only_the_replay_dashboard_may_read_health_across_origins(tmp_path):
    """Approved 2026-11-20: the replay page (127.0.0.1:8781) may read GET /api/health of the live
    dashboard, to show a small notice. No other origin, and no other route."""
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec")))
    ok = c.get("/api/health", headers={"Origin": "http://127.0.0.1:8781"})
    assert ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:8781"
    for origin in ("http://127.0.0.1:8780", "http://localhost:8781", "http://10.0.2.2:8781", "https://example.com", "null"):
        assert "access-control-allow-origin" not in c.get("/api/health", headers={"Origin": origin}).headers, origin
    assert "access-control-allow-origin" not in c.get("/api/health").headers
    for path in ("/api/alerts", "/api/run/steps", "/api/run", "/api/words", "/api/checks", "/api/mode"):
        assert "access-control-allow-origin" not in c.get(path, headers={"Origin": "http://127.0.0.1:8781"}).headers, path
    # a cross-origin POST would need a preflight; none is answered, so the browser never sends it
    pre = c.options("/api/run/three", headers={"Origin": "http://127.0.0.1:8781", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in pre.headers


def test_health_counts_the_records_received(tmp_path):
    c, _ = client(tmp_path, False, Clock())
    h = c.get("/api/health").json()
    import sqlite3
    con = sqlite3.connect(str(tmp_path / "s.db"))
    rows = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.execute("DELETE FROM events WHERE id = (SELECT MIN(id) FROM events)")       # ids now run past the row count
    con.commit()
    con.close()
    assert h["records"] == rows > 1
    assert h["records_text"] == L.WORDS["records"].format(n=rows, s="s")
    after = c.get("/api/health").json()
    assert after["records"] == rows - 1 and after["events_max_id"] == h["events_max_id"]   # counted rows, not the newest id


def test_a_rehearsal_is_badged_as_a_rehearsal_and_keeps_its_own_clock(tmp_path):
    clock = Clock(5000.0)
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "a.db"), recordings=str(tmp_path / "rec"),
                              mode="rehearsal", clock=clock))
    m = c.get("/api/mode").json()
    assert m["mode"] == "rehearsal" and "REHEARSAL" in m["badge"] and "no test machine" in m["badge"] and m["can_run"] is True
    assert c.get("/api/run/steps").json()["now"] == 5000.0


def test_the_run_steps_say_when_the_run_ended_so_the_elapsed_time_stops(tmp_path):
    """While a run goes there is no end time; once its log says it finished, the end time is taken once
    (by the dashboard's clock) and never moves."""
    clock = Clock(2000.0)
    runner = Runner(str(tmp_path / "rec"), command=["x"])
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(L.make_router(str(tmp_path / "s.db"), str(tmp_path / "a.db"), runner, clock=clock, watch_log=False))
    c = TestClient(app)
    assert c.get("/api/run/steps").json()["ended"] is None            # no run at all
    log = tmp_path / "run.log"
    log.write_text("--> 1. x\n--> 2. y\n", encoding="utf-8")
    runner.log, runner.started, runner.scenario = str(log), 2000.0, "s1"
    assert c.get("/api/run/steps").json()["ended"] is None            # started, not finished
    clock.t = 2540.0
    log.write_text("--> 1. x\n--> 2. y\n--> 3. z\n--> 4. a\n--> 5. b\nRUN r1: PASS\n", encoding="utf-8")
    assert c.get("/api/run/steps").json()["ended"] == 2540.0
    clock.t = 9999.0
    d = c.get("/api/run/steps").json()
    assert d["ended"] == 2540.0 and d["started"] == 2000.0 and d["now"] == 9999.0


def test_step_three_says_the_machine_is_settling_until_the_test_program_really_starts(tmp_path):
    """run_in_vm prints "--> 3." when the machine has logged on; the test program starts minutes later, when
    the launcher says "running". Seen on the real run of 2026-11-20 (the step said "running" from 1:40)."""
    log = tmp_path / "run.log"
    log.write_text("--> 1. Checks\n--> 2. Restore\n--> 3. Scenario running in the VM; waiting\n    VM: launcher-started\n    VM: settling\n", encoding="utf-8")
    d = L.run_steps(str(log))
    assert d["steps"][2] == {"text": L.SETTLING_STEP, "state": "current"}
    log.write_text(log.read_text(encoding="utf-8") + "    VM: running (calm)\n", encoding="utf-8")
    assert L.run_steps(str(log))["steps"][2] == {"text": dict(L.STEPS)["--> 3."], "state": "current"}
    log.write_text(log.read_text(encoding="utf-8") + "--> 4. Check\n", encoding="utf-8")
    assert L.run_steps(str(log))["steps"][2] == {"text": dict(L.STEPS)["--> 3."], "state": "done"}

