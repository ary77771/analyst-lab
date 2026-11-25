"""The warm test machine on the dashboard (2026-11-21; demo/warm_vm.py does the work).

Yousif: "the ability to open the vm with a button on the dashboard so we can run scenarioes faster and
live". Start the test machine once; then each test is one click and its alert lands in about a minute.
PRACTICE RUNS ONLY, on the live dashboard only (and a stand-in on the rehearsal one).

  GET  /api/warm                  the machine's state, its words, the buttons that may be pressed now
  POST /api/warm/start            start the machine (about 10 minutes until it is ready; measured 2026-11-21: 591-645 s)
  POST /api/warm/run/{scenario}   run one test in the running machine
  POST /api/warm/stop             shut the machine down

Rules kept here:
- GET reads memory only: no VirtualBox call, however often the page asks.
- The one-boot runs ("Run S1", "Run 3 tests in one boot") and a warm session refuse each other.
- Each warm test writes the same kind of progress file a one-boot run writes, so the live view counts
  from THAT test's own start and shows only its alerts (live_status.split). `Current` hands the live
  view whichever run is the newest.
- When no further test can start, the machine is shut down by itself (a controlled shutdown, minutes
  before Windows would stop the launcher), never while a test runs. The screen says so in plain words.
"""

import os
import threading
import time

from fastapi import APIRouter, HTTPException

WORDS = {
    "title": "Test machine",
    "practice": "Practice runs: the machine is started once and is not fresh for each test.",
    "practice_tag": "Practice runs",
    "start": "Start the test machine",
    "start_hint": "It takes about 10 minutes to start. Tests can then be started for a few minutes (the screen shows until when): "
                  "each is one click, and its alert comes 1 to 2 minutes later.",
    # the stop-gap of 2026-11-21 (demo/warm_vm.py START_TESTS_FOR_S): what is measured, said plainly, and nothing about why
    "early_limit": "Tests are started only in the first {minutes} minutes after the machine was switched on. "
                   "On 2026-11-21, tests started later than that did not begin reliably.",
    # the same limit on the trial path (2026-11-23): said after the trial's own line, which is never left out
    "early_limit_no_disc": "Tests are started only in the first {minutes} minutes after the machine was switched on. "
                           "On 2026-11-23, a test started later than that did not do its work.",
    "stop": "Shut the test machine down",
    "states": {
        "off": "The test machine is off",
        "starting": "Starting the test machine",
        "ready": "Ready for a test",
        "running": "A test is running",
        "stopping": "Shutting the test machine down",
        "failed": "The test machine could not be used",
        "recovering": "Test machine found running: checking it",
        "foreign": "The test machine is on (not started here)",
    },
    "boot_steps": {"booting": "Restoring the prepared test machine and starting it",
                   "settling": "Windows is starting up inside it",
                   "ready": "Ready"},
    "ready_until": "Tests can be started until {time} ({minutes} min left)",
    "last_minutes": "Less than {minutes} minutes left to start a test. After that the machine shuts down by itself.",
    "time_up": "No further test can start: the machine is being shut down (it is never stopped in the middle of a test).",
    "ended": {"time is up": "The test machine was shut down: its time for starting tests was over.",
              "asked": "The test machine was shut down."},
    "tests": {"s1": "S1: download and run", "s4": "S4: an unusual program chain", "s5": "S5: file churn"},
    "used": "already run in this session",
    "run_steps": ["Putting the test's CD into the running machine",
                  "The test machine reads it and checks it",
                  "Test program running inside the machine",
                  "Waiting until everything it did is recorded"],
    # the no-disc-change path (a trial behind a switch, demo/warm_vm.py): the same four steps, the first two in its own words
    "run_steps_no_disc": ["Telling the running machine which test to run",
                          "The test machine picks the test up",
                          "Test program running inside the machine",
                          "Waiting until everything it did is recorded"],
    "no_disc": "Trial: tests are named to the running machine and no CD is changed.",
    "run_done": "Test finished. The test machine stays on for the next test.",
    # after the session's last test (seen 2026-11-22: the line above stood there while the machine was shutting down)
    "run_done_last": "Test finished. No further test can start in this session.",
    "run_stopped": "The test did not finish.",
    "run_not_run": "The test did not run.",
    "busy_inside": "An earlier test is still going inside the test machine. No new test starts, and the machine is not shut down, "
                   "until that test has finished.",
    "before_test": "{n} alert{s} raised after the click, before this test's program started: see why",
    "before_mixed": "{n} alert{s} not from this test (raised while the test machine started up, or after the click "
                    "before the test program ran): see why",
    "unfinished": "A test was running when this dashboard restarted: the machine is shut down when it has finished.",
    "foreign": "The test machine is on, but this dashboard did not start it. It can't be shut down from here.",
    "recovering_hint": "This dashboard was restarted while the machine was on. It can be shut down now; tests come back "
                       "once the machine's own records show it is ready.",
    "other_run": "A one-boot run is going: the warm machine can't be used until it has finished.",
    "one_boot": "Or one run in a fresh machine (about 9 minutes each):",
}

# progress lines of one warm test, in the form live_status reads (run_in_vm's own markers)
MARKS = {"building": "--> 1. warm test: building its run CD", "inserted": "--> 2. warm test: run CD inserted",
         "running": "VM: running (warm)\n--> 3. warm test: running in the test machine",
         "flushing": "--> 4. warm test: waiting for the flush barrier"}
STEP_MARKERS = [("--> 1.", WORDS["run_steps"][0]), ("--> 2.", WORDS["run_steps"][1]),
                ("--> 3.", WORDS["run_steps"][2]), ("--> 4.", WORDS["run_steps"][3])]
# "not_started" is said only when the session proved the test's program never started (demo/warm_vm.py NOT_RUN)
STEP_MARKERS_NO_DISC = [(m, w) for (m, _), w in zip(STEP_MARKERS, WORDS["run_steps_no_disc"])]
OUTCOMES = {"not_started": WORDS["run_not_run"], "done": WORDS["run_done"], "stopped": WORDS["run_stopped"]}


# How long before the laptop SAW a warm test's program start an alert may be stamped and still be the
# test's. Measured on 2026-11-20/21 (265 launcher messages): the VM's messages reach the laptop 0.7 to
# 6.8 s after the VM's own time stamp; the session then polls every 2 s and the live view every second.
WARM_CLOCK_MARGIN_S = 20


def vm_seconds(stamp):
    """A time stamp of the test machine ("2026-11-21T10:37:37.1234567Z": Windows gives seven decimals) as
    seconds, or None when there is none or it can't be read."""
    import re
    from datetime import datetime, timezone
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", str(stamp or ""))
    if not m:
        return None
    try:
        whole = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return whole + float("0." + m.group(2)) if m.group(2) else whole


class RunStatus:
    def __init__(self, running, scenario, started, exit_code):
        self.running, self.scenario, self.started, self.exit_code, self.log_tail = running, scenario, started, exit_code, []


class WarmRuns:
    """The progress file of the warm test that is running (or ran last), written from the session's steps."""

    def __init__(self, recordings, clock=time.time):
        self.recordings, self.clock = recordings, clock
        self.log, self.started, self.scenario, self.exit_code, self.running = None, None, None, None, False
        self.test = False                      # True: `log` is a test's file; False: the session's start (no test yet)
        self.ended_vm = None                   # the test machine's own time of the test's end (seconds), when it gave one
        self.run_id = None                     # the current test's own run id (the launcher puts it on the test's command line)
        self.session = None                    # names the machine start the current file belongs to (its start file)
        self.no_disc = False                   # the session is on the no-disc-change path (its steps have their own words)
        self.more = None                       # () -> can another test still be started in this session? (set by the router)
        self.resumed_at = None                 # a test shown again after a restart: this laptop's time of its click
        self.ended_at = None                   # ... and of its end, when the session's notes know it
        self.test_from = None                  # ... and of the moment its program was seen running
        self.lock = threading.Lock()

    def begin(self, scenario, run_id=None):
        folder = os.path.join(self.recordings, "live")
        os.makedirs(folder, exist_ok=True)
        with self.lock:
            self.log = os.path.join(folder, f"warm-run-{int(time.time() * 1000)}.log")
            open(self.log, "w", encoding="utf-8").close()
            self.started, self.scenario, self.exit_code, self.running, self.test = self.clock(), scenario, None, True, True
            self.ended_vm, self.run_id, self.resumed_at, self.ended_at, self.test_from = None, run_id, None, None, None
            return self.log

    def resume(self, run, running):
        """After a restart of the dashboard: the session's last test again, from the session's own notes
        (`run`), so the live view shows that test's alerts (found by its own programs,
        engine/dashboard/attribution.py) instead of every alert in the store. The elapsed time goes on from
        the test's own click (and stops at its own end), instead of starting again at the restart."""
        scenario, run_id = run["scenario"], run["run_id"]
        log = self.begin(scenario, run_id)
        with self.lock:
            clicked, finished = run.get("clicked"), run.get("finished")
            if isinstance(clicked, (int, float)) and clicked <= self.clock():
                self.started = self.resumed_at = float(clicked)
                at = run.get("running_at")
                if isinstance(at, (int, float)) and clicked <= at <= self.clock():
                    self.test_from = float(at)
                if not running and isinstance(finished, (int, float)) and finished >= clicked:
                    self.ended_at = float(finished)
            not_run = bool(run.get("not_started"))
            ok = run.get("step") == "done"
            with open(log, "a", encoding="utf-8") as f:
                if not_run:                                  # its program never started: the steps it never reached stay open
                    f.write(MARKS["building"] + "\n" + MARKS["inserted"] + f"\nRUN {run_id}: warm test not started\n")
                else:
                    f.write("\n".join(MARKS[w] for w in ("building", "inserted", "running")) + "\n")
                    if not running and ok:
                        f.write(MARKS["flushing"] + f"\nRUN {run_id}: warm test done\n")
            if not running:
                self.running, self.exit_code = False, 0 if ok else 1
        return log

    def begin_session(self):
        """The click on "start the test machine". From here until the first test, the live view treats the
        machine like a one-boot run that is still starting: what is raised now is a start-up alert (the
        quiet line), not a test's alert, and older alerts are history."""
        folder = os.path.join(self.recordings, "live")
        os.makedirs(folder, exist_ok=True)
        with self.lock:
            self.log = os.path.join(folder, f"warm-session-{int(time.time() * 1000)}.log")
            open(self.log, "w", encoding="utf-8").close()
            self.started, self.scenario, self.exit_code, self.running, self.test = self.clock(), None, None, False, False
            self.session, self.ended_vm, self.run_id, self.resumed_at, self.ended_at, self.test_from = self.log, None, None, None, None, None
            return self.log

    def step(self, run_id, word, at=None):
        """Called by the session for each step of a test (and of the start, which has no test file).
        `at`: the test machine's own time stamp of the step, when the launcher gave one."""
        if not self.running or not self.log:
            return
        if word == "done":
            self.ended_vm = vm_seconds(at)
        line = MARKS.get(word)
        with self.lock:
            if word == "done":
                # a finished test has passed every step, also when this dashboard was not there to see each
                # one (a test that ended after a restart showed its last step unchecked, 2026-11-21)
                try:
                    with open(self.log, encoding="utf-8") as f:
                        have = f.read()
                except OSError:
                    have = ""
                missing = [MARKS[w] for w in ("building", "inserted", "running", "flushing") if MARKS[w].splitlines()[-1] not in have]
                line = "\n".join(missing + [f"RUN {run_id}: warm test done"])
            elif word == "not_run":                           # proven by the session: the test's program never started
                line = f"RUN {run_id}: warm test not started"
            if line:
                with open(self.log, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if word in ("done", "failed", "not_run"):
                self.running, self.exit_code = False, 0 if word == "done" else 1

    def close(self, log):
        """The thread of the test that wrote `log` has ended. If no step said how the test ended (the thread
        died on something unforeseen), it did not finish: the live view must not show a running test for ever."""
        with self.lock:
            if self.running and self.log == log:
                self.running, self.exit_code = False, 1


class Current:
    """What the live view follows: the newest of the one-boot run and the warm session's test. It looks
    like the one-boot Runner to live_status (log, started, status(), lock) and adds the warm step words."""

    def __init__(self, runner, warm_runs):
        self.runner, self.warm = runner, warm_runs
        self.lock = getattr(runner, "lock", None) or threading.Lock()

    def _warm(self):
        return self.warm.started is not None and (self.runner.started is None or self.warm.started >= self.runner.started)

    @property
    def log(self):
        return self.warm.log if self._warm() else self.runner.log

    @property
    def started(self):
        return self.warm.started if self._warm() else self.runner.started

    @property
    def step_words(self):
        if not (self._warm() and self.warm.test):
            return None
        return STEP_MARKERS_NO_DISC if self.warm.no_disc else STEP_MARKERS

    @property
    def outcome_words(self):
        if not (self._warm() and self.warm.test):
            return None
        try:
            last = self.warm.more is not None and not self.warm.more()
        except Exception:
            last = False
        return {**OUTCOMES, "done": WORDS["run_done_last"]} if last else OUTCOMES

    @property
    def carries_over(self):
        """A warm test runs in a machine that is already on: alerts that exist at its click are an earlier
        test's (live_status leaves them out of this test's view). A one-boot run starts from a restore."""
        return self._warm()

    @property
    def session(self):
        """Which machine start the current warm file belongs to (None: a one-boot run). The live view keeps
        that start's own alerts as the quiet start-up line for every test of the session."""
        return self.warm.session if self._warm() else None

    @property
    def starting_phase(self):
        return self._warm() and not self.warm.test

    @property
    def clock_margin(self):
        """A warm test: an alert counts as the test's from WARM_CLOCK_MARGIN_S before the laptop saw the test
        program start (the one-boot minute would reach back into the machine's own housekeeping)."""
        return WARM_CLOCK_MARGIN_S if self._warm() and self.warm.test else None

    @property
    def run_id(self):
        """The current warm test's run id: the live view finds the test's own programs by it."""
        return self.warm.run_id if self._warm() and self.warm.test else None

    @property
    def test_ended_at(self):
        """When the current warm test ended, on the test machine's own clock (the clock alerts are stamped
        with); None while it runs, for the session's start, or when the launcher gave no time."""
        return self.warm.ended_vm if self._warm() and self.warm.test and not self.warm.running else None

    @property
    def resumed_at(self):
        """A warm test shown again after a restart of the dashboard: this laptop's time of its click (the
        live view then counts as "already there" only what is stamped before that click, instead of
        everything that exists at the restart). None for anything else."""
        return self.warm.resumed_at if self._warm() and self.warm.test else None

    @property
    def resumed_test_at(self):
        """... and this laptop's time when that test's program was seen running, when the notes know it."""
        return self.warm.test_from if self._warm() and self.warm.test else None

    @property
    def ended_at(self):
        """This laptop's time of the end of a test shown again after a restart, when the notes know it."""
        return self.warm.ended_at if self._warm() and self.warm.test else None

    @property
    def before_mixed_words(self):
        return WORDS["before_mixed"] if self._warm() and self.warm.test else None

    @property
    def before_words(self):
        """Before a test's program starts: the warm words. While the machine itself is starting (no test
        yet), the one-boot words fit as they are ("during the test machine's start-up")."""
        return WORDS["before_test"] if self._warm() and self.warm.test else None

    def status(self):
        if self._warm():
            return RunStatus(self.warm.running, self.warm.scenario, self.warm.started, self.warm.exit_code)
        return self.runner.status()


def make_router(session, runner, warm_runs, mode, clock=time.time, watch=True, on_begin=None):
    """`session`: a demo/warm_vm.py WarmSession (or a stand-in with the same methods), or None when this
    dashboard has no warm machine (a replay, a plain development server).
    `on_begin`: called inside the request right after a start or a test was begun, so the live view notes
    at the click itself which alerts already existed (not a second later)."""
    on_begin = on_begin or (lambda: None)
    router = APIRouter()
    enabled = session is not None and mode in ("live", "rehearsal")
    busy = threading.Lock()

    def one_boot_running():
        return bool(runner.status().running)

    def in_thread(fn, *args, after=None):
        def work():
            try:
                fn(*args)
            except Exception:                  # the session keeps its own plain error words; nothing to add here
                pass
            finally:
                if after:
                    after()
        threading.Thread(target=work, daemon=True).start()

    def claim(fn, *args):
        """Take the session inside the request (one locked step in the session: of two clicks at the same
        moment one is refused here, with the session's own plain reason)."""
        try:
            return fn(*args)
        except Exception as e:
            raise HTTPException(status_code=409, detail=str(e))

    if enabled:
        # "stays on for the next test" is said only while another test can really be started
        warm_runs.more = lambda: any(session.can_run(s) is None for s in session.status().get("allowed", []))
    if enabled and watch:
        threading.Thread(target=session.watch, daemon=True).start()     # the shutdown by itself when the time is up
    if enabled and session.status().get("adopted"):
        # a session taken back after a restart: the live view follows its last test again (or, with no test
        # yet, its start), not the plain store
        st0 = session.status()
        try:
            if st0["runs"]:
                last = st0["runs"][-1]
                warm_runs.resume(last, running=bool(st0.get("unfinished")))
            else:
                warm_runs.begin_session()
        except (OSError, KeyError):
            pass

    def view():
        if not enabled:
            return {"enabled": False, "words": WORDS}
        st = session.status()
        warm_runs.no_disc = bool(st.get("no_disc"))            # (the session's own path: a session taken back keeps its own)
        out = {"enabled": True, "words": WORDS, **st, "other_run": one_boot_running(), "text": WORDS["states"].get(st["state"], st["state"])}
        if st["state"] == "starting":
            # the start as a short list of steps, with the time since the click (counted here, by one clock)
            order = ["booting", "settling"]
            at = order.index(st["boot_step"]) if st.get("boot_step") in order else 0
            out["boot_list"] = [{"text": WORDS["boot_steps"][k], "state": "done" if i < at else "current" if i == at else "todo"}
                                for i, k in enumerate(order)] + [{"text": WORDS["states"]["ready"], "state": "todo"}]
        left = st.get("seconds_left")
        if st["state"] in ("starting", "ready", "running") and st.get("no_disc"):
            out["hint"] = WORDS["no_disc"]                       # the trial is never run unseen
        if st["state"] in ("ready", "running") and st.get("early_limit"):
            out["hint"] = (WORDS["no_disc"] + " " + WORDS["early_limit_no_disc"] if st.get("no_disc") else WORDS["early_limit"]).format(minutes=st.get("tests_for_min"))
        if st["state"] == "ready" and st.get("busy_inside"):
            out["hint"] = WORDS["busy_inside"]
        if st["state"] == "recovering":
            out["hint"] = WORDS["unfinished"] if st.get("unfinished") else WORDS["recovering_hint"]
            if st.get("ready_until"):
                left = max(0, int(st["ready_until"] - clock()))
        if st.get("foreign") and st["state"] in ("off", "failed", "ended"):
            out["foreign_text"] = WORDS["foreign"]
            out["text"] = WORDS["states"]["foreign"]              # never "is off" beside "is on"
        if st["state"] in ("ready", "running", "recovering") and st.get("ready_until") and left is not None:
            out["ready_text"] = WORDS["ready_until"].format(time=time.strftime("%H:%M", time.localtime(st["ready_until"])), minutes=left // 60)
            if left <= 0:
                out["warning"] = WORDS["time_up"]
            elif left < 180:
                out["warning"] = WORDS["last_minutes"].format(minutes=left // 60 + 1)
        if st["state"] == "off" and st.get("ended"):
            out["ended_text"] = WORDS["ended"].get(st["ended"], WORDS["ended"]["asked"])
        out["tests"] = [{"id": s, "label": WORDS["tests"].get(s, s.upper()), "used": s in st["used"],
                         "can_run": st["state"] == "ready" and not out["other_run"] and session.can_run(s) is None} for s in st["allowed"]]
        out["can_start"] = st["state"] in ("off", "failed", "ended") and not out["other_run"]
        out["can_stop"] = (st["state"] == "ready" and not st.get("busy_inside")) or st["state"] == "failed" \
            or (st["state"] == "recovering" and not st.get("unfinished"))
        return out

    @router.get("/api/warm")
    def warm_state():
        return view()

    def need():
        if not enabled:
            raise HTTPException(status_code=409, detail="this dashboard has no warm test machine")

    @router.post("/api/warm/start")
    def warm_start():
        need()
        with busy:
            if one_boot_running():
                raise HTTPException(status_code=409, detail=WORDS["other_run"])
            state = session.status()["state"]
            if state not in ("off", "failed", "ended"):
                raise HTTPException(status_code=409, detail=WORDS["states"].get(state, "busy"))
            claim(session.claim_start)
            try:
                warm_runs.begin_session()
                on_begin()
            except Exception:                  # the live view's bookkeeping is never a reason not to start
                pass
            in_thread(session.start, True)
        return view()

    @router.post("/api/warm/run/{scenario}")
    def warm_run(scenario: str):
        need()
        with busy:
            if one_boot_running():
                raise HTTPException(status_code=409, detail=WORDS["other_run"])
            run = claim(session.claim_run, scenario)
            try:
                log = warm_runs.begin(run["scenario"], run["run_id"])
                on_begin()
            except Exception:                  # no progress file: the test still runs, the live view just can't follow it
                log = None

            def ended():
                warm_runs.close(log)
                release = getattr(session, "release", None)
                if release:
                    release(run)
            in_thread(session.run, scenario, run, after=ended)
        return view()

    @router.post("/api/warm/stop")
    def warm_stop():
        need()
        with busy:
            state = session.status()["state"]
            if state not in ("ready", "failed", "recovering"):   # only a machine this session started and that is not busy
                raise HTTPException(status_code=409, detail=WORDS["states"].get(state, state))
            if state == "recovering" and session.status().get("unfinished"):
                raise HTTPException(status_code=409, detail=WORDS["unfinished"])
            if state == "ready" and session.status().get("busy_inside"):
                raise HTTPException(status_code=409, detail=WORDS["busy_inside"])
            in_thread(session.stop)
        return view()

    router.active = (lambda: enabled and session.status()["state"] not in ("off", "failed", "ended"))   # for the one-boot buttons
    return router
