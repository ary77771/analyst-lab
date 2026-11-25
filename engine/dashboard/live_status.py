"""The Live screen's two read-only feeds (debate 11, A2 and the fresh review's items 3 and 4).

/api/health: the heartbeat banner. It never says "all clear" (nothing can prove a machine is fine;
if the recorder died, records would simply stop). It reports what is known:
  - waiting   "Waiting: no records from the test machine yet" (no event in the store, no run going)
  - starting  "Starting the test machine: no records yet"   (no event yet, this dashboard's VM run going)
  - watching  "Watching: last record N s ago, no alerts raised"
  - quiet     "No new records for N s" (amber: the machine may be idle, or not running)
  - alert     the newest raised alert's title and level (red), at or above the frozen floor
"N s ago" is ARRIVAL time by the laptop's clock (when the store last grew), never the event's own
time: replayed runs carry their old recorded dates, and the VM's clock may be skewed.

/api/run/steps: the VM run's progress as plain steps, read from the frozen tools/run_in_vm.py log
markers ("--> 1." ...). The raw log is never sent to the page (it can hold laptop paths).
"""

import os
import re
import sqlite3
import threading
import time

from fastapi import APIRouter, Request, Response

from .. import config
from ..alerts import LEVELS, AlertStore

QUIET_AFTER_S = 90      # amber after this long without a new record; to be checked at rehearsal 1
# The replay dashboard (demo port 8781) may read THIS route of the live one, to show a small "the live
# test machine raised an alert" notice (approved 2026-11-20: this origin, this route, GET only).
HEALTH_READERS = frozenset({"http://127.0.0.1:8781"})

def replay_playing(records):
    """While a demo replay is still feeding its store: how far it is, and the sentence the screens say in place
    of "No alerts have been raised in this recording." None otherwise, and on any trouble.
    The replay itself says when it starts and when it is done (tools/demo_replay.py -> engine/labs/_replay.py,
    a few values in memory; nothing here depends on Labs being switched on)."""
    try:
        from engine.labs import _replay
        st = _replay.state()
        if not st or st["done"]:
            return None
        n = int(records or 0)
        return {"total": st["total"], "records": n, "text": WORDS["replay_playing"].format(n=n, total=st["total"])}
    except Exception:
        return None


WORDS = {
    "waiting": "Waiting: no records from the test machine yet",
    "starting": "Starting the test machine: no records yet",
    "watching": "Watching: last record {n} s ago, no alerts raised",
    "quiet": "No new records for {n} s (the machine may be idle, or not running)",
    "alert": "Alert raised",
    "records": "{n} record{s} received",
    # while a demo replay is still feeding its store (2026-11-24: Watch said "No alerts have been raised in this
    # recording." about a recording of which 14 of 85 records had arrived). The old sentence stays for a
    # recording that is whole and has no alert.
    "replay_playing": "No alert yet: the replay is still playing ({n} of {total} records).",
    "watch_note": "Watching since the test program started",
    "before_test": "{n} alert{s} during the test machine's start-up, before the test program ran (or while its "
                   "recorder was starting): see why",
    "after_test": "{n} alert{s} after this test finished, not part of it: see why",
    "other_programs": "{n} alert{s} from other programs on the test machine, not part of this test: see why",
}

# run_in_vm relays the VM launcher's states; "running (...)" is printed right before a scenario
# program starts (after the calm-down wait), so it marks the start of the test. A batch run prefixes
# the scenario ("VM: S1: running (calm)"); a single run does not ("VM: running (calm)").
LAUNCHER = re.compile(r"VM: (?:[SCB]\d+[A-Z]?: )?running")
LAUNCHER_MARK = "VM: running"        # kept for readers; matching uses LAUNCHER
# the VM's clock is not synchronised with the laptop's (time sync off; skew measured up to ~9 s), so
# an alert stamped up to a minute before the laptop saw the launcher start still counts as the test's
CLOCK_MARGIN_S = 60


def _epoch(t):
    from datetime import datetime
    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()

STEPS = [   # (marker in run_in_vm's log, plain words)
    ("--> 1.", "Preparing the run"),
    ("--> 2.", "Restoring the prepared test machine and starting it"),
    ("--> 3.", "Test program running inside the machine"),
    ("--> 4.", "Checking what was recorded"),
    ("--> 5.", "Shutting the test machine down"),
]
SETTLING_STEP = "The machine is on: waiting for Windows to settle before the test starts"
RESULT_PREFIX = "RUN "
OUTCOME_WORDS = {
    "not_started": "The run could not start; the test machine was not touched.",
    "done": "Run finished: the test machine was shut down.",
    "stopped": "The run stopped before the end.",
}


def run_steps(log_path, exit_code=None, steps=None, outcomes=None):
    """[{text, state: done|current|todo}], whether the run finished, and a plain outcome line, from
    the run's own log (its markers and its final "RUN <id>: ..." line, never the raw text).
    `steps` / `outcomes`: other markers and words than the one-boot run's (a warm test has four steps
    and its own outcome line: engine/dashboard/warm.py)."""
    STEPS, OUTCOME_WORDS = steps or globals()["STEPS"], outcomes or globals()["OUTCOME_WORDS"]
    lines = []
    if log_path and os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    reached = [i for i, (marker, _) in enumerate(STEPS) if any(l.startswith(marker) for l in lines)]
    last = max(reached) if reached else -1
    result = next((l for l in reversed(lines) if l.startswith(RESULT_PREFIX)), None)
    finished = result is not None
    not_started = finished and "not started" in result
    default_words = steps is None
    steps = [{"text": text, "state": "done" if (i < last or (finished and not not_started and i <= last)) else
              "failed" if (not_started and i == last) else "current" if i == last and not finished else "todo"}
             for i, (_, text) in enumerate(STEPS)]
    # run_in_vm prints its step 3 the moment the machine has logged on, minutes before the test program
    # starts (inside, the launcher first waits for Windows to settle). Seen on the real run of 2026-11-20:
    # the screen said "Test program running" from 1:40 while nothing ran yet. Until the launcher's own
    # "running" line arrives, the step says what is really going on.
    if default_words and last == 2 and not finished and not any(LAUNCHER.search(l) for l in lines):
        steps[2]["text"] = SETTLING_STEP
    # a batch boot runs several test programs: say which one is running ("2 of 3")
    batch = next((re.search(r"Batch of (\d+)", l) for l in lines if l.startswith("Batch of ")), None)
    if batch:
        total = int(batch.group(1))
        started = sum(1 for l in lines if LAUNCHER.search(l))
        if 0 < started and len(steps) > 2:
            steps[2]["text"] += f" ({min(started, total)} of {total})"
    outcome = None
    if not_started:
        outcome = OUTCOME_WORDS["not_started"]
    elif finished:
        outcome = OUTCOME_WORDS["done"]
    elif exit_code not in (None, 0):
        outcome = OUTCOME_WORDS["stopped"]
    return {"steps": steps, "finished": finished, "outcome": outcome}


def make_router(events_db, alerts_db, runner, clock=time.time, watch_log=True):
    router = APIRouter()
    seen = {"max_id": None, "at": None}

    def store_counts():
        """(newest row id, number of rows) of the event store; (None, 0) when it is missing or empty.
        The id tells that something arrived; the screen's "records received" is the counted rows."""
        if not os.path.exists(events_db):
            return None, 0
        con = sqlite3.connect("file:" + os.path.abspath(events_db).replace("\\", "/") + "?mode=ro", uri=True)
        try:
            m, n = con.execute("SELECT MAX(id), COUNT(*) FROM events").fetchone()
            return m, n or 0
        except sqlite3.OperationalError:
            return None, 0
        finally:
            con.close()

    def raised():
        if not os.path.exists(alerts_db):
            return []
        s = AlertStore(alerts_db)
        try:
            floor = LEVELS.index(config.min_level())
            return [a for a in s.read() if LEVELS.index(a.level) >= floor]
        finally:
            s.close()

    # old: alerts that existed when this run was clicked in a machine that was already on (never this run's)
    # boot: of those, the ones the machine's own start-up raised in this warm session (kept as the quiet line)
    view = {"log": None, "from": None, "old": frozenset(), "boot": frozenset(), "session": None, "starting": False}
    from .attribution import Trees
    trees = Trees(events_db)                                   # whose alert is it, by the test's own programs
    lock = threading.Lock()

    def note_new_run(log):
        """Called once when the current run changes. A warm test starts in a machine that is already running
        (engine/dashboard/warm.py): the alerts that already exist at its click are not this test's. Among
        them, the ones raised while THIS session's machine was starting up stay on screen as the quiet
        start-up line for every test of the session, as a one-boot run shows its own (PROOF 2026-11-21).
        A one-boot run starts from a restored machine: nothing carries over there."""
        carries = bool(log) and getattr(runner, "carries_over", False)
        # A test shown again after a restart of the dashboard: "already there at its click" can't be read off
        # the store any more (its own alerts and the machine's later ones exist by now), so it is what is
        # STAMPED before that click. Without this, alerts other programs raised since the click were on no
        # line at all after a restart (2026-11-21).
        resumed = getattr(runner, "resumed_at", None) if carries else None
        try:
            if resumed is not None:
                cut = resumed - (getattr(runner, "clock_margin", None) or CLOCK_MARGIN_S)
                existing = frozenset(a.alert_id for a in raised() if _epoch(a.time) < cut)
            else:
                existing = frozenset(a.alert_id for a in raised()) if carries else frozenset()
        except Exception:
            existing = frozenset()
        session = getattr(runner, "session", None) if carries else None
        if session is None or session != view["session"]:
            boot = frozenset()                                   # another machine start, or a one-boot run
        elif view["starting"]:
            boot = existing - view["old"]                        # the session's first test: what its start-up raised
        else:
            boot = view["boot"]                                  # a later test of the same session
        view.update(log=log, old=existing - boot, boot=boot, session=session,
                    starting=bool(carries and getattr(runner, "starting_phase", False)))
        view["from"] = None

    def test_started_at():
        """Laptop time when this dashboard's current run first showed a test program starting (run_in_vm's
        relayed "VM: running (...)" or, in a batch, "VM: S1: running (...)" line), or None. Debate 12
        option (c): the live view watches from there; anything earlier in the same run is start-up.
        A background thread calls this every second, so the time is taken when the line is written,
        not when someone next opens the Live screen (fresh review 2026-11-20, blocker 3)."""
        with lock:
            log = runner.log
            if log != view["log"]:
                note_new_run(log)
            if log and view["from"] is None and os.path.exists(log):
                with open(log, encoding="utf-8", errors="replace") as f:
                    if any(LAUNCHER.search(line) for line in f):
                        # (a test shown again after a restart: the moment its program was seen running then)
                        view["from"] = getattr(runner, "resumed_test_at", None) or clock()
            return view["from"]

    ended = {"log": None, "at": None}

    def run_ended_at():
        """The dashboard clock's time when this dashboard's run was first seen finished or stopped (None while
        it runs, or with no run), so the page's elapsed time stops instead of counting on for ever."""
        with lock:
            log = runner.log
            if log != ended["log"]:
                ended["log"], ended["at"] = log, None
            if log and ended["at"] is None:
                # under the runner's own lock: Runner.start sets the new log BEFORE the new process, and for
                # that instant status() still describes the previous, finished run (review 2026-11-20:
                # a second run could be stamped "ended" at once and show Elapsed 00:00)
                with getattr(runner, "lock", None) or threading.Lock():
                    same, st = runner.log == log, runner.status()
                if same and not st.running and (st.exit_code is not None or run_steps(log)["finished"]):
                    known = getattr(runner, "ended_at", None)     # a test shown again after a restart: its own end
                    ended["at"] = known if known is not None else clock()
            return ended["at"]

    def watch():
        while True:
            try:
                test_started_at()
                run_ended_at()
            except Exception:
                pass
            time.sleep(1)

    if watch_log:
        threading.Thread(target=watch, daemon=True).start()
    router.view = view                                          # read by tests
    router.observe = test_started_at                            # the warm buttons call this at the click (warm.py: on_begin)

    def split(everything):
        """(in view, before the test, after the test, from other programs) for this dashboard's current run.
        By the clock (by_time) until the records can say more. Once the start of the test's own first program
        is recorded (a warm test names its run id: engine/dashboard/attribution.py), the test's alerts are the
        ones about ITS OWN PROGRAMS, whenever they were raised, and anything else the clock had counted since
        the click is from another program on the machine: its own quiet line, never the test's banner."""
        inside, before, after = by_time(everything)
        tree = trees.tree(getattr(runner, "run_id", None))
        if tree is None:
            return inside, before, after, []
        mine = [a for a in everything if trees.programs(a) & tree]
        own = {a.alert_id for a in mine}
        boot = [a for a in before if a.alert_id in view["boot"] and a.alert_id not in own]
        other = [a for a in inside + before + after if a.alert_id not in own and a.alert_id not in view["boot"]]
        return mine, boot, [], sorted(other, key=lambda a: a.time)

    def by_time(alerts):
        """(in view, before the test, after the test) for this dashboard's current run; with no run, all in
        view. Alerts older than the run itself (an earlier run in the same store) are in no list.
        A test's view closes at its end (PROOF 2026-11-21): what is raised after the test finished is not
        the test's, and is shown as its own quiet line, like the start-up line."""
        if not runner.log:
            return alerts, [], []
        start = test_started_at()                               # (also notes which alerts an earlier warm test raised)
        run_start = (runner.started or 0) - CLOCK_MARGIN_S
        boot = [a for a in alerts if a.alert_id in view["boot"]]       # this warm session's start-up alerts: always the quiet line
        alerts = [a for a in alerts if _epoch(a.time) >= run_start and a.alert_id not in view["old"] and a.alert_id not in view["boot"]]
        # how far before the laptop SAW the test start an alert may be stamped and still count as the test's.
        # One-boot: a minute (nothing else is going on in a machine that just booted). A warm test is clicked
        # in a machine that is already busy with its own housekeeping, so the margin is only what the clocks
        # and the polling can differ by (measured 2026-11-20/21: the VM's messages arrive 0.7-6.8 s late).
        margin = getattr(runner, "clock_margin", None) or CLOCK_MARGIN_S
        if start is None:
            over = run_ended_at()
            if over is None:
                return [], boot + alerts, []                    # the run is still booting
            # the run is over and its test never started: what is raised after that is not "before the test"
            # of anything (seen 2026-11-21: after a warm test whose disc change was missed, every later alert
            # stayed out of view for ever)
            return [a for a in alerts if _epoch(a.time) >= over - margin], boot + [a for a in alerts if _epoch(a.time) < over - margin], []
        cut = start - margin
        inside = [a for a in alerts if _epoch(a.time) >= cut]
        # the end: the test machine's own time of it when the run knows it (a warm test: the same clock the
        # alerts carry, so exact); else this laptop's time when the run was seen over (a one-boot run: its
        # machine is shut down by then)
        end = getattr(runner, "test_ended_at", None)
        if end is None:
            end = run_ended_at()
        after = [a for a in inside if end is not None and _epoch(a.time) > end]
        late = {a.alert_id for a in after}
        return [a for a in inside if a.alert_id not in late], boot + [a for a in alerts if _epoch(a.time) < cut], after

    @router.get("/api/health")
    def health(request: Request, response: Response):
        origin = request.headers.get("origin")
        if origin in HEALTH_READERS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        now = clock()
        m, count = store_counts()
        if m is not None and m != seen["max_id"]:
            seen["max_id"], seen["at"] = m, now
        everything = sorted(raised(), key=lambda a: a.time)
        alerts, before, after, other = split(everything)
        out = {"events_max_id": m, "alerts": len(alerts), "quiet_after_s": QUIET_AFTER_S,
               "view_ids": [a.alert_id for a in alerts], "watch_note": None, "before_test": None, "after_test": None, "other_alerts": None,
               "records": count, "records_text": WORDS["records"].format(n=count, s="" if count == 1 else "s")}
        playing = replay_playing(count)
        if playing:                                   # only while a replay is still feeding; otherwise the key is not there
            out["replay_playing"] = playing
        if view["from"] is not None and runner.log:
            out["watch_note"] = WORDS["watch_note"]
        if before:
            # which sentence: all from the machine's start-up (the one-boot words fit), all after a warm click
            # (the warm words), or some of each (the warm session's sentence that says both)
            n_boot = sum(1 for a in before if a.alert_id in view["boot"])
            words = WORDS["before_test"]
            if n_boot < len(before):
                words = getattr(runner, "before_words" if n_boot == 0 else "before_mixed_words", None) or WORDS["before_test"]
            out["before_test"] = {"count": len(before), "id": before[-1].alert_id,
                                  "text": words.format(n=len(before), s="" if len(before) == 1 else "s")}
        if after:
            out["after_test"] = {"count": len(after), "id": after[-1].alert_id,
                                 "text": WORDS["after_test"].format(n=len(after), s="" if len(after) == 1 else "s")}
        if other:
            out["other_alerts"] = {"count": len(other), "id": other[-1].alert_id,
                                   "text": WORDS["other_programs"].format(n=len(other), s="" if len(other) == 1 else "s")}
        if m is None:
            # "starting" only while this dashboard's own VM run is going; otherwise nothing is starting
            st = "starting" if runner.status().running else "waiting"
            out.update(state=st, text=WORDS[st], seconds=None)
        else:
            n = int(now - seen["at"])
            out["seconds"] = n
            if alerts:
                a = alerts[-1]
                out.update(state="alert", text=WORDS["alert"], alert={"id": a.alert_id, "title": a.title, "level": a.level, "time": a.time})
            elif n >= QUIET_AFTER_S:
                out.update(state="quiet", text=WORDS["quiet"].format(n=n))
            else:
                out.update(state="watching", text=WORDS["watching"].format(n=n))
        return out

    @router.get("/api/run/steps")
    def steps():
        st = runner.status()
        d = run_steps(runner.log, st.exit_code, getattr(runner, "step_words", None), getattr(runner, "outcome_words", None))
        # started = the laptop's clock when this dashboard started the run, so the page's timer
        # survives a reload (debate 12, worry 2)
        d.update(running=st.running, scenario=st.scenario, exit_code=st.exit_code, started=st.started, now=clock(),
                 ended=run_ended_at())
        return d

    return router
