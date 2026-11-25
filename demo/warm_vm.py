"""The warm test machine (2026-11-21): boot the lab VM ONCE, then start tests one by one. PRACTICE RUNS ONLY.

    python demo/warm_vm.py cycle s1 s4     # start, run S1 then S4, shut down; prints the measured times
    python demo/warm_vm.py stop            # shut the test machine down, whatever state this tool is in
    python demo/warm_vm.py status          # what the last warm session wrote down (no VirtualBox call)

Why: a one-boot run (tools/run_in_vm.py) restores, boots and shuts down for every click: about 9
minutes to the alert. Yousif wants to start the machine once and run tests live during the demo.

How (design agreed with PROOF, option "c"): nothing in the VM or its snapshot changes.
  1. START: restore the prepared snapshot, insert a "warm CD", boot. The VM's unchanged logon starter
     runs the launcher it finds on the CD: demo/warm/warm_launcher.ps1, which does the usual waits,
     says "warm-ready" and then WAITS instead of exiting.
  2. RUN <scenario>: build an ordinary run CD with the frozen tools/make_scenario_cd.ps1, copy it to
     its own folder, swap it into the running VM. The waiting launcher checks it and runs that CD's
     own run_scenario.ps1 (see the launcher's header for what it refuses).
  3. STOP: a controlled shutdown. It also happens by itself when no further test can start.

BEHIND A SWITCH, OFF BY DEFAULT (2026-11-21, PROOF and Yousif): the NO-DISC-CHANGE path. Set the
environment variable ANALYSTLAB_WARM_NO_DISC=1 (or pass no_disc=True / "--no-disc-change") and step 2 is:
  2'. RUN <scenario>: no CD is built or changed. The warm CD stays in the drive; it already holds
      run_scenario.ps1 and every scenario's programs (the frozen builder puts them on every CD). Its note
      carries one run id per test, made at the start, and the SHA-256 of each of its files, which the
      launcher (demo/warm/warm_launcher_signal.ps1) checks once before it says ready. This side then
      only NAMES the test: it sets one VirtualBox guest property (SIGNAL) to that test's run id.
      The rule (PROOF): "The only thing the laptop can send the test machine is the name of one of this
      session's three pre-checked tests." The value is one of the session's three run ids or nothing;
      no part of it is ever executed or used as a path; the launcher refuses anything else in words.
The CD path above, with its stop-gap (START_TESTS_FOR_S), stays the default until a real session has
proven the other. Why the other exists: on 2026-11-21 both disc changes made later than 14 minutes
after the machine's start hung for minutes (all ten earlier ones worked). The stop-gap holds on the
no-disc-change path too (2026-11-23): its first real trial showed that changing no disc is not enough,
a test named about 15 minutes after the start began and then did nothing.

Limits, said plainly on screen too:
  - The snapshot's logon task is stopped by Windows 30 minutes after logon. The launcher ends itself
    at 27 minutes and refuses a test that could not finish by then. So a session has a "ready until"
    time: the launcher reports how many seconds remain, and this side turns that into a clock time
    with ITS OWN clock (the VM's clock is not synchronised).
  - Not a fresh machine per test: each scenario runs at most once per session.
  - Practice only: refused when ANALYSTLAB_OFFICIAL is set; nothing is written to
    recordings/scenario_runs (the official runs' summaries). Session notes go to recordings/live/warm/.

Frozen code is imported or called, never edited: tools/run_in_vm.py (VBox, Tail, the record
matchers), tools/make_scenario_cd.ps1, tools/lab_servers.ps1. VBoxManage is called only inside
start(), run() and stop(); status() reads memory. Prints states and counts only (privacy rule 7).
"""

import argparse
import glob
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import run_in_vm as R  # noqa: E402  (frozen: imported, never edited)

ALLOWED = ("s1", "s4", "s5")                 # what the 3-test batch already runs in one boot; the launcher has the same list
SNAPSHOT = "lived-in"                        # the prepared snapshot the dashboard's one-boot runs use
WARM_DIR = os.path.join(PROJECT_ROOT, "build", "warm")
LAUNCHER = os.path.join(PROJECT_ROOT, "demo", "warm", "warm_launcher.ps1")
LAUNCHER_SIGNAL = os.path.join(PROJECT_ROOT, "demo", "warm", "warm_launcher_signal.ps1")     # the no-disc-change path's launcher
NO_DISC_ENV = "ANALYSTLAB_WARM_NO_DISC"      # "1": the no-disc-change path (off by default)
WORST_TEST_S = 450                           # the longest one test may take inside the machine (the launcher's own worst case, rounded up)
LAUNCHER_LIFE_S = 27 * 60                    # the launcher ends itself this long after it began
# THE STOP-GAP (2026-11-21, PROOF and Yousif): a test may be STARTED (its disc change begun) only until this
# long after the machine was started. Measured that day: all ten disc changes made up to 14 minutes after
# the machine's start were read in 15 to 45 s; both made later hung for minutes (one was read after 403 s,
# one never). In the five boots that lived long enough, that stretch began 14:16 to 15:20 after the start.
# 12 minutes (PROOF, 2026-11-21; first 13): a test clicked at the limit has its CD built and changed in
# about 14 s and found within 45 s more, so by about 12:59, which is 77 s before the earliest of the five
# (13 minutes left 17 s, too thin on five samples). In a usual start the machine is ready 8 to 10 minutes
# after it was started, so this is about 2 to 4 minutes for STARTING tests: two when the machine was ready
# by about 9:45 (a test takes about two minutes, and only its click must fall inside), otherwise one.
# The screen shows the real end time. Not a fix: the limit only keeps tests out of the stretch in which
# they did not start reliably.
START_TESTS_FOR_S = 12 * 60


def _seconds(stamp):
    """An ISO time stamp (this laptop's "received_utc", or the test machine's seven-decimal one) as seconds."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", str(stamp or ""))
    if not m:
        return None
    import calendar
    try:
        whole = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None
    return whole + (float("0." + m.group(2)) if m.group(2) else 0.0)


READY = re.compile(r"^warm-ready \(([^)]*)\) left=(\d+)$")
DONE = re.compile(r"^done (ok|late)(?: left=(\d+))?$")
ENTRY = re.compile(r"'(/[^=']+)=([^']+)'")
TIMEOUTS = {"unlock": 120, "boot": 480, "launcher": 900, "ready": 720, "noticed": 180, "read": 300, "run": 600, "barrier": 300,
            "shutdown": 180, "picked": 240}
# -- the no-disc-change path (behind the switch) --
SIGNAL = "/AnalystLab/Warm/Run"             # the one guest property this side sets: a run id of the session, or not set at all
SIGNAL_FLAGS = ("--flags", "TRANSIENT")     # VirtualBox drops the property when the machine is switched off. TWO words: VBoxManage
                                            # 7.2.4 refuses "--flags=TRANSIENT" (the form its own help shows) as a syntax error
SIGNAL_EVERY = 8.0                          # while a click waits to be picked up, the signal is taken away and set again this often
SWAP_TRIES, SWAP_PAUSE = 3, 5.0             # a missed disc change gets the same CD again (see WarmSession._await_found)
TAKE_BACK_S = 20.0                          # after the laptop took a CD back out: how long the launcher gets to say it had found it after all
# Why a test did not run, in plain words for the screen (PROOF 2026-11-21: "timed out after 60.0 s waiting
# for the test machine to notice the new CD" said neither what happened nor that the test never ran).
# Each of these is only ever said when the launcher itself never started the test's program.
NOT_RUN = {
    "cd_not_seen": "The test machine did not notice this test's CD ({tries} tries, {minutes} min). The test did not run; it can be started again if time allows.",
    "cd_unreadable": "The test machine saw this test's CD but could not read it ({minutes} min). The test did not run; it can be started again if time allows.",
    "cd_gone": "This test's CD was no longer in the drive when the test was about to start. The test did not run; it can be started again if time allows.",
    # the no-disc-change path
    "not_picked": "The test machine did not pick this test up ({minutes} min). The test did not run; it can be started again if time allows.",
    "taken_back": "The test machine picked this test up only after the laptop had called it off. The test did not run; it can be started again if time allows.",
    "not_named": "The laptop could not name this test to the test machine. The test did not run; it can be started again if time allows.",
}
BEGUN, OVER = ("found-cd", "running", "flushing"), ("done ", "failed", "refused")     # the launcher's own words for a test
BEGUN_ANY = BEGUN + ("picked-up",)          # ... on either path ("picked-up" is the no-disc-change launcher's word for "found-cd")
NOTE, LAUNCHER_ON_CD ="/AUTORUN_SCENARIO.txt", "/scenario_launcher.ps1"


class WarmError(Exception):
    """A warm step was refused or failed. The message is plain words, fit for the screen.
    `why`: a key of NOT_RUN when the step failed in a way that proves the test's program never started."""

    def __init__(self, message, why=None):
        super().__init__(message)
        self.why = why


class WarmTimeout(WarmError):
    """A wait ran out (told apart by its type, never by its words)."""


def copy_cd(src_viso, folder, name, files=None, texts=None, list_into=None, unlisted=()):
    """A frozen copy of a CD the frozen builder just made: every file it lists is copied into `folder`/cd
    and a new .viso pointing at the copies is written (a .viso points at files on the laptop, and the
    builder reuses one folder for every CD: a mounted CD's files must never change under it).
    `files` / `texts` replace single entries (CD path -> source file / text). `list_into`: a CD path of one of
    the `texts`; the SHA-256 of every copied file except the `unlisted` CD paths is appended to it, one line
    each ("file_<n>=<HASH>:<the file's path as Windows names it>") after "files=<how many>".
    Returns the new .viso path."""
    with open(src_viso, encoding="ascii") as f:
        entries = ENTRY.findall(f.read())
    if not entries:
        raise WarmError("the run CD description lists no files")
    stage = os.path.join(folder, "cd")
    if os.path.exists(folder):
        shutil.rmtree(folder)
    parts = ["--iprt-iso-maker-file-marker-bourne-sh", str(uuid.uuid4()), "--file-mode=0444", "--dir-mode=0555"]
    for cd_path, source in entries:
        copy = os.path.join(stage, *cd_path.strip("/").split("/"))
        os.makedirs(os.path.dirname(copy), exist_ok=True)
        if texts and cd_path in texts:
            with open(copy, "w", encoding="ascii", newline="") as out:
                out.write(texts[cd_path])
        else:
            shutil.copyfile((files or {}).get(cd_path, source), copy)
        parts.append(f"'{cd_path}={copy}'")
    if list_into:
        import hashlib
        listed = []
        for cd_path, _ in sorted(entries):
            if cd_path in unlisted or cd_path == list_into:
                continue
            with open(os.path.join(stage, *cd_path.strip("/").split("/")), "rb") as f:
                listed.append(f"{hashlib.sha256(f.read()).hexdigest().upper()}:{cd_path.strip('/').replace('/', chr(92)).lower()}")
        with open(os.path.join(stage, *list_into.strip("/").split("/")), "a", encoding="ascii", newline="") as out:
            out.write(f"\r\nfiles={len(listed)}" + "".join(f"\r\nfile_{n}={line}" for n, line in enumerate(listed, 1)))
    viso = os.path.join(folder, name)
    with open(viso, "w", encoding="ascii", newline="") as out:
        out.write(" ".join(parts))
    return viso


def build_warm_cd(session_id, powershell=R.powershell):
    """The warm CD: exactly a run CD's files (so the launcher's fingerprints match every later run CD),
    with our launcher under the name the VM's starter looks for and a note that says warm=1."""
    code, out = powershell("make_scenario_cd.ps1", "-RunId", session_id, "-Scenario", "s1")
    if code != 0:
        raise WarmError("building the warm CD failed: " + out.strip()[-300:])
    return copy_cd(R.RUN_CD, os.path.join(WARM_DIR, session_id, "warm"), "analystlab-warm.viso", files={LAUNCHER_ON_CD: LAUNCHER},
                   texts={NOTE: f"scenario=s1\r\nrun_id={session_id}\r\nwarm=1\r\npractice=1"})


def build_signal_cd(session_id, run_ids, powershell=R.powershell):
    """The no-disc-change path's warm CD, the only disc of its session: exactly a run CD's files as the frozen
    builder makes them (run_scenario.ps1 and every scenario's programs), with the SIGNAL launcher under the
    name the VM's starter looks for, and a note that says warm=1, carries one run id per test and lists the
    SHA-256 of every file for the launcher to check the CD against before it says ready."""
    code, out = powershell("make_scenario_cd.ps1", "-RunId", session_id, "-Scenario", "s1")
    if code != 0:
        raise WarmError("building the warm CD failed: " + out.strip()[-300:])
    note = f"scenario=s1\r\nrun_id={session_id}\r\nwarm=1\r\npractice=1" + "".join(f"\r\nrun_{s}={run_ids[s]}" for s in ALLOWED)
    return copy_cd(R.RUN_CD, os.path.join(WARM_DIR, session_id, "warm"), "analystlab-warm.viso", files={LAUNCHER_ON_CD: LAUNCHER_SIGNAL},
                   texts={NOTE: note}, list_into=NOTE, unlisted=(LAUNCHER_ON_CD,))


def build_run_cd(session_id, run_id, scenario, powershell=R.powershell):
    """One test's run CD, built by the frozen builder and copied to its own folder (a new path for every
    swap, so neither VirtualBox nor Windows can serve the previous disc)."""
    code, out = powershell("make_scenario_cd.ps1", "-RunId", run_id, "-Scenario", scenario)
    if code != 0:
        raise WarmError("building the run CD failed: " + out.strip()[-300:])
    return copy_cd(R.RUN_CD, os.path.join(WARM_DIR, session_id, run_id), f"run-{run_id}.viso")


class WarmSession:
    """One warm session. States: off -> starting -> ready <-> running -> stopping -> off; `failed` and
    `ended` (time up) both end in a shutdown. One thing at a time; status() never touches VirtualBox."""

    def __init__(self, vbox=None, recordings=None, build_warm=build_warm_cd, build_run=build_run_cd, servers=None,
                 tail=R.Tail, clock=time.time, sleep=time.sleep, say=None, timeouts=None, poll=R.POLL, cpus=1,
                 snapshot=SNAPSHOT, notes=None, on_step=None, owner="cli", no_disc=None, build_signal=build_signal_cd):
        self.vbox = vbox or R.VBox()
        self.recordings = recordings or os.path.join(PROJECT_ROOT, "recordings")
        self.build_warm, self.build_run, self.build_signal = build_warm, build_run, build_signal
        # THE SWITCH (off by default): True = the no-disc-change path for the sessions this object STARTS.
        # `no_disc` is the path of the session it has now (a session taken back after a restart keeps its own).
        self._want_no_disc = (os.environ.get(NO_DISC_ENV) == "1") if no_disc is None else bool(no_disc)
        self.no_disc = self._want_no_disc
        self.run_ids = {}                                    # no-disc path: this session's run id for each test (they are on the CD's note)
        self._since = {}                                     # run id -> where in _states its present attempt begins
        self._signal_value = None                            # no-disc path: what the signal says now (a run id, or None: not set)
        self.servers = servers or (lambda: R.powershell("lab_servers.ps1"))
        self.tail, self.clock, self.sleep, self.poll = tail, clock, sleep, poll
        self.say = say or (lambda *_: None)
        self.on_step = on_step or (lambda *_: None)          # (run id, step word): the dashboard writes its progress lines
        self.timeouts = {**TIMEOUTS, **(timeouts or {})}
        self.cpus, self.snapshot = cpus, snapshot
        self.notes = notes or os.path.join(self.recordings, "live", "warm", "session.json")
        self.owner = owner                                   # who starts sessions here ("cli", "dashboard"): written into the notes
        self.adopted = False                                 # this session was found running after a restart (adopt())
        self.foreign = False                                 # the machine is on, and not by a session of this owner
        self._deadline = None                                # when to give up on a machine found running, if its own time is unknown
        self._read = set()                                   # (run id, state) read back from the files at adoption
        self.boot_mark = None                                # VirtualBox's own stamp of this session's boot (see _mark)
        self.tests_until = None                              # this side's clock: no test is started after it (START_TESTS_FOR_S)
        self.lock = threading.Lock()                         # guards the state fields
        self.pump_lock = threading.Lock()                    # one reader of the record tails at a time
        self.state, self.error = "off", None
        self.session_id, self.ready_until, self.used, self.current = None, None, [], None
        self.runs, self.timings, self.ended = [], {}, None      # ended: why the last session was shut down
        self.boot_step = None                                # booting | settling | ready: which part of the start
        self.starting_since = None                           # this side's clock at the click on "start"
        self._tails, self._states, self._run_recs, self._barriers = None, [], {}, {}
        self._state_at = {}                                  # (run id, state) -> the launcher's own time stamp
        self._ended_by_launcher = False
        self._drive_empty = False                            # this side took the CD out (after giving up on it) and put none in since

    # -- what the screen may ask at any time: memory only ------------------------------------------
    def status(self):
        with self.lock:
            left = None if self.ready_until is None else max(0, int(self.ready_until - self.clock()))
            return {"state": self.state, "error": self.error, "session_id": self.session_id, "ready_until": self.ready_until,
                    "seconds_left": left if self.state in ("ready", "running") else None, "used": list(self.used),
                    "current": dict(self.current) if self.current else None, "runs": [dict(r) for r in self.runs],
                    "timings": dict(self.timings), "allowed": list(ALLOWED), "practice": True, "ended": self.ended,
                    "owner": self.owner, "adopted": self.adopted, "foreign": self.foreign, "boot_mark": self.boot_mark,
                    "tests_until": self.tests_until, "tests_for_min": START_TESTS_FOR_S // 60,
                    "no_disc": self.no_disc, "run_ids": dict(self.run_ids),
                    # True when it is the early limit (not the launcher's own time) that ends the time for tests
                    "early_limit": self.tests_until is not None and self.ready_until is not None and self.ready_until >= self.tests_until,
                    "unfinished": len(self._unfinished()) if self.state == "recovering" else 0,
                    "busy_inside": len(self._live()) if self.state == "ready" else 0, "drive_empty": self._drive_empty,
                    "boot_step": self.boot_step if self.state == "starting" else None,
                    "starting_seconds": int(self.clock() - self.starting_since)
                    if self.state == "starting" and self.starting_since is not None else None}

    def _capped(self, until):
        """A time until which tests may start, never later than the session's early limit (tests_until)."""
        if until is None or self.tests_until is None:
            return until
        return min(until, self.tests_until)

    def _mark(self):
        """VirtualBox's own stamp of when the machine entered its present state ("running since"). It stays
        the same for as long as the machine keeps running, and is another one after any switch-off and
        start: the proof that a machine found running is still the SAME boot a session started."""
        try:
            return R.machinereadable(self.vbox.info(), "VMStateChangeTime")
        except Exception:
            return None

    def _step(self, run_id, word, at=None):
        """Tell the dashboard a step was reached (`at`: the test machine's own time stamp of it, when the
        launcher gave one). Its trouble (a progress file it can't write) is never a reason for a test to
        count as failed."""
        try:
            self.on_step(run_id, word, at)
        except Exception:
            pass

    def _set(self, **kw):
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, v)
        self._save()

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.notes), exist_ok=True)
            with open(self.notes, "w", encoding="utf-8") as f:
                json.dump(self.status(), f, indent=2)
        except OSError:
            pass

    # -- the records the VM sends (files on this laptop; no VirtualBox) -----------------------------
    def _pump(self):
        """Read what arrived since the last look into memory. The launcher's states (for this session and
        its runs), the runs' own records, and the flush-barrier markers."""
        if self._tails is None:
            return
        with self.pump_lock:
            for rec in self._tails["runs"].new_records():
                rid = rec.get("run_id")
                if rec.get("type") == "LAUNCHER_STATE":
                    self._states.append((rid, str(rec.get("state", ""))))
                    self._state_at[(rid, str(rec.get("state", "")))] = rec.get("time")      # the test machine's own clock
                    if rid == self.session_id and str(rec.get("state", "")).startswith("warm-ended"):
                        self._ended_by_launcher = True
                elif rec.get("type") == "SCENARIO_RUN" and rid:
                    self._run_recs[rid] = rec
            for rec in self._tails["vm"].new_records():
                if rec.get("type") != "FILE_HASH":
                    continue
                for run in self.runs:
                    kind = R.is_barrier(rec, run["run_id"])
                    if kind:
                        self._barriers[run["run_id"]] = kind

    def _states_of(self, run_id):
        """What the launcher said about this run id, in its present attempt. (No-disc path: a test that
        provably did not run may be clicked again under the same run id; what was said about the earlier
        attempt is history. On the CD path every attempt has its own run id.)"""
        return [s for rid, s in self._states[self._since.get(run_id, 0):] if rid == run_id]

    def _wait(self, what, timeout, cond):
        deadline = self.clock() + timeout
        while True:
            self._pump()
            result = cond()
            if result:
                return result
            if self.clock() > deadline:
                raise WarmTimeout(f"timed out after {timeout} s waiting for {what}")
            self.sleep(self.poll)

    def _launcher_failure(self, run_id):
        """The launcher's own word for why something did not happen (a state starting with failed / refused)."""
        for s in self._states_of(run_id) + [s for rid, s in self._states if rid == "-"]:
            if re.match(r"(starter: )?(failed|refused)", s):
                return s
        return None

    # -- start --------------------------------------------------------------------------------------
    def claim_start(self):
        """Take the session for a start, in one locked step: of two clicks at the same moment exactly one
        gets it, the other is refused. (The dashboard claims in the request and does the work in a thread.)"""
        with self.lock:
            if self.state not in ("off", "ended", "failed"):
                raise WarmError(f"the test machine is already {self.state}")
            self.state, self.error = "starting", None
            self.session_id, self.ready_until, self.used, self.current = None, None, [], None
            self.runs, self.timings, self._states, self._run_recs, self._barriers = [], {}, [], {}, {}
            self._ended_by_launcher, self.ended, self.boot_step = False, None, "booting"
            self.starting_since = self.clock()
            self.adopted, self.foreign, self._deadline, self.boot_mark = False, False, None, None
            self.tests_until = None
            self.no_disc, self.run_ids, self._since, self._signal_value = self._want_no_disc, {}, {}, None
            self._drive_empty = False

    def start(self, claimed=False):
        if not claimed:
            self.claim_start()
        touched = False
        try:
            if os.environ.get("ANALYSTLAB_OFFICIAL"):
                raise WarmError("refused: ANALYSTLAB_OFFICIAL is set, and warm runs are practice runs only")
            state = self.vbox.state()
            if state not in ("poweroff", "aborted"):
                with self.lock:
                    self.foreign = True                       # it is on, and not by this session
                raise WarmError(f"the test machine is '{state}'; it must be switched off first")
            if self.snapshot not in self.vbox.snapshots():
                raise WarmError(f"the prepared snapshot '{self.snapshot}' was not found")
            code, out = self.servers()
            if code != 0:
                raise WarmError("the laptop's receiver and test server are not running")
            sid = R.new_run_id()
            if self.no_disc:
                ids = {}
                for s in ALLOWED:                             # one run id per test, made now: they go onto the CD's note
                    rid = R.new_run_id()
                    while rid == sid or rid in ids.values():
                        rid = R.new_run_id()
                    ids[s] = rid
                self._set(session_id=sid, run_ids=ids)
                self.say(f"warm session {sid}: building the warm CD (no-disc-change path)")
                viso = self.build_signal(sid, ids)
            else:
                self._set(session_id=sid)
                self.say(f"warm session {sid}: building the warm CD")
                viso = self.build_warm(sid)
            self._tails = {"runs": self.tail(os.path.join(self.recordings, "vmruns")), "vm": self.tail(os.path.join(self.recordings, "vm"))}
            self._wait("VirtualBox to release the test machine", self.timeouts["unlock"], self.vbox.unlocked)
            t0 = self.clock()
            self.vbox.restore(self.snapshot)
            touched = True
            if self.cpus:
                self.vbox.set_cpus(self.cpus)
            self.vbox.insert_cd(viso)
            self._drive_empty = False
            since = R.utc_now()
            # counted from the moment the machine is started. On BOTH paths (PROOF, 2026-11-23): in the trial of
            # that day a test NAMED about 15 minutes after the start (no disc changed) began and then did nothing
            self._set(tests_until=self.clock() + START_TESTS_FOR_S)
            self.vbox.start(True)
            self._set(boot_step="booting")
            self._step(sid, "booting")
            self.say("restored and started; waiting for the logon")
            self._wait("the test machine's logon", self.timeouts["boot"], lambda: self.vbox.logged_in_since(since))
            t_logon = self.clock()
            self._set(boot_step="settling", boot_mark=self._mark())
            self._step(sid, "settling")
            self.say("logged on; waiting for the warm launcher")

            def ready():
                bad = self._launcher_failure(sid)
                if bad:
                    raise WarmError(f"the test machine's launcher reported: {bad}")
                return next((m for m in (READY.match(s) for s in self._states_of(sid)) if m), None)

            m = self._wait("the warm launcher to say it is ready", self.timeouts["launcher"] + self.timeouts["ready"], ready)
            now = self.clock()
            self.timings.update(start_to_logon=round(t_logon - t0, 1), logon_to_ready=round(now - t_logon, 1), left_at_ready=int(m.group(2)))
            self._set(state="ready", ready_until=self._capped(now + int(m.group(2))))
            self._step(sid, "ready")
            self.say(f"READY ({m.group(1)}): tests can be started for {int(m.group(2))} s")
        except Exception as e:
            # a start refused before the machine was touched leaves it exactly as it was, and "off" for this
            # session: there is nothing of ours to shut down (the stop button must never reach a machine that
            # something else started)
            self._set(state="failed" if touched else "off", error=str(e) if isinstance(e, (WarmError, R.StepFailed)) else f"unexpected error: {e!r}")
            self.say(f"NOT READY: {self.error}")
            if touched:
                self._power_off()
            raise WarmError(self.error) from e

    # -- one test -----------------------------------------------------------------------------------
    def _swap(self, viso):
        """The old disc out, a pause long enough for Windows to see an empty drive, then the new disc.
        (A drive this side already emptied, after giving up on a CD, is not emptied a second time.)"""
        if not self._drive_empty:
            self.vbox.insert_cd("emptydrive")
            self.sleep(SWAP_PAUSE)
        self.vbox.insert_cd(viso)
        self._drive_empty = False
        self._save()

    def _word(self, run_id, *prefixes):
        """The launcher's first state for this run that starts with one of the prefixes, or None."""
        return next((x for x in self._states_of(run_id) if x.startswith(prefixes)), None)

    def _await_found(self, run, viso, alive):
        """Wait until the launcher says it found (read and checked) this run's CD. What 2026-11-21 taught:

        - Windows sometimes does not notice a disc change for a long time. Until the launcher says it has
          SEEN this CD, the same CD is put in again, up to SWAP_TRIES times (PROOF's retry).
        - Once the launcher's "seen-cd" (said before it reads the files) has ARRIVED here, the disc is never
          taken out to try again. That day the third try's eject came within about 2 s of the launcher
          finally seeing the disc; its read failed ("the wrong diskette is in the drive") and went on
          failing for 4 min 42 s. Whether the eject caused that is not proven (two clocks, no time sync).
          From "seen-cd" on, this side only waits, for up to timeouts["read"].
          What this can NOT do: the launcher's words reach this laptop 0.7 to 6.8 s late, so a disc seen
          in the very seconds before a retry is still pulled once. That costs time, not correctness: the
          same disc goes in again, "seen-cd" has arrived by then, and from there this side waits. (On that
          day's timeline: one more pull, then a wait of 300 s for a read that took 282 s. One sample.)
        - When this side gives up, it takes the disc OUT first. That day it gave up and left the disc in;
          the launcher found it 3.5 minutes later and was about to start the test with nobody watching,
          while the machine was being shut down. With the disc out, the launcher cannot start the test
          (it looks at the disc once more right before starting).
        Raises WarmError with `why` = cd_not_seen / cd_unreadable when the test did not run."""
        rid, s = run["run_id"], run["scenario"]
        found = lambda: alive() or self._word(rid, "found-cd")                       # noqa: E731
        per_try, tries, t0 = self.timeouts["noticed"] / SWAP_TRIES, 1, self.clock()
        why = "cd_not_seen"
        while True:
            try:
                self._wait("the test machine to notice the new CD", per_try, lambda: found() or self._word(rid, "seen-cd"))
                break
            except WarmTimeout:
                if tries >= SWAP_TRIES:
                    why = "cd_not_seen"
                    break
                tries += 1
                self.say(f"{s.upper()}: not noticed after {int(per_try)} s; putting the CD in again ({tries} of {SWAP_TRIES})")
                self._swap(viso)
        if self._word(rid, "found-cd"):
            return
        if self._word(rid, "seen-cd"):
            why = "cd_unreadable"
            run["step"] = "seen"
            self.say(f"{s.upper()}: the test machine has seen the CD; it is not taken out again while it is read")
            try:
                self._wait("the test machine to read and check the CD", self.timeouts["read"], found)
                return
            except WarmTimeout:
                pass
        # giving up: the disc comes out, and the launcher gets a moment to say it had found it after all
        self.say(f"{s.upper()}: giving up on this CD; taking it out so the test cannot start unwatched")
        try:
            self.vbox.insert_cd("emptydrive")
            self._drive_empty = True
            self._save()
        except Exception as e:                        # the disc may still be in: nothing is proven about the test
            raise WarmError(f"the test machine did not read this test's CD, and the CD could not be taken out again ({e}); "
                            "the test may still start") from e
        try:
            self._wait("the launcher's last word about the CD", TAKE_BACK_S, found)
            return                                    # found after all: the launcher now looks at the (empty) drive once
        except WarmTimeout:                           # more before starting, and says "failed not-started" itself
            minutes = max(1, round((self.clock() - t0) / 60))
            raise WarmError(NOT_RUN[why].format(tries=tries, minutes=minutes), why=why) from None

    # -- one test, no-disc-change path ---------------------------------------------------------------
    def _signal(self, run_id):
        """Name the test the launcher is to run: set the guest property to that test's run id, or (None) take
        it away. Nothing else can be said through it: the value is one of this session's three run ids, or
        there is none. The launcher compares it with the run ids on the CD's note and does nothing else
        with it. TRANSIENT: VirtualBox drops the property when the machine is switched off."""
        if run_id is None:
            # Taking it away must be KNOWN to have worked: a signal that still stands could start the test later.
            # So a VBoxManage that fails here raises (it is only ever called after a set, so there is something to unset).
            self.vbox.call("guestproperty", "unset", self.vbox.vm, SIGNAL)
        elif run_id in self.run_ids.values():
            self.vbox.call("guestproperty", "set", self.vbox.vm, SIGNAL, run_id, *SIGNAL_FLAGS)
        else:
            raise WarmError("refused: the signal can only be one of this session's three run ids")
        self._signal_value = run_id

    def _await_picked(self, run, alive, on_sent):
        """Name the test and wait until the launcher says it picked it up.
        - The launcher sleeps in a wait that only a CHANGE of the property ends, and a change that falls
          between its look and its wait would be missed. So until it answers, the signal is taken away and
          set again every SIGNAL_EVERY seconds.
        - When this side gives up, it takes the signal AWAY first and listens a little longer. The launcher
          looks at the signal once more right before it starts a test, so a test that was called off can't
          start minutes later with nobody watching (the near miss of 2026-11-21).
        Raises WarmError with why="not_picked" when the test did not run."""
        rid, s = run["run_id"], run["scenario"]
        picked = lambda: alive() or self._word(rid, "picked-up")                     # noqa: E731
        t0, first = self.clock(), True
        while True:
            if not first:
                self._signal(None)
                self.sleep(1.0)
            try:
                self._signal(rid)
            except Exception as e:
                if not first:
                    raise
                # The very first naming was refused by VirtualBox: nothing was ever said to the launcher. That is
                # "did not run" only if the property is known to be clear; so it is taken away once more, and if
                # THAT fails too, nothing is claimed (the outer handler then says the test may still start).
                self._signal_value = rid
                self._signal(None)
                raise WarmError(NOT_RUN["not_named"], why="not_named") from e
            if first:
                first = False
                on_sent()
            try:
                self._wait("the test machine to pick the test up", SIGNAL_EVERY, picked)
                return
            except WarmTimeout:
                if self.clock() - t0 >= self.timeouts["picked"]:
                    break
        self.say(f"{s.upper()}: not picked up after {int(self.clock() - t0)} s; calling it off so it cannot start unwatched")
        try:
            self._signal(None)
        except Exception as e:                        # the signal may still stand: nothing is proven about the test
            raise WarmError(f"the test machine did not pick this test up, and the signal could not be taken back ({e}); the test may still start") from e
        try:
            self._wait("the launcher's last word about the test", TAKE_BACK_S, picked)
            return                                    # picked up after all: the launcher's own last look at the signal decides
        except WarmTimeout:
            raise WarmError(NOT_RUN["not_picked"].format(minutes=max(1, round((self.clock() - t0) / 60))), why="not_picked") from None

    def _why_not(self, s):
        """(Called with the lock held.) None when scenario `s` may start now, else the plain reason."""
        if s not in ALLOWED:
            return f"only {', '.join(x.upper() for x in ALLOWED)} can be run in a warm session"
        if self.state != "ready":
            return f"the test machine is {self.state}"
        if s in self.used:
            return f"{s.upper()} already ran in this session (each test once: the machine is not fresh)"
        if self.no_disc and s not in self.run_ids:
            return "this session's notes carry no run id for that test"
        if self.ready_until is None or self.clock() >= self.ready_until:
            return "too little time is left in this session for another test"
        if self._live():
            return "an earlier test is still going inside the test machine"
        return None

    def _live(self):
        """The tests the LAUNCHER says it has begun and not ended (found-cd / running / flushing with no
        done / failed / refused after it), whatever this side thinks of them. While there is one, no new
        test starts and the machine is not shut down: this side may have stopped waiting for a test that
        is still going inside the machine (2026-11-21: the shutdown came about two minutes after a late
        "found-cd"; never in the middle of a test is the rule)."""
        out = []
        for r in self.runs:
            states = self._states_of(r.get("run_id"))
            if any(x.startswith(BEGUN_ANY) for x in states) and not any(x.startswith(OVER) for x in states):
                out.append(r)
        return out

    def can_run(self, scenario):
        """None when this scenario may start now, else the plain reason it may not."""
        with self.lock:
            return self._why_not(str(scenario).lower())

    def claim_run(self, scenario):
        """Check and take the session for one test, in one locked step (two clicks: one test). Returns the
        run's note; raises WarmError with the plain reason when the test may not start."""
        s = str(scenario).lower()
        with self.lock:
            why = self._why_not(s)
            if why:
                raise WarmError(why)
            # CD path: a new run id for every click. No-disc path: the id the CD's note carries for this test (a
            # test that provably did not run may be clicked again under it; the earlier attempt's words are history)
            rid = self.run_ids[s] if self.no_disc else R.new_run_id()
            run = {"scenario": s, "run_id": rid, "step": "building", "practice": True, "clicked": self.clock()}
            self._since[rid] = len(self._states)
            self.state, self.current, self.error = "running", run, None
            self.runs.append(run)
        self._save()
        return run

    def run(self, scenario, claimed=None):
        run = claimed or self.claim_run(scenario)
        s, rid = run["scenario"], run["run_id"]
        try:
            t_click = self.clock()
            self._step(rid, "building")
            sent = {}

            def on_sent():
                sent["at"] = self.clock()
                run["step"] = "inserted"                      # (the CD path's step name: here "the signal is out")
                self._step(rid, "inserted")
                self.say(f"{s.upper()} {rid}: named to the test machine")

            if not self.no_disc:
                viso = self.build_run(self.session_id, rid, s)
                self._swap(viso)
                t_swap = self.clock()
                run["step"] = "inserted"
                self._step(rid, "inserted")
                self.say(f"{s.upper()} {rid}: run CD swapped in")

            def alive():
                """Raises when the launcher said this test will not (or did not) run; otherwise None."""
                bad = self._launcher_failure(rid)
                if bad:
                    raise WarmError(f"the test machine's launcher reported: {bad}")
                if self._ended_by_launcher:
                    raise WarmError("the warm session ended before the test finished")
                return None

            def seen(prefix):
                return lambda: alive() or next((x for x in self._states_of(rid) if x.startswith(prefix)), None)

            if self.no_disc:
                self._await_picked(run, alive, on_sent)
                t_swap = sent["at"]
            else:
                self._await_found(run, viso, alive)
            run["step"] = "noticed"
            self._step(rid, "noticed")
            t_noticed = self.clock()
            self._wait("the test program to start", self.timeouts["run"], seen("running"))
            run["step"] = "running"
            self._step(rid, "running")
            t_running = run["running_at"] = self.clock()       # (kept in the notes: the screen's view after a restart)
            if self.no_disc:
                try:
                    self._signal(None)                        # it runs: the signal has done its work
                except Exception:
                    pass
            self.say(f"{s.upper()}: running in the test machine")
            self._wait("the test's own record", self.timeouts["run"], lambda: alive() or self._run_recs.get(rid))
            run["step"] = "flushing"
            self._step(rid, "flushing")
            done = self._wait("the launcher to finish the test", self.timeouts["barrier"] + 60, seen("done "))
            kind = self._wait("the flush barrier (the test machine's last events)", self.timeouts["barrier"], lambda: self._barriers.get(rid))
            now = self.clock()
            m = DONE.match(done)
            rec = self._run_recs.get(rid) or {}
            run.update(step="done", barrier=kind, run_record={k: rec.get(k) for k in ("start", "end", "exit_code")},
                       times={"click_to_swap": round(t_swap - t_click, 1), "swap_to_noticed": round(t_noticed - t_swap, 1),
                              "noticed_to_running": round(t_running - t_noticed, 1), "click_to_done": round(now - t_click, 1)})
            # the launcher's own time of "done" (the test machine's clock, the one alerts are stamped with):
            # what is raised after it is not this test's (PROOF 2026-11-21: a test's view closes at its end)
            run["ended_vm"] = self._state_at.get((rid, done))
            run["finished"] = now                             # this side's clock (the screen's elapsed time after a restart)
            self._step(rid, "done", run["ended_vm"])          # the screen's steps end before the buttons come back
            with self.lock:
                self.used.append(s)
                self.state, self.current = "ready", None
                if m and m.group(2) is not None:
                    self.ready_until = self._capped(now + int(m.group(2)))
            self._save()
            self.say(f"{s.upper()}: done ({kind}); {run['times']}")
            return run
        except Exception as e:
            run["step"] = "failed"
            msg = str(e) if isinstance(e, (WarmError, R.StepFailed)) else f"unexpected error: {e!r}"
            # Did the test's program certainly never start? Only then may the screen say "did not run" and
            # offer the test again: (a) the launcher never said it found the CD and the CD has been taken
            # out, or (b) the launcher itself said it did not start it (its last look at the drive).
            stands = False
            if self.no_disc and self._signal_value is not None:   # whatever went wrong: the signal never stays standing
                try:
                    self._signal(None)
                except Exception:
                    stands = True                             # ... and if it can't be taken away, nothing is claimed about the test
            self._pump()
            why = getattr(e, "why", None)
            if stands:
                why = None
                msg = "The laptop could not take back the signal that names this test. The test may still start; it is not offered again."
            if stands:
                pass
            elif (self._word(rid, "failed not-started") and not self._word(rid, "running", "flushing", "done ")):
                why = "taken_back" if self.no_disc else "cd_gone"
                msg = NOT_RUN[why]
            elif why in NOT_RUN and self._word(rid, *BEGUN_ANY):  # found after all, at the last moment: nothing is proven yet
                why, msg = None, "The test machine found this test's CD only after this side had stopped waiting. Its own word on the test is still to come."
            run["finished"] = self.clock()
            if why in NOT_RUN:
                run["not_started"], run["why"] = True, why
            self._step(rid, "not_run" if why in NOT_RUN else "failed")
            with self.lock:                                   # the machine stays up: another test may still be possible
                self.state, self.current, self.error = "ready", None, msg
                if why not in NOT_RUN:
                    self.used.append(s)                       # a test that may have started is not offered again
            self._save()
            self.say(f"{s.upper()}: STOPPED: {msg}")
            raise WarmError(msg, why=why if why in NOT_RUN else None) from e

    def release(self, run):
        """Called when a test's thread has ended. Normally run() has already put the session back to
        "ready"; if it died on something unforeseen, do it here, so the machine can still be shut down
        (by the button, or by itself when the time is up) instead of counting as busy for ever."""
        with self.lock:
            if self.state != "running" or self.current is not run:
                return False
            run["step"] = "failed"
            self.state, self.current, self.error = "ready", None, "the test stopped unexpectedly"
            if run["scenario"] not in self.used:
                self.used.append(run["scenario"])
        self._save()
        return True

    # -- the end ------------------------------------------------------------------------------------
    def due(self):
        """True when the session should be shut down by itself: the launcher said it ended, or no further
        test can start and none is running. (Reads the record files, not VirtualBox.)"""
        self._pump()
        if self.state == "recovering":
            self._recover()
        with self.lock:
            if self.state == "recovering":
                # a machine found running after a restart: shut down when the launcher ended, or when its
                # time for tests is over and a test that was running then has had its longest time to finish
                until = self.ready_until if self.ready_until is not None else self._deadline
                grace = WORST_TEST_S if self._unfinished() else 0
                return self._ended_by_launcher or (until is not None and self.clock() >= until + grace)
            if self.state != "ready":
                return False
            # a test the launcher says is still going (this side gave up on it) gets its longest time first
            grace = WORST_TEST_S if self._live() else 0
            return self._ended_by_launcher or (self.ready_until is not None and self.clock() >= self.ready_until + grace)

    # -- after a restart of the dashboard -----------------------------------------------------------
    def adopt(self):
        """Called once when a dashboard starts (the one place besides start/run/stop that asks VirtualBox).
        A dashboard that crashed or was restarted forgot its warm session while the machine kept running:
        no Stop button, no shutdown by itself (PROOF 2026-11-21). So:
          - the machine is off: nothing to do                                           -> "off"
          - it is on, the notes say a session of THIS owner was not ended, and VirtualBox's own stamp shows
            the machine has been running without a break since that session noted it (the SAME boot: stale
            notes must never make us take, and shut down, a later boot that something else started): take
            it back. The Stop button and the shutdown by itself work at once; tests only once the
            launcher's own records show it reached "ready", has not ended, and no test is unfinished
                                                                                        -> "adopted"
          - it is on and the notes say otherwise (another tool started it, or nobody):  -> "foreign"
            said plainly on screen, with no Stop: it is not ours to shut down."""
        try:
            with open(self.notes, encoding="utf-8") as f:
                old = json.load(f)
        except (OSError, ValueError):
            old = None
        try:
            vm = self.vbox.state()
        except Exception:
            return "unknown"                                  # VirtualBox can't be asked: claim nothing
        open_session = bool(old) and bool(old.get("session_id")) and old.get("state") in ("starting", "ready", "running", "recovering", "stopping")
        if vm in R.OFF:
            if open_session:                                  # that session is over: its notes must never be believed later
                end_notes(self.notes, "found switched off")
            return "off"
        ours = open_session and old.get("owner") == self.owner and bool(old.get("boot_mark")) and old["boot_mark"] == self._mark()
        if vm != "running" or not ours:
            with self.lock:
                self.foreign = True
            return "foreign"
        with self.lock:
            self.tests_until = old.get("tests_until")
            self.no_disc, self.run_ids = bool(old.get("no_disc")), dict(old.get("run_ids") or {})    # the session's own path, not this object's switch
            self._since, self._signal_value = {}, None
            self.session_id, self.ready_until = old["session_id"], self._capped(old.get("ready_until"))
            self.used = list(old.get("used") or [])
            self.runs = [dict(r) for r in old.get("runs") or []]
            for r in self.runs:                               # a test that may have started is not offered again
                if r.get("scenario") and r["scenario"] not in self.used and not r.get("not_started"):
                    self.used.append(r["scenario"])
            self.timings = dict(old.get("timings") or {})
            self.boot_mark = old["boot_mark"]
            self._drive_empty = bool(old.get("drive_empty"))  # this side had taken a CD back out and put none in since
            self.state, self.error, self.current, self.adopted, self.foreign = "recovering", None, None, True, False
            self._states, self._state_at, self._run_recs, self._barriers, self._ended_by_launcher = [], {}, {}, {}, False
            self._deadline = self.clock() + LAUNCHER_LIFE_S
        self._tails = {"runs": self.tail(os.path.join(self.recordings, "vmruns")), "vm": self.tail(os.path.join(self.recordings, "vm"))}
        self._read_back()
        self._recover()
        self._save()
        self.say(f"found warm session {self.session_id} still running: {self.state}")
        return "adopted"

    def _read_back(self):
        """What the launcher already said about this session and its tests, from the record files of the
        last two days (the tails only see what arrives from now on). Also when this laptop received the
        launcher's last count of seconds left: that gives the time tests can be started until."""
        mine = {self.session_id} | {r.get("run_id") for r in self.runs} | set(self.run_ids.values())
        until = None
        for path in sorted(glob.glob(os.path.join(self.recordings, "vmruns", "*.jsonl")))[-2:]:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                continue
            for line in lines:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                rid = rec.get("run_id")
                if rid not in mine:
                    continue
                if rec.get("type") == "SCENARIO_RUN":
                    self._run_recs[rid] = rec
                elif rec.get("type") == "LAUNCHER_STATE":
                    state = str(rec.get("state", ""))
                    self._states.append((rid, state))
                    self._state_at[(rid, state)] = rec.get("time")
                    self._read.add((rid, state))
                    if rid == self.session_id and state.startswith("warm-ended"):
                        self._ended_by_launcher = True
                    m = READY.match(state) if rid == self.session_id else DONE.match(state)
                    left = (m.group(2) if m else None)
                    got = _seconds(rec.get("received_utc"))
                    if left is not None and got is not None:
                        until = got + int(left)
        if until is not None:
            with self.lock:
                self.ready_until = self._capped(until)

    def _unfinished(self):
        """The tests of this session the launcher began and has not finished (by its own states)."""
        out = []
        for r in self.runs:
            states = self._states_of(r.get("run_id"))
            if r.get("step") in ("done", "failed"):
                continue
            if any(s.startswith(("done ", "refused", "failed")) for s in states):
                continue
            out.append(r)
        return out

    def _recover(self):
        """A machine taken back after a restart becomes "ready" for tests only when the launcher's own
        records say so: it reached warm-ready, it has not ended, and no test of the session is unfinished."""
        ready = any(READY.match(s) for s in self._states_of(self.session_id))
        with self.lock:
            if self.state != "recovering" or self._ended_by_launcher or not ready or self._unfinished():
                return False
            finished = []
            if self.ready_until is None:                      # caught while still starting: the launcher's count has just arrived
                m = next((x for x in (READY.match(s) for s in self._states_of(self.session_id)) if x), None)
                if m:
                    self.ready_until = self._capped(self.clock() + int(m.group(2)))
            for r in self.runs:                               # a test that finished while nobody watched
                if r.get("step") not in ("done", "failed"):
                    done = next((s for s in self._states_of(r.get("run_id")) if s.startswith("done ")), None)
                    r["step"] = "done" if done else "failed"
                    finished.append((r["run_id"], r["step"], self._state_at.get((r["run_id"], done)) if done else None))
                    m = DONE.match(done) if done else None
                    if m and m.group(2) is not None and (r["run_id"], done) not in self._read:
                        self.ready_until = self._capped(self.clock() + int(m.group(2)))     # just arrived: the launcher's newest count
            self.state = "ready"
        self._save()
        for run_id, word, at in finished:                     # the screen's steps end too (outside the lock)
            self._step(run_id, word, at)
        return True

    def _power_off(self):
        """Ask the machine to shut down and wait until it is off; then take the CD out. Reported, never silent."""
        try:
            if self.vbox.state() not in R.OFF:
                self.vbox.request_shutdown()
                self._wait("the test machine to switch off", self.timeouts["shutdown"], lambda: self.vbox.state() in R.OFF)
            self._wait("VirtualBox to release the test machine", self.timeouts["unlock"], self.vbox.unlocked)
            if not self._drive_empty:                         # (a drive this side already emptied is not emptied twice)
                self.vbox.insert_cd("emptydrive")
                self._drive_empty = True
            return True
        except (WarmError, R.StepFailed) as e:
            self.say(f"WARNING: {e}. Shut it down with: VBoxManage controlvm {self.vbox.vm} shutdown")
            return False

    def stop(self, reason="asked"):
        with self.lock:
            if self.state == "running":
                raise WarmError("a test is running; the machine is shut down when it has finished")
            if self.state == "starting":
                raise WarmError("the test machine is still starting; it can be shut down once it is ready")
            if self.state in ("stopping", "off"):                # "off": this session has no machine running
                return None
            if self.state == "recovering" and reason == "asked" and self._unfinished() and not self._ended_by_launcher:
                raise WarmError("a test was running when this dashboard restarted; the machine is shut down when it has finished")
            if self.state == "ready" and self._live() and not self._ended_by_launcher and not self._overdue():
                raise WarmError("a test is still going inside the test machine; it is shut down when the test has finished")
            self.state = "stopping"
        self._save()
        self.say(f"shutting the test machine down ({reason})")
        off = self._power_off()
        self._set(state="off" if off else "failed", error=None if off else "the test machine did not switch off", ready_until=None,
                  current=None, ended=reason)
        return off

    def _overdue(self):
        """(Lock held.) The session's time for tests is over AND the longest a test may take has passed since:
        from here a shutdown can't cut a test off, whatever the launcher last said."""
        return self.ready_until is not None and self.clock() >= self.ready_until + WORST_TEST_S

    def watch(self, every=5.0, stop=None):
        """Run in a background thread by the dashboard: shuts the session down by itself as soon as no further
        test can start (a controlled shutdown, minutes before Windows would stop the logon task)."""
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                if self.due():
                    self.stop("time is up")
            except WarmError:
                pass
            stop.wait(every)


def end_notes(path, reason):
    """Mark the session in the notes file as over (the machine was switched off some other way), so a
    dashboard starting later never takes a new boot of the machine for that session."""
    try:
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
        old.update(state="off", ended=reason, ready_until=None, current=None)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(old, f, indent=2)
        return True
    except (OSError, ValueError):
        return False


def cycle(scenarios, session=None, alerts_url="http://127.0.0.1:8780/api/alerts", no_disc=None):
    """The command-line driver for a VM test cycle: start, run each scenario, shut down, print the times.
    If a live dashboard is up, it also notes how long after the click a new alert was raised.
    It counts the dashboard's alert LIST (every alert at or above the frozen floor), not the Watch screen's
    "in view" number: that one follows the dashboard's own runs and stayed still during a command-line
    cycle (2026-11-21, cycles 3 and 4: click_to_alert came out empty although the alerts were raised)."""
    import urllib.request

    def alerts():
        try:
            with urllib.request.urlopen(alerts_url, timeout=2) as r:
                return len(json.loads(r.read().decode("utf-8")))
        except Exception:
            return None

    w = session or WarmSession(say=lambda m: print(f"  {time.strftime('%H:%M:%S')}  {m}", flush=True), no_disc=no_disc)
    code = 0
    try:
        w.start()
        for s in scenarios:
            before, t0, seen = alerts(), time.time(), {}

            def watch():
                while not seen.get("stop"):
                    n = alerts()
                    if before is not None and n is not None and n > before and "alert" not in seen:
                        seen["alert"] = round(time.time() - t0, 1)
                    time.sleep(1)

            t = threading.Thread(target=watch, daemon=True)
            t.start()
            try:
                run = w.run(s)
                time.sleep(12)                                # the live loop scores every few seconds
                run["times"]["click_to_alert"] = seen.get("alert")
            except WarmError:
                code = 1
            finally:
                seen["stop"] = True
    except WarmError:
        code = 2
    except KeyboardInterrupt:
        print("interrupted (Ctrl+C)")
        code = 3
    finally:
        if w.status()["state"] not in ("off",):
            waited = 0
            while w.status().get("busy_inside") and waited < WORST_TEST_S:      # a test this side gave up on is still going
                w.due()                                                           # (reads what the launcher says)
                time.sleep(5)
                waited += 5
            try:
                w.stop("end of the cycle")
            except WarmError as e:
                print(f"  could not stop: {e}")
        st = w.status()
        print("\nWARM CYCLE:", "ok" if code == 0 else f"problems (code {code})")
        print("  timings:", json.dumps(st["timings"]))
        for r in st["runs"]:
            print(f"  {r['scenario'].upper()} {r['run_id']}: {r['step']}  barrier={r.get('barrier')}  times={json.dumps(r.get('times'))}")
        print("  test machine:", w.vbox.state())
    return code


def main(argv=None):
    p = argparse.ArgumentParser(description="Warm test machine: practice runs in one boot, started one by one")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cycle", help="start, run the given scenarios one after another, shut down")
    c.add_argument("scenario", nargs="+", choices=ALLOWED)
    c.add_argument("--no-disc-change", action="store_true",
                   help=f"the no-disc-change path (off by default; the same as {NO_DISC_ENV}=1): tests are named by a signal, no CD is changed")
    sub.add_parser("stop", help="shut the test machine down (works without a running warm session)")
    sub.add_parser("status", help="print what the last warm session wrote down")
    a = p.parse_args(argv)
    if a.cmd == "cycle":
        if len(set(a.scenario)) != len(a.scenario):
            raise SystemExit("each scenario once per session")
        return cycle(a.scenario, no_disc=True if a.no_disc_change else None)
    if a.cmd == "stop":
        w = WarmSession(say=print)
        off = w._power_off()
        if off:
            end_notes(w.notes, "stopped from the command line")
        print("test machine:", w.vbox.state())
        return 0 if off else 3
    notes = os.path.join(PROJECT_ROOT, "recordings", "live", "warm", "session.json")
    if not os.path.exists(notes):
        print("no warm session has run here yet")
        return 0
    with open(notes, encoding="utf-8") as f:
        st = json.load(f)
    print(json.dumps({k: st.get(k) for k in ("state", "error", "session_id", "used", "timings")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
