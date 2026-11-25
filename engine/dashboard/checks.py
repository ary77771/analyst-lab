"""The "run the honesty checks" button (debate 12 E1, reshaped): runs the report's and the
dashboard's own tests live, so the audience sees them count up. Not the whole suite (~1,800 tests,
minutes, some start subprocesses): the fast, self-contained files that pin what the screens claim.

- Refuses while a VM run is going (the test machine has one CPU; nothing may slow it).
- One run at a time; the page polls GET /api/checks for the live count.
- Results come from pytest's own hooks (checks_plugin.py writes one line per test), not from what
  pytest prints: a coloured terminal once made the printed dots uncountable (0 of 118 on screen).
- Only counts, each check file's plain name (GROUPS) and each test's own name are sent to the page, never test output.
- A finished run whose results do not add up to the collected total is shown as NOT passed.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILES = [
    "tests/test_report_v3.py", "tests/test_report_plain.py", "tests/test_report.py",
    "tests/test_dashboard.py", "tests/test_dashboard_public.py", "tests/test_dashboard_live.py",
    "tests/test_dashboard_demo_mode.py", "tests/test_dashboard_scoreboard.py", "tests/test_dashboard_frontend.py",
    "tests/test_dashboard_twin.py", "tests/test_dashboard_coverage.py", "tests/test_dashboard_words_scan.py",
    "tests/test_dashboard_frontend_logic.py",      # the new screens: recorded order kept, a guess never drawn as a fact
]

# What each file of checks guards, in plain words (PROOF, 2026-11-20: the raw test names are gibberish to the
# professor). The screen shows these lines with their counts; they are scanned like every other word.
GROUPS = {
    "tests/test_report_v3.py": "The story's order, counts and inks",
    "tests/test_report_plain.py": "The report's plain wording",
    "tests/test_report.py": "Every fact cites a recorded event",
    "tests/test_dashboard.py": "Screens show what the engine found",
    "tests/test_dashboard_public.py": "Public data: guesses stay guesses",
    "tests/test_dashboard_live.py": "The live screen's states and steps",
    "tests/test_dashboard_demo_mode.py": "A replay can't pass for live",
    "tests/test_dashboard_scoreboard.py": "Old-vs-new numbers match the results",
    "tests/test_dashboard_frontend.py": "No claim typed into a screen; offline",
    "tests/test_dashboard_twin.py": "The look-alike pair matches its results",
    "tests/test_dashboard_coverage.py": "The 170-test wall matches its results",
    "tests/test_dashboard_words_scan.py": "No overclaiming word reaches a screen",
    "tests/test_dashboard_frontend_logic.py": "The screen keeps the recorded order",
}


def group_of(node_id, files):
    """The check file a test id belongs to, as listed in `files` (forward slashes, however pytest spells it)."""
    path = node_id.split("::")[0].replace("\\", "/")
    for f in files:
        g = f.replace("\\", "/")
        if path == g or path.endswith("/" + g) or g.endswith("/" + path):
            return f
    # pytest gives a file OUTSIDE the project an id with no path at all ("::test_ok"): it belongs to the one
    # listed file that lies outside the project, if there is exactly one (the real list has none)
    outside = [f for f in files if os.path.isabs(f) and not os.path.abspath(f).startswith(PROJECT_ROOT + os.sep)]
    return outside[0] if not path and len(outside) == 1 else (path or "other checks")


def group_name(f):
    return GROUPS.get(f.replace("\\", "/")) or os.path.basename(f).removeprefix("test_").removesuffix(".py").replace("_", " ")


WORDS = {
    "title": "Run the honesty checks now",
    "intro": "The tests that guard what these screens say, run live on this laptop. Among them: the scoreboard's, "
             "coverage's and twin's numbers match the committed results pages; no guess is ever shown as proven; no "
             "screen's words use the banned overclaiming words; the story's steps are listed in recorded order, a "
             "cause always before its effect; the page works without the internet.",
    "busy": "Not while the test machine is running: it has one processor and the checks would slow it down.",
    "running": "Running…",
    "ready": "{total} checks ready to run",
    "done_ok": "{passed} passed, {failed} failed, {skipped} skipped",
    "done_bad": "{passed} passed, {failed} failed, {skipped} skipped: see the log on this laptop",
    "done_uncounted": "Not passed: only {counted} of {total} results could be counted. See the log on this laptop.",
    "button": "Run the checks",
}

VBOX = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"


_VM_CACHE = {"at": 0.0, "value": True}


def vm_running(vm="AnalystLab-Win11", max_age=10.0):
    """True when VirtualBox says the test machine is running (started by anyone, not only this
    dashboard). Unknown (no VirtualBox, a timeout) counts as running: refuse rather than slow it.
    Cached for 10 s, so the page's polling never adds VBoxManage calls during a VM run."""
    now = time.time()
    if now - _VM_CACHE["at"] < max_age:
        return _VM_CACHE["value"]
    try:
        out = subprocess.run([VBOX, "showvminfo", vm, "--machinereadable"], capture_output=True, text=True, timeout=5).stdout
        value = 'VMState="poweroff"' not in out and 'VMState="saved"' not in out and 'VMState="aborted"' not in out
    except (OSError, subprocess.TimeoutExpired):
        value = True
    _VM_CACHE.update(at=now, value=value)
    return value


SCRUB = ("FORCE_COLOR", "PY_COLORS", "CLICOLOR_FORCE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")   # a caller's terminal settings
PLUGIN = "engine.dashboard.checks_plugin"
OUTCOMES = ("passed", "failed", "skipped")


# A few checks are NAMED after the words they forbid ("...never shows ... probably"). On screen such a word is
# put in quotes, so it reads as the thing being checked for, not as something the dashboard says.
MENTIONED = re.compile(r"\b(probably|likely|all clear|all good|no threats?|safe|secure)\b", re.I)


def plain_name(node_id):
    """'tests/test_x.py::test_no_guess_is_shown_as_fact' -> 'no guess is shown as fact' (the test's own name)."""
    name = node_id.split("::")[-1].split("[")[0]
    return MENTIONED.sub(lambda m: f'"{m.group(0)}"', name.removeprefix("test_").replace("_", " "))


class Checks:
    def __init__(self, runner, files=None, python=None, vm_busy=vm_running, plugin=PLUGIN):
        self.runner, self.files, self.python, self.vm_busy = runner, files or FILES, python or sys.executable, vm_busy
        self.plugin = plugin
        self.lock = threading.Lock()
        self.state = {"running": False, "total": None, "passed": 0, "failed": 0, "skipped": 0,
                      "started": None, "seconds": None, "exit_code": None, "items": [], "groups": self._groups({}, {})}
        self.counting = False
        self.counted = False          # counting is tried once: a count that yields nothing is not retried per poll

    def _command(self, out, extra=()):
        """(pytest command, environment): the caller's terminal colours and pytest options are scrubbed."""
        env = {k: v for k, v in os.environ.items() if k not in SCRUB}
        env.update(ANALYSTLAB_CHECKS_OUT=out, NO_COLOR="1", PYTHONIOENCODING="utf-8")
        cmd = [self.python, "-m", "pytest", "-q", "--tb=short", "--color=no", "-p", "no:cacheprovider", *extra]
        if self.plugin:
            cmd += ["-p", self.plugin]
        return cmd + list(self.files), env

    def _count(self):
        """How many checks there are, before any run (pytest only collects them), so the screen can say
        "118 checks ready" instead of a lone 0."""
        folder = None
        try:
            folder = tempfile.mkdtemp(prefix="analystlab-checks-")
            out = os.path.join(folder, "collected.jsonl")
            cmd, env = self._command(out, extra=("--collect-only",))
            subprocess.run(cmd, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=120)
            with self.lock:
                if not self.state["running"] and self.state["exit_code"] is None:
                    self._read(out)
        except Exception:
            pass
        finally:
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
            self.counting = False

    def count_once(self):
        """Start the counting in the background, once, and never while the test machine runs."""
        with self.lock:
            if self.counted or self.counting or self.state["running"] or self.state["total"] is not None or self.state["exit_code"] is not None:
                return
            self.counting = self.counted = True
        threading.Thread(target=self._count, daemon=True).start()

    def _groups(self, collected, by_id):
        """One line per check file, in the listed order: its plain name, how many checks it holds (None until
        counted) and how many passed, failed or were skipped so far."""
        rows = {f: {"name": group_name(f), "total": None, "passed": 0, "failed": 0, "skipped": 0} for f in self.files}
        for i in collected:
            g = rows.setdefault(group_of(i, self.files), {"name": group_name(group_of(i, self.files)), "total": None, "passed": 0, "failed": 0, "skipped": 0})
            g["total"] = (g["total"] or 0) + 1
        for i, outcome in by_id.items():
            g = rows.get(group_of(i, self.files))
            if g:
                g[outcome] += 1
        return list(rows.values())

    def _read(self, path):
        """The plugin's file so far -> state (the last line per test wins: a teardown error overrides)."""
        total, by_id, ids = None, {}, []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                    except ValueError:              # a line still being written
                        continue
                    if "collected" in d:
                        total, ids = d["collected"], d.get("ids") or []
                    elif d.get("outcome") in OUTCOMES:
                        by_id[d["id"]] = d["outcome"]
        except OSError:
            pass
        counts = {k: sum(1 for v in by_id.values() if v == k) for k in OUTCOMES}
        self.state.update(counts, total=total if total is not None else self.state["total"],
                          items=[{"name": plain_name(i), "outcome": o} for i, o in by_id.items()])
        if ids or by_id:
            self.state["groups"] = self._groups(ids, by_id)

    def _run(self):
        st = self.state
        folder = tempfile.mkdtemp(prefix="analystlab-checks-")
        out = os.path.join(folder, "results.jsonl")
        cmd, env = self._command(out)
        try:
            with open(os.path.join(folder, "pytest.log"), "w", encoding="utf-8") as log:     # stays on this laptop
                p = subprocess.Popen(cmd, cwd=PROJECT_ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)
                while p.poll() is None:
                    self._read(out)
                    time.sleep(0.15)
            self._read(out)
            st["exit_code"] = p.returncode
        except Exception:                      # a crash of the runner itself is a failure, not a pass
            st["exit_code"] = -1
        finally:
            st["seconds"] = round(time.time() - st["started"], 1)
            st["running"] = False

    def start(self):
        with self.lock:
            if self.runner.status().running or self.vm_busy():
                raise HTTPException(status_code=409, detail=WORDS["busy"])
            if self.state["running"]:
                return
            self.state.update(running=True, total=None, passed=0, failed=0, skipped=0, started=time.time(),
                              seconds=None, exit_code=None, items=[], groups=self._groups({}, {}))
            threading.Thread(target=self._run, daemon=True).start()

    def status(self):
        st = dict(self.state)
        if st["started"] and st["running"]:
            st["seconds"] = round(time.time() - st["started"], 1)
        st.pop("started")
        st["ok"] = None
        if not st["running"] and st["exit_code"] is None and st["total"]:
            st["ready_text"] = WORDS["ready"].format(total=st["total"])
        if not st["running"] and st["exit_code"] is not None:
            counted = st["passed"] + st["failed"] + st["skipped"]
            # every collected test must be accounted for: a run whose results could not be counted
            # is shown as a failure, never as "0 failed"
            if not st["total"] or counted != st["total"]:
                st["ok"], st["text"] = False, WORDS["done_uncounted"].format(counted=counted, total=st["total"] or 0)
            else:
                st["ok"] = st["exit_code"] == 0 and st["failed"] == 0
                st["text"] = (WORDS["done_ok"] if st["ok"] else WORDS["done_bad"]).format(**st)
        return st


def make_router(runner, checks=None):
    router = APIRouter()
    c = checks or Checks(runner)

    @router.get("/api/checks")
    def checks_status():
        busy = runner.status().running or c.vm_busy()
        if not busy:
            c.count_once()
        return {"words": WORDS, **c.status(), "busy": busy}

    @router.post("/api/checks/run")
    def checks_run():
        c.start()
        return c.status()

    return router
