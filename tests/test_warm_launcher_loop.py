"""The warm launcher's waiting loop, RUN on this laptop against a made-up CD folder (2026-11-21).

Why: demo/warm/warm_launcher.ps1 only ever runs inside the test machine, and a mistake in it ends the
whole warm session (its `trap` exits). The other tests read it as text. This one executes it: the loop
(section 6), the fingerprints (section 2) and the helper functions are taken from the file WORD FOR WORD
and run by Windows PowerShell here, so a slip in the two rules added after the S4 disc change of
2026-11-21 ("seen-cd" before the files are read; a last look at the drive before the start) shows up
on the laptop and not on demo day.

What is made up, and only this:
  - the "CD" is a folder in the test's temp directory; its run_scenario.ps1 is a three-line stand-in that
    writes one line into a file. No test program exists here, nothing of the lab is on this "CD".
  - the launcher's VM-only start (sections 1 and 3 to 5: the VM check, the recorder, the laptop's receiver,
    the long settling wait) is not run. Its State function, which posts to the laptop's receiver from
    inside the VM, is replaced by one that writes the same words into a file: nothing is sent anywhere.
  - the three folders it writes to inside the VM point into the temp directory.
  - Start-Sleep also looks for a stop file, so the loop ends when the test is over (and by itself after
    four minutes whatever happens).
It takes about 90 seconds: the launcher's own calm check (20 s) and settle pause (15 s) are the real ones.
It is a real-time test: run it with the laptop awake (lid open: a closed lid is Modern Standby).

A failure is never lost (PROOF 2026-11-21; two failures that evening left no trace): whatever goes wrong,
the message carries everything the loop said (its State file, its stdout and stderr, its own log, what it
ran, its exit code) and the same text is written to build/loop-test/last-failure.txt. Only when the test
MEASURED its own standstill (more than 5 s between two one-second ticks: the laptop dozed off) is a
failure reported as "skipped", with the measured seconds, and the evidence is still written to that file.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "demo", "warm", "warm_launcher.ps1")
POWERSHELL = shutil.which("powershell.exe") if sys.platform == "win32" else None

pytestmark = pytest.mark.skipif(not POWERSHELL, reason="needs Windows PowerShell")

SESSION, RUN_A, RUN_B, RUN_C = "20261121-000000-aaaa", "20261121-000100-bbbb", "20261121-000200-cccc", "20261121-000300-dddd"

STUB = """param([string]$Scenario, [string]$RunId)
Add-Content -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'ran.txt') -Value "$Scenario $RunId" -Encoding ascii
exit 0
"""


def between(text, start, end=None):
    a = text.index(start)
    return text[a:text.index(end, a)] if end else text[a:]


def harness(work):
    """The launcher's own text around a made-up start. Returns the script."""
    with open(LAUNCHER, encoding="utf-8") as f:
        text = f.read()
    assert text.isascii()                 # Windows PowerShell 5.1 in the VM reads a file without a byte-order mark as ANSI
    head = between(text, "$ErrorActionPreference = 'Stop'", "function Say")
    for name, folder in (("dataDir", "data"), ("barrierDir", "barrier")):
        head, n = re.subn(rf"(?m)^\${name} = '[^']*'", lambda m: f"${name} = '{os.path.join(work, folder)}'", head)
        assert n == 1, name
    head, n = re.subn(r"(?m)^\$agentStatus = '[^']*'", lambda m: f"$agentStatus = '{os.path.join(work, 'status.json')}'", head)
    assert n == 1
    helpers = between(text, "function Say", "function State") + between(text, "function AgentStatus", "# 1. the warm CD's own note")
    fingerprints = between(text, "# 2. fingerprints", "# 3. the VM's recorder")
    loop = between(text, "# 6. wait for run CDs")
    mine = f"""
function State($state) {{
    # (the test reads this file four times a second, and a virus scanner may look at it too: a write that
    # finds it busy is tried again instead of ending the loop)
    foreach ($try in 1..20) {{
        try {{ Add-Content -Path '{os.path.join(work, "states.txt")}' -Value "$runId|$state" -Encoding ascii -ErrorAction Stop; Say "state: $state"; return }}
        catch {{ Microsoft.PowerShell.Utility\\Start-Sleep -Milliseconds 100 }}
    }}
    throw "the harness could not write a state: $state"
}}
$harnessEnd = (Get-Date).AddSeconds(240)
function Start-Sleep {{
    param([int]$Seconds = 1)
    if ((Test-Path '{os.path.join(work, "stop")}') -or (Get-Date) -gt $harnessEnd) {{ exit 0 }}
    Microsoft.PowerShell.Utility\\Start-Sleep -Seconds $Seconds
}}
$sessionId = '{SESSION}'
$runId = $sessionId
"""
    script = "param([Parameter(Mandatory)][string]$Root)\n" + head + helpers + mine + fingerprints + loop
    code = "\n".join(line.split(" #")[0] for line in script.splitlines())
    assert "Invoke-RestMethod" not in code and "http://" not in code           # nothing is sent anywhere from here
    assert "C:\\LabTools" not in code and "C:\\LabRunner" not in code and "C:\\AnalystLab" not in code
    assert code.count("& powershell.exe") == 1                                 # the one start: the made-up CD's own stand-in
    return script


class Loop:
    def __init__(self, tmp_path):
        self.work = str(tmp_path)
        self.cd = os.path.join(self.work, "cd")
        os.makedirs(os.path.join(self.cd, "s1"))
        with open(os.path.join(self.cd, "run_scenario.ps1"), "w", encoding="ascii", newline="\r\n") as f:
            f.write(STUB)
        with open(os.path.join(self.cd, "s1", "program.txt"), "w", encoding="ascii") as f:
            f.write("a stand-in for a test program: never run")
        self.note(SESSION, "s1", warm=True)
        self.script = os.path.join(self.work, "harness.ps1")
        with open(self.script, "w", encoding="ascii", newline="\r\n") as f:
            f.write(harness(self.work))
        self.alive, self.longest_gap = True, 0.0
        threading.Thread(target=self.recorder, daemon=True).start()
        self.out = open(os.path.join(self.work, "out.txt"), "w", encoding="utf-8")
        self.proc = subprocess.Popen([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", self.script, "-Root", self.cd],
                                     stdout=self.out, stderr=subprocess.STDOUT, cwd=self.work)

    def recorder(self):
        """Stands in for the VM's recorder: its status file says "alive, nothing waiting" every second.
        It also notices when this whole process stood still (the laptop dozed off: Modern Standby)."""
        last = time.time()
        while self.alive:
            now = time.time()
            self.longest_gap = max(self.longest_gap, now - last)
            last = now
            tmp = os.path.join(self.work, "status.tmp")
            try:
                with open(tmp, "w", encoding="ascii") as f:
                    json.dump({"updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z", "files_waiting_for_hash": 0}, f)
                os.replace(tmp, os.path.join(self.work, "status.json"))
            except OSError:                       # the loop is reading it right now, or the test is over and its folder is gone
                pass
            time.sleep(1)

    def note(self, run_id, scenario, warm=False):
        tmp = os.path.join(self.work, "note.tmp")
        with open(tmp, "w", encoding="ascii", newline="") as f:
            f.write(f"scenario={scenario}\r\nrun_id={run_id}\r\n" + ("warm=1\r\n" if warm else "") + "practice=1")
        self.patiently(lambda: os.replace(tmp, os.path.join(self.cd, "AUTORUN_SCENARIO.txt")))

    def take_out(self):
        self.patiently(lambda: os.remove(os.path.join(self.cd, "AUTORUN_SCENARIO.txt")))

    @staticmethod
    def patiently(change):
        """A change to the made-up CD's note; tried again when the loop happens to be reading the note right then."""
        for _ in range(40):
            try:
                return change()
            except PermissionError:
                time.sleep(0.05)
        return change()

    def states(self):
        try:
            with open(os.path.join(self.work, "states.txt"), encoding="ascii") as f:
                return [tuple(line.rstrip("\n").split("|", 1)) for line in f if "|" in line]
        except OSError:
            return []

    def ran(self):
        try:
            with open(os.path.join(self.work, "ran.txt"), encoding="ascii") as f:
                return f.read().split("\n")[:-1]
        except OSError:
            return []

    def wait(self, cond, limit, what):
        t = time.time()
        while time.time() - t < limit:
            if cond():
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.25)
        raise AssertionError(f"never happened within {limit} s: {what}")       # (told() adds everything the loop said)

    def evidence(self):
        """Everything the loop left behind, as text: for the message of ANY failure of this test."""
        def text(name, keep=6000):
            try:
                with open(os.path.join(self.work, name), encoding="utf-8", errors="replace") as f:
                    t = f.read()
            except OSError as e:
                return f"(not there: {type(e).__name__})"
            cut = f"(the last {keep} of {len(t)} characters)\n" if len(t) > keep else ""
            return cut + (t[-keep:] if t.strip() else "(empty)")
        try:
            self.out.flush()
        except ValueError:
            pass
        return "\n".join([
            f"the loop's exit code: {self.proc.poll()} (None: still running) | longest standstill this test measured: {self.longest_gap:.1f} s",
            f"its files are in: {self.work}",
            "--- the State file (run id|state, every word the loop said)", text("states.txt"),
            "--- the loop's stdout and stderr", text("out.txt"),
            "--- the loop's own log (data/launcher.log)", text(os.path.join("data", "launcher.log")),
            "--- what the made-up CD's stand-in ran (ran.txt)", text("ran.txt")])

    def said(self, run_id, prefix):
        return lambda: any(r == run_id and s.startswith(prefix) for r, s in self.states())

    def end(self):
        with open(os.path.join(self.work, "stop"), "w") as f:
            f.write("stop")
        try:
            self.proc.wait(timeout=30)            # it ends by itself at its next sleep
        finally:
            self.alive = False
            try:
                self.out.flush()
            except ValueError:
                pass


LAST_FAILURE = os.path.join(ROOT, "build", "loop-test", "last-failure.txt")       # git-ignored; kept until the next failure
DOZED_S = 5.0                              # a standstill longer than this between two one-second ticks: the laptop dozed off


def told(loop, story, record=LAST_FAILURE, exit_code=0):
    """Run `story` against the loop and end the loop. Whatever goes wrong (a wait that ran out, a plain
    assert, an exception, the loop not ending, a wrong exit code), the failure carries all the evidence and
    the evidence is written to `record`. A measured standstill turns the failure into a skip; nothing else does."""
    failure = None
    try:
        story(loop)
    except Exception as e:
        failure = e
    finally:
        try:
            loop.end()
        except Exception as e:
            failure = failure or AssertionError(f"the loop did not end when asked to ({type(e).__name__}: {e})")
    if failure is None and loop.proc.returncode != exit_code:
        failure = AssertionError(f"the loop ended with exit code {loop.proc.returncode}, not {exit_code}")
    if failure is None:
        return
    evidence = f"{type(failure).__name__}: {failure}\n{loop.evidence()}"
    try:
        os.makedirs(os.path.dirname(record), exist_ok=True)
        with open(record, "w", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "  " + evidence + "\n")
        kept = f"also written to {record}"
    except OSError as e:
        kept = f"could NOT be written to {record} ({e})"
    if loop.longest_gap > DOZED_S:
        # 2026-11-21: a run the laptop's standby froze took 44 minutes and "failed" in the launcher's calm check
        pytest.skip(f"the laptop dozed off during this real-time test (it stood still for {loop.longest_gap:.0f} s, measured): "
                    f"nothing is proven either way. What failed: {type(failure).__name__}: {str(failure)[:200]} (all of it {kept})")
    raise AssertionError(f"{evidence}\n({kept})") from failure


def test_the_waiting_loop_runs_a_cd_once_says_seen_before_found_and_starts_nothing_from_a_cd_that_is_gone(tmp_path):
    told(Loop(tmp_path), the_whole_story)


def the_whole_story(loop):
    # the warm CD's own note is in the "drive": it waits, and says why once
    loop.wait(loop.said(SESSION, "waiting: the drive still shows the warm CD's note"), 40, "the first waiting word")

    # run CD A is put in: seen, checked against the warm CD's fingerprints, found, run, flushed, done
    loop.note(RUN_A, "s1")
    loop.wait(loop.said(RUN_A, "found-cd s1"), 30, "found-cd for A")
    words = [s for r, s in loop.states() if r == RUN_A]
    assert words[:2] == ["seen-cd", "found-cd s1"]                          # "seen" is said first, before the files are read
    assert loop.ran() == []                                                 # found is not started: the calm check comes first
    loop.wait(loop.said(RUN_A, "done "), 200, "A's test to finish")
    words = [s for r, s in loop.states() if r == RUN_A]
    assert [w.split(" ")[0] for w in words] == ["seen-cd", "found-cd", "running", "flushing", "done"]
    assert re.fullmatch(r"done (ok|late) left=\d+", words[-1]) and loop.ran() == [f"s1 {RUN_A}"]
    assert os.path.exists(os.path.join(loop.work, "barrier", f"barrier-{RUN_A}-{words[-1].split(' ')[1]}.txt"))

    # run CD B is put in, but one of its files can't be read (held locked here; on 2026-11-21 Windows said
    # "the wrong diskette is in the drive" for 4 min 42 s): it looks again and again, says "seen" ONCE,
    # says why it waits, and starts nothing
    import msvcrt
    held = open(os.path.join(loop.cd, "s1", "program.txt"), "r+b")
    msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, 16)
    try:
        loop.note(RUN_B, "s4")
        loop.wait(loop.said(SESSION, f"waiting: run CD {RUN_B} files unreadable"), 30, "the word that B's files can't be read")
        time.sleep(9)                                                       # four more looks at the unreadable CD
        assert [s for r, s in loop.states() if r == RUN_B] == ["seen-cd"] and loop.ran() == [f"s1 {RUN_A}"]
    finally:
        held.seek(0)
        msvcrt.locking(held.fileno(), msvcrt.LK_UNLCK, 16)
        held.close()
    # readable at last: found; then the laptop gives up and takes it out before the test starts
    loop.wait(loop.said(RUN_B, "found-cd s4"), 30, "found-cd for B")
    loop.take_out()
    loop.wait(loop.said(RUN_B, "failed not-started"), 150, "the launcher's word that B did not start")
    assert [s.split(" (")[0] for r, s in loop.states() if r == RUN_B] == ["seen-cd", "found-cd s4", "failed not-started"]
    assert loop.ran() == [f"s1 {RUN_A}"]                                    # nothing was started for B

    # the same two CDs again are never run twice; a CD of a scenario that is not allowed is refused in words
    loop.note(RUN_A, "s1")
    time.sleep(5)
    loop.note(RUN_B, "s4")
    time.sleep(5)
    loop.note(RUN_C, "s2")
    loop.wait(loop.said(RUN_C, "refused scenario 's2' is not one of"), 30, "the refusal of S2")
    assert loop.ran() == [f"s1 {RUN_A}"]
    everything = loop.states()
    assert sum(1 for r, s in everything if s == "seen-cd") == 3              # once per run CD (A, B, C), however long it stays in
    assert not any(s.startswith("failed error") for _, s in everything)     # the script itself never tripped


def must_fail(loop, story, record):
    """told() must report this story's failure as a FAILURE and hand back its message. If it calls it
    "dozed off" although no standstill was measured, that is itself a failure of this test (never a skip:
    the guard must not be able to skip its own breakage)."""
    try:
        told(loop, story, record=record)
    except pytest.skip.Exception as e:
        if loop.longest_gap > DOZED_S:
            raise                                                               # the laptop really dozed off during this very test
        pytest.fail(f"a failure was called 'dozed off' with no measured standstill ({loop.longest_gap:.1f} s): {e}")
    except AssertionError as e:
        return str(e)
    pytest.fail("the story failed and told() reported nothing")


def test_a_failure_of_this_test_carries_everything_the_loop_said_and_only_a_measured_standstill_is_a_skip(tmp_path):
    """PROOF's condition, tested on a real loop: make it fail on purpose (wait for a word it never says)
    and look at what the failure carries."""
    record = str(tmp_path / "kept" / "last-failure.txt")

    def never(loop):
        loop.wait(loop.said(SESSION, "waiting: the drive still shows the warm CD's note"), 40, "the first waiting word")
        loop.note(RUN_C, "s2")
        loop.wait(loop.said(RUN_C, "refused scenario 's2'"), 30, "the refusal of S2")
        loop.wait(loop.said(RUN_C, "a word the loop never says"), 3, "a word the loop never says")

    (tmp_path / "a").mkdir()
    msg = must_fail(Loop(tmp_path / "a"), never, record)
    assert msg.startswith("AssertionError: never happened within 3 s: a word the loop never says")
    state_file, out, log = (msg.split(mark)[1].split("\n---")[0] for mark in ("--- the State file", "--- the loop's stdout and stderr", "--- the loop's own log"))
    for said in (f"{SESSION}|waiting: the drive still shows the warm CD's note", f"{RUN_C}|seen-cd", f"{RUN_C}|refused scenario 's2' is not one of s1, s4, s5"):
        assert said in state_file, said                                         # the State file, word for word
    assert "state: seen-cd" in out and "state: refused scenario 's2'" in out      # what it printed
    assert "state: seen-cd" in log and re.search(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d state: waiting", log)      # its own log, with its times
    assert "the loop's exit code: 0" in msg and "longest standstill this test measured:" in msg and str(tmp_path / "a") in msg
    with open(record, encoding="utf-8") as f:
        kept = f.read()
    assert msg.split("\n(also written to")[0] in kept and f"also written to {record}" in msg         # and the same text is kept in a file
    # any other kind of failure carries it too: a plain assert, an exception of the story, a loop that tripped
    for n, (story, starts) in enumerate((
            (lambda l: (_ for _ in ()).throw(AssertionError("a plain assert of the story")), "AssertionError: a plain assert of the story"),
            (lambda l: {}["missing"], "KeyError: 'missing'"))):
        (tmp_path / f"b{n}").mkdir()
        other = must_fail(Loop(tmp_path / f"b{n}"), story, record)
        assert other.startswith(starts) and "--- the State file" in other and "--- the loop's stdout and stderr" in other
    # a skip needs a MEASURED standstill; then it says the seconds and what failed, and the evidence is still kept
    (tmp_path / "c").mkdir()
    dozed = Loop(tmp_path / "c")

    def froze(loop):
        loop.longest_gap = 579.0                                                # (as measured on 2026-11-21, lid closed)
        raise AssertionError("never happened within 200 s: A's test to finish")

    with pytest.raises(pytest.skip.Exception) as sk:
        told(dozed, froze, record=record)
    assert "stood still for 579 s, measured" in str(sk.value) and "A's test to finish" in str(sk.value)
    with open(record, encoding="utf-8") as f:
        assert "A's test to finish" in f.read()
    assert DOZED_S == 5.0
    (tmp_path / "d").mkdir()
    awake = Loop(tmp_path / "d")
    must_fail(awake, lambda l: (_ for _ in ()).throw(AssertionError("x")), record)          # no measured standstill: a failure stays a failure
    assert awake.longest_gap <= DOZED_S
