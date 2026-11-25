"""The NO-DISC-CHANGE launcher, RUN on this laptop against a made-up CD folder and a made-up signal (2026-11-21).

The path behind the switch (off by default): demo/warm/warm_launcher_signal.ps1. That file only ever runs
inside the test machine, and a mistake in it ends the whole warm session. tests/test_warm_signal.py reads
it as text; this file executes it: its check of the CD's files against the note's list (section 2), the
proof that the laptop's properties can be read (2b), the waiting loop (section 6) and the helper functions
are taken from the file WORD FOR WORD and run by Windows PowerShell here. The "CD" is built by the real
demo/warm_vm.py copy_cd, so the list the laptop writes and the check the launcher makes meet each other.
(The default path's launcher has its own such test: tests/test_warm_launcher_loop.py.)

What is made up, and only this:
  - the "CD" is a folder in the test's temp directory; its run_scenario.ps1 is a three-line stand-in that
    writes one line into a file. No test program exists here, nothing of the lab is on this "CD".
  - VBoxControl.exe (VirtualBox's tool inside the test machine, which reads the laptop's signal) is a
    stand-in that reads the signal from a file: `get` prints it the way VBoxControl does ("Value: ..." or
    "No value set!"), `wait` returns when the file changes. Every call of it is written down, so the test
    can see that the launcher starts nothing while it waits.
  - the launcher's VM-only start (sections 1 and 3 to 5) is not run. Its State function, which posts to the
    laptop's receiver from inside the VM, is replaced by one that writes the same words into a file:
    nothing is sent anywhere.
  - the three folders it writes to inside the VM point into the temp directory.
  - Start-Sleep also looks for a stop file, so the loop ends when the test is over (and by itself after
    five minutes whatever happens).
The story takes about two and a half minutes (the launcher's own calm check and settle pause are the real
ones), the channel test one more. Real-time tests: run them with the laptop awake, lid open.

A failure is never lost and only a measured standstill is a skip: told() of tests/test_warm_launcher_loop.py
(tested there) runs every story here.
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
sys.path.insert(0, os.path.join(ROOT, "demo"))
import warm_vm as W  # noqa: E402

from tests.test_warm_launcher_loop import told  # noqa: E402  (every failure carries the loop's evidence; tested there)

LAUNCHER = os.path.join(ROOT, "demo", "warm", "warm_launcher_signal.ps1")
POWERSHELL = shutil.which("powershell.exe") if sys.platform == "win32" else None

pytestmark = pytest.mark.skipif(not POWERSHELL, reason="needs Windows PowerShell")

SESSION, OTHER = "20261121-000000-aaaa", "20261121-999999-ffff"      # (OTHER: a run id shaped like ours that is not on this CD's note)
IDS = {"s1": "20261121-000100-bbbb", "s4": "20261121-000200-cccc", "s5": "20261121-000300-dddd"}

STUB = """param([string]$Scenario, [string]$RunId)
Add-Content -Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'ran.txt') -Value "$Scenario $RunId" -Encoding ascii
exit 0
"""

# The stand-in for VBoxControl.exe: `guestproperty get <name>` and `guestproperty wait <name> --timeout <ms>`.
FAKE_VBOXCONTROL = r'''
import os, sys, time
work, args = sys.argv[1], [a for a in sys.argv[2:] if a != "--nologo"]
signal, stop = os.path.join(work, "signal.txt"), os.path.join(work, "stop")
def read():
    try:
        with open(signal, encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None
with open(os.path.join(work, "calls.txt"), "a", encoding="ascii") as f:
    f.write(f"{time.time():.1f} {' '.join(args)}\n")
assert args[0] == "guestproperty" and args[2] in ("/AnalystLab/Warm/Run", "/VirtualBox/HostInfo/VBoxVer"), args
if args[1] == "get" and args[2] == "/VirtualBox/HostInfo/VBoxVer":
    print("No value set!" if os.path.exists(os.path.join(work, "host-properties-unreadable")) else "Value: 7.2.4")
elif args[1] == "get":
    v = read()
    print(f"Value: {v}" if v else "No value set!")
elif args[1] == "wait" and args[2] == "/AnalystLab/Warm/Run":
    assert args[3] == "--timeout" and int(args[4]) > 0, args
    was, until = read(), time.time() + int(args[4]) / 1000
    while read() == was and time.time() < until and not os.path.exists(stop):
        time.sleep(0.2)
    print(f"Name: {args[2]}, value: {read()}, flags:")
else:
    raise SystemExit(f"the launcher asked for something it must never ask: {args}")
'''


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
    head, n = re.subn(r"(?m)^\$vboxControl = @\(.*\|\r?\n\s+Where-Object .*$", lambda m: f"$vboxControl = '{os.path.join(work, 'VBoxControl.cmd')}'", head)
    assert n == 1                         # the stand-in, in place of the Guest Additions' tool
    helpers = between(text, "function Say", "function State") + between(text, "function AgentStatus", "# 1. the warm CD's own note")
    checks = between(text, "# one run id per test, from the note", "# 3. the VM's recorder")
    loop = between(text, "# 6. wait for the laptop's signal")
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
$harnessEnd = (Get-Date).AddSeconds(300)
function Start-Sleep {{
    param([int]$Seconds = 1)
    if ((Test-Path '{os.path.join(work, "stop")}') -or (Get-Date) -gt $harnessEnd) {{ exit 0 }}
    Microsoft.PowerShell.Utility\\Start-Sleep -Seconds $Seconds
}}
$note = ReadNote (Join-Path $Root 'AUTORUN_SCENARIO.txt')
$sessionId = [string]$note.run_id
$runId = $sessionId
"""
    script = ("param([Parameter(Mandatory)][string]$Root)\n" + head + helpers + mine + checks
              + "State 'harness: the CD and the signal passed their checks'\n" + loop)
    code = "\n".join(line.split(" #")[0] for line in script.splitlines() if not line.lstrip().startswith("#"))
    assert "Invoke-RestMethod" not in code and "http://" not in code           # nothing is sent anywhere from here
    assert "C:\\LabTools" not in code and "C:\\LabRunner" not in code and "C:\\AnalystLab" not in code and "System32" not in code
    assert code.count("& powershell.exe") == 1 and code.count("& $vboxControl") == 3      # the made-up CD's stand-in, and the signal tool's stand-in
    return script


class Loop:
    def __init__(self, tmp_path, spoil=None, first_signal=None, host_properties=True):
        self.work = str(tmp_path)
        # the made-up CD, built the way the laptop builds the real one: copy_cd writes the note and the list of fingerprints
        src = os.path.join(self.work, "src")
        os.makedirs(os.path.join(src, "s1"))
        files = {"/run_scenario.ps1": STUB.replace("\n", "\r\n"), "/s1/program.txt": "a stand-in for a test program: never run",
                 "/AUTORUN_SCENARIO.txt": "replaced below", "/scenario_launcher.ps1": "the launcher's place on the CD"}
        for cd_path, text in files.items():
            with open(os.path.join(src, *cd_path.strip("/").split("/")), "w", encoding="ascii", newline="") as f:
                f.write(text)
        viso = os.path.join(self.work, "src.viso")
        with open(viso, "w", encoding="ascii") as f:
            f.write("--iprt-iso-maker-file-marker-bourne-sh 1 " + " ".join(f"'{p}={os.path.join(src, *p.strip('/').split('/'))}'" for p in files))
        note = f"scenario=s1\r\nrun_id={SESSION}\r\nwarm=1\r\npractice=1" + "".join(f"\r\nrun_{s}={i}" for s, i in IDS.items())
        W.copy_cd(viso, os.path.join(self.work, "warm"), "warm.viso", texts={W.NOTE: note}, list_into=W.NOTE, unlisted=(W.LAUNCHER_ON_CD,))
        self.cd = os.path.join(self.work, "warm", "cd")
        if spoil:
            spoil(self.cd)
        with open(os.path.join(self.work, "fake_vboxcontrol.py"), "w", encoding="ascii") as f:
            f.write(FAKE_VBOXCONTROL)
        with open(os.path.join(self.work, "VBoxControl.cmd"), "w", encoding="ascii", newline="\r\n") as f:
            f.write(f'@"{sys.executable}" "{os.path.join(self.work, "fake_vboxcontrol.py")}" "{self.work}" %*\n')
        if not host_properties:
            open(os.path.join(self.work, "host-properties-unreadable"), "w").close()
        if first_signal:
            self.signal(None, raw=first_signal)              # (the laptop sets nothing at the start: the signal is "not set")
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

    def signal(self, word, raw=None):
        """The laptop's side of the signal, as warm_vm._signal does it: the test's run id, or (None) taken away.
        `raw`: a value it never sends, to try what the launcher does with it."""
        path = os.path.join(self.work, "signal.txt")
        if word is None and raw is None:
            self.patiently(lambda: os.path.exists(path) and os.remove(path))
            return
        tmp = os.path.join(self.work, "signal.tmp")
        with open(tmp, "w", encoding="ascii") as f:
            f.write(raw if raw is not None else IDS[word])
        self.patiently(lambda: os.replace(tmp, path))

    @staticmethod
    def patiently(change):
        """A change to a file the loop reads; tried again when the loop happens to be reading it right then."""
        for _ in range(40):
            try:
                return change()
            except PermissionError:
                time.sleep(0.05)
        return change()

    def _lines(self, name):
        try:
            with open(os.path.join(self.work, name), encoding="ascii") as f:
                return f.read().split("\n")[:-1]
        except OSError:
            return []

    def states(self):
        return [tuple(line.split("|", 1)) for line in self._lines("states.txt") if "|" in line]

    def ran(self):
        return self._lines("ran.txt")

    def calls(self):
        """Every call of the signal tool so far: "get" / "wait", in order."""
        return [line.split(" ")[2] for line in self._lines("calls.txt")]

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
            "--- what the made-up CD's stand-in ran (ran.txt)", text("ran.txt"),
            "--- every call of the signal tool (time, what was asked)", text("calls.txt", 2500),
            "--- the signal as it stands (signal.txt)", text("signal.txt")])

    def said(self, run_id, prefix):
        return lambda: any(r == run_id and s.startswith(prefix) for r, s in self.states())

    def end(self):
        with open(os.path.join(self.work, "stop"), "w") as f:
            f.write("stop")
        try:
            self.proc.wait(timeout=60)            # its wait for the signal ends at the stop file, and it ends itself at its next sleep
        finally:
            self.alive = False
            try:
                self.out.flush()
            except ValueError:
                pass


READY = "harness: the CD and the signal passed their checks"


def test_the_launcher_runs_a_named_test_once_with_no_disc_change_and_starts_nothing_that_was_called_off(tmp_path):
    told(Loop(tmp_path), the_whole_story)


def the_whole_story(loop):
    a, b, c = IDS["s1"], IDS["s4"], IDS["s5"]
    # the CD's files match the list in its note, each test has its run id there, and the laptop's properties can be read
    loop.wait(loop.said(SESSION, READY), 60, "the checks before ready")
    assert loop.calls() and set(loop.calls()) <= {"get", "wait"}

    # nothing is asked of it: it sits inside ONE wait and starts nothing
    time.sleep(3)
    quiet = loop.calls()
    assert quiet[-1] == "wait"
    time.sleep(8)
    assert loop.calls() == quiet and loop.ran() == []                          # eight seconds, not one more call

    # the laptop names S1: picked up, run from the CD that never left, flushed, done
    loop.signal("s1")
    loop.wait(loop.said(a, "picked-up s1"), 30, "S1 picked up")
    assert loop.ran() == []                                                 # picked up is not started: the calm check comes first
    loop.wait(loop.said(a, "done "), 200, "S1's test to finish")
    words = [s for r, s in loop.states() if r == a]
    assert [w.split(" ")[0] for w in words] == ["picked-up", "running", "flushing", "done"]
    assert re.fullmatch(r"done (ok|late) left=\d+", words[-1]) and loop.ran() == [f"s1 {a}"]       # with the run id the CD's note carries
    assert os.path.exists(os.path.join(loop.work, "barrier", f"barrier-{a}-{words[-1].split(' ')[1]}.txt"))

    # the laptop takes the signal away, as it does once a test runs; S1 named again later is never run twice
    loop.signal(None)
    time.sleep(3)
    loop.signal("s1")
    time.sleep(8)
    assert loop.ran() == [f"s1 {a}"] and len([1 for r, s in loop.states() if r == a and s.startswith("picked-up")]) == 1

    # S4 is named and picked up; then the laptop gives up and calls it off before it starts: nothing is started
    loop.signal("s4")
    loop.wait(loop.said(b, "picked-up s4"), 30, "S4 picked up")
    loop.signal(None)
    loop.wait(loop.said(b, "failed not-started"), 150, "the launcher's word that S4 did not start")
    assert loop.ran() == [f"s1 {a}"]

    # what the signal can never start: anything that is not one of this session's three run ids. It is refused in
    # plain words, once for as long as such a value stands, and nothing is started
    refusal = "refused a signal that is not one of this session's three run ids (nothing was started)"
    for raw in (OTHER, SESSION, "s5", c + "x", f"{c};calc", "..\\run_scenario.ps1", c.upper()):      # (the last: a run id in other letters is not that run id)
        loop.signal(None, raw=raw)
        time.sleep(4)
    assert loop.ran() == [f"s1 {a}"] and not any(r == c for r, _ in loop.states())
    assert [s for r, s in loop.states() if s.startswith("refused a signal")] == [refusal] and (SESSION, refusal) in loop.states()
    loop.signal(None)                                                        # taken away, then another such value: said again
    time.sleep(4)
    loop.signal(None, raw="s1")
    loop.wait(lambda: [s for _, s in loop.states()].count(refusal) == 2, 30, "the second refusal")
    assert loop.ran() == [f"s1 {a}"]
    states_text = open(os.path.join(loop.work, "states.txt"), encoding="ascii").read()
    assert OTHER not in states_text and "calc" not in states_text            # the refused value itself is never written into a message
    loop.signal(None)
    time.sleep(3)

    # S4 named again: it never ran, so its run id is still good, and now it runs
    loop.signal("s4")
    loop.wait(lambda: len([1 for r, s in loop.states() if r == b and s.startswith("picked-up")]) == 2, 30, "S4 picked up again")
    loop.wait(lambda: any(r == b and s.startswith("done ") for r, s in loop.states()), 200, "S4's test to finish")
    assert loop.ran() == [f"s1 {a}", f"s4 {b}"]
    assert [s.split(" ")[0] for r, s in loop.states() if r == b] == ["picked-up", "failed", "picked-up", "running", "flushing", "done"]
    everything = loop.states()
    assert not any(s.startswith(("failed error", "waiting: the wait for the signal returns at once")) for _, s in everything)
    # no rhythm: in the whole story the signal tool was called a few dozen times at most (each change of the signal: a wait ends, a look follows)
    assert len(loop.calls()) < 60 and set(loop.calls()) == {"get", "wait"}


def test_a_cd_that_does_not_match_its_notes_list_ends_the_session_before_ready(tmp_path):
    """A changed file, an extra file, a missing file, a note without a run id of its own for a test, a list
    line that can't be read, a signal that already says something strange: each is said in words and
    nothing is ever picked up."""
    def changed(cd):
        with open(os.path.join(cd, "s1", "program.txt"), "a", encoding="ascii") as f:
            f.write(" (changed after the list was written)")

    def extra(cd):
        with open(os.path.join(cd, "s1", "extra.exe"), "w", encoding="ascii") as f:
            f.write("not on the laptop's list")

    def missing(cd):
        os.remove(os.path.join(cd, "s1", "program.txt"))

    def note(change):
        def spoil(cd):
            p = os.path.join(cd, "AUTORUN_SCENARIO.txt")
            with open(p, encoding="ascii", newline="") as f:
                t = f.read()
            with open(p, "w", encoding="ascii", newline="") as f:
                f.write(change(t))
        return spoil

    cases = ((changed, None, 2, "failed a file on the warm CD differs from the laptop's list: s1\\program.txt"),
             (extra, None, 2, "failed the warm CD holds a file its list does not name: s1\\extra.exe"),
             (missing, None, 2, "failed the warm CD holds 1 of the 2 files its list names"),
             (note(lambda t: t.replace(f"run_s4={IDS['s4']}", f"run_s4={IDS['s1']}")), None, 2, "failed the warm CD's note carries no run id of its own for s4"),
             (note(lambda t: t.replace("file_1=", "file_1=zz")), None, 2, "failed the warm CD's note: line 1 of its file list can't be read"),
             (note(lambda t: t.replace("files=2", "files=0")), None, 2, "failed the warm CD's note lists no files"),
             (None, OTHER, 5, "failed the laptop's signal already says something that is not one of this session's run ids"))
    for n, (spoil, first, code, word) in enumerate(cases):
        (tmp_path / str(n)).mkdir()
        loop = Loop(tmp_path / str(n), spoil=spoil, first_signal=first)

        def story(loop, word=word):
            loop.wait(lambda: loop.proc.poll() is not None, 60, "the launcher to end itself")
            assert [s for _, s in loop.states()] == [word] and loop.ran() == []

        told(loop, story, exit_code=code)


def test_a_test_machine_that_cannot_read_the_laptops_properties_ends_the_session_before_ready(tmp_path):
    """The channel is proven BEFORE "ready" (one minute of looking): no session in which a click does nothing."""
    loop = Loop(tmp_path, host_properties=False)

    def story(loop):
        loop.wait(lambda: loop.proc.poll() is not None, 120, "the launcher to end itself")
        assert [s for _, s in loop.states()] == ["failed the laptop's signal can't be read in the test machine"] and loop.ran() == []
        assert 10 <= loop.calls().count("get") <= 13 and "wait" not in loop.calls()      # it looked a dozen times, five seconds apart, and gave up in words

    told(loop, story, exit_code=5)
