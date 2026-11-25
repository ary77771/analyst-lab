"""One-command scenario run in the lab VM: restore -> boot -> run -> collect -> check -> shut down.

    python tools/run_in_vm.py s1                # run S1 in a fresh VM and check it
    python tools/run_in_vm.py s1 --plan         # only show what would happen
    python tools/run_in_vm.py s1 --headless     # no VM window
    python tools/run_in_vm.py s1 --keep-running # leave the VM on afterwards (to look around)
    python tools/run_in_vm.py s1 --cpus 2       # 2 virtual CPUs (default 1: 2 freeze in slow mode)
    python tools/run_in_vm.py s3 s4 s5          # a BATCH: one boot, the scenarios one after another,
                                                # each with its own run id, barrier and checks (~3x faster
                                                # for development; official experiment runs: one boot each)

Scenarios whose answer sheet says `needs_calm_vm: false` skip the VM's calm-down wait (S4, S5:
no timing rule that Windows' startup storm could upset).

Steps (DESIGN 6.2, "One-command run"):
  1. Checks: the VM is powered off, snapshot 'clean' exists, the answer sheet exists, the laptop's
     receiver and test server run (tools/lab_servers.ps1 starts them if needed).
  2. Builds a run CD with a fresh run id (tools/make_scenario_cd.ps1 -RunId).
  3. Restores 'clean' (the VM's previous state is thrown away, by design), inserts the run CD,
     starts the VM, waits for the auto-logon.
  4. Inside the VM, the scenario launcher (tools/vm/scenario_launcher.ps1, a logon task) finds
     the CD, runs the scenario and drops a "flush barrier" marker file once its recorder has
     nothing left to fingerprint. Its progress (and the starter's) arrives as LAUNCHER_STATE records
     in recordings/vmruns (and the guest property /AnalystLab/Runner when VBoxControl exists).
  5. Waits for this run's record (recordings/vmruns) and then for the marker's FILE_HASH
     (recordings/vm). The VM's agent sends in order, so once the marker is here, everything
     before it is too.
  6. Runs tools/check_scenario.py and tools/check_graph_scenario.py <scenario> --run-id <id>
     (PASS/FAIL), then tools/check_alerts.py (detection: DETECTED / MISSED / NONE EXPECTED,
     recorded separately: a miss is a result, not a broken run)
     (the recording, and the evidence graph rebuilt by replay, against the answer sheet).
  7. Always shuts the VM down at the end (Guest Additions; ACPI button as a fallback), also
     after a failure, unless --keep-running.
A summary is saved to recordings/scenario_runs/<run id>.json (never committed).
Blind scenarios (B1, B2: folders outside the project) run with tools/run_blind.py, which reuses this Runner.
Exit codes: 0 PASS · 1 check FAIL · 2 not started (a check failed; the VM was not touched) ·
3 a VM step failed or timed out.
No admin rights, no passwords: only VirtualBox's own VBoxManage commands.
"""

import argparse
import glob
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VM = "AnalystLab-Win11"
SNAPSHOT = "clean"
RUN_CD = os.path.join(PROJECT_ROOT, "build", "analystlab-run.viso")
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")
TIMEOUTS = {"boot": 480, "launcher": 900, "run": 1200, "barrier": 300, "shutdown": 180, "unlock": 120}
OFF = ("poweroff", "aborted", "saved")
POLL = 2.0


class StepFailed(Exception):
    """A VM step failed or timed out (exit 3)."""


class NotStarted(Exception):
    """A pre-check failed; nothing was changed (exit 2)."""


def new_run_id(now=None):
    now = now or datetime.now(timezone.utc)
    return f"{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


def utc_now():
    return datetime.now(timezone.utc)


def parse_vbox_time(text):
    """VirtualBox timestamps have 9 fractional digits; Python takes 6."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z?$", text.strip())
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def machinereadable(text, key):
    m = re.search(rf'^{re.escape(key)}="(.*)"\s*$', text, re.M)
    return m.group(1) if m else None


def transient(text):
    """VBoxManage errors that clear up by themselves: the VM's lock just after a restore, and the
    console object vanishing while the VM powers off (2026-10-23: a passing run was reported
    "VM still running" because one showvminfo hit that moment)."""
    return "already locked" in text or "VBOX_E_INVALID_OBJECT_STATE" in text


class VBox:
    """The VBoxManage commands the runner needs (all work without admin rights)."""

    def __init__(self, exe=VBOXMANAGE, vm=VM):
        self.exe, self.vm = exe, vm

    def call(self, *args, check=True):
        for _ in range(5):          # VirtualBox may still hold the VM's lock just after a restore
            p = subprocess.run([self.exe, *args], capture_output=True, text=True, errors="replace")
            if p.returncode == 0 or not transient(p.stdout + p.stderr):
                break
            time.sleep(3)
        if check and p.returncode != 0:
            raise StepFailed(f"VBoxManage {' '.join(args[:2])} failed (exit {p.returncode}): {p.stderr.strip()[:300]}")
        return p.returncode, p.stdout + p.stderr

    def info(self):
        return self.call("showvminfo", self.vm, "--machinereadable")[1]

    def state(self):
        return machinereadable(self.info(), "VMState")

    def unlocked(self):
        s = machinereadable(self.info(), "SessionState")
        return s is None or s.lower() == "unlocked"   # listed only while a session exists

    def snapshots(self):
        code, out = self.call("snapshot", self.vm, "list", "--machinereadable", check=False)
        return re.findall(r'^SnapshotName(?:-[\d-]+)?="(.*)"\s*$', out, re.M) if code == 0 else []

    def restore(self, name):
        self.call("snapshot", self.vm, "restore", name)

    def set_cpus(self, n):
        """CPU count for this boot (after a restore, which brings back the snapshot's count)."""
        self.call("modifyvm", self.vm, f"--cpus={n}")

    def insert_cd(self, path):
        """Put a CD in the first DVD drive; "emptydrive" ejects it."""
        self.call("storageattach", self.vm, "--storagectl", "SATA", "--port", "1", "--device", "0",
                  "--type", "dvddrive", "--medium", path)

    def start(self, headless=False):
        for _ in range(5):          # VirtualBox may release its lock a moment late
            code, out = self.call("startvm", self.vm, "--type", "headless" if headless else "gui", check=False)
            if code == 0:
                return
            if "already locked" not in out:
                raise StepFailed(f"VBoxManage startvm failed: {out.strip()[:300]}")
            time.sleep(3)
        raise StepFailed("VBoxManage startvm: the VM stayed locked")

    def logged_in_since(self, after):
        """True if Guest Additions report a logged-in user, set after `after` (a value from
        before a restore or crash can linger, so the property's own timestamp must be newer)."""
        code, out = self.call("guestproperty", "enumerate", self.vm, check=False)
        m = re.search(r"/VirtualBox/GuestInfo/OS/LoggedInUsers\s*=\s*'(\d+)'\s*@\s*(\S+)", out)
        if code != 0 or not m:
            return False
        t = parse_vbox_time(m.group(2))
        return int(m.group(1)) >= 1 and t is not None and t > after

    def guest_property(self, name):
        code, out = self.call("guestproperty", "get", self.vm, name, check=False)
        m = re.match(r"\s*Value:\s*(.*?)\s*$", out, re.M)
        return m.group(1) if code == 0 and m else None

    def request_shutdown(self):
        code, _ = self.call("controlvm", self.vm, "shutdown", check=False)
        if code != 0:   # Guest Additions not answering: the virtual power button instead
            self.call("controlvm", self.vm, "acpipowerbutton", check=False)


class Tail:
    """New records appended to recordings/<label>/*.jsonl since this object was created.
    Reads only complete lines (the receiver may be mid-write) and remembers where it stopped."""

    def __init__(self, folder):
        self.folder = folder
        self.offsets = {p: os.path.getsize(p) for p in self._files()}

    def _files(self):
        return sorted(glob.glob(os.path.join(self.folder, "*.jsonl")))

    def new_records(self):
        out = []
        for path in self._files():
            start = self.offsets.get(path, 0)
            with open(path, "rb") as f:
                f.seek(start)
                chunk = f.read()
            end = chunk.rfind(b"\n")
            if end < 0:
                continue
            self.offsets[path] = start + end + 1
            for line in chunk[:end].splitlines():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass        # damaged line: engine/jsonl.py counts these; not ours to judge
        return out


def is_run_record(rec, run_id):
    return rec.get("type") == "SCENARIO_RUN" and rec.get("run_id") == run_id


def is_barrier(rec, run_id):
    """The marker's fingerprint: an agent FILE_HASH for ...\\_runner\\barrier-<run_id>-<ok|late>.txt.
    Returns 'ok', 'late' or None."""
    if rec.get("type") != "FILE_HASH":
        return None
    name = str((rec.get("data") or {}).get("TargetFilename", "")).replace("/", "\\").rsplit("\\", 1)[-1].lower()
    m = re.fullmatch(rf"barrier-{re.escape(run_id)}-(ok|late)\.txt", name)
    return m.group(1) if m else None


def powershell(script, *args):
    p = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(PROJECT_ROOT, "tools", script), *args],
                       capture_output=True, text=True, errors="replace")
    return p.returncode, p.stdout + p.stderr


def is_baseline(scenario):
    """A baseline boot (scenarios/s0: nothing runs) has nothing to check."""
    import yaml
    with open(os.path.join(PROJECT_ROOT, "scenarios", scenario, "ground_truth.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f).get("baseline") is True


def default_check(scenario, run_id, recordings=None):
    """Both checks of a run: the recording against the answer sheet, and the evidence graph rebuilt
    by replay against the answer sheet (the week-2 checkpoint). PASS only if both pass. A baseline
    boot passes when it was recorded (its run record and flush barrier arrived)."""
    if is_baseline(scenario):
        print(f"{scenario.upper()} is a baseline boot: recorded, nothing to check")
        return 0
    extra = ["--recordings", recordings] if recordings else []
    codes = [subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", tool), scenario, "--run-id", run_id] + extra).returncode
             for tool in ("check_scenario.py", "check_graph_scenario.py")]
    return 0 if all(c == 0 for c in codes) else 1


DETECTION = {0: "DETECTED", 1: "MISSED", 2: "NOT CHECKED"}


def default_detect_check(scenario, run_id, recordings=None):
    """What the detectors raised for the run (tools/check_alerts.py), recorded SEPARATELY from the
    run's PASS/FAIL: a miss is a result of the experiment, not a broken run (integration review
    2026-10-24: runs used to record no detection outcome at all)."""
    extra = ["--recordings", recordings] if recordings else []
    code = subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", "check_alerts.py"), scenario,
                           "--run-id", run_id] + extra).returncode
    if code == 0 and not expects_alert(scenario):
        return "NONE EXPECTED"
    return DETECTION.get(code, "NOT CHECKED")


def expects_alert(scenario):
    import yaml
    with open(os.path.join(PROJECT_ROOT, "scenarios", scenario, "ground_truth.yaml"), encoding="utf-8") as f:
        return bool(((yaml.safe_load(f) or {}).get("alert_expected") or {}).get("check"))


def needs_calm_vm(scenario):
    """An answer sheet may say `needs_calm_vm: false` (no timing rules that Windows' startup storm
    could upset): the VM's launcher then skips its calm-down wait for that scenario."""
    import yaml
    with open(os.path.join(PROJECT_ROOT, "scenarios", scenario, "ground_truth.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f).get("needs_calm_vm", True) is not False


class Runner:
    def __init__(self, scenario, vbox=None, recordings=None, headless=False, keep_running=False, cpus=None,
                 snapshot=SNAPSHOT, servers=None, build_cd=None, check=None, detect_check=None, timeouts=None, poll=POLL, say=print):
        # one scenario, or a BATCH (a list): one boot runs them one after another, each with its own
        # run id, run record, flush barrier and checks (DESIGN 6.2: for development runs; official
        # experiment runs use one clean boot each)
        scenarios = [scenario] if isinstance(scenario, str) else list(scenario)
        ids = []
        for _ in scenarios:
            rid = new_run_id()
            while rid in ids:
                rid = new_run_id()
            ids.append(rid)
        self.items = [{"scenario": s.lower(), "run_id": rid} for s, rid in zip(scenarios, ids)]
        self.run_id = self.items[0]["run_id"]
        self.vbox = vbox or VBox()
        self.run_cd = RUN_CD         # tools/run_blind.py builds its run CD outside the project
        self.recordings = recordings or os.path.join(PROJECT_ROOT, "recordings")
        self.headless, self.keep_running, self.cpus = headless, keep_running, cpus
        self.snapshot = snapshot     # 'clean' (default) or e.g. 'lived-in' (blind round 4, lived-in-vm.md); recorded
        self.servers = servers or (lambda: powershell("lab_servers.ps1"))
        # a single run's CD carries no batch line: single runs (the official experiment runs) keep
        # the calm-down wait whatever the answer sheet allows (review 2026-10-20)
        self.build_cd = build_cd or (lambda rid: powershell("make_scenario_cd.ps1", "-RunId", rid, "-Scenario", self.scenario,
                                                            *(["-Batch", self.batch_note()] if len(self.items) > 1 else [])))
        self.check = check or (lambda s, rid: default_check(s, rid, self.recordings))
        self.detect_check = detect_check or (lambda s, rid: default_detect_check(s, rid, self.recordings))
        self.timeouts = {**TIMEOUTS, **(timeouts or {})}
        self.poll, self.say = poll, say
        self.summary = {"run_id": self.run_id, "scenario": self.scenario.upper(), "vm": self.vbox.vm,
                        "snapshot": self.snapshot, "steps": {}}
        if len(self.items) > 1:
            self.summary["batch"] = [dict(i, scenario=i["scenario"].upper()) for i in self.items]
        self._seen = []              # launcher states shown so far (from either channel)
        self._runs = None            # Tail of recordings/vmruns: progress records + the run records
        self._run_recs = {}          # run id -> its SCENARIO_RUN record
        self._barriers = {}          # run id -> "ok" / "late" (the marker's FILE_HASH)

    @property
    def _run_rec(self):
        return self._run_recs.get(self.run_id)

    @property
    def scenario(self):
        """The (first) scenario; a single run's only one."""
        return self.items[0]["scenario"]

    @scenario.setter
    def scenario(self, value):
        self.items[0]["scenario"] = value.lower()

    def batch_note(self):
        """For the run CD: "s3:<run id>:calm,s4:<run id>:fast" (fast = skip the calm-down wait)."""
        return ",".join(f"{i['scenario']}:{i['run_id']}:{'calm' if i.get('calm', True) else 'fast'}" for i in self.items)

    def _label(self, run_id):
        """In a batch, progress lines name their scenario."""
        if len(self.items) == 1:
            return ""
        return next(i["scenario"].upper() for i in self.items if i["run_id"] == run_id) + ": "

    # -- helpers ---------------------------------------------------------------------------
    def _timed(self, name, fn):
        t0 = time.monotonic()
        result = fn()
        self.summary["steps"][name] = round(time.monotonic() - t0, 1)
        return result

    def _wait(self, what, timeout, cond, progress=True):
        deadline = time.monotonic() + timeout
        while True:
            result = cond()
            if result:
                return result
            if progress:
                self._guest_progress()
            if time.monotonic() > deadline:
                raise StepFailed(f"timed out after {timeout} s waiting for {what}")
            time.sleep(self.poll)

    def _report(self, state):
        """Show a launcher state once; stop early if the VM reports a failure."""
        if state in self._seen:
            return
        self._seen.append(state)
        self.say(f"    VM: {state}")
        if re.match(r"(S\d+[A-Z]?: )?(starter: )?failed", state):
            raise StepFailed(f"the VM's scenario launcher reported: {state}")

    def _guest_progress(self):
        """Progress from the VM: LAUNCHER_STATE records the launcher posts to the receiver
        (recordings/vmruns), and the guest property /AnalystLab/Runner when VBoxControl exists.
        The same pass picks up this run's SCENARIO_RUN record."""
        ids = {i["run_id"] for i in self.items}
        if self._runs is not None:
            for rec in self._runs.new_records():
                if rec.get("type") == "LAUNCHER_STATE" and rec.get("run_id") in ids:
                    self._report(self._label(rec["run_id"]) + str(rec.get("state", "")))
                elif rec.get("type") == "LAUNCHER_STATE" and rec.get("run_id") == "-":
                    # the starter before it has read the CD: the tail starts with this run (the VM
                    # was off), so these come from this boot; "no run CD" means it missed ours
                    state = str(rec.get("state", ""))
                    self._report(state)
                    if "no run CD" in state:
                        raise StepFailed("the VM's starter found no run CD (was the CD inserted?)")
                elif rec.get("type") == "SCENARIO_RUN" and rec.get("run_id") in ids:
                    self._run_recs[rec["run_id"]] = rec
        value = self.vbox.guest_property("/AnalystLab/Runner")
        for rid in ids:
            if value and value.startswith(rid + " "):
                self._report(self._label(rid) + value[len(rid) + 1:])

    # -- steps -----------------------------------------------------------------------------
    def precheck(self):
        self.precheck_sheets()
        self.precheck_vm()

    def precheck_sheets(self):
        """Our scenarios' answer sheets exist (and say whether a batch may skip the calm-down wait).
        tools/run_blind.py replaces this: a blind sheet is not opened before its run."""
        for item in self.items:
            if not os.path.exists(os.path.join(PROJECT_ROOT, "scenarios", item["scenario"], "ground_truth.yaml")):
                raise NotStarted(f"no answer sheet scenarios/{item['scenario']}/ground_truth.yaml")
            item["calm"] = needs_calm_vm(item["scenario"])

    def precheck_vm(self):
        state = self.vbox.state()
        if state not in ("poweroff", "aborted"):
            raise NotStarted(f"the VM is '{state}'; it must be powered off (shut it down first)")
        if self.snapshot not in self.vbox.snapshots():
            raise NotStarted(f"snapshot '{self.snapshot}' not found")
        code, out = self.servers()
        if code != 0:
            raise NotStarted("the laptop's receiver/test server aren't running:\n" + out.strip())
        code, out = self.build_cd(self.run_id)
        if code != 0:
            raise NotStarted("building the run CD failed:\n" + out.strip())

    def boot(self):
        self._wait("VirtualBox to release the VM", self.timeouts["unlock"], self.vbox.unlocked)
        self.vbox.restore(self.snapshot)
        if self.cpus:
            self.vbox.set_cpus(self.cpus)
            self.summary["cpus"] = self.cpus
        self.vbox.insert_cd(self.run_cd)
        t0 = utc_now()
        self.vbox.start(self.headless)
        self._wait("the VM's auto-logon", self.timeouts["boot"], lambda: self.vbox.logged_in_since(t0))

    def _first(self, tail, match):
        for rec in tail.new_records():
            found = match(rec, self.run_id)
            if found:
                return found if isinstance(found, str) else rec
        return None

    def _scan_barriers(self, vm):
        """Remember every barrier marker of this boot's runs (in a batch a later one must not be
        lost while waiting for an earlier one)."""
        for rec in vm.new_records():
            for item in self.items:
                kind = is_barrier(rec, item["run_id"])
                if kind:
                    self._barriers[item["run_id"]] = kind
        return None

    def collect(self, runs, vm, item=None, first=True):
        item = item or self.items[0]
        rid = item["run_id"]
        # In slow mode Guest Additions report the logon minutes before Windows starts logon tasks
        # (PowerShell alone took ~1 min to start, 2026-10-18); silence beyond that means no task.
        if first:
            self._wait("the VM's scenario launcher to start (none: was 'clean' taken after the new SETUP?)",
                       self.timeouts["launcher"], lambda: bool(self._seen))
        run = self._wait(f"the run record of {rid}", self.timeouts["run"], lambda: self._run_recs.get(rid))
        item["run_record"] = {k: run.get(k) for k in ("start", "end", "exit_code")}
        kind = self._wait("the flush barrier (the VM's last events)", self.timeouts["barrier"],
                          lambda: self._scan_barriers(vm) or self._barriers.get(rid))
        item["barrier"] = kind
        self.on_barrier(item)
        if rid == self.run_id:                       # the single-run summary keys, as before
            self.summary["run_record"], self.summary["barrier"] = item["run_record"], kind
        if kind == "late":
            self.say("    note: the VM's agent was still fingerprinting files after 180 s; the check may miss them")

    def on_barrier(self, item):
        """Called wherever a run's flush barrier is taken as arrived (tools/run_blind.py notes the
        time: its answer sheet may be opened only after it). Nothing here."""

    def shutdown(self):
        """Any state but off (running, starting, paused, stuck...) gets a shutdown request; a VM
        that doesn't power off is reported, never silently left on. Then the run CD is ejected,
        so a later boot can't run the scenario again."""
        if self.vbox.state() not in OFF:
            self.vbox.request_shutdown()
            self._wait("the VM to power off", self.timeouts["shutdown"], lambda: self.vbox.state() in OFF, progress=False)
        try:
            self._wait("VirtualBox to release the VM", self.timeouts["unlock"], self.vbox.unlocked, progress=False)
            self.vbox.insert_cd("emptydrive")
        except StepFailed as e:              # not fatal: the VM's launcher refuses a repeated run id
            self.say(f"    note: the run CD could not be ejected ({e})")

    def run(self):
        if len(self.items) > 1:
            names = ", ".join(f"{i['scenario'].upper()} ({i['run_id']})" for i in self.items)
            self.say(f"Batch of {len(self.items)} in one boot: {names} · VM {self.vbox.vm} from snapshot '{self.snapshot}'")
        else:
            self.say(f"Scenario {self.scenario.upper()} · run id {self.run_id} · VM {self.vbox.vm} from snapshot '{self.snapshot}'")
        tails = {}
        try:
            self.say("--> 1. Checks (VM off, snapshot, answer sheet, laptop servers) + run CD")
            self._timed("precheck", self.precheck)
        except (NotStarted, StepFailed) as e:     # e.g. VBoxManage itself failing: still nothing changed
            self.say(f"NOT STARTED: {e}\nThe VM was not touched.")
            return self._finish("not started", 2)
        code, verdict = 3, "vm step failed"
        try:
            tails = {"runs": Tail(os.path.join(self.recordings, "vmruns")), "vm": Tail(os.path.join(self.recordings, "vm"))}
            self._runs = tails["runs"]
            self.say(f"--> 2. Restore '{self.snapshot}', insert the run CD, boot (≈1 min)")
            self._timed("restore_and_boot", self.boot)
            # 3. collect EVERY run of the boot first, 4. then check them: a run's check window ends
            # where the next run starts, and that start is only known once the next run's record
            # is in (review 2026-10-20: checked early, S2 then S2J saw S2J's program inside S2's
            # window). If a later run fails, the runs that finished are still checked.
            stop = None
            for n, item in enumerate(self.items):
                tag = f" {item['scenario'].upper()}" if len(self.items) > 1 else ""
                self.say(f"--> 3.{tag} Scenario running in the VM; waiting for its record and the flush barrier")
                try:
                    self._timed(f"run_and_collect{tag.replace(' ', '_')}",
                                lambda: self.collect(tails["runs"], tails["vm"], item, first=(n == 0)))
                except StepFailed as e:
                    stop = e
                    self._scan_barriers(tails["vm"])            # what did arrive still counts
                    for it in self.items:
                        rid = it["run_id"]
                        if "barrier" not in it and rid in self._run_recs and rid in self._barriers:
                            it["run_record"] = {k: self._run_recs[rid].get(k) for k in ("start", "end", "exit_code")}
                            it["barrier"] = self._barriers[rid]
                            self.on_barrier(it)
                    break
            failed = []
            for item in [i for i in self.items if "barrier" in i]:
                tag = f" {item['scenario'].upper()}" if len(self.items) > 1 else ""
                self.say(f"--> 4.{tag} Check against the answer sheet\n")
                rc = self._timed(f"check{tag.replace(' ', '_')}", lambda: self.check(item["scenario"], item["run_id"]))
                item["result"] = "PASS" if rc == 0 else "FAIL"
                if rc != 0:
                    failed.append(item["scenario"].upper())
                self.say(f"--> 4b.{tag} What the detectors raised (recorded separately from PASS/FAIL)\n")
                item["detection"] = self._timed(f"detect{tag.replace(' ', '_')}",
                                                lambda: self.detect_check(item["scenario"], item["run_id"]))
                if item["run_id"] == self.run_id:
                    self.summary["detection"] = item["detection"]
            if stop is not None:
                raise stop
            code = 1 if failed else 0
            verdict = "PASS" if not failed else ("FAIL" if len(self.items) == 1 else f"FAIL ({', '.join(failed)})")
        except StepFailed as e:
            self.say(f"STOPPED: {e}")
        except KeyboardInterrupt:
            self.say("STOPPED: interrupted (Ctrl+C)")
        except Exception as e:               # a bug of ours: still shut down and write the summary
            self.say(f"STOPPED (unexpected error): {e!r}")
            verdict = "error"
        finally:
            if self.keep_running:
                self.say("--> 5. Leaving the VM running (--keep-running); the run CD stays inserted, "
                         "but the VM's launcher won't run this run id again")
            else:
                self.say("--> 5. Shutting the VM down")
                try:
                    self._timed("shutdown", self.shutdown)
                except (StepFailed, KeyboardInterrupt) as e:
                    self.say(f"WARNING: {e}. Shut it down with: VBoxManage controlvm {self.vbox.vm} shutdown")
                    code, verdict = 3, verdict + " (VM still running)"
        return self._finish(verdict, code)

    def _finish(self, verdict, code):
        self.summary.update({"result": verdict, "exit_code": code, "finished": utc_now().isoformat()})
        if len(self.items) > 1:
            self.summary["batch"] = [dict(i, scenario=i["scenario"].upper()) for i in self.items]
            for i in self.items:
                self.say(f"    {i['scenario'].upper():>4} {i['run_id']}  {i.get('result', 'not run')}"
                         f"  detection: {i.get('detection', 'not checked')}")
        folder = os.path.join(self.recordings, "scenario_runs")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{self.run_id}.json"), "w", encoding="utf-8") as f:
            json.dump(self.summary, f, indent=2)
        total = sum(self.summary["steps"].values())
        detection = f" · detection: {self.summary['detection']}" if "detection" in self.summary else ""
        self.say(f"\nRUN {self.run_id}: {verdict}{detection} · {total:.0f} s · summary in recordings/scenario_runs/")
        return code


def main(argv=None):
    p = argparse.ArgumentParser(description="Run a scenario (or a batch of them, in one boot) in a fresh lab VM and check it")
    p.add_argument("scenario", nargs="+", help="one scenario, or several to run one after another in ONE boot "
                                              "(faster; for development checks, not for the official experiment runs)")
    p.add_argument("--plan", action="store_true", help="only show what would happen")
    p.add_argument("--headless", action="store_true", help="no VM window")
    p.add_argument("--recordings", help="recordings folder (default: the project's recordings/)")
    p.add_argument("--keep-running", action="store_true", help="leave the VM on afterwards")
    # 1 vCPU by default: with 2, VirtualBox's slow mode froze the VM for 1.5-11 min in most boots and
    # once hung it in the firmware; with 1, 0 freezes in 5 boots and 3 of 3 S1 runs passed (2026-10-18)
    p.add_argument("--cpus", type=int, default=1, help="virtual CPUs for this boot (default 1; 0 = the snapshot's)")
    p.add_argument("--snapshot", default=SNAPSHOT, help=f"snapshot to restore (default {SNAPSHOT}; recorded in the run summary)")
    a = p.parse_args(argv)
    if a.plan:
        print(__doc__.split("Steps")[1].split("A summary")[0].strip())
        return 0
    if len(set(s.lower() for s in a.scenario)) != len(a.scenario):
        p.error("each scenario at most once per batch")
    target = a.scenario[0] if len(a.scenario) == 1 else a.scenario
    return Runner(target, recordings=a.recordings, headless=a.headless, keep_running=a.keep_running,
                  cpus=a.cpus or None, snapshot=a.snapshot).run()


if __name__ == "__main__":
    sys.exit(main())
