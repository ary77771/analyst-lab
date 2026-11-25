"""tools/run_in_vm.py (the one-command scenario runner) against a fake VirtualBox: the happy path,
the pre-checks that must refuse before anything changes, and failures that must still shut the
VM down. Also the record tail (partial lines) and the barrier/run-record matching."""

import json
import os
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import run_in_vm  # noqa: E402

FAST = {k: 0.3 for k in run_in_vm.TIMEOUTS}


class FakeVBox:
    """Simulates the VM: start() 'runs' the launcher, writing what the real VM would send."""

    vm = "FakeVM"

    def __init__(self, recordings, state="poweroff", snapshots=("clean",), send_run=True,
                 barrier="ok", guest="running", shutdown_works=True, http_states=(), starter_states=()):
        self.recordings, self.vm_state, self._snapshots = recordings, state, list(snapshots)
        self.send_run, self.barrier, self.guest, self.shutdown_works = send_run, barrier, guest, shutdown_works
        self.http_states = list(http_states)
        self.starter_states = list(starter_states)
        self.calls, self.run_id = [], None

    def state(self):
        if isinstance(self.vm_state, Exception):
            raise self.vm_state
        return self.vm_state

    def unlocked(self):
        return True

    def snapshots(self):
        return self._snapshots

    def restore(self, name):
        self.calls.append(("restore", name))

    def insert_cd(self, path):
        self.calls.append(("insert_cd", os.path.basename(path)))

    def set_cpus(self, n):
        self.calls.append(("cpus", n))

    def start(self, headless=False):
        self.calls.append(("start", headless))
        self.vm_state = "running"
        for st in self.starter_states:       # the starter before it has read the CD (run id "-")
            append(self.recordings, "vmruns", {"type": "LAUNCHER_STATE", "run_id": "-", "state": st})
        for st in self.http_states:          # what the launcher posts to the receiver
            append(self.recordings, "vmruns", {"type": "LAUNCHER_STATE", "run_id": self.run_id, "state": st})
        if self.send_run:
            append(self.recordings, "vmruns", {"type": "SCENARIO_RUN", "scenario": "S1", "run_id": self.run_id,
                                               "start": "2026-10-18T10:00:00Z", "end": "2026-10-18T10:00:10Z", "exit_code": 0})
        if self.barrier:
            append(self.recordings, "vm", {"type": "FILE_HASH", "data": {
                "TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{self.run_id}-{self.barrier}.txt"}})

    def logged_in_since(self, after):
        return self.vm_state == "running"

    def guest_property(self, name):
        return f"{self.run_id} {self.guest}" if self.guest else None

    def request_shutdown(self):
        self.calls.append(("shutdown",))
        if self.shutdown_works:
            self.vm_state = "poweroff"


def append(recordings, label, rec):
    folder = os.path.join(recordings, label)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "2026-10-18.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def make(tmp_path, checks=None, **fake_kw):
    rec = str(tmp_path)
    # an older run already in the recordings must not count for this run
    append(rec, "vmruns", {"type": "SCENARIO_RUN", "scenario": "S1", "run_id": "old", "start": "x", "end": "y", "exit_code": 0})
    fake = FakeVBox(rec, **fake_kw)
    seen = checks if checks is not None else []
    r = run_in_vm.Runner("s1", vbox=fake, recordings=rec, servers=lambda: (0, "ok"), build_cd=lambda rid: (0, "ok"),
                         check=lambda s, rid: seen.append((s, rid)) or 0, timeouts=FAST, poll=0.01, say=lambda m: None)
    fake.run_id = r.run_id
    return r, fake, seen


def summary(tmp_path, run_id):
    with open(tmp_path / "scenario_runs" / f"{run_id}.json", encoding="utf-8") as f:
        return json.load(f)


def test_happy_path_restores_runs_checks_and_shuts_down(tmp_path):
    r, fake, seen = make(tmp_path)
    assert r.run() == 0
    assert [c[0] for c in fake.calls] == ["restore", "insert_cd", "start", "shutdown", "insert_cd"]
    assert fake.calls[-1] == ("insert_cd", "emptydrive")       # run CD ejected: no re-run on a later boot
    assert fake.calls[0] == ("restore", "clean") and fake.calls[1] == ("insert_cd", "analystlab-run.viso")
    assert seen == [("s1", r.run_id)]                  # checks exactly this run
    s = summary(tmp_path, r.run_id)
    assert s["result"] == "PASS" and s["barrier"] == "ok" and fake.vm_state == "poweroff"


def test_check_fail_gives_exit_1_and_still_shuts_down(tmp_path):
    r, fake, _ = make(tmp_path)
    r.check = lambda s, rid: 1
    assert r.run() == 1
    assert ("shutdown",) in fake.calls and summary(tmp_path, r.run_id)["result"] == "FAIL"


def test_running_vm_is_refused_before_anything_changes(tmp_path):
    r, fake, seen = make(tmp_path, state="running")
    assert r.run() == 2
    assert fake.calls == [] and seen == []             # no restore, no shutdown of a VM we didn't start


def test_missing_snapshot_or_servers_or_cd_refused(tmp_path):
    r, fake, _ = make(tmp_path, snapshots=())
    assert r.run() == 2 and fake.calls == []
    r, fake, _ = make(tmp_path)
    r.servers = lambda: (1, "VM receiver NOT RUNNING")
    assert r.run() == 2 and fake.calls == []
    r, fake, _ = make(tmp_path)
    r.build_cd = lambda rid: (1, "Missing: s1_fetch.exe")
    assert r.run() == 2 and fake.calls == []


def test_unknown_scenario_refused(tmp_path):
    r, fake, _ = make(tmp_path)
    r.scenario = "s99"
    assert r.run() == 2 and fake.calls == []


def test_no_run_record_times_out_and_shuts_down(tmp_path):
    r, fake, seen = make(tmp_path, send_run=False)
    assert r.run() == 3
    assert ("shutdown",) in fake.calls and seen == []


def test_older_runs_record_does_not_count(tmp_path):
    # the fake sends nothing; only the pre-existing "old" record and a record with another id exist
    r, fake, seen = make(tmp_path, send_run=False, barrier=None)
    append(str(tmp_path), "vmruns", {"type": "SCENARIO_RUN", "scenario": "S1", "run_id": "20261018-000000-abcd"})
    assert r.run() == 3 and seen == []


def test_missing_barrier_times_out_without_checking(tmp_path):
    r, fake, seen = make(tmp_path, barrier=None)
    assert r.run() == 3
    assert seen == [] and fake.vm_state == "poweroff"


def test_late_barrier_is_reported(tmp_path):
    r, fake, _ = make(tmp_path, barrier="late")
    assert r.run() == 0 and summary(tmp_path, r.run_id)["barrier"] == "late"


def test_launcher_failure_stops_early(tmp_path):
    r, fake, seen = make(tmp_path, send_run=False, guest="failed waiting (agent running: False)")
    assert r.run() == 3
    assert seen == [] and ("shutdown",) in fake.calls


def test_shutdown_failure_reported(tmp_path):
    r, fake, _ = make(tmp_path, shutdown_works=False)
    assert r.run() == 3
    assert "VM still running" in summary(tmp_path, r.run_id)["result"]


def test_keep_running_skips_shutdown(tmp_path):
    r, fake, _ = make(tmp_path)
    r.keep_running = True
    assert r.run() == 0 and fake.vm_state == "running" and ("shutdown",) not in fake.calls


def test_tail_skips_old_content_and_waits_for_complete_lines(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    f = folder / "a.jsonl"
    f.write_text('{"n": 1}\n', encoding="utf-8")
    t = run_in_vm.Tail(str(folder))
    assert t.new_records() == []                       # existing content is not "new"
    with open(f, "a", encoding="utf-8") as h:
        h.write('{"n": 2}\n{"n": 3')                    # second line half-written
    assert t.new_records() == [{"n": 2}]
    with open(f, "a", encoding="utf-8") as h:
        h.write('}\n')
    assert t.new_records() == [{"n": 3}]
    (folder / "b.jsonl").write_text('{"n": 4}\nnot json\n', encoding="utf-8")   # a new day's file
    assert t.new_records() == [{"n": 4}]


def test_barrier_and_run_record_matching():
    rid = "20261018-101500-0a1b"
    fh = lambda name, typ="FILE_HASH": {"type": typ, "data": {"TargetFilename": "C:\\AnalystLab\\scenarios\\_runner\\" + name}}
    assert run_in_vm.is_barrier(fh(f"barrier-{rid}-ok.txt"), rid) == "ok"
    assert run_in_vm.is_barrier(fh(f"barrier-{rid}-late.txt"), rid) == "late"
    assert run_in_vm.is_barrier(fh(f"barrier-{rid}-ok.txt", "SYSMON"), rid) is None      # only the fingerprint counts
    assert run_in_vm.is_barrier(fh("barrier-20261018-101500-ffff-ok.txt"), rid) is None   # another run
    assert run_in_vm.is_barrier(fh(f"xbarrier-{rid}-ok.txt"), rid) is None
    assert run_in_vm.is_run_record({"type": "SCENARIO_RUN", "run_id": rid}, rid)
    assert not run_in_vm.is_run_record({"type": "SCENARIO_RUN"}, rid)


def test_run_id_and_vbox_parsing():
    rid = run_in_vm.new_run_id(datetime(2026, 10, 18, 10, 15, 0, tzinfo=timezone.utc))
    assert run_in_vm.RUN_ID.fullmatch(rid) and rid.startswith("20261018-101500-")
    t = run_in_vm.parse_vbox_time("2026-10-18T10:15:00.123456789Z")
    assert t == datetime(2026, 10, 18, 10, 15, 0, 123456, tzinfo=timezone.utc)
    info = 'name="x"\nVMState="poweroff"\nVMStateChangeTime="2026"\n'
    assert run_in_vm.machinereadable(info, "VMState") == "poweroff"
    assert run_in_vm.machinereadable(info, "SessionState") is None


def test_silent_launcher_fails_early_with_a_hint(tmp_path):
    msgs = []
    r, fake, seen = make(tmp_path, guest=None, send_run=False, barrier=None)   # a silent launcher delivers nothing
    r.say = msgs.append
    assert r.run() == 3 and seen == [] and ("shutdown",) in fake.calls
    assert any("was 'clean' taken after the new SETUP" in m for m in msgs)


def test_vboxmanage_failing_in_precheck_is_not_started(tmp_path):
    r, fake, _ = make(tmp_path, state=run_in_vm.StepFailed("VBoxManage showvminfo failed"))
    assert r.run() == 2 and fake.calls == []


def test_paused_or_stuck_vm_gets_a_shutdown_request(tmp_path):
    r, fake, _ = make(tmp_path)
    fake.vm_state = "paused"
    r.shutdown()
    assert fake.calls[0] == ("shutdown",) and fake.vm_state == "poweroff"
    r, fake, _ = make(tmp_path, shutdown_works=False)
    fake.vm_state = "gurumeditation"
    try:
        r.shutdown()
        raise AssertionError("a VM that stays on must be reported")
    except run_in_vm.StepFailed:
        pass


def test_unexpected_error_or_ctrl_c_still_shuts_down_and_writes_summary(tmp_path):
    for exc, verdict in ((ValueError("bug"), "error"), (KeyboardInterrupt(), "vm step failed")):
        r, fake, _ = make(tmp_path)
        def boom(s, rid, exc=exc):
            raise exc
        r.check = boom
        assert r.run() == 3
        assert ("shutdown",) in fake.calls and fake.vm_state == "poweroff"
        assert summary(tmp_path, r.run_id)["result"] == verdict


def test_cpus_override_applied_after_restore(tmp_path):
    r, fake, _ = make(tmp_path)
    r.cpus = 1
    assert r.run() == 0
    assert [c[0] for c in fake.calls][:3] == ["restore", "cpus", "insert_cd"] and ("cpus", 1) in fake.calls
    r, fake, _ = make(tmp_path)
    assert r.run() == 0 and not any(c[0] == "cpus" for c in fake.calls)     # default: snapshot's count

def test_progress_records_from_the_receiver_are_enough(tmp_path):
    # no VBoxControl in the VM (no guest property): the launcher's posted states still count
    msgs = []
    r, fake, seen = make(tmp_path, guest=None, http_states=["starter: found run CD at D:\\", "found-cd s1", "running (calm)"])
    r.say = msgs.append
    assert r.run() == 0 and seen == [("s1", r.run_id)]
    assert "    VM: running (calm)" in msgs


def test_starter_failure_posted_to_the_receiver_stops_early(tmp_path):
    r, fake, seen = make(tmp_path, guest=None, send_run=False, http_states=["starter: failed error: boom"])
    assert r.run() == 3 and seen == [] and ("shutdown",) in fake.calls


def test_another_runs_progress_is_ignored(tmp_path):
    r, fake, seen = make(tmp_path, guest=None, send_run=False, barrier=None, http_states=["running"])
    fake.run_id = "20261018-000000-abcd"        # the VM posts progress for ANOTHER run, during this one
    msgs = []
    r.say = msgs.append
    assert r.run() == 3 and seen == []          # silent as far as this run is concerned
    assert not any("VM: running" in m for m in msgs)

def test_starter_that_finds_no_run_cd_stops_the_run_early(tmp_path):
    msgs = []
    r, fake, seen = make(tmp_path, guest=None, send_run=False, barrier=None,
                         starter_states=["starter: started, looking for a run CD", "starter: no run CD, nothing to do"])
    r.say = msgs.append
    assert r.run() == 3 and seen == [] and ("shutdown",) in fake.calls
    assert any("found no run CD" in m for m in msgs)


def test_starter_failing_its_vm_check_is_shown_and_stops_the_run(tmp_path):
    r, fake, seen = make(tmp_path, guest=None, send_run=False, barrier=None,
                         starter_states=["starter: failed not-the-lab-vm (no VBoxService)"])
    assert r.run() == 3 and seen == []


def test_command_line_defaults_to_one_cpu(monkeypatch):
    got = {}

    class Spy:
        def __init__(self, scenario, **kw):
            got.update(kw)

        def run(self):
            return 0
    monkeypatch.setattr(run_in_vm, "Runner", Spy)
    assert run_in_vm.main(["s1"]) == 0 and got["cpus"] == 1
    assert run_in_vm.main(["s1", "--cpus", "0"]) == 0 and got["cpus"] is None      # 0 = the snapshot's count


def test_default_check_needs_both_checks_to_pass(monkeypatch):
    results = iter([0, 1])
    monkeypatch.setattr(run_in_vm.subprocess, "run", lambda *a, **k: type("P", (), {"returncode": next(results)})())
    assert run_in_vm.default_check("s1", "20261018-000000-abcd") == 1        # graph check failed

# -- batch: several scenarios in one boot (2026-10-20) --------------------------------------------
class BatchFake(FakeVBox):
    """start() 'runs' every item of the batch: a run record and a barrier each (barriers may arrive
    together; a failing item can stop the launcher)."""

    def __init__(self, recordings, items=(), fail_at=None, **kw):
        super().__init__(recordings, **kw)
        self.items, self.fail_at = items, fail_at

    def start(self, headless=False):
        self.calls.append(("start", headless))
        self.vm_state = "running"
        for n, it in enumerate(self.items):
            append(self.recordings, "vmruns", {"type": "LAUNCHER_STATE", "run_id": it["run_id"], "state": "launcher-started"})
            if n == self.fail_at:
                append(self.recordings, "vmruns", {"type": "LAUNCHER_STATE", "run_id": it["run_id"], "state": "failed run_scenario exit 1"})
                return
            append(self.recordings, "vmruns", {"type": "SCENARIO_RUN", "scenario": it["scenario"].upper(), "run_id": it["run_id"],
                                               "start": "x", "end": "y", "exit_code": 0})
        for it in self.items:            # all barriers in one go: none may be lost
            append(self.recordings, "vm", {"type": "FILE_HASH", "data": {
                "TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{it['run_id']}-ok.txt"}})

    def guest_property(self, name):
        return None


def make_batch(tmp_path, scenarios, check=None, **kw):
    rec = str(tmp_path)
    seen = []
    r = run_in_vm.Runner(scenarios, vbox=None, recordings=rec, servers=lambda: (0, "ok"), build_cd=lambda rid: (0, "ok"),
                         check=check or (lambda s, rid: seen.append((s, rid)) or 0), timeouts=FAST, poll=0.01, say=lambda m: None)
    r.vbox = BatchFake(rec, items=r.items, **kw)
    return r, seen


def test_a_batch_runs_every_scenario_in_one_boot_and_checks_each(tmp_path):
    r, seen = make_batch(tmp_path, ["s4", "s5", "s2"])
    assert r.run() == 0
    assert [c[0] for c in r.vbox.calls].count("start") == 1 and [c[0] for c in r.vbox.calls].count("restore") == 1
    assert seen == [(i["scenario"], i["run_id"]) for i in r.items] and len({rid for _, rid in seen}) == 3
    s = summary(tmp_path, r.run_id)
    assert [b["result"] for b in s["batch"]] == ["PASS", "PASS", "PASS"]
    assert r.batch_note().endswith(":calm") and ":fast," in r.batch_note()        # s4/s5 fast, s2 calm


def test_one_failing_check_in_a_batch_fails_the_batch_but_the_others_still_run(tmp_path):
    r, _ = make_batch(tmp_path, ["s4", "s5"], check=lambda s, rid: 1 if s == "s4" else 0)
    assert r.run() == 1
    s = summary(tmp_path, r.run_id)
    assert s["result"] == "FAIL (S4)" and [b["result"] for b in s["batch"]] == ["FAIL", "PASS"]


def test_a_launcher_failure_mid_batch_stops_and_shuts_down(tmp_path):
    r, seen = make_batch(tmp_path, ["s4", "s5"], fail_at=1)
    assert r.run() == 3 and ("shutdown",) in r.vbox.calls
    s = summary(tmp_path, r.run_id)
    assert s["result"] == "vm step failed" and s["batch"][1].get("result") is None      # S5 never ran


def test_main_refuses_a_scenario_twice_in_one_batch(capsys):
    import pytest
    with pytest.raises(SystemExit):
        run_in_vm.main(["s4", "s4"])

# -- review 2026-10-20 ------------------------------------------------------------------------------
def test_batch_checks_wait_until_every_run_record_is_in(tmp_path):
    # a run's check window ends where the NEXT run starts: checking before that record is in let
    # S2J's program into S2's window
    state = {}
    def check(s, rid):
        state.setdefault("records_at_first_check", len(r._run_recs))
        return 0
    r, _ = make_batch(tmp_path, ["s2", "s2j", "s4"], check=check)
    msgs = []
    r.say = msgs.append
    assert r.run() == 0 and state["records_at_first_check"] == 3
    collects = [i for i, m in enumerate(msgs) if m.startswith("--> 3.")]
    checks = [i for i, m in enumerate(msgs) if m.startswith("--> 4.")]
    assert len(collects) == 3 and len(checks) == 3 and max(collects) < min(checks)   # all collected first


def test_a_finished_run_is_still_checked_when_a_later_one_fails(tmp_path):
    seen = []
    r, _ = make_batch(tmp_path, ["s4", "s5"], fail_at=1, check=lambda s, rid: seen.append(s) or 0)
    r.vbox.items = r.items
    # the first run's record and barrier arrive before the second one's failure
    def start(headless=False, fake=r.vbox):
        fake.calls.append(("start", headless)); fake.vm_state = "running"
        a, b = r.items
        append(str(tmp_path), "vmruns", {"type": "LAUNCHER_STATE", "run_id": a["run_id"], "state": "launcher-started"})
        append(str(tmp_path), "vmruns", {"type": "SCENARIO_RUN", "scenario": "S4", "run_id": a["run_id"], "start": "x", "end": "y", "exit_code": 0})
        append(str(tmp_path), "vm", {"type": "FILE_HASH", "data": {"TargetFilename": rf"C:\AnalystLab\scenarios\_runner\barrier-{a['run_id']}-ok.txt"}})
        append(str(tmp_path), "vmruns", {"type": "LAUNCHER_STATE", "run_id": b["run_id"], "state": "failed run_scenario exit 1"})
    r.vbox.start = start
    assert r.run() == 3 and seen == ["s4"]
    s = summary(tmp_path, r.run_id)
    assert [b.get("result") for b in s["batch"]] == ["PASS", None]


def test_a_single_run_cd_has_no_batch_line(tmp_path):
    calls = []
    r = run_in_vm.Runner("s4", vbox=None, recordings=str(tmp_path))
    run_in_vm.powershell, saved = (lambda *a: calls.append(a) or (0, "")), run_in_vm.powershell
    try:
        r.build_cd(r.run_id)
    finally:
        run_in_vm.powershell = saved
    assert "-Batch" not in calls[0]                       # official single runs keep the calm-down wait


def test_transient_vboxmanage_errors_are_retried():
    import run_in_vm as r
    assert r.transient("VBoxManage.exe: error: Failed to get a console object from the direct session (VBOX_E_INVALID_OBJECT_STATE)")
    assert r.transient("error: The machine 'x' is already locked for a session")
    assert not r.transient("error: Could not find a registered machine named 'x'")

def test_detection_is_recorded_apart_from_pass_fail(tmp_path):
    # integration review 2026-10-24: a run records what the detectors raised; a miss is a result
    r, _ = make_batch(tmp_path, ["s4", "s5"])
    r.detect_check = lambda s, rid: "MISSED" if s == "s4" else "DETECTED"
    assert r.run() == 0                                       # both runs PASS: a miss is not a failure
    assert [i["detection"] for i in r.items] == ["MISSED", "DETECTED"]
    assert r.summary["detection"] == "MISSED" and r.summary["result"] == "PASS"


# -- the snapshot option (blind round 4 runs on 'lived-in', docs/plans/lived-in-vm.md; 2026-11-17) --------

def test_another_snapshot_is_restored_and_recorded(tmp_path):
    rec = str(tmp_path)
    fake = FakeVBox(rec, snapshots=("clean", "lived-in"))
    r = run_in_vm.Runner("s1", vbox=fake, recordings=rec, servers=lambda: (0, "ok"), build_cd=lambda rid: (0, "ok"),
                         check=lambda s, rid: 0, timeouts=FAST, poll=0.01, say=lambda m: None, snapshot="lived-in")
    fake.run_id = r.run_id
    assert r.run() == 0
    assert fake.calls[0] == ("restore", "lived-in") and ("restore", "clean") not in fake.calls
    assert summary(tmp_path, r.run_id)["snapshot"] == "lived-in"


def test_a_missing_chosen_snapshot_is_refused(tmp_path):
    rec = str(tmp_path)
    fake = FakeVBox(rec, snapshots=("clean",))
    r = run_in_vm.Runner("s1", vbox=fake, recordings=rec, servers=lambda: (0, "ok"), build_cd=lambda rid: (0, "ok"),
                         check=lambda s, rid: 0, timeouts=FAST, poll=0.01, say=lambda m: None, snapshot="lived-in")
    assert r.run() == 2 and fake.calls == []                                   # never falls back to 'clean'


def test_the_default_snapshot_is_clean_and_recorded(tmp_path):
    r, fake, _ = make(tmp_path)
    assert r.run() == 0 and summary(tmp_path, r.run_id)["snapshot"] == "clean"


def test_command_line_passes_the_snapshot(monkeypatch):
    got = {}

    class Spy:
        def __init__(self, scenario, **kw):
            got.update(kw)

        def run(self):
            return 0
    monkeypatch.setattr(run_in_vm, "Runner", Spy)
    assert run_in_vm.main(["s1"]) == 0 and got["snapshot"] == "clean"
    assert run_in_vm.main(["s1", "--snapshot", "lived-in"]) == 0 and got["snapshot"] == "lived-in"