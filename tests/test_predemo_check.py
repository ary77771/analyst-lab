"""tools/predemo_check.py with fakes: a ready laptop, then each way it can be not ready (one at a time)."""

import io
import json
import os
import sys
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import predemo_check as P  # noqa: E402

FOLDER = os.path.join("X:", os.sep, "demo")
PAYLOAD_BYTES = b"MZ the harmless S1 payload"
NOW = 1_800_000_000.0
FRESH = "2027-01-15T08:00:00Z"                     # = NOW below


class Fake(P.Probes):
    """A laptop where everything is ready; a test changes one thing."""

    def __init__(self, **over):
        self.json = {
            "http://127.0.0.1:8780/api/mode": {"mode": "live"},
            "http://127.0.0.1:8781/api/mode": {"mode": "replay"},
            "http://127.0.0.1:8781/api/labs/state": {"replay": {"total": 85, "done": True}},
            "http://127.0.0.1:8781/api/health": {"state": "alert", "records": 85, "seconds": 300, "quiet_after_s": 90},
            "http://127.0.0.1:8770/health": {"ok": True},
        }
        self.bytes = {"http://127.0.0.1:18765/analystlab-test-server.txt": b"analyst-lab test server\n",
                      "http://127.0.0.1:18765/s1_payload.exe": PAYLOAD_BYTES}
        self.files = {os.path.join(FOLDER, "scenarios", "www", "s1_payload.exe"): PAYLOAD_BYTES,
                      os.path.join(FOLDER, "recordings", ".state", "host", "status.json"):
                          json.dumps({"updated": FRESH, "errors": 0, "recording_file": "never printed"}).encode()}
        self.vm_state, self.snapshots, self.mains, self.pending, self.clock = "poweroff", ["clean", "lived-in"], True, False, NOW
        self.calls = []
        for k, v in over.items():
            setattr(self, k, v)

    def get_json(self, url):
        self.calls.append(("GET", url))
        v = self.json.get(url)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise OSError("connection refused")
        return v

    def get_bytes(self, url):
        self.calls.append(("GET", url))
        if url not in self.bytes:
            raise OSError("connection refused")
        return self.bytes[url]

    def file_bytes(self, path):
        return self.files[path]

    def exists(self, path):
        return path in self.files

    def vbox(self, *args):
        self.calls.append(("vbox",) + args)
        if args[0] == "showvminfo":
            return "" if self.vm_state is None else f'name="AnalystLab-Win11"\nVMState="{self.vm_state}"\n'
        return "".join(f'SnapshotName{"-" + str(i) if i else ""}="{s}"\n' for i, s in enumerate(self.snapshots))

    def on_mains(self):
        return self.mains

    def reboot_pending(self):
        return self.pending

    def now(self):
        return self.clock


def run(fake):
    results = P.run_checks(fake, FOLDER)
    lines, code = P.report(results)
    return results, lines, code


def failed(results):
    return [r.name for r in results if not r.ok]


def test_a_ready_laptop_is_ready_with_every_check_ticked():
    results, lines, code = run(Fake())
    assert code == 0 and lines[0] == "READY for the demo" and not failed(results)
    assert len(results) == 10 and all(l.startswith("  ✓") for l in lines[1:])


def test_it_only_ever_reads():
    f = Fake()
    run(f)
    assert all(c[0] == "GET" or c[:2] in (("vbox", "showvminfo"), ("vbox", "snapshot")) for c in f.calls)
    assert all(c[3:] == ("list", "--machinereadable") for c in f.calls if c[:2] == ("vbox", "snapshot"))   # never take/restore


def test_another_folders_payload_on_the_test_server_is_caught_with_its_fix():
    # what broke S1 on 2026-11-23: an old test-server window served another folder's build
    f = Fake()
    f.bytes["http://127.0.0.1:18765/s1_payload.exe"] = b"MZ an older build"
    results, lines, code = run(f)
    assert code == 1 and failed(results) == ["the test server on 18765 hands out the demo folder's s1_payload.exe"]
    assert any("different files" in l for l in lines)
    assert any(l.strip().startswith("fix: close the old test-server window") for l in lines)


@pytest.mark.parametrize("change, broken", [
    (dict(vm_state="running"), "the test machine is switched off"),
    (dict(vm_state=None), "the test machine is switched off"),
    (dict(snapshots=["clean"]), "the snapshot the demo restores ('lived-in') exists"),
    (dict(mains=False), "the laptop is on mains (plugged in)"),
    (dict(mains=None), "the laptop is on mains (plugged in)"),
    (dict(pending=True), "no Windows restart is pending"),
    (dict(clock=NOW + 600), "the recorder is writing (status fresh, 0 errors)"),
])
def test_each_machine_problem_fails_only_its_own_check(change, broken):
    results, lines, code = run(Fake(**change))
    assert code == 1 and failed(results) == [broken]
    i = next(k for k, l in enumerate(lines) if broken in l)
    assert lines[i].lstrip().startswith("✗") and lines[i + 1].strip().startswith("fix: ")


def test_servers_and_dashboards_that_do_not_answer_or_answer_wrongly():
    f = Fake()
    del f.json["http://127.0.0.1:8780/api/mode"]
    f.json["http://127.0.0.1:8770/health"] = {"ok": False}
    f.bytes["http://127.0.0.1:18765/analystlab-test-server.txt"] = b"<html>someone else</html>"
    results, _, code = run(f)
    assert code == 1 and set(failed(results)) == {"the live dashboard answers on 8780",
                                                  "the test server on 18765 hands out the demo folder's s1_payload.exe",
                                                  "the VM receiver answers on 8770"}
    f2 = Fake()
    f2.json["http://127.0.0.1:8781/api/mode"] = {"mode": "live"}          # two live dashboards: the replay is missing
    assert failed(P.run_checks(f2, FOLDER)) == ["the replay dashboard answers on 8781 in replay mode"]


def test_a_replay_still_filling_is_not_ready_and_an_older_build_is_judged_by_its_health():
    f = Fake()
    f.json["http://127.0.0.1:8781/api/labs/state"] = {"replay": {"total": 85, "done": False}}
    assert failed(P.run_checks(f, FOLDER)) == ["the replay on 8781 says it is complete"]
    old = Fake()                                                          # no /api/labs/state in that build
    old.json["http://127.0.0.1:8781/api/labs/state"] = urllib.error.HTTPError("u", 404, "Not Found", {}, io.BytesIO(b""))
    assert not failed(P.run_checks(old, FOLDER))
    old.json["http://127.0.0.1:8781/api/health"] = {"state": "alert", "records": 60, "seconds": 3, "quiet_after_s": 90}
    assert failed(P.run_checks(old, FOLDER)) == ["the replay on 8781 says it is complete"]


def test_recorder_errors_and_a_missing_status_file():
    f = Fake()
    path = os.path.join(FOLDER, "recordings", ".state", "host", "status.json")
    f.files[path] = json.dumps({"updated": FRESH, "errors": 2}).encode()
    results, lines, _ = run(f)
    assert failed(results) == ["the recorder is writing (status fresh, 0 errors)"] and any("2 error(s)" in l for l in lines)
    del f.files[path]
    assert failed(P.run_checks(f, FOLDER)) == ["the recorder is writing (status fresh, 0 errors)"]


def test_nothing_personal_is_printed():
    f = Fake()
    f.clock = NOW + 600
    _, lines, _ = run(f)
    text = "\n".join(lines)
    assert "never printed" not in text and FOLDER not in text
