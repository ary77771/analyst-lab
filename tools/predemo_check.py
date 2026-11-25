"""Pre-demo readiness check: is everything in place for the demo, right now? (night-tools, 2026-11-24)

    .venv\\Scripts\\python.exe tools\\predemo_check.py                      # this folder is the demo's folder
    .venv\\Scripts\\python.exe tools\\predemo_check.py --demo-folder <path>  # the folder demo\\start.ps1 ran from

Run it AFTER demo\\start.ps1, a few minutes before the audience arrives. One line per check, ✓ or ✗, and for
each ✗ a plain way to fix it. Exit code 0 = ready, 1 = not ready.

READ-ONLY: it never starts, stops or changes anything. It asks the dashboards, the receiver and the test server
over 127.0.0.1 (GET only), asks VirtualBox for the test machine's state (showvminfo / snapshot list), asks
Windows whether the laptop is on mains and whether a restart is pending (registry, read), and reads the
recorder's status file. Privacy rule 7: it prints yes/no, counts and ages only, never paths, names or addresses
from personal use.

The checks:
  1. the live dashboard answers on 8780 (live mode) and the replay dashboard on 8781 (replay mode)
  2. the replay on 8781 says its store is complete (GET /api/labs/state; an older build: /api/health quiet)
  3. the test server on 18765 is ours and hands out the SAME s1_payload.exe as the demo folder's
     scenarios\\www\\s1_payload.exe (SHA-256). On 2026-11-23 an old test-server window served another folder's
     build and S1's fingerprint check failed in front of the camera.
  4. the VM receiver on 8770 answers
  5. the test machine is switched off and the snapshot the demo restores ('lived-in') exists
  6. the laptop is on mains, and no Windows restart is pending
  7. the recorder's status file is fresh (written in the last minute) with 0 errors
It reuses demo/preflight.py's pieces (its VirtualBox calls, port check, mains check and snapshot name).
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))
import preflight  # noqa: E402  (demo/preflight.py: VM, SNAPSHOT, vbox, _on_mains)

LIVE, REPLAY, RECEIVER, TEST_SERVER = 8780, 8781, 8770, 18765
PAYLOAD = "s1_payload.exe"
STATUS_FRESH_S = 60                 # the agent writes its status file every few seconds
# Windows' own "a restart is pending" markers (read only): Windows Update's and the servicing stack's
REBOOT_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
               r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")

FIX = {
    "dash": "run demo\\start.ps1 from the demo folder (close old minimized dashboard windows first)",
    "replay": "wait a few seconds and run this again; if it stays, close the replay window and run demo\\start.ps1",
    "server": "close the old test-server window and run demo\\start.ps1 from the demo folder",
    "payload": "close the old test-server window (it serves another folder's build) and run demo\\start.ps1 from the demo folder",
    "no_payload": "build S1's programs into the demo folder's scenarios\\www (copy scenarios\\bin and scenarios\\www from wt\\v4)",
    "receiver": "run tools\\lab_servers.ps1 (or demo\\start.ps1) from the demo folder",
    "vm_on": "shut the test machine down: VBoxManage controlvm AnalystLab-Win11 shutdown",
    "vm_unknown": "open VirtualBox once to see whether AnalystLab-Win11 is there and switched off",
    "snapshot": "the demo restores the snapshot 'lived-in': ask PROOF before the demo, it must be made with the VM off",
    "mains": "plug the laptop in (on battery Windows dozes off sooner, and did on 2026-11-21)",
    "mains_unknown": "check the battery icon: the laptop should be plugged in",
    "reboot": "restart the laptop BEFORE the demo, then run demo\\start.ps1 again (a pending restart can start by itself)",
    "status_missing": "the recorder is not running: run tools\\verify_and_restart_agent.ps1 -RestartOnly (it asks for admin)",
    "status_old": "the recorder stopped writing: run tools\\verify_and_restart_agent.ps1 -RestartOnly (it asks for admin)",
    "status_errors": "look at recordings\\.state\\host\\agent.log, then run tools\\verify_and_restart_agent.ps1 -RestartOnly",
}


@dataclass
class Result:
    name: str
    ok: bool
    fix: str = ""
    detail: str = ""


# --- what the checks look at (each one replaceable in tests) --------------------------------------------------
class Probes:
    def get_json(self, url):
        with urllib.request.urlopen(url, timeout=4) as r:
            return json.loads(r.read().decode("utf-8"))

    def get_bytes(self, url):
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read()

    def file_bytes(self, path):
        with open(path, "rb") as f:
            return f.read()

    def exists(self, path):
        return os.path.isfile(path)

    def vbox(self, *args):
        return preflight.vbox(*args)

    def on_mains(self):
        return preflight._on_mains()

    def reboot_pending(self):
        try:
            import winreg
        except ImportError:
            return None
        for key in REBOOT_KEYS:
            try:
                winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key))
                return True
            except OSError:
                continue
        return False

    def now(self):
        return time.time()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _age_s(iso, now):
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now - t.timestamp()


# --- the checks -------------------------------------------------------------------------------------------------
def check_dashboards(p):
    out = []
    for name, port, want in (("the live dashboard", LIVE, "live"), ("the replay dashboard", REPLAY, "replay")):
        try:
            mode = p.get_json(f"http://127.0.0.1:{port}/api/mode").get("mode")
            out.append(Result(f"{name} answers on {port} in {want} mode", mode == want, "" if mode == want else FIX["dash"],
                              "" if mode == want else f"it says it is in {mode or 'no'} mode"))
        except Exception:
            out.append(Result(f"{name} answers on {port}", False, FIX["dash"], "nothing answers"))
    return out


def check_replay_complete(p):
    name = f"the replay on {REPLAY} says it is complete"
    try:
        st = p.get_json(f"http://127.0.0.1:{REPLAY}/api/labs/state").get("replay")
        if st is not None:
            done = bool(st.get("done"))
            return Result(name, done, "" if done else FIX["replay"],
                          f"{st.get('total')} records" + ("" if done else ", still filling its store"))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return Result(name, False, FIX["replay"], f"it answered HTTP {e.code}")
    except Exception:
        return Result(name, False, FIX["dash"], "nothing answers")
    # an older build without /api/labs/state: judged from its health (the alert is there and the feed is quiet)
    try:
        h = p.get_json(f"http://127.0.0.1:{REPLAY}/api/health")
    except Exception:
        return Result(name, False, FIX["dash"], "nothing answers")
    quiet = h.get("seconds") is not None and h.get("seconds") >= (h.get("quiet_after_s") or 90)
    ok = h.get("state") == "alert" and quiet
    return Result(name, ok, "" if ok else FIX["replay"],
                  f"{h.get('records')} records, judged from its health (this build has no replay state)")


def check_payload(p, demo_folder):
    name = f"the test server on {TEST_SERVER} hands out the demo folder's {PAYLOAD}"
    try:
        marker = p.get_bytes(f"http://127.0.0.1:{TEST_SERVER}/analystlab-test-server.txt").decode("utf-8", "replace")
    except Exception:
        return Result(name, False, FIX["server"], "nothing answers")
    if "analyst-lab test server" not in marker:
        return Result(name, False, FIX["server"], "the program on that port is not the lab's test server")
    local = os.path.join(demo_folder, "scenarios", "www", PAYLOAD)
    if not p.exists(local):
        return Result(name, False, FIX["no_payload"], f"the demo folder has no scenarios\\www\\{PAYLOAD}")
    try:
        served = _sha(p.get_bytes(f"http://127.0.0.1:{TEST_SERVER}/{PAYLOAD}"))
    except Exception:
        return Result(name, False, FIX["payload"], f"the server does not hand out {PAYLOAD}")
    mine = _sha(p.file_bytes(local))
    if served != mine:
        return Result(name, False, FIX["payload"], f"different files: served {served[:12]}…, demo folder {mine[:12]}…")
    return Result(name, True, "", f"same SHA-256 {mine[:12]}…")


def check_receiver(p):
    name = f"the VM receiver answers on {RECEIVER}"
    try:
        ok = bool(p.get_json(f"http://127.0.0.1:{RECEIVER}/health").get("ok"))
    except Exception:
        ok = False
    return Result(name, ok, "" if ok else FIX["receiver"], "" if ok else "no answer")


def check_vm(p):
    info = p.vbox("showvminfo", preflight.VM, "--machinereadable") or ""
    state = next((l.split("=", 1)[1].strip('"') for l in info.splitlines() if l.startswith("VMState=")), None)
    if state is None:
        off = Result("the test machine is switched off", False, FIX["vm_unknown"], "VirtualBox did not answer")
    else:
        off = Result("the test machine is switched off", state == "poweroff", "" if state == "poweroff" else FIX["vm_on"],
                     f"VirtualBox says: {state}")
    snaps = p.vbox("snapshot", preflight.VM, "list", "--machinereadable") or ""
    has = f'="{preflight.SNAPSHOT}"' in snaps
    return [off, Result(f"the snapshot the demo restores ('{preflight.SNAPSHOT}') exists", has, "" if has else FIX["snapshot"])]


def check_power(p):
    mains = p.on_mains()
    out = [Result("the laptop is on mains (plugged in)", mains is True,
                  "" if mains is True else FIX["mains"] if mains is False else FIX["mains_unknown"],
                  "" if mains is not None else "Windows did not say")]
    pending = p.reboot_pending()
    out.append(Result("no Windows restart is pending", pending is False, "" if pending is False else FIX["reboot"],
                      "" if pending is not None else "could not read the registry"))
    return out


def check_recorder(p, demo_folder):
    name = "the recorder is writing (status fresh, 0 errors)"
    path = os.path.join(demo_folder, "recordings", ".state", "host", "status.json")
    if not p.exists(path):
        return Result(name, False, FIX["status_missing"], "no status file")
    try:
        st = json.loads(p.file_bytes(path).decode("utf-8"))
    except (OSError, ValueError):
        return Result(name, False, FIX["status_missing"], "the status file could not be read")
    age = _age_s(st.get("updated"), p.now())
    errors = st.get("errors")
    if age is None or age > STATUS_FRESH_S:
        return Result(name, False, FIX["status_old"], "last written " + ("at an unknown time" if age is None else f"{int(age)} s ago"))
    if errors:
        return Result(name, False, FIX["status_errors"], f"{errors} error(s)")
    return Result(name, True, "", f"written {max(0, int(age))} s ago, 0 errors")


def run_checks(p, demo_folder):
    return (check_dashboards(p) + [check_replay_complete(p), check_payload(p, demo_folder), check_receiver(p)]
            + check_vm(p) + check_power(p) + [check_recorder(p, demo_folder)])


def report(results):
    """The printed lines and the exit code (0 = ready)."""
    bad = [r for r in results if not r.ok]
    lines = ["READY for the demo" if not bad else f"NOT READY: {len(bad)} of {len(results)} checks failed"]
    for r in results:
        lines.append(f"  {'✓' if r.ok else '✗'} {r.name}" + (f"  ({r.detail})" if r.detail else ""))
        if not r.ok and r.fix:
            lines.append(f"      fix: {r.fix}")
    return lines, (0 if not bad else 1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only pre-demo readiness check (exit 0 = ready, 1 = not ready)")
    ap.add_argument("--demo-folder", default=ROOT, help="the folder demo\\start.ps1 runs from (default: this one)")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    lines, code = report(run_checks(Probes(), os.path.abspath(a.demo_folder)))
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
