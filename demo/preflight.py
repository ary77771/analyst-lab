"""Demo-morning check (debate 11): prints one plain READY / NOT READY line, then each check.

    .venv\\Scripts\\python.exe demo\\preflight.py            # everything
    .venv\\Scripts\\python.exe demo\\preflight.py --before   # only what must hold BEFORE demo\\start.ps1

Prints counts and yes/no only (privacy rule 7): never paths from personal use, names or addresses.
Nothing here changes anything; it only looks.
"""

import argparse
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

VBOX = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
VM, SNAPSHOT = "AnalystLab-Win11", "lived-in"
PORTS = {"VM receiver": 8770, "test server": 18765}
DASH = {"live dashboard": 8780, "replay dashboard": 8781}


def listening(port, host="127.0.0.1"):
    s = socket.socket()
    s.settimeout(1)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def get_json(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def check(name, ok, detail=""):
    return {"name": name, "ok": bool(ok), "detail": detail}


def vbox(*args):
    try:
        return subprocess.run([VBOX, *args], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def before_checks():
    out = [check("ANALYSTLAB_OFFICIAL is not set (the demo is never an official run)", not os.environ.get("ANALYSTLAB_OFFICIAL"))]
    busy = [p for p in DASH.values() if listening(p)]
    out.append(check("the dashboard ports 8780 and 8781 are free (no old dashboard still running)", not busy,
                     "" if not busy else "close the old minimized dashboard windows (or restart the laptop) first"))
    info = vbox("showvminfo", VM, "--machinereadable")
    out.append(check("the test machine exists and is switched off", 'VMState="poweroff"' in info,
                     "" if info else "VirtualBox did not answer"))
    snaps = vbox("snapshot", VM, "list", "--machinereadable")
    out.append(check(f"the prepared snapshot '{SNAPSHOT}' exists", f'="{SNAPSHOT}"' in snaps))
    rec = os.path.join(ROOT, "recordings")
    out.append(check("this folder sees the lab recordings (junction)", os.path.isdir(os.path.join(rec, "scenario_runs"))))
    built = [os.path.join(ROOT, "scenarios", p) for p in ("bin/s1_fetch.exe", "bin/s1_payload.exe", "www/s1_payload.exe")]
    out.append(check("S1's harmless test programs are built in this folder", all(os.path.exists(p) for p in built),
                     "" if all(os.path.exists(p) for p in built) else "copy scenarios\\bin and scenarios\\www from wt\\v4"))
    out.append(check("the dashboard is built",os.path.exists(os.path.join(ROOT, "engine", "dashboard", "static", "app", "index.html"))))
    try:
        import winreg
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
            pending = True
        except OSError:
            pending = False
        out.append(check("no Windows restart is pending", not pending))
    except ImportError:
        pass
    plan = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "run_in_vm.py"), "s1", "--plan", "--snapshot", SNAPSHOT],
                          capture_output=True, text=True, cwd=ROOT, timeout=120)
    out.append(check("a VM run of S1 can be planned (run_in_vm --plan)", plan.returncode == 0))
    return out


def after_checks():
    out = []
    for name, port in PORTS.items():
        out.append(check(f"{name} answers on its port", listening(port)))
    for name, port in DASH.items():
        try:
            mode = get_json(f"http://127.0.0.1:{port}/api/mode")
            want = "live" if port == 8780 else "replay"
            out.append(check(f"{name} answers, in {want} mode", mode.get("mode") == want))
        except Exception:
            out.append(check(f"{name} answers", False))
    try:
        h = get_json("http://127.0.0.1:8780/api/health")
        out.append(check("the live view starts with no alert raised", h.get("state") != "alert", f"state: {h.get('state')}"))
    except Exception:
        out.append(check("the live view reports its state", False))
    return out


STORE_WAIT_S = 20.0     # how long the launcher's fresh live store may take to appear with its table


def store_ready(store):
    """True once the store file exists AND has its events table (the live loop makes both when it starts)."""
    if not os.path.exists(store):
        return False
    try:
        con = sqlite3.connect("file:" + os.path.abspath(store).replace("\\", "/") + "?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        con.execute("SELECT 1 FROM events LIMIT 1")
        return True
    except sqlite3.Error:
        return False
    finally:
        con.close()


def wait_for_store(store, timeout=STORE_WAIT_S, every=0.5, sleep=time.sleep, clock=time.monotonic):
    """Wait until the store is ready, at most `timeout` seconds. demo/start.ps1 starts the live loop and asks
    this a moment later: on 2026-11-20 the check ran before the loop had made the store's table and said NOT
    READY, though 30 s later all was fine. A store that never gets its table still fails."""
    end = clock() + timeout
    while True:
        if store_ready(store):
            return True
        if clock() >= end:
            return False
        sleep(every)


def projector_ok(store, wait=0.0, **kw):
    """The store exists with its table (waiting up to `wait` seconds for it) and holds only the test machine's records."""
    from engine.dashboard.demo_mode import projector_problems
    return wait_for_store(store, timeout=wait, **kw) and not projector_problems(store)


KEEP_ON_MIN = 40        # a warm session is about 25 minutes, a one-boot run about 10: the laptop must not doze inside that


def power_notes(query=None, on_mains=None):
    """Plain notes (never failures) about the laptop dozing off during the demo. Read-only: nothing is
    changed here; the notes say what Yousif can do himself.
    Why: on 2026-11-21 the laptop, on battery and untouched for three hours, turned its screen off and went
    into Modern Standby; the test machine stood still for 581 seconds in the middle of a start.
    `query(sub, setting)` -> (mains seconds, battery seconds) or None; 0 = never. `on_mains()` -> True / False / None."""
    query, on_mains = query or _powercfg, on_mains or _on_mains
    notes = []
    mains = on_mains()
    if mains is False:
        notes.append("the laptop is running on battery: plug it in for the demo (on battery Windows dozes off sooner, and did on 2026-11-21)")
    for what, sub, setting, where in (("go to sleep", "SUB_SLEEP", "STANDBYIDLE", "Sleep after"),
                                      ("turn its screen off", "SUB_VIDEO", "VIDEOIDLE", "Turn off the display after")):
        got = query(sub, setting)
        if got is None:
            notes.append(f"could not read when the laptop would {what} when left alone: look at Settings > System > Power yourself")
            continue
        for seconds, power, look in ((got[0], "plugged in", True), (got[1], "on battery", mains is False)):
            if look and 0 < seconds < KEEP_ON_MIN * 60:
                notes.append(f"{power}, the laptop would {what} after {seconds // 60} min without a touch: for the demo set "
                             f"'{where}' ({power}) to {KEEP_ON_MIN} minutes or more, or Never (Settings > System > Power)")
    return notes


def _powercfg(sub, setting):
    """(mains, battery) seconds of one timer of the active power plan, from `powercfg /query` (read-only)."""
    import re
    try:
        out = subprocess.run(["powercfg", "/query", "SCHEME_CURRENT", sub, setting], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    ac, dc = re.search(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)", out), re.search(r"Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)", out)
    return (int(ac.group(1), 16), int(dc.group(1), 16)) if ac and dc else None


def _on_mains():
    try:
        import ctypes
        status = ctypes.create_string_buffer(12)
        if not ctypes.windll.kernel32.GetSystemPowerStatus(status):
            return None
        return {0: False, 1: True}.get(status.raw[0])
    except (AttributeError, OSError):
        return None


def summary(results):
    bad = [r for r in results if not r["ok"]]
    return ("READY" if not bad else f"NOT READY ({len(bad)} of {len(results)} checks failed)"), bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--before", action="store_true", help="only the checks that must hold before starting")
    ap.add_argument("--live-store", help="the live event store the launcher created (projector guard)")
    a = ap.parse_args(argv)
    results = before_checks() if a.before else before_checks()[:1] + after_checks()
    if a.live_store:
        ok = projector_ok(a.live_store, wait=STORE_WAIT_S)
        results.append(check("the live store holds only the test machine's records (projector guard)", ok,
                             "" if ok or store_ready(a.live_store) else f"the live store did not appear with its table within {STORE_WAIT_S:.0f} s"))
    line, _ = summary(results)
    print(line)
    for r in results:
        print(f"  {'ok ' if r['ok'] else 'NO '} {r['name']}" + (f"  ({r['detail']})" if r["detail"] else ""))
    for note in power_notes():                    # notes, not checks: READY / NOT READY does not depend on them
        print(f"  NOTE {note}")
    return 0 if line == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
