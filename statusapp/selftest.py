"""Self-test (DESIGN 9.2): do four harmless things and check each one reached the recording.

  1. start and close an invisible helper program (cmd.exe /c exit 0, no window)
  2. create and delete a small temporary file (a .cmd name, a kind Sysmon is told to watch;
     it is never run)
  3. look up a made-up name ending in .invalid (a name reserved never to exist, RFC 2606)
  4. connect to the laptop itself (127.0.0.1, a port we open for a moment)

Then it reads the NEW part of the recording (from where it ended before the test) until all
four are found or the time is up. This tests the whole chain: Windows -> Sysmon -> recorder
-> file on disk. Neither part needs admin rights: the actions are ordinary, and the recording
is readable by its owner. (DESIGN 9.2 first planned to run it inside the recorder; this way
needs no message channel to the recorder and checks what is really on disk.)

The result is plain pass/fail per check with a next step, saved to <state>/selftest.json.
Only our own test names are compared; nothing else from the recording is kept or shown.
"""

import json
import os
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone

from agent.control import read_pause, utc_text
from agent.state import atomic_write_text

CREATE_NO_WINDOW = 0x08000000
TIMEOUT_SECONDS = 90

CHECKS = [
    ("program", "A program starting and closing", "process start + end"),
    ("file", "A file being created and deleted", "file created + deleted"),
    ("lookup", "A name lookup (DNS)", "DNS lookup"),
    ("connection", "A network connection", "connection to this laptop"),
]
NEXT_STEP = ("Restart the laptop and run the self-test again. If it still fails, send Yousif a "
             "screenshot of this window (it shows no personal information).")
FOREIGN_NOTE = ("Sysmon was already set up on this laptop before Analyst Lab, with its own settings, "
                "so some kinds of events may not be recorded. That's fine: please tell Yousif.")


def _offsets(folder: str) -> dict:
    """Current size of every plain recording file: the test reads only what comes after."""
    out = {}
    try:
        for name in os.listdir(folder):
            if name.endswith(".jsonl"):
                out[name] = os.path.getsize(os.path.join(folder, name))
    except FileNotFoundError:
        pass
    return out


class _NewLines:
    """Reads lines appended to the recording files after the test started."""

    def __init__(self, folder: str, start: dict):
        self.folder, self.pos = folder, dict(start)

    def read(self):
        for name in sorted(os.listdir(self.folder)) if os.path.isdir(self.folder) else []:
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(self.folder, name)
            at = self.pos.get(name, 0)
            try:
                with open(path, "rb") as f:
                    f.seek(at)
                    data = f.read()
            except OSError:
                continue
            end = data.rfind(b"\n") + 1
            self.pos[name] = at + end
            for line in data[:end].splitlines():
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def do_actions(tag: str, workdir: str = None) -> dict:
    """The four actions. Returns what to look for."""
    exp = {"tag": tag}
    # 1. invisible helper program
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    p = subprocess.Popen([cmd, "/c", "exit 0"], creationflags=CREATE_NO_WINDOW,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait(timeout=30)
    exp["pid"] = p.pid
    # 2. temporary file, created and deleted (never run)
    name = f"analystlab-selftest-{tag}.cmd"
    path = os.path.join(workdir or tempfile.gettempdir(), name)
    with open(path, "w", encoding="ascii") as f:
        f.write("rem Analyst Lab self-test file; safe to delete\r\n")
    time.sleep(0.5)
    os.remove(path)
    exp["file"] = name.lower()
    # 3. made-up name lookup: expected to fail; only the attempt matters
    exp["name"] = f"analystlab-selftest-{tag}.invalid"
    try:
        socket.getaddrinfo(exp["name"], None)
    except OSError:
        pass
    # 4. a connection to this laptop itself
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        exp["server_port"] = server.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", exp["server_port"]), timeout=5)
        exp["client_port"] = client.getsockname()[1]
        conn, _ = server.accept()
        conn.close()
        client.close()
    finally:
        server.close()
    return exp


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def match(record: dict, exp: dict, found: dict) -> None:
    """Mark what this record proves. Only our own test values are compared."""
    if record.get("source") != "sysmon" or record.get("paused"):
        return
    d = record.get("data") or {}
    eid = record.get("event_id")
    if eid == 1 and _num(d.get("ProcessId")) == exp["pid"] and str(d.get("Image", "")).lower().endswith("\\cmd.exe"):
        found["program_start"] = d.get("ProcessGuid") or True
    elif eid == 5 and (_num(d.get("ProcessId")) == exp["pid"] and str(d.get("Image", "")).lower().endswith("\\cmd.exe")):
        found["program_end"] = True
    elif eid in (11, 26) and str(d.get("TargetFilename", "")).lower().endswith("\\" + exp["file"]):
        found["file_created" if eid == 11 else "file_deleted"] = True
    elif eid == 22 and str(d.get("QueryName", "")).lower().rstrip(".") == exp["name"]:
        found["lookup"] = True
    elif eid == 3:
        ports = {_num(d.get("SourcePort")), _num(d.get("DestinationPort"))}
        if ports == {exp["client_port"], exp["server_port"]}:
            found["connection"] = True


def verdict(found: dict) -> list:
    """Per check: (key, label, ok, detail)."""
    parts = {"program": ("program_start", "program_end"), "file": ("file_created", "file_deleted"),
             "lookup": ("lookup",), "connection": ("connection",)}
    out = []
    for key, label, what in CHECKS:
        missing = [p.replace("_", " ") for p in parts[key] if not found.get(p)]
        out.append((key, label, not missing, "recorded" if not missing else "not recorded: " + ", ".join(missing)))
    return out


def run(recordings: str, label: str = "host", state_dir: str = None, timeout: float = TIMEOUT_SECONDS,
        poll: float = 1.0, actions=do_actions, now=None, foreign_sysmon: bool = False) -> dict:
    """Run the self-test and save the result. Returns the result dict. state_dir: where the
    pause file is and the result goes (the friend bundle: its control folder). foreign_sysmon:
    Sysmon was set up on this laptop by someone else, with settings that may not record every
    kind of event; a missing one is then reported as not covered rather than as a fault."""
    state_dir = state_dir or os.path.join(recordings, ".state", label)
    folder = os.path.join(recordings, label)
    now = now or (lambda: datetime.now(timezone.utc))
    started = now()
    pause = read_pause(state_dir)
    if pause and pause[1] > utc_text(started):
        result = {"time": utc_text(started), "passed": None, "paused": True,
                  "message": "Recording is paused, so the test can't see anything. Resume, then try again.",
                  "checks": []}
        return _save(state_dir, result)
    reader = _NewLines(folder, _offsets(folder))
    exp = actions(uuid.uuid4().hex[:10])
    found = {}
    deadline = time.monotonic() + timeout
    while True:
        for r in reader.read():
            match(r, exp, found)
        checks = verdict(found)
        if all(ok for _, _, ok, _ in checks) or time.monotonic() >= deadline:
            break
        time.sleep(poll)
    passed = all(ok for _, _, ok, _ in checks)
    result = {"time": utc_text(started), "passed": passed,
              "seconds": round((now() - started) / timedelta(seconds=1), 1),
              "checks": [{"key": k, "label": lb, "ok": ok, "detail": det} for k, lb, ok, det in checks],
              "message": "Everything is being recorded." if passed else (FOREIGN_NOTE if foreign_sysmon else NEXT_STEP)}
    if foreign_sysmon:
        for c in result["checks"]:
            if not c["ok"]:
                c["detail"] = "not covered by this laptop's own Sysmon settings"
    return _save(state_dir, result)


def _save(state_dir: str, result: dict) -> dict:
    path = os.path.join(state_dir, "selftest.json")
    try:
        with open(path, encoding="utf-8") as f:
            history = json.load(f)
    except (OSError, ValueError):
        history = {}
    runs = history.get("runs", 0) + (0 if result.get("paused") else 1)
    out = {"runs": runs, "last": result,
           "last_passed": history.get("last_passed") if result.get("paused") else result["passed"]}
    try:
        os.makedirs(state_dir, exist_ok=True)
        atomic_write_text(path, json.dumps(out))
    except OSError:
        pass
    return result


def history(state_dir: str) -> dict:
    try:
        with open(os.path.join(state_dir, "selftest.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
