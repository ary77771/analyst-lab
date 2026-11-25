"""Shared definitions for every lab (night 2, 2026-11-24; PROOF: "one clock, one harness, one vocabulary").
Plain functions only; no router (the registry skips files starting with "_"). Nothing here reads a store.

1. when(row): ONE CLOCK
   Sysmon's own UtcTime when the row has it, else the record time, as ISO UTC in the store's spelling
   ("2026-10-31T17:47:34.6270000Z"). Why: the record time is when Windows WROTE the event, Sysmon's UtcTime is
   when it HAPPENED; network events are written up to ~1.2 s late, so ordering by the record time put a file
   write before the connection that fetched it.

2. is_harness(row) / harness_reason(row): OUR OWN TEST MACHINERY, never part of a story
   A row is test machinery when it IS one of these (a test program it starts is not: what a launcher starts
   is the test itself). Every marker is taken from the project's own files:

   - the lab's own tools, already tagged origin = "project" by the agent's tagger: programs in C:\\LabTools
     on the VM and their children (agent/enrich.py OriginTagger; engine/retag.py VM_TOOLS)
   - a command line under C:\\LabRunner\\ : the VM's logon starter is installed as
     C:\\LabRunner\\start_run_cd.ps1 (tools/vm/vm_guest_setup.ps1 $launcherDir, tools/vm/launcher_stub.ps1)
   - a command line running scenario_launcher.ps1: the run CD's launcher, run by the starter
     (tools/vm/launcher_stub.ps1 "& (Join-Path $root 'scenario_launcher.ps1')"); the warm launchers are copied
     to the CD under that name (demo/warm/warm_launcher.ps1, demo/warm/warm_launcher_signal.ps1)
   - a command line running warm_launcher*.ps1 (demo/warm/warm_launcher.ps1, warm_launcher_signal.ps1)
   - a command line running run_scenario.ps1: started as its own powershell.exe -File by the launcher
     (tools/vm/scenario_launcher.ps1 "& powershell.exe -NoProfile -File (Join-Path $Root 'run_scenario.ps1')")
   - a command line running a RUN_<scenario>.cmd starter (tools/vm/RUN_S1.cmd)
   - the Guest Additions' own programs VBoxControl.exe (demo/warm/warm_launcher_signal.ps1 $vboxControl) and
     VBoxService.exe (tools/vm/launcher_stub.ps1 "Get-Service -Name VBoxService")
   - a connection to the laptop's receiver, RECEIVER_HOST:RECEIVER_PORT = 10.0.2.2:8770: the launchers' and
     run_scenario.ps1's "flush" of run records (tools/vm/launcher_stub.ps1, demo/warm/warm_launcher.ps1,
     tools/vm/run_scenario.ps1 "Invoke-RestMethod -Uri http://${HostAddr}:8770/batch"); the host address is the
     VM setup's $HostAddr (tools/vm/vm_guest_setup.ps1), the port the receiver's own (engine/receiver.py
     --port default=8770)

   tests/labs/test_shared_defs.py checks every marker is still in the file named here.
   A lab hides harness rows by default, behind one switch: "show the test machinery".

3. WORDS: ONE COUNTING VOCABULARY
   "programs" = distinct program files; "program starts" = process-start records (Sysmon event 1);
   "records" = recorded events of any kind.
"""

import re
from datetime import datetime, timedelta, timezone

RECEIVER_HOST = "10.0.2.2"
RECEIVER_PORT = 8770
RUNNER_FOLDER = "c:\\labrunner\\"
HARNESS_SCRIPTS = ("start_run_cd.ps1", "scenario_launcher.ps1", "warm_launcher", "run_scenario.ps1")
HARNESS_STARTER = re.compile(r"\brun_[a-z0-9]+\.cmd\b", re.I)
HARNESS_PROGRAMS = ("vboxcontrol.exe", "vboxservice.exe")

# every marker and the project file it comes from (checked by tests/labs/test_shared_defs.py)
SOURCES = [
    ("C:\\LabRunner", "tools/vm/vm_guest_setup.ps1"),
    ("start_run_cd.ps1", "tools/vm/vm_guest_setup.ps1"),
    ("scenario_launcher.ps1", "tools/vm/launcher_stub.ps1"),
    ("scenario_launcher.ps1", "demo/warm/warm_launcher.ps1"),
    ("run_scenario.ps1", "tools/vm/scenario_launcher.ps1"),
    ("VBoxControl.exe", "demo/warm/warm_launcher_signal.ps1"),
    ("VBoxService", "tools/vm/launcher_stub.ps1"),
    (":8770/batch", "tools/vm/launcher_stub.ps1"),
    (":8770/batch", "tools/vm/run_scenario.ps1"),
    ("default=8770", "engine/receiver.py"),
    ("HostAddr = '10.0.2.2'", "tools/vm/vm_guest_setup.ps1"),
    ("C:\\LabTools", "engine/retag.py"),
]

WORDS = {
    "programs": "programs",                    # distinct program files
    "programs_long": "programs (different program files)",
    "program_starts": "program starts",        # process-start records (Sysmon event 1)
    "program_starts_long": "program starts (each time a program was started)",
    "records": "records",                      # recorded events of any kind
    "records_long": "records (everything the recorder wrote down)",
    "harness_switch": "show the test machinery",
    # ONE family of scope sentences for every lab opened with ?alert=<id> (critique 3). {title} = the alert's
    # title, {programs} = its programs' file names. A lab shows `limited` (+ `programs` when it also narrows to
    # the alert's programs) with the `show_all` switch; after the switch, `all` with `show_alert`.
    "scope": {
        "limited": "Showing what relates to this alert's run",
        "programs": "and its program{s} {programs}",
        "no_start": "No machine start was recorded before this alert, so its run can't be told apart: showing the "
                    "whole recording",
        "all": "Showing the whole recording",
        "show_all": "show the whole recording",
        "show_alert": "show only this alert's run",
        "missing": "This alert isn't in this recording, so the whole chosen time is shown",
        "forget": "forget the alert",
    },
    "harness_hidden": "{n} rows of the lab's own test machinery (its launcher, its report back to the laptop, "
                      "the VM's helper programs) are hidden.",
}

_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")


def _iso(text):
    """'2026-10-31 17:47:34.627' or '2026-10-31T17:47:34.6270622Z' -> '2026-10-31T17:47:34.6270622Z' (UTC)."""
    m = _ISO.match(str(text or "").strip())
    if not m:
        return None
    frac = (m.group(5) or "") + "0000000"
    return f"{m.group(1)}T{m.group(2)}:{m.group(3)}:{m.group(4)}.{frac[:7]}Z"


def when_text(text):
    """One time text in the shared spelling (ISO UTC, 7 fraction digits, Z), or the text unchanged if unreadable."""
    return _iso(text) or text


def when_sql(columns):
    """The one clock as a SQL expression, for the columns the store has, spelled EXACTLY as when() spells it:
    'YYYY-MM-DDTHH:MM:SS.fffffffZ' (7 fraction digits). The bare COALESCE(UtcTime, time) mixed two spellings -
    Sysmon's '2026-10-31 17:47:35.395' (a space) and the recorder's '2026-10-31T17:47:34.6270622Z' (a T) - and
    a space sorts before 'T', so a LATER Sysmon row sorted before an EARLIER recorder row on the same day
    (found by night-pivot, 2026-11-24). With one spelling, text order is time order: ORDER BY, MIN/MAX and
    comparisons are safe."""
    base = "COALESCE(UtcTime, time)" if "utctime" in columns else "time"
    frac = f"CASE WHEN instr({base}, '.') > 0 THEN rtrim(substr({base}, instr({base}, '.') + 1), 'Z') ELSE '' END"
    return (f"(CASE WHEN {base} IS NULL THEN NULL ELSE substr(replace({base}, ' ', 'T'), 1, 19) || '.' || "
            f"substr({frac} || '0000000', 1, 7) || 'Z' END)")


def when(row):
    """The one clock: Sysmon's UtcTime when present, else the record time; ISO UTC (store spelling), or None."""
    get = row.get if hasattr(row, "get") else (lambda k: row[k] if k in row.keys() else None)
    return _iso(get("UtcTime")) or _iso(get("time"))


def when_seconds(row):
    t = when(row)
    if not t:
        return None
    base = datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return (base + timedelta(microseconds=int(t[20:26]))).timestamp()


def _get(row, key):
    if hasattr(row, "get"):
        return row.get(key)
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


def harness_reason(row):
    """Why this row is the lab's own test machinery (a short plain phrase), or None when it isn't.
    Looks only at the row itself (its program, its command line, where it connected), never at its parents:
    what a launcher starts is the test, not the machinery."""
    if (_get(row, "origin") or "") == "project":
        return "the lab's own tools"
    image = str(_get(row, "Image") or "").lower()
    name = image.replace("/", "\\").rsplit("\\", 1)[-1]
    if name in HARNESS_PROGRAMS:
        return "VirtualBox's helper program in the test machine"
    cmd = str(_get(row, "CommandLine") or "").lower()
    if RUNNER_FOLDER in cmd or RUNNER_FOLDER in image:
        return "the test machine's run starter"
    if any(s in cmd for s in HARNESS_SCRIPTS) or HARNESS_STARTER.search(cmd):
        return "the test launcher"
    ip, port = str(_get(row, "DestinationIp") or ""), _get(row, "DestinationPort")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None
    if ip == RECEIVER_HOST and port == RECEIVER_PORT:
        return "the test machine reporting back to the laptop"
    return None


def is_harness(row) -> bool:
    return harness_reason(row) is not None


def harness_sql(columns):
    """(' AND NOT (...)', params): the same test as harness_reason() for a WHERE clause, on the columns the
    store has (`columns` = lower-case names). NULLs never match a marker (COALESCE), so a row without a
    command line (a connection, a file write) is judged on its other fields only."""
    parts, params = [], []
    if "origin" in columns:
        parts.append("COALESCE(origin, '') = 'project'")
    if "image" in columns:
        for p in HARNESS_PROGRAMS:
            parts.append("lower(COALESCE(Image, '')) LIKE ?")
            params.append("%\\" + p)
        parts.append("lower(COALESCE(Image, '')) LIKE ?")
        params.append("%" + RUNNER_FOLDER + "%")
    if "commandline" in columns:
        for s in (RUNNER_FOLDER,) + HARNESS_SCRIPTS:
            parts.append("lower(COALESCE(CommandLine, '')) LIKE ?")
            params.append("%" + s + "%")
        parts.append("lower(COALESCE(CommandLine, '')) LIKE ? ESCAPE '!'")     # a literal "_" in run_<x>.cmd
        params.append("%run!_%.cmd%")
    if "destinationip" in columns and "destinationport" in columns:
        parts.append("(COALESCE(DestinationIp, '') = ? AND COALESCE(DestinationPort, 0) = ?)")
        params += [RECEIVER_HOST, RECEIVER_PORT]
    if not parts:
        return "", []
    return " AND NOT (" + " OR ".join(parts) + ")", params


def harness_sql_literal(columns):
    """harness_sql() with its (constant, quoted) values written into the text: for callers that build a
    WHERE clause without parameters."""
    where, params = harness_sql(columns)
    for p in params:
        lit = str(p) if isinstance(p, int) else "'" + str(p).replace("'", "''") + "'"
        where = where.replace("?", lit, 1)
    return where
