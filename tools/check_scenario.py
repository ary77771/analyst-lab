"""Observability check: does a scenario run's recording contain exactly what its true story says?

    python tools/check_scenario.py s1                 # newest recorded run of S1
    python tools/check_scenario.py s1 --run 2         # the 2nd newest
    python tools/check_scenario.py s1 --run-id <id>   # the run tools/run_in_vm.py started
    python tools/check_scenario.py b1 --run-id <id> --sheet <path>   # another answer sheet (blind runs)

Reads the scenario's answer sheet (scenarios/<s>/ground_truth.yaml), finds the run's time window
from the runner's record (recordings/vmruns/, sent by run_scenario.ps1 inside the VM), and checks
the VM recording (recordings/vm/) in that window:
  - the scenario's programs are anchored to their actual processes: exactly one start of the
    first program, and each later program started by an earlier one (by ProcessGuid), so a
    look-alike name or a process from another run can't stand in for them;
  - every step's evidence is present exactly once and belongs to those processes (Image ->
    ProcessGuid, ParentImage -> ParentProcessGuid; FILE_HASH -> its creator and its event 11;
    PORT_LISTEN_* -> process number + owner start time equal to the process's own event 1);
  - seconds_after: a step's record comes within [min, max] s after another step's record;
  - within_seconds: a step's N records all lie within that many seconds (a burst);
  - same_target_as_step: each record's TargetFilename is one that the given step recorded;
  - not_expected (sysmon_event or agent_type): none BEYOND what the steps explain, counting the
    scenario's processes, programs they start, and ports they own;
  - field rules: <Field>_endswith (file name), _contains (part), _suffix (ending), or equal;
  - a program that the scenario itself wrote to disk ran from exactly that file;
  - all Sysmon evidence is in the story's order, including the order inside a step (UtcTime);
  - nothing in not_expected was recorded for the scenario's programs or files.
The window is cut at neighbouring runs, so evidence can't be borrowed from another run.
Expectations come only from the answer sheet (rule 8: nothing hard-coded for our scenarios).
Prints counts and the scenario's own program names only. Exit 0 = PASS, 1 = FAIL.
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from urllib.parse import urlparse

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from engine.jsonl import iter_jsonl, recording_files  # noqa: E402
from engine.replay import parse_time  # noqa: E402

SLACK_BEFORE = timedelta(seconds=5)
SLACK_AFTER = timedelta(seconds=150)     # FILE_HASH may wait up to 120 s for the writer to close
NON_FIELD_KEYS = {"sysmon_event", "agent_type", "sha256_equals", "count", "interval_seconds", "spread_seconds_min",
                  "seconds_after", "within_seconds", "same_target_as_step"}
PORT_TYPES = ("PORT_LISTEN_START", "PORT_LISTEN_STOP")
# a port record's owner start time (psutil) vs the owner's Sysmon event 1 UtcTime: same clock,
# rounding only (engine/graph.py uses the same tolerance; kept separate on purpose)
START_MATCH = timedelta(seconds=1)
# Runs recorded before 2026-10-18 don't name the test server they used: it was always this one.
# Later runs carry it in their run record ("server"), so the lab may move it (it moved to 18765
# when another program took 8765).
LEGACY_SERVER = "http://10.0.2.2:8765"
# Every address the lab's test server has ever had (tools/test_server.ps1). A run record names its
# own server, so it must be one of these: a run pointed at a wrong server must not "agree with
# itself" (independent review 2026-10-18).
LAB_TEST_SERVERS = {("10.0.2.2", 8765), ("10.0.2.2", 18765)}


def run_server(run):
    """(ip, port) of the test server this run used; ValueError if it is not the lab's."""
    u = urlparse(run.get("server") or LEGACY_SERVER)
    server = (u.hostname, u.port)
    if server not in LAB_TEST_SERVERS:
        raise ValueError(f"this run used {run.get('server')}, which is not a lab test server address")
    return server


def fill(value, server):
    """The answer sheet names the lab's test server as {test_server.ip} / {test_server.port}."""
    if isinstance(value, dict):
        return {k: fill(v, server) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, server) for v in value]
    if isinstance(value, str):
        return value.replace("{test_server.ip}", str(server[0])).replace("{test_server.port}", str(server[1]))
    return value


def read_label(recordings, label):
    rows = []
    for path in recording_files(os.path.join(recordings, label)):
        rows.extend(iter_jsonl(path, {}))
    return rows


def all_runs(recordings):
    runs = [r for r in read_label(recordings, "vmruns") if r.get("type") == "SCENARIO_RUN"]
    return sorted(runs, key=lambda r: parse_time(r["start"]))


def sheet_path(scenario, sheet=None):
    """The answer sheet the checkers read: scenarios/<s>/ground_truth.yaml, or `sheet` when given
    (--sheet: a blind scenario's sheet, copied under recordings/blind/ only after its run).
    Shared by check_scenario, check_graph_scenario and check_alerts."""
    return sheet or os.path.join(PROJECT_ROOT, "scenarios", scenario.lower(), "ground_truth.yaml")


def find_run(recordings, scenario, nth=1, run_id=None):
    runs = [r for r in all_runs(recordings) if str(r.get("scenario", "")).upper() == scenario.upper()]
    if run_id is not None:                  # exactly the run the one-command runner started
        runs = [r for r in runs if r.get("run_id") == run_id]
        return runs[0] if len(runs) == 1 else None
    return runs[-nth] if len(runs) >= nth else None


class RunWindow(NamedTuple):
    """One run's evidence window in the recording (every checker cuts the same one)."""
    lo: datetime               # start - SLACK_BEFORE, but never before the previous run's end
    hi: datetime               # end + SLACK_AFTER, but never past the next run's start
    overlaps_previous: bool    # the previous run ended after this one started: evidence can't be separated


def run_window(recordings, run, runs=None):
    """The window of `run`: its start/end with the checkers' slack, cut at the neighbouring runs
    of ANY scenario so evidence can't be borrowed from another run. `runs` = all_runs(recordings)
    when the caller already has them. Shared by check_scenario, check_graph_scenario,
    check_alerts and the noise overlay (package J): the overlay's 0x store must hold exactly
    the rows the graph checker replays."""
    start, end = parse_time(run["start"]), parse_time(run["end"])
    others = [r for r in (runs if runs is not None else all_runs(recordings))
              if r is not run and r.get("start") != run["start"]]
    prev_end = max((parse_time(r["end"]) for r in others if parse_time(r["start"]) < start), default=None)
    next_start = min((parse_time(r["start"]) for r in others if parse_time(r["start"]) > start), default=None)
    lo = max(start - SLACK_BEFORE, prev_end) if prev_end else start - SLACK_BEFORE
    hi = min(end + SLACK_AFTER, next_start) if next_start else end + SLACK_AFTER
    return RunWindow(lo, hi, bool(prev_end and prev_end > start))


def base(path):
    """Lower-case file name after the last backslash ('' for None)."""
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def guid(value):
    return str(value or "").lower()


def sysmon_sha256(rec):
    for part in str((rec.get("data") or {}).get("Hashes", "")).split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].upper()
    return None


def utc(rec):
    data = rec.get("data") or {}
    t = data.get("UtcTime")
    if t:                                   # Sysmon's own clock, "YYYY-MM-DD HH:MM:SS.fff"
        return parse_time(t.replace(" ", "T") + "Z")
    return parse_time(rec["time"])


class Checker:
    def __init__(self, truth, window, server=None):
        self.truth, self.window = fill(truth, server or run_server({})), window
        self.names = {base(v): role for role, v in truth["programs"].items()}
        self.guid_of, self.image_of, self.problems = {}, {}, []
        self.start_of = {}           # role -> (process number, Sysmon start time) for port records

    # -- anchoring --------------------------------------------------------------------------
    def anchor(self):
        """Find each program's process: the first program exactly once; each later one started
        (ParentProcessGuid) by an earlier program's process."""
        starts = [r for r in self.window if r.get("source") == "sysmon" and r.get("event_id") == 1]
        for i, (role, exe) in enumerate(self.truth["programs"].items()):
            cands = [r for r in starts if base(r["data"].get("Image")) == base(exe)]
            if i > 0:
                parents = set(self.guid_of.values())
                cands = [r for r in cands if guid(r["data"].get("ParentProcessGuid")) in parents]
            if len(cands) != 1:
                self.problems.append(f"{exe}: {len(cands)} matching process start(s), expected exactly 1")
                continue
            self.guid_of[role] = guid(cands[0]["data"].get("ProcessGuid"))
            self.image_of[role] = str(cands[0]["data"].get("Image", ""))
            self.start_of[role] = (str(cands[0]["data"].get("ProcessId")), utc(cands[0]))
        return not self.problems

    # -- matching ---------------------------------------------------------------------------
    def port_owner_ok(self, data, role):
        """An agent port record has no Sysmon GUID: it belongs to the role's process only if its
        process number AND its owner's start time match that process's own event 1 (a process
        number alone is reused by Windows; number + start time is unique)."""
        if role not in self.start_of:
            return False
        pid, started = self.start_of[role]
        try:
            owner_start = parse_time(str(data.get("ProcessStartUtc")).replace(" ", "T") + "Z")
        except (TypeError, ValueError):
            return False
        return (owner_start is not None and str(data.get("ProcessId")) == pid
                and abs(owner_start - started) <= START_MATCH)

    def field_ok(self, data, key, want, port_record=False):
        if key in ("Image_endswith", "ParentImage_endswith"):
            field, gfield = key[: -len("_endswith")], ("ProcessGuid" if key == "Image_endswith" else "ParentProcessGuid")
            if base(data.get(field)) != base(want):
                return False
            role = self.names.get(base(want))
            if port_record and key == "Image_endswith":
                return role is None or self.port_owner_ok(data, role)
            return role is None or guid(data.get(gfield)) == self.guid_of.get(role)
        if key.endswith("_endswith"):
            return base(data.get(key[: -len("_endswith")])) == base(want)
        if key.endswith("_contains"):                # a part of the value (case-insensitive)
            return str(want).lower() in str(data.get(key[: -len("_contains")]) or "").lower()
        if key.endswith("_suffix"):                  # how the value ends (case-insensitive)
            return str(data.get(key[: -len("_suffix")]) or "").lower().endswith(str(want).lower())
        value = data.get(key)
        return value is not None and str(value).lower() == str(want).lower()

    def matches(self, rec, ev):
        if "sysmon_event" in ev and not (rec.get("source") == "sysmon" and rec.get("event_id") == ev["sysmon_event"]):
            return False
        if "agent_type" in ev and rec.get("type") != ev["agent_type"]:
            return False
        data = rec.get("data") or {}
        port_record = rec.get("type") in PORT_TYPES
        if not all(self.field_ok(data, k, v, port_record) for k, v in ev.items() if k not in NON_FIELD_KEYS):
            return False
        if rec.get("type") == "FILE_HASH":      # must belong to a scenario process's own event 11
            if guid(data.get("ProcessGuid")) not in self.guid_of.values():
                return False
            created = [r for r in self.window if r.get("source") == "sysmon" and r.get("event_id") == 11
                       and r.get("record_id") == data.get("ref_record_id")
                       and str(r["data"].get("TargetFilename", "")).lower() == str(data.get("TargetFilename", "")).lower()
                       and guid(r["data"].get("ProcessGuid")) == guid(data.get("ProcessGuid"))]
            if len(created) != 1:
                return False
        if "sha256_equals" in ev:                # the fingerprint equals what the scenario's process ran
            ran = {sysmon_sha256(r) for r in self.window if r.get("source") == "sysmon" and r.get("event_id") == 1
                   and guid(r["data"].get("ProcessGuid")) in self.guid_of.values()} - {None}
            if str(data.get("sha256", "")).upper() not in ran:
                return False
        return True

    def ours(self, rec):
        """Does this record belong to the scenario? By process identity always; by program or file
        name only for the scenario's OWN programs: a role listed in windows_programs (cmd.exe,
        powershell.exe) shares its name with Windows' and the runner's processes."""
        data = rec.get("data") or {}
        if rec.get("type") in PORT_TYPES:            # a port owned by a scenario process (PID + start)
            return any(self.port_owner_ok(data, role) for role in self.start_of)
        shared = {base(self.truth["programs"][r]) for r in self.truth.get("windows_programs", [])}
        own = set(self.names) - shared
        guids = set(self.guid_of.values())
        # a program STARTED by a scenario process is the scenario's doing too (review 2026-10-19:
        # an extra child of S4's PowerShell went unseen)
        return (guid(data.get("ProcessGuid")) in guids or guid(data.get("ParentProcessGuid")) in guids
                or base(data.get("Image")) in own or base(data.get("TargetFilename")) in own)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("scenario")
    p.add_argument("--run", type=int, default=1, help="1 = newest run, 2 = the one before, ...")
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    p.add_argument("--label", default="vm")
    p.add_argument("--run-id", help="check the run with this id (from tools/run_in_vm.py) instead of --run")
    p.add_argument("--sheet", help="answer sheet to check against instead of scenarios/<s>/ground_truth.yaml "
                                   "(a blind scenario's copy, made by tools/run_blind.py after its run)")
    a = p.parse_args(argv)

    with open(sheet_path(a.scenario, a.sheet), encoding="utf-8") as f:
        truth = yaml.safe_load(f)
    run = find_run(a.recordings, a.scenario, a.run, a.run_id)
    if run is None:
        which = f" with run id {a.run_id} (missing or recorded twice)" if a.run_id else ""
        print(f"No recorded run of {a.scenario.upper()}{which} (recordings/vmruns). Run it in the VM first.")
        return 1
    start, end = parse_time(run["start"]), parse_time(run["end"])
    age = (datetime.now(timezone.utc) - end).total_seconds() / 60
    print(f"Scenario {truth['scenario']} '{truth['title']}': run {run['start']} → {run['end']} "
          f"({age:,.0f} min ago), exit code {run['exit_code']}")

    ok = run["exit_code"] == 0
    # the window: this run only (cut at the neighbouring runs of any scenario)
    lo, hi, overlaps = run_window(a.recordings, run)
    if overlaps:
        ok = False
        print("  FAIL  this run overlaps the previous run; its evidence can't be separated")
    window = [r for r in read_label(a.recordings, a.label) if r.get("time") and lo <= parse_time(r["time"]) <= hi]
    print(f"{len(window)} records from '{a.label}' in this run's window\n")

    try:
        server = run_server(run)
    except ValueError as e:
        print(f"  FAIL  {e}\n\nRESULT: FAIL")
        return 1
    print(f"test server used by this run: {server[0]}:{server[1]}{'' if run.get('server') else ' (runs before 2026-10-18 did not record it)'}")
    truth = fill(truth, server)                  # the answer sheet with this run's test server
    c = Checker(truth, window, server)
    if not c.anchor():
        for pr in c.problems:
            print(f"  FAIL  {pr}")
        print("\nRESULT: FAIL")
        return 1
    print(f"  anchored: {', '.join(base(v) for v in truth['programs'].values())} (one process each, linked by ProcessGuid)")

    chain = []                                   # (step id, record) for the order check
    step_hits = {}                               # step id -> its records (first evidence item)
    step_hits_all = []                           # every step's matched records (for not_expected)
    step_targets = {}                            # step id -> all its records (same_target_as_step)
    for step in truth["steps"]:
        evidence = step["evidence"] if isinstance(step["evidence"], list) else [step["evidence"]]
        hits_all = [sorted((r for r in window if c.matches(r, ev)), key=utc) for ev in evidence]
        step_hits[step["id"]] = hits_all[0]
        step_hits_all.extend(hits_all)
        step_targets[step["id"]] = [r for h in hits_all for r in h]
        wanted = [ev.get("count", 1) for ev in evidence]          # "count": exactly N (default 1)
        passed = all(len(h) == n for h, n in zip(hits_all, wanted))
        notes = []
        for ev, h in zip(evidence, hits_all):    # "same_target_as_step": e.g. a deleted file must be
            ref_step = ev.get("same_target_as_step")    # one that step created (review 2026-10-19)
            if ref_step is None:
                continue
            made = {str((r.get("data") or {}).get("TargetFilename", "")).lower() for r in step_targets.get(ref_step, [])}
            strays = [r for r in h if str((r.get("data") or {}).get("TargetFilename", "")).lower() not in made]
            passed &= not strays
            notes.append(f"{len(h) - len(strays)} of {len(h)} are files step {ref_step} created")
        for ev, h in zip(evidence, hits_all):    # "within_seconds": all matches form one burst
            if ev.get("within_seconds") is not None and len(h) >= 2:
                span = (utc(h[-1]) - utc(h[0])).total_seconds()
                passed &= span <= ev["within_seconds"]
                notes.append(f"all within {span:.1f} s, at most {ev['within_seconds']} s allowed")
        for ev, h in zip(evidence, hits_all):    # "seconds_after": timing against an earlier step
            after = ev.get("seconds_after")
            if not after or not h:
                continue
            ref = step_hits.get(after["step"], [])
            if len(ref) != 1:
                passed = False
                notes.append(f"step {after['step']} has {len(ref)} record(s), so the timing can't be checked")
                continue
            secs = [(utc(r) - utc(ref[0])).total_seconds() for r in h]
            inside = all(after["min"] <= s <= after["max"] for s in secs)
            passed &= inside
            notes.append(f"{min(secs):.1f}-{max(secs):.1f} s after step {after['step']}, "
                         f"allowed {after['min']}-{after['max']} s")
        for ev, h, n in zip(evidence, hits_all, wanted):          # "interval_seconds": spacing of the N
            rng, spread = ev.get("interval_seconds"), ev.get("spread_seconds_min")
            if (rng or spread) and n < 2:
                passed = False                    # a spacing rule needs a count of 2 or more
                notes.append("answer sheet error: interval/spread rules need count >= 2")
            elif (rng or spread) and len(h) == n:
                gaps = [(utc(b) - utc(a)).total_seconds() for a, b in zip(h, h[1:])]
                if rng:
                    inside = all(rng["min"] <= g <= rng["max"] for g in gaps)
                    passed &= inside
                    notes.append(f"gaps {min(gaps):.1f}-{max(gaps):.1f} s, allowed {rng['min']}-{rng['max']} s")
                if spread:                        # the jitter variant must really vary (review 2026-10-19)
                    varied = max(gaps) - min(gaps) >= spread
                    passed &= varied
                    notes.append(f"spread {max(gaps) - min(gaps):.1f} s, at least {spread} s required")
        ok &= passed
        chain += [(step["id"], r) for h, n in zip(hits_all, wanted) if len(h) == n for r in h if r.get("source") == "sysmon"]
        counts = " + ".join(str(len(h)) for h in hits_all)
        expect = "exactly 1 each" if all(n == 1 for n in wanted) else "exactly " + " + ".join(str(n) for n in wanted)
        extra = f"; {' ; '.join(notes)}" if notes else ""
        print(f"  step {step['id']:>3}  {'PASS' if passed else 'FAIL'}  ({counts} matching, {expect} expected{extra})  {step['what']}")

    # a program the scenario wrote to disk must have run from exactly that file
    for role, exe in truth["programs"].items():
        made = [r for r in window if r.get("source") == "sysmon" and r.get("event_id") == 11
                and base(r["data"].get("TargetFilename")) == base(exe) and c.ours(r)]
        if made:
            same = all(str(r["data"]["TargetFilename"]).lower() == c.image_of[role].lower() for r in made)
            ok &= same
            print(f"  {'PASS' if same else 'FAIL'}  {base(exe)} ran from the file the scenario created")

    order_ok = all(utc(a2) >= utc(a1) for (_, a1), (_, a2) in zip(chain, chain[1:]))
    if not order_ok:
        for (s1, a1), (s2, a2) in zip(chain, chain[1:]):
            if utc(a2) < utc(a1):
                print(f"  ORDER: step {s2} evidence at {utc(a2).isoformat()} is before step {s1} evidence at {utc(a1).isoformat()}")
    ok &= order_ok
    print(f"  order by UtcTime ({len(chain)} Sysmon events, inside steps too): {'PASS' if order_ok else 'FAIL'}")

    # "not expected" means: none BEYOND what a step of the true story already explains
    explained = {id(r) for hits in step_hits_all for r in hits}
    for item in truth.get("not_expected", []):
        if "agent_type" in item:                 # e.g. any OTHER port the scenario's processes open
            bad = [r for r in window if r.get("type") == item["agent_type"] and c.ours(r) and id(r) not in explained]
            what = item["agent_type"]
        else:
            bad = [r for r in window if r.get("source") == "sysmon" and r.get("event_id") == item["sysmon_event"]
                   and c.ours(r) and id(r) not in explained]
            what = f"event {item['sysmon_event']}"
        ok &= not bad
        print(f"  absent  {'PASS' if not bad else 'FAIL'}  {what} for the scenario's programs/files: {len(bad)} ({item['why']})")

    contains = truth.get("payload_path_contains")
    if contains:
        # v3: the dropped program is the role named `payload`, or (a blind writer's sheet may name it
        # otherwise, e.g. `implant`) every program role whose `<role>_file` the expected graph names.
        # v2 assumed `payload` and crashed with KeyError on B3/B5's sheets.
        progs = truth.get("programs") or {}
        named = {str(x.get(k)) for x in ((truth.get("expected_graph") or {}).get("facts") or []) for k in ("from", "to")}
        roles = ["payload"] if "payload" in progs else sorted(r for r in progs if f"{r}_file" in named)
        if not roles:
            ok = False
            print(f"  payload written under {contains}: FAIL (the sheet names no payload program: a role "
                  "'payload', or a <role>_file in expected_graph)")
        for role in roles:
            payload = base(progs[role])
            made = [r for r in window if r.get("source") == "sysmon" and r.get("event_id") == 11
                    and base(r["data"].get("TargetFilename")) == payload and c.ours(r)]
            paths_ok = bool(made) and all(contains.lower() in str(r["data"]["TargetFilename"]).lower() for r in made)
            ok &= paths_ok
            print(f"  {role} written under {contains}: {'PASS' if paths_ok else 'FAIL'} ({len(made)} file event(s))")

    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
