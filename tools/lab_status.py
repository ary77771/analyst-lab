"""One-command health check for the lab (no admin rights needed).

    python tools/lab_status.py              # host agent
    python tools/lab_status.py --label vm

Answers three questions, with counts and times only (privacy rule: no names, paths, domains):
1. Is the agent alive?  status.json age, session, errors, last error, files waiting for a hash.
2. Was anything lost?   Sysmon numbers events 1, 2, 3, ... in its log. If the recordings contain
   every record number from the first to the last, nothing was lost, across sleep, shutdown
   and agent restarts (an independent check of completeness without reading the Sysmon log).
   A VM snapshot restore rewinds numbers; continuity is checked per run of increasing numbers.
3. What happened?       Agent sessions (start, how many events each) and quiet periods with no
   events at all (sleep/shutdown), and whether recording continued afterwards.
Exit code 0 = healthy, 1 = something needs attention.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from engine.jsonl import iter_jsonl, recording_files  # noqa: E402
from engine.replay import parse_time  # noqa: E402


def record_id_gaps(records):
    """Missing Sysmon record numbers. Input: (record number, time) pairs in recording order.

    A re-delivery after an agent restart repeats a number with the SAME time (a duplicate).
    A VM snapshot restore (or a cleared log) reuses numbers with a DIFFERENT time: that starts
    a new run (A10). Gaps are computed per run, so reused numbers from one run can't hide a
    gap in another. Returns (missing ranges, number of runs)."""
    runs, seen, current = [], {}, set()
    for rid, t in records:
        if rid in seen and seen[rid] != t and rid in current:
            runs.append(current)                  # the same number came back with a new time
            current, seen = set(), {}
        seen[rid] = t
        current.add(rid)
    if current:
        runs.append(current)
    missing = []
    for run in runs:
        nums = sorted(run)
        missing += [(a + 1, b - 1) for a, b in zip(nums, nums[1:]) if b - a > 1]
    return missing, len(runs)


def is_boot_marker(r):
    """Sysmon's record of a Windows boot: smss.exe started by System (exactly one per boot)."""
    d = r.get("data") or {}
    return (r.get("event_id") == 1 and str(d.get("Image", "")).lower().endswith("\\smss.exe")
            and str(d.get("ParentImage", "")).lower() == "system")


def per_boot_gaps(records):
    """Missing Sysmon record numbers per BOOT, for a machine restored from snapshots (the VM).
    Input: (record number, time, session, boot marker?) in recording order. A restore may rewind
    OR jump the numbers (another snapshot), so numbers are only compared within one boot. A boot
    is a run of agent sessions: a session whose records contain the boot marker starts a new
    boot; a session without one (the agent restarted inside a running VM, e.g. after a crash or
    by SETUP) continues the previous boot, so a jump there still counts as loss (independent
    review 2026-10-18: one session = one agent process, not one boot). What a discarded VM state
    never sent can't be judged. Returns (missing ranges, number of boots)."""
    order, rows, booted = [], {}, set()
    for rid, t, s, marker in records:
        if s not in rows:
            order.append(s)
            rows[s] = []
        rows[s].append((rid, t))
        if marker:
            booted.add(s)
    boots = []
    for s in order:
        if s in booted or not boots:
            boots.append([])
        boots[-1].extend(rows[s])
    missing = []
    for b in boots:
        missing += record_id_gaps(b)[0]
    return missing, len(boots)

def quiet_periods(times, min_minutes=10):
    """Stretches of at least min_minutes with no events at all (sleep, shutdown)."""
    ts = sorted(times)
    out = []
    for a, b in zip(ts, ts[1:]):
        if (b - a).total_seconds() >= min_minutes * 60:
            out.append((a, b))
    return out


def sessions(records):
    """Agent sessions in order of first appearance: (session, first time, events)."""
    seen = {}
    for r in records:
        s = r.get("session")
        t = r.get("time")
        if not s or not t:
            continue
        if s not in seen:
            seen[s] = [parse_time(t), 0]
        seen[s][1] += 1
    return sorted(((s, v[0], v[1]) for s, v in seen.items()), key=lambda x: x[1])


def local(dt):
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--label", default="host")
    p.add_argument("--quiet-minutes", type=int, default=10)
    p.add_argument("--stale-minutes", type=int, default=30,
                   help="labels without a local status file (the VM): problem if nothing arrived for this long")
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    a = p.parse_args(argv)
    problems = []

    # 1. agent alive?
    print("== Agent ==")
    status_path = os.path.join(a.recordings, ".state", a.label, "status.json")
    try:
        with open(status_path, encoding="utf-8") as f:
            st = json.load(f)
        age = (datetime.now(timezone.utc) - parse_time(st["updated"])).total_seconds()
        print(f"  status updated {age:,.0f} s ago · session {st.get('session')} · errors {st.get('errors')}"
              f" · files waiting for a hash {st.get('files_waiting_for_hash', '-')}")
        print(f"  CPU {st.get('cpu_percent_of_machine')}% · memory {st.get('memory_mb')} MB")
        if st.get("last_error"):
            print("  last error: present (see agent.log)")
        if age > 120:
            problems.append(f"agent status is {age / 60:.0f} min old (agent not running?)")
        if st.get("errors"):
            problems.append(f"agent reports {st['errors']} error(s); see agent.log")
    except FileNotFoundError:
        st = None
        print("  no status file here")

    # read recordings once
    sysmon_ids, times, records = [], [], []
    bad = {}
    files = recording_files(os.path.join(a.recordings, a.label))
    for path in files:
        for r in iter_jsonl(path, bad):
            if r.get("source") == "sysmon" and r.get("record_id") is not None:
                sysmon_ids.append((r["record_id"], r.get("time"), r.get("session"), is_boot_marker(r)))
            if r.get("time"):
                times.append(parse_time(r["time"]))
            records.append(r)

    if st is None:
        if times:
            # an agent that sends over HTTP (the VM) keeps its status file on its own machine
            age = (datetime.now(timezone.utc) - max(times)).total_seconds()
            print(f"  status lives on the sending machine (e.g. the VM); newest record {age / 60:,.1f} min old")
            if age > a.stale_minutes * 60:
                problems.append(f"nothing received for {age / 60:,.0f} min (machine off, agent stopped, "
                                f"or the laptop's receiver not running?)")
        else:
            problems.append("no status.json and no recordings: the agent has never run for this label")

    # 2. anything lost?
    print("\n== Completeness (Sysmon record numbers) ==")
    # the laptop never restores snapshots: a jump between agent sessions there is real loss, so it
    # is checked across sessions; a snapshot-restored machine (the VM) is checked per boot
    per_boot = a.label != "host"
    if per_boot:
        missing, runs = per_boot_gaps(sysmon_ids)
        how = "checked per boot: a snapshot restore rewinds or jumps the numbers"
    else:
        missing, runs = record_id_gaps([(rid, t) for rid, t, _, _ in sysmon_ids])
        how = "a new run starts when a snapshot restore reuses numbers"
    if sysmon_ids:
        n_missing = sum(b - a + 1 for a, b in missing)
        nums = [rid for rid, _, _, _ in sysmon_ids]
        print(f"  {len({(rid, t) for rid, t, _, _ in sysmon_ids}):,} distinct Sysmon records, numbers {min(nums):,}–{max(nums):,}"
              f" · {'boots' if per_boot else 'runs'} {runs} ({how}) · missing {n_missing:,}")
        if n_missing:
            problems.append(f"{n_missing} Sysmon record number(s) missing in {len(missing)} range(s)")
            for lo, hi in missing[:5]:
                print(f"    missing {lo:,}–{hi:,}")
    else:
        print("  no Sysmon records yet")
    print(f"  files {len(files)} · damaged lines skipped {bad.get('bad_lines', 0)}"
          + (f" · DAMAGED COMPRESSED FILES {bad['bad_files']}" if bad.get("bad_files") else ""))
    if bad.get("bad_files"):
        problems.append(f"{bad['bad_files']} compressed recording file(s) damaged (read up to the damage)")

    # 3. what happened?
    print("\n== Agent sessions ==")
    for s, first, n in sessions(records):
        print(f"  {local(first)}  session {s}  {n:,} records")
    print(f"\n== Quiet periods ≥ {a.quiet_minutes} min (sleep/shutdown) ==")
    qp = quiet_periods(times, a.quiet_minutes)
    for start, end in qp:
        mins = (end - start).total_seconds() / 60
        print(f"  {local(start)} → {local(end)}  ({mins:,.0f} min), then recording continued")
    if not qp:
        print("  none")

    print("\nRESULT:", "HEALTHY" if not problems else "NEEDS ATTENTION")
    for pr in problems:
        print("  -", pr)
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
