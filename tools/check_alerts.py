"""Detection check of one recorded VM run (integration review 2026-10-24: runs were checked for
what was RECORDED and what the GRAPH shows, never for what was DETECTED).

    python tools/check_alerts.py s1                 # newest S1 run
    python tools/check_alerts.py s1 --run-id <id>   # a given run (tools/run_in_vm.py uses this)

Replays the run's window of the VM recording (re-tagged like the live loop and engine/load.py)
into a fresh store, runs EVERY detector exactly as the live loop does (engine/score.py: Sigma,
own rules with the frozen learned-normal baselines, the check-in rhythm rule) and compares the
alerts with the answer sheet's machine-readable expectation, in one of two forms:
  - `alert_expected.check` (our own sheets): {rule_id, level, involves: <role>}: an alert of
    that rule AT that level whose evidence names the role's program (as the acting program, its
    parent or the file it wrote). DETECTED when every one is found.
  - `alert_expected.suspicious_steps` (blind round 2, v2 pre-registration: the writer names steps,
    never rules): a step is FLAGGED when a RAISED alert (at or above the frozen floor) cites, in
    its evidence, at least one of the records that check_scenario's Checker matches to that
    step's evidence (event level: the same program's other, innocent steps do not count).
    DETECTED when every suspicious step is flagged, MISSED otherwise. An empty list is an innocent
    scenario: CLEAN when no raised alert flags any step or names a scenario program, FALSE ALARM
    otherwise. Also counted: steps flagged at program level only (an alert naming the step's
    program; secondary), raised alerts on steps NOT marked suspicious, suspicious steps with no
    recorded evidence.
Also prints, as a measurement and never as a failure, the OTHER alerts raised (at or above the
frozen floor) inside the run window that name none of the scenario's programs: false alarms
during a run.

Exit codes: 0 = DETECTED, CLEAN or nothing expected; 1 = MISSED or FALSE ALARM; 2 = could not
check (no run, unreadable sheet, official-mode problems, programs not found). A miss is a RESULT,
not a broken run: tools/run_in_vm.py records it separately from the run's PASS/FAIL.
Prints rule ids, levels, roles and counts only (scenario programs are lab programs).
"""

import argparse
import ntpath
import os
import sys
import tempfile

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_scenario import Checker, base, find_run, run_server, run_window, sheet_path  # noqa: E402
from engine import config, detect, score  # noqa: E402
from engine.follow import follow_through  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402
from engine.replay import parse_time, read_recordings  # noqa: E402
from engine.store import EventStore  # noqa: E402

EVIDENCE_FIELDS = ("Image", "ParentImage", "TargetFilename")


def window(recordings, run):
    """The run's evidence window: its start/end with the checkers' slack, never overlapping the
    neighbouring runs: the one window every checker cuts (check_scenario.run_window)."""
    w = run_window(recordings, run)
    return w.lo, w.hi


def programs_named(con, alert):
    """Lower-case program/file names an alert's evidence events name."""
    names = set()
    cols = ", ".join(f"COALESCE({c}, '')" for c in EVIDENCE_FIELDS)
    for key in alert.evidence:
        row = con.execute(f"SELECT {cols} FROM events WHERE dedup_key = ?", (key,)).fetchone()
        if row:
            names |= {ntpath.basename(v).lower() for v in row if v}
    return names


def sheet_problems(truth):
    """Why a round-2 sheet cannot be scored as written ([] = fine): every step needs an id and
    evidence, and every suspicious step id must be one of the step ids (exactly, e.g. 4 not "4").
    Such a run is NOT CHECKED (listed, never translated into something the writer did not write)."""
    steps = truth.get("steps")
    if not isinstance(steps, list) or not steps:
        return ["the sheet has no steps"]
    problems = []
    ids = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or "id" not in step or not step.get("evidence"):
            problems.append(f"step {i + 1} has no id or no evidence")
        else:
            ids.append(step["id"])
    sus = (truth.get("alert_expected") or {}).get("suspicious_steps")
    if not isinstance(sus, list):
        problems.append("suspicious_steps is not a list")
    else:
        problems += [f"suspicious step {s!r} is not a step id" for s in sus if s not in ids]
    if not truth.get("programs"):
        problems.append("the sheet lists no programs")
    return problems


def step_records(truth, records, server):
    """(checker, {step id: [records]}): every record check_scenario's Checker matches to the step's
    evidence (all evidence items; the sheet filled with this run's test server), after anchoring
    the scenario's programs. A matched agent FILE_HASH record also brings the Sysmon event 11 it
    fingerprints (the record detectors cite; review 2026-11-13). Returns (checker, records per step,
    DIRECTLY matched dedup keys per step): a brought-in event 11 may flag its own step but never makes
    another step's record "shared" (advisor, 2026-11-13). (checker, None, None) when the programs
    cannot be anchored (absent, started more than once, or not started by an earlier program)."""
    c = Checker(truth, records, server)
    if not c.anchor():
        return c, None, None
    made = {}
    for r in records:
        if r.get("source") == "sysmon" and r.get("event_id") == 11:
            made.setdefault(r.get("record_id"), []).append(r)
    out, direct = {}, {}
    for step in c.truth.get("steps") or []:
        evidence = step["evidence"] if isinstance(step["evidence"], list) else [step["evidence"]]
        recs = [r for r in records if any(c.matches(r, ev) for ev in evidence)]
        direct[step["id"]] = {EventStore.dedup_key(r) for r in recs}
        for r in list(recs):
            if r.get("type") == "FILE_HASH":
                d = r.get("data") or {}
                recs += [m for m in made.get(d.get("ref_record_id"), [])
                         if str(m["data"].get("TargetFilename", "")).lower() == str(d.get("TargetFilename", "")).lower()
                         and str(m["data"].get("ProcessGuid", "")).strip("{}").lower() == str(d.get("ProcessGuid", "")).strip("{}").lower()
                         and m not in recs]
        out[step["id"]] = recs
    return c, out, direct


def check_steps(truth, alerts, con, records, server, say=print, detail=None, follow=None):
    """Blind round 2 (`alert_expected.suspicious_steps`): see the module docstring. Returns the same
    (verdict, found, missing, other) as check(); found/missing hold ({"rule_id": "step N", "level":
    "-", "involves": "step N"}, alerts) so time to detect works unchanged; `detail` (a dict) gets the
    per-step counts.

    Decided before any round-2 sheet was opened (review 2026-11-13):
      - a record that a step NOT marked suspicious also matches does not flag a suspicious step
        (two steps written with the same pattern cannot be told apart by their records; such
        shared records are counted per step, and a suspicious step whose records are ALL shared
        can never be flagged: MISSED, noted "ambiguous");
      - whether an alert involves the scenario is decided by process identity (check_scenario's
        Checker.ours: the scenario's processes and their children, its own program and file names;
        never Windows' shared names such as cmd.exe), not by program names alone."""
    detail = {} if detail is None else detail
    suspicious = list((truth.get("alert_expected") or {}).get("suspicious_steps") or [])
    floor = detect.LEVELS.index(config.min_level())
    raised = [a for a in alerts if detect.LEVELS.index(a.level) >= floor]
    if records is None:
        raise ValueError("suspicious_steps needs the run's records to find each step's events")
    bad = sheet_problems(truth)
    if bad:
        say("  alert  NOT CHECKED: the answer sheet cannot be scored as written: " + "; ".join(bad))
        detail.update(suspicious=suspicious, anchored=False, sheet_problems=bad)
        return "NOT CHECKED", [], [], []
    c, steps, direct = step_records(truth, records, server)
    by_key = {EventStore.dedup_key(r): r for r in records}

    def involves(a):
        return any(k in by_key and c.ours(by_key[k]) for k in a.evidence)
    if steps is None:
        say("  alert  NOT CHECKED: the scenario's programs cannot be anchored in the recording (absent, started more "
            "than once, or not started by an earlier program), so no step can be found")
        detail.update(suspicious=suspicious, anchored=False)
        progs = {base(n) for n in (truth.get("programs") or {}).values()}
        return "NOT CHECKED", [], [], [a for a in raised if not (programs_named(con, a) & progs)]
    other = [a for a in raised if not involves(a)]
    keys = {sid: {EventStore.dedup_key(r) for r in recs} for sid, recs in steps.items()}
    # records a step NOT marked suspicious matches DIRECTLY (one brought in through a fingerprint never excludes)
    innocent_keys = set().union(*(k for sid, k in direct.items() if sid not in suspicious)) if direct else set()
    own = {sid: keys[sid] - innocent_keys for sid in keys}            # records only suspicious steps match
    covers = {sid: [a for a in raised if set(a.evidence) & own[sid]] for sid in steps}
    step_names = {sid: {base((r.get("data") or {}).get("Image")) for r in recs} - {""} for sid, recs in steps.items()}
    by_program = {sid: [a for a in raised if programs_named(con, a) & step_names[sid]] for sid in steps}

    def entry(sid):
        return {"rule_id": f"step {sid}", "level": "-", "involves": f"step {sid}"}
    found = [(entry(s), covers.get(s, [])) for s in suspicious if covers.get(s)]
    missing = [(entry(s), []) for s in suspicious if not covers.get(s)]
    unrecorded = [s for s in suspicious if not steps.get(s)]
    # ambiguous = no record of its own that a detector could cite (agent FILE_HASH records are never cited)
    citable = {EventStore.dedup_key(r) for recs in steps.values() for r in recs if r.get("type") != "FILE_HASH"}
    ambiguous = [s for s in suspicious if keys.get(s) and not (own.get(s, set()) & citable)]
    sus_keys = set().union(*(own.get(s, set()) for s in suspicious)) if suspicious else set()
    on_other_steps = [a for a in raised if set(a.evidence) & innocent_keys and not set(a.evidence) & sus_keys]
    on_scenario = [a for a in raised if involves(a)]
    detail.update(anchored=True, suspicious=suspicious,
                  flagged=[s for s in suspicious if covers.get(s)],
                  flagged_by_program_only=[s for s in suspicious if not covers.get(s) and by_program.get(s)],
                  unrecorded=unrecorded, ambiguous=ambiguous,
                  shared_records={s: len(keys.get(s, set()) & innocent_keys) for s in suspicious},
                  alerts_on_other_steps=len(on_other_steps), alerts_on_scenario=len(on_scenario),
                  rules_per_step={s: sorted({f"{a.rule_id}[{a.level}]" for a in covers.get(s, [])}) for s in suspicious})
    # v4 F1, the INCIDENT column (never the verdict): a step also counts when a raised alert's
    # follow-through (engine/follow.py: what the flagged process and its descendants did next) holds
    # one of the step's own records. Symmetric: an innocent scenario whose records land in a raised
    # alert's follow-through counts against it. Same "shared with an innocent step" exclusion.
    if follow is not None:
        reach = {a.alert_id: set(a.evidence) | set(follow.get(a.alert_id, ())) for a in raised}
        inc_covers = {sid: [a for a in raised if reach[a.alert_id] & own[sid]] for sid in steps}
        inc_on_scenario = [a for a in raised if any(k in by_key and c.ours(by_key[k]) for k in reach[a.alert_id])]
        inc_flagged = [s for s in suspicious if inc_covers.get(s)]
        if not suspicious:
            inc_verdict = "FALSE ALARM" if inc_on_scenario else "CLEAN"
        else:
            inc_verdict = "DETECTED" if len(inc_flagged) == len(suspicious) else "MISSED"
        detail["incident"] = {"verdict": inc_verdict, "flagged": inc_flagged,
                              "flagged_by_follow_through_only": [s for s in inc_flagged if not covers.get(s)],
                              "alerts_on_scenario": len(inc_on_scenario),
                              # raised alerts that reach the scenario ONLY by following (their own evidence is
                              # elsewhere, e.g. an ancestor of the scenario): the "everything is one incident" check
                              "alerts_rooted_outside": sum(1 for a in inc_on_scenario if not involves(a)),
                              # the price of following: steps NOT marked suspicious held by follow-through alone
                              "innocent_steps_reached": sorted(sid for sid in steps if sid not in suspicious and any(
                                  set(follow.get(a.alert_id, ())) & keys[sid] and not set(a.evidence) & keys[sid]
                                  for a in raised))}
    for s in suspicious:
        hits = covers.get(s, [])
        note = (" (no recorded evidence for this step)" if s in unrecorded else
                " (ambiguous: every record of this step also matches a step not marked suspicious)" if s in ambiguous else
                " (an alert names its program, but cites none of this step's own events)" if by_program.get(s) and not hits else "")
        say(f"  step   {'FLAGGED' if hits else 'MISSED '}  suspicious step {s}: {len(hits)} raised alert(s)"
            f"{' ' + ', '.join(detail['rules_per_step'][s]) if hits else ''}{note}")
    say(f"  raised alerts on steps NOT marked suspicious: {len(on_other_steps)}")
    say(f"  other alerts raised in the run window (>= {config.min_level()}, not involving the scenario's processes): {len(other)}")
    if not suspicious:
        verdict = "FALSE ALARM" if on_scenario else "CLEAN"
        say(f"  innocent scenario (no suspicious step): {len(on_scenario)} raised alert(s) involving its processes")
    else:
        verdict = "DETECTED" if not missing else "MISSED"
    if follow is not None:
        inc = detail["incident"]
        say(f"  incident level (rule OR follow-through of a raised alert): {len(inc['flagged'])}/{len(suspicious)} "
            f"suspicious steps, {len(inc['flagged_by_follow_through_only'])} by follow-through only; raised alerts "
            f"reaching the scenario: {inc['alerts_on_scenario']} ({inc['alerts_rooted_outside']} rooted outside it); steps NOT "
            f"marked suspicious reached by following: "
            f"{len(inc['innocent_steps_reached'])} -> {inc['verdict']}")
    return verdict, found, missing, other


def check(truth, alerts, con, say=print, records=None, server=None, detail=None, follow=None):
    """(verdict, found, missing, other_raised) for one run's alerts against the sheet. A blind
    round-2 sheet (`alert_expected.suspicious_steps`) is judged by check_steps (needs `records`)."""
    if "suspicious_steps" in (truth.get("alert_expected") or {}):
        return check_steps(truth, alerts, con, records, server, say, detail, follow)
    expected = ((truth.get("alert_expected") or {}).get("check")) or []
    progs = {role: str(name).lower() for role, name in (truth.get("programs") or {}).items()}
    scenario_names = set(progs.values())
    found, missing = [], []
    for e in expected:
        want = progs.get(e["involves"])
        hits = [a for a in alerts if a.rule_id == e["rule_id"] and a.level == e["level"]
                and want in programs_named(con, a)]
        (found if hits else missing).append((e, hits))
    floor = detect.LEVELS.index(config.min_level())
    other = [a for a in alerts if detect.LEVELS.index(a.level) >= floor
             and not (programs_named(con, a) & scenario_names)]
    for e, hits in found:
        a = hits[0]
        say(f"  alert  PASS  {e['rule_id']} [{e['level']}] involving {e['involves']} "
            f"(at {a.time}{', ' + str(len(hits)) + ' alerts' if len(hits) > 1 else ''})")
    for e, _ in missing:
        near = sorted({f"{a.rule_id}[{a.level}]" for a in alerts if a.rule_id == e["rule_id"]})
        say(f"  alert  MISS  {e['rule_id']} [{e['level']}] involving {e['involves']}"
            f"{' (same rule at other levels or programs: ' + ', '.join(near) + ')' if near else ''}")
    by_rule = {}
    for a in other:
        by_rule[f"{a.rule_id}[{a.level}]"] = by_rule.get(f"{a.rule_id}[{a.level}]", 0) + 1
    say(f"  other alerts raised in the run window (>= {config.min_level()}, not involving the scenario's "
        f"programs): {len(other)}" + (f" {dict(sorted(by_rule.items()))}" if other else ""))
    if not expected:
        verdict = "NONE EXPECTED"
    else:
        verdict = "DETECTED" if not missing else "MISSED"
    return verdict, found, missing, other


def incident_view(con, alerts, say=print):
    """The follow-through for the incident column, or None (column not computed, said aloud): it must
    never cost the strict verdict (review 2026-11-15), and without a hub list an alert on the desktop
    shell would follow the whole machine, so then there is no column."""
    try:
        hubs = config.hubs(allow_missing=True)
        if not hubs:
            say("  incident level: not computed (no hub list on this machine)")
            return None
        return follow_through(con, alerts, hubs=hubs)
    except Exception as e:                       # noqa: BLE001
        say(f"  incident level: not computed ({type(e).__name__}: {str(e)[:100]})")
        return None


def main(argv=None):
    """Any unexpected error is NOT CHECKED (exit 2), never a miss (review 2026-11-13: an odd sheet
    used to exit 1, which the runner recorded as MISSED)."""
    try:
        return _main(argv)
    except Exception as e:                       # noqa: BLE001 - the outcome must be "not checked", whatever broke
        print(f"error while checking: {type(e).__name__}: {str(e)[:160]}\n\nDETECTION: NOT CHECKED")
        return 2


def _main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("scenario")
    p.add_argument("--run", type=int, default=1, help="1 = newest run, 2 = the one before, ...")
    p.add_argument("--run-id", help="the run with this id (from tools/run_in_vm.py)")
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    p.add_argument("--label", default="vm")
    p.add_argument("--sheet", help="answer sheet instead of scenarios/<s>/ground_truth.yaml (blind runs: "
                                   "tools/run_blind.py's copy, made after the run)")
    a = p.parse_args(argv)
    if config.is_official():
        problems = config.verify_official()
        if problems:
            for x in problems:
                print(f"  FAIL  official run: {x}")
            print("\nDETECTION: NOT CHECKED")
            return 2
    try:
        with open(sheet_path(a.scenario, a.sheet), encoding="utf-8") as f:
            truth = yaml.safe_load(f)
    except OSError as e:
        print(f"no answer sheet: {e}\n\nDETECTION: NOT CHECKED")
        return 2
    run = find_run(a.recordings, a.scenario, a.run, a.run_id)
    if run is None:
        print(f"No matching recorded run of {a.scenario.upper()} (recordings/vmruns).\n\nDETECTION: NOT CHECKED")
        return 2
    lo, hi = window(a.recordings, run)
    print(f"Scenario {truth['scenario']} '{truth['title']}': detection check of run {run['start']} -> {run['end']}"
          f"{' (run id ' + run['run_id'] + ')' if run.get('run_id') else ''}")
    # re-tag over the label's whole stream (a window alone loses process trees started before it)
    records = [r for r in read_recordings(recording_files(os.path.join(a.recordings, a.label)), retag=True)
               if r.get("time") and lo <= parse_time(r["time"]) <= hi]
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "run.db")
        st = EventStore(db)
        st.insert(records)
        st.close()
        con = detect.open_store(db)
        try:
            errors = []
            alerts = score.score(con, score.load_rules(), score.load_baseline(), errors=errors)
            print(f"replayed {len(records)} records; {len(alerts)} alerts at any level; detector errors: {len(errors)}")
            for rid, err in errors[:5]:
                print(f"  ERROR in {rid[:24]}: {err[:120]}")
            detail = {}
            verdict, *_ = check(truth, alerts, con, records=records, server=run_server(run), detail=detail,
                                follow=incident_view(con, alerts))
        finally:
            con.close()
    if errors:
        print("\nDETECTION: NOT CHECKED (a detector failed)")
        return 2
    print(f"\nDETECTION: {verdict}")
    if detail.get("incident"):                     # v4 F1: a second, labelled column; never the exit code
        print(f"INCIDENT LEVEL (with follow-through): {detail['incident']['verdict']}")
    return EXIT.get(verdict, 2)


EXIT = {"DETECTED": 0, "NONE EXPECTED": 0, "CLEAN": 0, "MISSED": 1, "FALSE ALARM": 1, "NOT CHECKED": 2}


if __name__ == "__main__":
    raise SystemExit(main())
