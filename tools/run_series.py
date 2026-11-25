"""Many single clean-boot VM runs one after another (package R, for the official experiment runs
and long practice series), e.g. overnight:

    python tools/run_series.py s1 s2 s2j s3 s4 s5 --repeats 5 --label practice
    python tools/run_series.py s1 s5 --repeats 2 --label practice --dry-run     # only show the order

Each run is ONE scenario in ONE fresh boot (`tools/run_in_vm.py <scenario>`, restore `clean`
-> boot -> run -> check -> shutdown), never a batch: official runs must not share a boot.
  - The order is shuffled with a recorded seed (so time of night or VM warm-up can't line up
    with one scenario), and the same seed gives the same order again.
  - A failed run (scenario check FAIL, exit 1) is recorded and the series goes on.
  - A run that couldn't start or whose VM step failed (exit 2 / 3) is recorded too; after
    `--stop-after` such failures IN A ROW the series stops (the VM or the laptop servers are
    broken: going on would only pile up failures).
  - `--label official` refuses to start unless the CURRENT freeze tag exists (`freeze-v2`,
    engine/evaluation.py; fair-test rule 2: nothing is evaluated before the freeze; official
    recordings start only after it), and the series file records it ("freeze"), so v1 and v2
    runs are never pooled.
  - A BLIND scenario is an item `blind:<folder>` (e.g. blind:C:\\Users\\<you>\\Documents\\AnalystLab-blind\\b1):
    it runs with tools/run_blind.py (same options, this series' --label), is shown by its id (B1).

Writes recordings/series/<series id>.json (git-ignored): seed, order, and per run the scenario,
run id, exit code, result and minutes. Prints only scenario names, results and times.
Keep the laptop awake and plugged in (Windows sleep would stop the VM).
"""

import argparse
import glob
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from keep_awake import keep_awake  # noqa: E402
from engine import evaluation  # noqa: E402

RESULTS ={0: "PASS", 1: "FAIL", 2: "NOT STARTED", 3: "VM STEP FAILED"}


BLIND = "blind:"


def is_blind(item):
    return item.lower().startswith(BLIND)


def plan(scenarios, repeats, seed):
    order = [s if is_blind(s) else s.lower() for s in scenarios for _ in range(repeats)]
    random.Random(seed).shuffle(order)
    return order


def name(item):
    """How a series item is shown and counted: S1, or a blind folder's id from its scenario.json
    (B1; never anything else from the blind folder)."""
    if not is_blind(item):
        return item.upper()
    from run_blind import read_id
    return read_id(item[len(BLIND):]) or "BLIND?"


def item_cmd(runner_cmd, item, label):
    """The command for one series item: `runner_cmd + [scenario]`, or for `blind:<folder>` the same
    options for tools/run_blind.py (with this series' label) and the folder."""
    if not is_blind(item):
        return runner_cmd + [item]
    cmd = [os.path.join(os.path.dirname(c), "run_blind.py") if os.path.basename(c) == "run_in_vm.py" else c
           for c in runner_cmd]
    return cmd + ["--label", label, item[len(BLIND):]]


def official_problems(root=PROJECT_ROOT):
    """Why official runs may not start ([] = go): the CURRENT freeze tag (freeze-v2) must exist and
    the code must be exactly the frozen code (engine/evaluation.py code_problems)."""
    return evaluation.code_problems(evaluation.FREEZE_TAG, root)


def has_freeze_tag(root=PROJECT_ROOT):
    """The CURRENT evaluation's freeze tag exists and the code equals it."""
    return not official_problems(root)


def _detection(summary_path):
    """The run's detection outcome from its summary (tools/run_in_vm.py), or None."""
    try:
        with open(summary_path, encoding="utf-8") as f:
            return json.load(f).get("detection")
    except (OSError, ValueError):
        return None


def _new_summaries(folder, before):
    return sorted(set(glob.glob(os.path.join(folder, "*.json"))) - before)


def run_series(order, label, seed, runner_cmd, recordings, stop_after=2, pause=20.0, say=print, sleep=time.sleep,
               env=None):
    series_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    runs_folder = os.path.join(recordings, "scenario_runs")
    os.makedirs(runs_folder, exist_ok=True)
    out_folder = os.path.join(recordings, "series")
    os.makedirs(out_folder, exist_ok=True)
    summary = {"series": series_id, "label": label, "seed": seed, "order": order, "runs": [],
               "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if label == "official":
        summary["freeze"] = evaluation.FREEZE_TAG    # which evaluation these runs belong to (none = v1)
        summary["code"] = evaluation.code_state()
    path = os.path.join(out_folder, f"{series_id}.json")
    # written BEFORE the first run (review 2026-11-13): a crash during run 1 must still leave the
    # series (its start, so the run falls inside an official period and is never practice data)
    _save(path, summary)
    broken_in_row = 0
    for n, item in enumerate(order, 1):
        scenario = name(item)
        before = set(glob.glob(os.path.join(runs_folder, "*.json")))
        say(f"[{n}/{len(order)}] {scenario.upper()} ...")
        t0 = time.monotonic()
        code = subprocess.run(item_cmd(runner_cmd, item, label), env=env).returncode
        minutes = round((time.monotonic() - t0) / 60, 1)
        new = _new_summaries(runs_folder, before)
        run_id = os.path.splitext(os.path.basename(new[-1]))[0] if new else None
        result = RESULTS.get(code, f"exit {code}")
        detection = _detection(new[-1]) if new else None
        summary["runs"].append({"n": n, "scenario": scenario.upper(), "run_id": run_id, "exit_code": code,
                                "result": result, "detection": detection, "minutes": minutes,
                                **({"blind": item[len(BLIND):]} if is_blind(item) else {})})
        _save(path, summary)
        say(f"[{n}/{len(order)}] {scenario.upper()}: {result}, detection {detection or 'not checked'} ({minutes} min)")
        # v3: an entry that left no run summary could not run, whatever its exit code (2026-11-13: a
        # crash before the VM step exited 1, like a scenario FAIL, so three entries burned in a minute)
        broken_in_row = broken_in_row + 1 if (code in (2, 3) or run_id is None) else 0
        if broken_in_row >= stop_after:
            summary["stopped"] = f"{broken_in_row} runs in a row could not run (exit 2/3): VM or servers broken"
            say(f"STOPPING: {summary['stopped']}")
            break
        if n < len(order):
            sleep(pause)                       # let VirtualBox release the VM before the next restore
    summary["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _save(path, summary)
    counts = {}
    for r in summary["runs"]:
        counts.setdefault(r["scenario"], {}).setdefault(r["result"], 0)
        counts[r["scenario"]][r["result"]] += 1
        if r.get("detection"):
            counts[r["scenario"]].setdefault(r["detection"], 0)
            counts[r["scenario"]][r["detection"]] += 1
    say("\n" + "\n".join(f"  {s:>4}: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())) for s, c in sorted(counts.items())))
    say(f"series {series_id}: {len(summary['runs'])} of {len(order)} runs · {path}")
    return summary


def _save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Many single clean-boot VM runs in a shuffled, recorded order")
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--label", choices=["practice", "official"], required=True)
    ap.add_argument("--seed", type=int, help="shuffle seed (default: from the clock, recorded)")
    ap.add_argument("--stop-after", type=int, default=2, help="stop after this many runs in a row that could not run")
    ap.add_argument("--pause", type=float, default=20.0, help="seconds between runs")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="only print the order")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    a = ap.parse_args(argv)
    if a.repeats < 1:
        ap.error("--repeats must be at least 1")
    seed = a.seed if a.seed is not None else int(time.time())
    order = plan(a.scenarios, a.repeats, seed)
    print(f"{a.label} series: {len(order)} single-boot runs, seed {seed}: {' '.join(name(s) for s in order)}")
    print(f"expected time: about {len(order) * 16 / 60:.1f} h (~16 min per run)")
    if a.dry_run:
        return 0
    if a.label == "official" and not has_freeze_tag():
        print(f"Refusing: official runs need the git tag {evaluation.FREEZE_TAG} and the code exactly as frozen (fair-test rule 2).")
        for p in official_problems():
            print(f"  {p}")
        return 2
    # -u: the run's progress shows in the log as it happens (not only when the run ends)
    cmd = [sys.executable, "-u", os.path.join(PROJECT_ROOT, "tools", "run_in_vm.py"), "--recordings", a.recordings] + \
          (["--headless"] if a.headless else [])
    # official runs: every checker verifies the frozen files (engine/config.verify_official)
    # v3: children print progress lines with non-ASCII characters; redirected to a file, Windows' default
    # code page cannot write them (2026-11-13: UnicodeEncodeError before any VM step). Always UTF-8.
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if a.label == "official":
        env["ANALYSTLAB_OFFICIAL"] = "1"
    with keep_awake():      # the laptop idle-sleeps after 20 min on AC (2026-10-30): a night batch would stop
        s = run_series(order, a.label, seed, cmd, a.recordings, a.stop_after, a.pause, env=env)
    return 0 if all(r["exit_code"] == 0 for r in s["runs"]) and len(s["runs"]) == len(order) else 1


if __name__ == "__main__":
    sys.exit(main())
