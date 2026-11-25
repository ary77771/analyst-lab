"""Build a noise-overlay store for one recorded VM practice run (package J part 1; engine/overlay.py,
docs/plans/package-j-design.md section 1).

    python tools/noise_overlay.py s1 --volume 1 --seed 1                 # newest S1 run
    python tools/noise_overlay.py s1 --run-id <id> --volume 5 --seed 2 --no-graft

The store = the run's window exactly as tools/check_graph_scenario.py replays it (0x) plus
`--volume` seeded, time-shifted slices of real laptop activity from the dev snapshot, re-hosted
under disjoint identities. Check it with
    python tools/check_graph_scenario.py s1 --run-id <id> --store <the .db>

Output: <recordings>/scratch/overlay/<scenario>-<run id>-<volume>x-s<seed>[-nograft].db, never
anywhere else (it holds laptop names: privacy rule 7). Prints counts only.
Refuses: a failed or overlapping run, a laptop database that is not the dev snapshot or whose
cutoff is later than the frozen one, and an output path outside the overlay folder.
Modes (package J part 2, docs/plans/package-j2-prereg.md): a PRACTICE run (not in an official
series) is dev data and is overlaid only outside official mode; an OFFICIAL run (a run of a series
labelled official) is TEST data and is overlaid only with ANALYSTLAB_OFFICIAL=1 after
engine.config.verify_official() passes (experiment J6 on the official runs). The noise itself always
comes from the laptop DEV snapshot.
"""

import argparse
import glob
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_graph_scenario import window_records  # noqa: E402
from check_scenario import find_run, run_window  # noqa: E402
from engine import config, evaluation, overlay  # noqa: E402

OVERLAY_DIR = ("scratch", "overlay")
DEFAULT_LAPTOP = ("scratch", "dev", "dev-laptop.db")


def official_series(recordings, version=None):
    """Every official series (recordings/series/*.json with label "official"), as
    [{"series", "started", "finished", "version", "runs": [the series' run entries]}]; with
    `version` ("v1" / "v2", engine/evaluation.py) only that evaluation's series (a series file
    without a "freeze" field is v1). An unreadable series file, or one with an unknown freeze tag,
    RAISES (review 2026-10-30: skipping it would turn its runs into practice runs)."""
    out = []
    for path in sorted(glob.glob(os.path.join(recordings, "series", "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            raise ValueError(f"series file {os.path.basename(path)} cannot be read ({e}): its runs' label is unknown")
        if str(doc.get("label", "")).lower() == "official":
            v = evaluation.version_of(doc, when=doc.get("started") or os.path.basename(path))
            if version is None or v == version:
                out.append({"series": doc.get("series") or os.path.splitext(os.path.basename(path))[0],
                            "started": doc.get("started"), "finished": doc.get("finished"), "version": v,
                            "runs": list(doc.get("runs") or [])})
    return out


def official_summary_ids(recordings, version=None):
    """Run ids whose own summary (recordings/scenario_runs/<run id>.json) says label official:
    tools/run_blind.py --label official writes one even outside a series. With `version`, only
    that evaluation's (a summary without "freeze" is v1)."""
    ids = set()
    for path in glob.glob(os.path.join(recordings, "scenario_runs", "*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            continue                      # a summary still being written; the series file is the record
        rid = doc.get("run_id") or os.path.splitext(os.path.basename(path))[0]
        if str(doc.get("label", "")).lower() == "official" and (version is None or evaluation.version_of(doc, when=rid) == version):
            ids.add(doc.get("run_id") or os.path.splitext(os.path.basename(path))[0])
    return ids


def official_run_ids(recordings, version=None):
    """Run ids of every official run (of `version` only, when given): listed in an official series
    OR carrying an official label in its own summary. Never dev data."""
    ids = {r.get("run_id") for s in official_series(recordings, version) for r in s["runs"] if r.get("run_id")}
    return ids | official_summary_ids(recordings, version)


def official_periods(recordings):
    """[(start, end or None)] of every official series of every version, parsed: a run recorded
    inside one is never practice data, even when the series lost track of it (a crash before the
    runner's summary; review 2026-10-30). A series with no "finished" time (it crashed, or is still
    running) is open-ended: nothing after its start is practice data. An unreadable start makes the
    whole store non-practice from the beginning (never a reason to call a run practice)."""
    from datetime import datetime, timezone
    from engine.replay import parse_time
    out = []
    for s in official_series(recordings):
        try:
            start = parse_time(str(s.get("started") or ""))
        except ValueError:                        # unknown start: nothing in the store may be practice
            out.append((datetime.min.replace(tzinfo=timezone.utc), None))
            continue
        try:
            end = parse_time(str(s["finished"])) if s.get("finished") else None
        except ValueError:
            end = None
        out.append((start, end))
    return out


def first_official_start(recordings):
    """The `started` time of the oldest official series (ISO text), or None: a run recorded at or
    after it is never practice data, even when its id is missing from the series (a crash before
    the runner's summary; review 2026-10-30)."""
    from engine.replay import parse_time
    starts = [s["started"] for s in official_series(recordings) if s.get("started")]
    return min(starts, key=parse_time) if starts else None


def out_folder(recordings):
    return os.path.join(recordings, *OVERLAY_DIR)


def out_name(scenario, run, volume, seed, graft):
    rid = run.get("run_id") or str(run.get("start", "")).replace(":", "").replace("-", "")
    return f"{scenario.lower()}-{rid}-{volume}x-s{seed}{'' if graft else '-nograft'}.db"


def inside_overlay_folder(path, recordings):
    folder = os.path.normcase(os.path.abspath(out_folder(recordings)))
    return os.path.normcase(os.path.abspath(path)).startswith(folder + os.sep)


def is_practice_run(recordings, run, ids=None, periods=None):
    """A run is practice (dev) data only if it is no official run (of any version) AND it started
    outside every official series' period (a run a series lost track of is still test data).
    v1 drew the line at the first official series' start; since v2 the line is each official
    series' own period, so the dev runs between v1's official runs and v2's freeze count as
    practice. `ids` and `periods` let a caller that loops over runs compute official_run_ids /
    official_periods once. Times are parsed (the VM writes 7-digit 'Z' stamps, run_series writes
    '+00:00'), never compared as text."""
    if run.get("run_id") in (official_run_ids(recordings) if ids is None else ids):
        return False
    from engine.replay import parse_time
    try:
        t = parse_time(str(run.get("start", "")))
    except ValueError:
        return False                      # an unreadable start time is never a reason to call a run practice
    for start, end in (official_periods(recordings) if periods is None else periods):
        if t >= start and (end is None or t <= end):
            return False
    return True


def build_for_run(recordings, scenario, run, volume, seed, graft=True, laptop=None, out=None, label="vm",
                  vm_records=None, pool=None):
    """Build one overlay store for `run` (a check_scenario run record): returns (path, meta).
    Raises ValueError for every refusal. `vm_records` lets a caller reuse the window's records;
    `pool` is the pool file verify_official checks in official mode (the caller's --pool)."""
    official_run = run.get("run_id") in official_run_ids(recordings)
    if config.is_official() and not official_run:
        raise ValueError(f"run {run.get('run_id')} is a practice run (dev data): not overlaid in official mode")
    if not official_run and not is_practice_run(recordings, run):
        raise ValueError(f"run {run.get('run_id')} started inside an official series' period: not dev data")
    if official_run and not config.is_official():
        raise ValueError(f"run {run.get('run_id')} belongs to an official series: official runs are test data, overlaid "
                         f"only with ANALYSTLAB_OFFICIAL=1 after the freeze (package J part 2)")
    if official_run:
        problems = config.verify_official(pool=pool) if pool else config.verify_official()
        if problems:
            raise ValueError("official mode: " + "; ".join(problems))
    if run.get("exit_code") != 0:
        raise ValueError(f"the run ended with exit code {run.get('exit_code')}: only clean practice runs are overlaid")
    lo, hi, overlaps = run_window(recordings, run)
    if overlaps:
        raise ValueError("this run overlaps the previous run; its evidence can't be separated")
    laptop = laptop or os.path.join(recordings, *DEFAULT_LAPTOP)
    out = out or os.path.join(out_folder(recordings), out_name(scenario, run, volume, seed, graft))
    if not inside_overlay_folder(out, recordings):
        raise ValueError(f"the output must be under {out_folder(recordings)} (it holds laptop names)")
    if vm_records is None:
        vm_records = window_records(recordings, label, lo, hi)
    info = {"scenario": scenario.upper(), "run_id": run.get("run_id"), "start": run.get("start"),
            "end": run.get("end"), "server": run.get("server")}
    meta = overlay.build(vm_records, lo, hi, laptop, volume, seed, out, graft=graft, run_info=info)
    return out, meta


def summary_lines(path, meta):
    """What the tool prints: counts only (no laptop path, name or address ever appears here)."""
    c = meta["counts"]
    lines = [f"overlay store: {os.path.basename(path)}",
             f"  run {meta['scenario']} {meta['run_id'] or ''} window {meta['window_seconds']:.0f} s on host {meta['host']}: "
             f"{meta['vm_records']} VM records",
             f"  volume {meta['volume']}x, seed {meta['seed']}, grafting {'on' if meta['graft'] else 'off'}: "
             f"{meta['overlay_rows']} overlay rows from {len(meta['slices'])} slice(s) of the laptop dev snapshot "
             f"(cutoff {meta['laptop_cutoff_day_utc']})"]
    for s in meta["slices"]:
        lines.append(f"    slice {s['k']}: {s['laptop_rows']} laptop rows, {s['rows_kept']} kept, shift {s['shift_seconds']:+.0f} s")
    rows = {k[5:]: v for k, v in c.items() if k.startswith("rows_")}
    lines.append(f"  rows by type: {rows}")
    dropped = {k[len('dropped_scenario_name_'):]: v for k, v in c.items() if k.startswith("dropped_scenario_name_")}
    lines.append(f"  dropped (named like a scenario program): {sum(dropped.values())} {dropped if dropped else ''}".rstrip())
    lines.append(f"  file paths rewritten (collide with the VM window): {c.get('path_collisions_rewritten', 0)}; "
                 f"program paths rewritten (created in the VM window): {c.get('image_collisions_rewritten', 0)}")
    lines.append(f"  boundary orphans grafted onto a live VM process: {c.get('grafted', 0)} (of which the laptop parent "
                 f"also acted inside the slice: {c.get('grafted_parent_also_acts_in_slice', 0)}); "
                 f"left as stubs: {c.get('orphans_not_grafted', 0)}")
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a noise-overlay store for one recorded VM practice run (counts only)")
    ap.add_argument("scenario")
    ap.add_argument("--run", type=int, default=1, help="1 = newest run, 2 = the one before, ...")
    ap.add_argument("--run-id", help="the run with this id (from tools/run_in_vm.py)")
    ap.add_argument("--volume", type=int, required=True, help="slices of laptop activity: 0, 1 or 5 in the experiment")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-graft", action="store_true", help="leave boundary orphans as stubs (sensitivity run)")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--label", default="vm")
    ap.add_argument("--laptop", help="the dev laptop snapshot (default <recordings>/scratch/dev/dev-laptop.db)")
    ap.add_argument("--out", help="output store (must be under <recordings>/scratch/overlay/)")
    a = ap.parse_args(argv)
    run = find_run(a.recordings, a.scenario, a.run, a.run_id)
    if run is None:
        print(f"No matching recorded run of {a.scenario.upper()} (recordings/vmruns).")
        return 1
    try:
        path, meta = build_for_run(a.recordings, a.scenario, run, a.volume, a.seed, not a.no_graft, a.laptop, a.out, a.label)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"Refusing: {e}")
        return 1
    print("\n".join(summary_lines(path, meta)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
