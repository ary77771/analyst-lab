"""A run_series series on another VM snapshot (blind round 4 and its noise boots run on 'lived-in'),
using the FROZEN v4 code unchanged (written 2026-11-20, after freeze-v4).

tools/run_series.py (frozen) builds each run's command from a runner command that does not name a
snapshot, so every run restores 'clean'. tools/run_in_vm.py and tools/run_blind.py (both frozen at
freeze-v4) do take --snapshot. This driver only calls the frozen run_series.run_series() with a
runner command that carries `--snapshot <name>`; run_series turns it into run_blind.py for blind
items exactly as it does for its own command line. Everything else (series file, official stamp,
refusals, keep-awake, stop rule) is the frozen code's. It lives outside the code gate (harness/), so
it cannot change any official result; it only decides which snapshot is restored, and every run
summary records that snapshot.

    python harness/snapshot_series.py --snapshot lived-in --label official --repeats 3 blind:C:\\...\\b18 ...
    python harness/snapshot_series.py --snapshot lived-in --label practice s0 --repeats 2
"""
import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, ROOT)
import run_series as RS  # noqa: E402
from engine import evaluation  # noqa: E402


def runner_cmd(recordings, snapshot, headless):
    return [sys.executable, "-u", os.path.join(ROOT, "tools", "run_in_vm.py"), "--recordings", recordings,
            "--snapshot", snapshot] + (["--headless"] if headless else [])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--label", choices=["practice", "official"], required=True)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--stop-after", type=int, default=2)
    ap.add_argument("--pause", type=float, default=20.0)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--recordings", default=os.path.join(ROOT, "recordings"))
    a = ap.parse_args(argv)
    if a.repeats < 1:
        ap.error("--repeats must be at least 1")
    seed = a.seed if a.seed is not None else int(time.time())
    order = RS.plan(a.scenarios, a.repeats, seed)
    cmd = runner_cmd(a.recordings, a.snapshot, a.headless)
    print(f"{a.label} series on snapshot '{a.snapshot}': {len(order)} single-boot runs, seed {seed}: "
          f"{' '.join(RS.name(s) for s in order)}")
    print("first run's command: " + " ".join(RS.item_cmd(cmd, order[0], a.label)))
    if a.dry_run:
        return 0
    if a.label == "official":
        problems = ([] if RS.has_freeze_tag() else [f"the git tag {evaluation.FREEZE_TAG} does not exist"]) + RS.official_problems()
        if problems:
            print("Refusing:", *problems, sep="\n  ")
            return 2
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if a.label == "official":
        env["ANALYSTLAB_OFFICIAL"] = "1"
    with RS.keep_awake():
        s = RS.run_series(order, a.label, seed, cmd, a.recordings, a.stop_after, a.pause, env=env)
    return 0 if all(r["exit_code"] == 0 for r in s["runs"]) and len(s["runs"]) == len(order) else 1


if __name__ == "__main__":
    sys.exit(main())
