"""Demo backup (v2 plan, package A): show a RECORDED scenario run in the dashboard as if it were
happening now, so the demo works even when the VM is slow or will not boot.

    python tools/demo_replay.py s1                       # the newest recorded S1 run, 3x real time
    python tools/demo_replay.py s1 --run-id <id> --speed 1
    python tools/demo_replay.py s5 s1 s4 s2 s3           # several recorded runs back to back, one store
    -> open http://127.0.0.1:8781 and watch the alerts and the graph appear; Ctrl+C to stop

Nothing new is invented: it reuses the pieces the live demo uses.
  1. The run's window and its raw VM records, re-tagged, exactly as the graph checker replays them
     (check_scenario.find_run / run_window, check_graph_scenario.window_records).
  2. engine/replay.py's replay() writes them, at --speed, into a fresh feed file under
     recordings/demo/<run id>-<time>/ (git-ignored, like all of recordings/).
  3. engine/live.py's LiveLoop follows that file and scores it every --every seconds, the same
     pass as live and batch scoring (engine/score.py), into a fresh store + alert database.
  4. The dashboard (engine/dashboard) serves that store; it rebuilds the graph whenever the store
     grows, so events, the graph and alerts appear as the replay goes.
Records are re-tagged once, over the whole VM stream (step 1); the loop does not re-tag again.
Prints counts only (privacy rule 7).
"""

import argparse
import os
import sys
import threading
import time
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_graph_scenario import window_records  # noqa: E402
from check_scenario import find_run, run_window  # noqa: E402
from engine import config, score  # noqa: E402
from engine import report as report_mod  # noqa: E402
from engine.alerts import AlertStore, declared_note  # noqa: E402
from engine.live import LiveLoop  # noqa: E402
from engine.replay import replay  # noqa: E402
from engine.store import EventStore  # noqa: E402

FEED = "feed"            # the label folder the loop follows (not "vm": the records are re-tagged already)


def prepare(recordings, scenario, run_id=None):
    """(run, records of its window, re-tagged) or raise SystemExit with a plain message."""
    run = find_run(recordings, scenario, run_id=run_id)
    if run is None:
        which = f" with run id {run_id}" if run_id else ""
        raise SystemExit(f"No recorded run of {scenario.upper()}{which} (recordings/vmruns).")
    lo, hi, _ = run_window(recordings, run)
    records = window_records(recordings, "vm", lo, hi)
    if not records:
        raise SystemExit("That run's window holds no VM records.")
    return run, records


def every_run(recordings, scenarios):
    """(scenarios, run_ids) naming EVERY recorded run of each listed scenario, oldest first (--all-runs)."""
    from check_scenario import all_runs
    wanted = {s.upper() for s in scenarios}
    picked = [r for r in all_runs(recordings) if str(r.get("scenario", "")).upper() in wanted and r.get("run_id")]
    missing = wanted - {str(r["scenario"]).upper() for r in picked}
    if missing:
        raise SystemExit(f"No recorded run of {', '.join(sorted(missing))} (recordings/vmruns).")
    picked.sort(key=lambda r: str(r.get("start")))
    return [str(r["scenario"]) for r in picked], [r["run_id"] for r in picked]


def prepare_many(recordings, scenarios, run_ids=None):
    """Several recorded runs played back to back (night 3): ([runs], records). Each run keeps its own window
    (run_window cuts it at the neighbouring runs, so no run borrows another's evidence); a record that two
    touching windows both hold is kept once; all records in recorded-time order. run_ids: none, or one per
    scenario in the same order. One scenario gives exactly prepare()'s records.
    Several: the VM stream is read and re-tagged ONCE (as window_records does for one run), then every record
    inside any of the windows is kept, so ~150 runs take one read, not 150."""
    import bisect
    from check_scenario import all_runs
    from engine.jsonl import recording_files
    from engine.replay import parse_time, read_recordings
    run_ids = list(run_ids or [])
    if run_ids and len(run_ids) != len(scenarios):
        raise SystemExit("Give one --run-id per scenario, in the same order (or none).")
    if len(scenarios) == 1:
        run, records = prepare(recordings, scenarios[0], run_ids[0] if run_ids else None)
        return [run], records
    everything = all_runs(recordings)
    runs, windows = [], []
    for i, scenario in enumerate(scenarios):
        run = find_run(recordings, scenario, run_id=run_ids[i] if run_ids else None)
        if run is None:
            which = f" with run id {run_ids[i]}" if run_ids else ""
            raise SystemExit(f"No recorded run of {scenario.upper()}{which} (recordings/vmruns).")
        if any(r.get("run_id") == run.get("run_id") and r.get("start") == run.get("start") for r in runs):
            raise SystemExit(f"{scenario.upper()} is listed twice (the same recorded run).")
        w = run_window(recordings, run, everything)
        runs.append(run)
        windows.append((w.lo, w.hi))
    spans = []                                    # the windows joined where they touch, in time order
    for lo, hi in sorted(windows):
        if spans and lo <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], hi)
        else:
            spans.append([lo, hi])
    starts = [s[0] for s in spans]
    merged = []
    for r in read_recordings(recording_files(os.path.join(recordings, "vm")), retag=True):
        if not r.get("time"):
            continue
        t = parse_time(r["time"])
        k = bisect.bisect_right(starts, t) - 1
        if k >= 0 and t <= spans[k][1]:
            merged.append(r)
    if not merged:
        raise SystemExit("Those runs' windows hold no VM records.")
    merged.sort(key=lambda r: parse_time(r["time"]).timestamp())
    return runs, merged


def describe(runs):
    """The badge's detail: one run as before; several = which ones, and that they are separate recorded runs."""
    def day(run):
        d = str(run.get("run_id") or "")[:8]
        return f"{d[:4]}-{d[4:6]}-{d[6:8]}"
    if len(runs) == 1:
        run = runs[0]
        return f"{run['scenario'].upper()}, recorded {day(run)} (run {run.get('run_id', '?')})"
    played = [str(r["scenario"]).upper() for r in sorted(runs, key=lambda r: str(r.get("start")))]   # played order
    if len(played) <= 6:
        names = "+".join(played)
    else:                                                    # many runs: how many of each, not a long list
        count = {}
        for s in played:
            count[s] = count.get(s, 0) + 1
        names = ", ".join(f"{s} x{n}" if n > 1 else s for s, n in sorted(count.items(), key=lambda kv: (-kv[1], kv[0])))
    days = sorted({day(r) for r in runs})
    when = " and ".join(days) if len(days) <= 2 else f"between {days[0]} and {days[-1]}"
    return f"{names}: {len(runs)} recorded runs played back to back, recorded {when}"


def make_folder(recordings, run):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = os.path.join(recordings, "demo", f"{run.get('run_id') or 'run'}-{stamp}")
    folder, n = base, 1
    while True:                               # two replays started in the same second each get their own folder
        try:
            os.makedirs(os.path.join(folder, FEED))
            break
        except FileExistsError:
            n += 1
            folder = f"{base}-{n}"
    store, alerts = os.path.join(folder, "events.db"), os.path.join(folder, "alerts.db")
    EventStore(store).close()                 # both exist before the dashboard opens them
    AlertStore(alerts).close()
    return folder, store, alerts


class Feeder:
    """Writes records into the feed file at replay speed (complete lines only, flushed each time),
    so the loop sees them arrive like the receiver's day files."""

    def __init__(self, path):
        import json
        self.json = json
        self.f = open(path, "a", encoding="utf-8")
        self.n = 0

    def __call__(self, r):
        self.f.write(self.json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n")
        self.f.flush()
        self.n += 1

    def close(self):
        self.f.close()


def serve(store, alerts, port, detail=None, labs=True):
    """The dashboard in a background thread (the same app and settings as engine.dashboard), in
    replay mode: every screen carries the REPLAY badge and no VM run can be started (debate 11).
    labs=False (--no-labs) gives the same shell as engine.dashboard --no-labs (night 2 review)."""
    import uvicorn
    from engine.dashboard.app import DASHBOARD_HOSTS, create_app
    app = create_app(store, alerts, hypotheses=report_mod.layer2_from(report_mod.DEFAULT_POOL),
                     hubs=config.hubs(), allowed_hosts=DASHBOARD_HOSTS, mode="replay", mode_detail=detail,
                     labs=labs)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):                      # wait until it listens
        if server.started:
            return server
        time.sleep(0.1)
    raise SystemExit(f"the dashboard did not start on port {port} (in use?)")


def _filling(total):
    """Tell the Labs shell that the store is being filled (`total` records to come) or, with None, that it is
    whole. Never a reason for the replay itself to fail."""
    try:
        from engine.labs import _replay
        _replay.finished() if total is None else _replay.started(total)
    except Exception:
        pass


def score_loop(loop, stop, every, say):
    while not stop.is_set():
        n, fresh = loop.tick()
        for a in fresh:
            say(f"  ALERT [{a.level}] {a.title}{declared_note(a)}")
        stop.wait(every)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Replay a recorded scenario run into the dashboard (demo backup)")
    ap.add_argument("scenario", nargs="+", help="e.g. s1, or several (s5 s1 s4) played back to back")
    ap.add_argument("--run-id", action="append", help="this run instead of the newest one (once per scenario)")
    ap.add_argument("--speed", type=float, default=3.0, help="1 = real time, 3 = 3x (default), 0 = instant")
    ap.add_argument("--max-gap", type=float, default=5.0, help="cap quiet gaps at this many recorded seconds")
    ap.add_argument("--every", type=float, default=2.0, help="seconds between scoring passes")
    ap.add_argument("--port", type=int, default=8781, help="dashboard port (8780 stays free for the live one)")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--no-serve", action="store_true", help="no dashboard (tests, or scoring only)")
    ap.add_argument("--exit", action="store_true", help="stop when the replay is done (default: keep serving)")
    ap.add_argument("--no-labs", action="store_true", help="no Labs and no Tour (the rehearsed shell)")
    ap.add_argument("--all-runs", action="store_true", help="every recorded run of each listed scenario, oldest first")
    a = ap.parse_args(argv)

    if a.all_runs:
        if a.run_id:
            raise SystemExit("--all-runs picks the runs itself: leave out --run-id.")
        a.scenario, a.run_id = every_run(a.recordings, a.scenario)
    runs, records = prepare_many(a.recordings, a.scenario, a.run_id)
    run = runs[0]
    folder, store, alerts = make_folder(a.recordings, run)
    which = (f"{'+'.join(str(r['scenario']) for r in runs)} run {'/'.join(str(r.get('run_id', '?')) for r in runs)}"
             if len(runs) <= 6 else describe(runs))
    print(f"{which}: {len(records)} records to replay at "
          f"{'instant' if not a.speed else f'{a.speed:g}x'} (quiet gaps capped at {a.max_gap:g} s)")
    rules = score.load_rules()
    loop = LiveLoop(os.path.join(folder, FEED), store, alerts, rules, retag=False,
                    baseline=score.load_baseline(score.baseline_files()))
    if not a.no_serve:
        serve(store, alerts, a.port, detail=describe(runs), labs=not a.no_labs)   # the store only ever holds these VM runs' windows
        print(f"Dashboard: http://127.0.0.1:{a.port}  (open it now; Ctrl+C stops everything)")
    stop = threading.Event()
    scorer = threading.Thread(target=score_loop, args=(loop, stop, a.every, print), daemon=True)
    scorer.start()
    feeder = Feeder(os.path.join(folder, FEED, "replay.jsonl"))
    try:
        _filling(len(records))                # the Labs pages wait until the store is whole (engine/labs/_replay.py)
        replay(records, feeder, a.speed, a.max_gap)
        feeder.close()
        stop.set()
        scorer.join()
        n, fresh = loop.tick()                # a last pass over whatever arrived after the previous one
        for x in fresh:
            print(f"  ALERT [{x.level}] {x.title}{declared_note(x)}")
        s = AlertStore(alerts)
        total = len(s.read())
        s.close()
        _filling(None)                        # every record and every alert is in the store now
        print(f"Replay done: {feeder.n} records, {total} alerts stored (store and alerts in recordings/demo/)")
        if a.no_serve or a.exit:
            return 0
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("stopped")
        return 0
    finally:
        stop.set()
        feeder.close()


if __name__ == "__main__":
    raise SystemExit(main())
