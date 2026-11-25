"""Rehearse the dashboard's LIVE screen without the test machine (development and practice only).

    python demo/dash_rehearse.py                 # S1's recorded run, on http://127.0.0.1:8795
    python demo/dash_rehearse.py s5 --boot 20

Why: a real run takes ~9 minutes and needs the VM. The live screen's moments (the run's steps, the
first records arriving, the alert landing) must be seen and practised many times before the demo.

What it does: it starts the same dashboard app with a stand-in runner. Clicking "Run" there starts NO
virtual machine. The stand-in writes the same progress lines tools/run_in_vm.py writes (on a short
timer), then feeds a RECORDED run's records into a fresh store, exactly as tools/demo_replay.py does
(same replay(), same LiveLoop scoring pass). So every alert, graph and word on screen still comes
from recorded data through the real engine; only the waiting is shortened.

What it never starts: a virtual machine, tools/run_in_vm.py or the real Runner (tests/test_dash_rehearse.py).
(The checks strip, as on every dashboard, asks VirtualBox whether the test machine is running: a question, not a start.)

Honesty: every screen carries the badge "REHEARSAL: a recorded run played back, no test machine".
It can never be opened by demo/start.ps1, and it listens on its own port (not 8780/8781).
The dashboard's clock is moved to the recording's time, because the live view decides which alerts
belong to "this run" by comparing the alert's recorded time with the clock (live_status.split).
Prints counts only (privacy rule 7). One rehearsal per start: restart it for a fresh store.
"""

import argparse
import os
import sys
import threading
import time
import traceback

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from demo_replay import FEED, Feeder, make_folder, prepare, score_loop  # noqa: E402
from engine import config, score  # noqa: E402
from engine import report as report_mod  # noqa: E402
from engine.dashboard.app import DASHBOARD_HOSTS, Runner, create_app  # noqa: E402
from engine.live import LiveLoop  # noqa: E402
from engine.replay import parse_time, replay  # noqa: E402
from fastapi import HTTPException  # noqa: E402


class RecordingClock:
    """The laptop's clock shifted to the recording's time (set when a rehearsal run starts)."""

    def __init__(self):
        self.offset = 0.0

    def __call__(self):
        return time.time() + self.offset


class RehearsalRunner(Runner):
    """Stands in for the VM run: run_in_vm's progress lines on a timer, then a recorded run's records."""

    def __init__(self, recordings, clock, records, feed_folder, loop, boot=15.0, speed=3.0, max_gap=5.0, pace=1.0):
        super().__init__(recordings, command=["(rehearsal: no command is ever started)"])
        self.clock, self.records, self.feed_folder, self.loop = clock, records, feed_folder, loop
        self.boot, self.speed, self.max_gap, self.pace = boot, speed, max_gap, pace     # pace < 1: a test's short waits
        self.thread, self.exit_code, self.used = None, None, False

    def start(self, scenario):
        scenarios = [scenario] if isinstance(scenario, str) else list(scenario)
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise HTTPException(status_code=409, detail="a rehearsal run is already going")
            if self.used:
                raise HTTPException(status_code=409, detail="one rehearsal per start: restart demo/dash_rehearse.py")
            first = min(parse_time(r["time"]).timestamp() for r in self.records if r.get("time"))   # raises before anything is marked used
            self.used = True
            os.makedirs(os.path.join(self.recordings, "live"), exist_ok=True)
            self.log = os.path.join(self.recordings, "live", f"rehearsal-run-{int(time.time())}.log")
            self.clock.offset = first - self.boot - 30 - time.time()     # the run "starts" shortly before its records
            self.scenario, self.started, self.exit_code = "+".join(scenarios), self.clock(), None
            self.thread = threading.Thread(target=self._play, daemon=True)
            self.thread.start()

    def _say(self, line):
        with open(self.log, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _play(self):
        stop, feeder = threading.Event(), None
        try:
            self._say("--> 1. rehearsal: preparing")
            time.sleep(3 * self.pace)
            self._say("--> 2. rehearsal: restoring and starting (shortened)")
            time.sleep(self.boot * self.pace)
            self._say("VM: running (rehearsal)")
            self._say("--> 3. rehearsal: test program running (a recorded run is played back)")
            scorer = threading.Thread(target=score_loop, args=(self.loop, stop, 2.0 * self.pace, lambda *_: None), daemon=True)
            scorer.start()
            feeder = Feeder(os.path.join(self.feed_folder, FEED, "replay.jsonl"))
            replay(self.records, feeder, self.speed, self.max_gap)
            feeder.close()
            stop.set()
            scorer.join()
            self.loop.tick()
            time.sleep(4 * self.pace)
            self._say("--> 4. rehearsal: checking")
            time.sleep(4 * self.pace)
            self._say("--> 5. rehearsal: shutting down")
            time.sleep(3 * self.pace)
            self._say("RUN rehearsal: finished")
            self.exit_code = 0
        except Exception:
            self.exit_code = 1
            try:                                   # why it stopped goes to its own file on this laptop, never to the page
                with open(self.log + ".error", "w", encoding="utf-8") as f:
                    traceback.print_exc(file=f)
            except OSError:
                pass
        finally:
            stop.set()                             # the scoring loop never outlives the run
            if feeder is not None:
                feeder.close()

    def status(self):
        from engine.dashboard.app import RunStatus
        running = self.thread is not None and self.thread.is_alive()
        return RunStatus(running=running, scenario=self.scenario, started=self.started,
                         exit_code=None if running or self.thread is None else self.exit_code, log_tail=[])


def main(argv=None):
    import uvicorn
    ap = argparse.ArgumentParser(description="Rehearse the live dashboard from a recorded run (no test machine)")
    ap.add_argument("scenario", nargs="?", default="s1")
    ap.add_argument("--run-id", default=None, help="this recorded run instead of the newest one")
    ap.add_argument("--port", type=int, default=8795)
    ap.add_argument("--boot", type=float, default=15.0, help="seconds the pretend start-up takes")
    ap.add_argument("--speed", type=float, default=3.0)
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--no-labs", action="store_true", help="no Labs and no Tour (the rehearsed shell)")
    a = ap.parse_args(argv)

    run, records = prepare(a.recordings, a.scenario, a.run_id)
    folder, store, alerts = make_folder(a.recordings, run)
    loop = LiveLoop(os.path.join(folder, FEED), store, alerts, score.load_rules(), retag=False,
                    baseline=score.load_baseline(score.baseline_files()))
    clock = RecordingClock()
    runner = RehearsalRunner(a.recordings, clock, records, folder, loop, boot=a.boot, speed=a.speed)
    recorded = str(run.get("run_id") or "")[:8]
    detail = f"{run['scenario'].upper()}, recorded {recorded[:4]}-{recorded[4:6]}-{recorded[6:8]}"
    app = create_app(store, alerts, recordings=a.recordings, runner=runner,
                     hypotheses=report_mod.layer2_from(report_mod.DEFAULT_POOL), hubs=config.hubs(),
                     allowed_hosts=DASHBOARD_HOSTS, mode="rehearsal", mode_detail=detail, clock=clock,
                     labs=not a.no_labs)
    print(f"Rehearsal dashboard: http://127.0.0.1:{a.port}  ({len(records)} recorded records ready; no test machine is used)")
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
