"""Dashboard (package I, DESIGN 4.9): a small local web app over the engine.

    python -m engine.dashboard --events recordings/live/vm.db --alerts recordings/live/vm-alerts.db
    -> http://127.0.0.1:8780

Three screens in one page (engine/dashboard/static/): Alerts, Investigation (evidence graph +
timeline + evidence panel + "Open report"), Scenarios (start a VM run, see its progress).
Decided 2026-10-23: a simple page now (FastAPI, already installed; cytoscape.js saved in the repo
so it works offline); a React front end may replace static/ later: everything it needs is in the
JSON API below (/api/...), which the tests check against fixed shapes.

Local only (127.0.0.1). Pages show program names, paths and addresses from the recording: run it
on the machine that owns the data. The lab VM reaches the laptop's loopback as 10.0.2.2 (VirtualBox
NAT), so main() accepts only the Host names the laptop itself uses (review 2026-10-31). This stops a
browser or an ordinary client in the VM; it does NOT stop a program that writes a false Host header
on purpose (the header is the sender's claim). Closing that needs the VM firewall limited to the
receiver and test-server ports, or a dashboard address the VM cannot reach (open item).
"""

import argparse
import asyncio
import glob
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import report as report_mod
from ..alerts import LEVELS, AlertStore
from .. import config
from ..graph import build_graph

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DASHBOARD_HOSTS = frozenset({"127.0.0.1", "localhost"})     # never 10.0.2.2: that is the VM's name for the laptop


class AlertRow(BaseModel):
    id: str
    title: str
    rule: str
    source: str
    level: str
    time: str
    host: str
    reason: str
    events: int


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    gaps: list[str]
    seed: bool
    hub: bool = False          # kept but not walked through (engine/hubs.py)
    hop: bool = False          # only on the path of a hypothesis (layer 2)
    # report v3 (debate 11), from report.build()'s layout: additive
    short: Optional[str] = None            # the label without the PID when the name is unique in the view
    icon: Optional[str] = None             # a name from report.ICON_NAMES, chosen in Python
    lane: Optional[int] = None             # one lane per program, for a left-to-right time layout
    order: Optional[int] = None            # the node's first row in the report's full-precision causal order
    t_offset_s: Optional[float] = None     # seconds from the first step of the alert's chain


class GraphEdge(BaseModel):
    id: str                    # report v3: the same id as the report's fact/hypothesis (report.edge_id)
    source: str
    target: str
    kind: str
    grade: str
    band: Optional[str] = None
    sentence: str
    time: Optional[str] = None
    evidence: list[str]
    short: Optional[str] = None
    icon: Optional[str] = None
    lane: Optional[int] = None
    order: Optional[int] = None
    time_precise: Optional[str] = None
    t_offset_s: Optional[float] = None
    in_chain: bool = False


STREAM_ROUNDS = 3600           # /api/stream checks every 2 s for an hour (a test shortens it)


class StreamAlert(BaseModel):
    id: str
    title: str
    level: str
    time: str


def stream_payload(rows, min_level=None, limit=50) -> dict:
    """What /api/stream sends (debate 11, fresh review item 3): the alerts AT OR ABOVE the frozen
    floor (config.min_level(), the same floor the alert list applies), newest first, each
    {id, title, level, time}; `alerts` = how many are shown, `counts` per shown level, and how many
    were left out below the floor (said, never hidden)."""
    min_level = min_level or config.min_level()
    floor = LEVELS.index(min_level)
    shown = sorted((a for a in rows if LEVELS.index(a.level) >= floor), key=lambda a: a.time, reverse=True)
    counts = {lvl: 0 for lvl in LEVELS[floor:]}
    for a in shown:
        counts[a.level] += 1
    items = [StreamAlert(id=a.alert_id, title=a.title, level=a.level, time=a.time).model_dump() for a in shown[:limit]]
    return {"alerts": len(shown), "min_level": min_level, "counts": counts, "below_floor": len(rows) - len(shown),
            "items": items, "latest": items[0] if items else None}


class Investigation(BaseModel):
    alert: AlertRow
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    report: dict
    warnings: list[str] = []   # e.g. the alert was raised on another event store than the one read


class DashboardConfig(BaseModel):
    min_level: str             # the frozen alert floor (config/frozen.yaml sigma.min_level)
    levels: list[str]          # every level, lowest first


class ScenarioRow(BaseModel):
    id: str
    title: str
    last_result: Optional[str] = None
    last_run: Optional[str] = None


class RunStatus(BaseModel):
    running: bool
    scenario: Optional[str] = None
    started: Optional[float] = None
    exit_code: Optional[int] = None
    log_tail: list[str]


def _row(a) -> AlertRow:
    return AlertRow(id=a.alert_id, title=a.title, rule=a.rule_id, source=a.source, level=a.level, time=a.time,
                    host=a.host, reason=a.reason, events=len(a.evidence))


class Runner:
    """At most one VM run at a time, started from the Scenarios screen (tools/run_in_vm.py)."""

    def __init__(self, recordings, command=None):
        self.recordings = recordings
        self.command = command or [sys.executable, "-u", os.path.join(PROJECT_ROOT, "tools", "run_in_vm.py")]
        self.proc, self.scenario, self.started, self.log = None, None, None, None
        self.lock = threading.Lock()

    def start(self, scenario):
        """`scenario` is one id ("s1") or a list for one boot (["s1", "s4", "s5"]: run_in_vm's batch,
        a development run, never an official one)."""
        scenarios = [scenario] if isinstance(scenario, str) else list(scenario)
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                raise HTTPException(status_code=409, detail="a VM run is already going")
            os.makedirs(os.path.join(self.recordings, "live"), exist_ok=True)
            self.log = os.path.join(self.recordings, "live", f"dashboard-run-{int(time.time())}.log")
            out = open(self.log, "w", encoding="utf-8")
            # debate 11 round 3 section 0: boot the prepared `lived-in` snapshot (0 boot alerts in its noise
            # boots and in the 11-20 practice run), never `clean` (2-3 boot alerts: the banner would turn red
            # before the scenario starts). The flag exists in the frozen run_in_vm.py.
            self.proc = subprocess.Popen(self.command + scenarios + ["--headless", "--snapshot", "lived-in"], stdout=out, stderr=subprocess.STDOUT,
                                         cwd=PROJECT_ROOT)
            self.scenario, self.started = "+".join(scenarios), time.time()

    def status(self) -> RunStatus:
        tail = []
        if self.log and os.path.exists(self.log):
            with open(self.log, encoding="utf-8", errors="replace") as f:
                tail = [l.rstrip("\n") for l in f.readlines()[-15:]]
        running = self.proc is not None and self.proc.poll() is None
        return RunStatus(running=running, scenario=self.scenario, started=self.started,
                         exit_code=None if (self.proc is None or running) else self.proc.returncode, log_tail=tail)


# the Story header's labels for alerts of a warm session (what is claimed: whose programs, nothing about harm)
ALERT_LABEL_WORDS = {
    "test": "Raised on {test}'s own programs",
    "other_short": "other",
    "other": "Raised on another program on the test machine, not on a test's own programs",
}


def create_app(events_db, alerts_db, recordings=None, runner=None, hypotheses=None, hubs=None,
               allowed_hosts=None, mode=None, mode_detail=None, clock=None, warm=None, keep_awake=None,
               labs=True, labs_hosts="vm") -> FastAPI:
    """hypotheses = graph.Layer2 (None: facts only); hubs = the frozen hub list (None: no suppression);
    allowed_hosts = Host header names accepted (None = no check, e.g. for tests);
    mode = None | "live" | "replay" | "rehearsal" (demo badge; demo_mode.py), mode_detail = the replay's
    date/run; clock = the live screen's clock (None = the laptop's; demo/dash_rehearse.py passes its own);
    warm = the warm test machine's session (demo/warm_vm.py WarmSession or a stand-in; None = none here);
    keep_awake = Windows' SetThreadExecutionState (or a stand-in): given, the laptop is asked to stay awake
    exactly while a one-boot run or a warm session is going (engine/dashboard/awake.py); None = never asked.
    labs = False: no lab is loaded at all (--no-labs, the panic button); labs_hosts = the machines a lab may
    show: "vm" (the default: the lab's test machine only, demo_mode.VM_HOSTS), a set of names, or None for
    no limit (--labs-all-hosts)."""
    recordings = recordings or os.path.join(PROJECT_ROOT, "recordings")
    runner = runner or Runner(recordings)
    app = FastAPI(title="Analyst Lab dashboard")
    # the warm test machine (engine/dashboard/warm.py): its tests and the one-boot runs refuse each other,
    # and the live view follows whichever run is the newest (`current`)
    from . import warm as warm_mod
    warm_runs = warm_mod.WarmRuns(recordings, clock=clock or time.time)
    if warm is not None and hasattr(warm, "on_step"):
        warm.on_step = warm_runs.step
    observe = []                              # the live view's "a new run began" (set below, once that router exists)
    warm_router = warm_mod.make_router(warm, runner, warm_runs, mode, clock=clock or time.time,
                                       on_begin=lambda: [f() for f in observe])
    current = warm_mod.Current(runner, warm_runs)

    if keep_awake is not None:
        from .awake import Keeper
        app.state.awake = Keeper(lambda: bool(runner.status().running) or bool(warm_router.active()), keep_awake,
                                 say=lambda m: print(f"keep awake: {m}", flush=True)).start()

    def no_warm_session():
        if warm_router.active():
            raise HTTPException(status_code=409, detail="the warm test machine is in use; shut it down before a one-boot run")
    cache = {"graph": None, "key": None}

    @app.middleware("http")
    async def laptop_only(request: Request, call_next):
        if allowed_hosts is not None:
            host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
            if host not in allowed_hosts:
                return JSONResponse({"detail": "unknown Host"}, status_code=421)
        return await call_next(request)

    def events_con():
        return sqlite3.connect("file:" + os.path.abspath(events_db).replace("\\", "/") + "?mode=ro", uri=True)

    def alerts():
        if not os.path.exists(alerts_db):
            return []
        s = AlertStore(alerts_db)
        try:
            return s.read()
        finally:
            s.close()

    def recorded_store(alert_id):
        """The event store the alert was raised on (AlertStore keeps it), or None."""
        if not os.path.exists(alerts_db):
            return None
        s = AlertStore(alerts_db)
        try:
            return s.events_dbs().get(alert_id)
        finally:
            s.close()

    def store_version(con):
        """The newest row id: the store is append-only, so a new event always raises it. (The file's
        mtime is not enough: EventStore uses WAL, so new rows sit in the -wal file first.)"""
        try:
            return con.execute("SELECT MAX(id) FROM events").fetchone()[0]
        except sqlite3.OperationalError:          # no events table yet
            return None

    def graph_for(host):
        """The full graph, rebuilt when the store changed (the live loop keeps adding events)."""
        con = events_con()
        try:
            key = (host, store_version(con))
            if cache["graph"] is None or cache["key"] != key:
                cache["graph"], cache["key"] = build_graph(con, host=host or None, hypotheses=hypotheses), key
        finally:
            con.close()
        return cache["graph"]

    def content_for(a, G):
        return report_mod.build(a, G, events_db, hubs=hubs, recorded_events_db=recorded_store(a.alert_id))

    @app.get("/api/config", response_model=DashboardConfig)
    def dashboard_config():
        """What the page needs to start: the frozen alert floor and the level names."""
        return DashboardConfig(min_level=config.min_level(), levels=list(LEVELS))

    @app.get("/api/alerts", response_model=list[AlertRow])
    def list_alerts(min_level: str = None, limit: int = 500):
        min_level = min_level or config.min_level()     # the frozen floor (Yousif 2026-10-23: medium)
        if min_level not in LEVELS:
            raise HTTPException(status_code=400, detail=f"min_level must be one of {LEVELS}")
        floor = LEVELS.index(min_level)
        rows = [a for a in alerts() if LEVELS.index(a.level) >= floor]
        rows.sort(key=lambda a: a.time, reverse=True)
        return [_row(a) for a in rows[:limit]]

    label_trees = {"t": None}

    @app.get("/api/alert-labels")
    def alert_labels():
        """For the Story header's alert buttons (2026-11-23): which of this warm session's tests an alert is
        about ("S1": a program of its own evidence is in that test's program tree, engine/dashboard/
        attribution.py), or that it is about another program on the test machine. Decided by the records,
        never by a name. {} when there is no warm session, and no label for an alert while a test whose
        programs are not recorded yet could still own it: the button then keeps its plain number."""
        try:
            runs = [r for r in (warm.status().get("runs") or []) if r.get("run_id") and r.get("scenario")] if warm is not None else []
        except Exception:
            runs = []
        if not runs:
            return {}
        from .attribution import Trees
        if label_trees["t"] is None:
            label_trees["t"] = Trees(events_db)
        trees = label_trees["t"]
        known = [(r, trees.tree(r["run_id"])) for r in runs]
        # a test that is still going (or whose end this side does not know) and has no recorded program yet
        open_run = any(t is None and r.get("step") not in ("done", "failed") for r, t in known)
        floor = LEVELS.index(config.min_level())
        out = {}
        for a in alerts():
            if LEVELS.index(a.level) < floor:
                continue
            mine = trees.programs(a)
            owner = next((r["scenario"].upper() for r, t in known if t and mine & t), None)
            if owner:
                out[a.alert_id] = {"label": owner, "kind": "test", "title": ALERT_LABEL_WORDS["test"].format(test=owner)}
            elif not open_run and any(t for _, t in known):
                out[a.alert_id] = {"label": ALERT_LABEL_WORDS["other_short"], "kind": "other", "title": ALERT_LABEL_WORDS["other"]}
        return out

    def find(alert_id):
        for a in alerts():
            if a.alert_id == alert_id:
                return a
        raise HTTPException(status_code=404, detail="no such alert")

    @app.get("/api/alerts/{alert_id}", response_model=Investigation)
    def investigation(alert_id: str):
        a = find(alert_id)
        G = graph_for(a.host)
        content = content_for(a, G)
        nodes, edges = [], []
        seed, _, H = report_mod.alert_view(a, G, hubs)           # the report's own view (same seed and time)
        lay_n = {x["id"]: x for x in content["layout"]["nodes"]}
        lay_e = {x["id"]: x for x in content["layout"]["edges"]}
        if seed:
            for n, d in H.nodes(data=True):
                x = lay_n.get(n, {})
                nodes.append(GraphNode(id=n, label=report_mod.label(H, n), kind=d.get("kind") or "?",
                                       gaps=sorted({g["kind"] for g in d.get("gaps", [])}), seed=(d.get("depth") == 0),
                                       hub=bool(d.get("hub")), hop=bool(d.get("hop")), short=x.get("short"),
                                       icon=x.get("icon"), lane=x.get("lane"), order=x.get("order"),
                                       t_offset_s=x.get("t_offset_s")))
            for u, v, k, d in H.edges(keys=True, data=True):
                ev = d.get("evidence") or ([d["primary"]] if d.get("primary") else [])
                eid = report_mod.edge_id(u, v, k)                # report v3: the report item's own id
                x = lay_e.get(eid, {})
                edges.append(GraphEdge(id=eid, source=u, target=v, kind=d.get("kind") or "?",
                                       grade=d.get("grade") or "?", band=d.get("band"),
                                       sentence=report_mod.sentence(H, u, v, d.get("kind")),
                                       time=report_mod._time(d.get("time")), evidence=[e["key"] for e in ev if e and e.get("key")],
                                       short=x.get("short"), icon=x.get("icon"), lane=x.get("lane"), order=x.get("order"),
                                       time_precise=x.get("time_precise"), t_offset_s=x.get("t_offset_s"),
                                       in_chain=bool(x.get("in_chain"))))
        return Investigation(alert=_row(a), nodes=nodes, edges=edges, report=content, warnings=content["warnings"])

    @app.get("/api/alerts/{alert_id}/film")
    def film(alert_id: str):
        """Which of the report's rows the Story screen's film tells (engine/dashboard/film.py): all of a
        short story; of a long one the alert's own chain. The report itself always keeps every row."""
        from .film import film_of
        a = find(alert_id)
        return film_of(content_for(a, graph_for(a.host)))

    @app.get("/api/alerts/{alert_id}/report", response_class=HTMLResponse)
    def report_page(alert_id: str):
        a = find(alert_id)
        return report_mod.render(content_for(a, graph_for(a.host)))

    @app.get("/api/events/{key:path}")
    def event(key: str):
        con = events_con()
        try:
            con.row_factory = sqlite3.Row
            row = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone()
        finally:
            con.close()
        if row is None:
            raise HTTPException(status_code=404, detail="no such event")
        return {k: row[k] for k in row.keys() if row[k] is not None and k != "raw_xml"}

    @app.get("/api/scenarios", response_model=list[ScenarioRow])
    def scenarios():
        import yaml
        last = {}
        for p in sorted(glob.glob(os.path.join(recordings, "scenario_runs", "*.json"))):
            try:
                with open(p, encoding="utf-8") as f:
                    s = json.load(f)
            except (OSError, ValueError):
                continue
            for item in s.get("batch") or [{"scenario": s.get("scenario"), "result": s.get("result")}]:
                if item.get("scenario"):
                    last[str(item["scenario"]).lower()] = (item.get("result") or s.get("result"), os.path.basename(p)[:15])
        out = []
        for path in sorted(glob.glob(os.path.join(PROJECT_ROOT, "scenarios", "*", "ground_truth.yaml"))):
            sid = os.path.basename(os.path.dirname(path))
            with open(path, encoding="utf-8") as f:
                title = (yaml.safe_load(f) or {}).get("title", sid)
            res, when = last.get(sid, (None, None))
            out.append(ScenarioRow(id=sid, title=title, last_result=res, last_run=when))
        return out

    @app.post("/api/scenarios/{scenario}/run", response_model=RunStatus)
    def run(scenario: str):
        if mode == "replay":                                  # debate 11 review item 6: a replay starts no VM run
            raise HTTPException(status_code=409, detail="this dashboard shows a replay; VM runs start from the live one")
        if not os.path.exists(os.path.join(PROJECT_ROOT, "scenarios", scenario, "ground_truth.yaml")):
            raise HTTPException(status_code=404, detail="no such scenario")
        no_warm_session()
        runner.start(scenario)
        return runner.status()

    @app.post("/api/run/three", response_model=RunStatus)
    def run_three():
        """S1, S4 and S5 in one boot (debate 12 E3; tested on `lived-in` 2026-11-20: all three PASS and
        DETECTED, alerts about a minute apart, 12.3 min in all). A development batch, not an official run."""
        if mode == "replay":
            raise HTTPException(status_code=409, detail="this dashboard shows a replay; VM runs start from the live one")
        no_warm_session()
        runner.start(["s1", "s4", "s5"])
        return runner.status()

    @app.get("/api/run", response_model=RunStatus)
    def run_status():
        return runner.status()

    @app.get("/api/stream")
    async def stream():
        """Server-sent events: stream_payload() (the alerts at or above the frozen floor, each with
        its title and level), whenever it changes (live updates)."""
        async def gen():
            last = None
            for _ in range(STREAM_ROUNDS):              # an hour, then the browser reconnects
                msg = json.dumps(stream_payload(alerts()))
                if msg != last:
                    last = msg
                    yield f"data: {msg}\n\n"
                await asyncio.sleep(2)
        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/")
    def index():
        """The new dashboard (dashboard/ built into static/app/, debate 11) once it is built;
        until then, and always at /classic, the freeze-v4 page."""
        new = os.path.join(STATIC, "app", "index.html")
        # no-cache: a rebuilt page (new hashed file names) must never be hidden by an old cached copy
        return FileResponse(new if os.path.exists(new) else os.path.join(STATIC, "index.html"),
                            headers={"Cache-Control": "no-cache"})

    @app.get("/classic")
    def classic():
        return FileResponse(os.path.join(STATIC, "index.html"))

    from .public import router as public_router
    from .scoreboard import router as scoreboard_router
    from .words import router as words_router
    app.include_router(words_router)
    app.include_router(public_router)
    app.include_router(scoreboard_router)
    from .live_status import make_router as live_router
    live = live_router(events_db, alerts_db, current, clock=clock or time.time)
    observe.append(live.observe)
    app.include_router(live)
    app.include_router(warm_router)
    from .demo_mode import make_router as mode_router
    app.include_router(mode_router(mode, mode_detail))
    from .checks import make_router as checks_router
    app.include_router(checks_router(current))
    from .coverage import router as coverage_router
    app.include_router(coverage_router)
    from .twin import router as twin_router
    app.include_router(twin_router)
    # The guided tour's words (the page only places them). The tour came with Labs on the night of 2026-11-23,
    # so --no-labs, the panic switch, takes it away too: without GET /api/tour the page shows no Tour button,
    # and the top bar is exactly the rehearsed one (review of 2026-11-24).
    if labs:
        from .tour import make_router as tour_router
        app.include_router(tour_router(labs=True))

    # Labs (engine/labs/): new investigation features, each its own file under /api/labs/<name>. They only
    # READ, through this context; a lab that is broken is left out and listed at /api/labs, and nothing
    # about Labs may stop the dashboard itself.
    try:
        from .. import labs as labs_mod
        if labs:
            from .demo_mode import VM_HOSTS
            labs_mod.mount(app, labs_mod.Context(events_db, alerts_db, recordings=recordings, graph=graph_for,
                                                 story=lambda a: report_mod.alert_view(a, graph_for(a.host), hubs),
                                                 report=lambda a: content_for(a, graph_for(a.host)),
                                                 hosts=VM_HOSTS if labs_hosts == "vm" else labs_hosts))
        else:
            labs_mod.switched_off(app)
    except Exception as e:                        # the dashboard without Labs, never no dashboard
        print(f"labs: not available ({e!r})", flush=True)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def main(argv=None):
    import uvicorn
    ap = argparse.ArgumentParser(description="Analyst Lab dashboard (local only)")
    ap.add_argument("--events", required=True, help="event store (read-only), e.g. the live loop's store")
    ap.add_argument("--alerts", required=True, help="alert database")
    ap.add_argument("--port", type=int, default=8780)
    ap.add_argument("--pool", default=report_mod.DEFAULT_POOL, help="pool of normal rates for hypotheses (layer 2)")
    ap.add_argument("--no-hubs", action="store_true", help="switch hub suppression off")
    ap.add_argument("--demo", choices=["live"], help="demo mode: LIVE badge + projector guard (VM data only)")
    ap.add_argument("--no-warm", action="store_true", help="demo mode without the warm test machine's buttons")
    ap.add_argument("--no-labs", action="store_true", help="start without any lab (the Labs entry disappears; the rehearsed screens are untouched)")
    ap.add_argument("--labs-all-hosts", action="store_true",
                    help="let labs show every machine in the store, not only the lab's test machine (off by default; never for a demo)")
    ap.add_argument("--warm-no-disc-change", action="store_true",
                    help="the warm machine's no-disc-change path (a trial, off by default; the same as ANALYSTLAB_WARM_NO_DISC=1)")
    a = ap.parse_args(argv)
    report_mod.official_or_exit(a.pool, a.no_hubs)        # official run: everything frozen must be in place
    if a.demo:
        from .demo_mode import projector_problems
        problems = projector_problems(a.events)
        if problems:
            raise SystemExit("Refusing (projector guard): " + "; ".join(problems))
    warm = None
    if a.demo == "live" and not a.no_warm:        # the warm test machine: the live demo dashboard only (demo/warm_vm.py)
        sys.path.insert(0, os.path.join(PROJECT_ROOT, "demo"))
        try:
            from warm_vm import WarmSession
            warm = WarmSession(owner="dashboard", no_disc=True if a.warm_no_disc_change else None)   # None: the environment's switch, off by default
            # a restart must not forget a machine this dashboard started (or claim one it did not)
            print(f"warm test machine at start-up: {warm.adopt()}")
            print("warm test machine, path for new sessions: " + ("NO DISC CHANGE (trial: tests are named by a signal)" if warm.status().get("no_disc") or getattr(warm, "_want_no_disc", False)
                                                              else "a CD per test (the default)"))
        except Exception as e:                    # never a reason not to start the dashboard
            print(f"warm test machine not available: {e!r}")
    keep_awake = None
    if a.demo == "live":                          # the live demo dashboard only: a frozen test machine is the demo's worst case
        from .awake import windows_setter
        keep_awake = windows_setter()
    app = create_app(a.events, a.alerts, hypotheses=report_mod.layer2_from(a.pool),
                     hubs=None if a.no_hubs else config.hubs(), allowed_hosts=DASHBOARD_HOSTS, mode=a.demo, warm=warm,
                     keep_awake=keep_awake, labs=not a.no_labs, labs_hosts=None if a.labs_all_hosts else "vm")
    print("labs: " + ("OFF (--no-labs)" if a.no_labs else "on, every machine in the store (--labs-all-hosts)" if a.labs_all_hosts
                      else "on, the lab's test machine only"))
    print(f"Analyst Lab dashboard: http://127.0.0.1:{a.port}")
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
