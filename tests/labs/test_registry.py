"""The Labs registry (engine/labs/__init__.py): labs are found by themselves, they only read, and a broken
lab never harms the dashboard. Fixtures only: a made-up event store and alert database."""

import os
import sqlite3
import sys
import textwrap

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from engine import labs
from engine.dashboard.app import create_app


class NoRun:
    log, started, lock = None, None, None

    def status(self):
        return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()


@pytest.fixture
def stores(tmp_path):
    """A small store with the s1-like story the report tests use, and its alert."""
    from tests.test_report import s1_like
    con, alert, _ = s1_like(tmp_path)
    con.close()
    from engine.alerts import AlertStore
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    return events, str(tmp_path / "alerts.db"), alert


def app_of(stores, tmp_path):
    events, alerts, _ = stores
    # (the fixture's machine is called "h1", not the lab VM: these tests are about the registry, so the limit to
    # the test machine's data, tests/labs/test_isolation.py, is lifted here)
    return TestClient(create_app(events, alerts, recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None))


def test_the_dashboard_finds_the_example_lab_by_itself(stores, tmp_path):
    c = app_of(stores, tmp_path)
    listing = c.get("/api/labs").json()
    assert {"name": "glance", "prefix": "/api/labs/glance"} in listing["labs"] and listing["left_out"] == []
    g = c.get("/api/labs/glance").json()
    assert g["empty"] is False and g["events"] > 0 and g["hosts"] == 1 and g["alerts"] == 1 and g["first"] <= g["last"]
    assert g["levels"] == [{"level": stores[2].level, "count": 1}] and g["words"]["title"]
    assert set(g) == {"words", "events", "hosts", "programs", "first", "last", "empty", "alerts", "shown", "min_level", "levels"}     # counts only


def test_the_rehearsed_routes_are_exactly_what_they_were(stores, tmp_path):
    """Labs add routes under /api/labs and nothing else."""
    c = app_of(stores, tmp_path)
    paths = sorted(c.get("/openapi.json").json()["paths"])
    labs_paths = [p for p in paths if "labs" in p]
    # every lab's route lives under /api/labs/<lab> (more labs may be merged); the listing and the example stay
    assert all(p == "/api/labs" or p.startswith("/api/labs/") for p in labs_paths), labs_paths
    assert {"/api/labs", "/api/labs/glance"} <= set(labs_paths)
    for known in ("/api/alerts", "/api/alerts/{alert_id}", "/api/alerts/{alert_id}/film", "/api/health", "/api/run/steps", "/api/warm", "/api/words"):
        assert known in paths, known
    assert c.get("/api/alerts").status_code == 200 and c.get("/").status_code == 200


def test_the_context_reads_what_the_dashboard_reads_and_can_write_nothing(stores, tmp_path):
    events, alerts, alert = stores
    c = app_of(stores, tmp_path)
    ctx = labs.context()
    assert ctx.events_db == events and ctx.alerts_db == alerts
    assert [a.alert_id for a in ctx.alerts()] == [alert.alert_id] and ctx.alert(alert.alert_id).title == alert.title and ctx.alert("nope") is None
    with ctx.reading() as con:
        n = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        with pytest.raises(sqlite3.OperationalError):                       # read-only: SQLite itself refuses
            con.execute("DELETE FROM events")
        with pytest.raises(sqlite3.OperationalError):
            con.execute("CREATE TABLE x (a)")
        key = con.execute("SELECT dedup_key FROM events LIMIT 1").fetchone()[0]
    assert n > 0 and ctx.event(key)["dedup_key"] == key and ctx.event("no such key") is None
    # the graph, the alert's own view and its report are the dashboard's own
    seed, _, H = ctx.story(alert)
    assert seed and any(d.get("depth") == 0 for _, d in H.nodes(data=True)) and ctx.graph(alert.host).number_of_nodes() >= H.number_of_nodes()
    api = c.get(f"/api/alerts/{alert.alert_id}").json()
    assert ctx.report(alert)["summary"] == api["report"]["summary"] and len(ctx.report(alert)["timeline"]) == len(api["report"]["timeline"])
    assert [a.alert_id for a in ctx.shown_alerts()] == [r["id"] for r in c.get("/api/alerts").json()]


def test_a_broken_lab_is_left_out_and_said_and_never_takes_a_route(tmp_path, monkeypatch, capsys):
    pkg = tmp_path / "madeup_labs"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    good = '''
        from fastapi import APIRouter
        router = APIRouter(prefix="/api/labs/{name}")
        @router.get("")
        def hello():
            return {{"lab": "{name}"}}
        @router.get("/more/{{x}}")
        def more(x: str):
            return {{"x": x}}
    '''
    (pkg / "fine.py").write_text(textwrap.dedent(good.format(name="fine")), encoding="utf-8")
    (pkg / "crashes.py").write_text("raise RuntimeError('a lab that fails while it is loaded')\n", encoding="utf-8")
    (pkg / "norouter.py").write_text("x = 1\n", encoding="utf-8")
    (pkg / "elsewhere.py").write_text(textwrap.dedent(good.format(name="fine")), encoding="utf-8")            # another lab's prefix
    (pkg / "grabby.py").write_text("from fastapi import APIRouter\nrouter = APIRouter(prefix='/api')\n"
                                   "@router.get('/alerts')\ndef mine():\n    return ['taken over']\n", encoding="utf-8")
    (pkg / "_private.py").write_text("raise RuntimeError('never loaded: its name starts with _')\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    app = FastAPI()

    @app.get("/api/alerts")
    def real():
        return ["the dashboard's own"]

    listing = labs.mount(app, labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-a.db")), package="madeup_labs")
    assert listing["labs"] == [{"name": "fine", "prefix": "/api/labs/fine"}]
    problems = {b["name"]: b["problem"] for b in listing["left_out"]}
    assert set(problems) == {"crashes", "norouter", "elsewhere", "grabby"}
    assert "could not be loaded: RuntimeError" in problems["crashes"] and "no `router`" in problems["norouter"]
    assert "/api/labs/elsewhere" in problems["elsewhere"] and "/api/labs/grabby" in problems["grabby"]
    c = TestClient(app)
    assert c.get("/api/labs/fine").json() == {"lab": "fine"} and c.get("/api/labs/fine/more/7").json() == {"x": "7"}
    assert c.get("/api/alerts").json() == ["the dashboard's own"]                  # nothing was taken over
    assert c.get("/api/labs").json() == listing and "left out" in capsys.readouterr().out
    for name in ("madeup_labs", "madeup_labs.fine", "madeup_labs.norouter", "madeup_labs.elsewhere", "madeup_labs.grabby"):
        sys.modules.pop(name, None)


def test_a_dashboard_whose_labs_fail_altogether_still_starts(stores, tmp_path, monkeypatch):
    monkeypatch.setattr(labs, "mount", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("labs are broken")))
    c = app_of(stores, tmp_path)
    assert c.get("/api/alerts").status_code == 200 and c.get("/api/labs").status_code == 404


def test_the_context_says_plainly_what_is_missing(tmp_path):
    ctx = labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-a.db"))
    assert ctx.alerts() == [] and ctx.event("k") is None
    with pytest.raises(FileNotFoundError, match="no event store yet"):
        ctx.events()
    with pytest.raises(RuntimeError, match="without the evidence graph"):
        ctx.graph("h")
    labs.configure(ctx)
    c = TestClient(_only_glance())
    g = c.get("/api/labs/glance").json()
    assert g["empty"] is True and g["events"] == 0 and g["alerts"] == 0 and g["levels"] == []


def _only_glance():
    from engine.labs import glance
    app = FastAPI()
    app.include_router(glance.router)
    return app


def test_the_labs_package_itself_holds_no_path_into_the_recordings():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for name in os.listdir(os.path.join(root, "engine", "labs")):
        if name.endswith(".py"):
            with open(os.path.join(root, "engine", "labs", name), encoding="utf-8") as f:
                text = f.read()
            assert "recordings/" not in text.replace("recordings/ ", "").replace("or recordings/;", "") or name == "__init__.py", name
    assert isinstance(labs.discover()[0][0][1], APIRouter)
