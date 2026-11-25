"""Labs can't harm the dashboard, and show the test machine's data only (night plan rules 11 and 13).

- a deliberately broken fixture lab (tests/labs/fixture_labs/broken.py) is left out, named, and everything
  else works: the dashboard's own screens and the other labs;
- `--no-labs`: no lab is loaded, the page is told so, the rehearsed routes are untouched;
- by default the context hands out the lab VM's data only; another machine's rows, alerts, graph and reports
  are out of a lab's reach unless the dashboard was started with --labs-all-hosts.
Fixtures only: made-up stores with made-up machine names."""

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import labs
from engine.alerts import AlertStore
from engine.dashboard import app as dash
from engine.dashboard.app import create_app
from engine.dashboard.demo_mode import VM_HOSTS
from engine.store import EventStore
from tests.test_detect import ev
from tests.test_report import s1_like

VM = sorted(VM_HOSTS)[0]


class NoRun:
    log, started, lock = None, None, None

    def status(self):
        return type("S", (), {"running": False, "scenario": None, "started": None, "exit_code": None, "log_tail": []})()


@pytest.fixture
def two_machines(tmp_path):
    """A store with the s1-like story on a machine called "h1" (it stands for a laptop) and a few rows of the
    lab VM, with one alert of each."""
    con, laptop_alert, _ = s1_like(tmp_path)
    con.close()
    events = str(tmp_path / "s.db")
    st = EventStore(events)
    st.insert([ev(1, 100, host=VM, ProcessGuid="{V1}", ParentProcessGuid="{V0}", Image="C:\\t\\test.exe", ProcessId=50),
               ev(3, 101, host=VM, ProcessGuid="{V1}", Image="C:\\t\\test.exe", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765),
               ev(11, 102, host=VM, ProcessGuid="{V1}", Image="C:\\t\\test.exe", TargetFilename="C:\\t\\out.exe")])
    st.close()
    import dataclasses
    con = sqlite3.connect(events)
    key = con.execute("SELECT dedup_key FROM events WHERE host = ? ORDER BY id LIMIT 1", (VM,)).fetchone()[0]
    counts = dict(con.execute("SELECT host, COUNT(*) FROM events GROUP BY host"))
    con.close()
    vm_alert = dataclasses.replace(laptop_alert, host=VM, incident="the VM's own", evidence=(key,))
    s = AlertStore(str(tmp_path / "a.db"))
    s.write([laptop_alert, vm_alert])
    s.close()
    return events, str(tmp_path / "a.db"), laptop_alert, vm_alert, counts


def dashboard(two, tmp_path, **kw):
    return TestClient(create_app(two[0], two[1], recordings=str(tmp_path / "rec"), runner=NoRun(), **kw))


# ---------------------------------------------------------------- one broken lab never harms the rest

def test_a_deliberately_broken_lab_is_left_out_and_the_dashboard_and_the_other_labs_work(two_machines, tmp_path, monkeypatch, capsys):
    real = labs.discover
    monkeypatch.setattr(labs, "discover", lambda package=None: real("tests.labs.fixture_labs"))
    c = dashboard(two_machines, tmp_path)
    listing = c.get("/api/labs").json()
    assert listing["enabled"] is True and listing["labs"] == [{"name": "fine", "prefix": "/api/labs/fine"}]
    assert listing["left_out"] == [{"name": "broken", "problem": "could not be loaded: RuntimeError: this lab is broken on purpose"}]
    assert "labs: 'broken' left out" in capsys.readouterr().out                      # and it is in the server's own output
    assert c.get("/api/labs/fine").json()["lab"] == "fine"                             # the other lab works
    assert c.get("/api/labs/broken").status_code == 404
    for path in ("/api/alerts", "/api/health", "/api/run/steps", "/api/words", "/api/tour", "/api/mode"):
        assert c.get(path).status_code == 200, path                                   # and so does every rehearsed screen's data
    assert c.get("/").status_code == 200


def test_a_lab_that_cannot_be_included_is_left_out_like_one_that_cannot_be_loaded(tmp_path, monkeypatch):
    app = FastAPI()
    real = app.include_router

    def include(router, *a, **k):
        if getattr(router, "prefix", "") == "/api/labs/fine":
            raise ValueError("a route of this lab can't be added")
        return real(router, *a, **k)

    monkeypatch.setattr(app, "include_router", include)
    listing = labs.mount(app, labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-a.db")), package="tests.labs.fixture_labs")
    assert listing["labs"] == [] and {b["name"]: b["problem"] for b in listing["left_out"]} == {
        "broken": "could not be loaded: RuntimeError: this lab is broken on purpose",
        "fine": "could not be included: ValueError: a route of this lab can't be added"}
    assert TestClient(app).get("/api/labs").json() == listing


# ---------------------------------------------------------------- the panic button

def test_no_labs_loads_no_lab_tells_the_page_and_leaves_the_rehearsed_routes_alone(two_machines, tmp_path, monkeypatch):
    on, off = dashboard(two_machines, tmp_path), dashboard(two_machines, tmp_path, labs=False)
    assert off.get("/api/labs").json() == {"enabled": False, "labs": [], "left_out": [], "hosts": []}
    assert off.get("/api/labs/glance").status_code == 404 and on.get("/api/labs/glance").status_code == 200
    paths = lambda c: sorted(p for p in c.get("/openapi.json").json()["paths"] if not p.startswith("/api/labs"))      # noqa: E731
    # everything that is not Labs is exactly the same, but for the guided tour: it came with Labs, and the
    # panic switch takes it away too (the page shows no Tour button without GET /api/tour: Tour.tsx)
    assert [p for p in paths(on) if p not in paths(off)] == ["/api/tour"] and set(paths(off)) < set(paths(on))
    assert off.get("/api/tour").status_code == 404 and on.get("/api/tour").status_code == 200
    assert "labs" in [s["screen"] for s in on.get("/api/tour").json()["steps"]]
    assert off.get("/api/alerts").json() == on.get("/api/alerts").json()
    for path in ("/api/alerts", "/api/health", "/api/run/steps", "/api/words", "/api/mode", "/api/scoreboard", "/"):
        assert off.get(path).status_code == 200, path                                # the rehearsed screens' own data is all there
    import os
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(root, "dashboard", "src", "ui2", "Tour.tsx"), encoding="utf-8") as f:
        page = f.read()
    assert "api.tour().then(setTour).catch(() => setTour(null))" in page and "if (!tour || steps.length === 0) return null;" in page
    # (the tour's own three-page wording, for a dashboard that would keep the tour without Labs, still stands)
    from engine.dashboard import tour as T
    bare = FastAPI()
    bare.include_router(T.make_router(labs=False))
    t_on, t_off = on.get("/api/tour").json()["steps"], TestClient(bare).get("/api/tour").json()["steps"]
    assert [s["screen"] for s in t_off].count("labs") == 0 and len(t_off) == len(t_on) - 1
    assert "four pages" in t_on[0]["text"] and "three pages" in t_off[0]["text"] and "Labs" not in t_off[0]["text"]
    assert t_off[1:] == [s for s in t_on[1:] if s["screen"] != "labs"]
    # the switch on the command line, off by default (the demo launcher passes neither switch)
    seen = {}
    monkeypatch.setattr(dash.report_mod, "official_or_exit", lambda *a: None)
    monkeypatch.setattr(dash.report_mod, "layer2_from", lambda pool: None)
    monkeypatch.setattr(dash, "create_app", lambda *a, **kw: seen.update(kw) or object())
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    base = ["--events", two_machines[0], "--alerts", two_machines[1], "--no-hubs"]
    dash.main(base)
    assert seen["labs"] is True and seen["labs_hosts"] == "vm"
    dash.main(base + ["--no-labs"])
    assert seen["labs"] is False
    dash.main(base + ["--labs-all-hosts"])
    assert seen["labs"] is True and seen["labs_hosts"] is None


# ---------------------------------------------------------------- the test machine's data only, by default

def test_by_default_a_lab_is_handed_the_test_machines_data_only(two_machines, tmp_path):
    events, alerts, laptop_alert, vm_alert, counts = two_machines
    c = dashboard(two_machines, tmp_path)
    ctx = labs.context()
    assert ctx.hosts == VM_HOSTS and c.get("/api/labs").json()["hosts"] == [VM]
    with ctx.reading() as con:
        assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == counts[VM] == 3
        assert {h for (h,) in con.execute("SELECT DISTINCT host FROM events")} == {VM}
        assert con.execute("SELECT COUNT(*) FROM events WHERE Image LIKE '%fetch.exe'").fetchone()[0] == 0        # the other machine's rows are not there
        with pytest.raises(sqlite3.OperationalError):                                 # ... and the store is still read-only
            con.execute("DELETE FROM main.events")
    assert [a.alert_id for a in ctx.alerts()] == [vm_alert.alert_id] and ctx.alert(laptop_alert.alert_id) is None
    assert [a.alert_id for a in ctx.shown_alerts()] == [vm_alert.alert_id]
    other_key = sqlite3.connect(events).execute("SELECT dedup_key FROM events WHERE host = 'h1' LIMIT 1").fetchone()[0]
    assert ctx.event(other_key) is None and ctx.event(vm_alert.evidence[0])["host"] == VM
    for ask, what in ((lambda: ctx.graph("h1"), "the graph"), (lambda: ctx.graph(None), "the graph"),
                      (lambda: ctx.story(laptop_alert), "an alert"), (lambda: ctx.report(laptop_alert), "an alert")):
        with pytest.raises(PermissionError, match="the test machine's data only"):
            ask()
    assert ctx.graph(VM).number_of_nodes() > 0 and ctx.report(vm_alert)["summary"] is not None
    assert ctx.host_sql() == ("host IN (?)", [VM]) and ctx.host_sql("e.host") == ("e.host IN (?)", [VM])
    g = c.get("/api/labs/glance").json()                                              # the example lab counts the test machine only
    assert g["events"] == 3 and g["hosts"] == 1 and g["alerts"] == 1
    # the dashboard's own screens are not Labs: they show what they always showed
    assert len(c.get("/api/alerts").json()) == 2


def test_other_machines_are_reachable_only_with_the_explicit_switch(two_machines, tmp_path):
    events, alerts, laptop_alert, vm_alert, counts = two_machines
    c = dashboard(two_machines, tmp_path, labs_hosts=None)
    ctx = labs.context()
    assert ctx.hosts is None and c.get("/api/labs").json()["hosts"] is None and ctx.host_sql() == ("1=1", [])
    with ctx.reading() as con:
        assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == sum(counts.values())
    assert len(ctx.alerts()) == 2 and ctx.report(laptop_alert)["summary"] is not None and ctx.graph("h1").number_of_nodes() > 0
    # a list of machines can be given too; a machine that is not on it stays out
    only = labs.Context(events, alerts, hosts={"h1"})
    with only.reading() as con:
        assert {h for (h,) in con.execute("SELECT DISTINCT host FROM events")} == {"h1"}
    assert [a.host for a in only.alerts()] == ["h1"] and not only.allows(VM)
    nobody = labs.Context(events, alerts, hosts=set())
    with nobody.reading() as con:
        assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert nobody.alerts() == [] and nobody.host_sql() == ("0=1", [])


def test_the_one_place_a_lab_may_write_is_the_case_boards_folder(tmp_path):
    ctx = labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-a.db"), recordings=str(tmp_path / "rec"))
    assert ctx.cases_dir == str(tmp_path / "rec" / "cases")
    assert labs.Context("e", "a").cases_dir is None
    assert "recordings/cases/" in labs.__doc__ and "ONE EXCEPTION" in labs.__doc__


def test_a_lab_named_like_a_python_builtin_or_like_the_registrys_own_names_is_never_imported(tmp_path, monkeypatch):
    """Found by night-explain: engine/labs/next.py replaced the builtin next() for the whole package, and
    every lab's ctx.alert() failed. A file with such a name is left out BEFORE it is imported."""
    import builtins
    import sys
    import textwrap
    pkg = tmp_path / "named_labs"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("mount = 'a name this made-up package itself uses'\n", encoding="utf-8")
    lab = textwrap.dedent('''
        from fastapi import APIRouter
        router = APIRouter(prefix="/api/labs/{name}")
        @router.get("")
        def hello():
            return {{"lab": "{name}"}}
    ''')
    for name in ("next", "open", "filter", "list", "print", "class", "mount", "whatnext"):
        (pkg / f"{name}.py").write_text(lab.format(name=name), encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    good, bad = labs.discover("named_labs")
    assert [n for n, _ in good] == ["whatnext"]
    assert sorted(b["name"] for b in bad) == ["class", "filter", "list", "mount", "next", "open", "print"]
    assert all("rename the file" in b["problem"] for b in bad)
    assert not any(m.startswith("named_labs.") and m != "named_labs.whatnext" for m in sys.modules)      # never imported
    import named_labs
    assert named_labs.mount == "a name this made-up package itself uses"                                 # ... so nothing was replaced
    for m in ("named_labs", "named_labs.whatnext"):
        sys.modules.pop(m, None)
    # the real package: every builtin is still itself, and a second look finds the same labs (an imported lab is not "taken")
    first = [n for n, _ in labs.discover()[0]]
    assert labs.discover()[1] == [] and [n for n, _ in labs.discover()[0]] == first and "glance" in first
    for name in ("next", "sorted", "any", "print", "open", "filter", "list", "map"):
        assert getattr(labs, name, getattr(builtins, name)) is getattr(builtins, name), name
    # and even with the builtin replaced in the package, finding one alert still works
    monkeypatch.setattr(labs, "next", object(), raising=False)
    assert labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-a.db")).alert("nope") is None
