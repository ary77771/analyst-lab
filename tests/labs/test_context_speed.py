"""The Labs context's two speed fixes (night-hunt's audit, 2026-11-24; engine/labs/__init__.py):
  1. an alert's report and story are built once while the stores have not changed, and every caller still gets
     its own copy;
  2. within one request every ctx.event() uses one read-only connection, closed when the request ends.
Neither may change an answer, keep a stale one, or leave a handle on the store."""

import os
import sqlite3
import threading
import time

import networkx as nx
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from engine import labs
from engine.alerts import Alert, AlertStore
from engine.dashboard.app import create_app
from engine.store import EventStore
from tests.labs.test_registry import NoRun, stores  # noqa: F401  (a small store with one alert and its story)
from tests.test_detect import ev


def an_alert(n=1, details=None, incident="", evidence=("k1",)):
    return Alert(rule_id=f"analystlab.test{n}", title=f"alert {n}", source="analystlab", level="medium", time="2026-11-24T10:00:00Z",
                 host="vm", reason="because", evidence=evidence, details=details or {}, incident=incident)


def make_stores(tmp_path, name="e", events=3, alerts=(1,)):
    e, a = str(tmp_path / f"{name}.db"), str(tmp_path / f"{name}-alerts.db")
    s = EventStore(e)
    s.insert([ev(1, i, host="vm", Image=rf"C:\t\p{i}.exe", ProcessGuid=f"{{G{i}}}") for i in range(events)])
    s.insert([ev(1, 50, host="laptop", Image=r"C:\other\x.exe", ProcessGuid="{L}")])
    s.close()
    st = AlertStore(a)
    st.write([an_alert(n) for n in alerts])
    st.close()
    return e, a


def keys_of(db, host="vm"):
    con = sqlite3.connect(db)
    try:
        return [r[0] for r in con.execute("SELECT dedup_key FROM events WHERE host = ? ORDER BY id", (host,))]
    finally:
        con.close()


class Builds:
    """Stand-ins for the dashboard's own report and story builders, counting how often each is really called."""

    def __init__(self):
        self.reports = self.stories = 0

    def report(self, alert):
        self.reports += 1
        return {"facts": [{"id": "f1", "citations": [{"key": "k1"}]}], "timeline": [{"id": "f1"}], "built": self.reports}

    def story(self, alert):
        self.stories += 1
        H = nx.MultiDiGraph(seed=["a"], gaps=[{"node": "a"}])
        H.add_node("a", depth=0)
        H.add_edge("a", "b", key=0, kind="started", evidence=[{"key": "k1"}])
        return ["a"], "2026-11-24T10:00:00Z", H


def ctx_of(tmp_path, name="e", hosts=("vm",), **kw):
    e, a = make_stores(tmp_path, name, **kw)
    b = Builds()
    return labs.Context(e, a, report=b.report, story=b.story, hosts=hosts), b, e, a


# ---- 1. report and story: built once, own copy for every caller, never stale ------------------------------------

def test_a_report_is_built_once_and_every_caller_gets_its_own_copy(tmp_path):
    ctx, b, _, _ = ctx_of(tmp_path)
    a = an_alert()
    first = ctx.report(a)
    first["facts"].append("a lab changed what it was given")           # the FIRST caller's copy is its own too
    first["timeline"][0]["id"] = "changed"
    second = ctx.report(a)
    assert b.reports == 1
    assert second == {"facts": [{"id": "f1", "citations": [{"key": "k1"}]}], "timeline": [{"id": "f1"}], "built": 1}
    assert second is not first and second["facts"] is not ctx.report(a)["facts"]
    assert b.reports == 1 and ctx._reports.builds == 1


def test_a_story_is_built_once_and_every_caller_gets_its_own_graph(tmp_path):
    ctx, b, _, _ = ctx_of(tmp_path)
    a = an_alert()
    seed, at, H = ctx.story(a)
    H.add_node("made-up")
    H.nodes["a"]["depth"] = 99
    H.graph["gaps"].append("made-up")
    seed.append("made-up")
    seed2, at2, H2 = ctx.story(a)
    assert b.stories == 1
    assert seed2 == ["a"] and at2 == at and set(H2.nodes) == {"a", "b"} and H2.nodes["a"]["depth"] == 0
    assert H2.graph["gaps"] == [{"node": "a"}] and H2 is not H
    assert [d["kind"] for _, _, d in H2.edges(data=True)] == ["started"]


def test_a_new_event_or_a_new_alert_makes_it_be_built_again(tmp_path):
    ctx, b, e, a_db = ctx_of(tmp_path)
    a = an_alert()
    ctx.report(a), ctx.story(a), ctx.report(a)
    assert (b.reports, b.stories) == (1, 1)
    s = EventStore(e)                                                   # the recording grew by one event
    s.insert([ev(1, 99, host="vm", Image=r"C:\t\late.exe", ProcessGuid="{LATE}")])
    s.close()
    assert ctx.report(a)["built"] == 2 and ctx.report(a)["built"] == 2
    ctx.story(a)
    assert (b.reports, b.stories) == (2, 2)
    st = AlertStore(a_db)                                               # one more alert was raised
    st.write([an_alert(2)])
    st.close()
    assert ctx.report(a)["built"] == 3 and b.reports == 3


def test_an_alert_rewritten_in_place_is_not_answered_from_the_older_build(tmp_path):
    """An alert whose evidence can grow keeps its id (engine/alerts.py: `incident`): same id, same row count."""
    ctx, b, _, _ = ctx_of(tmp_path)
    early = an_alert(incident="p|1", evidence=("k1",))
    grown = an_alert(incident="p|1", evidence=("k1", "k2"))
    assert early.alert_id == grown.alert_id
    assert ctx.report(early)["built"] == 1 and ctx.report(grown)["built"] == 2
    assert ctx.report(an_alert(incident="p|1", evidence=("k1",), details={"score": 2}))["built"] == 3    # only a detail differs
    assert ctx.report(early)["built"] == 1 and b.reports == 3          # each version of the alert kept apart


def test_two_dashboards_never_share_what_they_keep(tmp_path):
    """Fixture stores often have the same alert id, newest row id and alert count: the kept reports are per Context."""
    one, b1, _, _ = ctx_of(tmp_path, "one")
    two, b2, _, _ = ctx_of(tmp_path, "two")
    a = an_alert()
    assert one._version() == two._version()                            # indistinguishable by version alone
    one.report(a), one.report(a), two.report(a)
    assert (b1.reports, b2.reports) == (1, 1)


def test_a_failed_build_keeps_nothing_and_another_machines_alert_is_still_refused(tmp_path):
    ctx, b, _, _ = ctx_of(tmp_path)
    a = an_alert()
    calls = []

    def flaky(alert):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("the graph could not be built")
        return {"ok": True}
    ctx._report = flaky
    try:
        ctx.report(a)
        raise AssertionError("the first build's error must reach the caller")
    except RuntimeError:
        pass
    assert ctx.report(a) == {"ok": True} and ctx.report(a) == {"ok": True} and len(calls) == 2
    other = Alert(rule_id="analystlab.x", title="t", source="analystlab", level="medium", time="2026-11-24T10:00:00Z", host="laptop",
                  reason="because", evidence=("k9",))
    for ask in (ctx.report, ctx.story):
        try:
            ask(other)
            raise AssertionError("labs show the test machine's data only")
        except PermissionError:
            pass


def test_without_a_readable_store_nothing_is_kept_and_it_still_answers(tmp_path):
    b = Builds()
    ctx = labs.Context(str(tmp_path / "none.db"), str(tmp_path / "none-alerts.db"), report=b.report, story=b.story, hosts=("vm",))
    a = an_alert()
    assert ctx._version() is None
    assert ctx.report(a)["built"] == 1 and ctx.report(a)["built"] == 2          # built each time, as before the fix
    assert labs.Context._alert_key(object()) is None                            # no id: nothing to keep it under


def test_two_requests_for_the_same_alert_build_it_once(tmp_path):
    ctx, b, _, _ = ctx_of(tmp_path)
    a = an_alert()
    started, release = threading.Event(), threading.Event()

    def slow(alert):
        b.reports += 1
        started.set()
        release.wait(5)
        return {"built": b.reports}
    ctx._report = slow
    out = []
    threads = [threading.Thread(target=lambda: out.append(ctx.report(a))) for _ in range(4)]
    threads[0].start()
    assert started.wait(5)
    for t in threads[1:]:
        t.start()
    time.sleep(0.15)                                                    # the other three are waiting, not building
    release.set()
    for t in threads:
        t.join(5)
    assert b.reports == 1 and out == [{"built": 1}] * 4 and len({id(x) for x in out}) == 4


def test_heavy_builds_never_run_side_by_side(tmp_path):
    """Pages opened together must not each build the graph: the graph, a story and a report are built one at a time."""
    ctx, _, _, _ = ctx_of(tmp_path)
    running, most, lock = [0], [0], threading.Lock()

    def heavy(*_):
        with lock:
            running[0] += 1
            most[0] = max(most[0], running[0])
        time.sleep(0.08)
        with lock:
            running[0] -= 1
        return {"x": 1}
    ctx._report = heavy

    def heavy_story(alert):
        heavy()
        return ["a"], "t", None
    ctx._story = heavy_story
    ctx._graph = heavy
    jobs = [lambda: ctx.report(an_alert(1)), lambda: ctx.story(an_alert(1)), lambda: ctx.graph("vm"), lambda: ctx.report(an_alert(2)),
            lambda: ctx.story(an_alert(2)), lambda: ctx.graph("vm")]
    threads = [threading.Thread(target=j) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert most[0] == 1


# ---- 2. event lookups: one connection per request, closed with it ------------------------------------------------

def test_lookups_in_one_request_share_one_connection_and_answer_as_before(tmp_path):
    ctx, _, e, _ = ctx_of(tmp_path, events=40)
    keys = keys_of(e)
    plain = [ctx.event(k) for k in keys]                                # outside a request: one connection each, as ever
    assert all(r and r["host"] == "vm" for r in plain) and len(plain) == 40
    opened = []
    real = labs.Context._open
    ctx._open = lambda any_thread=False: (opened.append(any_thread), real(ctx, any_thread))[1]
    with labs.session() as scope:
        inside = [ctx.event(k) for k in keys] + [ctx.event(k) for k in keys]        # each key twice
        assert scope.opened == 1 and opened == [True]
        assert inside == plain + plain
        row = ctx.event(keys[0])
        row["Image"] = "a lab changed its copy"
        assert ctx.event(keys[0]) == plain[0]                           # every caller's dict is its own
        assert ctx.event("no-such-key") is None and ctx.event("no-such-key") is None
        assert ctx.event(keys_of(e, "laptop")[0]) is None               # another machine's record stays invisible
    assert scope.closed and scope.cons == {}
    assert ctx.event(keys[0]) == plain[0] and opened == [True, False]   # after the request: the old way again


def test_no_handle_on_the_store_outlives_the_request(tmp_path):
    ctx, _, e, a_db = ctx_of(tmp_path)
    with labs.session():
        assert ctx.event(keys_of(e)[0]) is not None
        ctx.report(an_alert())                                          # (the version is read on its own connections)
    os.remove(e)                                                        # Windows refuses this while any handle is open
    os.remove(a_db)
    assert not os.path.exists(e)
    with labs.session():
        assert ctx.event("k") is None                                   # no store: "none", as before, never an error
    assert ctx.event("k") is None


def test_trouble_with_the_shared_connection_falls_back_to_the_old_way(tmp_path):
    ctx, _, e, _ = ctx_of(tmp_path)
    key = keys_of(e)[0]
    with labs.session() as scope:
        want = ctx.event(key)
        scope.rows.clear()
        scope.cons[ctx].close()                                         # the shared connection breaks mid-request
        assert ctx.event(key) == want                                   # answered on a connection of its own
        scope.close()                                                   # the request's scope is over, the code still asks
        assert ctx.event(key) == want


def test_a_lab_route_gets_the_scope_by_itself_and_it_is_closed_after_the_answer(tmp_path):
    ctx, _, e, _ = ctx_of(tmp_path, events=25)
    keys = keys_of(e)
    router = APIRouter(prefix="/api/labs/probe")
    seen = {}

    @router.get("")
    def probe():                                                        # a plain (threaded) route, like every lab's
        scope = labs._scope.get()
        found = sum(ctx.event(k) is not None for k in keys)
        seen["scope"] = scope
        return {"found": found, "opened": scope.opened if scope else None, "version": ctx._version() is not None}

    app = FastAPI()
    app.include_router(router, dependencies=[Depends(labs.request_scope)])      # what labs.mount() does for every lab
    d = TestClient(app).get("/api/labs/probe").json()
    assert d == {"found": 25, "opened": 1, "version": True}
    assert seen["scope"].closed and labs._scope.get() is None
    os.remove(e)                                                        # nothing is left open after the answer


def test_mount_gives_every_lab_route_the_scope(stores, tmp_path, monkeypatch):
    """The real dashboard and a real lab page: its event lookups open one shared connection, not one each."""
    events, alerts, a = stores
    shared, own, real = [], [], labs.Context._open

    def counting(self, any_thread=False):
        (shared if any_thread else own).append(1)
        return real(self, any_thread)
    monkeypatch.setattr(labs.Context, "_open", counting)
    lookups, real_event = [], labs.Context.event

    def counting_event(self, key):
        lookups.append(key)
        return real_event(self, key)
    monkeypatch.setattr(labs.Context, "event", counting_event)
    c = TestClient(create_app(events, alerts, recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None))
    r = c.get(f"/api/labs/why/{a.alert_id}")
    assert r.status_code == 200 and r.json()["story"]["available"] is True
    assert len(lookups) >= 3, "this page is expected to look up several records (else the test proves nothing)"
    assert len(shared) == 1                                             # all of them on the request's one connection
    builds = labs.context()._reports.builds
    assert c.get(f"/api/labs/why/{a.alert_id}").json() == r.json()      # the same answer again
    assert labs.context()._reports.builds == builds == 1                # and its report was not built a second time
