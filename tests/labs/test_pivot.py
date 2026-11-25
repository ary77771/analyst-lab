"""Labs, pivot on anything (engine/labs/pivot.py), on a made-up story (tests/labs/pivotfix.py)."""

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import pivot as P
from tests.labs.pivotfix import FETCH, HASH, LAPTOP, VM, RUNKEY, TOOL, ZERO, FakeContext, story, use


def open_ro(path):
    return sqlite3.connect("file:" + path.replace("\\", "/") + "?mode=ro", uri=True)


@pytest.fixture
def world(tmp_path, monkeypatch):
    events_db, alerts_db, alert, keys = story(tmp_path)
    ctx = FakeContext(events_db, alerts_db)
    use(monkeypatch, ctx)                                # the labs read this context, never a stale global one
    return ctx, alert, keys


def run(ctx, kind, value, **kw):
    con = ctx.events()
    try:
        return P.pivot(con, ctx.alerts(), kind, value, **kw)
    finally:
        con.close()


def test_hash_found_in_the_agent_fingerprint_and_in_sysmon_hashes(world):
    ctx, alert, keys = world
    r = run(ctx, "hash", HASH.upper())            # any case in, one value out
    assert r["value"] == HASH and r["total"] == 2
    assert {e["key"] for e in r["events"]} == {keys[4], keys[5]}
    assert any(e["kind"] == "file" and e["value"] == TOOL for e in r["linked"])
    assert [a["id"] for a in r["alerts"]] == [alert.alert_id]
    assert "1 of its evidence events" in r["alerts"][0]["why"]


def test_program_shows_its_events_children_and_the_unknown_parent_as_a_gap(world):
    ctx, alert, keys = world
    r = run(ctx, "program", FETCH.upper())        # paths ignore case
    assert r["total"] == 5                         # its start, lookup, connection, file, and the child's start
    assert [p["guid"] for p in r["processes"]] == ["{F}", "{C}"]
    assert [c["guid"] for c in r["children"]] == ["{C}"]
    assert all(p["guid"] != ZERO for p in r["parents"])
    assert any(g["what"] == "parent unknown" for g in r["gaps"])
    linked = {(e["kind"], e["value"]) for e in r["linked"]}
    assert {("domain", "test.lab.example"), ("ip", "10.0.2.2"), ("file", TOOL), ("user", "LAB\\u")} <= linked
    assert not any(e["value"] == ZERO for e in r["linked"])
    assert ("program", FETCH) not in linked           # the pivot itself is not listed as linked to itself


def test_a_run_named_only_by_its_id_gets_its_program(world):
    """Critique 2026-11-24: the fingerprint row carries only the writer's id (in another case): the run is
    fetch.exe, found from its own start record, and the two spellings are one run."""
    ctx, _, _ = world
    r = run(ctx, "hash", HASH)                     # here only the fingerprint row names fetch.exe's run
    assert [p["label"] for p in r["processes"]] == ["fetch.exe (PID 10)", "tool.exe (PID 11)"]
    assert [p["label"] for p in run(ctx, "file", TOOL)["processes"]] == ["fetch.exe (PID 10)", "tool.exe (PID 11)"]
    assert run(ctx, "process", "{f}")["total"] == run(ctx, "process", "{F}")["total"] >= 6     # either case finds it


def test_one_run_lists_its_parent_by_id(world):
    ctx, _, _ = world
    r = run(ctx, "process", "{C}")
    assert [p["guid"] for p in r["parents"]] == ["{F}"] and r["parents"][0]["label"] == "fetch.exe (PID 10)"


def test_ip_domain_registry_user_and_file(world):
    ctx, alert, keys = world
    assert run(ctx, "ip", "10.0.2.2")["total"] == 1
    assert run(ctx, "domain", "TEST.lab.example")["total"] == 1
    reg = run(ctx, "registry", RUNKEY.lower())
    assert reg["total"] == 1 and reg["events"][0]["summary"].startswith("tool.exe (PID 11) set registry key")
    assert run(ctx, "user", "lab\\u")["total"] == 5 and run(ctx, "user", "LAB\\other")["total"] == 1
    f = run(ctx, "file", TOOL)
    assert f["total"] == 4                        # created, fingerprinted, run, and its registry write (as the program)
    assert {a["id"] for a in f["alerts"]} == {alert.alert_id}


def test_nothing_found_and_bad_input(world):
    ctx, _, _ = world
    r = run(ctx, "hash", "cd" * 32)
    assert r["total"] == 0 and r["events"] == [] and r["alerts"] == []
    with pytest.raises(ValueError):
        run(ctx, "colour", "red")
    with pytest.raises(ValueError):
        run(ctx, "file", "   ")


def test_limit_says_how_many_are_shown(world):
    ctx, _, _ = world
    r = run(ctx, "user", "LAB\\u", limit=2)
    assert r["total"] == 5 and r["shown"] == 2 and len(r["events"]) == 2


def test_host_filter(world):
    ctx, _, _ = world
    assert run(ctx, "program", FETCH, host=VM)["total"] == 5
    assert run(ctx, "program", FETCH, host="other")["total"] == 0


def test_laptop_data_is_hidden_unless_the_dashboard_allows_every_machine(world, monkeypatch):
    """Night rule 11: the machines come from labs.context().hosts only (the lab VM's by default); the laptop's
    records and alerts appear only when the dashboard itself allows every machine (--labs-all-hosts)."""
    ctx, alert, keys = world
    monkeypatch.setenv("ANALYSTLAB_LABS_LAPTOP", "1")                  # the old switch of this lab: ignored now
    r = run(ctx, "hash", HASH)
    assert r["total"] == 2 and keys[8] not in {e["key"] for e in r["events"]}
    assert run(ctx, "program", FETCH, host=LAPTOP)["total"] == 0           # asking for the laptop is not enough
    assert run(ctx, "user", "LAPTOP\\me")["total"] == 0
    assert [a["id"] for a in run(ctx, "program", FETCH)["alerts"]] == [alert.alert_id]
    con = ctx.events()
    try:
        assert all(e["value"] != "LAPTOP\\me" for e in P.search(con, "laptop"))
        assert [s["id"] for s in P.starts(con, ctx.alerts())] == [alert.alert_id]
    finally:
        con.close()
    ctx.hosts = None                                                     # a dashboard started with --labs-all-hosts
    r = run(ctx, "hash", HASH)
    assert r["total"] == 3 and keys[8] in {e["key"] for e in r["events"]}
    assert len(run(ctx, "program", FETCH)["alerts"]) == 2
    ctx.hosts = frozenset({LAPTOP})                                      # whatever the dashboard says, exactly
    assert run(ctx, "hash", HASH)["total"] == 1


def test_without_a_dashboard_only_the_lab_vm(world, monkeypatch):
    """No running dashboard (or a context that does not say): the lab VM's names, never every machine."""
    ctx, alert, keys = world
    def no_dashboard():
        raise RuntimeError("no dashboard is running in this process")
    monkeypatch.setattr(P, "_context", no_dashboard)
    assert P.allowed_hosts() == frozenset({VM})
    assert run(ctx, "hash", HASH)["total"] == 2

def test_search_and_starts(world):
    ctx, alert, _ = world
    con = ctx.events()
    try:
        found = P.search(con, "tool")
        assert {(e["kind"], e["value"]) for e in found} >= {("program", TOOL), ("file", TOOL)}
        assert P.search(con, "x") == []
        assert ("hash", HASH) in {(e["kind"], e["value"].lower()) for e in P.search(con, HASH)}
        st = P.starts(con, ctx.alerts())
        assert st[0]["id"] == alert.alert_id
        assert ("file", TOOL) in {(e["kind"], e["value"]) for e in st[0]["entities"]}
    finally:
        con.close()


def test_the_store_is_never_written(world):
    """The pivot reads through a read-only connection: a write on it must fail (proves the guard is real)."""
    ctx, _, _ = world
    con = ctx.events()
    try:
        run(ctx, "program", FETCH)
        with pytest.raises(sqlite3.OperationalError):
            con.execute("DELETE FROM events")
    finally:
        con.close()


def test_routes(world, monkeypatch):
    ctx, alert, _ = world
    app = FastAPI()
    app.include_router(P.router)
    c = TestClient(app)
    r = c.get("/api/labs/pivot", params={"kind": "hash", "value": HASH})
    assert r.status_code == 200 and r.json()["total"] == 2
    assert c.get("/api/labs/pivot", params={"kind": "nope", "value": "x"}).status_code == 400
    assert c.get("/api/labs/pivot", params={"kind": "file", "value": " "}).status_code == 400
    assert {k["kind"] for k in c.get("/api/labs/pivot/kinds").json()} == set(P.KINDS)
    assert c.get("/api/labs/pivot/search", params={"q": "fetch"}).json()
    assert c.get("/api/labs/pivot/starts").json()[0]["id"] == alert.alert_id


def test_summaries_and_entities_of_a_row():
    row = {"event_id": 3, "Image": FETCH, "ProcessId": 10, "DestinationIp": "10.0.2.2", "DestinationPort": 18765,
           "ProcessGuid": "{F}", "ParentProcessGuid": ZERO}
    assert P.summary(row) == "fetch.exe (PID 10) connected to 10.0.2.2:18765"
    assert P.summary({**row, "DestinationHostname": "-"}) == "fetch.exe (PID 10) connected to 10.0.2.2:18765"
    kinds = [(e["kind"], e["value"]) for e in P.entities_of(row)]
    assert ("ip", "10.0.2.2") in kinds and ("process", ZERO) not in kinds
    assert all(e["value"] != "-" for e in P.entities_of({**row, "DestinationHostname": "-"}))   # Sysmon's "not known"


def test_alert_list_is_capped_but_counted(world, monkeypatch):
    ctx, alert, _ = world
    monkeypatch.setattr(P, "ALERT_LIMIT", 0)
    r = run(ctx, "hash", HASH)
    assert r["alerts_total"] == 1 and r["alerts"] == []


def clock_store(tmp_path):
    """fetch.exe: a connection WRITTEN at +3 s that HAPPENED at +1 s, a file written at +2 s, the recorder's own
    fingerprint at +2.5 s (no UtcTime, "T" spelling), a report back to the laptop and a VBoxControl start."""
    from engine.store import EventStore
    from tests.test_detect import ev
    recs = [
        ev(1, 0, host=VM, ProcessGuid="{F}", Image=FETCH, ProcessId=10, happened=0),
        ev(3, 3, host=VM, ProcessGuid="{F}", Image=FETCH, Initiated="true", DestinationIp="10.0.2.2",
           DestinationPort=18765, happened=1),
        ev(11, 2, host=VM, ProcessGuid="{F}", Image=FETCH, TargetFilename=TOOL, happened=2),
        {"host": VM, "session": "s", "seq": 1, "time": "2026-10-22T10:00:02.500000Z", "type": "FILE_HASH",
         "source": "agent", "data": {"sha256": HASH, "hash_status": "ok", "TargetFilename": TOOL, "ProcessGuid": "{F}"}},
        ev(22, 3.5, host=VM, ProcessGuid="{F}", Image=FETCH, QueryName="after.lab.example", happened=3.5),   # after it
        ev(3, 4, host=VM, ProcessGuid="{F}", Image=FETCH, Initiated="true", DestinationIp="10.0.2.2",
           DestinationPort=8770, happened=4),                                           # the report back: machinery
        ev(1, 5, host=VM, ProcessGuid="{V}", ParentProcessGuid="{F}", ParentImage=FETCH,
           Image=r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe", ProcessId=20, happened=5),
    ]
    path = str(tmp_path / "clock.db")
    st = EventStore(path)
    st.insert(recs)
    st.close()
    return FakeContext(path, str(tmp_path / "none.db"))


def test_one_clock_puts_the_connection_before_the_file(tmp_path, monkeypatch):
    """Night 2 shared clock (engine/labs/_shared_defs.py): Sysmon's UtcTime first, so the connection that fetched
    the file comes before the file, although Windows wrote it down later; the recorder's row sorts among them."""
    ctx = clock_store(tmp_path)
    use(monkeypatch, ctx)
    con = ctx.events()
    try:
        r = P.pivot(con, [], "process", "{F}")
    finally:
        con.close()
    assert [e["event_id"] or e["type"] for e in r["events"]] == [1, 3, 11, "FILE_HASH", 22]
    assert r["events"][1]["time"].startswith("2026-10-22T10:00:01")                     # when it happened


def test_the_test_machinery_is_hidden_unless_asked(tmp_path, monkeypatch):
    ctx = clock_store(tmp_path)
    use(monkeypatch, ctx)
    con = ctx.events()
    try:
        r = P.pivot(con, [], "process", "{F}")
        assert r["machinery_hidden"] == 2 and r["total"] == 5                             # report back + VBoxControl
        assert not any("8770" in e["summary"] for e in r["events"])
        assert [c["label"] for c in r["children"]] == []                                  # VBoxControl's start is hidden
        assert r["words"]["machinery_switch"] == "show the test machinery"
        all_ = P.pivot(con, [], "process", "{F}", machinery=True)
        assert all_["machinery_hidden"] == 0 and all_["total"] == 7
        assert not any(e["value"].lower().endswith("vboxcontrol.exe") for e in P.search(con, "vbox"))
        assert any(e["value"].lower().endswith("vboxcontrol.exe") for e in P.search(con, "vbox", machinery=True))
    finally:
        con.close()
