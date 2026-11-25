"""Night rule 11: the hunting labs show the lab VM's data only, unless the server was started with
--labs-all-hosts (labs.context().hosts is None). The fixture store also holds a made-up "laptop" machine whose program sits in
Downloads, is a renamed certutil, has an unknown parent, connects out, and has the store's newest event."""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import _huntdb as db, gaps, hunts, network, persistence, rarity
from tests.labs import hunt_fixtures as fx


def client(store, monkeypatch, all_hosts=False):
    fx.use_store(monkeypatch, store, hosts=None if all_hosts else (fx.HOST,))
    app = FastAPI()
    for m in (hunts, rarity, persistence, network, gaps):
        app.include_router(m.router)
    return TestClient(app)


PATHS = (["/api/labs/hunts/summary?window=all", "/api/labs/persistence/?window=all&show_unchanged=true",
          "/api/labs/network/?window=7d", "/api/labs/gaps/?window=all"]
         + [f"/api/labs/hunts/run/{h['id']}?window=all" for h in hunts.HUNTS]
         + [f"/api/labs/rarity/?kind={k}&window=all" for k in rarity.KINDS])


@pytest.fixture()
def store(tmp_path):
    return fx.build(tmp_path / "e.db")


def test_nothing_of_another_machine_is_shown_by_default(store, monkeypatch):
    c = client(store, monkeypatch)
    for p in PATHS:
        text = json.dumps(c.get(p).json())
        assert fx.LAPTOP not in text and "private.exe" not in text and "203.0.113.9" not in text, p
    r = c.get("/api/labs/hunts/run/user-folders?window=24h").json()
    assert r["window"]["until"] == fx.ts(fx.T_END)          # counted back from the VM's newest event, not the laptop's
    assert r["store"]["hosts"] == [fx.HOST] and "lab VM only" in r["scope"]


def test_asking_for_another_host_by_name_gives_nothing(store, monkeypatch):
    c = client(store, monkeypatch)
    r = c.get(f"/api/labs/hunts/run/user-folders?window=all&host={fx.LAPTOP}").json()
    assert r["count"] == 0
    r = c.get(f"/api/labs/rarity/?kind=programs&window=all&host={fx.LAPTOP}").json()
    assert r["items"] == 0


def test_the_switch_shows_every_machine(store, monkeypatch):
    c = client(store, monkeypatch, all_hosts=True)
    r = c.get("/api/labs/hunts/run/user-folders?window=all").json()
    assert fx.LAPTOP_PROGRAM in [x["cells"]["program"] for x in r["rows"]]
    assert "every machine" in r["scope"]
    assert c.get("/api/labs/hunts/run/user-folders?window=24h").json()["window"]["until"] > fx.ts(fx.T_END)


def test_only_the_running_dashboard_decides_which_machines(store, monkeypatch):
    from engine import labs
    monkeypatch.setenv("ANALYSTLAB_LABS_ALL_HOSTS", "1")      # the old switch: ignored, never widens anything
    fx.use_store(monkeypatch, store, hosts=(fx.HOST,))
    assert db.allowed_hosts() == frozenset({fx.HOST}) and db.events_path() == store
    fx.use_store(monkeypatch, store, hosts=None)              # a dashboard started with --labs-all-hosts
    assert db.allowed_hosts() is None
    monkeypatch.setattr(labs, "_current", None)               # no dashboard: the lab VM only, never every machine
    assert db.allowed_hosts() == frozenset({fx.HOST})


def test_the_labs_load_without_the_beacon_module_being_imported():
    import importlib
    import sys
    sys.modules.pop("engine.labs.network", None)
    m = importlib.import_module("engine.labs.network")
    assert isinstance(m.beacon, m._Lazy) and m.router.prefix == "/api/labs/network"
