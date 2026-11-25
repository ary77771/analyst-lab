"""Sweep with ?alert=: the alert's own indicators, and where else each one appears, counted by runs
(a run = one machine start to the next)."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import sweep, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx

SHA = "ef" * 32
DROP = "C:\\Users\\analyst\\AppData\\Local\\Temp\\stage2.dll"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


class Ctx:
    hosts = frozenset({fx.HOST})

    def __init__(self, store, alerts):
        self.events_db, self.alerts_db, self._alerts = store, None, alerts

    def alert(self, alert_id):
        return next((a for a in self._alerts if a.alert_id == alert_id), None)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from engine import labs
    b = fx.Builder()
    t1 = fx.T_END - timedelta(days=1)
    b.sysmon(4, t1, State="Started")                                                    # run 1
    b.start(t1 + timedelta(minutes=1), fx.guid(9), PS, fx.guid(0), "C:\\Windows\\explorer.exe",
            cmd="powershell.exe -NoProfile -File D:\\run_scenario.ps1 -Scenario s1")    # the launcher: machinery
    ev = b.start(t1 + timedelta(minutes=2), fx.guid(10), fx.EVIL, fx.guid(9), PS)
    ev["data"]["Hashes"] = f"SHA256={SHA.upper()}"
    b.connect(t1 + timedelta(minutes=2, seconds=5), fx.guid(10), fx.EVIL, "10.0.2.2", 18765)
    b.sysmon(11, t1 + timedelta(minutes=2, seconds=8), ProcessGuid=fx.guid(10), Image=fx.EVIL, TargetFilename=DROP)
    b.connect(t1 + timedelta(minutes=3), fx.guid(9), PS, "10.0.2.2", 8770)              # the flush: never an indicator
    t2 = fx.T_END - timedelta(hours=2)
    b.sysmon(4, t2, State="Started")                                                    # run 2
    ev2 = b.start(t2 + timedelta(minutes=1), fx.guid(20), "C:\\Users\\analyst\\Desktop\\renamed.exe", fx.guid(1),
                  "C:\\Windows\\explorer.exe")
    ev2["data"]["Hashes"] = f"SHA256={SHA.upper()}"                                     # the same file, renamed
    b.connect(t2 + timedelta(minutes=1, seconds=3), fx.guid(20), "C:\\Users\\analyst\\Desktop\\renamed.exe", "10.0.2.2", 18765)
    p = tmp_path / "w.db"
    s = EventStore(str(p))
    s.insert(b.records)
    s.close()
    alert = SimpleNamespace(alert_id="a1", title="Dropper", host=fx.HOST, time=fx.ts(t1 + timedelta(minutes=2, seconds=9)),
                            evidence=(ev and EventStore.dedup_key(ev),))
    monkeypatch.setattr(labs, "_current", Ctx(str(p), [alert]))
    app = FastAPI()
    app.include_router(sweep.router)
    return TestClient(app)


def by_role(out):
    return {(r["role"], r["raw"]): r for r in out["rows"]}


def test_the_alerts_own_indicators_and_where_else_they_appear(client):
    out = client.get("/api/labs/sweep/alert/a1").json()
    rows = by_role(out)
    fp = rows[("the program's fingerprint", SHA.upper())]
    assert fp["verdict"] == "seen" and fp["in_this_run"] == 1 and fp["other_runs"] == 1 and fp["elsewhere"] == 1
    addr = rows[("an address it contacted", "10.0.2.2")]
    assert addr["other_runs"] == 1 and addr["in_this_run"] == 1
    wrote = rows[("a file it wrote", DROP)]
    assert wrote["other_runs"] == 0 and wrote["in_this_run"] == 1 and wrote["elsewhere"] == 0
    assert ("its parent program", PS) not in rows                                      # the launcher is machinery
    assert not any("8770" in r["raw"] for r in out["rows"])
    assert out["spread"] >= 2 and out["text"].count("\n") == len(out["rows"]) - 1
    assert out["rows"][0]["other_runs"] >= out["rows"][-1]["other_runs"]               # spread first


def test_an_alert_that_is_not_here(client):
    assert client.get("/api/labs/sweep/alert/nope").json()["alert"] == {"id": "nope", "missing": True}
