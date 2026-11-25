"""Labs read the alert store READ-ONLY (review of 2026-11-24): engine.alerts.AlertStore opens the file for
writing and may CREATE or ALTER its table when it is opened; a lab's context must never do that."""

import hashlib
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from engine import alerts as A
from engine import labs
from engine.dashboard.app import create_app
from tests.labs.test_registry import NoRun, stores  # noqa: F401  (a small store with one alert)


def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest(), os.path.getsize(path)


def test_reading_alerts_never_opens_the_store_for_writing(stores, tmp_path, monkeypatch):
    events, alerts_db, alert = stores
    before = digest(alerts_db)
    ctx = labs.Context(events, alerts_db)
    opened = []
    real = sqlite3.connect

    def watch(target, *a, **k):
        opened.append((str(target), k.get("uri", False)))
        return real(target, *a, **k)

    monkeypatch.setattr(sqlite3, "connect", watch)
    monkeypatch.setattr(A.AlertStore, "__init__", lambda self, path: (_ for _ in ()).throw(AssertionError("the alert store was opened for writing")))
    got = ctx.alerts()
    assert [a.alert_id for a in got] == [alert.alert_id] and got[0].title == alert.title and got[0].evidence == alert.evidence
    assert ctx.alert(alert.alert_id).level == alert.level and ctx.alert("nope") is None and [a.alert_id for a in ctx.shown_alerts()] in ([alert.alert_id], [])
    mine = [(t, uri) for t, uri in opened if "alerts.db" in t]
    assert mine and all(uri and t.startswith("file:") and t.endswith("?mode=ro") for t, uri in mine), mine
    assert digest(alerts_db) == before                                         # not a byte of the file changed


def test_a_store_from_before_incidents_is_read_as_it_is_and_not_altered(tmp_path):
    path = str(tmp_path / "old-alerts.db")
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, title TEXT, source TEXT NOT NULL,
                   level TEXT NOT NULL, time TEXT NOT NULL, host TEXT, reason TEXT NOT NULL, evidence TEXT NOT NULL, details TEXT, events_db TEXT)""")
    con.execute("INSERT INTO alerts VALUES ('a1', 'r1', 'an old alert', 'sigma', 'medium', '2026-10-30T20:01:41', 'analystlab-vm', 'why', '[\"e1\"]', '{}', NULL)")
    con.commit()
    con.close()
    before = digest(path)
    got = labs.Context(str(tmp_path / "none.db"), path).alerts()
    assert len(got) == 1 and got[0].title == "an old alert" and got[0].incident == "" and got[0].evidence == ("e1",)
    assert digest(path) == before
    con = sqlite3.connect(path)
    assert "incident" not in {r[1] for r in con.execute("PRAGMA table_info(alerts)")}       # opening it the store's own way would have added it
    con.close()
    A.AlertStore(path).close()                                                 # ... as this shows: the check above can fail
    con = sqlite3.connect(path)
    assert "incident" in {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
    con.close()


def test_a_store_with_no_table_yet_gives_no_alerts_and_stays_empty(tmp_path):
    path = tmp_path / "new-alerts.db"
    path.write_bytes(b"")
    ctx = labs.Context(str(tmp_path / "none.db"), str(path))
    assert ctx.alerts() == [] and ctx.shown_alerts() == [] and ctx.alert("x") is None
    assert path.read_bytes() == b""                                            # no table was created in it
    assert labs.Context(str(tmp_path / "none.db"), str(tmp_path / "not-there.db")).alerts() == [] and not (tmp_path / "not-there.db").exists()


def test_the_limit_to_the_test_machine_still_holds(stores, tmp_path):
    events, alerts_db, alert = stores
    assert labs.Context(events, alerts_db, hosts={"another-machine"}).alerts() == []
    assert [a.alert_id for a in labs.Context(events, alerts_db, hosts={alert.host}).alerts()] == [alert.alert_id]


def test_a_lab_page_leaves_the_alert_store_untouched(stores, tmp_path):
    events, alerts_db, _ = stores
    c = TestClient(create_app(events, alerts_db, recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None))
    before = digest(alerts_db)                                                 # (after the dashboard's own start, which is not a lab)
    assert c.get("/api/labs/glance").json()["alerts"] == 1 and c.get("/api/labs/guide").json()["alert"] is not None
    assert digest(alerts_db) == before
