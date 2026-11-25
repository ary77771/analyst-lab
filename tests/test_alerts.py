import sqlite3

import pytest

from engine.alerts import Alert, AlertStore, missing_evidence
from engine.store import EventStore


def make(**kw):
    base = dict(rule_id="analystlab.test", title="Test", source="analystlab", level="medium",
                time="2026-10-22T10:00:00Z", host="h", reason="because", evidence=("k2", "k1"))
    base.update(kw)
    return Alert(**base)


def test_alert_id_ignores_evidence_order_and_details():
    assert make().alert_id == make(evidence=("k1", "k2"), details={"x": 1}).alert_id
    assert make().alert_id != make(evidence=("k1",)).alert_id
    assert make().alert_id != make(rule_id="other").alert_id
    assert make().alert_id != make(host="other").alert_id


@pytest.mark.parametrize("bad", [dict(level="severe"), dict(source="mine"), dict(evidence=()), dict(reason="  ")])
def test_invalid_alerts_are_refused(bad):
    with pytest.raises(ValueError):
        make(**bad)


def test_list_evidence_becomes_tuple():
    assert make(evidence=["k1"]).evidence == ("k1",)


def test_store_round_trip_and_idempotent(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    a = make(details={"score": 0.9})
    assert s.write([a, make(rule_id="r2", time="2026-10-22T09:00:00Z")]) == 2
    assert s.write([a]) == 0                     # same alert again: kept once
    got = s.read()
    assert [x.rule_id for x in got] == ["r2", "analystlab.test"]     # ordered by time
    assert got[1] == a and got[1].details == {"score": 0.9}
    s.close()


def test_missing_evidence(tmp_path):
    st = EventStore(str(tmp_path / "e.db"))
    st.insert([{"host": "h", "channel": "c", "record_id": 1, "time": "t1", "event_id": 1}])
    key = EventStore.dedup_key({"host": "h", "channel": "c", "record_id": 1, "time": "t1"})
    st.close()
    db = sqlite3.connect(str(tmp_path / "e.db"))
    assert missing_evidence(make(evidence=(key,)), db) == []
    assert missing_evidence(make(evidence=(key, "nope")), db) == ["nope"]


def test_incident_alert_grows_in_place_and_keeps_first_seen(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    first = make(evidence=("k1", "k2"), incident="g|1", details={"seen_utc": "T1", "n": 2})
    assert s.write([first]) == 1
    grown = make(evidence=("k1", "k2", "k3"), incident="g|1", reason="bigger", details={"n": 3})
    assert grown.alert_id == first.alert_id                      # same incident, same id
    assert s.write([grown]) == 0                                 # not new ...
    (got,) = s.read()
    assert set(got.evidence) == {"k1", "k2", "k3"} and got.reason == "bigger"   # ... but updated
    assert got.details == {"n": 3, "seen_utc": "T1"} and got.incident == "g|1"
    assert s.write([first]) == 0 and len(s.read()[0].evidence) == 3              # never shrinks
    assert s.read()[0].reason == "bigger"                        # an older, smaller copy changes nothing
    s.close()


def test_old_alert_databases_get_the_incident_column(tmp_path):
    import sqlite3 as _sql
    db = _sql.connect(str(tmp_path / "old.db"))
    db.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, title TEXT, source TEXT NOT NULL, "
               "level TEXT NOT NULL, time TEXT NOT NULL, host TEXT, reason TEXT NOT NULL, evidence TEXT NOT NULL, details TEXT, events_db TEXT)")
    db.commit(); db.close()
    s = AlertStore(str(tmp_path / "old.db"))
    assert s.write([make()]) == 1 and s.read()[0].incident == ""
    s.close()


def test_lone_surrogates_are_stored_escaped(tmp_path):
    from engine.store import EventStore
    st = EventStore(str(tmp_path / "s.db"))
    rec = {"host": "h", "channel": "c", "record_id": 1, "time": "t", "event_id": 11,
           "data": {"TargetFilename": "C:\\a\ud800b.exe", "Odd\udc80Field": "x"}}
    assert st.insert([rec]) == (1, 0)
    assert st.insert([rec]) == (0, 1)                                   # dedup still works
    row = st.db.execute("SELECT TargetFilename FROM events").fetchone()[0]
    assert row == "C:\\a\\ud800b.exe"
    assert any(c.lower().startswith("odd") for c in st.columns)
    st.close()
