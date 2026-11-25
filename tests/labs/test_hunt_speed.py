"""Speed audit (2026-11-24): a lab seen VM-only on a store that holds no VM rows (the 2.4 GB laptop store) must
answer "nothing" at once, not after reading every row (network took 65 s, gaps 20 s, hunts 9 s)."""

import sqlite3

from engine.labs import _huntdb as db
from engine.labs import gaps, hunts
from engine.store import EventStore

from tests.labs import hunt_fixtures as fx


def _store(path, hosts):
    recs = []
    for n, h in enumerate(hosts):
        for i in range(3):
            recs.append({"host": h, "label": "x", "session": "s", "source": "sysmon", "channel": fx.SYSMON,
                         "record_id": n * 10 + i + 1, "event_id": 1, "time": f"2026-11-01T10:00:0{i}.0000000Z",
                         "origin": "normal", "data": {"ProcessGuid": fx.guid(n * 10 + i), "Image": "C:\\x\\a.exe",
                                                      "ParentProcessGuid": fx.guid(999)}})
    s = EventStore(str(path))
    s.insert(recs)
    s.close()
    return str(path)


def test_a_store_without_the_vm_answers_nothing_without_reading_rows(tmp_path, monkeypatch):
    # "analystlab-vm2|..." must not count as "analystlab-vm" (the key's '|' ends the host name)
    path = fx.use_store(monkeypatch, _store(tmp_path / "laptop.db", [fx.LAPTOP, fx.HOST + "2"]))
    assert db.present_hosts(frozenset({fx.HOST})) == frozenset()
    assert db.scope_sql() == (" AND 0", [])
    assert db.host_filter(fx.HOST) == (" AND 0", [])
    con = db.connect(path)
    assert db.newest_time(con) is None
    assert hunts.summary(window="all")["hunts"] and all(h["count"] == 0 for h in hunts.summary(window="all")["hunts"])
    assert gaps.gaps(window="all")["window"]["since"] is None


def test_the_vm_rows_are_found_and_only_through_the_unique_key_index(tmp_path, monkeypatch):
    path = fx.use_store(monkeypatch, _store(tmp_path / "mixed.db", [fx.LAPTOP, fx.HOST]))
    assert db.present_hosts(frozenset({fx.HOST, "not-here"})) == frozenset({fx.HOST})
    assert db.scope_sql() == (" AND host IN (?)", [fx.HOST])
    con = sqlite3.connect(path)
    plan = " ".join(r[3] for r in con.execute(
        "EXPLAIN QUERY PLAN SELECT 1 FROM events WHERE dedup_key >= ? AND dedup_key < ? AND host = ? LIMIT 1", ("a|", "a}", "a")))
    assert "INDEX sqlite_autoindex_events" in plan and "SCAN" not in plan, plan


def test_a_store_keyed_another_way_keeps_the_slow_but_correct_path(tmp_path, monkeypatch):
    """If a store's dedup_key did not start with '<host>|', the fast path would hide its rows: it is not used."""
    path = _store(tmp_path / "other.db", [fx.LAPTOP, fx.HOST])
    con = sqlite3.connect(path)
    con.execute("UPDATE events SET dedup_key = 'k' || id")
    con.commit()
    con.close()
    fx.use_store(monkeypatch, path)
    assert db.present_hosts(frozenset({fx.HOST, "not-here"})) == frozenset({fx.HOST, "not-here"})
    assert db.scope_sql() == (" AND host IN (?)", [fx.HOST])


def test_every_host_shown_with_the_all_hosts_switch(tmp_path, monkeypatch):
    fx.use_store(monkeypatch, _store(tmp_path / "laptop.db", [fx.LAPTOP]), hosts=None)
    assert db.scope_sql() == ("", [])
    assert db.host_filter(fx.LAPTOP) == (" AND host = ?", [fx.LAPTOP])
    assert db.host_filter("nobody") == (" AND 0", [])
