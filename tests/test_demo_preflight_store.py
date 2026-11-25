"""demo/preflight.py's projector guard waits for the launcher's fresh live store (its own file, so
tests/test_demo_preflight.py keeps its three tests: the checks-button tests count them)."""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo"))
import preflight as P  # noqa: E402


def make_store(path, hosts=("analystlab-vm",), table=True):
    con = sqlite3.connect(path)
    if table:
        con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT)")
        con.executemany("INSERT INTO events (host) VALUES (?)", [(h,) for h in hosts])
    con.commit()
    con.close()


class Waits:
    """A made-up clock: each sleep moves it on, and may do something (the live loop making its store)."""

    def __init__(self, during=None):
        self.t, self.naps, self.during = 0.0, 0, during or {}

    def clock(self):
        return self.t

    def sleep(self, seconds):
        self.naps += 1
        self.t += seconds
        if self.naps in self.during:
            self.during[self.naps]()


def test_the_guard_waits_for_a_live_store_that_appears_a_moment_later(tmp_path):
    """The 2026-11-20 race: the launcher asked before the live loop had made the store's table."""
    store = str(tmp_path / "events.db")
    w = Waits({2: lambda: open(store, "wb").close(),            # first the empty file ...
               5: lambda: (os.remove(store), make_store(store))})   # ... then the table
    assert not P.store_ready(store)
    assert P.projector_ok(store, wait=20, every=0.5, sleep=w.sleep, clock=w.clock)
    assert w.naps == 5 and w.t == 2.5                              # it waited only as long as needed


def test_a_store_that_never_gets_its_table_still_fails(tmp_path):
    missing, empty = str(tmp_path / "missing.db"), str(tmp_path / "empty.db")
    make_store(empty, table=False)
    for store in (missing, empty):
        w = Waits()
        assert not P.projector_ok(store, wait=20, every=0.5, sleep=w.sleep, clock=w.clock)
        assert w.t >= 20 and w.naps == 40                         # it gave the full wait, then said no
    assert not P.projector_ok(empty)                              # and with no wait it says no at once


def test_waiting_never_lets_another_machine_through(tmp_path):
    mixed = str(tmp_path / "mixed.db")
    make_store(mixed, hosts=("analystlab-vm", "other"))
    w = Waits()
    assert not P.projector_ok(mixed, wait=20, sleep=w.sleep, clock=w.clock) and w.naps == 0
