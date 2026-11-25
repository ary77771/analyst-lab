"""tools/false_alarms.py: per-active-hour counting, anonymity, no paths in the report."""

import os
import sqlite3
import sys

from engine.alerts import Alert
from engine.store import EventStore
from tests.test_detect import ev, store

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import false_alarms as fa  # noqa: E402

SECRET = r"C:\Users\yousif\Secret Project\thing.exe"


def test_counts_per_active_hour_and_never_prints_paths(tmp_path):
    recs = [ev(1, 0, Image=SECRET), ev(1, 30, Image=SECRET),            # same minute 0
            ev(1, 61, Image=r"C:\Windows\System32\cmd.exe"),            # minute 1
            ev(1, 3600, Image=SECRET),                                  # minute 60
            ev(1, 7200, origin="project", Image=SECRET),                # our tools: not active time
            ev(1, 7300, paused=True, Image=SECRET)]                     # paused: not active time
    con = sqlite3.connect(store(tmp_path, recs))
    assert fa.active_minutes(con) == 3
    alerts = [Alert("r1", "Rule one", "sigma", "low", "2026-10-22T10:00:00.000Z", "h1", "x", (EventStore.dedup_key(recs[0]),)),
              Alert("r1", "Rule one", "sigma", "low", "2026-10-22T11:00:00.000Z", "h1", "x", (EventStore.dedup_key(recs[3]),)),
              Alert("r2", "Rule two", "analystlab", "medium", "2026-10-23T10:00:00.000Z", "h1", "y", (EventStore.dedup_key(recs[2]),))]
    res = fa.analyse(con, alerts)
    assert res["active_hours"] == 0.1 and res["alerts"] == 3
    assert res["by_level"]["low"][0] == 2 and res["by_level"]["medium"][0] == 1
    (_, top), (_, second) = res["rules"]
    assert top["n"] == 2 and len(top["programs"]) == 1 and len(top["days"]) == 1
    assert top["places"] == {"user folders": 2} and second["places"] == {"Windows": 1}
    text = fa.report(res, "t", ["e.db"])
    assert "yousif" not in text.lower() and "secret" not in text.lower() and "cmd.exe" not in text.lower()
    assert "| sigma | low | Rule one | 2 |" in text


def test_place():
    assert fa.place(r"C:\Program Files (x86)\x.exe") == "Program Files"
    assert fa.place(r"c:\programdata\x.exe") == "ProgramData"
    assert fa.place(r"D:\x.exe") == "other" and fa.place(None) == "unknown"
