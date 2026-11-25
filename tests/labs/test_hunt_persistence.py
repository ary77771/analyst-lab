"""Persistence before/after (engine/labs/persistence.py): the replayed autostart list."""

from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.labs import persistence, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx

RUN = "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
SVC = "HKLM\\System\\CurrentControlSet\\Services\\Updater"
T = fx.T_END


def reg(b, when, etype, obj, details=None, image="C:\\Windows\\regedit.exe", g=5):
    b.sysmon(13 if etype == "SetValue" else 12, when, ProcessGuid=fx.guid(g), Image=image, EventType=etype,
             TargetObject=obj, Details=details)


@pytest.fixture(autouse=True)
def no_dashboard(monkeypatch):
    """No dashboard context left by another test decides which machines these tests see."""
    from engine import labs
    monkeypatch.setattr(labs, "_current", None)


@pytest.fixture()
def store(tmp_path):
    b = fx.Builder()
    # before the test window (window = the last 2 hours)
    reg(b, T - timedelta(days=2), "SetValue", RUN + "\\OneDrive", '"C:\\OneDrive.exe" /background')
    reg(b, T - timedelta(days=2), "SetValue", RUN + "\\Old", "C:\\old.exe")
    reg(b, T - timedelta(days=2), "SetValue", RUN + "\\Same", "C:\\same.exe")
    reg(b, T - timedelta(days=2), "SetValue", SVC + "\\ImagePath", "C:\\svc\\upd.exe")
    reg(b, T - timedelta(days=2), "SetValue", SVC + "\\Start", "DWORD (0x00000003)")
    reg(b, T - timedelta(days=2), "SetValue", RUN + "\\Keep", "C:\\keep.exe")              # never touched again
    # inside the window
    reg(b, T - timedelta(minutes=50), "SetValue", RUN + "\\Updater", f'"{fx.EVIL}"', image=fx.EVIL, g=10)
    reg(b, T - timedelta(minutes=40), "SetValue", RUN + "\\OneDrive", '"C:\\Temp\\OneDrive.exe"', image=fx.EVIL, g=10)
    reg(b, T - timedelta(minutes=30), "DeleteValue", RUN + "\\Old")
    reg(b, T - timedelta(minutes=29), "SetValue", RUN + "\\Same", "C:\\same.exe")              # rewritten, same value
    reg(b, T - timedelta(minutes=20), "CreateKey", RUN + "\\Empty")                           # an empty key: no entry
    reg(b, T - timedelta(minutes=15), "DeleteKey", SVC)                                        # takes ImagePath + Start
    b.sysmon(11, T - timedelta(minutes=10), ProcessGuid=fx.guid(10), Image=fx.EVIL,
             TargetFilename="C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.lnk")
    b.start(T - timedelta(minutes=5), fx.guid(31), "C:\\Windows\\System32\\schtasks.exe", fx.guid(10), fx.EVIL,
            cmd='schtasks /create /tn "Daily Upd" /tr C:\\x.exe /sc daily')
    b.start(T, fx.guid(32), "C:\\Windows\\System32\\notepad.exe", fx.guid(1), "C:\\Windows\\explorer.exe")
    p = tmp_path / "p.db"
    s = EventStore(str(p))
    s.insert(b.records)
    s.close()
    return str(p)


def by_name(out):
    return {r["cells"]["name"]: r for r in out["rows"]}


def test_before_and_after_a_two_hour_window(store):
    con = db.connect(store)
    try:
        w = db.window(con, start=fx.ts(T - timedelta(hours=2)), end=fx.ts(T))
        out = persistence.compare(con, w)
    finally:
        con.close()
    rows = by_name(out)
    assert rows["Updater"]["status"] == "added" and rows["Updater"]["cells"]["by"] == "evil.exe"
    assert rows["OneDrive"]["status"] == "changed"
    assert rows["OneDrive"]["cells"]["before"] == '"C:\\OneDrive.exe" /background'
    assert rows["Old"]["status"] == "removed"
    assert rows["Same"]["status"] == "rewritten"            # same value written again inside the window: shown
    assert rows["Keep"]["status"] == "unchanged"
    assert rows["ImagePath"]["status"] == "removed" and rows["Start"]["status"] == "removed"   # the whole key went
    assert rows["Start"]["cells"]["kind"] == "Service start mode" and rows["Start"]["cells"]["value"] == "manual"
    assert rows["upd.lnk"]["status"] == "added" and rows["upd.lnk"]["cells"]["kind"] == "Startup folder"
    assert rows["Daily Upd"]["status"] == "added" and rows["Daily Upd"]["cells"]["kind"] == "Scheduled task"
    assert "Empty" not in rows
    assert out["counts"] == {"added": 3, "first_seen": 0, "changed": 1, "rewritten": 1, "removed": 3, "unchanged": 1}
    assert out["before_total"] == 6 and out["after_total"] == 6
    assert out["writes_in_window"] == 7 and out["registry_recorded"] is True     # CreateKey is no entry


def test_without_recording_before_the_window_nothing_is_added_only_first_seen(store, tmp_path):
    """Critique 2026-11-24: the live store starts at boot, so its 'before' is empty by construction."""
    con = db.connect(store)
    try:
        first = db.parse_iso(con.execute("SELECT MIN(time) FROM events").fetchone()[0])
        out = persistence.compare(con, db.window(con, start=fx.ts(first - timedelta(minutes=1)), end=fx.ts(T)))
        whole = persistence.compare(con, db.window(con, "all"))
    finally:
        con.close()
    for o in (out, whole):
        assert o["has_before"] is False and o["counts"]["added"] == 0 and o["counts"]["first_seen"] == o["after_total"]
        assert "not as added" in o["before_note"]
    with_before = persistence.compare(*(lambda c: (c, db.window(c, start=fx.ts(T - timedelta(hours=2)), end=fx.ts(T))))(db.connect(store)))
    assert with_before["has_before"] is True and with_before["counts"]["first_seen"] == 0 and with_before["before_note"] is None


def test_replay_applies_changes_in_time_order():
    ch = [("2", ("reg", "k\\a"), "Run key", "k", "a", None, None, None, "value deleted"),
          ("1", ("reg", "k\\a"), "Run key", "k", "a", "x", None, None, "value set")]
    ch.sort(key=lambda c: c[0])
    assert persistence.replay(ch) == {}
    assert persistence.replay(ch, until="1")[("reg", "k\\a")]["value"] == "x"


def test_task_names():
    assert persistence._task_name('schtasks /create /tn "My Task" /tr x') == "My Task"
    assert persistence._task_name("schtasks /Create /TN Upd /tr x") == "Upd"
    assert persistence._task_name("schtasks /query") is None


def test_api_hides_unchanged_by_default(store, monkeypatch):
    fx.use_store(monkeypatch, store)
    app = FastAPI()
    app.include_router(persistence.router)
    c = TestClient(app)
    q = f"start={fx.ts(T - timedelta(hours=2))}&end={fx.ts(T)}"
    a = c.get(f"/api/labs/persistence/?{q}").json()
    assert {r["status"] for r in a["rows"]} == {"added", "changed", "rewritten", "removed"}
    b = c.get(f"/api/labs/persistence/?{q}&show_unchanged=true").json()
    assert len(b["rows"]) == len(a["rows"]) + 1
    assert a["not_seen"] and a["window"]["name"] == "custom"
    assert c.get("/api/labs/persistence/?start=yesterday").status_code == 400


def test_a_store_without_registry_says_so(tmp_path, monkeypatch):
    p = fx.build(tmp_path / "e.db")
    con = db.connect(p)
    try:
        out = persistence.compare(con, db.window(con, "24h"))
    finally:
        con.close()
    assert out["registry_recorded"] is True                   # EventStore creates the registry columns up front
    kinds = {r["cells"]["kind"] for r in out["rows"]}
    assert {"Run key", "Startup folder", "Scheduled task"} <= kinds
