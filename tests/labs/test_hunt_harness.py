"""The shared harness definition in the hunting labs: the run's own report back to the laptop
(10.0.2.2:8770) and the launcher are hidden by default, shown with "show the test machinery"; the test's own
programs (started by the launcher) are never hidden."""

from datetime import timedelta

import pytest

from engine.labs import hunts, network, rarity, _huntdb as db
from engine.store import EventStore
from tests.labs import hunt_fixtures as fx

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


@pytest.fixture()
def con(tmp_path, monkeypatch):
    b = fx.Builder()
    t = fx.T_END - timedelta(minutes=30)
    b.sysmon(4, t - timedelta(minutes=1), State="Started")
    b.start(t, fx.guid(1), PS, fx.guid(0), "C:\\Windows\\explorer.exe",
            cmd="powershell.exe -NoProfile -File D:\\run_scenario.ps1 -Scenario s1 -RunId 20261030-195534-dac0")
    b.start(t + timedelta(seconds=5), fx.guid(2), "D:\\s1\\s1_fetch.exe", fx.guid(1), PS, cmd="D:\\s1\\s1_fetch.exe")
    b.connect(t + timedelta(seconds=6), fx.guid(2), "D:\\s1\\s1_fetch.exe", "10.0.2.2", 18765)
    for i in range(3):
        b.connect(t + timedelta(seconds=30 + i * 20), fx.guid(1), PS, "10.0.2.2", 8770)
    p = tmp_path / "h.db"
    s = EventStore(str(p))
    s.insert(b.records)
    s.close()
    fx.use_store(monkeypatch, str(p))
    c = db.connect(str(p))
    yield c
    c.close()


def test_network_hides_the_flush_by_default(con):
    shown = {p["dest"] for p in network.view(con, db.window(con, "24h"))["pairs"]}
    assert shown == {"10.0.2.2:18765"}                                   # the test's own fetch stays
    every = {p["dest"] for p in network.view(con, db.window(con, "24h"), include_own=True)["pairs"]}
    assert every == {"10.0.2.2:18765", "10.0.2.2:8770"}
    assert any("test machinery is hidden" in n for n in network.view(con, db.window(con, "24h"))["notes"])


def test_rarity_and_hunts_leave_out_the_launcher_but_not_the_test(con):
    progs = {r["cells"]["item"] for r in rarity.stack(con, "programs", db.window(con, "24h"))["rows"]}
    assert progs == {"D:\\s1\\s1_fetch.exe"}
    progs = {r["cells"]["item"] for r in rarity.stack(con, "programs", db.window(con, "24h"), include_own=True)["rows"]}
    assert PS in progs
    unknown = [r["cells"]["program"] for r in hunts.run_hunt(con, "unknown-net", db.window(con, "24h"))["rows"]]
    assert unknown == ["D:\\s1\\s1_fetch.exe"]


def test_first_and_last_use_the_one_clock(con):
    r = rarity.stack(con, "programs", db.window(con, "24h"))["rows"][0]
    # Sysmon's own UtcTime (the fixture writes it to the millisecond), in the store's spelling
    assert r["first"].endswith("0000Z") and "T" in r["first"]
