"""Lab "Around this moment" (engine/labs/moment.py): fixtures only."""

import sqlite3
from datetime import datetime, timedelta, timezone

from engine.labs import moment
from engine.store import EventStore

SYSMON = "Microsoft-Windows-Sysmon/Operational"
T0 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
_seq = [0]


def ev(event_id, seconds, host="h1", logged_late=0.0, origin="normal", **data):
    _seq[0] += 1
    happened = T0 + timedelta(seconds=seconds)
    data.setdefault("UtcTime", happened.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
    t = (happened + timedelta(seconds=logged_late)).isoformat().replace("+00:00", "Z")
    return {"host": host, "channel": SYSMON, "record_id": _seq[0], "time": t, "event_id": event_id, "origin": origin,
            "source": "sysmon", "data": data}


def store(tmp_path, recs):
    p = str(tmp_path / "e.db")
    s = EventStore(p)
    s.insert(recs)
    s.close()
    return sqlite3.connect("file:" + p.replace("\\", "/") + "?mode=ro", uri=True)


def recs():
    return [
        ev(1, -40, Image=r"C:\x\early.exe", ProcessGuid="{E}", ProcessId=9),                       # outside ±30
        ev(1, -5, Image=r"C:\x\a.exe", ProcessGuid="{A}", ProcessId=10, ParentImage=r"C:\x\cmd.exe", CommandLine="a.exe -go"),
        ev(3, -1, Image=r"C:\x\a.exe", ProcessGuid="{A}", ProcessId=10, DestinationIp="10.0.2.2", DestinationPort=8770,
           logged_late=8),                                                                            # logged 8 s late
        ev(11, 0, Image=r"C:\x\a.exe", ProcessGuid="{A}", ProcessId=10, TargetFilename=r"C:\x\drop.exe"),
        ev(1, 2, Image=r"C:\x\drop.exe", ProcessGuid="{B}", ProcessId=11, ParentImage=r"C:\x\a.exe"),
        ev(22, 3, Image=r"C:\x\tool.exe", ProcessGuid="{T}", ProcessId=12, QueryName="example.invalid", origin="project"),
        ev(1, 1, host="h2", Image=r"C:\x\other-host.exe", ProcessGuid="{H}", ProcessId=13),         # another machine
        ev(1, 25, Image=r"C:\x\late.exe", ProcessGuid="{L}", ProcessId=14),
        ev(3, 26, Image=r"C:\X\LATE.exe", ProcessId=14, DestinationIp="10.0.2.2", DestinationPort=1),  # no guid: joins {L}
    ]


def test_window_lanes_anchor_and_alert_marks(tmp_path):
    r = recs()
    con = store(tmp_path, r)
    anchor = EventStore.dedup_key(r[3])
    out = moment.around(con, "h1", T0, 30, [anchor], {EventStore.dedup_key(r[4]): ["alert-1"]})
    whats = [e["what"] for e in out["events"]]
    assert "C:\\x\\early.exe" not in str(whats) and "other-host" not in str(whats)     # outside / other machine
    assert out["total"] == 7 and not out["truncated"]
    assert [e["offset"] for e in out["events"]] == [-5.0, -1.0, 0.0, 2.0, 3.0, 25.0, 26.0]   # happened time, not logged
    assert out["events"][-1]["lane"] == "{L}" and len(out["lanes"]) == 4                     # joined, not a 5th lane
    a = out["lanes"][0]
    assert a["id"] == "{A}" and a["anchor"] and a["label"] == "a.exe" and a["parent"] == "cmd.exe" and a["count"] == 3
    hit = [e for e in out["events"] if e["anchor"]]
    assert len(hit) == 1 and hit[0]["kind"] == "file" and hit[0]["what"] == "C:\\x\\drop.exe"
    net = next(e for e in out["events"] if e["kind"] == "network")
    assert net["what"] == "10.0.2.2:8770" and net["name"] == "network connection"
    b = next(e for e in out["events"] if e["lane"] == "{B}")
    assert b["alerts"] == ["alert-1"]
    tool = next(e for e in out["events"] if e["kind"] == "dns")
    assert tool["own_tool"] and next(l for l in out["lanes"] if l["id"] == "{T}")["own_tool"]


def test_a_smaller_window_and_the_cut(tmp_path):
    r = recs()
    con = store(tmp_path, r)
    out = moment.around(con, "h1", T0, 2, [EventStore.dedup_key(r[3])])
    assert [e["offset"] for e in out["events"]] == [-1.0, 0.0, 2.0]
    cut = moment.around(con, "h1", T0, 30, [EventStore.dedup_key(r[7])], max_rows=2)
    assert cut["truncated"] and cut["total"] == 7 and cut["shown"] == 2
    assert any(e["anchor"] for e in cut["events"])                                     # the anchor is always kept


def test_route_for_an_alert_and_an_event(tmp_path):
    from fastapi.testclient import TestClient
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None))
    r = c.get(f"/api/labs/moment?alert={a.alert_id}&seconds=60").json()
    assert r["anchor"]["kind"] == "alert" and r["events"] and any(e["anchor"] for e in r["events"])
    assert {e["key"] for e in r["events"] if e["anchor"]} <= set(a.evidence)
    k = next(e["key"] for e in r["events"] if e["anchor"])
    r2 = c.get(f"/api/labs/moment", params={"event": k, "seconds": 5}).json()
    assert r2["anchor"]["kind"] == "event" and [e["key"] for e in r2["events"] if e["anchor"]] == [k]
    assert c.get("/api/labs/moment?alert=nope").status_code == 404
    assert c.get("/api/labs/moment").json()["anchor"] is None


def test_one_lane_per_program_whatever_the_case_of_its_guid(tmp_path):
    recs = [ev(1, 0, Image=r"C:\x\a.exe", ProcessGuid="{ABCD-1}", ProcessId=10),
            ev(3, 1, Image=r"C:\x\a.exe", ProcessGuid="{abcd-1}", ProcessId=10, DestinationIp="10.0.2.2", DestinationPort=1)]
    out = moment.around(store(tmp_path, recs), "h1", T0, 30, [])
    assert len(out["lanes"]) == 1 and out["lanes"][0]["count"] == 2


def test_the_test_machinery_is_marked_by_the_shared_definition(tmp_path):
    """The launcher, the VM's helper programs and the report back to the laptop (engine/labs/_shared_defs.py) are
    marked own_tool, so the page hides them by default; the test program itself is not."""
    recs = [ev(1, 0, Image=r"C:\x\powershell.exe", ProcessGuid="{R}", ProcessId=20, CommandLine=r"powershell -File D:\run_scenario.ps1"),
            ev(3, 1, Image=r"C:\x\powershell.exe", ProcessGuid="{R}", ProcessId=20, DestinationIp="10.0.2.2", DestinationPort=8770),
            ev(1, 2, Image=r"C:\x\VBoxControl.exe", ProcessGuid="{V}", ProcessId=21),
            ev(1, 3, Image=r"D:\s1\s1_fetch.exe", ProcessGuid="{F}", ProcessId=22, CommandLine="s1_fetch.exe -server http://10.0.2.2:18765")]
    out = moment.around(store(tmp_path, recs), "h1", T0, 30, [])
    lanes = {l["id"]: l for l in out["lanes"]}
    assert lanes["{R}"]["own_tool"] and lanes["{V}"]["own_tool"] and not lanes["{F}"]["own_tool"]
    fetch_net = [e for e in out["events"] if e["lane"] == "{F}"]
    assert fetch_net and not any(e["own_tool"] for e in fetch_net)
