"""Scenario S3 (unexpected listener) against both checkers: a hand-made run that matches the
answer sheet, and broken variants that must FAIL. Port records come from the agent, not Sysmon,
and carry no GUID, so the key risk is tying them to the wrong process: a reused process number
(PID) with another start time must not count."""

import json
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
from test_check_graph_scenario import pool_file  # noqa: E402  (layer 2 needs a pool of normal rates)

LISTEN = r"D:\s3\s3_listen.exe"
BASE = datetime(2026, 10, 20, 12, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def sysmon_time(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def ev(rid, eid, sec, **data):
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal", "data": {"UtcTime": sysmon_time(sec), **data}}


def port(seq, kind, sec, pid=7, started=0.5, lport=47213, ip="127.0.0.1", image=LISTEN):
    return {"host": "VM", "label": "vm", "session": "s", "source": "agent", "seq": seq, "type": kind,
            "time": iso(sec), "origin": "normal",
            "data": {"LocalIp": ip, "LocalPort": lport, "ProcessId": pid, "Image": image,
                     "ProcessStartUtc": sysmon_time(started) if started is not None else None}}


def story(start_at=8, stop_at=68, **port_kw):
    rows = [ev(100, 1, 0.5, Image=LISTEN, ProcessGuid="{L}", ProcessId=7, ParentProcessGuid="{R}",
               ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    if start_at is not None:
        rows.append(port(1, "PORT_LISTEN_START", start_at, **port_kw))
    rows.append(ev(101, 5, 64, Image=LISTEN, ProcessGuid="{L}", ProcessId=7))
    if stop_at is not None:
        rows.append(port(2, "PORT_LISTEN_STOP", stop_at, **port_kw))
    return rows


def both(tmp_path, capsys, rows, end=70):
    for label, data in (("vm", rows), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S3", "exit_code": 0,
                                                    "time": iso(0), "start": iso(0), "end": iso(end),
                                                    "server": "http://10.0.2.2:18765"}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-20.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    a = check_scenario.main(["s3", "--recordings", str(tmp_path)])
    pool_file(tmp_path)
    b = check_graph_scenario.main(["s3", "--recordings", str(tmp_path)])
    return a, b, capsys.readouterr().out


def test_true_s3_story_passes_both_checks(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, story())
    assert (a, b) == (0, 0), out
    assert "7.5-7.5 s after step 1" in out and "60.0-60.0 s after step 2" in out
    assert "fact  PASS  listener started listening on its port" in out
    assert "fact  PASS  listener stopped listening on its port" in out
    assert "trace  PASS" in out


def test_a_reused_process_number_with_another_start_time_does_not_count(tmp_path, capsys):
    # same PID and program name, but the owner started 40 s earlier: a different process
    a, b, out = both(tmp_path, capsys, story(started=-40))
    assert a == 1 and b == 1 and "(0 matching, exactly 1 each expected" in out


def test_a_port_record_without_the_owners_start_time_does_not_count(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(started=None))
    assert a == 1


def test_wrong_port_or_address_fails(tmp_path, capsys):
    a, b, _ = both(tmp_path, capsys, story(lport=47214))
    assert a == 1 and b == 1


def test_wrong_address_fails(tmp_path, capsys):
    a, b, _ = both(tmp_path, capsys, story(ip="0.0.0.0"))
    assert a == 1 and b == 1


def test_listener_never_seen_fails(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, story(start_at=None))
    assert a == 1 and b == 1


def test_port_closing_far_too_early_fails_the_timing(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(stop_at=30))
    assert a == 1 and "22.0-22.0 s after step 2, allowed 45-75 s" in out


def test_seen_too_late_after_the_start_fails(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, story(start_at=40, stop_at=100), end=110)
    assert a == 1 and "allowed 0-25 s" in out


def test_a_connection_by_the_listener_is_not_part_of_the_story(tmp_path, capsys):
    rows = story()
    rows.insert(2, ev(150, 3, 20, Image=LISTEN, ProcessGuid="{L}", Protocol="tcp", Initiated="true",
                      SourceIp="127.0.0.1", SourcePort=50000, DestinationIp="127.0.0.1", DestinationPort=47213))
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  event 3" in out


def test_another_program_listening_during_the_run_is_not_mistaken_for_ours(tmp_path, capsys):
    # realistic: a Windows service opens its own port while S3 runs
    rows = story()
    rows.insert(1, ev(99, 1, 0.2, Image=r"C:\Windows\System32\svchost.exe", ProcessGuid="{S}", ProcessId=900,
                      ParentProcessGuid="{P}"))
    rows.append(port(3, "PORT_LISTEN_START", 18, pid=900, started=0.2, lport=5040, ip="0.0.0.0",
                     image=r"C:\Windows\System32\svchost.exe"))
    a, b, out = both(tmp_path, capsys, rows)
    assert (a, b) == (0, 0), out


def test_trace_catches_a_port_record_whose_owner_start_differs_from_the_raw_event(tmp_path, capsys):
    # the graph is built from one version, the raw recording says another: the trace must notice
    import tempfile
    from check_scenario import run_server
    from engine.graph import build_graph
    from engine.store import EventStore
    import yaml
    rows = story()
    with tempfile.TemporaryDirectory() as tmp:
        st = EventStore(os.path.join(tmp, "g.db"))
        st.insert(rows)
        st.close()
        G = build_graph(os.path.join(tmp, "g.db"))
    truth = yaml.safe_load(open(os.path.join(PROJECT_ROOT, "scenarios", "s3", "ground_truth.yaml"), encoding="utf-8"))
    from engine.replay import parse_time
    lo, hi = parse_time(iso(-5)), parse_time(iso(200))
    c = check_graph_scenario.GraphCheck(truth, G, lo, hi, run_server({"server": "http://10.0.2.2:18765"}), say=lambda m: None)
    assert c.resolve()
    c.check_facts()
    assert c.ok
    raw = {EventStore.dedup_key(r): json.loads(json.dumps(r)) for r in rows}
    for r in raw.values():
        if r.get("type", "").startswith("PORT_LISTEN"):
            r["data"]["ProcessStartUtc"] = sysmon_time(-40)
    c.trace(raw)
    assert not c.ok


# -- review 2026-10-20: false passes that must now fail ------------------------------------------
def test_an_extra_port_opened_by_the_listener_fails(tmp_path, capsys):
    rows = story()
    rows.append(port(3, "PORT_LISTEN_START", 18, lport=4444, ip="0.0.0.0"))   # same process, PID + start
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  PORT_LISTEN_START for the scenario's programs/files: 1" in out


def test_a_program_started_by_the_listener_fails(tmp_path, capsys):
    rows = story()
    rows.insert(2, ev(120, 1, 9, Image=r"C:\Windows\System32\notepad.exe", ProcessGuid="{N}", ProcessId=50,
                      ParentProcessGuid="{L}", ParentImage=LISTEN))
    a, _, out = both(tmp_path, capsys, rows)
    assert a == 1 and "absent  FAIL  event 1 for the scenario's programs/files: 1" in out
