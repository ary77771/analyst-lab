"""Stage 3 robustness tests, one per finding of the independent review (2026-10-16)."""

import glob
import json
import os
import threading
import time
import uuid

import pytest
import pywintypes
import win32event

import agent.eventlog
import agent.main
from agent import ports as ports_module
from agent.main import Agent, parse_args
from agent.sink import JsonlSink
from agent.state import atomic_write_text, read_text
from tests.test_agent_mechanics import write_events


def args_for(provider, tmp_path, seconds=3, no_ports=True):
    argv = ["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
            "--label", "test", "--recordings", str(tmp_path), "--run-seconds", str(seconds)]
    if no_ports:
        argv.append("--no-ports")
    return parse_args(argv)


def recorded(tmp_path):
    rows = []
    for path in sorted(glob.glob(str(tmp_path / "test" / "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
    return rows


def test_unparsable_event_is_recorded_and_skipped_not_fatal(tmp_path, monkeypatch):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 3)
    real_parse = agent.eventlog.parse_event_xml
    calls = {"n": 0}

    def flaky_parse(xml):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("simulated malformed event")
        return real_parse(xml)

    monkeypatch.setattr(agent.eventlog, "parse_event_xml", flaky_parse)
    a = Agent(args_for(provider, tmp_path))
    a.run()

    rows = recorded(tmp_path)
    assert len(rows) == 3
    bad = [r for r in rows if "parse_error" in r]
    assert len(bad) == 1 and "simulated malformed event" in bad[0]["parse_error"]
    assert bad[0]["record_id"] is not None and bad[0]["raw_xml"]
    assert a.errors == 1

    # the bookmark moved past the bad event: a restart reads nothing new
    monkeypatch.setattr(agent.eventlog, "parse_event_xml", real_parse)
    Agent(args_for(provider, tmp_path, seconds=2)).run()
    assert len(recorded(tmp_path)) == 3


def test_idle_agent_reads_only_when_windows_signals(tmp_path):
    # Windows answers EvtNext with 4317 ("The operation identifier is not valid") when it is
    # called again after "no more items" without the subscription's signal being set (probed
    # 2026-10-17; seen in the VM at every start). Reading only after the signal, as Microsoft's
    # pull-subscription sample does, must leave an idle agent with no errors at all.
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 2)
    a = Agent(args_for(provider, tmp_path, seconds=4))           # ~3 idle seconds after the backlog
    a.run()
    assert len(recorded(tmp_path)) == 2
    assert a.errors == 0, a.last_error


def test_events_arriving_after_an_idle_period_are_read(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    threading.Timer(2.5, write_events, args=(provider, 3)).start()   # nothing at first, then 3
    a = Agent(args_for(provider, tmp_path, seconds=5))
    a.run()
    assert len(recorded(tmp_path)) == 3 and a.errors == 0, a.last_error


def test_signal_with_nothing_new_is_not_an_error(tmp_path):
    # review finding 3: a signal with nothing readable behind it must not raise 4317
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    reader = agent.eventlog.ChannelReader("Application", query=f"*[System[Provider[@Name='{provider}']]]")
    assert reader.next_batch() == []
    win32event.SetEvent(reader._signal)
    assert reader.wait(0) and reader.next_batch() == []


def test_failed_second_read_leaves_the_signal_set(monkeypatch):
    # review finding 2: if the re-check after the reset fails, the next pass must read again
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    reader = agent.eventlog.ChannelReader("Application", query=f"*[System[Provider[@Name='{provider}']]]")
    real = agent.eventlog.win32evtlog.EvtNext
    calls = {"n": 0}

    def fake(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise pywintypes.error(6, "EvtNext", "The handle is invalid.")
        return real(*a, **kw)

    monkeypatch.setattr(agent.eventlog.win32evtlog, "EvtNext", fake)
    with pytest.raises(pywintypes.error):
        reader.next_batch()
    assert reader.wait(0)


def test_quiet_agent_rebuilds_its_subscription_and_still_reads(tmp_path, monkeypatch):
    # review finding 1: with reads only on a signal, a silently dead subscription would go
    # unnoticed; after IDLE_RESUBSCRIBE quiet seconds the agent rebuilds it from the bookmark
    monkeypatch.setattr(agent.main, "IDLE_RESUBSCRIBE", 1)
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 2)
    threading.Timer(3.0, write_events, args=(provider, 2)).start()
    a = Agent(args_for(provider, tmp_path, seconds=6))
    first_reader = a.reader
    a.run()
    assert a.reader is not first_reader
    rows = recorded(tmp_path)
    assert len(rows) == 4 and len({r["record_id"] for r in rows}) == 4 and a.errors == 0, a.last_error
    assert "rebuilding the subscription as a precaution" in (tmp_path / ".state" / "test" / "agent.log").read_text(encoding="utf-8")


def test_corrupt_bookmark_falls_back_without_crashing(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 4)
    state = tmp_path / ".state" / "test"
    state.mkdir(parents=True)
    (state / "bookmark.xml").write_text("<not a real bookmark", encoding="utf-8")

    a = Agent(args_for(provider, tmp_path))
    a.run()
    assert a.reader.resumed is False
    assert a.reader.fallback_reason and "bookmark unusable" in a.reader.fallback_reason
    assert len(recorded(tmp_path)) == 4
    assert "bookmark unusable" in (state / "agent.log").read_text(encoding="utf-8")


def test_sink_isolates_a_partial_line_left_by_a_crash(tmp_path):
    folder = tmp_path / "rec"
    folder.mkdir()
    sink = JsonlSink(str(folder))
    sink.write_batch([{"a": 1}])
    path = sink.current_path
    sink.close()
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"half": ')                       # crash mid-write

    sink = JsonlSink(str(folder))
    sink.write_batch([{"b": 2}])
    sink.close()
    lines = open(path, encoding="utf-8").read().splitlines()
    assert lines == ['{"a":1}', '{"half": ', '{"b":2}']


def test_atomic_write_survives_target_briefly_held_open(tmp_path):
    path = str(tmp_path / "status.json")
    atomic_write_text(path, "old")
    holder = open(path, encoding="utf-8")         # like the status app reading the file

    def release():
        time.sleep(0.3)
        holder.close()

    threading.Thread(target=release).start()
    atomic_write_text(path, "new")                 # must retry until the reader lets go
    assert read_text(path) == "new"


def test_agent_logs_to_file(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 1)
    Agent(args_for(provider, tmp_path, seconds=1)).run()
    text = (tmp_path / ".state" / "test" / "agent.log").read_text(encoding="utf-8")
    assert "start session=" in text and "stop session=" in text


def test_port_stop_keeps_the_image_of_the_exited_program(tmp_path, monkeypatch):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    snapshots = [{("127.0.0.1", 5000): 111}, {("127.0.0.1", 5000): 111}, {}]
    images = {111: r"C:\Tools\server.exe"}
    monkeypatch.setattr(ports_module, "listening_ports", lambda: snapshots.pop(0))
    monkeypatch.setattr(ports_module, "process_image", lambda pid: images.get(pid))

    a = Agent(args_for(provider, tmp_path, no_ports=False))      # snapshot 1 at start
    assert a._port_records() == []                                # snapshot 2: unchanged
    images.clear()                                                # the program has exited
    stop = a._port_records()                                      # snapshot 3: port gone
    assert [r["type"] for r in stop] == ["PORT_LISTEN_STOP"]
    assert stop[0]["data"]["Image"] == r"C:\Tools\server.exe"
