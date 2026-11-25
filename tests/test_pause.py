"""Pause for 1 hour (agent/control.py): the file format, the agent's view of it, and the real agent
writing only skeletons (number, time, type) for events inside a pause."""

import json
from datetime import datetime, timedelta, timezone

from agent import control
from agent.control import PauseWatch, read_pause, request_pause, resume_now, utc_text
from tests.test_agent_mechanics import recorded, run_agent, write_events

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def at(minutes):
    return utc_text(T0 + timedelta(minutes=minutes))


def test_request_read_and_resume(tmp_path):
    p = request_pause(str(tmp_path), now=T0)
    assert p == {"requested": at(0), "until": at(60)}
    assert read_pause(str(tmp_path)) == (at(0), at(60))
    resume_now(str(tmp_path), now=T0 + timedelta(minutes=10))
    assert read_pause(str(tmp_path)) == (at(0), at(10))


def test_a_pause_can_never_be_longer_than_65_minutes(tmp_path):
    request_pause(str(tmp_path), minutes=600, now=T0)                       # the app's limit
    assert read_pause(str(tmp_path))[1] == at(60)
    (tmp_path / control.PAUSE_FILE).write_text(json.dumps({"requested": at(0), "until": at(60 * 24 * 365)}))
    assert read_pause(str(tmp_path))[1] == at(65)                          # edited by hand: cut


def test_damaged_or_backwards_pause_file_means_no_pause(tmp_path):
    for content in ("{not json", json.dumps({"requested": at(0)}), json.dumps({"requested": at(5), "until": at(1)}),
                    json.dumps(["x"]), json.dumps({"requested": "yesterday", "until": "tomorrow"})):
        (tmp_path / control.PAUSE_FILE).write_text(content)
        assert read_pause(str(tmp_path)) is None


def test_watch_reports_start_change_end_and_judges_by_event_time(tmp_path):
    w = PauseWatch(str(tmp_path))
    assert w.poll(at(0)) == []
    request_pause(str(tmp_path), now=T0)
    assert w.poll(at(0)) == [("start", at(0), at(60))] and w.paused_until == at(60)
    assert w.poll(at(1)) == []
    resume_now(str(tmp_path), now=T0 + timedelta(minutes=5))
    assert w.poll(at(5)) == [("change", at(0), at(5)), ("end", at(0), at(5))] and w.paused_until is None
    assert w.covers(at(3)) and not w.covers(at(6))                         # an event read late still counts


def test_a_pause_that_ended_while_the_agent_was_off_still_covers_its_events(tmp_path):
    request_pause(str(tmp_path), minutes=30, now=T0)
    w = PauseWatch(str(tmp_path))
    assert w.poll(at(90)) == [("start", at(0), at(30)), ("end", at(0), at(30))]
    assert w.covers(at(10)) and w.active is None


def test_real_agent_writes_only_skeletons_while_paused(tmp_path):
    import uuid
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    state = tmp_path / ".state" / "test"
    request_pause(str(state), minutes=2, now=datetime.now(timezone.utc) - timedelta(minutes=1))
    write_events(provider, 5)
    run_agent(provider, tmp_path)
    rows = recorded(tmp_path)
    events = [r for r in rows if r.get("source") != "agent"]
    assert len(events) == 5 and len({r["record_id"] for r in events}) == 5   # still complete
    for r in events:
        assert r["paused"] is True and r["data"] == {}                        # but nothing of what
        assert "analyst lab test event" not in json.dumps(r)
    assert [r["type"] for r in rows if r.get("source") == "agent"] == ["PAUSE_START"]
    status = json.loads((state / "status.json").read_text(encoding="utf-8"))
    assert status["paused_until"] is not None


def test_real_agent_records_normally_after_the_pause(tmp_path):
    import uuid
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    state = tmp_path / ".state" / "test"
    request_pause(str(state), minutes=1, now=datetime.now(timezone.utc) - timedelta(minutes=5))   # long over
    write_events(provider, 3)
    run_agent(provider, tmp_path)
    rows = recorded(tmp_path)
    events = [r for r in rows if r.get("source") != "agent"]
    assert len(events) == 3 and all("paused" not in r and r["data"] for r in events)
    assert [r["type"] for r in rows if r.get("source") == "agent"] == ["PAUSE_START", "PAUSE_END"]


def test_store_keeps_the_mark_and_the_graph_skips_paused_rows(tmp_path):
    from engine.graph import build_graph
    from engine.store import EventStore
    st = EventStore(str(tmp_path / "e.db"))
    base = {"host": "H", "label": "host", "session": "s", "source": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational", "time": at(0), "origin": "normal"}
    st.insert([dict(base, record_id=1, event_id=1, paused=True, data={}),
               dict(base, record_id=2, event_id=1, data={"ProcessGuid": "{A}", "ProcessId": 4, "Image": r"C:\x.exe",
                                                           "UtcTime": "2026-10-20 12:00:00.000",
                                                           "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}"})])
    assert st.count("paused = 1") == 1
    G = build_graph(st)
    assert G.graph["stats"]["paused_rows_skipped"] == 1
    assert G.number_of_nodes() == 1                                         # only the real process
    # skipped as paused, not miscounted as a broken event (sabotage check 2026-10-19)
    assert not any(k.endswith("_without_process_guid") for k in G.graph["stats"])


# -- review 2026-10-19 ---------------------------------------------------------------------------
class _FakeReader:
    """Hands out prepared batches; the friend clicks Pause right after the first one is read."""
    resumed, fallback_reason = False, None

    def __init__(self, batches, before_second):
        self.batches, self.before_second, self.calls = list(batches), before_second, 0

    def next_batch(self):
        self.calls += 1
        batch = self.batches.pop(0)() if self.batches else []
        if self.calls == 1:
            self.before_second()        # the click lands while the first batch is being written
        return batch

    def bookmark_xml(self):
        return "<BookmarkList/>"


def _event(rid):
    return {"channel": "Application", "record_id": rid, "event_id": 1000, "provider": "p",
            "time": control.utc_text(datetime.now(timezone.utc)), "data": {"values": [f"secret {rid}"]}}


def test_a_pause_clicked_during_a_long_catch_up_covers_the_next_batch(tmp_path):
    from agent.main import Agent, parse_args
    control_dir = tmp_path / "control"
    a = Agent(parse_args(["--channel", "Application", "--label", "test", "--recordings", str(tmp_path),
                          "--no-ports", "--control-dir", str(control_dir)]))
    a.reader = _FakeReader([lambda: [_event(1)], lambda: [_event(2)]],
                           before_second=lambda: request_pause(str(control_dir), now=datetime.now(timezone.utc)))
    a._drain()
    a.sink.close()
    rows = recorded(tmp_path)
    assert [r.get("paused", False) for r in rows] == [False, True]
    assert "secret 2" not in json.dumps(rows)
    assert [r["type"] for r in a._pending_agent] == ["PAUSE_START"]


def test_after_a_pause_no_port_record_names_a_program_started_during_it(tmp_path, monkeypatch):
    import uuid
    from agent import ports
    snapshots = iter([{}])
    monkeypatch.setattr(ports, "listening_ports", lambda: next(snapshots, {("0.0.0.0", 5555): 4321}))
    monkeypatch.setattr(ports, "process_image", lambda pid: r"C:\Private\started-during-pause.exe")
    monkeypatch.setattr(ports, "process_start", lambda pid: "2026-10-20T12:00:00.0000000Z")
    state = tmp_path / ".state" / "test"
    now = datetime.now(timezone.utc)
    request_pause(str(state), minutes=1, now=now - timedelta(minutes=3))   # a pause that is over
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    from agent.main import Agent, parse_args
    a = Agent(parse_args(["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
                          "--label", "test", "--recordings", str(tmp_path), "--run-seconds", "2.5",
                          "--port-interval", "0.4"]))
    a.run()
    rows = recorded(tmp_path)
    assert [r["type"] for r in rows if r.get("source") == "agent"] == ["PAUSE_START", "PAUSE_END"]
    assert "started-during-pause" not in json.dumps(rows)
    assert ("0.0.0.0", 5555) in a.ports_before                                 # became the new baseline


def test_friend_laptops_count_their_own_claude_and_virtualbox_use_as_normal(tmp_path):
    from agent.enrich import OriginTagger
    claude = {"event_id": 1, "data": {"ProcessGuid": "{1}", "Image": r"C:\Apps\claude.exe"}}
    assert OriginTagger(str(tmp_path)).tag(claude) == "project"                 # Yousif's laptop
    assert OriginTagger(str(tmp_path), dev_tools=False).tag(claude) == "normal"   # a friend's
