"""Stage 3: the agent's core guarantees, tested on real Windows events (no admin needed).

Each test writes uniquely-labelled events to the Windows Application log (provider name
"AnalystLabTest-<random>"), runs the real agent on that channel filtered to that provider,
and checks the recording: nothing lost, nothing duplicated, correct resume after restart.
"""

import glob
import json
import uuid

import win32evtlog
import win32evtlogutil

from agent.main import Agent, parse_args


def write_events(provider: str, count: int, start: int = 0) -> None:
    for i in range(start, start + count):
        win32evtlogutil.ReportEvent(provider, 1000, eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                                    strings=[f"analyst lab test event {i}"])


def run_agent(provider: str, recordings, seconds: float = 3) -> Agent:
    args = parse_args([
        "--channel", "Application",
        "--query", f"*[System[Provider[@Name='{provider}']]]",
        "--label", "test",
        "--recordings", str(recordings),
        "--run-seconds", str(seconds),
        "--no-ports",
    ])
    agent = Agent(args)
    agent.run()
    return agent


def recorded(recordings) -> list:
    rows = []
    for path in sorted(glob.glob(str(recordings / "test" / "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            rows += [json.loads(line) for line in f if line.strip()]
    return rows


def messages(rows) -> list:
    return [r["data"]["values"][0] for r in rows]


def test_no_loss_no_duplicates(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 50)
    run_agent(provider, tmp_path)

    rows = recorded(tmp_path)
    assert len(rows) == 50
    assert len({r["record_id"] for r in rows}) == 50
    assert sorted(messages(rows)) == sorted(f"analyst lab test event {i}" for i in range(50))


def test_resume_after_restart_picks_up_events_written_while_stopped(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 30)
    first = run_agent(provider, tmp_path)
    assert first.reader.resumed is False

    write_events(provider, 20, start=30)          # agent is not running now
    second = run_agent(provider, tmp_path)
    assert second.reader.resumed is True
    assert second.session != first.session

    rows = recorded(tmp_path)
    assert len(rows) == 50, "every event exactly once across the restart"
    assert len({r["record_id"] for r in rows}) == 50
    assert sum(r["session"] == second.session for r in rows) == 20


def test_events_arriving_while_running_are_recorded(tmp_path):
    import threading

    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    writer = threading.Timer(1.0, write_events, args=(provider, 25))
    writer.start()
    run_agent(provider, tmp_path, seconds=4)
    writer.join()

    rows = recorded(tmp_path)
    assert len(rows) == 25
    assert len({r["record_id"] for r in rows}) == 25


def test_status_heartbeat_written(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 5)
    agent = run_agent(provider, tmp_path, seconds=2)

    with open(agent.status_path, encoding="utf-8") as f:
        status = json.load(f)
    assert status["events_written"] == 5
    assert status["session"] == agent.session
    assert status["last_record_id"] is not None
