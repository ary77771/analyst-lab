"""Tests for the final audit of 2026-10-16 (code auditor findings), one per fix."""

import time
import uuid

import agent.main
from agent import ports as ports_module
from agent.main import Agent, parse_args, single_instance


def quiet_agent(tmp_path, **flags):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    argv = ["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
            "--label", "test", "--recordings", str(tmp_path), "--run-seconds", "1"]
    argv += [f"--{k}" for k, v in flags.items() if v is True]
    return Agent(parse_args(argv))


def event11(path, rid=1, origin_dir=None):
    return {"event_id": 11, "record_id": rid, "time": "2026-10-16T16:00:00.0000000Z", "channel": "c",
            "provider": "p", "data": {"TargetFilename": str(path), "ProcessGuid": "{X}",
                                      **({"CurrentDirectory": origin_dir} if origin_dir else {})}}


def test_port_owner_change_stop_names_the_old_owner(tmp_path, monkeypatch):
    snapshots = [{("127.0.0.1", 5000): 111}, {("127.0.0.1", 5000): 222}]
    images = {111: r"C:\old\server.exe", 222: r"C:\new\server.exe"}
    monkeypatch.setattr(ports_module, "listening_ports", lambda: snapshots.pop(0))
    monkeypatch.setattr(ports_module, "process_image", lambda pid: images.get(pid))
    a = quiet_agent(tmp_path)                                   # snapshot 1 (pid 111)
    recs = a._port_records()                                    # snapshot 2 (pid 222)
    assert [(r["type"], r["data"]["ProcessId"], r["data"]["Image"]) for r in recs] == [
        ("PORT_LISTEN_STOP", 111, r"C:\old\server.exe"),
        ("PORT_LISTEN_START", 222, r"C:\new\server.exe"),
    ]


def test_hashing_respects_a_time_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "HASH_BUDGET_SECONDS", 0.05)
    slow = lambda path: (time.sleep(0.03), ("ok", "AA", 1))[1]
    monkeypatch.setattr(agent.main, "hash_when_closed", slow)
    a = quiet_agent(tmp_path, **{"no-ports": True})
    for i in range(20):
        a._event_record(event11(tmp_path / f"f{i}.exe", rid=i))
    a._process_hash_queue()
    assert 1 <= len(a._pending_agent) < 20                      # stopped at the budget
    assert len(a._pending_agent) + len(a._hash_queue) == 20     # nothing lost


def test_hash_queue_overflow_becomes_gap_records(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "HASH_QUEUE_MAX", 3)
    a = quiet_agent(tmp_path, **{"no-ports": True})
    for i in range(5):
        a._event_record(event11(tmp_path / f"f{i}.exe", rid=i))
    assert len(a._hash_queue) == 3
    assert [r["data"]["hash_status"] for r in a._pending_agent] == ["skipped_queue_full"] * 2


def test_files_created_by_project_work_are_not_fingerprinted(tmp_path):
    a = quiet_agent(tmp_path, **{"no-ports": True})
    ev = event11(agent.main.PROJECT_ROOT + r"\.venv\Lib\site-packages\x.py")
    ev["data"]["Image"] = agent.main.PROJECT_ROOT + r"\.venv\Scripts\python.exe"   # e.g. pip installing
    a._event_record(ev)
    assert a._hash_queue == []
    # the same kind of file created by an ordinary program IS fingerprinted
    a._event_record(event11(tmp_path / "tool.py", rid=2))
    assert len(a._hash_queue) == 1


def test_a_hash_error_does_not_lose_or_duplicate_records(tmp_path, monkeypatch):
    calls = {"n": 0}

    def flaky(path):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return ("ok", "AA", 1)
    monkeypatch.setattr(agent.main, "hash_when_closed", flaky)
    a = quiet_agent(tmp_path, **{"no-ports": True})
    for i in range(3):
        a._event_record(event11(tmp_path / f"f{i}.exe", rid=i))
    a._process_hash_queue()
    assert sorted(r["data"]["hash_status"] for r in a._pending_agent) == ["ok", "ok", "unreadable"]
    assert a._hash_queue == []


def test_agent_rebuilds_its_subscription_after_repeated_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "RETRY_SECONDS", 0.01)
    monkeypatch.setattr(agent.main, "RESUBSCRIBE_AFTER", 3)
    a = quiet_agent(tmp_path, **{"no-ports": True})
    a.args.run_seconds = 2

    def broken():
        raise OSError("subscription broken")
    a.reader.next_batch = broken
    first_reader = a.reader
    a.run()
    assert a.reader is not first_reader                         # rebuilt
    assert "rebuilding the event-log subscription" in (tmp_path / ".state" / "test" / "agent.log").read_text(encoding="utf-8")


def test_receiver_refuses_oversized_batches(tmp_path):
    from fastapi.testclient import TestClient
    from engine.receiver import MAX_RECORDS, create_app
    client = TestClient(create_app(str(tmp_path)))
    r = client.post("/batch", json={"label": "vm", "records": [{"a": 1}] * (MAX_RECORDS + 1)})
    assert r.status_code == 413 and not any(tmp_path.iterdir())


def test_only_one_agent_per_state_folder(tmp_path):
    first = single_instance(str(tmp_path / "state"))
    assert first is not None
    assert single_instance(str(tmp_path / "state")) is None     # a second agent would be refused
    assert single_instance(str(tmp_path / "other")) is not None
