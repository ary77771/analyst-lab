"""Tests for the third independent review (S1, receiver, retry), one per finding or gap."""

import hashlib
import json
import threading
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

import agent.main
from agent import ports as ports_module
from agent.main import Agent, parse_args
from agent.sink import HttpSink, JsonlSink
from engine.receiver import create_app
from tests.test_agent_mechanics import write_events
from tests.test_receiver import LiveReceiver, agent_args, lines, reserve_port


def quiet_agent(tmp_path, **extra):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    argv = ["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
            "--label", "test", "--recordings", str(tmp_path), "--run-seconds", "1", "--no-ports"]
    for k, v in extra.items():
        argv += [f"--{k.replace('_', '-')}", v]
    return Agent(parse_args(argv))


def test_agent_hashes_a_new_file_only_after_its_writer_closes_it(tmp_path):
    a = quiet_agent(tmp_path)
    path = tmp_path / "payload.exe"
    writer = open(path, "wb")
    writer.write(b"partial")
    writer.flush()
    a._event_record({"event_id": 11, "record_id": 7, "time": "2026-10-16T16:00:00.0000000Z",
                     "channel": "c", "provider": "p",
                     "data": {"TargetFilename": str(path), "ProcessGuid": "{F}"}})
    a._process_hash_queue()
    assert a._pending_agent == [] and len(a._hash_queue) == 1          # still being written

    writer.write(b" and the rest")
    writer.close()
    a._process_hash_queue()
    (rec,) = a._pending_agent
    assert rec["type"] == "FILE_HASH" and rec["data"]["hash_status"] == "ok"
    assert rec["data"]["sha256"] == hashlib.sha256(b"partial and the rest").hexdigest().upper()
    assert rec["data"]["size"] == 20
    assert (rec["data"]["ref_record_id"], rec["data"]["ProcessGuid"]) == (7, "{F}")


def test_new_folder_is_marked_directory_not_unreadable(tmp_path):
    a = quiet_agent(tmp_path)
    folder = tmp_path / "AnalystLab" / "payload"
    folder.mkdir(parents=True)
    a._event_record({"event_id": 11, "record_id": 9, "time": "2026-10-17T17:32:15.4840000Z",
                     "channel": "c", "provider": "p",
                     "data": {"TargetFilename": str(folder), "ProcessGuid": "{F}"}})
    a._process_hash_queue()
    (rec,) = a._pending_agent
    assert rec["data"]["hash_status"] == "directory" and rec["data"]["sha256"] is None


def test_hash_gives_up_after_the_wait_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "HASH_WAIT_SECONDS", 0)
    a = quiet_agent(tmp_path)
    path = tmp_path / "stuck.exe"
    with open(path, "wb") as writer:
        writer.write(b"x")
        writer.flush()
        a._event_record({"event_id": 11, "record_id": 8, "time": "t", "channel": "c", "provider": "p",
                         "data": {"TargetFilename": str(path)}})
        a._process_hash_queue()
    assert a._pending_agent[0]["data"]["hash_status"] == "busy_timeout"


class FailSecondWrite:
    """Wraps a file: the 2nd write raises after writing part of a line (a mid-batch failure)."""

    def __init__(self, f):
        self.f, self.calls = f, 0
        self.name = f.name

    def write(self, text):
        self.calls += 1
        if self.calls == 2:
            self.f.write("{\"cut")
            raise OSError("disk hiccup")
        return self.f.write(text)

    def __getattr__(self, name):
        return getattr(self.f, name)


def test_sink_retry_after_mid_batch_failure_loses_no_record(tmp_path):
    sink = JsonlSink(str(tmp_path))
    real = sink._file_for_today()
    sink._file = FailSecondWrite(real)
    sink._file.calls = 1          # the sink now writes a whole batch in one call: fail that one
    batch = [{"n": 1}, {"n": 2}]
    with pytest.raises(OSError):
        sink.write_batch(batch)
    sink.write_batch(batch)                                   # the agent's retry
    sink.close()
    parsed = []
    for line in open(real.name, encoding="utf-8").read().splitlines():
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            pass                                              # the isolated fragment
    assert {"n": 1} in parsed and {"n": 2} in parsed


def test_http_sink_retries_on_server_errors_and_names_refusals():
    answers = iter([500, 503, 200])
    transport = httpx.MockTransport(lambda req: httpx.Response(next(answers), json={}))
    sink = HttpSink("http://receiver", "vm", transport=transport)
    for _ in range(2):
        with pytest.raises(ConnectionError):
            sink.write_batch([{"a": 1}])
    sink.write_batch([{"a": 1}])
    assert sink.written == 1

    refused = HttpSink("http://receiver", "vm", transport=httpx.MockTransport(lambda r: httpx.Response(400)))
    with pytest.raises(ConnectionError, match="REFUSED"):
        refused.write_batch([{"a": 1}])


@pytest.mark.parametrize("label", ["vm\n", "host\n"])
def test_label_with_trailing_newline_rejected(tmp_path, label):
    client = TestClient(create_app(str(tmp_path)))
    assert client.post("/batch", json={"label": label, "records": [{"a": 1}]}).status_code == 400


def test_record_claiming_another_label_is_rejected(tmp_path):
    # review (low): a VM process must not be able to write records labelled "host"
    client = TestClient(create_app(str(tmp_path)))
    assert client.post("/batch", json={"label": "vm", "records": [{"label": "host", "a": 1}]}).status_code == 400
    assert client.post("/batch", json={"label": "vm", "records": [{"label": "vm", "a": 1}, {"a": 2}]}).status_code == 200


def test_receiver_comes_back_during_one_agent_run(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "RETRY_SECONDS", 0.2)
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 12)
    sock, port = reserve_port()
    receiver = LiveReceiver(tmp_path / "host_side", sock)
    threading.Timer(1.0, receiver.__enter__).start()          # comes up mid-run
    try:
        # 8 s run: leaves ample time after the receiver starts, even on a cold, busy machine
        # (with only 3.5 s left, a slow receiver start could end the run before delivery)
        Agent(agent_args(provider, tmp_path / "state", f"http://127.0.0.1:{port}", 8)).run()
    finally:
        time.sleep(0.2)
        receiver.__exit__(None, None, None)
    got = lines(tmp_path / "host_side" / "vm")
    assert len(got) == 12 and len({r["record_id"] for r in got}) == 12


def test_port_records_travel_over_http(tmp_path, monkeypatch):
    snapshots = [{}, {("127.0.0.1", 6001): 4242}]
    monkeypatch.setattr(ports_module, "listening_ports", lambda: snapshots.pop(0) if snapshots else {("127.0.0.1", 6001): 4242})
    monkeypatch.setattr(ports_module, "process_image", lambda pid: r"C:\x\server.exe")
    sock, port = reserve_port()
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    with LiveReceiver(tmp_path / "host_side", sock):
        a = Agent(parse_args(["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
                              "--label", "vm", "--state-dir", str(tmp_path / "state"),
                              "--send-to", f"http://127.0.0.1:{port}", "--run-seconds", "2",
                              "--port-interval", "0.5"]))
        a.run()
    got = [r for r in lines(tmp_path / "host_side" / "vm") if r.get("type") == "PORT_LISTEN_START"]
    assert got and got[0]["data"]["LocalPort"] == 6001
