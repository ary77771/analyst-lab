"""VM receiver and agent HTTP delivery: every batch arrives at least once, even when the receiver
is down for a while (the agent keeps the batch and never moves its bookmark until it's stored).
Rare re-deliveries (e.g. a timeout after the receiver already wrote) are removed by the store."""

import glob
import json
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from fastapi.testclient import TestClient

import agent.main
from agent.main import Agent, parse_args
from engine.receiver import create_app
from tests.test_agent_mechanics import write_events


def lines(folder):
    out = []
    for path in sorted(glob.glob(str(folder / "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            out += [json.loads(l) for l in f if l.strip()]
    return out


def test_batch_is_written_to_label_folder(tmp_path):
    client = TestClient(create_app(str(tmp_path)))
    assert client.get("/health").json() == {"ok": True}
    r = client.post("/batch", json={"label": "vm", "records": [{"a": 1}, {"a": 2}]})
    assert r.status_code == 200 and r.json()["accepted"] == 2
    assert [x["a"] for x in lines(tmp_path / "vm")] == [1, 2]


@pytest.mark.parametrize("label", ["../escape", "host", "VM", "", "a" * 40])
def test_bad_labels_rejected(tmp_path, label):
    client = TestClient(create_app(str(tmp_path)))
    assert client.post("/batch", json={"label": label, "records": [{"a": 1}]}).status_code == 400
    assert not any(tmp_path.iterdir())


def reserve_port():
    """Bind a socket to a free port and KEEP it bound (not listening) until the receiver takes
    it over. Releasing the port and reusing it later is a race another process can win (a likely
    cause of a rare flake). While bound but not listening, connections are refused, which is
    exactly "receiver down"."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    return s, s.getsockname()[1]


class LiveReceiver:
    def __init__(self, recordings, reserved_socket, keys=None):
        self.sock = reserved_socket
        self.server = uvicorn.Server(uvicorn.Config(create_app(str(recordings), keys=keys), log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("test receiver did not start within 15 s")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)


def agent_args(provider, state_dir, url, seconds):
    return parse_args(["--channel", "Application", "--query", f"*[System[Provider[@Name='{provider}']]]",
                       "--label", "vm", "--state-dir", str(state_dir), "--send-to", url,
                       "--run-seconds", str(seconds), "--no-ports"])


def test_agent_delivers_every_event_once_through_receiver(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 30)
    sock, port = reserve_port()
    with LiveReceiver(tmp_path / "host_side", sock):
        Agent(agent_args(provider, tmp_path / "state", f"http://127.0.0.1:{port}", 3)).run()
    got = lines(tmp_path / "host_side" / "vm")
    assert len(got) == 30 and len({r["record_id"] for r in got}) == 30


def test_receiver_down_then_up_loses_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.main, "RETRY_SECONDS", 0.2)
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 10)
    sock, port = reserve_port()                                        # held, not listening
    url = f"http://127.0.0.1:{port}"

    down = Agent(agent_args(provider, tmp_path / "state", url, 2))     # connections refused
    down.run()
    assert down.errors >= 1
    assert down.sink.written == 0
    assert not (tmp_path / "state" / "bookmark.xml").exists()         # position never moved

    write_events(provider, 5, start=10)                                # more arrive meanwhile
    with LiveReceiver(tmp_path / "host_side", sock):
        Agent(agent_args(provider, tmp_path / "state", url, 3)).run()
    got = lines(tmp_path / "host_side" / "vm")
    assert len(got) == 15 and len({r["record_id"] for r in got}) == 15


def test_only_lab_labels_are_accepted(tmp_path):
    client = TestClient(create_app(str(tmp_path)))
    for label in ("vm", "vmruns", "vmdiag"):
        assert client.post("/batch", json={"label": label, "records": [{"a": 1}]}).status_code == 200
    for label in ("other", "con", "aux"):
        assert client.post("/batch", json={"label": label, "records": [{"a": 1}]}).status_code == 400
    assert sorted(p.name for p in tmp_path.iterdir()) == ["vm", "vmdiag", "vmruns"]


def test_size_limits(tmp_path, monkeypatch):
    import engine.receiver as rcv
    monkeypatch.setattr(rcv, "MAX_BODY", 100)
    client = TestClient(create_app(str(tmp_path)))
    assert client.post("/batch", json={"label": "vm", "records": [{"a": "y" * 200}]}).status_code == 413
    assert not (tmp_path / "vm").exists()


def test_unknown_host_header_refused(tmp_path):
    client = TestClient(create_app(str(tmp_path), allowed_hosts={"10.0.2.2", "127.0.0.1"}))
    assert client.post("/batch", json={"label": "vm", "records": [{"a": 1}]}, headers={"host": "evil.example"}).status_code == 421
    assert client.post("/batch", json={"label": "vm", "records": [{"a": 1}]}, headers={"host": "10.0.2.2:8770"}).status_code == 200


def test_lone_surrogate_is_written_escaped_not_fatal(tmp_path):
    from agent.sink import JsonlSink
    from engine.jsonl import iter_jsonl
    sink = JsonlSink(str(tmp_path / "vm"))
    sink.write_batch([{"a": 1}, {"name": "a\ud800b.exe"}, {"a": 3}])
    got = list(iter_jsonl(next((tmp_path / "vm").glob("*.jsonl")).as_posix()))
    assert [r.get("a") for r in got] == [1, None, 3] and got[1]["name"] == "a\ud800b.exe"
    assert sink.written == 3


def test_oversized_record_becomes_a_note_not_a_refusal(tmp_path, monkeypatch):
    import engine.receiver as rcv
    monkeypatch.setattr(rcv, "MAX_RECORD", 1000)
    client = TestClient(create_app(str(tmp_path)))
    huge = {"host": "vm1", "channel": "c", "record_id": 7, "time": "t", "event_id": 1, "data": {"CommandLine": "\u0639" * 2000}}
    r = client.post("/batch", json={"label": "vm", "records": [{"a": 1}, huge]})
    assert r.status_code == 200 and r.json()["accepted"] == 2          # the agent can move on
    got = lines(tmp_path / "vm")
    assert got[0] == {"a": 1}
    assert got[1]["type"] == "RECORD_TOO_LARGE" and got[1]["record_id"] == 7 and "data" not in got[1]


def test_vm_sink_sends_ascii_json(tmp_path):
    import httpx
    from agent.sink import HttpSink
    seen = []
    def answer(req):
        seen.append(req.content)
        return httpx.Response(200, json={})
    sink = HttpSink("http://receiver", "vm", transport=httpx.MockTransport(answer))
    sink.write_batch([{"name": "a\ud800b.exe"}, {"name": "\u0639"}])
    body = seen[0]
    body.decode("ascii")                                                # pure ASCII on the wire
    assert json.loads(body)["records"][0]["name"] == "a\ud800b.exe" and sink.written == 2


def test_lab_key_required_for_vm_events_only(tmp_path):
    client = TestClient(create_app(str(tmp_path), keys={"vm": "s3cret"}))
    body = {"label": "vm", "records": [{"a": 1}]}
    assert client.post("/batch", json=body).status_code == 401
    assert client.post("/batch", json=body, headers={"X-Lab-Key": "wrong"}).status_code == 401
    assert client.post("/batch", json=body, headers={"X-Lab-Key": "s3cret"}).status_code == 200
    assert client.post("/batch", json={"label": "vmruns", "records": [{"a": 1}]}).status_code == 200   # progress: keyless
    assert [r["a"] for r in lines(tmp_path / "vm")] == [1]


def test_vm_sink_sends_the_key(tmp_path):
    import httpx
    from agent.sink import HttpSink
    seen = []
    sink = HttpSink("http://r", "vm", key="k1", transport=httpx.MockTransport(lambda req: (seen.append(req.headers.get("x-lab-key")), httpx.Response(200, json={}))[1]))
    sink.write_batch([{"a": 1}])
    assert seen == ["k1"]
    sink2 = HttpSink("http://r", "vm", transport=httpx.MockTransport(lambda req: (seen.append(req.headers.get("x-lab-key")), httpx.Response(200, json={}))[1]))
    sink2.write_batch([{"a": 1}])
    assert seen[-1] is None


def test_pause_is_off_in_the_vm(tmp_path):
    from agent.control import PauseWatch, request_pause
    request_pause(str(tmp_path), minutes=5)
    assert PauseWatch(str(tmp_path)).poll("2099-01-01T00:00:00Z")            # normally seen
    off = PauseWatch(str(tmp_path), enabled=False)
    assert off.poll("2026-01-01T00:00:00Z") == [] and off.active is None


def test_agent_with_the_lab_key_gets_through_and_without_it_does_not(tmp_path):
    provider = f"AnalystLabTest-{uuid.uuid4().hex[:8]}"
    write_events(provider, 5)
    key_file = tmp_path / "key.txt"
    key_file.write_text("k-123\n", encoding="ascii")
    sock, port = reserve_port()
    with LiveReceiver(tmp_path / "host_side", sock, keys={"vm": "k-123"}):
        args = agent_args(provider, tmp_path / "state", f"http://127.0.0.1:{port}", 3)
        args.lab_key_file = str(key_file)
        Agent(args).run()
        no_key = Agent(agent_args(provider, tmp_path / "state2", f"http://127.0.0.1:{port}", 2))
        no_key.run()
        assert no_key.last_error and "401" in str(no_key.last_error)
    got = lines(tmp_path / "host_side" / "vm")
    assert len(got) == 5                                        # only the keyed agent's events


def test_key_is_required_only_when_armed(tmp_path):
    import pytest as _pt
    from engine.receiver import load_keys
    state = tmp_path / ".state"
    state.mkdir()
    (state / "lab_key.txt").write_text("a" * 64, encoding="ascii")
    assert load_keys(str(tmp_path)) == {}                         # a key alone doesn't arm it
    (state / "lab_key.required").write_text("", encoding="ascii")
    assert load_keys(str(tmp_path)) == {"vm": "a" * 64}
    (state / "lab_key.txt").write_text("", encoding="ascii")
    with _pt.raises(SystemExit):
        load_keys(str(tmp_path))                                  # armed but empty: refuse to start


def test_non_ascii_key_header_is_401_not_500(tmp_path):
    client = TestClient(create_app(str(tmp_path), keys={"vm": "k" * 64}))
    r = client.post("/batch", json={"label": "vm", "records": [{"a": 1}]}, headers={"X-Lab-Key": b"\xe4\xf6"})
    assert r.status_code == 401


def test_progress_records_get_their_arrival_time(tmp_path):
    client = TestClient(create_app(str(tmp_path)))
    client.post("/batch", json={"label": "vmruns", "records": [{"type": "SCENARIO_RUN"}]})
    client.post("/batch", json={"label": "vm", "records": [{"a": 1}]})
    assert "received_utc" in lines(tmp_path / "vmruns")[0] and "received_utc" not in lines(tmp_path / "vm")[0]
