"""The test server (Python's built-in http.server, as tools/test_server.ps1 runs it) serves
the S1 payload byte-for-byte and listens on 127.0.0.1 only. The payload is downloaded into
memory and compared, never saved or run (scenarios run only inside the VM).

The server runs in-process (the same stdlib classes the `python -m http.server` command uses)
on a port the OS assigns, so there is no "pick a free port, then hope it's still free" race and
no wait for a separate Python process to start (the likely cause of a rare cold-start flake,
VERIFICATION_LOG 2026-10-16/17).
"""

import functools
import hashlib
import os
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from tests.conftest import TCP_STATE_BROKEN

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WWW = os.path.join(ROOT, "scenarios", "www")
PAYLOAD = os.path.join(WWW, "s1_payload.exe")


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):          # keep test output clean
        pass


@pytest.fixture
def server():
    if not os.path.exists(PAYLOAD):                     # build it rather than silently skipping
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(ROOT, "tools", "build_scenarios.ps1")], check=True)
    assert os.path.exists(PAYLOAD)
    handler = functools.partial(QuietHandler, directory=WWW)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)   # port 0: the OS picks a free one
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_serves_payload_byte_for_byte(server):
    r = httpx.get(f"http://127.0.0.1:{server}/s1_payload.exe")
    assert r.status_code == 200
    with open(PAYLOAD, "rb") as f:
        assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(f.read()).hexdigest()


def test_missing_file_is_404(server):
    assert httpx.get(f"http://127.0.0.1:{server}/nothing-here").status_code == 404


@TCP_STATE_BROKEN
def test_listens_on_loopback_only(server):
    from agent.ports import listening_ports
    addresses = [ip for (ip, port) in listening_ports() if port == server]
    assert addresses == ["127.0.0.1"]
