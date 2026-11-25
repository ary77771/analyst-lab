"""VM receiver: accepts event batches from the VM agent and records them on the host.

The VM has no shared folders (isolation), so its agent sends batches over HTTP to this small
FastAPI service on 127.0.0.1:8770. From inside the VM that is http://10.0.2.2:8770 (VirtualBox
NAT maps 10.0.2.2 to the host's loopback). Each batch is appended with the same JsonlSink the
host agent uses, so VM recordings look exactly like host recordings:
recordings/<label>/<UTC date>.jsonl. The agent saves its bookmark only after a 200 response.

    python -m engine.receiver            # serve on 127.0.0.1:8770

Limits (security review 2026-10-23: data from the VM must not be able to break the host):
only the lab's own labels (vm, vmruns, vmdiag); a request body of at most 64 MB (Content-Length
required); a record over 1 MB (UTF-8) is stored as a small RECORD_TOO_LARGE note instead (refusing
the batch would make the agent retry it forever and stall the recording); when served by main(), only the Host names the VM
and the laptop really use (127.0.0.1, localhost, 10.0.2.2), so a web page in the laptop's
browser can't reach it through DNS rebinding. Lab key (2026-10-23): when
recordings/.state/lab_key.txt exists (made by tools/make_vm_bundle.ps1 for a new VM snapshot),
records for label "vm" (the VM agent's events and file fingerprints) need header X-Lab-Key with
that key; the agent reads it from a file only the VM's administrators can read, so a scenario
program (normal user) can't forge evidence. Progress records (vmruns) come from user-level
scripts and stay keyless (a forged one can only abort a run, visibly).
"""

import argparse
import hmac
from datetime import datetime, timezone
import os
import re
import threading

import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agent.sink import JsonlSink

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABEL = re.compile(r"^[a-z0-9_-]{1,32}$")
MAX_RECORDS = 5000      # the agent sends batches of <= 200 events; anything far larger is refused
LAB_LABELS = frozenset({"vm", "vmruns", "vmdiag"})     # VM agent, run records, VM diagnostics
MAX_BODY = 64 * 1024 * 1024                             # 200 events x the largest real record fits
MAX_RECORD = 1024 * 1024                                # UTF-8 bytes; a 2 x 32 k-character command line fits
LAB_HOSTS = frozenset({"127.0.0.1", "localhost", "10.0.2.2"})


class Batch(BaseModel):
    label: str
    records: list[dict]


def _capped(r: dict) -> dict:
    size = len(json.dumps(r, ensure_ascii=False).encode("utf-8", "backslashreplace"))
    if size <= MAX_RECORD:
        return r
    keep = {k: r[k] for k in ("host", "label", "session", "source", "channel", "record_id", "seq", "event_id", "time") if k in r}
    return dict(keep, type="RECORD_TOO_LARGE", parse_error=f"receiver: record of {size} bytes replaced (limit {MAX_RECORD})")


def create_app(recordings_dir: str, labels=LAB_LABELS, allowed_hosts=None, keys=None) -> FastAPI:
    """allowed_hosts: Host header names accepted (None = no check, e.g. for tests).
    keys: {label: key} that must arrive as header X-Lab-Key for that label."""
    keys = keys or {}
    app = FastAPI(title="Analyst Lab VM receiver")
    sinks: dict[str, JsonlSink] = {}
    lock = threading.Lock()                 # FastAPI runs sync endpoints on a thread pool

    @app.middleware("http")
    async def limits(request: Request, call_next):
        if allowed_hosts is not None:
            host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
            if host not in allowed_hosts:
                return JSONResponse({"detail": "unknown Host"}, status_code=421)
        if request.method == "POST":
            size = request.headers.get("content-length")
            if size is None or not size.isdigit():
                return JSONResponse({"detail": "Content-Length required"}, status_code=411)
            if int(size) > MAX_BODY:
                return JSONResponse({"detail": f"request body over {MAX_BODY} bytes"}, status_code=413)
        return await call_next(request)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/batch")
    def batch(b: Batch, request: Request):
        need = keys.get(b.label)
        if need is not None and not hmac.compare_digest(request.headers.get("x-lab-key", "").encode("utf-8", "replace"),
                                                        need.encode("utf-8")):
            raise HTTPException(status_code=401, detail="lab key missing or wrong")
        if not LABEL.fullmatch(b.label) or b.label == "host" or b.label not in labels:
            raise HTTPException(status_code=400, detail=f"label must be one of {sorted(labels)}")
        if len(b.records) > MAX_RECORDS:
            raise HTTPException(status_code=413, detail=f"at most {MAX_RECORDS} records per batch")
        # an oversized record is replaced by a small "too large" note, not refused with the whole
        # batch: a refusal would make the agent retry the same batch forever and stall recording
        records = [_capped(r) for r in b.records]
        if b.label == "vmruns":
            # progress/run records come from user-level scripts (no key): note when they really
            # ARRIVED, so a run window can be checked against the laptop's own clock
            now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            records = [dict(r, received_utc=now) for r in records]
        # a record may not claim another recording than its batch (e.g. "host" from inside the VM)
        if any("label" in r and r["label"] != b.label for r in b.records):
            raise HTTPException(status_code=400, detail="a record's label differs from the batch label")
        with lock:
            sink = sinks.get(b.label)
            if sink is None:
                sink = sinks[b.label] = JsonlSink(os.path.join(recordings_dir, b.label))
            sink.write_batch(records)       # flushed and fsync'd before we answer
            return {"accepted": len(b.records), "written_total": sink.written}

    return app


def load_keys(recordings_dir: str) -> dict:
    """The key is REQUIRED only once lab_key.required exists (set after the new VM snapshot passed,
    docs/plans/vm-security.md): making a key alone must not lock out an older snapshot."""
    state = os.path.join(recordings_dir, ".state")
    if not os.path.exists(os.path.join(state, "lab_key.required")):
        return {}
    try:
        with open(os.path.join(state, "lab_key.txt"), encoding="ascii") as f:
            key = f.read().strip()
    except OSError:
        key = ""
    if len(key) < 32:
        raise SystemExit("refusing to start: lab_key.required is set but lab_key.txt is missing, empty or too short")
    return {"vm": key}


def main(argv=None):
    import uvicorn

    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8770)
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    a = p.parse_args(argv)
    keys = load_keys(a.recordings)
    print("lab key: " + ("required for label vm" if keys else "not required (lab_key.required not set)"))
    uvicorn.run(create_app(a.recordings, allowed_hosts=LAB_HOSTS, keys=keys), host="127.0.0.1", port=a.port)


if __name__ == "__main__":
    main()
