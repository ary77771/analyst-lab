"""Recording sink: appends events as JSON lines, one file per UTC day.

recordings/<label>/<YYYY-MM-DD>.jsonl

Each batch is flushed and fsync'd before the caller saves the bookmark, so a crash can
cause at most a re-delivery of the last batch (never a silent loss). A re-delivered event
comes from a new agent session, so duplicates are removed by (host, channel, record_id,
time), which is what the engine's store does.

If a previous run died mid-write, the file may end in a partial line; a newline is added
before appending so the partial line stays isolated (readers skip unparsable lines).
"""

import json
import os
from datetime import datetime, timezone


class HttpSink:
    """Sends each batch to the host's VM receiver (engine/receiver.py) instead of a local file.

    write_batch returns only after the receiver confirms (HTTP 200) that the batch is on the
    host's disk; any failure raises ConnectionError (an OSError), so the agent keeps the batch,
    retries later, and does not move its bookmark.
    """

    def __init__(self, url: str, label: str, timeout: float = 15.0, transport=None, key: str = None):
        import httpx

        self.url = url.rstrip("/") + "/batch"
        self.label = label
        self.headers = {"Content-Type": "application/json"}
        if key:
            self.headers["X-Lab-Key"] = key              # proves the batch comes from the lab's agent
        self.written = 0
        self._client = httpx.Client(timeout=timeout, transport=transport)   # transport: tests only
        self._httpx = httpx

    @property
    def current_path(self):
        return self.url

    def write_batch(self, records) -> None:
        if not records:
            return
        # ASCII-only JSON (\u escapes): a lone surrogate in a file name can't break the
        # encoding and stall the VM's recording (review 2026-10-23); same JSON on the receiver
        body = json.dumps({"label": self.label, "records": records}, ensure_ascii=True).encode("ascii")
        try:
            r = self._client.post(self.url, content=body, headers=self.headers)
        except self._httpx.HTTPError as e:
            raise ConnectionError(f"receiver unreachable: {e}") from e
        if 400 <= r.status_code < 500:
            # A refused request won't fix itself (e.g. a bad label): say so plainly. It is still
            # retried, so nothing is dropped, and it shows in status.json as last_error.
            raise ConnectionError(f"receiver REFUSED the batch (HTTP {r.status_code}, check the agent's "
                                  f"settings): {r.text[:200]}")
        if r.status_code != 200:
            raise ConnectionError(f"receiver answered HTTP {r.status_code}: {r.text[:200]}")
        self.written += len(records)

    def close(self) -> None:
        self._client.close()


def _ends_without_newline(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return False
            f.seek(-1, os.SEEK_END)
            return f.read(1) != b"\n"
    except FileNotFoundError:
        return False


class JsonlSink:
    def __init__(self, folder: str):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._day = None
        self._file = None
        self.written = 0

    def _file_for_today(self):
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if day != self._day:
            self.close()
            self._day = day
            path = os.path.join(self.folder, f"{day}.jsonl")
            needs_newline = _ends_without_newline(path)
            self._file = open(path, "a", encoding="utf-8")
            if needs_newline:
                self._file.write("\n")
        return self._file

    @property
    def current_path(self):
        return self._file.name if self._file else None

    def write_batch(self, records) -> None:
        if not records:
            return
        # encode the whole batch first: a record that can't be written as UTF-8 (a lone surrogate
        # in a file name, review 2026-10-23) is written with \u escapes instead, and nothing is
        # half-written if encoding fails (a retry would otherwise duplicate the first records)
        lines = []
        for record in records:
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            try:
                line.encode("utf-8")
            except UnicodeEncodeError:
                line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
            lines.append(line + "\n")
        f = self._file_for_today()
        try:
            f.write("".join(lines))
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            # A failed write can leave a partial last line. Close the file so the retry reopens
            # it and starts on a fresh line, instead of gluing its first record onto the fragment.
            try:
                f.close()
            except OSError:
                pass
            self._file = None
            self._day = None
            raise
        self.written += len(records)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
