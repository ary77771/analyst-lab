"""Small on-disk state: the Windows bookmark and the agent's status heartbeat.

Files are written atomically (write a temporary file, then os.replace), the standard way
to make sure a crash never leaves a half-written file behind. On Windows, os.replace fails
with "access denied" while another program (the status app, antivirus, the search indexer)
briefly has the target open, so the replace is retried a few times.
"""

import json
import os
import tempfile
import time

REPLACE_ATTEMPTS = 20


def atomic_write_text(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp-", suffix=os.path.basename(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def read_text(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def write_json(path: str, data: dict) -> None:
    atomic_write_text(path, json.dumps(data, indent=2))
