"""Is a demo replay still filling its store? (VISION's critique 3 of 2026-11-24.)

tools/demo_replay.py feeds a recorded run into a fresh store at 3x speed and scores it every 2 seconds, in the
same process as the dashboard it serves. For 15 to 20 seconds after a start the store is incomplete, and a
lab opened then would say things like "This alert isn't in this recording", which read as findings.

Only the replay itself knows when it has finished (a quiet stretch in the recording is not the end: gaps are
capped at 5 recorded seconds, and a scoring pass comes every 2). So it says so here:
    started(total)   before the first record is fed: how many records the recording holds
    finished()       after the last scoring pass: every record and every alert is in the store
and GET /api/labs/state hands it to the Labs shell, which draws no lab until `done` is true.

A dashboard that is not a demo replay never calls these: state() is then None ("nothing is filling").
Not a lab (its name starts with "_").
"""

import threading

_lock = threading.Lock()
_state = {"total": None, "done": None}


def started(total):
    with _lock:
        _state.update(total=int(total), done=False)


def finished():
    with _lock:
        if _state["done"] is not None:
            _state["done"] = True


def reset():
    """For tests: as if no replay had ever been started in this process."""
    with _lock:
        _state.update(total=None, done=None)


def state():
    """{"total": records in the recording, "done": is the store whole?}, or None when no replay runs here."""
    with _lock:
        return None if _state["done"] is None else dict(_state)
