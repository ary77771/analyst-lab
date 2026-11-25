"""Demo mode: the LIVE / REPLAY badge and the projector guard (debate 11, C4 and C5).

- Every screen shows a server-made badge: "LIVE: the test machine" or "REPLAY of a recorded run
  from <date>", so a replay can never pass for live (replays look exactly like live on purpose:
  that is the fallback's value, and the badge is what keeps it honest).
- Projector guard (privacy rule 7): in demo mode the dashboard refuses to open an event store that
  holds any machine other than the lab VM, so this laptop's own recording never reaches a projector.
- A replay dashboard can't start VM runs (its Run button is hidden; the endpoint refuses).
"""

import os
import sqlite3

from fastapi import APIRouter

VM_HOSTS = frozenset({"analystlab-vm"})
# Where the demo's live dashboard listens (demo\start.ps1). The replay page asks it, read-only, whether
# the live test machine raised an alert (live_status.HEALTH_READERS allows exactly that).
LIVE_DASHBOARD = "http://127.0.0.1:8780"
REPLAY_DASHBOARD = "http://127.0.0.1:8781"

WORDS = {
    "live": "LIVE: the test machine",
    "replay": "REPLAY of a recorded run",
    # demo/dash_rehearse.py: the whole live screen fed from a recording, no test machine involved
    "rehearsal": "REHEARSAL: a recorded run played back, no test machine",
}


def store_hosts(events_db):
    if not os.path.exists(events_db):
        return set()
    con = sqlite3.connect("file:" + os.path.abspath(events_db).replace("\\", "/") + "?mode=ro", uri=True)
    try:
        return {h for (h,) in con.execute("SELECT DISTINCT host FROM events")}
    except sqlite3.OperationalError:
        return set()
    finally:
        con.close()


def projector_problems(events_db):
    """[] when every host in the store is the lab VM; otherwise why the demo must not open it."""
    other = store_hosts(events_db) - VM_HOSTS
    return [f"the store holds {len(other)} machine(s) other than the lab VM; demo mode shows VM data only"] if other else []


def make_router(mode, detail=None):
    router = APIRouter()

    @router.get("/api/mode")
    def get_mode():
        if mode is None:
            return {"mode": None, "badge": None, "detail": None, "can_run": True}
        return {"mode": mode, "badge": WORDS[mode], "detail": detail, "can_run": mode in ("live", "rehearsal")}

    @router.get("/api/peer")
    def peer():
        """The demo's other dashboard, for the one-click switch: a replay is told where the live one is (it
        also reads its health for the small "live raised an alert" notice); the live one is told where the
        replay is (a link only: it reads nothing from it)."""
        return {"live_url": LIVE_DASHBOARD if mode == "replay" else None,
                "replay_url": REPLAY_DASHBOARD if mode == "live" else None}

    return router
