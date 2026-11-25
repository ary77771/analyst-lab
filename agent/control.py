"""The one request the status app can send the agent: "pause for 1 hour" (DESIGN 9.2).

The app writes <state folder>/pause.json; the agent reads it on every loop pass. No admin
rights and no network: the app and the agent only share this small file.

    {"requested": "<UTC time of the click>", "until": "<UTC end>"}

While paused, the agent still reads every event (so the bookmark moves and nothing is lost),
but writes only a *skeleton* of it: record number, time, event type and "paused": true, never
the program, file, address or command line. Statistics stay honest (we know how much happened
while paused, and Sysmon's numbering stays complete) and nothing private is kept.

Pauses are decided by the EVENT's own time, not by when the agent reads it: an event from
inside the pause that is read a little later is still a skeleton. A pause can never be longer
than PAUSE_MAX_MINUTES, even if the file is damaged or edited by hand. "Resume now" rewrites
the file with until = now.
"""

import json
import os
from datetime import datetime, timedelta, timezone

from .state import atomic_write_text

PAUSE_FILE = "pause.json"
PAUSE_MINUTES = 60
PAUSE_MAX_MINUTES = 65          # a little slack for clock rounding; a longer pause is cut here


def utc_text(dt: datetime) -> str:
    """Sysmon's own time format (7 fractional digits + Z), so times compare as text."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def parse_utc(text: str) -> datetime:
    t = text.rstrip("Z")
    if "." in t:
        head, frac = t.split(".", 1)
        t = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(t).replace(tzinfo=timezone.utc)


def pause_path(state_dir: str) -> str:
    return os.path.join(state_dir, PAUSE_FILE)


def request_pause(state_dir: str, minutes: int = PAUSE_MINUTES, now: datetime = None) -> dict:
    now = now or datetime.now(timezone.utc)
    minutes = max(1, min(int(minutes), PAUSE_MINUTES))
    pause = {"requested": utc_text(now), "until": utc_text(now + timedelta(minutes=minutes))}
    os.makedirs(state_dir, exist_ok=True)
    atomic_write_text(pause_path(state_dir), json.dumps(pause))
    return pause


def resume_now(state_dir: str, now: datetime = None) -> None:
    """End a running pause early (the pause itself stays on record)."""
    current = read_pause(state_dir)
    if current is None:
        return
    now = now or datetime.now(timezone.utc)
    if parse_utc(current[1]) > now:
        atomic_write_text(pause_path(state_dir), json.dumps({"requested": current[0], "until": utc_text(now)}))


def read_pause(state_dir: str):
    """(requested, until) as Sysmon-format UTC text, or None if there is no valid pause file.
    until is capped at requested + PAUSE_MAX_MINUTES."""
    try:
        with open(pause_path(state_dir), encoding="utf-8") as f:
            raw = json.load(f)
        start, end = parse_utc(raw["requested"]), parse_utc(raw["until"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    end = min(end, start + timedelta(minutes=PAUSE_MAX_MINUTES))
    if end <= start:
        return None
    return utc_text(start), utc_text(end)


class PauseWatch:
    """The agent's view of pauses: remembers every pause seen in this session (an event read
    late must still be judged by the pause that covered it) and reports start/end changes."""

    def __init__(self, state_dir: str, enabled: bool = True):
        self.state_dir = state_dir
        # disabled in the lab VM (security review 2026-10-23): a scenario must not be able to
        # "pause" the recorder by writing a pause file
        self.enabled = enabled
        self.intervals = {}          # requested -> until
        self.active = None           # requested time of the pause currently running, if any

    def covers(self, event_time) -> bool:
        if not event_time:
            return False
        return any(start <= event_time <= end for start, end in self.intervals.items())

    def poll(self, now_text: str):
        """Re-read the pause file. Returns a list of ("start"|"end"|"change", requested, until)."""
        changes = []
        if not self.enabled:
            return changes
        current = read_pause(self.state_dir)
        if current is not None:
            start, end = current
            if self.intervals.get(start) != end:
                # a pause that already ended (the agent was off) still counts for events read
                # late, and still appears on the timeline: start, then end at once below
                kind = "change" if start in self.intervals else "start"
                self.intervals[start] = end
                if kind == "start" and self.active is not None:     # replaced before it ended
                    changes.append(("end", self.active, self.intervals[self.active]))
                changes.append((kind, start, end))
                if kind == "start":
                    self.active = start
        if self.active is not None and self.intervals[self.active] <= now_text:
            changes.append(("end", self.active, self.intervals[self.active]))
            self.active = None
        return changes

    @property
    def paused_until(self):
        return self.intervals[self.active] if self.active else None
