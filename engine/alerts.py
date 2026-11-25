"""The one alert format (DESIGN 4.6: "Every alert stores which events triggered it and a
human-readable reason"). Sigma rules, our own rules and the check-in rhythm rule all produce
`Alert`s, so the graph, the report and the dashboard read one thing.

Alerts are kept in their OWN database file (not in the event store): the dev snapshots are
read-only, and one event store can be scored by several rule sets. Each alert names its
evidence by the event store's `dedup_key`s; `missing_evidence` checks they all exist.

The alert id is derived from (rule, host, evidence), so running the same rules twice over the
same events gives the same ids and the second write adds nothing.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field

LEVELS = ("informational", "low", "medium", "high", "critical")   # Sigma's levels
SOURCES = ("sigma", "analystlab", "beacon")                         # community / ours / rhythm


@dataclass(frozen=True)
class Alert:
    rule_id: str              # Sigma rule id, or "analystlab.<name>" / "beacon"
    title: str
    source: str
    level: str
    time: str                 # ISO-8601 UTC: when the rule's condition became true
    host: str
    reason: str               # one plain sentence: why it fired, with the numbers
    evidence: tuple           # dedup_keys of the events that triggered it
    details: dict = field(default_factory=dict, compare=False)   # scores, counts, matched fields
    # for alerts whose evidence can still GROW (a burst, a chain): what makes it one incident
    # (e.g. program + burst start). Then the id comes from it, not from the evidence, so the
    # live loop updates one alert instead of adding a new one each time more events arrive.
    incident: str = field(default="", compare=False)

    def __post_init__(self):
        if self.level not in LEVELS:
            raise ValueError(f"unknown level {self.level!r}")
        if self.source not in SOURCES:
            raise ValueError(f"unknown source {self.source!r}")
        if not self.evidence:
            raise ValueError("an alert needs at least one evidence event")
        if not self.reason.strip():
            raise ValueError("an alert needs a reason")
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def alert_id(self) -> str:
        if self.incident:
            body = "\x1f".join([self.rule_id, self.host, "incident", self.incident])
        else:
            body = "\x1f".join([self.rule_id, self.host, *sorted(self.evidence)])
        return hashlib.sha1(body.encode()).hexdigest()[:16]


def declared_note(alert: Alert) -> str:
    """v4 F7/F8: ' (declared on a command line, not recorded)' for an alert raised on a DECLARED row,
    '' otherwise: every one-line alert print shows it, so a screen never reads it as a recorded fact."""
    return " (declared on a command line, not recorded)" if (alert.details or {}).get("derived_from") == "command_line" else ""


class AlertStore:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, title TEXT, source TEXT NOT NULL,
  level TEXT NOT NULL, time TEXT NOT NULL, host TEXT, reason TEXT NOT NULL,
  evidence TEXT NOT NULL, details TEXT, events_db TEXT)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(time)")
        if "incident" not in {r[1] for r in self.db.execute("PRAGMA table_info(alerts)")}:
            self.db.execute("ALTER TABLE alerts ADD COLUMN incident TEXT")
        self.db.commit()

    def write(self, alerts, events_db: str = None) -> int:
        """Store alerts; returns how many were new. The same alert again is kept once; an
        incident alert that arrives again with MORE evidence updates its evidence, reason and
        details, keeping its first time and anything first recorded (e.g. seen_utc)."""
        new = 0
        for a in alerts:
            details = json.dumps(a.details, sort_keys=True, default=str)
            cur = self.db.execute(
                "INSERT OR IGNORE INTO alerts (alert_id, rule_id, title, source, level, time, host, reason, "
                "evidence, details, events_db, incident) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.alert_id, a.rule_id, a.title, a.source, a.level, a.time, a.host, a.reason,
                 json.dumps(list(a.evidence)), details, events_db, a.incident or None))
            if cur.rowcount:
                new += 1
                continue
            if not a.incident:
                continue
            old_ev, old_details = self.db.execute("SELECT evidence, details FROM alerts WHERE alert_id = ?",
                                                  (a.alert_id,)).fetchone()
            if set(a.evidence) <= set(json.loads(old_ev)):
                continue
            merged = dict(a.details)
            merged.update({k: v for k, v in json.loads(old_details or "{}").items() if k == "seen_utc"})
            self.db.execute("UPDATE alerts SET evidence = ?, reason = ?, details = ? WHERE alert_id = ?",
                            (json.dumps(sorted(set(a.evidence) | set(json.loads(old_ev)))), a.reason,
                             json.dumps(merged, sort_keys=True, default=str), a.alert_id))
        self.db.commit()
        return new

    def read(self, where: str = "1=1", params=()) -> list:
        rows = self.db.execute(
            f"SELECT rule_id, title, source, level, time, host, reason, evidence, details, incident FROM alerts "
            f"WHERE {where} ORDER BY time, alert_id", params).fetchall()
        return [Alert(r[0], r[1], r[2], r[3], r[4], r[5], r[6], tuple(json.loads(r[7])), json.loads(r[8] or "{}"),
                      r[9] or "") for r in rows]

    def events_dbs(self) -> dict:
        """{alert_id: the event store it was raised on (as written; None if not recorded)}."""
        return dict(self.db.execute("SELECT alert_id, events_db FROM alerts").fetchall())

    def close(self):
        self.db.close()


def missing_evidence(alert: Alert, events: sqlite3.Connection) -> list:
    """The alert's evidence keys that are NOT in the event store (should always be empty)."""
    missing = []
    for key in alert.evidence:
        if events.execute("SELECT 1 FROM events WHERE dedup_key = ?", (key,)).fetchone() is None:
            missing.append(key)
    return missing
