"""SQLite event store.

One row per event, **one column per field** (Sysmon field names kept as-is), because the
Sigma SQLite backend turns rules into plain SQL over such a flat table and fails on missing
columns. New field names are added as columns automatically. Timestamps are ISO-8601 text.

Duplicates: the agent may re-deliver a batch after a crash (by design: never lose, maybe
repeat). A Windows event is identified by (host, channel, record_id, time): the time part
keeps two different events apart when a VM snapshot restore rewinds record numbers.
Agent-generated events (PORT_LISTEN_START/STOP, FILE_HASH) are identified by
(host, session, seq, time): the time part keeps them apart if a live VM snapshot with a
running agent is restored (same session and seq numbers again, different time).
"""

import hashlib
import sqlite3

CORE_COLUMNS = [
    ("host", "TEXT"), ("label", "TEXT"), ("session", "TEXT"), ("source", "TEXT"),
    ("channel", "TEXT"), ("record_id", "INTEGER"), ("seq", "INTEGER"), ("event_id", "INTEGER"),
    ("type", "TEXT"), ("provider", "TEXT"), ("time", "TEXT"), ("origin", "TEXT"),
    ("origin_recorded", "TEXT"),      # the agent's own tag when engine.retag changed it on load
    ("parse_error", "TEXT"), ("raw_xml", "TEXT"),
    ("paused", "INTEGER"),            # 1 = recorded during a user pause: number/time/type only
]
CORE_NAMES = {name for name, _ in CORE_COLUMNS}
# SQLite column names ignore case, so every name check is done in lower case.
RESERVED_LOWER = {n.lower() for n in CORE_NAMES} | {"id", "dedup_key"}

# Numeric Sysmon fields get NUMERIC affinity, so range comparisons (Sigma gt/lt on ports or
# process ids) compare numbers, not text. '443' and 443 both still match DestinationPort = 443.
NUMERIC_FIELDS = {"ProcessId", "ParentProcessId", "SourcePort", "DestinationPort", "LocalPort",
                  "TerminalSessionId", "size", "ref_record_id"}

# Sysmon fields for the event types we record (schema 4.91), created up front so Sigma
# queries never hit a missing column. Anything else is added on first sight.
SYSMON_FIELDS = [
    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description",
    "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User",
    "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes",
    "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser",
    "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort",
    "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
    "DestinationPort", "DestinationPortName", "TargetFilename", "CreationUtcTime",
    "QueryName", "QueryStatus", "QueryResults", "Contents", "Hash", "IsExecutable", "Archived",
    "State", "Version", "SchemaVersion", "Configuration", "ConfigurationFileHash",
    "EventType", "TargetObject", "Details", "NewName",          # registry events 12/13/14 (config v0.3)
    # agent events: PORT_LISTEN_START/STOP and FILE_HASH
    "LocalIp", "LocalPort", "hash_status", "sha256", "size", "ref_record_id", "ref_time",
]

INDEXED = ["time", "event_id", "ProcessGuid", "ParentProcessGuid", "TargetFilename", "DestinationIp"]


def _safe(v):
    return v.encode("utf-8", "backslashreplace").decode("utf-8") if isinstance(v, str) else v


def _safe_key(k):
    try:
        k.encode("utf-8")
        return k
    except UnicodeEncodeError:
        return _safe(k)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class EventStore:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._create()
        # lower-case name -> the column's actual name
        self.columns = {row[1].lower(): row[1] for row in self.db.execute("PRAGMA table_info(events)")}

    def _create(self):
        cols = ",\n  ".join(f"{_q(n)} {t}" for n, t in CORE_COLUMNS)
        fields = ",\n  ".join(f"{_q(f)} {'NUMERIC' if f in NUMERIC_FIELDS else 'TEXT'}" for f in SYSMON_FIELDS)
        self.db.execute(f"""CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  dedup_key TEXT NOT NULL UNIQUE,
  {cols},
  {fields}
)""")
        for col in INDEXED:
            self.db.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{col} ON events({_q(col)})")
        self.db.commit()

    @staticmethod
    def dedup_key(record: dict) -> str:
        if record.get("record_id") is not None:
            return f"{record['host']}|{record.get('channel')}|{record['record_id']}|{record.get('time')}"
        if "parse_error" in record:
            # unreadable event with no record number: identify it by its content
            body = (record.get("raw_xml") or "") + (record.get("parse_error") or "")
            return f"{record['host']}|{record.get('session')}|parse_error|{hashlib.sha1(body.encode()).hexdigest()}"
        return f"{record['host']}|{record.get('session')}|agent|{record.get('seq')}|{record.get('time')}"

    def _column_for(self, name: str) -> str:
        """The real column for a field name, created on first sight (case-insensitively)."""
        existing = self.columns.get(name.lower())
        if existing:
            return existing
        self.db.execute(f"ALTER TABLE events ADD COLUMN {_q(name)} TEXT")
        self.columns[name.lower()] = name
        return name

    def insert(self, records) -> tuple:
        """Insert records; return (inserted, duplicates)."""
        inserted = duplicates = 0
        for record in records:
            row = {k: record.get(k) for k in CORE_NAMES if k in record}
            used = {k.lower() for k in row}
            for k, v in (record.get("data") or {}).items():
                k = _safe_key(k)
                if k.lower() in RESERVED_LOWER:
                    k = f"data_{k}"
                while k.lower() in used:            # same name twice in one event, differing in case
                    k = f"dup_{k}"
                used.add(k.lower())
                row[k] = v if not isinstance(v, (list, dict)) else str(v)
            row["dedup_key"] = self.dedup_key(record)

            row = {self._column_for(k): v for k, v in row.items()}
            names = list(row)
            sql = (f"INSERT OR IGNORE INTO events ({', '.join(_q(n) for n in names)}) "
                   f"VALUES ({', '.join('?' for _ in names)})")
            values = [row[n] for n in names]
            try:
                cur = self.db.execute(sql, values)
            except UnicodeEncodeError:
                # a lone surrogate (e.g. a broken file name) can't be stored as UTF-8: keep it
                # readable as a \udc80-style escape instead of failing the whole load
                cur = self.db.execute(sql, [_safe(v) for v in values])
            if cur.rowcount == 1:
                inserted += 1
            else:
                duplicates += 1
        self.db.commit()
        return inserted, duplicates

    def count(self, where: str = "1=1", params=()) -> int:
        return self.db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]

    def close(self):
        self.db.close()
