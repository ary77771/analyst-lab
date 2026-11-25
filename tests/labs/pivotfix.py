"""A small made-up story for the night-pivot labs' tests (fixtures, never recordings).

explorer.exe (parent never seen: zero id) -> fetch.exe {F} looks up test.lab.example, connects to
10.0.2.2:18765, creates tool.exe; the agent fingerprints tool.exe; fetch.exe starts tool.exe {C}, which sets
a Run key. notepad.exe {N} is unrelated. One alert cites the create and the start.
"""

import sqlite3
from datetime import timedelta

from engine.alerts import Alert, AlertStore
from engine.store import EventStore
from tests.test_detect import T0, ev

HASH = "ab" * 32
VM = "analystlab-vm"          # engine.dashboard.demo_mode.VM_HOSTS
LAPTOP = "laptop-1"
ZERO = "{00000000-0000-0000-0000-000000000000}"
FETCH = r"C:\Users\u\fetch.exe"
TOOL = r"C:\Users\u\tool.exe"
RUNKEY = r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\tool"


class FakeContext:
    """The parts of engine.labs.Context the night-pivot labs use."""

    def __init__(self, events_db, alerts_db, recordings=None, report=None, hosts=frozenset({"analystlab-vm"})):
        self.events_db, self.alerts_db, self.recordings, self._report = events_db, alerts_db, recordings, report
        self.hosts = None if hosts is None else frozenset(hosts)     # as labs.Context: None = every machine

    def events(self):
        import os
        if not os.path.exists(self.events_db):
            raise FileNotFoundError(self.events_db)
        return sqlite3.connect("file:" + self.events_db.replace("\\", "/") + "?mode=ro", uri=True)

    def reading(self):
        """As labs.Context.reading(): a read-only connection that closes after the `with` block."""
        from contextlib import closing
        return closing(self.events())

    def alerts(self):
        s = AlertStore(self.alerts_db)
        try:
            return s.read()
        finally:
            s.close()

    def shown_alerts(self):
        return sorted(self.alerts(), key=lambda a: a.time, reverse=True)

    def alert(self, alert_id):
        return next((a for a in self.alerts() if a.alert_id == alert_id), None)

    def event(self, key):
        con = self.events()
        try:
            con.row_factory = sqlite3.Row
            row = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,)).fetchone()
        finally:
            con.close()
        return {k: row[k] for k in row.keys() if row[k] is not None} if row else None

    def story(self, alert):
        """(seed, time, sub-graph) as the dashboard builds it (engine.report.alert_view over the real graph);
        `self.add_edges(G)` may add hand-made layer-2 edges first (the made-up store has no pool of rates)."""
        from engine import report as report_mod
        from engine.graph import build_graph
        con = sqlite3.connect(self.events_db)
        try:
            G = build_graph(con)
        finally:
            con.close()
        if getattr(self, "add_edges", None):
            self.add_edges(G)
        return report_mod.alert_view(alert, G, None)

    def report(self, alert):
        if self._report is None:
            raise RuntimeError("no report here")
        return self._report(alert)


def use(monkeypatch, ctx):
    """Make every night-pivot lab read `ctx` as the running dashboard's context (as labs.context() would)."""
    from engine.labs import cases, claim, pivot
    for mod in (pivot, cases, claim):
        monkeypatch.setattr(mod, "_context", lambda: ctx)


def story(tmp_path):
    """(events_db, alerts_db, alert, keys): the store and alert DB of the made-up story. keys[8] and the
    second alert are the LAPTOP's: the labs must hide them unless the laptop switch is on."""
    t_hash = (T0 + timedelta(seconds=3)).isoformat().replace("+00:00", "Z")
    recs = [
        ev(1, 0, host=VM, ProcessGuid="{F}", ParentProcessGuid=ZERO, Image=FETCH, ParentImage=r"C:\Windows\explorer.exe",
           ProcessId=10, User="LAB\\u", CommandLine=f"{FETCH} --get"),
        ev(22, 1, host=VM, ProcessGuid="{F}", Image=FETCH, ProcessId=10, QueryName="test.lab.example", User="LAB\\u"),
        ev(3, 1.5, host=VM, ProcessGuid="{F}", Image=FETCH, ProcessId=10, Initiated="true", DestinationIp="10.0.2.2",
           DestinationPort=18765, SourceIp="10.0.2.15", User="LAB\\u"),
        ev(11, 2, host=VM, ProcessGuid="{F}", Image=FETCH, ProcessId=10, TargetFilename=TOOL, User="LAB\\u"),
        {"host": VM, "session": "s1", "seq": 7, "time": t_hash, "type": "FILE_HASH", "source": "agent",
         "data": {"sha256": HASH.upper(), "hash_status": "ok", "final_path": TOOL, "TargetFilename": TOOL,
                  "ProcessGuid": "{f}"}},                       # the writer's id, in the recorder's own (lower) case
        ev(1, 5, host=VM, ProcessGuid="{C}", ParentProcessGuid="{F}", Image=TOOL, ParentImage=FETCH, ProcessId=11,
           ParentProcessId=10, User="LAB\\u", Hashes=f"MD5={'0' * 32},SHA256={HASH.upper()}", CommandLine=TOOL),
        ev(13, 6, host=VM, ProcessGuid="{C}", Image=TOOL, ProcessId=11, TargetObject=RUNKEY, EventType="SetValue",
           Details=TOOL),
        ev(1, 9, host=VM, ProcessGuid="{N}", ParentProcessGuid=ZERO, Image=r"C:\Windows\notepad.exe", ProcessId=12,
           User="LAB\\other"),
        # the laptop: never shown by default (night rule 11)
        ev(1, 10, host=LAPTOP, ProcessGuid="{L}", ParentProcessGuid=ZERO, Image=FETCH, ProcessId=99, User="LAPTOP\\me",
           Hashes=f"SHA256={HASH.upper()}"),
    ]
    events_db = str(tmp_path / "s.db")
    st = EventStore(events_db)
    st.insert(recs)
    st.close()
    keys = [EventStore.dedup_key(r) for r in recs]
    alert = Alert("analystlab.fetch_write_run", "A downloaded program was started", "analystlab", "high",
                  recs[5]["time"], VM, "fetch.exe created tool.exe and started it 3 s later",
                  (keys[3], keys[5]))
    laptop_alert = Alert("analystlab.fetch_write_run", "Laptop alert", "analystlab", "high", recs[8]["time"], LAPTOP,
                         "fetch.exe ran on the laptop", (keys[8],))
    alerts_db = str(tmp_path / "alerts.db")
    s = AlertStore(alerts_db)
    s.write([alert, laptop_alert])
    s.close()
    return events_db, alerts_db, alert, keys
