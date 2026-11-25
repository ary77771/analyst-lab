"""Whose alert is it? A warm test's alerts by the test's OWN PROGRAMS, not by the clock (2026-11-21).

Why: a warm machine is busy with its own housekeeping. In two of the first three real warm sessions
Windows' compatibility telemetry (CompatTelRunner.exe, started by the service host) started two shells
while a test was running or right after one. A time window cannot tell those from the test: on
2026-11-21 they fell 15 s and 22 s after S1's "running" line and would have stood under S1 as its own
"Alert raised".

The records can tell them apart exactly. The launcher starts every test as
    powershell.exe -NoProfile -File <CD>\\run_scenario.ps1 -Scenario <s> -RunId <run id>
so the recorded start of the program whose command line carries the run's own id is the test's first
program, and everything started from it (the recorder's parent links, Sysmon event 1) is the test's
program tree. An alert is the test's when a program of its own evidence is in that tree. Checked on
the real session of 2026-11-21: S5's tree holds S5's alert only, S1's tree S1's alert only, and the
two CompatTelRunner shells and the logon shell are in neither.

Nothing is decided by a program's name. The command line is read only to find the run id (a string
this laptop made up for the run); it is never returned, shown or logged.
"""

import os
import re
import sqlite3

RUN_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{4}")


def unknown(guid):
    """A missing or all-zero process id: "not recorded" (CLAUDE.md: a zero ParentProcessGuid is a GAP, never
    a real process). It is never a program, and never a parent that links anything into a tree."""
    return not guid or not str(guid).strip("{}").replace("-", "").strip("0")


class Trees:
    """The program tree of a run, and the programs an alert's evidence is about, read from the event
    store (read-only). Both are kept until the store grows."""

    def __init__(self, events_db):
        self.db = events_db
        self._trees, self._programs = {}, {}

    def _con(self):
        return sqlite3.connect("file:" + os.path.abspath(self.db).replace("\\", "/") + "?mode=ro", uri=True)

    def tree(self, run_id):
        """The run's own programs (their process ids as the recorder names them), or None when the start of
        the run's first program has not been recorded (yet): then nothing can be said by this rule."""
        if not run_id or not RUN_ID.fullmatch(str(run_id)) or not os.path.exists(self.db):
            return None
        try:
            con = self._con()
        except sqlite3.OperationalError:
            return None
        try:
            version = con.execute("SELECT MAX(id) FROM events").fetchone()[0]
            hit = self._trees.get(run_id)
            if hit and hit[0] == version:
                return hit[1]
            roots = [g for (g,) in con.execute("SELECT ProcessGuid FROM events WHERE event_id = 1 AND CommandLine LIKE ?", (f"%{run_id}%",))
                     if not unknown(g)]
            tree = None
            if roots:
                children = {}
                for g, p in con.execute("SELECT ProcessGuid, ParentProcessGuid FROM events WHERE event_id = 1 AND ProcessGuid IS NOT NULL"):
                    if not unknown(g) and not unknown(p):     # an unknown parent links nothing: programs whose start
                        children.setdefault(p, []).append(g)  # was not recorded are never gathered under one "parent"
                tree, todo = set(roots), list(roots)
                while todo:
                    for child in children.get(todo.pop(), []):
                        if child not in tree:
                            tree.add(child)
                            todo.append(child)
                tree = frozenset(tree)
            self._trees[run_id] = (version, tree)
            return tree
        except sqlite3.OperationalError:          # a store without these columns: nothing can be said
            return None
        finally:
            con.close()

    def programs(self, alert):
        """The programs (process ids) of the recorded events an alert is raised on."""
        keys = tuple(alert.evidence)
        key = (alert.alert_id, len(keys))
        if key in self._programs:
            return self._programs[key]
        found = set()
        try:
            con = self._con()
        except sqlite3.OperationalError:
            return frozenset()
        try:
            for i in range(0, len(keys), 200):
                part = keys[i:i + 200]
                marks = ",".join("?" * len(part))
                found.update(g for (g,) in con.execute(f"SELECT DISTINCT ProcessGuid FROM events WHERE dedup_key IN ({marks})", part) if not unknown(g))
        except sqlite3.OperationalError:
            return frozenset()
        finally:
            con.close()
        if found:                                 # (an alert whose events are not in the store yet is asked again next time)
            self._programs[key] = frozenset(found)
        return frozenset(found)

    def owns(self, run_id, alert):
        """True / False: the alert is / is not about one of the run's own programs. None: the run's tree
        is not known, so the question can't be answered from the records."""
        tree = self.tree(run_id)
        if tree is None:
            return None
        return bool(self.programs(alert) & tree)
