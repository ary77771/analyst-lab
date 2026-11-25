"""A tiny pytest plugin for the "run the honesty checks" button (engine/dashboard/checks.py).

It writes one JSON line per event to the file named by ANALYSTLAB_CHECKS_OUT:
    {"collected": 118, "ids": ["tests/test_x.py::test_name", ...]}
    {"id": "tests/test_x.py::test_name", "outcome": "passed" | "failed" | "skipped"}
The dashboard reads that file while pytest runs. Before 2026-11-20 it counted the dots pytest prints
on the terminal instead; a coloured terminal (FORCE_COLOR) wraps every dot in colour codes, so the
count stayed at 0 while all tests passed. Results now come from pytest's own hooks, not its looks.
(pytest-reportlog does the same job; this is 20 lines and adds nothing to the shared .venv.)
"""

import json
import os

_seen = set()


def _write(obj):
    path = os.environ.get("ANALYSTLAB_CHECKS_OUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")


def pytest_collection_finish(session):
    _write({"collected": len(session.items), "ids": [i.nodeid for i in session.items]})


def pytest_runtest_logreport(report):
    """One line per test: the call's outcome, or a setup error / skip. A teardown error writes a
    second line for the same test; the reader keeps the last line per test, so it ends as failed."""
    if report.when == "teardown":
        if report.outcome == "failed":
            _write({"id": report.nodeid, "outcome": "failed"})
        return
    if report.nodeid in _seen:
        return
    if report.when == "call" or report.outcome != "passed":
        _seen.add(report.nodeid)
        _write({"id": report.nodeid, "outcome": report.outcome})
