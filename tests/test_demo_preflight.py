"""demo/preflight.py: the summary line, and the projector check on a store."""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo"))
import preflight as P  # noqa: E402


def test_one_failed_check_makes_it_not_ready():
    assert P.summary([P.check("a", True), P.check("b", True)])[0] == "READY"
    line, bad = P.summary([P.check("a", True), P.check("b", False)])
    assert line.startswith("NOT READY (1 of 2") and bad[0]["name"] == "b"


def test_projector_check_on_a_store(tmp_path):
    vm, mixed = str(tmp_path / "vm.db"), str(tmp_path / "mixed.db")
    for path, hosts in ((vm, ["analystlab-vm"]), (mixed, ["analystlab-vm", "other"])):
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, host TEXT)")
        con.executemany("INSERT INTO events (host) VALUES (?)", [(h,) for h in hosts])
        con.commit()
        con.close()
    assert P.projector_ok(vm) and not P.projector_ok(mixed) and not P.projector_ok(str(tmp_path / "missing.db"))


def test_official_variable_fails_the_first_check(monkeypatch):
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(P, "vbox", lambda *a: "")
    monkeypatch.setattr(P.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 1})())
    first = P.before_checks()[0]
    assert "ANALYSTLAB_OFFICIAL" in first["name"] and not first["ok"]
