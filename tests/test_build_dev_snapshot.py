"""tools/build_dev_snapshot.py: only dev days go in, the result is read-only and plain-journal."""

import json
import os
import sqlite3
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import build_dev_snapshot as b  # noqa: E402


def rec(n, time, host="h"):
    return {"host": host, "channel": "Microsoft-Windows-Sysmon/Operational", "record_id": n, "time": time,
            "event_id": 1, "source": "sysmon", "data": {"Image": "C:\\x.exe"}}


def write_day(folder, day, records):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, f"{day}.jsonl"), "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_only_dev_days_and_read_only(tmp_path):
    vm = tmp_path / "vm"
    write_day(str(vm), "2026-10-21", [rec(1, "2026-10-21T10:00:00Z")])
    write_day(str(vm), "2026-10-22", [rec(2, "2026-10-22T23:59:59Z"), rec(3, "2026-10-23T00:00:05Z")])  # spills over
    write_day(str(vm), "2026-10-23", [rec(4, "2026-10-23T10:00:00Z")])                                   # test day
    db = str(tmp_path / "dev.db")
    info = b.build(db, b.day_files(str(vm), "2026-10-22"), "2026-10-22", retag=False)
    assert info["events"] == "2"                                  # record 3 (after midnight) and day 23 left out
    assert json.loads(info["totals"])["after_cutoff_removed"] == 1
    assert json.loads(info["files"]) == ["2026-10-21.jsonl", "2026-10-22.jsonl"]
    assert not os.stat(db).st_mode & stat.S_IWRITE                # marked read-only
    assert not os.path.exists(db + "-wal")
    con = b.open_dev(db)
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM events")
    con.close()
    # rebuilding over the read-only file works
    info = b.build(db, b.day_files(str(vm), "2026-10-21"), "2026-10-21", retag=False)
    assert info["events"] == "1"
    os.chmod(db, stat.S_IREAD | stat.S_IWRITE)


def test_refuses_to_build_from_a_worktree(tmp_path, monkeypatch):
    fake = tmp_path / "wt"
    fake.mkdir()
    (fake / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    monkeypatch.setattr(b, "PROJECT_ROOT", str(fake))
    assert b.main(["--recordings", str(tmp_path / "rec")]) == 2
    assert not (tmp_path / "rec" / "scratch" / "dev" / "dev-vm.db").exists()
