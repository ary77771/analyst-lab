"""tools/lab_status.py: completeness by Sysmon record numbers, quiet periods, sessions, health."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import lab_status  # noqa: E402


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def rec(rid, t, session="s1"):
    return {"host": "PC", "label": "host", "session": session, "source": "sysmon", "channel": "c",
            "record_id": rid, "event_id": 1, "time": iso(t), "origin": "normal", "data": {}}


def write(tmp_path, records, status_age_s=5, errors=0):
    folder = tmp_path / "host"
    folder.mkdir()
    (folder / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    state = tmp_path / ".state" / "host"
    state.mkdir(parents=True)
    updated = datetime.now(timezone.utc) - timedelta(seconds=status_age_s)
    (state / "status.json").write_text(json.dumps({"updated": iso(updated), "session": "s2", "errors": errors}),
                                       encoding="utf-8")


def pairs(*ids, t="a"):
    return [(i, f"{t}{i}") for i in ids]


def test_record_id_gaps():
    assert lab_status.record_id_gaps(pairs(1, 2, 3) + pairs(3, 4)) == ([], 1)     # re-delivery: same time
    assert lab_status.record_id_gaps(pairs(1, 2, 5, 6)) == ([(3, 4)], 1)
    # snapshot restore: numbers 3.. come back with new times -> a second run, no false gap
    assert lab_status.record_id_gaps(pairs(1, 2, 3, 4, 5) + pairs(3, 4, 5, 6, t="b")) == ([], 2)


def test_gap_after_a_restore_is_not_hidden_by_reused_numbers():
    # review M3: run 2 skips 5, which run 1 had; merging the runs would hide the gap
    missing, runs = lab_status.record_id_gaps(pairs(1, 2, 3, 4, 5, 6) + pairs(3, 4, 6, t="b"))
    assert runs == 2 and missing == [(5, 5)]


def test_vm_label_with_nothing_recent_needs_attention(tmp_path, capsys):
    t0 = datetime.now(timezone.utc) - timedelta(minutes=45)
    folder = tmp_path / "vm"
    folder.mkdir()
    (folder / "2026-10-17.jsonl").write_text(json.dumps(rec(1, t0)) + "\n", encoding="utf-8")
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 1
    assert "nothing received for 45 min" in capsys.readouterr().out


def test_quiet_periods():
    t0 = datetime(2026, 10, 17, 0, 0, tzinfo=timezone.utc)
    times = [t0, t0 + timedelta(minutes=1), t0 + timedelta(hours=7), t0 + timedelta(hours=7, minutes=1)]
    assert lab_status.quiet_periods(times, 10) == [(t0 + timedelta(minutes=1), t0 + timedelta(hours=7))]


def test_healthy_across_a_night_with_restart(tmp_path, capsys):
    t0 = datetime(2026, 10, 16, 21, 0, tzinfo=timezone.utc)
    night = [rec(i, t0 + timedelta(seconds=i)) for i in range(1, 50)]
    morning = [rec(i, t0 + timedelta(hours=8, seconds=i), session="s2") for i in range(50, 90)]
    write(tmp_path, night + morning)
    assert lab_status.main(["--recordings", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "HEALTHY" in out and "missing 0" in out and "then recording continued" in out


def test_vm_label_without_local_status_is_healthy(tmp_path, capsys):
    # the VM agent sends over HTTP; its status.json stays inside the VM
    t0 = datetime.now(timezone.utc) - timedelta(minutes=2)
    folder = tmp_path / "vm"
    folder.mkdir()
    (folder / "2026-10-17.jsonl").write_text(
        "".join(json.dumps(rec(i, t0 + timedelta(seconds=i))) + "\n" for i in range(1, 6)), encoding="utf-8")
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 0
    out = capsys.readouterr().out
    assert "status lives on the sending machine" in out and "HEALTHY" in out


def test_label_with_nothing_at_all_needs_attention(tmp_path, capsys):
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 1
    assert "never run" in capsys.readouterr().out


def test_missing_records_and_stale_agent_need_attention(tmp_path, capsys):
    t0 = datetime(2026, 10, 16, 21, 0, tzinfo=timezone.utc)
    write(tmp_path, [rec(i, t0 + timedelta(seconds=i)) for i in (1, 2, 3, 7, 8)], status_age_s=3600)
    assert lab_status.main(["--recordings", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "NEEDS ATTENTION" in out and "3 Sysmon record number(s) missing" in out and "min old" in out


def write_vm(tmp_path, records):
    folder = tmp_path / "vm"
    folder.mkdir()
    (folder / "2026-10-18.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def boot_marker(r):
    """Turn a record into Sysmon's record of a Windows boot (smss.exe started by System)."""
    r["data"] = {"Image": r"C:\Windows\System32\smss.exe", "ParentImage": "System"}
    return r


def test_vm_boots_from_different_snapshots_are_not_loss(tmp_path, capsys):
    # boot A from an older snapshot sends 10-20; boot B from a newer snapshot starts at 31:
    # numbers jump forward between boots, which is a restore, not loss (2026-10-18)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    a = [rec(i, t0 + timedelta(seconds=i), session="bootA") for i in range(10, 21)]
    b = [rec(i, t0 + timedelta(minutes=2, seconds=i), session="bootB") for i in range(31, 40)]
    boot_marker(a[0]), boot_marker(b[1])
    write_vm(tmp_path, a + b)
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 0
    out = capsys.readouterr().out
    assert "missing 0" in out and "boots 2" in out


def test_vm_gap_inside_one_boot_is_still_loss(tmp_path, capsys):
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    b = [rec(i, t0 + timedelta(seconds=i), session="bootB") for i in (31, 32, 35, 36)]
    write_vm(tmp_path, b)
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 1
    assert "2 Sysmon record number(s) missing" in capsys.readouterr().out


def test_laptop_jump_between_sessions_is_still_loss(tmp_path, capsys):
    # the laptop never restores snapshots: a new session starting past the old one's end = loss
    t0 = datetime(2026, 10, 16, 21, 0, tzinfo=timezone.utc)
    write(tmp_path, [rec(i, t0 + timedelta(seconds=i)) for i in (1, 2, 3)] +
          [rec(i, t0 + timedelta(hours=1, seconds=i), session="s2") for i in (7, 8)])
    assert lab_status.main(["--recordings", str(tmp_path)]) == 1
    assert "3 Sysmon record number(s) missing" in capsys.readouterr().out


def test_vm_agent_restart_inside_one_boot_that_skips_ahead_is_loss(tmp_path, capsys):
    # independent review 2026-10-18: a session is one agent PROCESS. The agent restarted inside the
    # same boot (no boot marker in the new session) and resumed past where the old one stopped.
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    first = [rec(i, t0 + timedelta(seconds=i), session="agent1") for i in range(10, 21)]
    boot_marker(first[0])
    again = [rec(i, t0 + timedelta(minutes=2, seconds=i), session="agent2") for i in range(25, 30)]
    write_vm(tmp_path, first + again)
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 1
    assert "4 Sysmon record number(s) missing" in capsys.readouterr().out


def test_vm_agent_restart_inside_one_boot_that_resumes_is_fine(tmp_path, capsys):
    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    first = [rec(i, t0 + timedelta(seconds=i), session="agent1") for i in range(10, 21)]
    boot_marker(first[0])
    again = [rec(i, t0 + timedelta(minutes=2, seconds=i), session="agent2") for i in range(21, 30)]
    write_vm(tmp_path, first + again)
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm"]) == 0
    assert "boots 1" in capsys.readouterr().out