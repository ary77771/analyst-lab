"""tools/compress_recordings.py and the readers' handling of compressed days (engine/jsonl.py)."""

import gzip
import json
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import compress_recordings  # noqa: E402
from engine.jsonl import expand_patterns, iter_jsonl, recording_files  # noqa: E402

DAY = 24 * 3600


def day_file(folder, day, rows, age_hours=48, raw_tail=b""):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / f"{day}.jsonl"
    p.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode() + raw_tail)
    old = time.time() - age_hours * 3600
    os.utime(p, (old, old))
    return p


def test_compressed_day_reads_back_identically_and_original_is_gone(tmp_path):
    rows = [{"n": i, "name": "مرحبا"} for i in range(1000)]
    p = day_file(tmp_path / "host", "2026-10-16", rows, raw_tail=b'{"cut')     # a damaged last line
    original = p.read_bytes()
    assert compress_recordings.main(["--recordings", str(tmp_path), "--go"]) == 0
    assert not p.exists()
    gz = tmp_path / "host" / "2026-10-16.jsonl.gz"
    assert gzip.decompress(gz.read_bytes()) == original                        # byte-identical
    bad = {}
    assert list(iter_jsonl(str(gz), bad)) == rows and bad == {"bad_lines": 1}  # same as before


def test_today_and_recently_written_files_are_left_alone(tmp_path):
    today = time.strftime("%Y-%m-%d", time.gmtime())
    day_file(tmp_path / "host", today, [{"n": 1}], age_hours=48)               # today's name
    day_file(tmp_path / "vm", "2026-10-16", [{"n": 1}], age_hours=0.5)         # written 30 min ago
    assert compress_recordings.finished_days(str(tmp_path), idle_hours=2) == []
    assert compress_recordings.main(["--recordings", str(tmp_path), "--go"]) == 0
    assert sorted(os.listdir(tmp_path / "host")) == [f"{today}.jsonl"]


def test_plan_only_changes_nothing(tmp_path):
    p = day_file(tmp_path / "host", "2026-10-16", [{"n": 1}])
    compress_recordings.main(["--recordings", str(tmp_path)])
    assert p.exists() and not (tmp_path / "host" / "2026-10-16.jsonl.gz").exists()


def test_failed_verification_keeps_the_original(tmp_path, monkeypatch):
    p = day_file(tmp_path / "host", "2026-10-16", [{"n": 1}])
    real = compress_recordings.sha256_of
    calls = iter(range(10))
    monkeypatch.setattr(compress_recordings, "sha256_of", lambda s: real(s) + ("x" if next(calls) == 1 else ""))
    assert compress_recordings.main(["--recordings", str(tmp_path), "--go"]) == 1
    assert p.exists() and not (tmp_path / "host" / "2026-10-16.jsonl.gz").exists()
    assert not (tmp_path / "host" / "2026-10-16.jsonl.gz.tmp").exists()


def test_a_day_in_both_forms_is_read_once(tmp_path):
    # a compression interrupted after the rename, before deleting the original
    folder = tmp_path / "host"
    p = day_file(folder, "2026-10-16", [{"n": 1}])
    (folder / "2026-10-16.jsonl.gz").write_bytes(gzip.compress(p.read_bytes()))
    day_file(folder, "2026-10-15", [{"n": 0}])
    (folder / "2026-10-15.jsonl.gz").write_bytes(gzip.compress(b'{"n": 0}\n'))
    os.remove(folder / "2026-10-15.jsonl")                                     # a normal compressed day
    files = [os.path.basename(f) for f in recording_files(str(folder))]
    assert files == ["2026-10-15.jsonl.gz", "2026-10-16.jsonl"]
    assert [os.path.basename(f) for f in expand_patterns([str(folder / "*.jsonl")])] == files


def test_lab_status_counts_compressed_days(tmp_path, capsys):
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
    import lab_status
    rows = [{"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": "c", "record_id": i,
             "event_id": 1, "time": f"2026-10-16T10:00:{i:02d}.0000000Z", "data": {}} for i in range(1, 11)]
    day_file(tmp_path / "vm", "2026-10-16", rows[:5])
    compress_recordings.main(["--recordings", str(tmp_path), "--go"])
    day_file(tmp_path / "vm", "2026-10-17", rows[5:], age_hours=0)
    lab_status.main(["--recordings", str(tmp_path), "--label", "vm", "--stale-minutes", "100000000"])
    out = capsys.readouterr().out
    assert "10 distinct Sysmon records" in out and "missing 0" in out


def test_original_still_open_is_reported_not_failed(tmp_path, monkeypatch, capsys):
    p = day_file(tmp_path / "vm", "2026-10-16", [{"n": 1}])
    real = os.remove

    def locked(path):
        if str(path) == str(p):
            raise PermissionError(32, "being used by another process")
        return real(path)
    monkeypatch.setattr(compress_recordings.os, "remove", locked)
    assert compress_recordings.main(["--recordings", str(tmp_path), "--go"]) == 0
    out = capsys.readouterr().out
    assert "OPEN  vm/2026-10-16.jsonl" in out and p.exists() and p.with_suffix(".jsonl.gz").exists()
    assert recording_files(str(tmp_path / "vm")) == [str(p)]                  # read once, the original


def test_damaged_compressed_file_is_counted_not_fatal(tmp_path, capsys):
    import lab_status
    rows = [{"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": "c", "record_id": i,
             "event_id": 1, "time": f"2026-10-16T10:{i // 60:02d}:{i % 60:02d}.0000000Z", "data": {}} for i in range(1, 400)]
    folder = tmp_path / "vm"
    folder.mkdir()
    full = gzip.compress("".join(json.dumps(r) + "\n" for r in rows).encode())
    (folder / "2026-10-16.jsonl.gz").write_bytes(full[: len(full) // 2])           # cut short
    bad = {}
    got = list(iter_jsonl(str(folder / "2026-10-16.jsonl.gz"), bad))
    assert bad.get("bad_files") == 1 and 0 < len(got) < len(rows)
    assert lab_status.main(["--recordings", str(tmp_path), "--label", "vm", "--stale-minutes", "100000000"]) == 1
    assert "DAMAGED COMPRESSED FILES 1" in capsys.readouterr().out


def test_leftover_tmp_file_is_never_read(tmp_path):
    folder = tmp_path / "host"
    day_file(folder, "2026-10-16", [{"n": 1}])
    (folder / "2026-10-16.jsonl.gz.tmp").write_bytes(b"half-written")
    assert [os.path.basename(f) for f in recording_files(str(folder))] == ["2026-10-16.jsonl"]
    assert [os.path.basename(f) for f in expand_patterns([str(folder / "*")])] == ["2026-10-16.jsonl"]


def test_scenario_checkers_read_a_compressed_day(tmp_path, capsys):
    import check_graph_scenario
    import check_scenario
    from tests.test_check_graph_scenario import good_run, iso, pool_file
    vm, runs = tmp_path / "vm", tmp_path / "vmruns"
    day_file(vm, "2026-10-17", good_run())
    day_file(runs, "2026-10-17", [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0,
                                   "time": iso(0), "start": iso(0), "end": iso(20)}])
    pool_file(tmp_path)                              # layer 2 needs a pool of normal rates
    assert compress_recordings.main(["--recordings", str(tmp_path), "--go"]) == 0
    assert not list(vm.glob("*.jsonl")) and list(vm.glob("*.jsonl.gz"))
    assert check_scenario.main(["s1", "--recordings", str(tmp_path)]) == 0
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path)]) == 0
