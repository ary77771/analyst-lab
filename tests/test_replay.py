"""Stage 7: replay gives back exactly what was recorded, in order, at the requested speed."""

import hashlib
import json
import time

from engine.replay import parse_time, read_recordings, replay
from engine.store import EventStore


def make_records(n=20, step_ms=50):
    out = []
    for i in range(n):
        ms = i * step_ms
        out.append({"host": "PC", "source": "sysmon", "channel": "c", "record_id": i + 1, "event_id": 1,
                    "time": f"2026-10-16T14:00:{ms // 1000:02d}.{ms % 1000:03d}0000Z", "origin": "normal",
                    "data": {"Image": f"p{i}.exe"}})
    return out


def write_jsonl(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def content_hash(records):
    lines = sorted(json.dumps(r, sort_keys=True) for r in records)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def test_parse_time_handles_windows_precision():
    t = parse_time("2026-10-16T14:26:24.6357992Z")
    assert (t.second, t.microsecond, t.tzinfo is not None) == (24, 635799, True)
    assert parse_time("2026-10-16T14:00:00Z").microsecond == 0


def test_record_replay_rerecord_is_identical(tmp_path):
    records = make_records()
    shuffled = records[::-1]                         # file order differs from time order
    write_jsonl(tmp_path / "rec.jsonl", shuffled)

    replayed = []
    replay(read_recordings([str(tmp_path / "rec.jsonl")]), replayed.append, speed=0)
    assert content_hash(replayed) == content_hash(records)
    assert [r["record_id"] for r in replayed] == list(range(1, 21))     # time order restored


def test_speeds_give_identical_results(tmp_path):
    write_jsonl(tmp_path / "rec.jsonl", make_records())
    recs = read_recordings([str(tmp_path / "rec.jsonl")])
    outs = {}
    for speed in (0, 10, 100):
        got = []
        replay(recs, got.append, speed=speed, sleep=lambda s: None)
        outs[speed] = content_hash(got)
    assert len(set(outs.values())) == 1


def test_real_speed_timing_is_respected():
    recs = make_records(n=11, step_ms=100)          # 1.0 s of recorded time
    start = time.monotonic()
    replay(recs, lambda r: None, speed=2)            # should take about 0.5 s
    elapsed = time.monotonic() - start
    assert 0.4 < elapsed < 0.9


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.slept.append(round(s, 6))
        self.now += s


def test_max_gap_compresses_idle_time():
    recs = make_records(n=2)
    recs[1]["time"] = "2026-10-16T15:00:00.0000000Z"   # one hour later
    fc = FakeClock()
    replay(recs, lambda r: None, speed=1, max_gap=5, sleep=fc.sleep, clock=fc.clock)
    assert fc.slept == [5]


def test_timing_does_not_drift_with_slow_processing():
    recs = make_records(n=11, step_ms=100)            # 1.0 s of recorded time, 10 gaps of 0.1 s
    fc = FakeClock()

    def slow_consume(r):
        fc.now += 0.03                                 # each event takes 30 ms to process
    replay(recs, slow_consume, speed=1, sleep=fc.sleep, clock=fc.clock)
    # wall-clock scheduling: total ends at ~1.0 s (+ last processing), not 1.0 + 11 * 0.03
    assert abs(fc.now - 1.03) < 1e-6


def test_parse_time_offsets_and_precision():
    assert parse_time("2026-10-16T17:00:00.123+03:00") == parse_time("2026-10-16T14:00:00.123Z")
    assert parse_time("2026-10-16T17:00:00+03:00") == parse_time("2026-10-16T14:00:00Z")
    assert parse_time("2026-10-16T14:00:00.1234567Z").microsecond == 123456


def test_timeless_records_are_kept_in_place(tmp_path):
    records = make_records(3)
    bad = {"host": "PC", "source": "sysmon", "record_id": None, "time": None, "parse_error": "x", "data": {}}
    write_jsonl(tmp_path / "rec.jsonl", [records[0], records[1], bad, records[2]])
    out = read_recordings([str(tmp_path / "rec.jsonl")])
    assert len(out) == 4
    assert out[2].get("parse_error") == "x"


def test_replay_into_store_matches_direct_load(tmp_path):
    from engine.load import load_files
    records = make_records()
    records.append(dict(records[3]))                 # a re-delivered duplicate
    write_jsonl(tmp_path / "rec.jsonl", records)
    replayed = EventStore(str(tmp_path / "r.db"))
    replay(read_recordings([str(tmp_path / "rec.jsonl")]), lambda r: replayed.insert([r]), speed=0)
    direct = EventStore(str(tmp_path / "d.db"))
    load_files(direct, [str(tmp_path / "rec.jsonl")])
    rows = lambda s: sorted(s.db.execute("SELECT dedup_key, Image, event_id FROM events").fetchall())
    assert replayed.count() == 20
    assert rows(replayed) == rows(direct)


def test_partial_line_is_skipped(tmp_path):
    path = tmp_path / "rec.jsonl"
    write_jsonl(path, make_records(3))
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"half": ')
    assert len(read_recordings([str(path)])) == 3
