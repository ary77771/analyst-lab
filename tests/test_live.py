"""Package L: the live loop (engine/live.py) on a folder that grows while we watch."""

import gzip
import json
import os
from datetime import datetime, timezone

from engine import detect, live
from tests.test_detect import EVIL, ev, rules_from
from tests.test_own_rules import chain


def append(path, records, partial=b""):
    with open(path, "ab") as f:
        for r in records:
            f.write((json.dumps(r) + "\n").encode())
        f.write(partial)


def test_follows_complete_lines_and_scores_new_events_once(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    rules = rules_from(tmp_path, EVIL)
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules)

    first = ev(1, 0, Image=r"C:\x\evil.exe")
    half = json.dumps(ev(1, 1, Image=r"C:\y\evil.exe")).encode()
    append(day, [first], partial=half[:20])                    # second line still being written
    n, fresh = loop.tick(now=datetime(2026, 10, 22, 10, 0, 5, tzinfo=timezone.utc))
    assert n == 1 and len(fresh) == 1 and fresh[0].details["seen_utc"] == "2026-10-22T10:00:05Z"

    append(day, [], partial=half[20:] + b"\n")                 # the line completes
    n, fresh = loop.tick()
    assert n == 1 and len(fresh) == 1 and fresh[0].time.startswith("2026-10-22T10:00:01")
    assert loop.tick() == (0, [])                              # nothing new: nothing again
    assert loop.follower.bad_lines == 0


def test_own_rules_and_correlations_see_history(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), [])
    recs = chain()
    append(day, recs[:2])                                      # connect + write arrive first
    assert loop.tick()[1] == []
    append(day, recs[2:])                                      # the start arrives later
    n, fresh = loop.tick()
    assert [a.rule_id for a in fresh] == ["analystlab.fetch_write_run"]
    assert loop.tick() == (0, [])


def test_finished_compressed_days_are_read_once(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    with gzip.open(folder / "2026-10-21.jsonl.gz", "wb") as f:
        f.write((json.dumps(ev(1, 0, Image=r"C:\x\evil.exe")) + "\n").encode())
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules_from(tmp_path, EVIL))
    assert loop.tick()[0] == 1 and loop.tick()[0] == 0


def test_refuses_a_dev_snapshot_as_live_store(tmp_path):
    bad = os.path.join(str(tmp_path), "scratch", "dev", "dev-vm.db")
    try:
        live.main(["--store", bad, "--alerts", str(tmp_path / "a.db"), "--once", "--recordings", str(tmp_path)])
    except SystemExit as e:
        assert "dev snapshot" in str(e)
    else:
        raise AssertionError("must refuse")


def test_live_burst_is_one_alert_that_grows(tmp_path):
    from tests.test_own_rules import churn
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), [])
    recs = churn(60, 60, spread=55.0)
    for i in range(0, 120, 20):                                  # the burst arrives in six passes
        append(day, recs[i:i + 20])
        loop.tick()
    from engine.alerts import AlertStore
    got = AlertStore(str(tmp_path / "alerts.db")).read()
    assert len(got) == 1 and len(got[0].evidence) == 120 and "seen_utc" in got[0].details


def test_known_alerts_are_not_returned_again(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules_from(tmp_path, EVIL))
    append(day, [ev(1, 0, Image=r"C:\x\evil.exe")])
    assert len(loop.tick()[1]) == 1
    loop.last_id = 0                                             # force a full rescan of the same events
    append(day, [ev(1, 5, Image=r"C:\x\harmless.exe")])
    assert loop.tick()[1] == []


def test_truncated_file_is_read_again(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    day = folder / "2026-10-22.jsonl"
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules_from(tmp_path, EVIL))
    append(str(day), [ev(1, i, Image=r"C:\x\a.exe") for i in range(5)])
    assert loop.tick()[0] == 5
    day.write_bytes(b"")
    append(str(day), [ev(1, 9, Image=r"C:\x\evil.exe")])
    n, fresh = loop.tick()
    assert n == 1 and len(fresh) == 1


def test_a_malformed_record_is_quarantined_not_fatal(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules_from(tmp_path, EVIL))
    good = ev(1, 0, Image=r"C:\x\evil.exe")
    bad = [dict(ev(1, 1), record_id=10 ** 20), {k: v for k, v in ev(1, 2).items() if k != "host"},
           dict(ev(1, 3), data=[1]), dict(ev(1, 4), data={"a\u0000b": "x"})]
    append(day, [good] + bad)
    n, fresh = loop.tick()
    assert len(fresh) == 1 and loop.rejected == 4
    assert len((tmp_path / "rejected.jsonl").read_text(encoding="utf-8").splitlines()) == 4
    append(day, [ev(1, 9, Image=r"C:\y\evil.exe")])
    assert len(loop.tick()[1]) == 1                              # still running afterwards


def test_rule_errors_are_visible(tmp_path):
    folder = tmp_path / "vm"
    folder.mkdir()
    bad = detect.Rule("broken", "broken", "high", "sigma", "x.yml", ["SELECT nope FROM logs"])
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), [bad])
    append(str(folder / "2026-10-22.jsonl"), [ev(1, 0, Image="x")])
    loop.tick()
    assert loop.rule_errors and loop.rule_errors[0][0] == "broken"


def test_refusal_ignores_case(tmp_path):
    bad = os.path.join(str(tmp_path), "Scratch", "DEV", "dev-vm.db")
    try:
        live.main(["--store", bad, "--alerts", str(tmp_path / "a.db"), "--once", "--recordings", str(tmp_path)])
    except SystemExit as e:
        assert "dev snapshot" in str(e)
    else:
        raise AssertionError("must refuse")

def test_live_raises_the_rhythm_alert_once_and_equals_batch_scoring(tmp_path):
    # integration review 2026-10-24: the check-in rhythm rule ran neither live nor in batch
    from engine import score
    from engine.beacon import BeaconConfig
    from engine.store import EventStore
    from tests.test_beacon import iso, net, rhythm
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8, level="medium")
    recs = [net("h", i + 1, iso(t), r"C:\x\checkin.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30))]
    folder = tmp_path / "vm"
    folder.mkdir()
    day = str(folder / "2026-10-22.jsonl")
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), [], beacon_cfg=cfg)
    append(day, recs[:4])
    assert loop.tick()[1] == []                                # 4 check-ins: not judged yet
    append(day, recs[4:])
    fresh = loop.tick()[1]
    assert [a.rule_id for a in fresh] == ["beacon"] and fresh[0].level == "medium"
    append(day, [net("h", 99, iso(300.0), r"C:\x\checkin.exe", "10.0.0.9")])
    assert loop.tick()[1] == []                                # the series grows: the same alert, not a new one
    # batch scoring of the same records gives the same alerts (one function for both)
    st = EventStore(str(tmp_path / "batch.db"))
    st.insert(recs + [net("h", 99, iso(300.0), r"C:\x\checkin.exe", "10.0.0.9")])
    st.close()
    con = detect.open_store(str(tmp_path / "batch.db"))
    batch = {a.alert_id for a in score.score(con, [], None, cfg)}
    con.close()
    from engine.alerts import AlertStore
    s = AlertStore(str(tmp_path / "alerts.db"))
    assert {a.alert_id for a in s.read()} == batch
    s.close()


def test_frozen_baselines_must_exist(tmp_path):
    import pytest
    from engine import score
    (tmp_path / "config").mkdir()
    f = tmp_path / "config" / "frozen.yaml"
    f.write_text("baselines:\n  - {file: recordings/baselines/missing.json, sha256: x}\n", encoding="utf-8")
    files = score.baseline_files(str(f))
    assert files == [str(tmp_path / "recordings" / "baselines" / "missing.json")]
    with pytest.raises(FileNotFoundError, match="learned-normal baseline"):
        score.load_baseline(files)
    assert score.load_baseline([]) is None


def test_since_skips_what_was_recorded_before_the_start(tmp_path):
    """--since-now (the demo): records before the start are not loaded, so no old alert shows."""
    folder = tmp_path / "vm"
    folder.mkdir()
    rules = rules_from(tmp_path, EVIL)
    since = datetime(2026, 10, 22, 10, 0, 1, tzinfo=timezone.utc)
    loop = live.LiveLoop(str(folder), str(tmp_path / "live.db"), str(tmp_path / "alerts.db"), rules, since=since)
    append(str(folder / "2026-10-22.jsonl"), [ev(1, 0, Image=r"C:\x\evil.exe"), ev(1, 2, Image=r"C:\y\evil.exe")])
    n, fresh = loop.tick()
    assert n == 1 and len(fresh) == 1 and fresh[0].time.startswith("2026-10-22T10:00:02")
