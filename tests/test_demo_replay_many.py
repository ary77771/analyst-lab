"""tools/demo_replay.py with several recorded runs (night 3): each run keeps its own window, records are kept once
and in time order, one scenario is exactly the old single-run replay, the badge says the runs are separate
recordings played back to back, and the combined replay still raises the single run's alert."""

import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import demo_replay  # noqa: E402
from engine.alerts import AlertStore  # noqa: E402
from engine.replay import parse_time  # noqa: E402
from tests.test_check_graph_scenario import ev, good_run, iso  # noqa: E402

LATER = 3600            # the second run, an hour after the first


def second_run():
    return [ev(201, 1, LATER + 2, Image=r"C:\Lab\other.exe", ProcessGuid="{X}", ProcessId=20, ParentProcessGuid="{R}"),
            ev(202, 5, LATER + 9, Image=r"C:\Lab\other.exe", ProcessGuid="{X}")]


def between():
    """A record between the two runs' windows: neither run may show it."""
    return [ev(150, 1, LATER // 2, Image=r"C:\Lab\stray.exe", ProcessGuid="{S}", ProcessId=30, ParentProcessGuid="{R}")]


@pytest.fixture
def recordings(tmp_path):
    runs = [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0, "run_id": "20261017-000000-aaaa",
             "time": iso(0), "start": iso(0), "end": iso(20)},
            {"type": "SCENARIO_RUN", "scenario": "S2", "exit_code": 0, "run_id": "20261018-000000-bbbb",
             "time": iso(LATER), "start": iso(LATER), "end": iso(LATER + 20)}]
    rows = good_run() + between() + second_run()
    for label, data in (("vm", rows), ("vmruns", runs)):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    return tmp_path


def ids(records):
    return [r.get("record_id") for r in records]


def test_one_scenario_is_exactly_the_single_run_replay(recordings):
    run, records = demo_replay.prepare(str(recordings), "s1")
    runs, merged = demo_replay.prepare_many(str(recordings), ["s1"])
    assert runs == [run] and merged == records


def test_two_runs_keep_their_own_windows_in_time_order(recordings):
    runs, merged = demo_replay.prepare_many(str(recordings), ["s2", "s1"])        # listed out of order on purpose
    assert [r["scenario"] for r in runs] == ["S2", "S1"]
    assert 201 in ids(merged) and 101 in ids(merged)
    assert 150 not in ids(merged)                                                  # between the windows: not borrowed
    times = [parse_time(r["time"]) for r in merged]
    assert times == sorted(times)


def test_several_runs_hold_exactly_the_records_of_their_own_windows(recordings):
    """The one-read cut gives the same records as cutting each run on its own (prepare), joined."""
    _, merged = demo_replay.prepare_many(str(recordings), ["s1", "s2"])
    one_by_one = demo_replay.prepare(str(recordings), "s1")[1] + demo_replay.prepare(str(recordings), "s2")[1]
    key = lambda r: json.dumps(r, sort_keys=True)                                  # noqa: E731
    assert sorted(map(key, merged)) == sorted(map(key, one_by_one))


def test_a_record_two_touching_windows_hold_is_kept_once(tmp_path):
    """S2 starts 5 s after S1 ends: both windows hold the record in between; it is played once."""
    runs = [{"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0, "run_id": "r1", "time": iso(0), "start": iso(0),
             "end": iso(20)},
            {"type": "SCENARIO_RUN", "scenario": "S2", "exit_code": 0, "run_id": "r2", "time": iso(25), "start": iso(25),
             "end": iso(40)}]
    rows = good_run() + [ev(160, 1, 22, Image=r"C:\Lab\edge.exe", ProcessGuid="{E}", ProcessId=40, ParentProcessGuid="{R}")]
    for label, data in (("vm", rows), ("vmruns", runs)):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    assert 160 in ids(demo_replay.prepare(str(tmp_path), "s1")[1]) and 160 in ids(demo_replay.prepare(str(tmp_path), "s2")[1])
    _, merged = demo_replay.prepare_many(str(tmp_path), ["s1", "s2"])
    assert ids(merged).count(160) == 1


def test_all_runs_names_every_run_oldest_first(recordings):
    assert demo_replay.every_run(str(recordings), ["s2", "s1"]) == (["S1", "S2"],
                                                                     ["20261017-000000-aaaa", "20261018-000000-bbbb"])
    with pytest.raises(SystemExit, match="No recorded run of S7"):
        demo_replay.every_run(str(recordings), ["s1", "s7"])
    with pytest.raises(SystemExit, match="leave out --run-id"):
        demo_replay.main(["s1", "--all-runs", "--run-id", "x", "--recordings", str(recordings), "--no-serve"])


def test_many_runs_are_counted_not_listed():
    runs = [{"scenario": "S1", "run_id": f"202610{d:02d}-000000-x", "start": f"2026-10-{d:02d}"} for d in range(10, 20)]
    runs.append({"scenario": "S4", "run_id": "20261120-000000-y", "start": "2026-11-20"})
    text = demo_replay.describe(runs)
    assert text == "S1 x10, S4: 11 recorded runs played back to back, recorded between 2026-10-10 and 2026-11-20"


def test_plain_messages_for_wrong_lists(recordings):
    with pytest.raises(SystemExit, match="one --run-id per scenario"):
        demo_replay.prepare_many(str(recordings), ["s1", "s2"], ["20261017-000000-aaaa"])
    with pytest.raises(SystemExit, match="listed twice"):
        demo_replay.prepare_many(str(recordings), ["s1", "s1"])
    with pytest.raises(SystemExit, match="No recorded run of S7"):
        demo_replay.prepare_many(str(recordings), ["s1", "s7"])


def test_the_badge_says_what_is_played(recordings):
    runs, _ = demo_replay.prepare_many(str(recordings), ["s1", "s2"])
    assert demo_replay.describe(runs[:1]) == "S1, recorded 2026-10-17 (run 20261017-000000-aaaa)"   # unchanged wording
    both = demo_replay.describe(runs)
    assert both.startswith("S1+S2: 2 recorded runs played back to back")
    assert demo_replay.describe(runs[::-1]).startswith("S1+S2:")                  # in the order they play, as typed or not
    assert "2026-10-17" in both and "2026-10-18" in both


def test_the_combined_replay_still_raises_the_single_runs_alert(recordings, capsys):
    assert demo_replay.main(["s1", "--recordings", str(recordings), "--speed", "0", "--every", "0.2", "--no-serve"]) == 0
    assert demo_replay.main(["s1", "s2", "--recordings", str(recordings), "--speed", "0", "--every", "0.2",
                             "--no-serve"]) == 0
    single, combined = sorted((recordings / "demo").iterdir(), key=lambda p: p.stat().st_mtime)
    got = {}
    for name, folder in (("single", single), ("combined", combined)):
        s = AlertStore(str(folder / "alerts.db"))
        got[name] = {a.alert_id for a in s.read()}
        s.close()
    assert got["single"] and got["single"] <= got["combined"]
    with open(combined / demo_replay.FEED / "replay.jsonl", encoding="utf-8") as f:
        assert sum(1 for _ in f) == len(demo_replay.prepare_many(str(recordings), ["s1", "s2"])[1])
