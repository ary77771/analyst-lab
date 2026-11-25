"""tools/run_series.py with a fake single-run command (no VM)."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import run_series as rs  # noqa: E402

FAKE = """
import json, os, sys, uuid
scenario, rec, codes = sys.argv[-1], sys.argv[1], json.loads(sys.argv[2])
state = os.path.join(rec, "fake_state.json")
n = json.load(open(state)) if os.path.exists(state) else 0
json.dump(n + 1, open(state, "w"))
code = codes[n] if n < len(codes) else 0
if code not in (2, 9):              # a run that started writes its summary (9 = crash before it: exit 1, none)
    rid = f"run{n:02d}-{scenario}"
    json.dump({"scenario": scenario}, open(os.path.join(rec, "scenario_runs", rid + ".json"), "w"))
sys.exit(1 if code == 9 else code)
"""


def fake_cmd(tmp_path, codes):
    script = tmp_path / "fake_run.py"
    script.write_text(FAKE, encoding="utf-8")
    rec = tmp_path / "rec"
    (rec / "scenario_runs").mkdir(parents=True, exist_ok=True)
    return [sys.executable, str(script), str(rec), json.dumps(codes)], str(rec)


def quiet(*a, **k):
    pass


def test_plan_is_shuffled_reproducibly_and_complete():
    a = rs.plan(["s1", "S2", "s3"], 5, seed=7)
    assert sorted(a) == sorted(["s1", "s2", "s3"] * 5)
    assert a == rs.plan(["s1", "s2", "s3"], 5, seed=7) and a != rs.plan(["s1", "s2", "s3"], 5, seed=8)


def test_failures_are_recorded_and_the_series_goes_on(tmp_path):
    cmd, rec = fake_cmd(tmp_path, [0, 1, 3, 0])
    s = rs.run_series(["s1", "s2", "s3", "s4"], "practice", 1, cmd, rec, stop_after=2, pause=0, say=quiet)
    assert [r["result"] for r in s["runs"]] == ["PASS", "FAIL", "VM STEP FAILED", "PASS"]
    assert [r["run_id"] for r in s["runs"]] == ["run00-s1", "run01-s2", "run02-s3", "run03-s4"]
    assert "stopped" not in s
    saved = json.load(open(os.path.join(rec, "series", f"{s['series']}.json")))
    assert saved["seed"] == 1 and len(saved["runs"]) == 4 and saved["finished"]


def test_stops_when_the_vm_is_broken(tmp_path):
    cmd, rec = fake_cmd(tmp_path, [0, 2, 3, 0, 0])
    s = rs.run_series(["s1"] * 5, "practice", 1, cmd, rec, stop_after=2, pause=0, say=quiet)
    assert len(s["runs"]) == 3 and "stopped" in s
    assert s["runs"][1]["run_id"] is None                       # not started: no summary


def test_a_crash_before_any_run_summary_counts_as_could_not_run(tmp_path):
    """v3: exit 1 WITHOUT a run summary (a crash before the VM step) is broken, not a scenario FAIL."""
    cmd, rec = fake_cmd(tmp_path, [9, 9, 0, 0])
    s = rs.run_series(["s1"] * 4, "practice", 1, cmd, rec, stop_after=2, pause=0, say=quiet)
    assert len(s["runs"]) == 2 and "stopped" in s and [r["run_id"] for r in s["runs"]] == [None, None]


def test_official_needs_the_freeze_tag(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rs, "has_freeze_tag", lambda root=None: False)
    assert rs.main(["s1", "--label", "official", "--recordings", str(tmp_path)]) == 2
    assert not (tmp_path / "series").exists()
    assert rs.evaluation.FREEZE_TAG in capsys.readouterr().out


def test_the_freeze_tag_checked_is_the_current_one(monkeypatch):
    """freeze-v1 exists in this repository: it must NOT open v2's official runs."""
    from tests.conftest import REAL_CODE_PROBLEMS
    monkeypatch.setattr(rs.evaluation, "code_problems", REAL_CODE_PROBLEMS)
    asked = []
    monkeypatch.setattr(rs.evaluation, "has_tag", lambda tag, root=None: asked.append(tag) or tag == "freeze-v1")
    assert rs.has_freeze_tag() is False and asked == [rs.evaluation.FREEZE_TAG]


def test_official_series_records_its_freeze_and_code(tmp_path):
    cmd, rec = fake_cmd(tmp_path, [0])
    s = rs.run_series(["s1"], "official", 1, cmd, rec, pause=0, say=quiet)
    assert s["freeze"] == rs.evaluation.FREEZE_TAG and s["code"]["frozen"] is True
    cmd, rec = fake_cmd(tmp_path, [0])
    assert "freeze" not in rs.run_series(["s1"], "practice", 1, cmd, rec, pause=0, say=quiet)


def test_dry_run_runs_nothing(tmp_path):
    assert rs.main(["s1", "s5", "--repeats", "2", "--label", "practice", "--dry-run", "--recordings", str(tmp_path)]) == 0
    assert not (tmp_path / "series").exists()


def test_headless_reaches_the_runner(tmp_path, monkeypatch):
    seen = {}
    def fake(order, label, seed, cmd, rec, stop_after, pause, env=None):
        seen["cmd"] = cmd
        return {"runs": [{"exit_code": 0}] * len(order)}
    monkeypatch.setattr(rs, "run_series", fake)
    assert rs.main(["s1", "--label", "practice", "--headless", "--recordings", str(tmp_path)]) == 0
    assert seen["cmd"][-1] == "--headless" and "-u" in seen["cmd"]
    rs.main(["s1", "--label", "practice", "--recordings", str(tmp_path)])
    assert "--headless" not in seen["cmd"]

def test_recordings_and_official_mode_reach_the_runner(tmp_path, monkeypatch):
    seen = {}
    def fake(order, label, seed, cmd, rec, stop_after, pause, env=None):
        seen["cmd"], seen["env"] = cmd, env
        return {"runs": [{"exit_code": 0}] * len(order)}
    monkeypatch.setattr(rs, "run_series", fake)
    rs.main(["s1", "--label", "practice", "--recordings", str(tmp_path)])
    i = seen["cmd"].index("--recordings")
    assert seen["cmd"][i + 1] == str(tmp_path) and "ANALYSTLAB_OFFICIAL" not in seen["env"]   # practice
    assert seen["env"]["PYTHONIOENCODING"] == "utf-8"                         # v3: children always write UTF-8
    monkeypatch.setattr(rs, "has_freeze_tag", lambda root=None: True)
    rs.main(["s1", "--label", "official", "--recordings", str(tmp_path)])
    assert seen["env"]["ANALYSTLAB_OFFICIAL"] == "1"                          # official: every checker verifies


def test_detection_outcome_is_recorded_per_run(tmp_path):
    import json, sys
    runs = tmp_path / "scenario_runs"
    runs.mkdir()
    script = tmp_path / "fake_runner.py"
    script.write_text("import json, sys, os\n"
                      "json.dump({'detection': 'MISSED'}, open(os.path.join(sys.argv[1], 'r1.json'), 'w'))\n",
                      encoding="utf-8")
    s = rs.run_series(["s1"], "practice", 1, [sys.executable, str(script), str(runs)], str(tmp_path),
                      pause=0, say=lambda m: None)
    assert s["runs"][0]["detection"] == "MISSED" and s["runs"][0]["result"] == "PASS"   # a miss is not a failed run


def test_the_series_file_exists_before_the_first_run(tmp_path, monkeypatch):
    """A crash during run 1 must still leave the series (review 2026-11-13): its start puts the run
    inside an official period, so it can never become practice data."""
    rec = tmp_path / "rec"
    seen = []

    class Done:
        returncode = 0

    def fake_run(cmd, env=None):
        seen.append(sorted(os.listdir(rec / "series")))
        raise KeyboardInterrupt
    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    try:
        rs.run_series(["s1"], "official", 1, ["x"], str(rec), pause=0, say=quiet)
    except KeyboardInterrupt:
        pass
    assert len(seen) == 1 and len(seen[0]) == 1
    saved = json.load(open(rec / "series" / seen[0][0]))
    assert saved["freeze"] == rs.evaluation.FREEZE_TAG and saved["started"] and saved["runs"] == []