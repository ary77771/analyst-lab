"""Scenario S5 (file churn: 40 dummy files created, 40 copies written, 40 originals deleted)
against both checkers: the true story, and broken variants that must FAIL (a missing deletion,
a "burst" that isn't one, an extra file in the folder, deletions by another program)."""

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
from test_check_graph_scenario import pool_file  # noqa: E402  (layer 2 needs a pool of normal rates)

CHURN = r"D:\s5\s5_churn.exe"
WORK = r"C:\AnalystLab\scenarios\s5\work"
BASE = datetime(2026, 10, 20, 14, 0, 0)
CH = "Microsoft-Windows-Sysmon/Operational"
N = 40


def iso(sec):
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def ev(rid, eid, sec, **data):
    t = (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {"host": "VM", "label": "vm", "session": "s", "source": "sysmon", "channel": CH, "record_id": rid,
            "event_id": eid, "time": iso(sec), "origin": "normal", "data": {"UtcTime": t, **data}}


def sha(i):
    return hashlib.sha256(f"dummy {i}".encode()).hexdigest().upper()


def made(rid, seq, sec, path, i, guid="{W}"):
    """Event 11 + the agent's fingerprint of it a moment later."""
    e = ev(rid, 11, sec, Image=CHURN, ProcessGuid=guid, TargetFilename=path)
    h = {"host": "VM", "label": "vm", "session": "s", "source": "agent", "seq": seq, "type": "FILE_HASH",
         "time": iso(sec + 1), "origin": "normal",
         "data": {"TargetFilename": path, "ProcessGuid": guid, "hash_status": "ok", "sha256": sha(i), "size": 60,
                  "final_path": path, "ref_record_id": rid, "ref_time": e["time"]}}
    return [e, h]


def story(n_deleted=N, copy_step=0.01, deleter=("{W}", CHURN)):
    rows = [ev(100, 1, 0.5, Image=CHURN, ProcessGuid="{W}", ProcessId=7, ParentProcessGuid="{R}"),
            ev(101, 11, 0.8, Image=CHURN, ProcessGuid="{W}", TargetFilename=r"C:\AnalystLab\scenarios\s5"),   # its folders
            ev(102, 11, 0.81, Image=CHURN, ProcessGuid="{W}", TargetFilename=WORK)]
    rid, seq = 1000, 1
    for i in range(1, N + 1):
        rows += made(rid, seq, 1 + i * 0.01, rf"{WORK}\note_{i:02d}.txt", i)
        rid, seq = rid + 1, seq + 1
    for i in range(1, N + 1):
        rows += made(rid, seq, 12 + i * copy_step, rf"{WORK}\note_{i:02d}.txt.s5copy", i)
        rid, seq = rid + 1, seq + 1
    last = 12 + N * copy_step
    for i in range(1, n_deleted + 1):
        rows.append(ev(rid, 26, last + 1 + i * 0.01, Image=deleter[1], ProcessGuid=deleter[0],
                       TargetFilename=rf"{WORK}\note_{i:02d}.txt", Hashes=f"SHA256={sha(i)}"))
        rid += 1
    rows.append(ev(rid, 5, last + 4, Image=CHURN, ProcessGuid="{W}", ProcessId=7))
    return sorted(rows, key=lambda r: r["time"]), last + 5


def both(tmp_path, capsys, rows, end):
    for label, data in (("vm", rows), ("vmruns", [{"type": "SCENARIO_RUN", "scenario": "S5", "exit_code": 0,
                                                    "time": iso(0), "start": iso(0), "end": iso(end),
                                                    "server": "http://10.0.2.2:18765"}])):
        (tmp_path / label).mkdir()
        (tmp_path / label / "2026-10-20.jsonl").write_text("".join(json.dumps(r) + "\n" for r in data), encoding="utf-8")
    a = check_scenario.main(["s5", "--recordings", str(tmp_path)])
    pool_file(tmp_path)
    b = check_graph_scenario.main(["s5", "--recordings", str(tmp_path)])
    return a, b, capsys.readouterr().out


def test_true_s5_story_passes_both_checks(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, *story())
    assert (a, b) == (0, 0), out
    assert "(40 matching, exactly 40 expected; all within 0.4 s, at most 15 s allowed)" in out
    for says in ("churn created the 40 originals", "churn created the 40 copies", "churn deleted the 40 originals"):
        assert f"fact  PASS  {says}  (40 edge(s)" in out
    assert "trace  PASS" in out and "gaps  PASS  0" in out


def test_one_deletion_missing_fails(tmp_path, capsys):
    a, b, out = both(tmp_path, capsys, *story(n_deleted=N - 1))
    assert a == 1 and b == 1 and "(39 matching, exactly 40 expected" in out


def test_a_slow_trickle_is_not_a_burst(tmp_path, capsys):
    a, _, out = both(tmp_path, capsys, *story(copy_step=1.0))          # 40 copies over 39 s
    assert a == 1 and "all within 39.0 s, at most 15 s allowed" in out


def test_deletions_by_another_program_fail(tmp_path, capsys):
    a, b, _ = both(tmp_path, capsys, *story(deleter=("{X}", r"C:\Windows\explorer.exe")))
    assert a == 1 and b == 1


def test_an_extra_file_in_the_work_folder_fails_the_graph_check(tmp_path, capsys):
    rows, end = story()
    rows += made(5000, 900, 14, rf"{WORK}\unexpected.dat", 99)
    a, b, out = both(tmp_path, capsys, sorted(rows, key=lambda r: r["time"]), end)
    assert a == 1 and b == 1 and "1 other file node(s) in the scenario's folder" in out
    assert "absent  FAIL  event 11 for the scenario's programs/files: 1" in out


def test_trace_catches_a_deletion_whose_raw_event_names_another_file(tmp_path):
    import tempfile
    import yaml
    from check_scenario import run_server
    from engine.graph import build_graph
    from engine.replay import parse_time
    from engine.store import EventStore
    rows, end = story()
    with tempfile.TemporaryDirectory() as tmp:
        st = EventStore(os.path.join(tmp, "g.db"))
        st.insert(rows)
        st.close()
        G = build_graph(os.path.join(tmp, "g.db"))
    truth = yaml.safe_load(open(os.path.join(PROJECT_ROOT, "scenarios", "s5", "ground_truth.yaml"), encoding="utf-8"))
    c = check_graph_scenario.GraphCheck(truth, G, parse_time(iso(-5)), parse_time(iso(end + 100)),
                                        run_server({"server": "http://10.0.2.2:18765"}), say=lambda m: None)
    assert c.resolve()
    c.check_facts()
    assert c.ok
    raw = {EventStore.dedup_key(r): json.loads(json.dumps(r)) for r in rows}
    for r in raw.values():
        if r.get("event_id") == 26:
            r["data"]["TargetFilename"] = r"C:\Users\Someone\Documents\report.docx"
    c.trace(raw)
    assert not c.ok

# -- review 2026-10-20: false passes that must now fail ------------------------------------------
def test_a_file_written_outside_the_work_folder_fails(tmp_path, capsys):
    rows, end = story()
    rows.append(ev(6000, 11, 14, Image=CHURN, ProcessGuid="{W}",
                   TargetFilename=r"C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe"))
    a, _, out = both(tmp_path, capsys, sorted(rows, key=lambda r: r["time"]), end)
    assert a == 1 and "absent  FAIL  event 11 for the scenario's programs/files: 1" in out


def test_deleting_the_copies_too_fails_both_checks(tmp_path, capsys):
    rows, end = story()
    for i in range(1, N + 1):
        rows.append(ev(7000 + i, 26, 15 + i * 0.01, Image=CHURN, ProcessGuid="{W}",
                       TargetFilename=rf"{WORK}\note_{i:02d}.txt.s5copy"))
    a, b, out = both(tmp_path, capsys, sorted(rows, key=lambda r: r["time"]), end + 2)
    assert a == 1 and b == 1 and "absent  FAIL  event 26 for the scenario's programs/files: 40" in out


def test_deleting_files_it_did_not_create_fails(tmp_path, capsys):
    rows, end = story()
    for r in rows:
        if r.get("event_id") == 26:
            r["data"]["TargetFilename"] = r["data"]["TargetFilename"].replace("note_", "other_")
    a, _, out = both(tmp_path, capsys, rows, end)
    assert a == 1 and "0 of 40 are files step 3 created" in out


def test_a_manual_rerun_whose_clean_up_falls_in_the_window_still_passes(tmp_path, capsys):
    # the runner's PowerShell deletes the previous run's 40 copies just before the scenario starts
    rows, end = story()
    old = [ev(8000 + i, 26, -2 + i * 0.01, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              ProcessGuid="{RUN}", TargetFilename=rf"{WORK}\note_{i:02d}.txt.s5copy") for i in range(1, N + 1)]
    a, b, out = both(tmp_path, capsys, sorted(old + rows, key=lambda r: r["time"]), end)
    assert (a, b) == (0, 0), out
