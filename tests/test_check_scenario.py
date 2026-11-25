"""tools/check_scenario.py against hand-made S1 runs: one that matches the true story, and broken
variants that must each FAIL, including the independent review's probes A-E (2026-10-17):
look-alike program, payload from elsewhere, wrong order inside a step, evidence borrowed from a
neighbouring run, and a missing FILE_HASH covered by the previous run's."""

import copy
import json
import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_scenario  # noqa: E402

FETCH = r"D:\s1\s1_fetch.exe"
PAYLOAD = r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe"
H = "AB" * 32
BASE = datetime(2026, 10, 17, 18, 0, 0)


def ev(rid, eid, sec, base=BASE, **data):
    t = base + timedelta(seconds=sec)
    return {"source": "sysmon", "event_id": eid, "record_id": rid, "label": "vm",
            "time": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
            "data": {"UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], **data}}


def file_hash(sec, created, base=BASE, sha=H):
    t = base + timedelta(seconds=sec)
    return {"source": "agent", "type": "FILE_HASH", "label": "vm", "time": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
            "data": {"TargetFilename": created["data"]["TargetFilename"], "ProcessGuid": created["data"]["ProcessGuid"],
                     "hash_status": "ok", "sha256": sha, "ref_record_id": created["record_id"], "ref_time": created["time"]}}


def good_run(base=BASE, rid=100, f="{F}", p="{P}"):
    made = ev(rid + 2, 11, 3, base, Image=FETCH, ProcessGuid=f, TargetFilename=PAYLOAD)
    return [
        ev(rid, 1, 1, base, Image=FETCH, ProcessGuid=f, ParentProcessGuid="{RUNNER}", Hashes="SHA256=11"),
        ev(rid + 1, 3, 2, base, Image=FETCH, ProcessGuid=f, DestinationIp="10.0.2.2", DestinationPort=8765),
        made,
        file_hash(4, made, base),
        ev(rid + 3, 1, 5, base, Image=PAYLOAD, ParentImage=FETCH, ProcessGuid=p, ParentProcessGuid=f, Hashes=f"SHA256={H}"),
        ev(rid + 4, 5, 7, base, Image=PAYLOAD, ProcessGuid=p),
        ev(rid + 5, 5, 8, base, Image=FETCH, ProcessGuid=f),
    ]


def run_record(base=BASE, exit_code=0):
    iso = lambda s: (base + timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"source": "runner", "type": "SCENARIO_RUN", "scenario": "S1", "exit_code": exit_code,
            "time": iso(0), "start": iso(0), "end": iso(10)}


def check(tmp_path, capsys, records, runs=None, argv=()):
    for label, rows in (("vm", records), ("vmruns", runs or [run_record()])):
        folder = tmp_path / label
        folder.mkdir()
        (folder / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    code = check_scenario.main(["s1", "--recordings", str(tmp_path), *argv])
    return code, capsys.readouterr().out


def test_true_story_passes(tmp_path, capsys):
    code, out = check(tmp_path, capsys, good_run())
    assert code == 0, out
    assert "FAIL" not in out and "ran from the file the scenario created" in out


def test_missing_step_fails(tmp_path, capsys):
    rows = [r for r in good_run() if r.get("event_id") != 3]
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "step   2  FAIL" in out


def test_wrong_order_fails(tmp_path, capsys):
    rows = good_run()
    rows[2] = ev(102, 11, 0, Image=FETCH, ProcessGuid="{F}", TargetFilename=PAYLOAD)   # file before fetch started
    rows[3] = file_hash(4, rows[2])
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "FAIL" in out.split("order by UtcTime")[1].splitlines()[0]


def test_forbidden_event_fails(tmp_path, capsys):
    rows = good_run() + [ev(150, 22, 2, Image=FETCH, ProcessGuid="{F}", QueryName="x")]
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "absent  FAIL  event 22" in out


def test_download_marker_on_the_payload_fails_whatever_the_image(tmp_path, capsys):
    rows = good_run() + [ev(151, 15, 3, Image=r"C:\Windows\explorer.exe", ProcessGuid="{X}", TargetFilename=PAYLOAD)]
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "absent  FAIL  event 15" in out


def test_fingerprint_must_equal_the_running_payload(tmp_path, capsys):
    rows = good_run()
    rows[3]["data"]["sha256"] = "CD" * 32
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "step  3b  FAIL" in out


def test_failed_run_fails(tmp_path, capsys):
    code, _ = check(tmp_path, capsys, good_run(), runs=[run_record(exit_code=1)])
    assert code == 1


# -- the independent review's probes ------------------------------------------------------------
def test_A_lookalike_program_cannot_stand_in(tmp_path, capsys):
    rows = [r for r in good_run() if r.get("event_id") != 3]
    rows.append(ev(160, 3, 2, Image=r"C:\x\evil_s1_fetch.exe", ProcessGuid="{EVIL}",
                   DestinationIp="10.0.2.2", DestinationPort=8765))
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "step   2  FAIL" in out


def test_B_payload_from_elsewhere_with_another_parent_fails(tmp_path, capsys):
    rows = good_run()
    rows[4] = ev(103, 1, 5, Image=r"C:\Temp\s1_payload.exe", ParentImage=FETCH, ProcessGuid="{P}",
                 ParentProcessGuid="{OTHER}", Hashes=f"SHA256={H}")
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "s1_payload.exe: 0 matching process start(s)" in out


def test_payload_started_by_fetch_but_from_another_file_fails(tmp_path, capsys):
    rows = good_run()
    rows[4]["data"]["Image"] = r"C:\Temp\s1_payload.exe"
    code, out = check(tmp_path, capsys, rows)
    assert code == 1 and "FAIL  s1_payload.exe ran from the file the scenario created" in out


def test_C_order_inside_a_step_is_checked(tmp_path, capsys):
    rows = good_run()
    rows[5], rows[6] = ev(104, 5, 8, Image=PAYLOAD, ProcessGuid="{P}"), ev(105, 5, 7, Image=FETCH, ProcessGuid="{F}")
    code, out = check(tmp_path, capsys, rows)                    # fetch exits before its payload
    assert code == 1 and "ORDER: step 5" in out


def test_D_evidence_is_not_borrowed_from_the_next_run(tmp_path, capsys):
    first = [r for r in good_run() if not (r.get("event_id") == 5 and "fetch" in r["data"]["Image"])]  # fetch end missing
    later = BASE + timedelta(seconds=70)
    second = good_run(later, rid=200, f="{F2}", p="{P2}")
    code, out = check(tmp_path, capsys, first + second, runs=[run_record(), run_record(later)], argv=("--run", "2"))
    assert code == 1 and "step   5  FAIL" in out


def test_E_missing_file_hash_is_not_covered_by_the_previous_run(tmp_path, capsys):
    earlier = BASE - timedelta(seconds=60)
    prev = good_run(earlier, rid=50, f="{F0}", p="{P0}")
    late_prev_hash = file_hash(70, prev[2], earlier)                  # lands inside the next run's window
    current = [r for r in good_run() if r.get("type") != "FILE_HASH"]
    code, out = check(tmp_path, capsys, [r for r in prev if r.get("type") != "FILE_HASH"] + [late_prev_hash] + current,
                      runs=[run_record(earlier), run_record()])
    assert code == 1 and "step  3b  FAIL" in out


def test_overlapping_runs_fail(tmp_path, capsys):
    other = copy.deepcopy(run_record(BASE - timedelta(seconds=5)))      # ends 5 s into this run
    code, out = check(tmp_path, capsys, good_run(), runs=[other, run_record()])
    assert code == 1 and "overlaps the previous run" in out


def test_run_id_selects_exactly_that_run(tmp_path, capsys):
    # the run with the evidence, then a newer run (an hour later) that recorded nothing
    mine = {**run_record(), "run_id": "20261017-180000-aaaa"}
    newer = {**run_record(BASE + timedelta(hours=1)), "run_id": "20261017-190000-bbbb"}
    code, out = check(tmp_path, capsys, good_run(), runs=[mine, newer], argv=["--run-id", "20261017-180000-aaaa"])
    assert code == 0, out
    assert check_scenario.main(["s1", "--recordings", str(tmp_path)]) == 1             # newest = the empty run
    assert check_scenario.main(["s1", "--recordings", str(tmp_path), "--run-id", "nope"]) == 1
    assert "with run id nope" in capsys.readouterr().out


def test_run_id_recorded_twice_is_refused(tmp_path, capsys):
    twice = {**run_record(), "run_id": "20261017-180000-aaaa"}
    code, out = check(tmp_path, capsys, good_run(), runs=[twice, dict(twice)], argv=["--run-id", "20261017-180000-aaaa"])
    assert code == 1 and "recorded twice" in out


def test_run_on_the_new_server_port_checks_against_that_port(tmp_path, capsys):
    # since 2026-10-18 a run records the test server it used; the answer sheet says {test_server.port}
    rows = good_run()
    rows[1]["data"]["DestinationPort"] = 18765
    new = {**run_record(), "server": "http://10.0.2.2:18765"}
    code, out = check(tmp_path, capsys, rows, runs=[new])
    assert code == 0, out
    assert "test server used by this run: 10.0.2.2:18765" in out


def test_connection_to_the_old_port_fails_a_run_that_used_the_new_one(tmp_path, capsys):
    new = {**run_record(), "server": "http://10.0.2.2:18765"}
    code, out = check(tmp_path, capsys, good_run(), runs=[new])     # good_run connects to 8765
    assert code == 1 and "step   2  FAIL" in out


def test_older_runs_without_a_server_field_used_8765(tmp_path, capsys):
    code, out = check(tmp_path, capsys, good_run())                  # run_record() has no "server"
    assert code == 0 and "10.0.2.2:8765 (runs before 2026-10-18 did not record it)" in out


def test_run_naming_a_server_that_is_not_the_labs_fails(tmp_path, capsys):
    # the run record and the connection would agree with each other; the address itself is wrong
    rows = good_run()
    rows[1]["data"]["DestinationPort"] = 9999
    code, out = check(tmp_path, capsys, rows, runs=[{**run_record(), "server": "http://10.0.2.2:9999"}])
    assert code == 1 and "not a lab test server address" in out


def _renamed_sheet(tmp_path, keep_graph=True):
    """S1's sheet with the dropped program's role called `implant` (as a blind writer's B5 did), not `payload`."""
    import yaml
    with open(os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml"), encoding="utf-8") as f:
        sheet = yaml.safe_load(f)
    sheet["programs"]["implant"] = sheet["programs"].pop("payload")
    facts = sheet["expected_graph"]["facts"]
    for fact in facts:
        for k in ("from", "to"):
            fact[k] = {"payload": "implant", "payload_file": "implant_file"}.get(fact[k], fact[k])
    if not keep_graph:
        sheet["expected_graph"]["facts"] = [x for x in facts if "implant_file" not in (x["from"], x["to"])]
    path = tmp_path / "sheet.yaml"
    path.write_text(yaml.safe_dump(sheet), encoding="utf-8")
    return str(path)


def test_a_payload_role_with_another_name_is_checked_not_a_crash(tmp_path, capsys):
    """v3: v2 assumed the role `payload` and crashed (KeyError) on B3/B5's sheets, so every run was NOT CHECKED."""
    code, out = check(tmp_path, capsys, good_run(), argv=["--sheet", _renamed_sheet(tmp_path)])
    assert "implant written under" in out and "implant written under \\AnalystLab\\scenarios\\s1\\payload\\: PASS" in out


def test_payload_path_without_any_payload_program_fails_clearly(tmp_path, capsys):
    code, out = check(tmp_path, capsys, good_run(), argv=["--sheet", _renamed_sheet(tmp_path, keep_graph=False)])
    assert code == 1 and "the sheet names no payload program" in out
