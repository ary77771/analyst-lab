"""tools/check_alerts.py: the detection check of a VM run against the answer sheet's
`alert_expected.check` list (integration review 2026-10-24)."""

import os
import sys

import pytest

from engine import detect, score
from tests.test_detect import store
from tests.test_own_rules import W, chain

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import check_alerts  # noqa: E402

TRUTH = {"programs": {"payload": W.rsplit("\\", 1)[-1]},
         "alert_expected": {"check": [{"rule_id": "analystlab.fetch_write_run", "level": "medium", "involves": "payload"}]}}


def run(tmp_path, records, truth=TRUTH):
    con = detect.open_store(store(tmp_path, records))
    try:
        alerts = score.score(con, [], None)
        lines = []
        verdict, found, missing, other = check_alerts.check(truth, alerts, con, say=lines.append)
        return verdict, lines, other
    finally:
        con.close()


def test_expected_alert_involving_the_scenario_program_is_detected(tmp_path):
    verdict, lines, other = run(tmp_path, chain())
    assert verdict == "DETECTED" and any("alert  PASS  analystlab.fetch_write_run [medium] involving payload" in l for l in lines)
    assert other == []


def test_a_missing_alert_is_missed(tmp_path):
    verdict, lines, _ = run(tmp_path, chain(t_start=500.0))           # started too late for the rule's window
    assert verdict == "MISSED" and any("alert  MISS" in l for l in lines)


def test_the_alert_must_involve_the_scenario_program(tmp_path):
    truth = dict(TRUTH, programs={"payload": "something_else.exe"})
    verdict, _, other = run(tmp_path, chain(), truth)
    assert verdict == "MISSED" and len(other) == 1                    # it counts as an OTHER raised alert


def test_the_level_must_match(tmp_path):
    truth = dict(TRUTH, alert_expected={"check": [dict(TRUTH["alert_expected"]["check"][0], level="informational")]})
    assert run(tmp_path, chain(), truth)[0] == "MISSED"


def test_nothing_expected(tmp_path):
    assert run(tmp_path, chain(), {"programs": {}})[0] == "NONE EXPECTED"


def test_every_sheet_names_real_rules_levels_and_roles():
    import yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    from engine import beacon, own_rules
    known = set(own_rules.RULES) | set(own_rules.BASELINE_RULES) | {beacon.RULE_ID}
    # community rules a sheet names (S6, version 2) must exist in the pinned set at that level
    community = ({r.rule_id: r.level for r in detect.load_rules([detect.COMMUNITY_RULES])[0]}
                 if os.path.isdir(detect.COMMUNITY_RULES) else None)
    for name in sorted(os.listdir(os.path.join(root, "scenarios"))):
        path = os.path.join(root, "scenarios", name, "ground_truth.yaml")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            truth = yaml.safe_load(f)
        for e in (truth.get("alert_expected") or {}).get("check") or []:
            if e["rule_id"] not in known:
                if community is None:
                    pytest.skip("SigmaHQ rules not fetched (tools/fetch_sigma_rules.ps1)")
                assert community.get(e["rule_id"]) == e["level"], (name, e)
            assert e["level"] in detect.LEVELS, (name, e)
            assert e["involves"] in (truth.get("programs") or {}), (name, e)


# -- blind round 2: suspicious steps (v2 pre-registration) --------------------------------------------------------
from tests.test_detect import ev  # noqa: E402

MAIN = r"C:\AnalystLab\scenarios\b9\bin\b9_main.exe"
NOTE = r"C:\AnalystLab\scenarios\b9\work\note.txt"


def b9_records(t_start=5.0):
    """b9_main connects out, writes an innocent note and a program, then starts that program: the
    community-free own rule fetch_write_run cites the connection, the program file and its start."""
    return [ev(1, 0.0, Image=MAIN, ProcessGuid="{M}", ParentProcessGuid="{R}", ProcessId=10),
            ev(3, 1.0, Image=MAIN, ProcessGuid="{M}", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=80),
            ev(11, 1.5, Image=MAIN, ProcessGuid="{M}", TargetFilename=NOTE),
            ev(11, 2.0, Image=MAIN, ProcessGuid="{M}", TargetFilename=W),
            ev(1, t_start, Image=W, ProcessGuid="{C}", ParentProcessGuid="{M}", ParentImage=MAIN, ProcessId=11)]


def b9_truth(suspicious):
    return {"scenario": "B9", "programs": {"main": "b9_main.exe", "payload": "tool.exe"},
            "steps": [{"id": 1, "what": "starts", "evidence": {"sysmon_event": 1, "Image_endswith": "b9_main.exe"}},
                      {"id": 2, "what": "connects", "evidence": {"sysmon_event": 3, "Image_endswith": "b9_main.exe"}},
                      {"id": 3, "what": "writes a note", "evidence": {"sysmon_event": 11, "Image_endswith": "b9_main.exe",
                                                                      "TargetFilename_suffix": ".txt"}},
                      {"id": 4, "what": "writes a program", "evidence": {"sysmon_event": 11, "TargetFilename_endswith": "tool.exe"}},
                      {"id": 5, "what": "starts it", "evidence": {"sysmon_event": 1, "Image_endswith": "tool.exe",
                                                                  "ParentImage_endswith": "b9_main.exe"}}],
            "alert_expected": {"suspicious_steps": suspicious, "why": "test"}}


def run_steps(tmp_path, records, truth):
    con = detect.open_store(store(tmp_path, records))
    try:
        alerts = score.score(con, [], None)
        lines, detail = [], {}
        verdict, found, missing, other = check_alerts.check(truth, alerts, con, say=lines.append, records=records, detail=detail)
        return verdict, detail, lines, found, missing
    finally:
        con.close()


def test_suspicious_steps_are_flagged_by_the_events_an_alert_cites(tmp_path):
    verdict, d, lines, found, missing = run_steps(tmp_path, b9_records(), b9_truth([4, 5]))
    assert verdict == "DETECTED" and d["flagged"] == [4, 5] and missing == []
    assert d["rules_per_step"][4] == ["analystlab.fetch_write_run[medium]"]
    assert [e["rule_id"] for e, _ in found] == ["step 4", "step 5"]          # time to detect works per step
    assert not any("cites none" in l for l in lines)                          # a flagged step never says it was not cited


def test_an_innocent_step_of_the_same_program_is_not_flagged(tmp_path):
    """Event level, not program level: the alert names b9_main.exe, but cites none of the note's events."""
    verdict, d, lines, _, missing = run_steps(tmp_path, b9_records(), b9_truth([3]))
    assert verdict == "MISSED" and d["flagged"] == [] and d["flagged_by_program_only"] == [3]
    assert d["alerts_on_other_steps"] == 1 and len(missing) == 1
    assert any("cites none of this step's own events" in l for l in lines)


def test_an_innocent_scenario_is_clean_or_a_false_alarm(tmp_path):
    assert run_steps(tmp_path, b9_records(), b9_truth([]))[0] == "FALSE ALARM"
    assert run_steps(tmp_path, b9_records(t_start=500.0), b9_truth([]))[0] == "CLEAN"     # too late: the rule does not fire


def test_unfound_programs_and_missing_records_are_not_checked(tmp_path):
    truth = dict(b9_truth([4]), programs={"main": "other.exe"})
    assert run_steps(tmp_path, b9_records(), truth)[0] == "NOT CHECKED"
    con = detect.open_store(store(tmp_path, b9_records()))
    try:
        with pytest.raises(ValueError, match="needs the run's records"):
            check_alerts.check(b9_truth([4]), [], con)
    finally:
        con.close()


def test_a_suspicious_step_never_recorded_is_named(tmp_path):
    records = [r for r in b9_records() if not (r["event_id"] == 11 and r["data"]["TargetFilename"] == NOTE)]
    verdict, d, *_ = run_steps(tmp_path, records, b9_truth([3, 4]))
    assert verdict == "MISSED" and d["unrecorded"] == [3] and d["flagged"] == [4]


def test_exit_codes_cover_every_verdict():
    assert {v: check_alerts.EXIT[v] for v in ("DETECTED", "NONE EXPECTED", "CLEAN", "MISSED", "FALSE ALARM", "NOT CHECKED")} == \
        {"DETECTED": 0, "NONE EXPECTED": 0, "CLEAN": 0, "MISSED": 1, "FALSE ALARM": 1, "NOT CHECKED": 2}

def test_alerts_below_the_floor_do_not_flag_a_step(tmp_path):
    from engine.alerts import Alert
    from engine.store import EventStore
    records = b9_records(t_start=500.0)                    # the own rule does not fire
    key = EventStore.dedup_key(records[3])                  # step 4's event
    con = detect.open_store(store(tmp_path, records))
    try:
        for level, want in (("low", "MISSED"), ("medium", "DETECTED")):
            a = Alert(rule_id="x", title="x", source="sigma", level=level, time=records[3]["time"], host="h1", reason="r",
                      evidence=(key,), details={})
            assert check_alerts.check(b9_truth([4]), [a], con, say=lambda m: None, records=records)[0] == want, level
    finally:
        con.close()

# -- review 2026-11-13: shared evidence, FILE_HASH steps, process identity, sheet errors ---------------------------
def test_a_record_shared_with_an_innocent_step_does_not_flag_a_suspicious_one(tmp_path):
    """Step 6 is written with step 2's pattern (the connection): the alert cites that connection, but
    a record that the innocent step 2 also matches cannot flag step 6."""
    truth = b9_truth([6])
    truth["steps"].append({"id": 6, "what": "connects (again)", "evidence": {"sysmon_event": 3, "Image_endswith": "b9_main.exe"}})
    verdict, d, lines, *_ = run_steps(tmp_path, b9_records(), truth)
    assert verdict == "MISSED" and d["ambiguous"] == [6] and d["shared_records"] == {6: 1}
    assert any("ambiguous" in l for l in lines)
    both = b9_truth([2, 6])                                   # both suspicious: nothing is shared with an innocent step
    both["steps"].append(truth["steps"][-1])
    assert run_steps(tmp_path, b9_records(), both)[0] == "DETECTED"


def test_a_file_hash_step_is_flagged_through_the_file_event_it_fingerprints(tmp_path):
    records = b9_records()
    made = records[3]                                          # main writes tool.exe (event 11)
    records.append({"host": "h1", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH", "time": made["time"],
                    "origin": "normal", "data": {"TargetFilename": W, "ProcessGuid": "{M}", "hash_status": "ok", "sha256": "AA",
                                                 "ref_record_id": made["record_id"], "ref_time": made["time"]}})
    truth = b9_truth([4])
    truth["steps"][3]["evidence"] = {"agent_type": "FILE_HASH", "TargetFilename_endswith": "tool.exe"}
    assert run_steps(tmp_path, records, truth)[0] == "DETECTED"


def test_shared_windows_names_do_not_make_an_innocent_run_a_false_alarm(tmp_path):
    from engine.alerts import Alert
    from engine.store import EventStore
    shell = ev(1, 3.0, Image=r"C:\Windows\System32\cmd.exe", ProcessGuid="{X}", ParentProcessGuid="{RUNNER}", ProcessId=50)
    own_shell = ev(1, 2.5, Image=r"C:\Windows\System32\cmd.exe", ProcessGuid="{SH}", ParentProcessGuid="{M}", ProcessId=49)
    records = b9_records(t_start=500.0) + [own_shell, shell]
    truth = b9_truth([])
    truth["programs"]["shell"] = "cmd.exe"
    truth["windows_programs"] = ["shell"]
    con = detect.open_store(store(tmp_path, records))
    try:
        a = Alert(rule_id="x", title="x", source="sigma", level="medium", time=shell["time"], host="h1", reason="r",
                  evidence=(EventStore.dedup_key(shell),), details={})
        verdict, _, _, other = check_alerts.check(truth, [a], con, say=lambda m: None, records=records)
        assert verdict == "CLEAN" and other == [a]           # the runner's cmd.exe is not the scenario's
        b = Alert(rule_id="y", title="y", source="sigma", level="medium", time=own_shell["time"], host="h1", reason="r",
                  evidence=(EventStore.dedup_key(own_shell),), details={})
        assert check_alerts.check(truth, [b], con, say=lambda m: None, records=records)[0] == "FALSE ALARM"   # the scenario's own shell
    finally:
        con.close()


def test_a_sheet_that_cannot_be_scored_is_not_checked(tmp_path):
    for broken in ({"suspicious_steps": ["4"], "why": "x"}, {"suspicious_steps": [9], "why": "x"}):
        truth = dict(b9_truth([4]), alert_expected=broken)
        verdict, d, lines, *_ = run_steps(tmp_path, b9_records(), truth)
        assert verdict == "NOT CHECKED" and d["sheet_problems"] and any("cannot be scored as written" in l for l in lines)
    truth = b9_truth([4])
    del truth["steps"][2]["evidence"]
    assert run_steps(tmp_path, b9_records(), truth)[0] == "NOT CHECKED"


def test_an_unexpected_error_in_the_cli_is_not_checked(monkeypatch, capsys):
    monkeypatch.setattr(check_alerts, "_main", lambda argv=None: 1 / 0)
    assert check_alerts.main(["b9"]) == 2 and "NOT CHECKED" in capsys.readouterr().out

def test_a_step_whose_only_own_record_is_a_fingerprint_is_ambiguous(tmp_path):
    """Detectors never cite FILE_HASH records: if a suspicious step's only record of its own is one,
    it can never be flagged, and is reported "ambiguous" (follow-up review 2026-11-13)."""
    records = b9_records()
    made = records[3]
    records.append({"host": "h1", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH", "time": made["time"],
                    "origin": "normal", "data": {"TargetFilename": W, "ProcessGuid": "{M}", "hash_status": "ok", "sha256": "AA",
                                                 "ref_record_id": made["record_id"], "ref_time": made["time"]}})
    truth = b9_truth([6])
    truth["steps"].append({"id": 6, "what": "fingerprint", "evidence": {"agent_type": "FILE_HASH", "TargetFilename_endswith": "tool.exe"}})
    verdict, d, *_ = run_steps(tmp_path, records, truth)            # step 4 (innocent) matches the same event 11
    assert verdict == "MISSED" and d["ambiguous"] == [6]

def test_a_fingerprint_step_never_makes_the_write_step_ambiguous(tmp_path):
    """The other direction (round 1's B1 layout): "writes tool.exe" (event 11) is suspicious, "the agent
    fingerprints it" (FILE_HASH) is not. The event 11 that the innocent fingerprint step brings in must
    not count as shared: an alert citing it flags the write step (advisor, 2026-11-13)."""
    records = b9_records()
    made = records[3]
    records.append({"host": "h1", "session": "s", "source": "agent", "seq": 1, "type": "FILE_HASH", "time": made["time"],
                    "origin": "normal", "data": {"TargetFilename": W, "ProcessGuid": "{M}", "hash_status": "ok", "sha256": "AA",
                                                 "ref_record_id": made["record_id"], "ref_time": made["time"]}})
    truth = b9_truth([4])
    truth["steps"].append({"id": 6, "what": "fingerprint", "evidence": {"agent_type": "FILE_HASH", "TargetFilename_endswith": "tool.exe"}})
    verdict, d, *_ = run_steps(tmp_path, records, truth)
    assert verdict == "DETECTED" and d["flagged"] == [4] and d["ambiguous"] == [] and d["shared_records"] == {4: 0}


# -- v4 F1: the incident column (follow-through), next to the unchanged strict verdict ------------------------------
def run_incident(tmp_path, truth, with_follow=True):
    from engine import follow
    records = b9_records() + [ev(3, 6.0, Image=W, ProcessGuid="{C}", Initiated="true", DestinationIp="10.0.2.2",
                                 DestinationPort=443)]                       # the started program phones out
    truth = dict(truth, steps=truth["steps"] + [{"id": 6, "what": "the program connects",
                                                 "evidence": {"sysmon_event": 3, "Image_endswith": "tool.exe"}}])
    con = detect.open_store(store(tmp_path, records))
    try:
        alerts = score.score(con, [], None)
        ft = follow.follow_through(con, alerts, hubs=frozenset(), min_level="medium") if with_follow else None
        lines, detail = [], {}
        verdict, *_ = check_alerts.check(truth, alerts, con, say=lines.append, records=records, detail=detail, follow=ft)
        return verdict, detail, lines
    finally:
        con.close()


def test_follow_through_fills_the_incident_column_and_never_the_verdict(tmp_path):
    verdict, d, lines = run_incident(tmp_path, b9_truth([4, 5, 6]))
    assert verdict == "MISSED" and d["flagged"] == [4, 5]                    # strict: no rule cites the connection
    assert d["incident"] == {"verdict": "DETECTED", "flagged": [4, 5, 6], "flagged_by_follow_through_only": [6],
                             "alerts_on_scenario": 1, "alerts_rooted_outside": 0, "innocent_steps_reached": [3]}
    assert any("incident level" in l and "DETECTED" in l for l in lines)
    verdict, d, _ = run_incident(tmp_path, b9_truth([4, 5, 6]), with_follow=False)
    assert verdict == "MISSED" and "incident" not in d                       # no follow-through given: no column


def test_the_incident_column_keeps_the_innocent_step_exclusion_and_counts_against_innocent_runs(tmp_path):
    # step 3 (the note, 1.5 s) is in the follow-through of the alert, but it is the only suspicious step
    # here and step 6 is innocent: the connection must not flag anything, the note may (its own record)
    verdict, d, _ = run_incident(tmp_path, b9_truth([3]))
    assert verdict == "MISSED" and d["incident"]["flagged"] == [3]
    verdict, d, _ = run_incident(tmp_path, b9_truth([]))
    assert verdict == "FALSE ALARM" and d["incident"]["verdict"] == "FALSE ALARM"


def test_the_strict_result_is_identical_with_and_without_follow_through(tmp_path):
    for sus in ([4, 5, 6], [3], [4], []):
        v1, d1, l1 = run_incident(tmp_path, b9_truth(sus))
        v2, d2, l2 = run_incident(tmp_path, b9_truth(sus), with_follow=False)
        d1.pop("incident")
        assert (v1, d1, [x for x in l1 if "incident level" not in x]) == (v2, d2, l2)


def test_an_alert_rooted_above_an_innocent_scenario_counts_against_it_at_incident_level(tmp_path):
    """Symmetry: strict CLEAN (no alert cites the scenario), but a raised alert on a non-lab ancestor
    follows down into it: incident FALSE ALARM, and the alert is counted as rooted outside."""
    from engine import follow
    from engine.alerts import Alert
    from engine.store import EventStore
    opener = ev(1, 0.0, Image=r"C:\Users\u\Downloads\opener.exe", ProcessGuid="{R}", ParentProcessGuid="{Q}", ProcessId=9)
    records = [opener] + b9_records(t_start=500.0)          # {R} is b9_main's parent; fetch_write_run stays quiet
    con = detect.open_store(store(tmp_path, records))
    try:
        alerts = [Alert("some.rule", "t", "sigma", "medium", "2026-10-22T10:00:00.000Z", "h1", "because",
                        (EventStore.dedup_key(opener),))]
        ft = follow.follow_through(con, alerts, hubs=frozenset(), min_level="medium")
        d = {}
        verdict, *_ = check_alerts.check(b9_truth([]), alerts, con, say=lambda s: None, records=records, detail=d, follow=ft)
    finally:
        con.close()
    assert verdict == "CLEAN" and d["incident"]["verdict"] == "FALSE ALARM" and d["incident"]["alerts_rooted_outside"] == 1


def test_a_failing_follow_through_never_costs_the_strict_verdict(tmp_path, monkeypatch):
    lines = []
    monkeypatch.setattr(check_alerts.config, "hubs", lambda **kw: (_ for _ in ()).throw(ValueError("hub list changed")))
    assert check_alerts.incident_view(None, [], say=lines.append) is None and "not computed" in lines[0]
    monkeypatch.setattr(check_alerts.config, "hubs", lambda **kw: None)
    assert check_alerts.incident_view(None, [], say=lines.append) is None and "no hub list" in lines[1]
