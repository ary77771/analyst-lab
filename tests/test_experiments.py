"""Package J part 2: tools/experiments.py (the pre-registered experiments driver), the graph
checker's tally counters, tools/build_test_snapshot.py and the official-mode gating of the overlay
tools. Hand-made inputs only (the graph checker's own S1 fixture, the overlay tests' tiny laptop
snapshot, hand-written result documents); nothing here reads recordings/."""

import json
import os
import sqlite3
import sys

import pytest

from engine import confidence as C
from engine.alerts import Alert, AlertStore
from engine.store import EventStore
from tests.test_build_dev_snapshot import rec as day_rec, write_day
from tests.test_check_graph_scenario import BASE, FETCH, PAYLOAD, ev, good_run, iso, pool_file
from tests.test_overlay import RUN_ID, laptop_db, run_record, write_recordings

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import build_test_snapshot  # noqa: E402
import experiments as X  # noqa: E402
import noise_overlay  # noqa: E402
import overlay_experiment  # noqa: E402


# -- fixtures -------------------------------------------------------------------------------------------
@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A practice Lab over a hand-made S1 run (the checker's fixture: the payload starts 13 s after
    the connection, so the sheet's optional T3 link is rightly absent), with no Sigma rules and no
    learned-normal baseline (the own rules alone detect S1), outputs under tmp."""
    write_recordings(tmp_path)
    monkeypatch.setattr(X.Lab, "rules", lambda self: [])
    monkeypatch.setattr(X.Lab, "baseline", lambda self: None)
    return X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"))


def official_series(tmp_path, run_ids):
    (tmp_path / "series").mkdir(exist_ok=True)
    (tmp_path / "series" / "official.json").write_text(json.dumps({"label": "official", "runs": [{"run_id": r} for r in run_ids]}),
                                                       encoding="utf-8")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# -- 1. the proportion helper ------------------------------------------------------------------------------
def test_share_is_a_clopper_pearson_interval():
    s = X.share(5, 10)
    assert s["share"] == 0.5 and abs(s["lo"] - 0.1871) < 5e-4 and abs(s["hi"] - 0.8129) < 5e-4
    assert X.share(0, 0) is None and X.pct(None) == "-"
    assert X.pct(X.share(1, 1)).startswith("100 % (1/1; 95 % [3, 100] %)")
    assert X.median([3, 1, 2]) == 2 and X.median([1, 2, 3, 4]) == 2.5 and X.median([]) is None


# -- 2. the gate: practice never in official mode, official never without it --------------------------------
def test_gate_practice_vs_official(tmp_path, monkeypatch):
    lab = X.Lab("practice", str(tmp_path))
    assert lab.problems() == []
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    assert any("contradiction" in p for p in lab.problems())
    off = X.Lab("official", str(tmp_path), of="v1")
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: ["pool missing"])
    assert off.problems() == ["official mode: pool missing"]
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: [])
    assert off.problems() == []
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    assert any("ANALYSTLAB_OFFICIAL=1" in p for p in off.problems())
    with pytest.raises(ValueError):
        X.Lab("dev", str(tmp_path))
    assert X.main(["detection", "--label", "official", "--recordings", str(tmp_path)]) == 2


def official_series_doc(tmp_path, entries, started, name="official.json", series="20261101-000000"):
    (tmp_path / "series").mkdir(exist_ok=True)
    (tmp_path / "series" / name).write_text(json.dumps({"label": "official", "series": series, "started": started, "runs": entries}), encoding="utf-8")


def test_select_runs_keeps_the_dev_test_split(tmp_path, monkeypatch):
    """practice = runs outside every official series and before the first one began, never a blind
    id; official = every series entry (a crash before the summary = "could not run"), plus runs whose
    own summary says official; a blind run needs its opened sheet; failed runs are listed, not scored."""
    practice = run_record()
    official = run_record(run_id="20261101-010000-off1", start=iso(3600), end=iso(3620), time=iso(3600))
    failed = run_record(run_id="20261101-020000-off2", start=iso(7200), end=iso(7220), time=iso(7200), exit_code=1)
    lost = run_record(run_id="20261101-025000-lost", start=iso(9000), end=iso(9020), time=iso(9000))   # crashed before its summary
    blind = run_record(run_id="20261101-030000-bli1", start=iso(10800), end=iso(10820), time=iso(10800), scenario="B1")
    solo = run_record(run_id="20261101-040000-solo", start=iso(14400), end=iso(14420), time=iso(14400), scenario="B2")
    write_recordings(tmp_path, runs=[practice, official, failed, lost, blind, solo])
    entries = [{"n": 1, "scenario": "S1", "run_id": official["run_id"], "exit_code": 0, "result": "PASS"},
               {"n": 2, "scenario": "S1", "run_id": failed["run_id"], "exit_code": 1, "result": "FAIL"},
               {"n": 3, "scenario": "S1", "run_id": None, "exit_code": 3, "result": "VM STEP FAILED"},
               {"n": 4, "scenario": "B1", "run_id": blind["run_id"], "exit_code": 0, "result": "PASS"}]
    official_series_doc(tmp_path, entries, started=iso(3000))
    (tmp_path / "scenario_runs").mkdir()                              # run_blind.py --label official, no series
    (tmp_path / "scenario_runs" / f"{solo['run_id']}.json").write_text(json.dumps({"run_id": solo["run_id"], "label": "official"}), encoding="utf-8")
    lab = X.Lab("practice", str(tmp_path))
    assert [it.run_id for it in lab.select_runs()] == [RUN_ID]           # the lost run started after the series began: not practice
    assert lab.select_runs(["s1"], blind=False)[0].truth["scenario"] == "S1"
    with pytest.raises(ValueError):
        lab.select_runs(blind=True)
    with pytest.raises(ValueError):
        lab.select_runs(["b1"])
    assert lab.select_runs(["s3"]) == []
    assert [it.run_id for it in X.Lab("practice", str(tmp_path), until="2026-10-16").select_runs()] == []
    assert len(X.Lab("practice", str(tmp_path), last=1).select_runs()) == 1
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    off = X.Lab("official", str(tmp_path), of="v1")
    items = off.select_runs()
    assert [(it.run_id, it.status) for it in items] == [
        (official["run_id"], "ok"), (failed["run_id"], "run failed (exit code 1)"),
        (str(iso(3000)), "could not run (series 20261101-000000 #3: VM STEP FAILED, exit code 3, no run record)")]
    with pytest.raises(ValueError, match="cherry-picking"):
        off.select_runs(["s1"])
    with pytest.raises(ValueError, match="cherry-picking"):
        X.Lab("official", str(tmp_path), of="v1", last=1).select_runs()
    b = off.select_runs(blind=True)
    assert [(it.run_id, it.status) for it in b] == [(blind["run_id"], "answer sheet not opened for this run"),
                                                    (solo["run_id"], "answer sheet not opened for this run")]
    sheet = tmp_path / "blind" / "B1" / blind["run_id"]
    sheet.mkdir(parents=True)
    (sheet / "ground_truth.yaml").write_text(read(os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml")).replace("scenario: S1", "scenario: B1"),
                                             encoding="utf-8")
    b = off.select_runs(blind=True)
    assert b[0].ok and b[0].truth["scenario"] == "B1"
    # a malformed blind sheet is that run's status, not the end of J3
    (sheet / "ground_truth.yaml").write_text("scenario: [unclosed\n", encoding="utf-8")
    assert off.select_runs(blind=True)[0].status.startswith("answer sheet unreadable: ")
    # an unreadable series file is an error, never "those runs are practice"
    (tmp_path / "series" / "broken.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot be read"):
        off.select_runs()
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    with pytest.raises(ValueError, match="cannot be read"):
        X.Lab("practice", str(tmp_path)).select_runs()
    assert X.main(["detection", "--label", "practice", "--recordings", str(tmp_path)]) == 2


def test_the_practice_boundary_parses_times_instead_of_comparing_text(tmp_path):
    """A series started at 20:50+02:00 (= 18:50Z); a run at 19:00Z is AFTER it, although the text
    '2026-10-17T19:00:00.0000000Z' sorts before '2026-10-17T20:50:00+02:00'."""
    write_recordings(tmp_path, runs=[run_record(run_id="20261017-190000-late", start="2026-10-17T19:00:00.0000000Z", end="2026-10-17T19:00:20.0000000Z",
                                                time="2026-10-17T19:00:00.0000000Z")])
    official_series_doc(tmp_path, [], started="2026-10-17T20:50:00+02:00")
    run = __import__("check_scenario").find_run(str(tmp_path), "s1", run_id="20261017-190000-late")
    assert not noise_overlay.is_practice_run(str(tmp_path), run)
    assert X.Lab("practice", str(tmp_path)).select_runs() == []
    assert noise_overlay.is_practice_run(str(tmp_path), dict(run, start="2026-10-17T18:49:59.9999999Z"))
    assert not noise_overlay.is_practice_run(str(tmp_path), dict(run, start="yesterday"))      # unreadable: never practice
    official_series_doc(tmp_path, [], started="2026-10-17T23:00:00+00:00", name="later.json")
    assert noise_overlay.first_official_start(str(tmp_path)) == "2026-10-17T20:50:00+02:00"


def test_official_mode_refuses_every_data_choice_on_the_command_line(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: [])
    base = ["--label", "official", "--recordings", str(tmp_path)]
    for extra in (["--runs", "s1"], ["--last", "1"], ["--until", "2026-11-01"], ["--big", "x.jsonl"], ["--alerts", "a.db"], ["--seeds", "1"],
                  ["--bootstrap", "200"], ["--friends", "f"], ["--vm-label", "vm2"]):
        assert X.main(["detection"] + base + extra) == 2
        assert "refused" in capsys.readouterr().out
    lab = X.Lab("official", str(tmp_path), of="v1")
    with pytest.raises(ValueError, match="refused"):
        X.cmd_overlay(lab, runs=["s1:1"])
    with pytest.raises(ValueError, match="--alerts"):
        X.cmd_false_alerts(lab, alerts=["a.db"])
    with pytest.raises(ValueError, match="--big"):
        X.cmd_performance(lab, big="x.jsonl")


# -- 3. J1 and J2 on the hand-made S1 run ---------------------------------------------------------------
def test_detection_measures_the_verdict_and_the_time_to_detect(lab, tmp_path):
    assert X.cmd_detection(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "detection.json"))
    (run,) = doc["runs"]
    assert run["verdict"] == "DETECTED" and run["anchored"] and run["other_alerts"] == 0
    (ttd,) = run["time_to_detect"]
    # the own rule's alert time = the payload's start (15 s); the first program started at 1 s
    assert ttd["rule_id"] == "analystlab.fetch_write_run" and ttd["seconds"] == 14.0
    s = doc["summary"]["per_scenario"]["S1"]
    assert s["detected"] == 1 and s["rate"]["share"] == 1.0 and s["ttd_seconds"]["median"] == 14.0
    text = read(tmp_path / "results" / "detection-practice.md")
    assert "| S1 | 1 | 1 | 1 | 0 | 0 | 100 %" in text and "analystlab.fetch_write_run[medium] 14.0" in text and "(1 of 1)" in text
    for private in ("D:\\s1", "C:\\AnalystLab", "10.0.2"):
        assert private not in text, private


def test_detection_counts_a_miss_and_an_unrelated_alert(lab, tmp_path, monkeypatch):
    """A sheet whose programs are not the ones that acted: the expected alert is MISSED, and the alert
    that really fired names none of the sheet's programs, so it is counted as an OTHER alert."""
    truth = lab.select_runs()[0].truth
    truth["programs"] = {"fetch": "other_fetch.exe", "payload": "other_payload.exe"}
    monkeypatch.setattr(X, "load_sheet", lambda path: truth)
    assert X.cmd_detection(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "detection.json"))
    (run,) = doc["runs"]
    assert run["verdict"] == "MISSED" and run["missed"] == ["analystlab.fetch_write_run[medium]"]
    assert run["other_alerts"] == 1 and run["other_by_rule"] == {"analystlab.fetch_write_run[medium]": 1}
    assert doc["summary"]["pooled"]["share"] == 0.0 and not run["anchored"]


def test_time_to_detect_without_an_anchor_is_reported_not_crashed(lab, tmp_path, monkeypatch):
    """Review 2026-10-30 (major 4): anchor() failing gave seconds None and min() over None crashed `all`."""
    import check_scenario
    monkeypatch.setattr(check_scenario.Checker, "anchor", lambda self: False)
    assert X.cmd_detection(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "detection.json"))
    (run,) = doc["runs"]
    assert run["verdict"] == "DETECTED" and run["time_to_detect"][0]["seconds"] is None
    t = doc["summary"]["per_scenario"]["S1"]["ttd_seconds"]
    assert t == {"n": 0, "not_anchored": 1, "min": None, "median": None, "max": None}
    text = read(tmp_path / "results" / "detection-practice.md")
    assert "(0 of 1)" in text and "not anchored" in text


def test_an_odd_sheet_is_recorded_as_a_status_not_a_crash(lab, tmp_path, monkeypatch):
    """Review 2026-10-30 (major 5): one sheet without `programs` must not kill the whole table."""
    monkeypatch.setattr(X, "load_sheet", lambda path: {"scenario": "S1", "alert_expected": {"check": [{"rule_id": "x", "level": "medium", "involves": "p"}]}})
    assert X.cmd_detection(lab) == 2                         # nothing scored, but the file and the status exist
    doc = json.loads(read(tmp_path / "out" / "detection.json"))
    assert doc["runs"] == [] and doc["skipped"][0]["status"].startswith("could not score: KeyError")
    assert "could not score" in read(tmp_path / "results" / "detection-practice.md")


def test_story_counts_facts_hypotheses_and_views(lab, tmp_path):
    assert X.cmd_story(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "story.json"))
    (run,) = doc["runs"]
    t = run["tally"]
    assert run["pass"] and t["facts_expected"] == 4 and t["facts_found"] == 4 and t.get("facts_unexpected", 0) == 0
    assert t["hyps_expected"] == 1 and t["hyps_found"] == 1 and t["hyps_optional_absent"] == 1 and t.get("hyps_unlisted", 0) == 0
    assert t["gaps_ok"] == 1 and t["view_ok"] == 1 and t["runner_view_ok"] == 1 and t["trace_ok"] == 1
    p = doc["summary"]["pooled"]
    assert p["facts"]["recall"]["share"] == 1.0 and p["facts"]["precision"]["share"] == 1.0
    assert p["hypotheses"]["recall"]["share"] == 1.0 and p["bands"] == {"T1/low": 1}
    text = read(tmp_path / "results" / "story-practice.md")
    assert "| S1 | 1 | 1 | 100 % (4/4" in text and "- T1 low: 1" in text
    for private in ("D:\\s1", "C:\\AnalystLab", "10.0.2"):
        assert private not in text, private


def test_story_counts_a_lost_fact_and_a_false_hypothesis(lab, tmp_path, monkeypatch):
    """Sabotage of the graph, not of the checker: drop the `created` fact and add a hypothesis the
    sheet does not list between two scenario nodes. Recall and precision must say so."""
    real = X.build_graph

    def broken(db, **kw):
        G = real(db, **kw)
        G.remove_edges_from([(u, v, k) for u, v, k, d in G.edges(keys=True, data=True) if d.get("kind") == "created"])
        procs = [n for n, d in G.nodes(data=True) if d.get("kind") == "process" and str(d.get("label")).lower() in ("s1_fetch.exe", "s1_payload.exe")]
        G.add_edge(procs[0], procs[1], kind="remote_command", grade="hypothesis", layer=2, row="T2", band="low", claim="x",
                   reason="r", alternative="a", evidence=[], time=None, basis="formula", via=procs[0], p=0.5, n_causes=1, assessable=True)
        return G
    monkeypatch.setattr(X, "build_graph", broken)
    assert X.cmd_story(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "story.json"))
    (run,) = doc["runs"]
    t = run["tally"]
    assert not run["pass"] and t["facts_found"] == 3 and t["facts_expected"] == 4 and t["hyps_unlisted"] == 1
    p = doc["summary"]["pooled"]
    assert p["facts"]["recall"]["share"] == 0.75 and p["hypotheses"]["precision"]["share"] == 0.5
    assert any("unlisted hypothesis" in l for l in run["fail_lines"]) and any("0 'created' fact edge" in l for l in run["fail_lines"])


def test_an_unresolved_run_counts_every_sheet_edge_as_missing(lab, tmp_path, monkeypatch):
    """Review 2026-10-30 (major 3): roles the checker cannot resolve gave 0/0 and vanished from the
    rates; now the sheet's own counts are the denominator and the views/trace count as not ok."""
    real = X.build_graph

    def nameless(db, **kw):
        G = real(db, **kw)
        for n, d in G.nodes(data=True):
            if d.get("kind") == "process":
                d["label"] = "renamed.exe"
        return G
    monkeypatch.setattr(X, "build_graph", nameless)
    assert X.cmd_story(lab) == 0
    doc = json.loads(read(tmp_path / "out" / "story.json"))
    (run,) = doc["runs"]
    assert not run["resolved"] and run["tally"]["facts_expected"] == 4 and run["tally"].get("facts_found", 0) == 0
    assert run["tally"]["hyps_expected"] == 1                       # the optional one is not counted
    p = doc["summary"]["pooled"]
    assert p["facts"]["recall"]["share"] == 0.0 and p["hypotheses"]["recall"]["share"] == 0.0
    assert p["gaps_ok"]["n"] == 1 and p["gaps_ok"]["k"] == 0 and p["trace_ok"]["n"] == 1 and p["trace_ok"]["k"] == 0
    assert abs(p["trace_ok"]["hi"] - 0.975) < 1e-6


def test_a_resolved_run_with_an_empty_fact_list_is_not_unresolved(lab, tmp_path, monkeypatch):
    """Review: `facts_expected in tally` would call a sheet with `facts: []` unresolved; the signal
    is now the checker's own check_facts having run."""
    truth = lab.select_runs()[0].truth
    truth["expected_graph"]["facts"] = []                     # the hypotheses stay, so the roles still resolve
    monkeypatch.setattr(X, "load_sheet", lambda path: truth)
    X.cmd_story(lab)
    (run,) = json.loads(read(tmp_path / "out" / "story.json"))["runs"]
    # (the T1 link is then found but not correct: its `via` process is no longer a role of this sheet)
    assert run["resolved"] and run["tally"].get("facts_expected", 0) == 0 and run["tally"]["hyps_expected"] == 1
    assert run["tally"]["facts_unexpected"] == 1              # the real `started` fact is now unlisted


def test_a_found_hypothesis_whose_trace_fails_is_not_correct(lab, tmp_path, monkeypatch):
    """Minor (review 2026-10-30): the checker counts a hypothesis as found before its method check and
    trace; the experiment calls it correct only when those passed too."""
    real = X.build_graph

    def bad_citation(db, **kw):
        G = real(db, **kw)
        for _, _, d in G.edges(data=True):
            if d.get("kind") == "content_from":
                d["evidence"] = [{"key": "no-such-event", "event": 0}]
        return G
    monkeypatch.setattr(X, "build_graph", bad_citation)
    X.cmd_story(lab)
    doc = json.loads(read(tmp_path / "out" / "story.json"))
    (run,) = doc["runs"]
    assert run["tally"]["hyps_found"] == 1 and run["tally"]["hyps_correct"] == 0 and not run["hypotheses"][0]["correct"]
    p = doc["summary"]["pooled"]["hypotheses"]
    assert p["found"] == 1 and p["correct"] == 0 and p["recall"]["share"] == 0.0 and p["precision"]["share"] == 0.0


def test_a_hypothesis_graded_as_a_fact_counts_against_both(lab, tmp_path, monkeypatch):
    real = X.build_graph

    def as_fact(db, **kw):
        G = real(db, **kw)
        for _, _, d in G.edges(data=True):
            if d.get("kind") == "content_from":
                d["grade"] = "fact"
        return G
    monkeypatch.setattr(X, "build_graph", as_fact)
    X.cmd_story(lab)
    t = json.loads(read(tmp_path / "out" / "story.json"))["runs"][0]["tally"]
    assert t["hyps_as_fact"] == 1 and t.get("hyps_found", 0) == 0 and t["facts_unexpected"] == 1


# -- 4. J4 on a tiny dev snapshot ----------------------------------------------------------------------------
def test_false_alerts_counts_raised_per_active_hour(tmp_path, monkeypatch):
    snap = laptop_db(tmp_path, after_cutoff=False)
    con = sqlite3.connect(snap)
    keys = [r[0] for r in con.execute("SELECT dedup_key FROM events WHERE event_id = 1 LIMIT 3")]
    con.close()
    alerts = [Alert("analystlab.x", "Our rule", "analystlab", "medium", "2026-10-17T18:00:00.000Z", "h", "why", (keys[0],)),
              Alert("r-low", "Low rule", "sigma", "low", "2026-10-17T18:00:00.000Z", "h", "why", (keys[1],)),
              Alert("beacon", "Rhythm", "beacon", "medium", "2026-10-17T19:00:00.000Z", "h", "why", (keys[2],))]
    st = AlertStore(str(tmp_path / "a.db"))
    st.write(alerts)
    st.close()
    lab = X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"))
    assert X.cmd_false_alerts(lab, snap, [str(tmp_path / "a.db")]) == 0
    doc = json.loads(read(tmp_path / "out" / "false-alerts.json"))
    assert doc["all"]["alerts"] == 3 and doc["raised"]["alerts"] == 2 and doc["all"]["active_hours"] > 0
    assert {r["source"] for r in doc["raised_rules"]} == {"analystlab", "beacon"}
    text = read(tmp_path / "results" / "false-alerts-practice.md")
    assert "per active hour" in text and "| low | 1 |" in text
    for private in ("Users\\u", "app.exe", "tool.exe", "example.com", "8.8.4.4"):
        assert private not in text, private
    # the official label refuses a dev snapshot, and the practice label a test one
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    with pytest.raises(ValueError):
        X.Lab("official", str(tmp_path), of="v1").laptop_db(snap)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    con = sqlite3.connect(snap)
    con.execute("INSERT INTO snapshot VALUES ('kind', 'test')")
    con.commit()
    con.close()
    with pytest.raises(ValueError):
        lab.laptop_db(snap)


# -- 5. J5a: the agreement rule on hand-made tables ------------------------------------------------------------
def test_a16_agreement_rule():
    cfg = C.load_config()
    res = {"T1": {"causes": 3, "bands": {"medium": {"causes": 3, "processes": 2, "predicted": 0.02, "control": 0.03, "rotate": 0.01, "real": 0.1,
                                                     "per_process": {"predicted_controlled": 0.02, "control": 0.03}},
                                         "low": {"causes": 1, "processes": 1, "predicted": 0.3, "control": 0.05, "rotate": 0.1, "real": 0.2,
                                                 "per_process": {"predicted_controlled": 0.3, "control": 0.05}}}, "graded_pairs": {}}}
    side = {"rows": {"T1": {"offsets": {"-12": {"bands": {"medium": {"processes": 40, "control_hits": 20, "decidable": True,
                                                                     "per_process": {"beta": 1.5, "beta_upper95": 2.4}}}},
                                        "+12": {"bands": {"medium": {"processes": 40, "control_hits": 20, "decidable": True,
                                                                     "per_process": {"beta": 2.0, "beta_upper95": 3.1}},
                                                          "pooled": {"processes": 5, "control_hits": 2, "decidable": False,
                                                                     "per_process": {"beta": 9.0, "beta_upper95": 30.0}}}}}}}}
    ag = X.a16_agreement(res, side, cfg)
    assert ag["a16"]["T1"]["medium"]["agrees"] is True and ag["a16"]["T1"]["low"]["agrees"] is False
    assert ag["a16"]["T1"]["medium"]["direction"] == "agrees" and ag["a16"]["T1"]["low"]["direction"] == "over-cautious"
    assert ag["sideband"]["T1"]["-12/medium"]["covered"] is True and ag["sideband"]["T1"]["+12/medium"]["covered"] is False
    assert ag["sideband"]["T1"]["+12/pooled"]["covered"] is None
    assert "does NOT cover" in ag["verdict"]
    side["rows"]["T1"]["offsets"]["+12"]["bands"]["medium"]["per_process"]["beta_upper95"] = 2.5
    assert "covers" in X.a16_agreement(res, side, cfg)["verdict"] and "NOT" not in X.a16_agreement(res, side, cfg)["verdict"]
    assert "not decidable" in X.a16_agreement(res, {"rows": {}}, cfg)["verdict"]


def test_a16_command_runs_on_a_tiny_snapshot(tmp_path, monkeypatch):
    snap = laptop_db(tmp_path, after_cutoff=False)
    pool_file(tmp_path)
    cfg = C.load_config()
    from dataclasses import replace
    monkeypatch.setattr(X.C, "load_config", lambda official=False: replace(cfg, pool_sha256=None))
    lab = X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"))
    assert X.cmd_a16(lab, snap, bootstrap=200) == 0
    doc = json.loads(read(tmp_path / "out" / "a16.json"))
    assert set(doc["a16"]) == {"T1", "T2", "T3"} and "verdict" in doc["agreement"]
    text = read(tmp_path / "results" / "a16-practice.md")
    assert "Verdict" in text and "sideband" in text
    for private in ("Users\\u", "app.exe", "example.com"):
        assert private not in text, private


# -- 6. J5b: calibration from a hand-made overlay document ---------------------------------------------------
def overlay_doc(official=False):
    cell = lambda vol, graft, exp, classes, obs, sp: {"volume": vol, "graft": graft, "expected_hypotheses": exp, "hypotheses_by_class": classes,
                                                     "cross": {"cross_t_observed": obs, "cross_t_sigma_p": sp}}
    return {"inputs": {"official": official, "runs": 1, "volumes": [0, 1], "seeds": [1]},
            "cells": [cell(0, True, [{"row": "T1", "band": "low"}], {"vm-background": {"T3": {"low": 4}}}, 0, 0.0),
                      cell(1, True, [{"row": "T1", "band": "low"}], {"cross/graft": {"T3": {"low": 11}}, "cross-r4": {"R4": {"medium": 1}},
                                                                     "overlay-internal": {"R3": {"high": 7}}}, 11, 10.0),
                      cell(1, False, [{"row": "T1", "band": "low"}], {"cross": {"T3": {"low": 99}}}, 99, 1.0)],
            "r4": {"per_volume": {"1": {"graphs": 1, "total": 1, "rate_per_graph": 1.0, "rate_ci95": [0.0, 5.6]}}}}


def test_calibration_counts_correct_false_and_unknown_per_band():
    cal = X.calibration_from(overlay_doc())
    low1 = cal["per_band"]["1x/low"]
    assert low1["correct"] == 1 and low1["false"] == 11 and low1["unknown"] == 0 and low1["judged"] == 12
    assert abs(low1["share_correct"]["share"] - 1 / 12) < 1e-9 and low1["by_row"] == {"T1": {"correct": 1, "false": 0}, "T3": {"correct": 0, "false": 11}}
    assert cal["per_band"]["1x/medium"] == {"volume": 1, "band": "medium", "correct": 0, "false": 1, "unknown": 0, "share_correct": None,
                                            "judged": 1, "by_row": {"R4": {"correct": 0, "false": 1}}}
    assert cal["per_band"]["1x/high"]["unknown"] == 7 and cal["per_band"]["0x/low"]["unknown"] == 4
    assert cal["independence"]["1"] == {"graphs": 1, "observed": 11, "sigma_p": 10.0, "ratio": 1.1}      # the no-graft cell is left out
    # scenario-story links beyond the sheet's expected ones are false (an unlisted link between role nodes)
    doc = overlay_doc()
    doc["cells"][1]["hypotheses_by_class"]["scenario-story"] = {"T1": {"low": 3}, "R4": {"low": 1}}
    low1 = X.calibration_from(doc)["per_band"]["1x/low"]
    assert low1["correct"] == 1 and low1["false"] == 11 + 2 + 1 and low1["by_row"]["T1"] == {"correct": 1, "false": 2}


def test_calibration_command_reads_the_labels_own_overlay_only(tmp_path, capsys):
    lab = X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"))
    assert X.cmd_calibration(lab) == 2
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "noise-overlay.json").write_text(json.dumps(overlay_doc(official=True)), encoding="utf-8")
    assert X.cmd_calibration(lab) == 2 and "official mode" in capsys.readouterr().out
    (tmp_path / "out" / "noise-overlay.json").write_text(json.dumps(overlay_doc()), encoding="utf-8")
    assert X.cmd_calibration(lab) == 0
    text = read(tmp_path / "results" / "calibration-practice.md")
    assert "| 1x | low | 1 | 11 | 8 % (1/12" in text and "not claimed (1 judged < 10)" in text and "| 1x | 1 | 11 | 10.000 | 1.10 |" in text


# -- 7. J6: official-mode gating of the overlay tools -------------------------------------------------------------
def test_overlay_gating_practice_vs_official(tmp_path, monkeypatch, capsys):
    write_recordings(tmp_path)
    laptop = laptop_db(tmp_path)
    run = __import__("check_scenario").find_run(str(tmp_path), "s1", run_id=RUN_ID)
    # a practice run: built outside official mode, refused inside it
    path, _ = noise_overlay.build_for_run(str(tmp_path), "s1", run, 0, 1, laptop=laptop)
    assert os.path.exists(path)
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    with pytest.raises(ValueError, match="practice run"):
        noise_overlay.build_for_run(str(tmp_path), "s1", run, 0, 1, laptop=laptop)
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    # an official run: refused outside official mode, built inside it once the frozen files verify
    official_series(tmp_path, [RUN_ID])
    with pytest.raises(ValueError, match="official series"):
        noise_overlay.build_for_run(str(tmp_path), "s1", run, 0, 1, laptop=laptop)
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(noise_overlay.config, "verify_official", lambda **kw: ["pool missing"])
    with pytest.raises(ValueError, match="official mode: pool missing"):
        noise_overlay.build_for_run(str(tmp_path), "s1", run, 0, 1, laptop=laptop)
    seen = {}
    monkeypatch.setattr(noise_overlay.config, "verify_official", lambda **kw: seen.update(kw) or [])
    path, meta = noise_overlay.build_for_run(str(tmp_path), "s1", run, 1, 2, laptop=laptop, pool="the-pool.json")
    assert meta["overlay_rows"] > 0 and seen == {"pool": "the-pool.json"}             # the caller's --pool is what is verified
    # plan_runs: official mode takes every official run, practice mode none of them; --until filters;
    # a scenario without a clean run raises, or with skip_missing is noted and left out
    assert [r["run_id"] for _, r in overlay_experiment.plan_runs(str(tmp_path), ["s1"], official=True)] == [RUN_ID]
    with pytest.raises(ValueError, match="no clean practice run"):
        overlay_experiment.plan_runs(str(tmp_path), ["s1"])
    skipped, notes = [], []
    plan = overlay_experiment.plan_runs(str(tmp_path), ["s3", "s1"], official=True, skip_missing=True, skipped=skipped, say=notes.append)
    assert [s for s, _ in plan] == ["s1"] and skipped == ["S3"] and any("skipped" in n for n in notes)
    (tmp_path / "series" / "official.json").unlink()
    assert [r["run_id"] for _, r in overlay_experiment.plan_runs(str(tmp_path), ["s1"])] == [RUN_ID]
    with pytest.raises(ValueError, match="no clean practice run"):
        overlay_experiment.plan_runs(str(tmp_path), ["s1"], until="2026-10-16")
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    # a practice run recorded after the first official series began is not dev data either
    official_series_doc(tmp_path, [], started=iso(-100))
    with pytest.raises(ValueError, match="inside an official series' period"):
        noise_overlay.build_for_run(str(tmp_path), "s1", run, 0, 1, laptop=laptop)
    with pytest.raises(ValueError, match="no clean practice run"):
        overlay_experiment.plan_runs(str(tmp_path), ["s1"])


def test_friends_are_numbered_in_the_report(tmp_path, monkeypatch):
    """Privacy (review 2026-10-30, major 7): the friend folder names never reach the markdown."""
    import friend_stats
    s = lambda h: {"days_recorded": 7, "active_hours": h, "events_per_active_hour": {"process starts": 10.0, "network connections": 5.0,
                                                                                        "DNS lookups": 1.0, "files created (watched kinds)": 2.0}}
    rows = [("zara-laptop", "2026-11-02", "p1", s(20.0), None), ("adam", "2026-11-03", "p2", s(30.0), None), ("adam", "2026-11-01", "p3", s(3.0), None)]
    monkeypatch.setattr(friend_stats, "collect", lambda paths, root, given=None: rows)
    monkeypatch.setattr(X.glob, "glob", lambda pattern: ["p1", "p2", "p3"])
    fr = X.friends_table(str(tmp_path))
    assert list(fr["friends"]) == ["friend 1", "friend 2"] and fr["folders"] == {"friend 1": "adam", "friend 2": "zara-laptop"}
    assert fr["friends"]["friend 1"]["active_hours"] == 30.0 and fr["files"] == 3 and fr["refused"] == 0
    # the official J4 report prints the numbers only (the mapping lives in the JSON)
    snap = laptop_db(tmp_path, after_cutoff=False)
    con = sqlite3.connect(snap)
    con.execute("UPDATE snapshot SET value = '2026-10-23' WHERE key = 'cutoff_day_utc'")
    con.execute("INSERT INTO snapshot VALUES ('kind', 'test')")
    con.execute("INSERT INTO snapshot VALUES ('from_day_utc', '2026-10-23')")
    con.execute("UPDATE events SET time = '2026-10-25' || substr(time, 11)")
    con.commit()
    con.close()
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: [])
    lab = X.Lab("official", str(tmp_path), of="v1", out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"))
    monkeypatch.setattr(X, "score_laptop", lambda lab, laptop, out, rescore=False: ([], "stubbed"))
    assert X.cmd_false_alerts(lab, snap) == 0
    text = read(tmp_path / "results" / "false-alerts-official-v1runs.md")
    assert "| friend 1 |" in text and "| friend 2 |" in text and "adam" not in text and "zara" not in text
    assert json.loads(read(tmp_path / "out" / "false-alerts.json"))["friends"]["folders"]["friend 1"] == "adam"


def test_overlay_command_passes_the_labels_outputs(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(X.overlay_experiment, "main", lambda argv: seen.setdefault("argv", argv) and 0)
    lab = X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "out"), results_dir=str(tmp_path / "results"), until="2026-10-24")
    assert X.cmd_overlay(lab, ["s1:1"], [0, 1], [1], 2) == 0
    argv = seen["argv"]
    assert argv[argv.index("--out-json") + 1] == X.overlay_json(lab) and "--until" in argv and argv[argv.index("--runs") + 1] == "s1:1"
    assert argv[argv.index("--volumes"):argv.index("--volumes") + 3] == ["--volumes", "0", "1"] and argv[argv.index("--r4-seeds") + 1] == "2"


# -- 8. J7: the measurement on a tiny run ----------------------------------------------------------------------------
def test_performance_measures_replay_score_and_graph(lab, tmp_path):
    assert X.cmd_performance(lab, skip_big=True) == 0
    doc = json.loads(read(tmp_path / "out" / "performance.json"))
    (r,) = doc["runs"]
    assert r["events"] == 11 and r["replay_events_per_second"] > 0 and r["score_events_per_second"] > 0    # S1 story + 4 background rows
    assert r["load_events_per_second"] > 0
    assert r["graph_status"] == "ok" and r["graph"]["nodes"] > 0 and doc["big"] is None
    assert "events/s" in read(tmp_path / "results" / "performance-practice.md")


def test_performance_names_a_given_file_by_what_it_is(lab, tmp_path):
    vm_day = str(tmp_path / "vm" / "2026-10-17.jsonl")
    assert X.cmd_performance(lab, big=vm_day) == 0
    doc = json.loads(read(tmp_path / "out" / "performance.json"))
    assert doc["big"]["what"] == "recording given with --big (laptop day 2026-10-17)" and doc["big"]["largest_of_label"] is False
    assert "largest" not in read(tmp_path / "results" / "performance-practice.md")


def test_timed_graph_reports_a_timeout_instead_of_hanging(monkeypatch):
    import time as _t
    monkeypatch.setattr(X, "build_graph", lambda db, **kw: _t.sleep(2))
    g, took, status = X.timed_graph("nowhere.db", None, cap_seconds=0.05)
    assert g is None and status == "not finished within the cap" and took < 1.5


# -- 9. the laptop TEST snapshot builder ---------------------------------------------------------------------------
def test_test_snapshot_keeps_only_days_after_the_cutoff(tmp_path, monkeypatch):
    host = tmp_path / "host"
    write_day(str(host), "2026-10-22", [day_rec(1, "2026-10-22T10:00:00Z"), day_rec(2, "2026-10-22T23:59:59Z")])   # dev day
    write_day(str(host), "2026-10-23", [day_rec(3, "2026-10-23T00:00:05Z"), day_rec(4, "2026-10-23T10:00:00Z")])
    write_day(str(host), "2026-10-24", [day_rec(5, "2026-10-24T10:00:00Z"), day_rec(6, "2026-10-25T00:00:01Z")])   # spills over
    write_day(str(host), "2026-10-25", [day_rec(7, "2026-10-25T10:00:00Z")])
    files = build_test_snapshot.day_files_between(str(host), "2026-10-23", "2026-10-24")
    assert [os.path.basename(f) for f in files] == ["2026-10-23.jsonl", "2026-10-24.jsonl"]
    db = str(tmp_path / "test-laptop.db")
    info = build_test_snapshot.build(db, files + [str(host / "2026-10-22.jsonl")], "2026-10-23", "2026-10-24", retag=False)
    assert info["events"] == "3" and info["from_day_utc"] == "2026-10-23"                 # 3, 4, 5 only
    con = sqlite3.connect(f"file:{db.replace(os.sep, '/')}?mode=ro", uri=True)
    meta = dict(con.execute("SELECT key, value FROM snapshot"))
    assert meta["kind"] == "test" and meta["from_day_utc"] == "2026-10-23" and meta["cutoff_day_utc"] == "2026-10-24"
    assert con.execute("SELECT MIN(time), MAX(time) FROM events").fetchone() == ("2026-10-23T00:00:05Z", "2026-10-24T10:00:00Z")
    con.close()
    # the official label accepts it, the practice label refuses it
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    assert X.Lab("official", str(tmp_path), of="v1").laptop_db(db) == db
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    with pytest.raises(ValueError, match="practice mode reads the DEV snapshot"):
        X.Lab("practice", str(tmp_path)).laptop_db(db)
    with pytest.raises(ValueError):
        build_test_snapshot.build(db, files, "2026-10-25", "2026-10-24", retag=False)
    os.chmod(db, 0o666)


def test_test_snapshot_cli_refuses_dev_days_and_worktrees(tmp_path, monkeypatch, capsys):
    assert build_test_snapshot.main(["--from", "2026-10-22", "--recordings", str(tmp_path)]) == 2
    assert "not after the frozen dev cutoff" in capsys.readouterr().out
    assert build_test_snapshot.main(["--from", "2026-10-25", "--to", "2026-10-24", "--recordings", str(tmp_path)]) == 2
    fake = tmp_path / "wt"
    fake.mkdir()
    (fake / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    monkeypatch.setattr(build_test_snapshot, "PROJECT_ROOT", str(fake))
    assert build_test_snapshot.main(["--recordings", str(tmp_path)]) == 2
    assert "main project folder" in capsys.readouterr().out
    assert build_test_snapshot.main(["--info", "--recordings", str(tmp_path)]) == 0


# -- 10. the whole driver on the hand-made run ------------------------------------------------------------------------
def test_main_runs_every_dev_question_it_can(tmp_path, monkeypatch, capsys):
    write_recordings(tmp_path)
    monkeypatch.setattr(X.Lab, "rules", lambda self: [])
    monkeypatch.setattr(X.Lab, "baseline", lambda self: None)
    out, res = str(tmp_path / "out"), str(tmp_path / "results")
    base = ["--label", "practice", "--recordings", str(tmp_path), "--out-dir", out, "--results-dir", res]
    assert X.main(["detection"] + base) == 0 and X.main(["story"] + base) == 0
    assert X.main(["performance", "--skip-big"] + base) == 0
    assert X.main(["blind"] + base) == 2                       # blind scenarios are test data
    assert X.main(["calibration"] + base) == 2                 # no overlay results yet
    assert sorted(os.listdir(res)) == ["detection-practice.md", "performance-practice.md", "story-practice.md"]
    assert EventStore.dedup_key(good_run()[0]) and FETCH and PAYLOAD and BASE and ev      # fixture imports stay used


# -- version 2 (engine/evaluation.py): v1's official runs and results are never mixed in or overwritten ------------
def series_doc(tmp_path, name, entries, started, finished=None, freeze=None):
    (tmp_path / "series").mkdir(exist_ok=True)
    doc = {"label": "official", "series": name, "started": started, "runs": entries}
    if finished:
        doc["finished"] = finished
    if freeze:
        doc["freeze"] = freeze
    (tmp_path / "series" / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_v1_and_v2_official_runs_are_never_pooled(tmp_path, monkeypatch):
    v1 = run_record(run_id="20261101-010000-v1aa", start=iso(3600), end=iso(3620), time=iso(3600))
    v2 = run_record(run_id="20261101-030000-v2aa", start=iso(10800), end=iso(10820), time=iso(10800), scenario="S6")
    between = run_record(run_id="20261101-020000-devv", start=iso(7200), end=iso(7220), time=iso(7200))
    write_recordings(tmp_path, runs=[run_record(), v1, between, v2])
    series_doc(tmp_path, "v1", [{"n": 1, "scenario": "S1", "run_id": v1["run_id"], "exit_code": 0}], iso(3500), finished=iso(3700))
    series_doc(tmp_path, "v2", [{"n": 1, "scenario": "S6", "run_id": v2["run_id"], "exit_code": 0}], iso(10700), freeze="freeze-v2")
    assert [s["version"] for s in noise_overlay.official_series(str(tmp_path))] == ["v1", "v2"]
    assert noise_overlay.official_run_ids(str(tmp_path), "v1") == {v1["run_id"]}
    assert noise_overlay.official_run_ids(str(tmp_path), "v2") == {v2["run_id"]}
    # practice = outside every official period: the dev run between v1's runs and v2's freeze counts
    assert [it.run_id for it in X.Lab("practice", str(tmp_path)).select_runs()] == [RUN_ID, between["run_id"]]
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    off2 = X.Lab("official", str(tmp_path), of="v2")                        # v2's runs (v3: an earlier evaluation)
    assert off2.of == "v2" and [it.run_id for it in off2.select_runs()] == [v2["run_id"]]
    off1 = X.Lab("official", str(tmp_path), of="v1")                      # the regression: v1's runs, v2's code
    assert [it.run_id for it in off1.select_runs()] == [v1["run_id"]]
    # a series with an unknown freeze tag is an error, never "some version"
    series_doc(tmp_path, "odd", [], iso(20000), freeze="freeze-v9")
    with pytest.raises(ValueError, match="unknown freeze tag"):
        off2.select_runs()


def test_v2_never_writes_v1s_result_files(tmp_path):
    lab = X.Lab("practice", str(tmp_path))
    assert os.path.normpath(lab.results_dir) == os.path.join(PROJECT_ROOT, "docs", "results", X.evaluation.CURRENT)
    assert os.path.normpath(lab.out_dir) == os.path.join(PROJECT_ROOT, "recordings", "experiments", X.evaluation.CURRENT, "practice")
    for of, name in ((X.evaluation.CURRENT, "detection-official.md"), ("v1", "detection-official-v1runs.md")):
        off = X.Lab("official", str(tmp_path), of=of, out_dir=str(tmp_path / of), results_dir=str(tmp_path / "res"))
        js, md = off.write("detection", {}, ["x"])
        assert os.path.basename(md) == name and not os.path.basename(md).startswith("j2-")
    assert f"re-scored with {X.evaluation.CURRENT}'s code" in X.Lab("official", str(tmp_path), of="v1").header("t", "w")[0]
    with pytest.raises(ValueError, match="official mode only"):
        X.Lab("practice", str(tmp_path), of="v1")


def test_v2_official_mode_runs_only_its_pre_registered_questions(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: [])
    for q in ("a16", "overlay", "calibration", "performance"):
        assert X.main([q, "--label", "official", "--recordings", str(tmp_path)]) == 2
        assert "v1 result" in capsys.readouterr().out


def test_v2_laptop_test_days_are_exactly_the_frozen_days(tmp_path, monkeypatch):
    snap = tmp_path / "scratch" / "test" / "test-laptop-v2.db"
    snap.parent.mkdir(parents=True)
    con = sqlite3.connect(snap)
    con.execute("CREATE TABLE snapshot (key TEXT, value TEXT)")
    con.executemany("INSERT INTO snapshot VALUES (?, ?)", [("kind", "test"), ("from_day_utc", "2026-11-14"), ("cutoff_day_utc", "2026-11-20")])
    con.execute("CREATE TABLE events (time TEXT)")
    con.commit()
    con.close()
    real = X.config.load()
    lab = X.Lab("official", str(tmp_path), of="v2")

    def days(a, b):
        monkeypatch.setattr(X.config, "load", lambda *x, **k: dict(real, data=dict(real["data"], v2_test_from_day_utc=a, v2_test_to_day_utc=b)))
    days(None, None)
    with pytest.raises(ValueError, match="not chosen"):
        lab.laptop_db()
    for a, b in (("2026-11-13", "2026-11-20"), ("2026-11-14", "2026-11-21"), ("2026-11-15", "2026-11-20")):
        days(a, b)                                    # an earlier or later start, a longer end: all refused
        with pytest.raises(ValueError, match="exactly the frozen"):
            lab.laptop_db()
    days("2026-11-14", "2026-11-20")
    assert lab.laptop_db() == str(snap)


def test_official_code_gate_and_output_folders(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    monkeypatch.setattr(X.config, "verify_official", lambda **kw: [])
    monkeypatch.setattr(X.evaluation, "code_problems", lambda tag=None, root=None: ["the git tag freeze-v2 does not exist yet"])
    assert X.Lab("official", str(tmp_path), of="v1").problems() == ["official mode: the git tag freeze-v2 does not exist yet"]
    monkeypatch.setattr(X.evaluation, "code_problems", lambda tag=None, root=None: [])
    monkeypatch.setattr(X, "PROJECT_ROOT", str(tmp_path))  # even if the refusal broke, nothing reaches the real docs/
    for opt in ("--out-dir", "--results-dir"):            # v1's official JSON could otherwise be overwritten
        assert X.main(["detection", "--label", "official", "--of", "v1", "--recordings", str(tmp_path), opt, str(tmp_path / "x")]) == 2
        assert "--out-dir and --results-dir are refused" in capsys.readouterr().out
    js, _ = X.Lab("practice", str(tmp_path), out_dir=str(tmp_path / "o"), results_dir=str(tmp_path / "r")).write("d", {}, ["x"])
    doc = json.load(open(js, encoding="utf-8"))
    assert doc["of"] == X.evaluation.CURRENT and doc["code"]["frozen"] is True


def test_a_v2_run_whose_vm_step_failed_after_the_program_ran_is_listed_not_scored(tmp_path, monkeypatch):
    ran = run_record(run_id="20261114-010000-ran1", start=iso(3600), end=iso(3620), time=iso(3600), scenario="S6")
    ok = run_record(run_id="20261114-020000-ok01", start=iso(7200), end=iso(7220), time=iso(7200), scenario="S6")
    write_recordings(tmp_path, runs=[ran, ok])
    series_doc(tmp_path, "v2", [{"n": 1, "scenario": "S6", "run_id": ran["run_id"], "exit_code": 3, "result": "VM STEP FAILED"},
                                {"n": 2, "scenario": "S6", "run_id": None, "exit_code": 2, "result": "NOT STARTED"},
                                {"n": 3, "scenario": "S6", "run_id": ok["run_id"], "exit_code": 0, "result": "PASS"}],
               iso(3500), finished=iso(8000), freeze="freeze-v2")
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    items = X.Lab("official", str(tmp_path), of="v2").select_runs()
    assert [it.status.split(" (")[0] for it in items] == ["VM step failed after the program ran", "could not run", "ok"]


def test_practice_boundary_edges(tmp_path):
    """Open-ended (crashed) series, an unreadable start, and runs exactly at a period's edges."""
    def run(sec, rid):
        return {"run_id": rid, "start": iso(sec)}
    series_doc(tmp_path, "done", [], iso(1000), finished=iso(2000))
    assert not noise_overlay.is_practice_run(str(tmp_path), run(1000, "a"))       # at the start: inside
    assert not noise_overlay.is_practice_run(str(tmp_path), run(2000, "b"))       # at the end: inside
    assert noise_overlay.is_practice_run(str(tmp_path), run(2001, "c"))
    series_doc(tmp_path, "crashed", [], iso(5000))                                 # never finished: open-ended
    assert not noise_overlay.is_practice_run(str(tmp_path), run(99999, "d"))
    assert noise_overlay.is_practice_run(str(tmp_path), run(3000, "e"))
    series_doc(tmp_path, "odd", [], "not a time", finished=iso(10))               # unreadable start: from the beginning
    assert not noise_overlay.is_practice_run(str(tmp_path), run(3000, "f"))


def test_practice_blind_is_only_the_dummy(tmp_path):
    lab = X.Lab("practice", str(tmp_path))
    with pytest.raises(ValueError, match="dummy B9"):
        lab.select_runs(blind=True)
    with pytest.raises(ValueError, match="dummy B9"):
        lab.select_runs(["b3"], blind=True)
    write_recordings(tmp_path)
    assert lab.select_runs(["b9"], blind=True) == []

def test_round_two_step_counts_are_summarised():
    def row(verdict, suspicious, flagged, prog=(), unrec=(), other=0):
        return {"scenario": "B9", "run_id": "r", "records": 1, "expected": 0, "found": 0, "missed": [], "verdict": verdict,
                "time_to_detect": [], "other_alerts": 0, "other_by_rule": {},
                "steps": {"anchored": True, "suspicious": list(suspicious), "flagged": list(flagged),
                          "flagged_by_program_only": list(prog), "unrecorded": list(unrec), "alerts_on_other_steps": other}}
    rows = [row("DETECTED", [3, 4], [3, 4]), row("MISSED", [3, 4], [4], prog=[3], other=2), row("CLEAN", [], []), row("FALSE ALARM", [], [])]
    s = X.summarize_detection(rows)["per_scenario"]["B9"]["steps"]
    assert (s["suspicious_steps"], s["flagged"], s["flagged_by_program_only"], s["alerts_on_other_steps"]) == (4, 3, 1, 2)
    assert (s["innocent_runs"], s["clean"], s["false_alarm"]) == (2, 1, 1) and s["step_rate"]["share"] == 0.75
    md = "\n".join(X.detection_markdown(X.Lab("practice", "."), [], rows, X.summarize_detection(rows)))
    assert "Blind round 2: suspicious steps" in md and "| B9 | 4 | 75 %" in md and "| 1 / 1 |" in md

def test_a_run_official_by_its_own_summary_follows_the_exit_rule(tmp_path, monkeypatch):
    run = run_record(run_id="20261114-030000-solo", start=iso(3600), end=iso(3620), time=iso(3600), scenario="B3")
    write_recordings(tmp_path, runs=[run])
    (tmp_path / "scenario_runs").mkdir()
    (tmp_path / "scenario_runs" / f"{run['run_id']}.json").write_text(
        json.dumps({"run_id": run["run_id"], "label": "official", "freeze": "freeze-v2", "exit_code": 3}), encoding="utf-8")
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    items = X.Lab("official", str(tmp_path), of="v2").select_runs(blind=True)
    assert [it.status.split(" (")[0] for it in items] == ["VM step failed after the program ran"]

def test_test_snapshot_never_overwrites_and_takes_a_name(tmp_path, capsys, monkeypatch):
    """v1's test week (test-laptop.db) is a frozen input of the v2 regression: building v2's days must
    never replace it (pre-registration review 2026-11-13)."""
    monkeypatch.setattr(build_test_snapshot, "PROJECT_ROOT", str(tmp_path))   # the worktree refusal is tested apart
    test_dir = tmp_path / "scratch" / "test"
    test_dir.mkdir(parents=True)
    (test_dir / "test-laptop.db").write_bytes(b"v1")
    assert build_test_snapshot.main(["--from", "2026-11-14", "--to", "2026-11-20", "--recordings", str(tmp_path)]) == 2
    assert "never overwritten" in capsys.readouterr().out and (test_dir / "test-laptop.db").read_bytes() == b"v1"
    assert build_test_snapshot.main(["--from", "2026-11-14", "--to", "2026-11-20", "--name", "..\\x.db", "--recordings", str(tmp_path)]) == 2
    assert "plain file name" in capsys.readouterr().out
    # a new name goes on to the next check (no day files here), never touching v1's file
    assert build_test_snapshot.main(["--from", "2026-11-14", "--to", "2026-11-20", "--name", "test-laptop-v2.db",
                                     "--recordings", str(tmp_path)]) == 2
    assert "no laptop recording days" in capsys.readouterr().out and (test_dir / "test-laptop.db").read_bytes() == b"v1"