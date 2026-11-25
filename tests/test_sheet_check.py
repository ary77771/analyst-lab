"""tools/sheet_check.py: an answer sheet's layout against what the checkers read. Golden: every one of
our own sheets passes, and the two J3 writer sheets (docs/results/blind/b*.original.yaml) fail on
exactly what made them unreadable (windows_programs as a mapping; roles the graph checker can't
find). Plus one case per rule, and run_blind's --check-sheet (writer-only, dry run only)."""

import copy
import glob
import os
import sys

import pytest
import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import run_blind  # noqa: E402
import sheet_check  # noqa: E402
from tests.test_run_blind import lab, make_blind  # noqa: E402,F401  (lab is a fixture)

OURS = sorted(glob.glob(os.path.join(PROJECT_ROOT, "scenarios", "*", "ground_truth.yaml")))
J3 = os.path.join(PROJECT_ROOT, "docs", "results", "blind")

GOOD = {
    "scenario": "B3", "title": "t", "runs_in": "vm",
    "programs": {"main": "b3_main.exe", "shell": "cmd.exe"},
    "windows_programs": ["shell"],
    "file_groups": {"notes": {"path_contains": "\\AnalystLab\\scenarios\\b3\\work\\", "suffix": ".txt", "count": 3}},
    "steps": [
        {"id": 1, "what": "main starts", "evidence": {"sysmon_event": 1, "Image_endswith": "b3_main.exe"}},
        {"id": 2, "what": "three notes", "evidence": {"sysmon_event": 11, "Image_endswith": "b3_main.exe",
                                                      "TargetFilename_suffix": ".txt", "count": 3,
                                                      "within_seconds": 5}},
        {"id": 3, "what": "check-ins", "evidence": {"sysmon_event": 3, "Image_endswith": "b3_main.exe",
                                                    "count": 4, "interval_seconds": {"min": 5, "max": 15},
                                                    "seconds_after": {"step": 1, "min": 0, "max": 60}}},
        {"id": 4, "what": "main starts cmd", "evidence": {"sysmon_event": 1, "Image_endswith": "cmd.exe",
                                                          "ParentImage_endswith": "b3_main.exe"}},
    ],
    "not_expected": [{"sysmon_event": 22, "why": "no names looked up"}],
    "expected_graph": {
        "facts": [{"from": "main", "edge": "connected_to", "to": "test_server", "says": "x", "count": 4},
                  {"from": "main", "edge": "created", "to": "notes", "says": "x", "count": 3},
                  {"from": "main", "edge": "started", "to": "shell", "says": "x"}],
        "hypotheses": [{"claim": "c", "between": ["test_server", "notes"], "kind": "content_from", "optional": True}],
        "gaps": [],
    },
    "alert_expected": {"suspicious_steps": [3, 4], "why": "regular check-ins, then a shell"},
}


def problems(sheet, expect_id=None):
    return sheet_check.check_sheet(sheet, expect_id)[0]


@pytest.mark.parametrize("path", OURS, ids=[os.path.basename(os.path.dirname(p)) for p in OURS])
def test_every_one_of_our_sheets_passes(path):
    probs, warns, err = sheet_check.check_file(path)
    assert err is None and probs == [] and warns == []


@pytest.mark.parametrize("name", ["b1", "b2"])
def test_the_j3_writer_sheets_fail_on_what_broke_them(name):
    probs, _, err = sheet_check.check_file(os.path.join(J3, f"{name}.original.yaml"))
    assert err is None
    text = "\n".join(probs)
    assert "windows_programs: must be a LIST" in text                 # the KeyError in check_scenario
    assert "is not a role the checker can find" in text               # "role ... not defined" in the graph checker
    assert "alert_expected: required for a blind scenario" in text    # NONE EXPECTED 10/10


def test_the_writers_template_passes_once_its_id_is_filled_in():
    with open(os.path.join(PROJECT_ROOT, "docs", "blind", "template_ground_truth.yaml"), encoding="utf-8") as f:
        t = yaml.safe_load(f)
    assert "scenario must be" not in "".join(problems(t))     # Bx is refused, so the writer must change it
    t["scenario"] = "B3"
    assert problems(t, "B3") == []


def test_a_complete_blind_sheet_passes():
    assert problems(GOOD, "b3") == []


def test_the_good_sheet_really_is_read_by_the_checkers():
    """Not just our idea of the layout: the graph checker resolves every role of GOOD."""
    from check_graph_scenario import GraphCheck
    import networkx as nx
    G = nx.MultiDiGraph()
    G.add_node("p", kind="process", label="b3_main.exe", start_recorded=True, start=5)
    G.add_node("c", kind="process", label="cmd.exe", start_recorded=True, start=6)
    G.add_edge("p", "c", kind="started", grade="fact")
    G.add_node("e", kind="endpoint")
    G = nx.relabel_nodes(G, {"e": "net:vm:10.0.2.2:18765"})
    for i in range(3):
        G.add_node(f"f{i}", kind="file", path=f"C:\\AnalystLab\\scenarios\\b3\\work\\{i}.txt")
        G.add_edge("p", f"f{i}", kind="created", grade="fact", time=7)
    gc = GraphCheck(GOOD, G, 0, 100, ("10.0.2.2", 18765), say=lambda *_: None,
                    cfg={"before": 0, "after": 10, "band_medium": 0.1, "span": 60})
    assert gc.resolve()


def mutate(path, value):
    s = copy.deepcopy(GOOD)
    *head, last = path
    d = s
    for k in head:
        d = d[k]
    if value is KeyError:
        del d[last]
    else:
        d[last] = value
    return s


@pytest.mark.parametrize("path,value,expect", [
    (["windows_programs"], {"shell": "cmd.exe"}, "windows_programs"),
    (["programs", "main"], "C:\\x\\b3_main.exe", "without a folder"),
    (["steps", 0, "evidence"], {"Image_endswith": "b3_main.exe"}, "exactly one of sysmon_event or agent_type"),
    (["steps", 0, "evidence", "sysmon_event"], 99, "sysmon_event must be one of"),
    (["steps", 1, "evidence", "count"], 0, "count must be"),
    (["steps", 2, "evidence", "seconds_after", "step"], 9, "EARLIER step"),
    (["steps", 2, "evidence", "interval_seconds"], {"min": 9, "max": 1}, "interval_seconds"),
    (["steps", 0, "evidence", "count"], 1, None),
    (["steps", 0, "when"], "now", "unknown key 'when'"),
    (["not_expected", 0, "Image_endswith"], "b3_main.exe", "unknown key 'Image_endswith'"),
    (["expected_graph", "facts", 0, "edge"], "talked_to", "edge must be one of"),
    (["expected_graph", "facts", 0, "to"], "server", "not a role the checker can find"),
    (["expected_graph", "facts", 1, "to"], "main_file", "not a role the checker can find"),
    (["expected_graph", "hypotheses", 0, "kind"], "guess", "kind must be one of"),
    (["expected_graph", "gaps"], [{"node": "main", "kind": "lost"}], "kind must be one of"),
    (["alert_expected", "suspicious_steps"], [7], "suspicious_steps"),
    (["alert_expected", "check"], [{"rule_id": "x", "level": "medium", "involves": "main"}], "does not know the lab's rules"),
    (["alert_expected"], KeyError, "required for a blind scenario"),
    (["scenario"], "B4", "scenario.json says B3"),
])
def test_one_broken_rule_each(path, value, expect):
    got = "\n".join(problems(mutate(path, value), "B3"))
    if expect is None:
        assert got == ""
    else:
        assert expect in got


def test_an_empty_suspicious_list_is_allowed_for_an_innocent_scenario():
    assert problems(mutate(["alert_expected", "suspicious_steps"], []), "B3") == []


def test_main_file_role_needs_payload_path_contains():
    s = mutate(["expected_graph", "facts", 1, "to"], "main_file")
    s["payload_path_contains"] = "\\AnalystLab\\scenarios\\b3\\"
    assert problems(s, "B3") == []


def test_unknown_top_level_key_is_a_note_not_a_problem():
    probs, warns = sheet_check.check_sheet(mutate(["listener"], {"ip": "127.0.0.1", "port": 1}), "B3")
    assert probs == [] and any("listener" in w for w in warns)


def test_unreadable_yaml(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("steps: [\n", encoding="utf-8")
    assert sheet_check.main([str(p)]) == 2


# run_blind --check-sheet --------------------------------------------------------------------------

def test_check_sheet_needs_dry_run(lab, monkeypatch, capsys):
    folder, _, _ = make_blind(lab["tmp"])
    monkeypatch.setattr(run_blind, "BlindRunner", lambda *a, **k: pytest.fail("must not run"))
    assert run_blind.main([str(folder), "--check-sheet"]) == 2
    assert "only goes with --dry-run" in capsys.readouterr().out


def test_check_sheet_reports_a_bad_sheet(lab, monkeypatch, capsys):
    folder, _, _ = make_blind(lab["tmp"])                  # its sheet has no steps, graph or alert list
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    assert run_blind.main([str(folder), "--dry-run", "--check-sheet"]) == 2
    assert "NOT READABLE BY THE CHECKERS" in capsys.readouterr().out


def test_check_sheet_passes_a_good_sheet(lab, monkeypatch, capsys):
    folder, _, _ = make_blind(lab["tmp"], sid="B3", out="C:\\AnalystLab\\scenarios\\b3\\work")
    (folder / "ground_truth.yaml").write_text(yaml.safe_dump(GOOD), encoding="utf-8")
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    assert run_blind.main([str(folder), "--dry-run", "--check-sheet"]) == 0
    assert "Answer sheet layout: OK" in capsys.readouterr().out


def test_plain_dry_run_never_opens_the_sheet(lab, monkeypatch):
    folder, _, _ = make_blind(lab["tmp"])
    monkeypatch.setattr(run_blind, "STAGE_ROOT", str(lab["stage"]))
    monkeypatch.setattr(sheet_check, "check_file", lambda *a, **k: pytest.fail("sheet opened"))
    assert run_blind.main([str(folder), "--dry-run"]) == 0
