"""Lab "What to do next" (engine/labs/respond.py, _d3fend.py): only MITRE's published steps, with their links.
Fixtures only: the made-up ATT&CK bundle of test_techniques and a two-file made-up D3FEND release."""

import json

import pytest

from engine.alerts import Alert
from engine.labs import _d3fend, respond as next_lab
from tests.labs.test_techniques import RULES, attack  # noqa: F401  (the `attack` fixture)

HEAD = ("query_def_tech_label,top_def_tech_label,def_tactic_label,def_tactic_rel_label,def_tech_label,def_artifact_rel_label,"
        "def_artifact_label,off_artifact_label,off_artifact_rel_label,off_tech_label,off_tech_id")


@pytest.fixture
def d3(tmp_path):
    (tmp_path / "d3fend.csv").write_text(
        "ID,D3FEND Tactic,D3FEND Technique,D3FEND Technique Level 0,D3FEND Technique Level 1,Definition\n"
        "D3-EAL,Isolate,,Executable Allowlisting,,\"Only allow listed programs to run.\"\n"
        "D3-PSA,Detect,,,Process Spawn Analysis,\"Analyzing spawn events.\"\n"
        "D3-PT,Evict,,Process Termination,,\"Terminating a running process.\"\n", encoding="utf-8")
    rows = [
        "Executable Allowlisting,Execution Isolation,Isolate,enables,Executable Allowlisting,blocks,Executable File,Executable Script,executes,PowerShell,T1059.001",
        "Process Spawn Analysis,Process Analysis,Detect,enables,Process Spawn Analysis,analyzes,Process,Process,creates,PowerShell,T1059.001",
        "Process Spawn Analysis,Process Analysis,Detect,enables,Process Spawn Analysis,analyzes,Process,Process,creates,Interpreter,T1059",
        "Process Termination,Process Eviction,Evict,enables,Process Termination,terminates,Process,Process,creates,Time checks,T1497",
        # D3FEND's query column names a broader technique than the one with the link: never listed itself
        "Process Eviction,Process Eviction,Evict,enables,Process Termination,terminates,Process,Process,creates,Time checks,T1497",
    ]
    (tmp_path / "d3fend-full-mappings.csv").write_text(HEAD + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(json.dumps({"version": "9.9.9"}), encoding="utf-8")
    return _d3fend.load(str(tmp_path))


def alert(rule_id):
    return Alert(rule_id, "a", "sigma", "high", "2026-10-22T10:00:00.000Z", "h1", "r", ("k1",))


def test_steps_are_mitres_mitigations_and_d3fend_defences_with_their_links(attack, d3):  # noqa: F811
    s = next_lab.steps(alert("r-ps"), attack, d3, {r["id"]: r for r in RULES})
    assert [t["id"] for t in s] == ["T1059.001"]
    t = s[0]
    assert t["name"] == "Command and Scripting Interpreter: PowerShell"
    assert t["mitigations"] == [{"id": "M1038", "name": "Execution Prevention", "url": "https://attack.mitre.org/mitigations/M1038",
                                 "how": "Use application control to block PowerShell where it is not needed.",
                                 "description": "Block execution."}]
    d = t["d3fend"]
    assert d["via"] == "T1059.001" and d["count"] == 2
    assert [g["tactic"] for g in d["tactics"]] == ["Isolate", "Detect"]          # D3FEND's order: acting first
    eal = d["tactics"][0]["techniques"][0]
    assert (eal["id"], eal["definition"]) == ("D3-EAL", "Only allow listed programs to run.")
    assert eal["links"] == [{"defence": "Executable Allowlisting", "defence_rel": "blocks", "artifact": "Executable File",
                             "attack_rel": "executes", "attack_artifact": "Executable Script"}]


def test_a_sub_technique_without_mappings_falls_back_to_its_parent_and_says_so(attack, d3):  # noqa: F811
    d = d3.for_technique("T1497.003")
    assert d["via"] == "T1497" and d["tactics"][0]["tactic"] == "Evict"
    assert [x["name"] for x in d["tactics"][0]["techniques"]] == ["Process Termination"]    # not "Process Eviction"
    assert all(l["defence"] == "Process Termination" for l in d["tactics"][0]["techniques"][0]["links"])
    assert d3.for_technique("T4242")["count"] == 0


def test_no_tags_no_steps(attack, d3):  # noqa: F811
    assert next_lab.steps(alert("analystlab.file_churn"), attack, d3, {r["id"]: r for r in RULES}) == []


def test_revoked_tag_is_followed(attack, d3):  # noqa: F811
    assert [t["id"] for t in next_lab.steps(alert("r-old"), attack, d3, {r["id"]: r for r in RULES})] == ["T1059.001"]


def test_missing_d3fend_data_is_none(tmp_path):
    assert _d3fend.load(str(tmp_path)) is None
