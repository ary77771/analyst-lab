"""Lab "ATT&CK map" (engine/labs/techniques.py, _attack.py, _rule_tags.py) and the Labs routes of the
night-explain labs through the real dashboard app. Fixtures only: a tiny made-up STIX bundle, made-up rules."""

import json

import pytest
from fastapi.testclient import TestClient

from engine.alerts import Alert
from engine.labs import _attack, _rule_tags, techniques


def ap(stix, tid, name, tactics, sub=False, revoked=False, deprecated=False):
    return {"type": "attack-pattern", "id": stix, "name": name, "x_mitre_is_subtechnique": sub, "revoked": revoked,
            "x_mitre_deprecated": deprecated, "description": f"{name} text (Citation: Someone 2020) with [a link](https://x.invalid).",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/techniques/{tid}"}],
            "x_mitre_platforms": ["Windows"]}


def bundle():
    tac = lambda stix, short, tid, name: {"type": "x-mitre-tactic", "id": stix, "x_mitre_shortname": short, "name": name,
                                          "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}
    return {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "id": "c", "x_mitre_version": "99.0"},
        {"type": "x-mitre-matrix", "id": "m", "tactic_refs": ["tac-ex", "tac-st"]},
        tac("tac-ex", "execution", "TA0002", "Execution"), tac("tac-st", "stealth", "TA0005", "Stealth"),
        ap("ap-1", "T1059", "Command and Scripting Interpreter", ["execution"]),
        ap("ap-2", "T1059.001", "PowerShell", ["execution"], sub=True),
        ap("ap-3", "T1497", "Virtualization/Sandbox Evasion", ["stealth"]),
        ap("ap-4", "T1497.003", "Time Based Checks", ["stealth"], sub=True),
        ap("ap-old", "T1086", "PowerShell (old)", ["execution"], revoked=True),
        {"type": "relationship", "id": "r1", "relationship_type": "revoked-by", "source_ref": "ap-old", "target_ref": "ap-2"},
        {"type": "course-of-action", "id": "coa-1", "name": "Execution Prevention", "description": "Block execution.",
         "external_references": [{"source_name": "mitre-attack", "external_id": "M1038", "url": "https://attack.mitre.org/mitigations/M1038"}]},
        {"type": "relationship", "id": "r2", "relationship_type": "mitigates", "source_ref": "coa-1", "target_ref": "ap-2",
         "description": "Use application control to block PowerShell where it is not needed."},
    ]}


@pytest.fixture
def attack(tmp_path):
    p = tmp_path / "enterprise-attack-99.0.json"
    p.write_text(json.dumps(bundle()), encoding="utf-8")
    (tmp_path / "manifest.json").write_text(json.dumps({"file": p.name}), encoding="utf-8")
    return _attack.load(_attack.bundle_path(str(tmp_path)))


def alert(rule_id, n, level="high", source="sigma"):
    return Alert(rule_id, f"alert of {rule_id}", source, level, f"2026-10-22T10:00:0{n}.000Z", "h1", "r", (f"k{rule_id}{n}",))


RULES = [
    {"id": "r-ps", "title": "PS rule", "level": "high", "tags": ["attack.execution", "attack.t1059.001"], "ours": True, "source": "sigma"},
    {"id": "r-old", "title": "Old tag rule", "level": "medium", "tags": ["attack.t1086"], "ours": True, "source": "sigma"},
    {"id": "r-time", "title": "Time rule", "level": "low", "tags": ["attack.t1497.003"], "ours": True, "source": "sigma"},
    {"id": "r-linux", "title": "Not our events", "level": "high", "tags": ["attack.t1497"], "ours": False, "source": "sigma"},
    {"id": "r-bad", "title": "Unknown tag", "level": "high", "tags": ["attack.t9999"], "ours": True, "source": "sigma"},
]


def test_bundle_is_read_with_mitres_own_names_order_and_relationships(attack):
    assert attack.version == "99.0" and [t["shortname"] for t in attack.tactics] == ["execution", "stealth"]
    assert attack.full_name("T1059.001") == "Command and Scripting Interpreter: PowerShell"
    assert attack.resolve("t1086") == ("T1059.001", "revoked: now T1059.001")
    assert attack.resolve("T9999") == (None, "unknown")
    assert attack.mitigates["T1059.001"][0]["mitigation"] == "M1038"
    assert _attack.plain(attack.techniques["T1059"]["description"]) == "Command and Scripting Interpreter text with a link."


def test_tags_to_techniques():
    assert _attack.technique_tags(["attack.execution", "attack.t1059.001", "attack.T1059.001", "attack.g0016", "attack.t1497"]) == ["T1059.001", "T1497"]


def test_matrix_lights_alerts_from_tags_only_and_counts_coverage_of_our_rules(attack):
    alerts = [alert("r-ps", 1), alert("r-ps", 2), alert("r-old", 3), alert("analystlab.file_churn", 4, source="analystlab")]
    m = techniques.matrix(attack, alerts, RULES, floor_index=2)            # medium
    cells = {c["id"]: c for t in m["tactics"] for c in t["techniques"]}
    assert set(cells) == {"T1059", "T1497"}                                 # parents only; subs inside them
    assert cells["T1059"]["alerts"] == 3                                    # 2 via T1059.001, 1 via the revoked T1086
    assert cells["T1059"]["subs"][0] == {"id": "T1059.001", "name": "PowerShell", "alerts": 3, "rules": 2, "rules_floor": 2}
    assert cells["T1497"]["alerts"] == 0
    assert cells["T1497"]["rules"] == 1 and cells["T1497"]["rules_floor"] == 0    # low rule: sees it, raises nothing; the non-Windows rule is not ours
    t = m["totals"]
    assert (t["alerts_tagged"], t["alerts_untagged"], t["techniques_hit"]) == (3, 1, 1)
    assert (t["techniques_covered"], t["techniques_covered_floor"], t["rules_ours"]) == (2, 1, 4)
    assert m["untagged"] == [{"rule_id": "analystlab.file_churn", "title": "alert of analystlab.file_churn", "source": "analystlab", "alerts": 1}]
    assert {"tag": "T9999", "note": "unknown"} in m["unknown_tags"] and {"tag": "T1086", "note": "revoked: now T1059.001"} in m["unknown_tags"]


def test_every_level_counts_the_lower_alerts_the_screens_leave_out(attack):
    class Ctx:
        def alerts(self):
            return [alert("r-ps", 1), alert("r-time", 2, level="low")]

        def shown_alerts(self):
            return [alert("r-ps", 1)]

    shown = techniques.matrix(attack, techniques._alerts(Ctx(), "shown"), RULES, floor_index=2)
    every = techniques.matrix(attack, techniques._alerts(Ctx(), "all"), RULES, floor_index=2)
    cells = lambda m: {c["id"]: c["alerts"] for t in m["tactics"] for c in t["techniques"]}
    assert cells(shown) == {"T1059": 1, "T1497": 0} and cells(every) == {"T1059": 1, "T1497": 1}


def test_detail_lists_the_techniques_alerts_and_rules(attack):
    alerts = [alert("r-ps", 1), alert("r-time", 2, level="medium")]
    d = techniques.detail(attack, "T1059", alerts, RULES, floor_index=2)
    assert d["technique"]["name"] == "Command and Scripting Interpreter" and d["technique"]["subs"] == [{"id": "T1059.001", "name": "PowerShell"}]
    assert [a["rule_id"] for a in d["alerts"]] == ["r-ps"] and d["rules_total"] == 2
    assert techniques.detail(attack, "T1086", alerts, RULES, 2)["technique"]["note"] == "revoked: now T1059.001"
    assert techniques.detail(attack, "T4242", alerts, RULES, 2) is None


def test_rule_index_keeps_only_rules_for_the_events_we_record(tmp_path):
    (tmp_path / "a.yml").write_text("title: A\nid: aaa\nlevel: high\ntags: [attack.t1059]\n"
                                    "logsource: {category: process_creation, product: windows}\ndetection: {s: {Image: x}, condition: s}\n", encoding="utf-8")
    (tmp_path / "b.yml").write_text("title: B\nid: bbb\nlevel: high\ntags: [attack.t1059]\n"
                                    "logsource: {category: process_creation, product: linux}\ndetection: {s: {Image: x}, condition: s}\n", encoding="utf-8")
    (tmp_path / "c.yml").write_text("title: C\nid: ccc\nname: base_c\nlogsource: {category: file_event, product: windows}\n"
                                    "detection: {s: {TargetFilename: x}, condition: s}\n---\ntitle: C burst\nid: ddd\nlevel: medium\n"
                                    "correlation: {type: event_count, rules: [base_c], group-by: [Image], timespan: 1m, condition: {gte: 3}}\n", encoding="utf-8")
    idx = _rule_tags.index((str(tmp_path),))
    assert idx["aaa"]["ours"] and not idx["bbb"]["ours"] and idx["ddd"]["ours"] and idx["ddd"]["category"] == "correlation"


# -- through the real dashboard (create_app + the Labs registry) --------------------------------------------------
@pytest.fixture
def client(tmp_path):
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    return TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun(), labs_hosts=None)), a


def test_the_labs_are_found_and_answer_through_the_dashboard(client):
    c, a = client
    names = {x["name"] for x in c.get("/api/labs").json()["labs"]}
    assert {"why", "techniques"} <= names and c.get("/api/labs").json()["left_out"] == []
    picked = c.get("/api/labs/why").json()
    assert [x["id"] for x in picked["alerts"]] == [a.alert_id]
    w = c.get(f"/api/labs/why/{a.alert_id}").json()
    assert w["rule"]["kind"] == "python" and w["story"]["available"] is True and w["story"]["rows"]
    assert {r["ink"] for r in w["story"]["rows"]} <= {"fact", "hypothesis", "gap"}
    assert c.get("/api/labs/why/nope").status_code == 404
    t = c.get("/api/labs/techniques")
    assert t.status_code == 200 and "words" in t.json()


def test_by_default_these_labs_show_no_other_machine_than_the_test_vm(tmp_path):
    """Night rule 11: a dashboard started normally limits labs to demo_mode.VM_HOSTS; the fixture's machine is
    'h1', so every night-explain lab must show nothing of it."""
    from tests.labs.test_registry import NoRun
    from tests.test_report import s1_like
    from engine.alerts import AlertStore
    from engine.dashboard.app import create_app
    con, a, _ = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([a])
    s.close()
    events = next(str(p) for p in tmp_path.iterdir() if p.suffix == ".db" and p.name != "alerts.db")
    c = TestClient(create_app(events, str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), runner=NoRun()))
    assert c.get("/api/labs/why").json()["alerts"] == [] and c.get("/api/labs/respond").json()["alerts"] == []
    assert c.get(f"/api/labs/why/{a.alert_id}").status_code == 404
    assert c.get(f"/api/labs/respond/{a.alert_id}").status_code == 404
    assert c.get(f"/api/labs/moment?alert={a.alert_id}").status_code == 404
    assert c.get(f"/api/labs/moment", params={"event": a.evidence[0]}).status_code == 404
    t = c.get("/api/labs/techniques").json()
    assert t.get("totals", {}).get("alerts_shown", 0) == 0


def test_no_lab_module_shadows_a_python_builtin():
    """engine/labs/__init__.py uses builtins (next, sorted, ...): importing a lab module named like one puts
    the module in the package's namespace in its place and breaks every lab (found 2026-11-23 with `next`)."""
    import builtins
    import pkgutil
    import engine.labs as pkg
    names = [m.name for m in pkgutil.iter_modules(pkg.__path__)]
    assert "respond" in names and not [n for n in names if hasattr(builtins, n)]


def test_respond_answers_through_the_dashboard(client):
    c, a = client
    r = c.get(f"/api/labs/respond/{a.alert_id}")
    assert r.status_code == 200 and r.json()["words"]["no_tags"]
    techs = r.json()["techniques"]
    if r.json()["attack"]["available"]:     # fetch_write_run has no tag: T1105 by Analyst Lab's reading, said so
        assert [(t["id"], t["source"]) for t in techs] == [("T1105", "reading")] and techs[0]["reason"]
    else:
        assert techs == []
    assert c.get(f"/api/labs/why/{a.alert_id}").status_code == 200          # still fine after respond was imported


def test_no_lab_word_overclaims(client):
    from tests.test_dashboard_words_scan import scan
    for words in (techniques.WORDS, __import__("engine.labs.why", fromlist=["WORDS"]).WORDS):
        assert not scan(json.dumps(words, ensure_ascii=False))
