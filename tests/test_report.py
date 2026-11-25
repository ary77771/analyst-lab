"""Package H: the investigation report (engine/report.py) and its citation checker."""

import sqlite3

import networkx as nx

from engine import own_rules, report
from engine.graph import build_graph
from engine.store import EventStore
from tests.test_detect import ev

W = r"C:\Users\u\Downloads\tool.exe"


def s1_like(tmp_path):
    recs = [ev(1, 0, ProcessGuid="{F}", ParentProcessGuid="{E}", Image=r"C:\Users\u\fetch.exe", ProcessId=10),
            ev(3, 1, ProcessGuid="{F}", Image=r"C:\Users\u\fetch.exe", Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765),
            ev(11, 2, ProcessGuid="{F}", Image=r"C:\Users\u\fetch.exe", TargetFilename=W),
            ev(1, 5, ProcessGuid="{C}", ParentProcessGuid="{F}", Image=W, ParentImage=r"C:\Users\u\fetch.exe", ProcessId=11)]
    path = str(tmp_path / "s.db")
    st = EventStore(path)
    st.insert(recs)
    st.close()
    con = sqlite3.connect(path)
    alert = own_rules.fetch_write_run(con)[0]
    return con, alert, build_graph(con)


def test_report_has_every_section_and_cited_facts(tmp_path):
    con, alert, G = s1_like(tmp_path)
    c = report.build(alert, G, "s.db")
    sentences = [f["sentence"] for f in c["facts"]]
    assert any("connected to 10.0.2.2:18765" in s for s in sentences)
    assert any("created tool.exe" in s for s in sentences)
    assert any(s.startswith("fetch.exe (PID 10) started tool.exe") for s in sentences)
    assert all(f["citations"] for f in c["facts"])
    assert report.check_citations(c, con) == []
    html = report.render(c)
    for heading in ("1. Summary", "2. The alert and why it fired", "3. Timeline", "4. Established facts",
                    "5. Hypotheses", "6. What the evidence cannot show", "7. Limitations", "8. Recommended next steps"):
        assert heading in html
    assert alert.title in html and "no AI wrote it" in html
    assert {"origin unknown", "content unknown"} <= {g["what"] for g in c["gaps"]}   # parent never seen starting; no fingerprint


def test_checker_catches_bad_citations_and_incomplete_hypotheses(tmp_path):
    con, alert, G = s1_like(tmp_path)
    c = report.build(alert, G)
    c["facts"][0]["citations"][0]["key"] = "not-a-real-key"
    c["facts"].append({"sentence": "made up", "citations": [], "time": "x", "kind": "x"})
    c["hypotheses"].append({"sentence": "a guess", "band": "high", "reason": "", "alternative": None, "citations": []})
    problems = report.check_citations(c, con)
    assert any("not in the store" in p for p in problems)
    assert any("fact without a source" in p for p in problems)
    assert any("without reason" in p for p in problems) and any("without alternative" in p for p in problems)


def test_hypothesis_edges_are_reported_with_band_chance_and_alternative(tmp_path):
    con, alert, G = s1_like(tmp_path)
    net = next(n for n in G if n.startswith("net:"))
    f = next(n for n in G if n.startswith("file:"))
    key = alert.evidence[1]
    G.add_edge(net, f, kind="content_from", grade="hypothesis", band="medium", p=0.034, n_causes=1,
               reason="created 1 s after the connection", alternative="the program had the content already",
               provisional=True, provisional_reason="burst factor not fixed yet", basis="formula",
               time=G.edges[next(iter(G.out_edges(f, keys=True)), None) or list(G.in_edges(f, keys=True))[0]]["time"],
               evidence=[{"key": key, "event": 11}])
    c = report.build(alert, G)
    (h,) = c["hypotheses"]
    # report-next (debate 10 M1/M2): "may have" + the band's gloss; the chance and the exact reason
    # are in the folded technical details; a hand-made edge (no row) keeps its reason as the "why"
    assert h["band"] == "medium" and h["sentence"].startswith("the content of tool.exe may have come from 10.0.2.2:18765")
    assert h["band_label"] == "possible link"
    html = report.render(c)
    assert "0.034" in html and "Other explanation:</strong> the program had the content already" in html
    assert "provisional" in html and report.check_citations(c, con) == []


def test_unknown_kinds_and_unplaceable_alerts_do_not_break_a_report(tmp_path):
    con, alert, G = s1_like(tmp_path)
    assert report.sentence(G, *list(G.edges())[0], "brand_new_kind").count("brand_new_kind") == 1
    from engine.alerts import Alert
    lost = Alert("r", "Lost", "sigma", "low", "2026-10-22T10:00:00.000Z", "h1", "x", ("nowhere",))
    c = report.build(lost, G)
    assert c["facts"] == [] and "could be placed" in " ".join(c["limitations"])
    assert "Lost" in report.render(c)

def test_view_keeps_a_hub_but_does_not_walk_through_it(tmp_path):
    import dataclasses
    from engine.graph import norm_path
    con, alert, G = s1_like(tmp_path)
    child = next(n for n, d in G.nodes(data=True) if d.get("kind") == "process" and d.get("label") == "tool.exe")
    hubs = frozenset({norm_path(r"C:\Users\u\fetch.exe")})
    H = report.view(G, child, hubs)
    fetch = next(n for n, d in H.nodes(data=True) if d.get("label") == "fetch.exe")
    assert H.nodes[fetch].get("hub") is True
    assert not any(n.startswith("net:") for n in H)                  # its connection is not walked to
    assert any(n.startswith("net:") for n in report.view(G, child))  # without the list it is
    seeded = dataclasses.replace(alert, evidence=(G.nodes[child]["start_evidence"]["key"],))
    c = report.build(seeded, G, hubs=hubs)
    assert c["graph"]["hubs"] == ["fetch.exe (PID 10)"]
    # report-next S1: plain words for hubs ("busy common programs"), on purpose
    assert any("busy common program" in l and "not followed further" in l and "fetch.exe" in l for l in c["limitations"])
    assert "1 busy common program(s) shown but not followed further" in report.render(c)
    assert any("not set aside in this view" in l for l in report.build(seeded, G)["limitations"])


def test_a_declared_registry_alert_says_so_in_the_report(tmp_path):
    """v4 F7: an alert on a registry change read from reg.exe's command line must not read like a
    recorded change: the summary and the limitations say it was declared and may have failed."""
    import dataclasses
    con, alert, G = s1_like(tmp_path)
    plain = report.build(alert, G, "s.db")
    declared = report.build(dataclasses.replace(alert, details={**alert.details, "derived_from": "command_line"}), G, "s.db")
    assert "declared on reg.exe's command line" in declared["summary"] and "may have failed" in declared["summary"]
    assert report.DECLARED_LIMITATION in declared["limitations"]
    assert "declared" not in plain["summary"] and report.DECLARED_LIMITATION not in plain["limitations"]
    assert "NOT recorded" in report.render(declared)


def test_a_declared_script_alert_says_so_in_the_report(tmp_path):
    """v4 F8: an alert on PowerShell code read from powershell.exe's command line says the code was
    declared and may not have run, with ITS limitation (not the registry one)."""
    import dataclasses
    con, alert, G = s1_like(tmp_path)
    details = {**alert.details, "derived_from": "command_line", "declared": {"event_id": 4104, "ScriptBlockText": "x"}}
    declared = report.build(dataclasses.replace(alert, details=details), G, "s.db")
    assert "PowerShell code declared on powershell.exe's command line" in declared["summary"]
    assert "may not have run" in declared["summary"]
    assert report.DECLARED_SCRIPT_LIMITATION in declared["limitations"]
    assert report.DECLARED_LIMITATION not in declared["limitations"]

