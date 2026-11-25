"""The case report's story picture (engine/labs/_story_svg.py): every arrow is a link of the alert's own report,
drawn in its grade's style; the starter is greyed out; the lab's own machinery inside the chain is left out."""

import xml.etree.ElementTree as ET

import networkx as nx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine import report as report_mod
from engine.labs import _story_svg as S
from engine.labs import cases as C
from tests.labs.pivotfix import FakeContext, story, use
from tests.labs.test_claim import NET, TOOLF, add_hypothesis

STYLE = {"fact": "solid", "hypothesis": "dashed", "gap": "dotted"}


@pytest.fixture
def world(tmp_path, monkeypatch):
    events_db, alerts_db, alert, keys = story(tmp_path)
    ctx = FakeContext(events_db, alerts_db, recordings=str(tmp_path / "rec"))
    ctx.add_edges = add_hypothesis

    def full_report(a):                                  # as the dashboard: the report of the FULL graph
        import sqlite3
        from engine.graph import build_graph
        con = sqlite3.connect(events_db)
        try:
            G = build_graph(con)
        finally:
            con.close()
        add_hypothesis(G)
        return report_mod.build(a, G, events_db)
    ctx._report = full_report
    use(monkeypatch, ctx)
    return ctx, alert, keys


def links_of(content):
    """{(u, v, kind): grade} of the report's own facts and hypotheses."""
    out = {(f["u"], f["v"], f.get("kind")): "fact" for f in content["facts"] if f.get("u")}
    out.update({(h["u"], h["v"], h.get("kind")): "hypothesis" for h in content["hypotheses"] if h.get("u")})
    return out


def test_every_arrow_comes_from_the_story_in_its_grades_style(world):
    ctx, alert, keys = world
    content = ctx.report(alert)
    _, _, H = ctx.story(alert)
    pic = S.story_picture(content, H, ctx)
    links = links_of(content)
    gaps = {g["node_id"] for g in content["gaps"]}
    assert pic["edges"], "the picture draws something"
    for e in pic["edges"]:
        if e["grade"] == "gap":
            assert e["v"] in gaps and e["u"] == f"?:{e['v']}"
        else:
            assert links.get((e["u"], e["v"], e["kind"])) == e["grade"], e      # from the report, same grade
        assert e["style"] == STYLE[e["grade"]]
    assert any(e["grade"] == "hypothesis" and (e["u"], e["v"]) == (NET, TOOLF) for e in pic["edges"])
    # the SVG draws exactly these, each path's dash matching its grade
    svg = ET.fromstring(pic["svg"])
    paths = [p for p in svg.iter("{http://www.w3.org/2000/svg}path") if p.get("data-grade")]
    assert len(paths) == len(pic["edges"])
    for p in paths:
        assert p.get("data-style") == STYLE[p.get("data-grade")]
        assert (p.get("stroke-dasharray") is None) == (p.get("data-grade") == "fact")


def test_the_chain_only_and_the_starter_greyed_out(world):
    ctx, alert, keys = world
    content = ctx.report(alert)
    _, _, H = ctx.story(alert)
    pic = S.story_picture(content, H, ctx)
    chain = {(f["u"], f["v"]) for f in content["facts"] if f.get("in_chain")}
    drawn_facts = {(e["u"], e["v"]) for e in pic["edges"] if e["grade"] == "fact" and not e["context"]}
    assert drawn_facts == chain
    for e in pic["edges"]:
        if e["context"]:
            assert e["kind"] == "started" and e["v"] in {u for u, _ in chain} | {v for _, v in chain}


def test_machinery_inside_the_chain_is_left_out():
    """A hand-made report: run A started the VirtualBox helper (test machinery) and created a file."""
    H = nx.MultiDiGraph()
    H.add_node("A", kind="process", label="a.exe", pid=1, gaps=[])
    H.add_node("V", kind="process", label="VBoxControl.exe", image=r"C:\\x\\VBoxControl.exe", pid=2, gaps=[])
    H.add_node("F", kind="file", label="f.txt", path=r"C:\\x\\f.txt", gaps=[])
    content = {"facts": [{"u": "A", "v": "V", "kind": "started", "in_chain": True},
                         {"u": "A", "v": "F", "kind": "created", "in_chain": True}], "hypotheses": [], "gaps": []}
    pic = S.story_picture(content, H)
    assert [(e["u"], e["v"]) for e in pic["edges"]] == [("A", "F")]
    assert S.story_picture({"facts": [], "hypotheses": [], "gaps": []}, H)["svg"] == ""


def test_the_report_carries_the_picture_on_its_first_page(world, monkeypatch):
    ctx, alert, keys = world
    app = FastAPI()
    app.include_router(C.router)
    c = TestClient(app)
    cid = c.post("/api/labs/cases", json={"title": ""}).json()["id"]
    c.post(f"/api/labs/cases/{cid}/pins", json={"type": "alert", "ref": alert.alert_id})
    html = c.get(f"/api/labs/cases/{cid}/report").text
    page1 = html.split("<div class='pb'></div>")[0]
    assert "The story in one picture" in page1 and "<svg" in page1 and "content from?" in page1
    assert ".pic svg { display: block; width: 100%" in html                    # scales to the A4 page width
