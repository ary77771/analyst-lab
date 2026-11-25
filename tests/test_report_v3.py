"""Report v3, tier 1 (docs/vision/debates/11-dashboard.md, "Agreed plan" + fresh review items 3, 7, 8,
11): presentation fields that report.build() adds for the report page and the new dashboard.

Every test runs on a REAL graph (engine/graph.py, frozen) and recomputes each number from the stored
field it comes from: offsets from time_precise and the layout's t0, the chance figure from p through
per_thousand, counts from the lists. Three stores:
  rich    (tests/report_fixtures.rich): layer 2 on, every hypothesis case of debate 10;
  causal  (report_fixtures.causal): Sysmon stamps an effect BEFORE its cause, inside the chain;
  s1_like (tests/test_report.s1_like): the S1 shape, also what the dashboard tests serve.
`invariants()` is the generic check; tests/test_report_v3_s1.py runs it on the real practice S1
sample when that store is available.
"""

import dataclasses
import json
import re
from datetime import timedelta

import markupsafe
import pytest
from fastapi.testclient import TestClient

from engine import confidence as C
from engine import config, report
from engine.alerts import LEVELS, Alert, AlertStore
from engine.dashboard.app import create_app, stream_payload
from engine.graph import parse_time
from report_fixtures import causal, key, rich
from tests.test_report import s1_like

# no step, short line, icon or verdict may say the download happened (debate 11 round 2b)
CLAIM = re.compile(r"\b(downloaded|download|dropped|fetched|severity|danger)\b", re.I)
DANGER_ICON = re.compile(r"download|danger|alert|warn|skull|bug|threat|virus|bomb", re.I)


@pytest.fixture(scope="module")
def rich_c(tmp_path_factory):
    db, alert, G = rich(tmp_path_factory.mktemp("rich3"))
    c = report.build(alert, G, "rich.db")
    return db, alert, G, c, report.render(c)


@pytest.fixture(scope="module")
def causal_c(tmp_path_factory):
    db, alert, G = causal(tmp_path_factory.mktemp("causal"))
    c = report.build(alert, G, "causal.db")
    return db, alert, G, c, report.render(c)


def view_of(alert, G):
    return report.alert_view(alert, G, None)[2]


def rows_by_order(c):
    return sorted(c["timeline"], key=lambda t: t["order"])


def item_by_id(c):
    return {x["id"]: x for sec in ("facts", "hypotheses", "gaps") for x in c[sec]}


def claim_texts(c):
    """Every NEW text field v3 shows (the existing `sentence`/`text` are debate 10's and unchanged)."""
    v = c["verdict"]
    out = [v["level_text"], v["proven"]["text"], (v["not_proven"] or {}).get("text") or "",
           (v["cant_see"] or {}).get("text") or ""]
    out += [s["text"] for s in v["steps"]] + [s["offset_text"] or "" for s in v["steps"]]
    out += [x["short"] for sec in ("facts", "hypotheses") for x in c[sec]]
    out += [g["plain"] for g in c["gaps"]] + [t["short"] for t in c["timeline"]]
    out += [t["offset_text"] or "" for t in c["timeline"]]
    out += [h["chance_short"] or "" for h in c["hypotheses"]]
    out += [x["short"] for x in c["layout"]["nodes"] + c["layout"]["edges"]]
    out += [x["text"] for x in c["alert"]["citations"]]
    return out


def assert_time_order(c, H):
    by_id = item_by_id(c)
    edges = {report.edge_id(u, v, k): (u, v, d) for u, v, k, d in H.edges(keys=True, data=True)}
    facts = c["facts"]
    start_of = {f["v"]: f["id"] for f in facts if f["kind"] == "started"}

    def first_fact_about(node):
        about = [f for f in facts if f["v"] == node]
        return min(about, key=lambda f: (parse_time(f["time_precise"]), 0 if f["kind"] == "started" else 1,
                                         f["sentence"]))["id"] if about else None

    def preds(x):
        if x["id"] in edges:
            u, v, d = edges[x["id"]]
            return [p for p in (start_of.get(report._actor_of(H, u, v, d)),) if p and p != x["id"]]
        return [p for p in (start_of.get(x["node_id"]), first_fact_about(x["node_id"])) if p]

    def ancestors(i, seen=None):
        seen = set() if seen is None else seen
        for p in preds(by_id[i]):
            if p not in seen:
                seen.add(p)
                ancestors(p, seen)
        return seen

    rows = [t for t in rows_by_order(c) if t["placement"] == "at" and t["time_precise"]]
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            if parse_time(b["time_precise"]) < parse_time(a["time_precise"]):
                held = [by_id[p]["order"] for p in ancestors(b["id"])]
                assert any(o >= a["order"] for o in held), (a["short"], "listed above the earlier", b["short"])


def invariants(c, alert, H):
    """What must hold on ANY store (the fixtures and the real S1 sample)."""
    ids = [x["id"] for sec in ("facts", "hypotheses", "gaps") for x in c[sec]]
    assert len(ids) == len(set(ids))                                      # one id per item
    edges = {report.edge_id(u, v, k): (u, v, d) for u, v, k, d in H.edges(keys=True, data=True)}
    for x in c["facts"] + c["hypotheses"]:
        u, v, d = edges[x["id"]]
        assert (x["u"], x["v"]) == (u, v) and x["sentence"] == report.sentence(H, u, v, d.get("kind"))
        assert x["time_precise"] == (d["time"].isoformat(timespec="microseconds").replace("+00:00", "Z"))
    for g in c["gaps"]:
        assert g["node_id"] in H and g["placement"] == ("before" if g["kind"] in report.BEFORE_GAPS else "at")
    # one full order: timeline orders are 0..n-1, "Before this" rows first, facts/gaps in that order
    orders = [t["order"] for t in c["timeline"]]
    assert orders == list(range(len(c["timeline"])))
    nb = sum(1 for t in c["timeline"] if t["placement"] == "before")
    assert all(t["placement"] == "before" for t in c["timeline"][:nb]) and nb == c["counts"]["before"]
    assert all(t["text"].startswith("Before this: ") for t in c["timeline"][:nb])
    assert [f["order"] for f in c["facts"]] == sorted(f["order"] for f in c["facts"])
    # the causal rule: a program's own rows never list above the fact that started it
    by_id = item_by_id(c)
    started = {f["v"]: f["order"] for f in c["facts"] if f["kind"] == "started"}
    for u, v, k, d in H.edges(keys=True, data=True):
        x = by_id.get(report.edge_id(u, v, k))
        actor = report._actor_of(H, u, v, d)
        if x is not None and actor in started and x["kind"] != "started":
            assert x["order"] > started[actor], x["sentence"]
    # time order at full precision, except where the causal rule moved a row (v3 review fix 5): when
    # a row A lists above a row B stamped EARLIER, some required predecessor of B (the start of B's
    # program, or for a gap the first fact about its node; recursively) lists at or below A, so B
    # had to wait. Never because of record ids.
    assert_time_order(c, H)
    # offsets: recomputed from the stored full-precision time and the layout's t0
    t0 = parse_time(c["layout"]["t0"]) if c["layout"]["t0"] else None
    for t in c["timeline"]:
        if t["placement"] == "before":
            assert t["t_offset_s"] is None and t["offset_text"] is None
        elif t["time_precise"] and t0:
            dt = (parse_time(t["time_precise"]) - t0).total_seconds()
            assert t["t_offset_s"] == pytest.approx(dt, abs=1e-6)
            if t["offset_text"] != "start":
                assert t["offset_text"] == report.offset_text(dt)
    chain = [f for f in c["facts"] if f["in_chain"]]
    if chain:
        assert c["layout"]["t0_from"] == "first chain step" and c["layout"]["t0"] == chain[0]["time_precise"]
    own = set(alert.evidence)
    for f in c["facts"]:
        assert f["in_chain"] == any(x["key"] in own for x in f["citations"])
    assert all(x["in_chain"] is False for x in c["hypotheses"] + c["gaps"])
    # steps: the chain's facts (identical sentences once), in section 4's order, sharing their items
    want, seen = [], set()
    for f in chain:
        if f["sentence"] not in seen:
            seen.add(f["sentence"])
            want.append(f)
    steps = c["verdict"]["steps"]
    assert [s["id"] for s in steps] == [f["id"] for f in want][:report.MAX_STEPS]
    assert c["verdict"]["steps_more"] == max(0, len(want) - report.MAX_STEPS)
    for i, s in enumerate(steps):
        f = by_id[s["id"]]
        assert s["n"] == i + 1 and s["citations"] is f["citations"] and s["text"] == f["short"]
    # M4 still holds: the Proven line's facts are section 4's own items, and they are the first steps
    proven = c["summary_lines"][1]["facts"]
    assert all(any(p is f for f in c["facts"]) for p in proven)
    assert [p["id"] for p in proven] == [f["id"] for f in want][:len(proven)]
    # counts recomputed from the lists
    assert c["counts"] == {"facts": len(c["facts"]), "hypotheses": len(c["hypotheses"]), "gaps": len(c["gaps"]),
                           "before": nb, "in_chain": len(chain), "steps": len(want), "nodes": H.number_of_nodes()}
    # icons from the closed set only, never a download or danger picture
    icons = [x["icon"] for sec in ("facts", "hypotheses", "gaps", "timeline") for x in c[sec]]
    icons += [x["icon"] for x in c["layout"]["nodes"] + c["layout"]["edges"]] + [s["icon"] for s in steps]
    assert set(icons) <= report.ICON_NAMES and not any(DANGER_ICON.search(i) for i in report.ICON_NAMES)
    # no new text claims the download
    for text in claim_texts(c):
        assert not CLAIM.search(text), text
    json.dumps(c, allow_nan=False)


def test_invariants_hold_on_every_fixture(rich_c, causal_c, tmp_path):
    for db, alert, G, c, _ in (rich_c, causal_c):
        invariants(c, alert, view_of(alert, G))
        assert report.check_citations(c, db) == []
    con, alert, G = s1_like(tmp_path)
    invariants(report.build(alert, G), alert, view_of(alert, G))


# -- shared ids -------------------------------------------------------------------------------------------
def test_ids_come_from_the_edge_not_its_position(rich_c):
    db, alert, G, c, _ = rich_c
    H = view_of(alert, G)
    # the rich view holds 25 parallel connections to one address and hypotheses sharing a fact's row
    assert sum(1 for f in c["facts"] if f["sentence"].startswith("x.exe (PID 13) connected to")) == 25
    rebuilt = nx_reversed(G)
    again = report.build(alert, rebuilt)
    assert {(x["id"], x["sentence"]) for x in again["facts"] + again["hypotheses"]} == \
           {(x["id"], x["sentence"]) for x in c["facts"] + c["hypotheses"]}
    assert len({x["id"] for x in c["facts"] + c["hypotheses"]}) == H.number_of_edges()


def nx_reversed(G):
    """The same graph with its edges handed over in the reverse order (same keys)."""
    import networkx as nx
    R = nx.MultiDiGraph(**G.graph)
    R.add_nodes_from(G.nodes(data=True))
    for u, v, k, d in reversed(list(G.edges(keys=True, data=True))):
        R.add_edge(u, v, key=k, **d)
    return R


def dash(tmp_path, con_alert_G, hypotheses=None, extra_alerts=()):
    con, alert, G = con_alert_G
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert, *extra_alerts])
    s.close()
    (tmp_path / "rec" / "scenario_runs").mkdir(parents=True, exist_ok=True)
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"),
                                 hypotheses=hypotheses))


def test_the_api_graph_reuses_the_report_ids_and_layout(tmp_path):
    from engine.graph import Layer2
    con, alert, G = s1_like(tmp_path)
    con.close()
    per_band = {k: {b: (1, 100.0) for b in ("<60", "60-3600", ">=3600")} for k in C.KINDS}
    C.Pool({k: {} for k in C.KINDS}, per_band, C.pool_settings(C.load_config())).save(str(tmp_path / "pool.json"))
    c = dash(tmp_path, (None, alert, G), hypotheses=Layer2.from_pool_file(str(tmp_path / "pool.json")))
    inv = c.get(f"/api/alerts/{alert.alert_id}").json()
    rep = inv["report"]
    items = {x["id"]: x for x in rep["facts"] + rep["hypotheses"]}
    assert {e["grade"] for e in inv["edges"]} == {"fact", "hypothesis"}
    assert {e["id"] for e in inv["edges"]} == set(items) and not any(re.fullmatch(r"e\d+", i) for i in items)
    lay_e = {x["id"]: x for x in rep["layout"]["edges"]}
    for e in inv["edges"]:
        x = items[e["id"]]
        assert (e["source"], e["target"], e["sentence"]) == (x["u"], x["v"], x["sentence"])
        for f in ("lane", "order", "icon", "short", "t_offset_s", "time_precise", "in_chain"):
            assert e[f] == lay_e[e["id"]][f], f
    lay_n = {x["id"]: x for x in rep["layout"]["nodes"]}
    for n in inv["nodes"]:
        assert (n["lane"], n["order"], n["icon"], n["short"]) == tuple(lay_n[n["id"]][f] for f in ("lane", "order", "icon", "short"))


# -- order --------------------------------------------------------------------------------------------------
def test_full_precision_order_inside_one_second(causal_c):
    c = causal_c[3]
    z, a = (next(f for f in c["facts"] if f["short"] == f"kid.exe created {n}") for n in ("zzz.exe", "aaa.exe"))
    assert z["time"] == a["time"]                                       # the same second when cut ...
    assert parse_time(z["time_precise"]) < parse_time(a["time_precise"])  # ... 0.3 s apart in full
    assert z["order"] < a["order"] and z["sentence"] > a["sentence"]    # time decides, not the sentence


def test_an_effect_stamped_before_its_cause_lists_after_it(causal_c):
    c = causal_c[3]
    start = next(f for f in c["facts"] if f["short"] == "loader.exe started kid.exe")
    conn = next(f for f in c["facts"] if f["short"] == "kid.exe connected to 10.0.0.9:443")
    assert parse_time(conn["time_precise"]) < parse_time(start["time_precise"])   # Sysmon's stamps, kept as stored
    assert start["order"] < conn["order"]                                         # the cause still lists first
    dt = (parse_time(conn["time_precise"]) - parse_time(start["time_precise"])).total_seconds()
    assert dt == pytest.approx(-0.5) and conn["t_offset_s"] == pytest.approx(dt) and conn["offset_text"] == "0.5 s before"
    steps = c["verdict"]["steps"]
    assert [s["text"] for s in steps] == ["loader.exe started kid.exe", "kid.exe connected to 10.0.0.9:443",
                                          "kid.exe created out.exe"]
    assert [s["offset_text"] for s in steps] == ["start", "0.5 s before", "0.3 s before"]   # negative offsets allowed


def test_a_gap_at_a_file_lists_after_the_fact_that_made_the_file(causal_c):
    c = causal_c[3]
    made = next(f for f in c["facts"] if f["short"] == "kid.exe created nohash.exe")
    (gap,) = [g for g in c["gaps"] if g["kind"] == "content_unknown"]
    assert gap["placement"] == "at" and gap["node_id"] == made["v"] and gap["order"] == made["order"] + 1
    start = next(f for f in c["facts"] if f["short"] == "loader.exe started kid.exe")
    # the gap's own stamp is BEFORE kid's start, yet it lists after the start and after its file's fact
    assert parse_time(gap["time_precise"]) < parse_time(start["time_precise"]) and start["order"] < made["order"] < gap["order"]


def test_parent_and_origin_unknown_become_before_this_rows(causal_c, tmp_path):
    c = causal_c[3]
    (before,) = [g for g in c["gaps"] if g["placement"] == "before"]
    assert before["kind"] == "parent_unknown" and before["order"] == 0 and c["gaps"][0] is before
    row = c["timeline"][0]
    assert row["id"] == before["id"] and row["text"] == f"Before this: {report.gap_plain(before, before['where'])}"
    assert "explorer.exe" in row["short"] and "explorer.exe (PID" not in row["short"]
    con, alert, G = s1_like(tmp_path)
    s1 = report.build(alert, G)
    kinds = [(g["kind"], g["placement"]) for g in s1["gaps"]]
    assert ("origin_unknown", "before") in kinds and ("content_unknown", "at") in kinds
    origin = next(g for g in s1["gaps"] if g["kind"] == "origin_unknown")      # fetch.exe's parent, never seen starting
    assert s1["timeline"][0]["text"] == f"Before this: how {origin['where']} was started: its start was not recorded " \
                                        "(it was already running, or it started outside the recording)"
    page = report.render(s1)
    assert "Before this:" in page.split("3. Timeline")[1].split("4. Established")[0]
    # a before-gap's stored time is when the recording noticed the program (in S1: its END), not
    # when it started: the page never prints it, in the timeline or in section 6
    first_row = page.split("3. Timeline")[1].split('<tr class="before">')[1].split("</tr>")[0]
    assert re.findall(r"<td>(.*?)</td>", first_row)[:2] == ["before this", ""]
    sec6 = page.split("6. What the evidence cannot show")[1].split("7. Limitations")[0]
    block = sec6.split("Before this:")[1].split('<div class="item')[0]
    assert f'<span class="muted">({origin["time"]})</span>' not in block and '<span class="muted">(' not in block


def test_record_id_order_never_decides(causal_c):
    db, _, _, c, _ = causal_c
    early = next(f for f in c["facts"] if f["short"] == "loader.exe created early.exe")
    rid = {f["id"]: f["citations"][0]["record"] for f in c["facts"]}
    later = [f for f in c["facts"] if parse_time(f["time_precise"]) > parse_time(early["time_precise"])
             and rid[f["id"]] < rid[early["id"]]]
    assert later                                                         # ids and times disagree in this store ...
    assert all(early["order"] < f["order"] for f in later)               # ... and the times win


def test_before_gaps_claim_no_time_and_follow_their_programs(causal_c):
    _, alert, G, c, _ = causal_c
    (g,) = [g for g in c["gaps"] if g["placement"] == "before"]
    stored = next(x for x in G.graph["gaps"] if x["kind"] == "parent_unknown")["time"]
    assert g["time_precise"] is None and g["noticed_time"] == stored.isoformat(timespec="microseconds").replace("+00:00", "Z")
    row = c["timeline"][0]
    assert row["id"] == g["id"] and row["time_precise"] is None and row["noticed_time"] == g["noticed_time"]
    assert all(x["noticed_time"] is None for x in c["gaps"] if x["placement"] == "at")
    # two "Before this" gaps whose NOTICED times disagree with the order their programs enter the
    # story (a hand-placed second gap on a copy of the graph: this tests only the ordering)
    H = G.copy()
    gaps = [dict(x) for x in G.graph["gaps"]]
    ex = next(x for x in gaps if x["kind"] == "parent_unknown")
    other = next(n for n, d in G.nodes(data=True) if d.get("label") == "other.exe" and d.get("pid") == 41)
    ex["time"] = parse_time(row["noticed_time"]) + timedelta(seconds=190)          # noticed LATE
    gaps.append({"kind": "origin_unknown", "node": other, "reason": "test", "time": parse_time(row["noticed_time"])
                 + timedelta(seconds=5), "evidence": ex["evidence"]})              # noticed EARLY
    H.graph["gaps"] = gaps
    c2 = report.build(alert, H)
    before = [x for x in c2["gaps"] if x["placement"] == "before"]
    assert [x["node_id"] for x in before] == [ex["node"], other]        # explorer.exe enters the story first
    assert [t["id"] for t in c2["timeline"][:2]] == [x["id"] for x in before]


def test_offsets_say_what_they_count_from(causal_c, rich_c):
    for c, html in ((causal_c[3], causal_c[4]), (rich_c[3], rich_c[4])):
        assert c["layout"]["offset_from"] == c["verdict"]["offset_from"] == "step 1"
        assert "<th>when (from step 1)</th>" in html
    db, alert, G, _, _ = rich_c
    none = report.build(dataclasses.replace(alert, evidence=(key(db, 13),)), G)
    assert none["layout"]["offset_from"] == "the first row" and "<th>when (from the first row)</th>" in report.render(none)


# -- the chain, the steps and the verdict -------------------------------------------------------------------
def test_verdict_card(rich_c, causal_c):
    for db, alert, G, c, html in (rich_c, causal_c):
        v = c["verdict"]
        assert v["title"] == alert.title and v["level_text"] == f"Alert level: {alert.level}"
        assert v["proven"]["ids"] == [s["id"] for s in v["steps"]]
        # review fix 3: section 4's gloss (a step can be an exact match between two records)
        assert v["proven"]["text"] == f"{len(v['steps'])} numbered step{'s' if len(v['steps']) != 1 else ''}, " \
                                      "each one stated by a recorded event, or by an exact match between two records."
        own = set(alert.evidence)
        touching = [h for h in c["hypotheses"] if any(x["key"] in own for x in h["citations"])]
        if touching:
            assert v["not_proven"]["id"] == touching[0]["id"] and touching[0]["short"] in v["not_proven"]["text"]
            assert touching[0]["band_label"] in v["not_proven"]["text"]
            # review fix 4: the others are counted, not hidden
            n = len(touching) - 1
            assert v["not_proven"]["more"] == n
            assert (f"(and {n} more suspected link{'s' if n != 1 else ''} about the alert's events in section 5)"
                    in v["not_proven"]["text"]) == (n > 0)
        assert v["cant_see"]["id"] in {g["id"] for g in c["gaps"]}
        n = len(c["gaps"]) - 1
        assert v["cant_see"]["more"] == n and (f"(and {n} more thing{'s' if n != 1 else ''} the recording can't show, "
                                               "in section 6)" in v["cant_see"]["text"]) == (n > 0)
        card = html.split('id="verdict"')[1].split('id="legend"')[0]
        assert html.index('id="verdict"') < html.index('id="legend"') < html.index("1. Summary")
        assert card.count("<li>") == len(v["steps"]) and "Severity" not in html
        for s in v["steps"]:
            assert str(markupsafe.escape(s["text"])) in card
            for x in s["citations"]:
                assert str(markupsafe.escape(x["text"])) in card
    # rich: the alert's own connection is the cause of a.exe's T1 link, so "Not proven" names a link.
    # causal (no layer 2, 3 steps): CHANGED ON PURPOSE (review fix 1; it was "no Not proven line"):
    # the card still says what the steps do not prove
    assert rich_c[3]["verdict"]["not_proven"]["id"] is not None
    v = causal_c[3]["verdict"]
    assert len(v["steps"]) >= 2 and v["not_proven"] == {"text": report.NO_LINK_TEXT, "id": None, "band": None, "more": 0}
    assert v["not_proven"]["text"] == "that one step caused the next; each step is recorded on its own."
    assert "? Not proven:</strong> " + v["not_proven"]["text"] in causal_c[4].split('id="verdict"')[1].split('id="legend"')[0]


def test_one_step_and_no_link_says_nothing_unproven(causal_c):
    db, alert, G, _, _ = causal_c
    one = dataclasses.replace(alert, evidence=(key(db, 10),))          # kid's start only: one step
    c = report.build(one, G)
    assert len(c["verdict"]["steps"]) == 1 and c["verdict"]["not_proven"] is None


def test_cant_see_prefers_a_gap_at_the_chain(causal_c):
    db, alert, G, c, _ = causal_c
    # as built, no gap touches the chain: the "Before this" gap (explorer.exe's parent) is named
    assert c["verdict"]["cant_see"]["id"] == c["gaps"][0]["id"] and c["gaps"][0]["placement"] == "before"
    # once the alert also cites the creation of nohash.exe, ITS gap touches the chain and wins
    wider = dataclasses.replace(alert, evidence=alert.evidence + (key(db, 13),))
    w = report.build(wider, G)
    (gap,) = [g for g in w["gaps"] if g["kind"] == "content_unknown"]
    assert w["gaps"][0]["placement"] == "before" and w["gaps"][0]["id"] != gap["id"]   # not simply the first gap
    assert w["verdict"]["cant_see"]["id"] == gap["id"] and w["verdict"]["cant_see"]["text"].startswith(gap["plain"])


def test_the_summary_proven_line_names_the_steps(rich_c, causal_c):
    for db, alert, G, c, _ in (rich_c, causal_c):
        p, n = c["summary_lines"][1], c["counts"]["steps"]
        shown = len(p["facts"])
        want = ("the one numbered step" if n == 1 else f"all {n} numbered steps" if n == shown else
                f"the first {shown} of the {n} numbered steps")
        assert f"({shown} of {len(c['facts'])} facts: {want}; each cites recorded events, see section 4)." in p["text"]
    db, alert, G, _, _ = rich_c
    many = dataclasses.replace(alert, evidence=tuple(key(db, r) for r in (10, 11, 20, 21, 12, 31)))
    c = report.build(many, G)
    assert c["counts"]["steps"] > 3
    assert f"(3 of {len(c['facts'])} facts: the first 3 of the {c['counts']['steps']} numbered steps;" \
        in c["summary_lines"][1]["text"]


def test_identical_chain_sentences_make_one_step(rich_c):
    db, alert, G, _, _ = rich_c
    twice = dataclasses.replace(alert, evidence=(key(db, 120), key(db, 121)))  # two of x.exe's 25 equal connections
    c = report.build(twice, G)
    chain = [f for f in c["facts"] if f["in_chain"]]
    assert len(chain) == 2 and chain[0]["sentence"] == chain[1]["sentence"] and chain[0]["id"] != chain[1]["id"]
    assert [s["id"] for s in c["verdict"]["steps"]] == [chain[0]["id"]] and c["counts"]["steps"] == 1
    invariants(c, twice, view_of(twice, G))


def test_more_steps_than_the_card_holds_are_counted_not_hidden(causal_c, monkeypatch):
    _, alert, G, _, _ = causal_c
    monkeypatch.setattr(report, "MAX_STEPS", 2)
    c = report.build(alert, G)
    v = c["verdict"]
    assert len(v["steps"]) == 2 and v["steps_more"] == 1 and c["counts"]["steps"] == 3
    assert v["proven"]["ids"] == [s["id"] for s in v["steps"]]
    assert v["proven"]["text"] == ("2 numbered steps (and 1 more in section 4), each one stated by a recorded event, "
                                   "or by an exact match between two records.")
    assert "and 1 more step(s) in section 4" in report.render(c).split('id="verdict"')[1].split('id="legend"')[0]
    invariants(c, alert, view_of(alert, G))


def test_a_chain_less_alert_says_so(rich_c):
    db, alert, G, _, _ = rich_c
    none = dataclasses.replace(alert, evidence=(key(db, 13),))     # child.exe's end: no fact cites it
    c = report.build(none, G)
    assert c["verdict"]["steps"] == [] and c["verdict"]["proven"]["text"] == "no recorded fact cites the alert's own events."
    assert c["layout"]["t0_from"] == "first timed row"


# -- short -------------------------------------------------------------------------------------------------
def test_short_drops_the_pid_only_when_the_name_is_unique_in_the_view(causal_c):
    _, alert, G, c, _ = causal_c
    H = view_of(alert, G)
    assert sum(1 for _, d in G.nodes(data=True) if d.get("label") == "other.exe") == 2      # two in the graph ...
    assert sum(1 for _, d in H.nodes(data=True) if d.get("label") == "other.exe") == 1      # ... one in the view
    shorts = {f["short"] for f in c["facts"]}
    assert "loader.exe started other.exe" in shorts                       # unique in the VIEW: no PID
    assert {"loader.exe started dup.exe (PID 31)", "loader.exe started dup.exe (PID 32)"} <= shorts
    for f in c["facts"]:
        assert re.search(r"\(PID \d+\)", f["sentence"])                 # `sentence` never changes
    assert all(f["sentence"] == report.sentence(H, f["u"], f["v"], f["kind"]) for f in c["facts"])


def test_the_marker_fact_keeps_its_sentence_but_its_short_form_claims_no_download(rich_c):
    c = rich_c[3]
    (m,) = [f for f in c["facts"] if f["kind"] == "download_marker"]
    assert m["sentence"].endswith("as downloaded")                      # debate 10's sentence, unchanged
    assert not CLAIM.search(m["short"]) and "mark-of-the-web" in m["short"] and "own statement" in m["short"]


# -- icons ---------------------------------------------------------------------------------------------------
def test_created_is_a_neutral_item_unless_its_fingerprint_proves_a_file(rich_c, tmp_path):
    db, _, _, c, _ = rich_c
    created = [f for f in c["facts"] if f["kind"] == "created"]
    proven = [f for f in created if f["icon"] == "file-created"]
    assert proven and any(f["icon"] == "item-created" for f in created)  # run.exe's fingerprint failed
    for f in proven:
        ic = f["icon_citation"]
        assert ic["event"] == "FILE_HASH" and db.execute("SELECT 1 FROM events WHERE dedup_key = ?", (ic["key"],)).fetchone()
    con, alert, G = s1_like(tmp_path)
    s1 = report.build(alert, G)                                          # tool.exe: no fingerprint at all
    assert [f["icon"] for f in s1["facts"] if f["kind"] == "created"] == ["item-created"]
    assert report.EDGE_ICONS["download_marker"] == "mark" and report.EDGE_ICONS["created"] == "item-created"
    assert {h["icon"] for h in c["hypotheses"]} == {"suspected"} and {g["icon"] for g in c["gaps"]} == {"unknown"}


# -- layout --------------------------------------------------------------------------------------------------
def test_one_lane_per_program_and_things_in_their_first_actors_lane(causal_c):
    _, alert, G, c, _ = causal_c
    H = view_of(alert, G)
    lay = c["layout"]
    nodes = {n["id"]: n for n in lay["nodes"]}
    procs = [n for n in lay["nodes"] if n["kind"] == "process"]
    assert len({n["lane"] for n in procs}) == len(procs)                 # each program its own lane
    assert sorted(procs, key=lambda n: n["order"]) == sorted(procs, key=lambda n: n["lane"])
    assert [l["lane"] for l in lay["lanes"]] == list(range(len(lay["lanes"])))
    for e in lay["edges"]:
        u, v, d = next((u, v, d) for u, v, k, d in H.edges(keys=True, data=True) if report.edge_id(u, v, k) == e["id"])
        actor = report._actor_of(H, u, v, d)
        assert e["lane"] == nodes[actor]["lane"]
    items = item_by_id(c)
    for n in lay["nodes"]:
        touching = [t["order"] for t in rows_by_order(c)
                    if n["id"] in (items[t["id"]].get("u"), items[t["id"]].get("v"), items[t["id"]].get("node_id"))]
        assert n["order"] == (min(touching) if touching else None)
    kid = next(n for n in procs if n["short"] == "kid.exe")
    out = next(n for n in lay["nodes"] if n["short"] == "out.exe")
    assert out["lane"] == kid["lane"] and out["icon"] == "file"


# -- named alert citations -----------------------------------------------------------------------------------
def test_the_alerts_own_citations_are_named(rich_c):
    db, alert, G, c, html = rich_c
    cites = c["alert"]["citations"]
    assert [x["key"] for x in cites] == list(alert.evidence)
    for x in cites:
        row = db.execute("SELECT event_id, record_id FROM events WHERE dedup_key = ?", (x["key"],)).fetchone()
        assert (x["event"], x["record"]) == tuple(row) and x["text"] == f"{report.event_name(row[0])}, record {row[1]}"
    sec2 = html.split("2. The alert and why it fired")[1].split("3. Timeline")[0]
    assert all(str(markupsafe.escape(x["text"])) in sec2 for x in cites)
    lost = dataclasses.replace(alert, evidence=alert.evidence + ("not-in-the-graph",))
    assert report.build(lost, G)["alert"]["citations"][-1]["text"] == "a recorded event the evidence graph does not place"


# -- the stream ----------------------------------------------------------------------------------------------
def _alert(i, level, t):
    return Alert(f"r{i}", f"Rule {i}", "sigma", level, f"2026-10-20T10:0{t}:00.000Z", "PC", "x", (f"k{i}",))


def test_the_stream_applies_the_frozen_floor_and_names_each_alert():
    rows = [_alert(i, lvl, i) for i, lvl in enumerate(LEVELS)]           # one alert at every level
    p = stream_payload(rows)
    floor = LEVELS.index(config.min_level())
    shown = [a for a in rows if LEVELS.index(a.level) >= floor]
    assert 0 < len(shown) < len(rows)                                    # the floor really drops some here
    assert p["min_level"] == config.min_level() and p["alerts"] == len(shown) and p["below_floor"] == len(rows) - len(shown)
    assert p["counts"] == {lvl: sum(1 for a in shown if a.level == lvl) for lvl in LEVELS[floor:]}
    assert [x["id"] for x in p["items"]] == [a.alert_id for a in sorted(shown, key=lambda a: a.time, reverse=True)]
    for x in p["items"]:
        assert set(x) == {"id", "title", "level", "time"}
    assert p["latest"] == p["items"][0]
    assert stream_payload([])["latest"] is None


def test_the_stream_endpoint_sends_the_payload(tmp_path, monkeypatch):
    import engine.dashboard.app as dash_app
    monkeypatch.setattr(dash_app, "STREAM_ROUNDS", 1)                   # one check, then the stream ends
    con, alert, G = s1_like(tmp_path)
    con.close()
    below = Alert("low.rule", "A low one", "sigma", "low", alert.time, alert.host, "x", alert.evidence)
    c = dash(tmp_path, (None, alert, G), extra_alerts=[below])
    with c.stream("GET", "/api/stream") as r:
        line = next(l for l in r.iter_lines() if l.startswith("data: "))
    msg = json.loads(line[len("data: "):])
    assert msg["alerts"] == 1 and msg["below_floor"] == 1 and msg["items"][0]["title"] == alert.title


# -- polish: two-tier coincidence text, "within 0.1 s", red only for the alert level --------------------------
def test_the_short_coincidence_line_takes_its_figure_from_per_thousand(rich_c):
    c = rich_c[3]
    cfg = C.load_config()
    seen = set()
    for h in c["hypotheses"]:
        s = h["chance_short"]
        formula = h["row"] in report.TIMING_ROWS and h["assessable"] and h["basis"] in (None, "formula")
        if not formula:
            assert s is None, h["sentence"]                             # marker-graded / can't assess: no line
            continue
        k = report.per_thousand(h["p"], cfg)
        assert s.startswith(f"Timing alone: {report.BAND_GLOSS[h['band']]}. ")
        assert f"about {k} times" in s or f"{k} times" in s
        if h["n_causes"] > 1:                                           # review fix 7: the full line's words
            assert (f"in the {cfg.window:g} s window around at least one of its {h['n_causes']} "
                    f"{'incoming connection' if h['row'] == 'T2' else 'connection'}s in the "
                    f"{cfg.competing_span_seconds / 60:g} minutes either side by chance") in s
        assert len(re.findall(r"\d[\d,.]*", s.replace(f"{cfg.window:g} s", "").replace(f"its {h['n_causes']} ", "")
                              .replace(f"the {cfg.competing_span_seconds / 60:g} minutes", ""))) \
            == len(re.findall(r"\d[\d,.]*", k))                          # no figure other than per_thousand's
        if h["row"] == "T1" and not h["lead_only"] and h["p1"] >= cfg.band_high:
            # j2-a16 measured T1 over-cautious only where p1 is in the medium or low band
            assert s.endswith("This estimate leans toward calling it coincidence.")
            seen.add("lean")
        elif h["row"] == "T1" and not h["lead_only"]:
            assert s.endswith("even when nothing is linked.") and "leans" not in s     # high p1: never measured
            seen.add("unmeasured")
        else:
            assert "leans" not in s and s.endswith("That is the formula's figure; real use gives more.")
            seen.add("lead")
    assert seen == {"lean", "lead", "unmeasured"}


def test_no_lean_on_a_provisional_graph(rich_c):
    _, alert, G, _, _ = rich_c
    H = G.copy()
    for *_, d in H.edges(data=True):
        if d.get("row") in report.TIMING_ROWS:
            d["provisional"] = True
    c = report.build(alert, H)
    assert any(h["chance_short"] for h in c["hypotheses"])
    assert not any("leans" in (h["chance_short"] or "") for h in c["hypotheses"])


def test_the_full_line_is_folded_under_the_short_one(rich_c):
    c, html = rich_c[3], rich_c[4]
    h = next(h for h in c["hypotheses"] if h["chance_short"])
    full = next(l["text"] for l in h["plain"] if l["label"].startswith("How often"))
    folded = "".join(re.findall(r"<details\b.*?</details>", html, re.S))
    assert str(markupsafe.escape(full)) in folded and str(markupsafe.escape(h["chance_short"])) in html


def test_a_gap_under_a_tenth_of_a_second_reads_within_0_1_s(rich_c):
    _, alert, G, _, _ = rich_c
    H = G.copy()
    for *_, d in H.edges(data=True):
        if d.get("row") == "T1" and d.get("basis") == "formula" and d.get("effect", {}).get("time"):
            tc = parse_time(d["cause"]["time"])
            d["effect"] = {**d["effect"], "time": (tc + timedelta(milliseconds=9)).isoformat()}
    c = report.build(alert, H)
    whys = [next(l["text"] for l in h["plain"] if l["label"] == "Why we think so") for h in c["hypotheses"] if h["row"] == "T1"
            and h["basis"] == "formula"]
    assert whys and all(" within 0.1 s after it connected to " in w and "0.0 s" not in w for w in whys)
    assert report.offset_text(0.009) == report.offset_text(-0.04) == "within 0.1 s"
    assert report.offset_text(0.06) == "+0.1 s" and report.offset_text(-0.5) == "0.5 s before" and report.offset_text(None) is None


def test_red_is_only_the_alert_level(rich_c):
    html = rich_c[4]
    style = re.sub(r"/\*.*?\*/", "", html.split("<style>")[1].split("</style>")[0], flags=re.S)
    reds = re.findall(r"#b42318|#d92d20|#f04438|\bred\b", style, re.I)
    assert reds == ["#b42318"] and "--alert:#b42318" in style
    rules = [r.strip() for r in re.findall(r"([^{}]+)\{[^}]*var\(--alert\)[^}]*\}", style)]
    assert rules == [".level"]
    assert f'<span class="level">Alert level: {rich_c[1].level}</span>' in html
    for band in ("high", "medium", "low"):
        rule = re.search(r"\.band\." + band + r"\s*\{([^}]*)\}", style).group(1)
        assert "background" not in rule and "border-style" in rule


# -- the frozen code stays byte-identical ------------------------------------------------------------------
def test_frozen_engine_paths_are_unchanged():
    import subprocess
    try:
        out = subprocess.run(["git", "diff", "--name-only", "freeze-v4", "--", "engine", "tools", "config", "rules",
                              "scenarios", "agent", "statusapp"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git not available")
    if out.returncode != 0:
        pytest.skip("tag freeze-v4 not in this checkout")
    changed = [p for p in out.stdout.splitlines() if p]
    # engine/labs/ (2026-11-23, the night plan's Labs contract): NEW files only, each a read-only feature of its
    # own; the folder did not exist at freeze-v4, so nothing frozen can change by being listed here
    # tools/predemo_check.py (2026-11-25, night 2): a NEW read-only readiness check (GETs, showvminfo, registry
    # reads); it changes nothing and no frozen file depends on it
    allowed = ("engine/report.py", "engine/templates/", "engine/dashboard/", "tools/demo_replay.py", "engine/labs/",
               "tools/predemo_check.py")
    assert [p for p in changed if not p.startswith(allowed)] == []
