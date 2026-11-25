"""Stage 11, package F: evidence graph layer 2 (hypotheses), golden tests.

Every test builds a small hand-made event set in a real EventStore, a hand-built pool of normal
rates, and checks the layer-2 edges against values computed HERE from DESIGN 4.7's formula
(so a graph that passes wrong inputs to engine/confidence.py is caught too). Written before
the code (docs/plans/reports/hypotheses.md section 4).

Active time: a machine is "active" only while recorded events are at most 60 s apart, so the
stories carry a filler process (event 16, not read by the graph) every 30 s.
"""

import math
from dataclasses import replace

import pytest

from engine import confidence as C
from engine.graph import Layer2, build_graph, facts, hypotheses, subgraph_around
from engine.store import EventStore
from test_graph import P, ROOT, agent, at, ev, file_hash, root, start

# the golden numbers below are computed by hand at burst factor 1 with every row graded by the formula;
# the frozen factor (2.5) and the leads-only rows (T2, T3) are tested separately
CFG = replace(C.load_config(), burst_factor=None, leads_only=())
BANDS = ("<60", "60-3600", ">=3600")
PP = "{A1000000-0000-0000-0000-000000000000}"          # the process under test
CC = "{A2000000-0000-0000-0000-000000000000}"          # its child
MM = "{A3000000-0000-0000-0000-000000000000}"          # a file maker
BB = "{A4000000-0000-0000-0000-000000000000}"          # a process started from a made file
QQ = "{A5000000-0000-0000-0000-000000000000}"          # some other process
FILL = "{FE000000-0000-0000-0000-000000000000}"
TOOL = r"C:\tool.exe"
F = r"C:\dl\got.exe"
R = "net:PC:10.0.0.1:443"
H = "AB" * 32                                           # a content fingerprint


def pool(**rates):
    """A pool whose rate for `kind` is the same in every lifetime band (per_program empty)."""
    per_band = {k: {b: (rates.get(k, 0.0) * 1e6, 1e6) for b in BANDS} for k in C.KINDS}
    return C.Pool({k: {} for k in C.KINDS}, per_band, C.pool_settings(CFG))


def L2(**rates):
    return Layer2(pool(**rates), CFG)


def filler(lo=0, hi=1800, step=30, host="PC"):
    return [ev(90000 + i, 16, s, host=host, ProcessGuid=FILL) for i, s in enumerate(range(lo, hi + 1, step))]


def life(guid=PP, image=TOOL, pid=9, lo=0, hi=1800, rid=2, parent=ROOT, **kw):
    return [start(rid, lo, guid, pid, image, parent, 100, **kw),
            ev(rid + 1, 5, hi, ProcessGuid=guid, ProcessId=pid, Image=image)]


def out(rid, s, guid=PP, ip="10.0.0.1", port=443, image=TOOL, pid=9, **kw):
    return ev(rid, 3, s, ProcessGuid=guid, ProcessId=pid, Image=image, Protocol="tcp", Initiated="true",
              SourceIp="10.0.2.15", SourcePort=50000, DestinationIp=ip, DestinationPort=port, **kw)


def inbound(rid, s, guid=PP, ip="10.0.0.5", local_port=50000, image=TOOL, proto="tcp"):
    return ev(rid, 3, s, ProcessGuid=guid, ProcessId=9, Image=image, Protocol=proto, Initiated="false",
              SourceIp=ip, SourcePort=40000, DestinationIp="10.0.2.15", DestinationPort=local_port)


def made(rid, s, path=F, guid=PP, image=TOOL, pid=9):
    return ev(rid, 11, s, ProcessGuid=guid, ProcessId=pid, Image=image, TargetFilename=path)


def deleted(rid, s, path, guid=QQ, image=r"C:\clean.exe", sha=None):
    return ev(rid, 26, s, ProcessGuid=guid, ProcessId=77, Image=image, TargetFilename=path,
              Hashes=f"SHA256={sha}" if sha else "-")


def child(rid, s, guid=CC, parent=PP, image=r"C:\child.exe", parent_image=TOOL, **kw):
    return start(rid, s, guid, 55, image, parent, 9, parent_image, sha="CD" * 32, **kw)


def marker(rid, s, path=F, guid=PP, url="http://10.0.0.1/x.exe", stream=":Zone.Identifier", image=TOOL, contents=None):
    text = contents if contents is not None else f"[ZoneTransfer]  ZoneId=3  HostUrl={url}"
    return ev(rid, 15, s, ProcessGuid=guid, ProcessId=9, Image=image, TargetFilename=path + stream,
              Contents=text, Hash="SHA256=" + H)


def lookup(rid, s, name, answer, guid=PP, image=TOOL):
    return ev(rid, 22, s, ProcessGuid=guid, ProcessId=9, Image=image, QueryName=name, QueryStatus=0,
              QueryResults=answer)


def graph(tmp_path, records, **kw):
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = EventStore(str(tmp_path / "g.db"))
    store.insert(records)
    return build_graph(store, **kw), store


def hyps(G, kind=None):
    return [(u, v, d) for u, v, d in hypotheses(G) if kind is None or d["kind"] == kind]


def one(G, kind):
    es = hyps(G, kind)
    assert len(es) == 1, f"{len(es)} {kind} hypotheses"
    return es[0]


def p_hand(rate, n_effects, life_seconds, n_causes):
    """DESIGN 4.7 by hand: lambda = max(pool, within-life), p1 = 1 - e^(-lambda t), p = 1 - (1 - p1)^N."""
    lam = max(rate, n_effects / life_seconds)
    p1 = -math.expm1(-lam * CFG.window)
    return -math.expm1(n_causes * math.log1p(-p1))


def band_hand(p):
    return "high" if p < 0.01 else ("medium" if p < 0.10 else "low")


def t1_story(effect_at=101, causes=(100,), rate=0.002, hi=1800, extra=()):
    m = made(20, effect_at)
    recs = [root(), *life(hi=hi), *filler(hi=hi), *[out(100 + i, s) for i, s in enumerate(causes)],
            m, file_hash(1, effect_at + 1, m, "ok", H), *extra]
    return recs


# -- T1: content_from ------------------------------------------------------------------------------
def test_t1_golden_one_cause(tmp_path):
    G, store = graph(tmp_path, t1_story(), hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert (u, v) == (R, f"file:PC:{F.lower()}|{H}") and d["grade"] == "hypothesis" and d["layer"] == 2
    assert d["row"] == "T1" and d["via"] == P(PP)
    p = p_hand(0.002, 1, 1800, 1)                              # pool 0.002 > within-life 1/1800
    assert d["p"] == pytest.approx(p) and d["band"] == band_hand(p) == "medium" and d["n_causes"] == 1
    assert d["life_seconds"] == pytest.approx(1800) and d["assessable"] is True and d["basis"] == "formula"
    assert d["lam_source"].startswith("pool:") and d["timing_band"] == d["band"]
    assert d["provisional"] is True and "burst" in d["provisional_reason"]     # burst_factor is open
    assert d["alternative"] and d["reason"] and "got.exe" in d["claim"] and "10.0.0.1:443" in d["claim"]
    assert [e["event"] for e in d["evidence"]] == [3, 11] and d["primary"]["event"] == 11
    assert d["cause"]["event"] == 3 and d["effect"]["event"] == 11 and d["support"] == []
    for e in d["evidence"]:
        assert store.db.execute("SELECT id FROM events WHERE dedup_key=?", (e["key"],)).fetchone() == (e["id"],)
    # the layer-0/1 facts are untouched and the hypothesis is not among them
    assert {d["kind"] for _, _, d in facts(G)} == {"started", "connected_to", "created"}
    s = G.graph["layer2"]
    assert s["counts"]["T1"] == {"medium": 1} and s["tested"]["T1"] == 1 and s["linked"]["T1"] == 1
    assert s["sigma_p"] == pytest.approx(p) and s["sigma_p_assessable"] == pytest.approx(p)
    assert s["provisional"] == 1 and s["not_assessable"] == 0


def test_t1_competing_causes_and_latest_cause_wins(tmp_path):
    # three connections in +-15 min; the effect at 101 is linked to the latest cause whose window
    # [c - 2, c + 10] holds it (100), and N counts all three
    G, _ = graph(tmp_path, t1_story(causes=(50, 100, 150)), hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert d["n_causes"] == 3 and d["cause"]["record_id"] == 101
    p = p_hand(0.002, 1, 1800, 3)
    assert d["p"] == pytest.approx(p) and d["band"] == band_hand(p) == "medium"
    G, _ = graph(tmp_path / "b", t1_story(causes=tuple(range(60, 141, 4))), hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert d["n_causes"] == 21 and d["band"] == "low" and d["p"] == pytest.approx(p_hand(0.002, 1, 1800, 21))


@pytest.mark.parametrize("offset,linked", [(-2.0, True), (-2.001, False), (10.0, True), (10.001, False)])
def test_t1_window_boundaries(tmp_path, offset, linked):
    G, _ = graph(tmp_path, t1_story(effect_at=100 + offset), hypotheses=L2(file=0.002))
    assert len(hyps(G, "content_from")) == (1 if linked else 0)
    assert G.graph["layer2"]["tested"]["T1"] == 1 and G.graph["layer2"]["linked"]["T1"] == (1 if linked else 0)


def test_t1_within_life_rate_wins_when_the_pool_is_quieter(tmp_path):
    G, _ = graph(tmp_path, t1_story(rate=0.0001, extra=[made(21, 500), made(22, 900)]), hypotheses=L2(file=0.0001))
    d = next(d for _, v, d in hyps(G, "content_from"))
    assert d["lam_source"] == "within-life" and d["lam"] == pytest.approx(3 / 1800)
    assert d["p"] == pytest.approx(p_hand(0.0001, 3, 1800, 1))


def test_t1_folder_is_not_an_effect_and_other_process_never_links(tmp_path):
    folder = made(20, 101, path=r"C:\dl\newdir")
    recs = [root(), *life(), *life(QQ, r"C:\q.exe", 77, rid=4), *filler(), out(10, 100),
            folder, file_hash(1, 101.5, folder, "directory"), made(21, 102, guid=QQ, image=r"C:\q.exe", pid=77)]
    G, _ = graph(tmp_path, recs, hypotheses=L2(file=0.002))
    assert hyps(G) == [] and G.graph["layer2"]["tested"]["T1"] == 1          # QQ's file was tested, no cause


def test_t1_short_lived_process_is_not_assessable_and_never_high(tmp_path):
    G, _ = graph(tmp_path, t1_story(effect_at=3, causes=(2,), hi=8), hypotheses=L2(file=0.0000001))
    u, v, d = one(G, "content_from")
    assert d["assessable"] is False and d["band"] == d["timing_band"] == "low" and d["p"] == 1.0
    assert "not assessable" in d["reason"] and d["life_seconds"] == pytest.approx(8)
    s = G.graph["layer2"]
    assert s["not_assessable"] == 1 and s["sigma_p"] == 1.0 and s["sigma_p_assessable"] == 0.0


def test_t1_cause_not_in_the_graph_draws_nothing(tmp_path):
    # the latest cause (t=100) is an event 3 without an address: the Activity counts it, the graph
    # drops it. No edge, never the earlier connection instead (its window holds the effect too)
    recs = t1_story(causes=(95,))
    recs.append(ev(19, 3, 100, ProcessGuid=PP, ProcessId=9, Image=TOOL, Protocol="tcp", Initiated="true",
                   DestinationPort=443))
    G, _ = graph(tmp_path, recs, hypotheses=L2(file=0.002))
    assert hyps(G) == [] and G.graph["layer2"]["not_drawn"]["cause_not_in_graph"] == 1


def test_life_without_an_end_stops_at_the_graphs_end_time(tmp_path):
    # review finding 7: P has no event 5; other (non-graph) rows go on long after the graph's last
    # row. The Activity is loaded up to the graph's end time, so P's life ends there (101 s), not
    # at the end of the store (3000 s): the within-life rate is 1/101, not 1/3000
    m = made(20, 101)
    recs = [root(), start(2, 0, PP, 9, TOOL, ROOT, 100), *filler(hi=3000), out(100, 100), m, file_hash(1, 102, m, "ok", H)]
    G, _ = graph(tmp_path, recs, hypotheses=L2(file=0.0001))
    u, v, d = one(G, "content_from")
    assert d["life_seconds"] == pytest.approx(102) and d["lam_source"] == "within-life"
    assert d["p"] == pytest.approx(p_hand(0.0001, 1, 102, 1))


def test_t1_grades_use_only_rows_up_to_the_hosts_end_time(tmp_path):
    base = t1_story()
    G1, _ = graph(tmp_path / "a", base, hypotheses=L2(file=0.002))
    other = [ev(500, 16, 9000, host="PC2", ProcessGuid=FILL), start(501, 9001, QQ, 5, r"C:\z.exe", ROOT, host="PC2")]
    G2, _ = graph(tmp_path / "b", base + other, hypotheses=L2(file=0.002))
    d1, d2 = one(G1, "content_from")[2], one(G2, "content_from")[2]
    assert (d1["p"], d1["life_seconds"], d1["n_causes"]) == (d2["p"], d2["life_seconds"], d2["n_causes"])
    assert set(G2.graph["layer2"]["until"]) == {"PC", "PC2"}


# -- T2: remote_command ------------------------------------------------------------------------------
def t2_story(local_port=50000, proto="tcp", listen=True):
    recs = [root(), *life(image=r"C:\srv.exe"), *filler(), inbound(10, 100, local_port=local_port, proto=proto,
                                                                   image=r"C:\srv.exe"),
            child(40, 101, parent_image=r"C:\srv.exe"), ev(41, 5, 300, ProcessGuid=CC, ProcessId=55, Image=r"C:\child.exe")]
    if listen:
        recs.append(agent(1, 5, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=local_port, ProcessId=9,
                          Image=r"C:\srv.exe", ProcessStartUtc=at(0)))
    return recs


def test_t2_golden(tmp_path):
    G, _ = graph(tmp_path, t2_story(), hypotheses=L2(child=0.001))
    u, v, d = one(G, "remote_command")
    assert (u, v) == ("net:PC:10.0.0.5", P(CC)) and d["row"] == "T2" and d["via"] == P(PP)
    p = p_hand(0.001, 1, 1800, 1)
    assert d["p"] == pytest.approx(p) and d["band"] == band_hand(p) == "medium"
    assert [e["event"] for e in d["evidence"]] == [3, 1] and d["primary"]["event"] == 1
    assert "child.exe" in d["claim"] and "10.0.0.5" in d["claim"]


def test_t2_same_millisecond_rows_that_do_not_qualify_are_never_the_cause(tmp_path):
    # review finding 3: a UDP "inbound" stamped at the same millisecond as the graded TCP cause
    udp = inbound(11, 100, ip="10.9.9.9", local_port=50000, image=r"C:\srv.exe", proto="udp")
    G, _ = graph(tmp_path / "a", t2_story() + [udp], hypotheses=L2(child=0.001))
    (u, v, d) = one(G, "remote_command")
    assert u == "net:PC:10.0.0.5" and d["tied"] is False
    # the graded TCP row has no source address (not in the graph); the UDP row must not stand in
    recs = t2_story() + [udp]
    tcp = next(r for r in recs if r.get("event_id") == 3 and r["data"]["Protocol"] == "tcp")
    del tcp["data"]["SourceIp"]
    G, _ = graph(tmp_path / "b", recs, hypotheses=L2(child=0.001))
    assert hyps(G) == [] and G.graph["layer2"]["not_drawn"]["cause_not_in_graph"] == 1


def test_t2_needs_tcp_to_a_listened_or_non_ephemeral_port(tmp_path):
    assert hyps(graph(tmp_path / "a", t2_story(proto="udp"), hypotheses=L2(child=0.001))[0]) == []
    assert hyps(graph(tmp_path / "b", t2_story(listen=False), hypotheses=L2(child=0.001))[0]) == []
    assert len(hyps(graph(tmp_path / "c", t2_story(local_port=8080, listen=False), hypotheses=L2(child=0.001))[0],
                    "remote_command")) == 1


# -- T3: fetched_then_ran ----------------------------------------------------------------------------
def t3_story(child_at=102, **kw):
    return [root(), *life(), *filler(), out(10, 100), child(40, child_at, **kw),
            ev(41, 5, 300, ProcessGuid=CC, ProcessId=55, Image=r"C:\child.exe")]


def test_t3_golden_and_a_high_grade_is_provisional(tmp_path):
    G, _ = graph(tmp_path, t3_story(), hypotheses=L2(child=0.0001))
    u, v, d = one(G, "fetched_then_ran")
    assert (u, v) == (R, P(CC)) and d["row"] == "T3"
    p = p_hand(0.0001, 1, 1800, 1)                            # within-life 1/1800 > pool: 0.66 % -> high
    assert d["lam_source"] == "within-life" and d["p"] == pytest.approx(p) and d["band"] == "high"
    assert d["provisional"] is True and "child starts" in d["provisional_reason"]
    assert G.graph["layer2"]["counts"]["T3"] == {"high": 1}


def test_t3_project_child_is_not_an_activity_effect(tmp_path):
    G, _ = graph(tmp_path, t3_story(origin="project"), hypotheses=L2(child=0.0001))
    assert (P(PP), P(CC), "started") in {(u, v, d["kind"]) for u, v, d in facts(G)}   # include_project=True
    assert hyps(G) == [] and G.graph["layer2"]["not_drawn"]["effect_not_in_activity"] == 1


def test_project_process_is_not_in_the_activity(tmp_path):
    recs = [root(), *life(origin="project"), *filler(), out(10, 100, origin="project"),
            child(40, 102, origin="project")]
    G, _ = graph(tmp_path, recs, hypotheses=L2(child=0.0001))
    assert hyps(G) == [] and G.graph["layer2"]["not_drawn"]["process_not_in_activity"] == 1


# -- R1: same_path_unknown_content -------------------------------------------------------------------
def r1_story(hash_status="failed", file_sha=H, run_sha="BC" * 32, extra=()):
    m = made(20, 10, guid=MM, image=r"C:\maker.exe", pid=8)
    return [root(), *life(MM, r"C:\maker.exe", 8), *filler(), m, file_hash(1, 11, m, hash_status, file_sha), *extra,
            *life(BB, F, 12, lo=50, hi=60, rid=4, sha=run_sha)]


def test_r1_content_unknown_is_medium(tmp_path):
    G, _ = graph(tmp_path, r1_story(), hypotheses=L2())
    u, v, d = one(G, "same_path_unknown_content")
    assert (u, v) == (f"file:PC:{F.lower()}", P(BB)) and d["row"] == "R1" and d["band"] == "medium"
    assert d["basis"] == "rule" and d["p"] is None and d["alternative"] and "fingerprint" in d["reason"]
    assert [e["event"] for e in d["evidence"]] == [11, 1] and d["primary"]["event"] == 1


def test_r1_deleted_in_between_is_low(tmp_path):
    G, _ = graph(tmp_path, r1_story(extra=[deleted(30, 30, F)]), hypotheses=L2())
    assert one(G, "same_path_unknown_content")[2]["band"] == "low"


def test_r1_replaced_file_gives_no_link(tmp_path):
    G, _ = graph(tmp_path, r1_story(hash_status="ok", file_sha="12" * 32, run_sha="34" * 32), hypotheses=L2())
    assert hyps(G) == [] and G.graph["layer2"]["r1_replaced"] == 1


def test_r1_hidden_project_recreation_still_means_replaced(tmp_path):
    # a project process re-created the path after the maker (hidden by include_project=False):
    # the blocker comes from ALL rows, so R1 is not drawn from the maker's creation
    again = made(21, 20, guid=QQ, image=r"C:\claude.exe", pid=77)
    again["origin"] = "project"
    G, _ = graph(tmp_path, r1_story(extra=[again, file_hash(2, 21, again, "ok", "35" * 32)]),
                 hypotheses=L2(), include_project=False)
    assert hyps(G) == [] and G.graph["layer2"]["not_drawn"]["latest_creation_hidden"] == 1


def test_r1_equal_content_is_only_the_layer1_fact(tmp_path):
    G, _ = graph(tmp_path, r1_story(hash_status="ok", file_sha=H, run_sha=H), hypotheses=L2())
    assert hyps(G) == [] and any(d["kind"] == "ran_as" for _, _, d in facts(G))


def test_r1_latest_creation_wins_and_window_applies(tmp_path):
    early = made(21, 5, guid=QQ, image=r"C:\q.exe", pid=77)
    G, _ = graph(tmp_path, r1_story(extra=[early, file_hash(2, 6, early, "ok", "45" * 32)]), hypotheses=L2())
    u, v, d = one(G, "same_path_unknown_content")
    assert u == f"file:PC:{F.lower()}" and d["evidence"][0]["record_id"] == 20        # the maker's, at t=10
    late = r1_story()
    for r in late:
        if r.get("event_id") == 11 or r.get("type") == "FILE_HASH":
            r["time"] = r["time"].replace("10:00:1", "11:00:1")
            if "UtcTime" in r["data"]:
                r["data"]["UtcTime"] = r["data"]["UtcTime"].replace("10:00:1", "11:00:1")
            if r.get("type") == "FILE_HASH":
                r["data"]["ref_time"] = r["data"]["ref_time"].replace("10:00:1", "11:00:1")
    G, _ = graph(tmp_path / "b", late, hypotheses=L2())
    assert hyps(G) == []                                                      # created after the start


def test_placeholder_hash_is_never_a_fact_even_at_layer_1(tmp_path):
    for sha in (C.EMPTY_SHA256, "A" * 64):
        G, _ = graph(tmp_path / sha[:3], r1_story(hash_status="ok", file_sha=sha, run_sha=sha), hypotheses=L2())
        assert not any(d["kind"] == "ran_as" for _, _, d in facts(G))
        assert one(G, "same_path_unknown_content")[2]["band"] == "medium"
    G, _ = graph(tmp_path / "off", r1_story(hash_status="ok", file_sha=C.EMPTY_SHA256, run_sha=C.EMPTY_SHA256))
    assert not any(d["kind"] == "ran_as" for _, _, d in facts(G))


# -- R2: same_content (fact) + copy_of (hypothesis) ------------------------------------------------------
X = r"C:\dl\tool.exe"
Y = r"C:\temp\tool.exe"


def r2_story(y_created=True, y_hash="ok", extra=(), x_hash_at=11):
    x = made(20, 10, path=X, guid=MM, image=r"C:\maker.exe", pid=8)
    recs = [root(), *life(MM, r"C:\maker.exe", 8), *filler(), x, file_hash(1, x_hash_at, x, "ok", H), *extra]
    if y_created:
        y = made(21, 20, path=Y, guid=MM, image=r"C:\maker.exe", pid=8)
        recs += [y, file_hash(2, 21, y, y_hash, H)]
    recs += life(BB, Y, 12, lo=30, hi=40, rid=4, sha=H)
    return recs


def test_r2_golden_copy_direction_high(tmp_path):
    G, _ = graph(tmp_path, r2_story(), hypotheses=L2())
    xf, yf = f"file:PC:{X.lower()}|{H}", f"file:PC:{Y.lower()}|{H}"
    same = [(u, v, d) for u, v, d in facts(G) if d["kind"] == "same_content"]
    assert [(u, v) for u, v, _ in same] == [(xf, P(BB))] and same[0][2]["layer"] == 2
    assert [e["event"] for e in same[0][2]["evidence"]] == ["FILE_HASH", 1]
    assert any(d["kind"] == "ran_as" for _, _, d in facts(G))                 # Y fingerprinted: layer 1 too
    u, v, d = one(G, "copy_of")
    assert (u, v) == (xf, yf) and d["row"] == "R2" and d["band"] == "high" and "1 other path" in d["reason"]
    assert [e["event"] for e in d["evidence"]] == ["FILE_HASH", 11, 1]


def test_r2_no_recorded_creation_of_y_is_fact_only(tmp_path):
    G, _ = graph(tmp_path, r2_story(y_created=False), hypotheses=L2())
    assert len([d for _, _, d in facts(G) if d["kind"] == "same_content"]) == 1 and hyps(G, "copy_of") == []
    assert "no recorded creation" in next(iter(G.graph["layer2"]["r2_no_direction"]))


@pytest.mark.parametrize("extra,why", [
    ([deleted(30, 15, X, sha=H)], "X was deleted"),
    ([ev(31, 4, 15, ProcessGuid="{00000000-0000-0000-0000-000000000000}")], "Sysmon restarted"),
    ([deleted(32, 25, Y, sha=H)], "Y was deleted"),
])
def test_r2_blockers_leave_the_fact_without_a_direction(tmp_path, extra, why):
    G, _ = graph(tmp_path, r2_story(extra=extra), hypotheses=L2())
    assert hyps(G, "copy_of") == [] and any(why in k for k in G.graph["layer2"]["r2_no_direction"])
    assert len([d for _, _, d in facts(G) if d["kind"] == "same_content"]) == 1


def test_r2_y_created_before_x_fingerprint_is_fact_only(tmp_path):
    G, _ = graph(tmp_path, r2_story(x_hash_at=25), hypotheses=L2())            # Y created at 20, X proven at 25
    assert hyps(G, "copy_of") == [] and len([d for _, _, d in facts(G) if d["kind"] == "same_content"]) == 1


def test_r2_x_known_only_from_a_deletion_is_fact_only(tmp_path):
    recs = [root(), *life(MM, r"C:\maker.exe", 8), *filler(), deleted(30, 5, X, sha=H),
            *life(BB, Y, 12, lo=30, hi=40, rid=4, sha=H)]
    G, _ = graph(tmp_path, recs, hypotheses=L2())
    assert len([d for _, _, d in facts(G) if d["kind"] == "same_content"]) == 1 and hyps(G, "copy_of") == []


def test_r2_several_sources_and_the_path_count(tmp_path):
    z = made(22, 12, path=r"C:\other\tool.exe", guid=MM, image=r"C:\maker.exe", pid=8)
    G, _ = graph(tmp_path, r2_story(extra=[z, file_hash(3, 13, z, "ok", H)]), hypotheses=L2())
    es = hyps(G, "copy_of")
    assert len(es) == 2 and {d["band"] for _, _, d in es} == {"medium"}       # 2 other paths hold H
    assert len([d for _, _, d in facts(G) if d["kind"] == "same_content"]) == 2


def test_r2_path_count_includes_hidden_copies(tmp_path):
    # review finding 5: a copy made by a project process (hidden by include_project=False) still
    # counts as a path holding the content, so the direction stays medium, never high
    z = made(22, 12, path=r"C:\other\tool.exe", guid=QQ, image=r"C:\claude.exe", pid=77)
    z["origin"] = "project"
    zh = file_hash(3, 13, z, "ok", H)
    zh["origin"] = "project"
    G, _ = graph(tmp_path, r2_story(extra=[z, zh]), hypotheses=L2(), include_project=False)
    assert {d["band"] for _, _, d in hyps(G, "copy_of")} == {"medium"}


def test_r2_constant_hash_or_other_host_gives_nothing(tmp_path):
    recs = r2_story()
    for r in recs:
        if r.get("type") == "FILE_HASH":
            r["data"]["sha256"] = C.EMPTY_SHA256
        if r.get("event_id") == 1 and r["data"]["ProcessGuid"] == BB:
            r["data"]["Hashes"] = "SHA256=" + C.EMPTY_SHA256
    G, _ = graph(tmp_path / "a", recs, hypotheses=L2())
    # no fact and no copy direction from an empty-file hash; R1 ("same path, content unknown") is right
    assert hyps(G, "copy_of") == [] and not any(d["kind"] in ("same_content", "ran_as") for _, _, d in facts(G))
    assert {d["kind"] for _, _, d in hyps(G)} == {"same_path_unknown_content"}
    recs = r2_story(y_created=False)
    for r in recs:
        if r.get("data", {}).get("ProcessGuid") == BB:
            r["host"] = "PC2"
    G, _ = graph(tmp_path / "b", recs, hypotheses=L2())
    assert not any(d["kind"] == "same_content" for _, _, d in facts(G)) and hyps(G) == []


# -- R3: name_for_connection ---------------------------------------------------------------------------
def r3_story(lookups=(("example.test", "type: 5 cname.example.test;10.0.0.1;", 90),), conn_at=100):
    return [root(), *life(), *filler(), *[lookup(50 + i, s, n, a) for i, (n, a, s) in enumerate(lookups)],
            out(10, conn_at)]


def test_r3_golden(tmp_path):
    G, _ = graph(tmp_path, r3_story(), hypotheses=L2())
    u, v, d = one(G, "name_for_connection")
    assert (u, v) == ("dns:PC:example.test", R) and d["row"] == "R3" and d["band"] == "high"
    assert [e["event"] for e in d["evidence"]] == [22, 3] and d["primary"]["event"] == 3 and d["via"] == P(PP)


def test_r3_band_by_number_of_names(tmp_path):
    two = [(f"n{i}.test", "10.0.0.1;", 90 + i) for i in range(2)]
    five = [(f"n{i}.test", "10.0.0.1;", 90 + i) for i in range(5)]
    assert {d["band"] for _, _, d in hyps(graph(tmp_path / "a", r3_story(two), hypotheses=L2())[0])} == {"medium"}
    assert {d["band"] for _, _, d in hyps(graph(tmp_path / "b", r3_story(five), hypotheses=L2())[0])} == {"low"}


def test_r3_lookup_after_by_another_process_or_too_old_gives_nothing(tmp_path):
    assert hyps(graph(tmp_path / "a", r3_story(conn_at=89), hypotheses=L2())[0]) == []
    recs = r3_story()
    recs.append(ev(99, 22, 95, ProcessGuid=QQ, ProcessId=77, Image=r"C:\q.exe", QueryName="other.test", QueryResults="10.0.0.1;"))
    assert len(hyps(graph(tmp_path / "b", recs, hypotheses=L2())[0])) == 1       # QQ's lookup never counts
    assert hyps(graph(tmp_path / "c", r3_story(conn_at=90 + CFG.competing_span_seconds + 1), hypotheses=L2())[0]) == []


def test_r3_parses_ipv4_mapped_and_skips_cnames(tmp_path):
    G, _ = graph(tmp_path, r3_story((("m.test", "type: 5 c.m.test;::ffff:10.0.0.1;", 90),)), hypotheses=L2())
    assert len(hyps(G, "name_for_connection")) == 1
    G, _ = graph(tmp_path / "b", r3_story((("m.test", "type: 5 10.0.0.1;", 90),)), hypotheses=L2())
    assert hyps(G) == []


# -- R4: started_with_file_argument --------------------------------------------------------------------
NOTE = r"C:\w\note.ps1"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def r4_story(cmd=f"powershell.exe -File {NOTE}", note_at=10, extra=()):
    n = made(20, note_at, path=NOTE, guid=MM, image=r"C:\maker.exe", pid=8)
    return [root(), *life(MM, r"C:\maker.exe", 8), *filler(), n, *extra,
            *life(BB, PS, 12, lo=20, hi=40, rid=4, CommandLine=cmd)]


@pytest.mark.parametrize("cmd,band", [
    (f"powershell.exe -File {NOTE}", "medium"), (f'"{PS}" -File "{NOTE}"', "medium"), (f"powershell -File={NOTE}", "medium"),
    ("powershell -File note.ps1", "low"), (r"powershell -File .\note.ps1", "low"),
])
def test_r4_full_path_is_medium_and_name_only_is_low(tmp_path, cmd, band):
    G, _ = graph(tmp_path, r4_story(cmd), hypotheses=L2())
    u, v, d = one(G, "started_with_file_argument")
    assert (u, v) == (f"file:PC:{NOTE.lower()}", P(BB)) and d["row"] == "R4" and d["band"] == band
    assert [e["event"] for e in d["evidence"]] == [11, 1]


@pytest.mark.parametrize("cmd", ["powershell -File mynote.ps1x", "powershell -File note.ps1.bak", f"{PS}",
                                 "powershell -Command note.ps1foo",
                                 r"powershell -File C:\elsewhere\note.ps1",            # review finding 10: another full path
                                 r"powershell -File \\server\share\note.ps1"])
def test_r4_partial_words_and_own_image_give_nothing(tmp_path, cmd):
    assert hyps(graph(tmp_path, r4_story(cmd), hypotheses=L2())[0]) == []


def test_r4_deleted_between_is_low_and_created_after_or_folder_is_nothing(tmp_path):
    G, _ = graph(tmp_path / "a", r4_story(extra=[deleted(30, 15, NOTE)]), hypotheses=L2())
    assert one(G, "started_with_file_argument")[2]["band"] == "low"
    assert hyps(graph(tmp_path / "b", r4_story(note_at=25), hypotheses=L2())[0]) == []
    recs = r4_story(cmd=r"powershell -File C:\w\note.ps1")
    n = next(r for r in recs if r.get("event_id") == 11)
    recs.append(file_hash(1, 10.5, n, "directory"))
    assert hyps(graph(tmp_path / "c", recs, hypotheses=L2())[0]) == []


# -- F1: download_marker and what it does to T1 ----------------------------------------------------------
def f1_story(url="http://10.0.0.1/x.exe", marker_guid=PP, marker_at=103, port=80, extra=(), stream=":Zone.Identifier"):
    m = made(20, 101)
    recs = [root(), *life(), *life(QQ, r"C:\q.exe", 77, rid=4), *filler(), out(10, 100, port=port), m,
            file_hash(1, 102, m, "ok", H), *extra]
    if marker_guid:
        recs.append(marker(30, marker_at, guid=marker_guid, url=url, stream=stream,
                           image=TOOL if marker_guid == PP else r"C:\q.exe"))
    return recs


def test_f1_marker_fact_and_t1_upgraded_to_a_high_hypothesis(tmp_path):
    G, store = graph(tmp_path, f1_story(), hypotheses=L2(file=0.002))
    fnode = f"file:PC:{F.lower()}|{H}"
    (m,) = [(u, v, d) for u, v, d in facts(G) if d["kind"] == "download_marker"]
    assert (m[0], m[1]) == (P(PP), fnode) and m[2]["layer"] == 2
    assert m[2]["marker_host"] == "10.0.0.1" and m[2]["marker_port"] == 80 and m[2]["marker_sha256"] == H
    assert [e["event"] for e in m[2]["evidence"]] == [15]
    u, v, d = one(G, "content_from")
    assert d["grade"] == "hypothesis" and d["band"] == "high" and d["basis"] == "download marker"
    p = p_hand(0.002, 1, 1800, 1)
    assert d["timing_band"] == "medium" and d["p"] == pytest.approx(p)        # the timing grade is untouched
    assert d["provisional"] is False and [e["event"] for e in d["support"]] == [15]
    assert "marker" in d["reason"]
    assert G.graph["layer2"]["sigma_p"] == pytest.approx(p) and G.graph["layer2"]["counts"]["T1"] == {"high": 1}
    assert G.graph["layer2"]["facts"] == {"download_marker": 1}


@pytest.mark.parametrize("url", ["http://evil.test/x.exe", "http://10.0.0.1:8080/x.exe", "https://10.0.0.1/x.exe",
                                 "http://10.0.0.1.evil.test/x.exe", "http://10.0.0.1@evil.test/x.exe",
                                 # no usable port (review finding 2): the "address AND port" check cannot pass
                                 "file://10.0.0.1/x.exe", "gopher://10.0.0.1/x", "http://10.0.0.1:99999/x.exe",
                                 "http://10.0.0.1:0/x"])          # port 0 stays 0 (fixed in main 28b8de4)
def test_f1_other_host_or_port_is_support_only(tmp_path, url):
    G, _ = graph(tmp_path, f1_story(url=url), hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert d["band"] == "medium" and d["basis"] == "formula"
    has_port = url.startswith("http") and ":99999" not in url          # port 0 is a known port that never matches
    assert [e["event"] for e in d["support"]] == ([15] if has_port else [])     # no usable port: no check at all


def test_f1_marker_hash_must_match_the_content_node(tmp_path):
    # review finding 1: the marker record vouches for the content only through its own Hash; a marker
    # long after the creation (an unrecorded overwrite in between) with another hash points at the path
    recs = f1_story(marker_at=1500)
    m = next(r for r in recs if r.get("event_id") == 15)
    m["data"]["Hash"] = "SHA256=" + "CD" * 32
    G, _ = graph(tmp_path / "a", recs, hypotheses=L2(file=0.002))
    (target,) = [v for u, v, d in facts(G) if d["kind"] == "download_marker"]
    assert target == f"file:PC:{F.lower()}" and one(G, "content_from")[2]["band"] == "medium"
    m["data"]["Hash"] = "-"
    G, _ = graph(tmp_path / "b", recs, hypotheses=L2(file=0.002))
    (target,) = [v for u, v, d in facts(G) if d["kind"] == "download_marker"]
    assert target == f"file:PC:{F.lower()}" and one(G, "content_from")[2]["band"] == "medium"


def test_f1_marker_by_a_process_seen_nowhere_else_adds_no_node(tmp_path):
    # review finding 9: layer 2 never invents a process node (a stub without its origin gap)
    recs = [root(), *life(), *filler(), marker(30, 103, guid="{A9000000-0000-0000-0000-000000000000}")]
    G, _ = graph(tmp_path, recs, hypotheses=L2())
    assert not any(d["kind"] == "download_marker" for _, _, d in facts(G))
    assert "proc:PC:{A9000000-0000-0000-0000-000000000000}" not in G
    assert G.graph["layer2"]["stats"]["markers_by_unknown_process"] == 1


def test_f1_marker_by_another_process_or_other_stream_changes_nothing(tmp_path):
    G, _ = graph(tmp_path / "a", f1_story(marker_guid=QQ), hypotheses=L2(file=0.002))
    assert one(G, "content_from")[2]["band"] == "medium" and one(G, "content_from")[2]["support"] == []
    G, _ = graph(tmp_path / "b", f1_story(stream=":other"), hypotheses=L2(file=0.002))
    assert one(G, "content_from")[2]["band"] == "medium" and not any(d["kind"] == "download_marker" for _, _, d in facts(G))


def test_f1_name_tied_by_a_high_lookup_is_high_but_medium_lookup_is_support(tmp_path):
    hi = [lookup(50, 99, "dl.test", "10.0.0.1;")]
    G, _ = graph(tmp_path / "a", f1_story(url="http://dl.test/x.exe", extra=hi), hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert d["band"] == "high" and d["basis"] == "download marker + lookup" and d["grade"] == "hypothesis"
    med = [lookup(50, 99, "dl.test", "10.0.0.1;"), lookup(51, 99.5, "cdn.test", "10.0.0.1;")]
    G, _ = graph(tmp_path / "b", f1_story(url="http://dl.test/x.exe", extra=med), hypotheses=L2(file=0.002))
    assert one(G, "content_from")[2]["band"] == "medium"


def test_f1_marker_on_a_later_creation_or_after_a_change_does_not_upgrade(tmp_path):
    # creation 1 (t=101, in the T1 window) and creation 2 (t=150) share the content-unknown node
    recs = f1_story(marker_at=151, extra=[made(21, 150)])
    recs = [r for r in recs if r.get("type") != "FILE_HASH"]
    G, _ = graph(tmp_path / "a", recs, hypotheses=L2(file=0.002))
    u, v, d = one(G, "content_from")
    assert d["band"] == "medium" and d["support"] == [] and d["effect"]["record_id"] == 20
    assert any(d["kind"] == "download_marker" for _, _, d in facts(G))
    # the file was deleted between its creation and the marker: the marker is about the path only
    G, _ = graph(tmp_path / "b", f1_story(extra=[deleted(31, 102.5, F, sha=H)]), hypotheses=L2(file=0.002))
    assert one(G, "content_from")[2]["band"] == "medium"
    (m,) = [v for u, v, d in facts(G) if d["kind"] == "download_marker"]
    assert m == f"file:PC:{F.lower()}"


def test_f1_marker_without_a_recorded_creation_points_at_the_path(tmp_path):
    recs = [root(), *life(), *filler(), marker(30, 103)]
    G, _ = graph(tmp_path, recs, hypotheses=L2())
    (m,) = [(u, v) for u, v, d in facts(G) if d["kind"] == "download_marker"]
    assert m == (P(PP), f"file:PC:{F.lower()}") and hyps(G) == []


# -- invariants and the walk -------------------------------------------------------------------------
def full_story():
    recs = t1_story(extra=[child(40, 103), lookup(50, 99, "example.test", "10.0.0.1;")])
    recs += [ev(41, 5, 300, ProcessGuid=CC, ProcessId=55, Image=r"C:\child.exe")]
    return recs


def test_layer2_only_adds_edges(tmp_path):
    G0, _ = graph(tmp_path / "a", full_story())
    G2, _ = graph(tmp_path / "b", full_story(), hypotheses=L2(file=0.002, child=0.002))
    key = lambda G: sorted((u, v, d["kind"], d["primary"]["key"]) for u, v, d in G.edges(data=True) if d["layer"] < 2)
    assert key(G0) == key(G2) and G0.graph["layers"] == (0, 1) and G2.graph["layers"] == (0, 1, 2)
    procs = lambda G: {n: dict(d) for n, d in G.nodes(data=True) if d["kind"] == "process"}
    assert procs(G0) == procs(G2) and set(G0) <= set(G2) and G0.graph["gaps"] == G2.graph["gaps"]
    assert {d["kind"] for _, _, d in hyps(G2)} == {"content_from", "fetched_then_ran", "name_for_connection"}


def test_every_hypothesis_carries_its_attributes_and_cites_stored_rows(tmp_path):
    G, store = graph(tmp_path, full_story(), hypotheses=L2(file=0.002, child=0.002))
    assert hyps(G) and not any(d["grade"] != "fact" for _, _, d in facts(G))
    for u, v, d in hyps(G):
        assert d["grade"] == "hypothesis" and d["layer"] == 2 and d["band"] in ("high", "medium", "low")
        assert d["claim"] and d["reason"] and d["alternative"] and d["row"] and len(d["evidence"]) >= 2
        assert d["time"] is not None and d["primary"]["key"] in {e["key"] for e in d["evidence"]}
        for e in d["evidence"] + d["support"]:
            assert store.db.execute("SELECT id FROM events WHERE dedup_key=?", (e["key"],)).fetchone() == (e["id"],)
        if d["row"].startswith("T"):
            assert 0 <= d["p"] <= 1 and d["n_causes"] >= 1 and d["lam_source"] and d["timing_band"]
            assert d["assessable"] or (d["timing_band"] == "low" and d["p"] == 1.0)
        else:
            assert d["p"] is None and d["basis"] == "rule"
    s = G.graph["layer2"]
    assert s["sigma_p"] == pytest.approx(sum(d["p"] for _, _, d in hyps(G) if d["p"] is not None))


def test_walk_follows_facts_only_and_shows_hypotheses_with_one_hop(tmp_path):
    # X (made by M2, who also connected somewhere; M2's parent is not B's root) is tied to B only
    # by R2: same_content X -> B (a layer-2 fact) and copy_of X -> Y. Seeded at B, the view shows X
    # as a hop but never walks on to M2 (the old all-edges walk did), and the layer-2 edges are drawn.
    M2 = "{A6000000-0000-0000-0000-000000000000}"
    x = made(22, 12, path=X, guid=M2, image=r"C:\m2.exe", pid=66)
    recs = [root(), *life(MM, r"C:\maker.exe", 8), *life(M2, r"C:\m2.exe", 66, rid=6, parent="{A7000000-0000-0000-0000-000000000000}"), *filler(),
            x, file_hash(3, 13, x, "ok", H), out(11, 14, guid=M2, image=r"C:\m2.exe", pid=66, ip="10.0.0.9")]
    y = made(21, 20, path=Y, guid=MM, image=r"C:\maker.exe", pid=8)
    recs += [y, file_hash(2, 21, y, "ok", H), *life(BB, Y, 12, lo=30, hi=40, rid=4, sha=H)]
    G, _ = graph(tmp_path, recs, hypotheses=L2())
    xf, yf = f"file:PC:{X.lower()}|{H}", f"file:PC:{Y.lower()}|{H}"
    H1 = subgraph_around(G, P(BB))
    assert xf in H1 and H1.nodes[xf]["hop"] is True and P(M2) not in H1 and "net:PC:10.0.0.9:443" not in H1
    assert {d["kind"] for _, _, d in H1.edges(data=True) if d["layer"] == 2} == {"same_content", "copy_of"}
    assert H1.graph["layer2"]["counts"]["R2"] == {"high": 1}
    assert P(MM) in H1 and H1.graph["truncated"] is False
    H2 = subgraph_around(G, P(BB), max_nodes=4)                    # B, Y, M (facts) and the root fill it
    assert xf not in H2 and H2.graph["truncated"] is True


def test_view_never_shows_another_users_links_through_a_shared_server(tmp_path):
    # review finding 4: A connects to R; an unrelated Z (another parent) connects to R 0.5 s later,
    # creates a file and starts a child. Seeded at A, the view holds R but none of Z's links
    Z, ZC = "{B1000000-0000-0000-0000-000000000000}", "{B2000000-0000-0000-0000-000000000000}"
    zf = made(21, 101, path=r"C:\z\secret.exe", guid=Z, image=r"C:\z.exe", pid=66)
    recs = [root(), *life(), *life(Z, r"C:\z.exe", 66, rid=4, parent="{B3000000-0000-0000-0000-000000000000}"), *filler(),
            out(100, 100), out(101, 100.5, guid=Z, image=r"C:\z.exe", pid=66), zf, file_hash(1, 102, zf, "ok", "EF" * 32),
            child(40, 102, guid=ZC, parent=Z, parent_image=r"C:\z.exe"), lookup(50, 99, "r.test", "10.0.0.1;", guid=Z, image=r"C:\z.exe")]
    G, _ = graph(tmp_path, recs, hypotheses=L2(file=0.002, child=0.002))
    assert {d["kind"] for _, _, d in hyps(G)} == {"content_from", "fetched_then_ran", "name_for_connection"}   # all Z's
    Hv = subgraph_around(G, P(PP))
    assert R in Hv and not any(n in Hv for n in (P(Z), P(ZC), "dns:PC:r.test")) and not any("secret" in n for n in Hv)
    assert [d for _, _, d in Hv.edges(data=True) if d["layer"] == 2] == [] and Hv.graph["layer2"]["counts"] == {}


def test_download_marker_event_can_seed_a_view(tmp_path):
    G, store = graph(tmp_path, f1_story(), hypotheses=L2(file=0.002))
    key = store.db.execute("SELECT dedup_key FROM events WHERE record_id=30").fetchone()[0]   # the event 15
    assert P(PP) in subgraph_around(G, key)


def test_event_seed_shared_by_a_fact_and_a_hypothesis_resolves_to_the_fact(tmp_path):
    G, store = graph(tmp_path, t1_story(), hypotheses=L2(file=0.002))
    key = store.db.execute("SELECT dedup_key FROM events WHERE record_id=20").fetchone()[0]   # the event 11
    Hs = subgraph_around(G, key)
    assert P(PP) in Hs and Hs.graph["seed"] == key                  # the creator, not the endpoint, is walked back


# -- the false-fact attack: none of these may add a fact that one record does not state -------------------
def assert_no_false_fact(G, store):
    for u, v, d in facts(G):
        if d["layer"] < 2:
            continue
        assert d["kind"] in ("same_content", "download_marker"), d["kind"]
        if d["kind"] == "same_content":
            assert G.nodes[u]["host"] == G.nodes[v]["host"]
            assert G.nodes[u]["sha256"] == G.nodes[v]["sha256"] and not C.constant_hash(G.nodes[u]["sha256"])
        else:
            assert [e["event"] for e in d["evidence"]] == [15] and u in G and G.nodes[u]["kind"] == "process"
            if G.nodes[v]["sha256"]:                     # a content node only when the record's own hash is it
                assert d["marker_sha256"] == G.nodes[v]["sha256"]
        for e in d["evidence"]:
            assert store.db.execute("SELECT 1 FROM events WHERE dedup_key=?", (e["key"],)).fetchone()
    assert not any(d["kind"] == "content_from" for _, _, d in facts(G))


def _twice(recs):
    """Every row once more under another record id / seq (the store keeps both)."""
    out_ = []
    for r in recs:
        c = {**r, "data": dict(r["data"])}
        if "record_id" in c:
            c["record_id"] += 1000
        else:
            c["seq"] += 1000
        out_.append(c)
    return recs + out_


@pytest.mark.parametrize("name,recs", [
    ("forged host", f1_story(url="http://10.0.0.1/x.exe", marker_guid=QQ)),
    ("other port", f1_story(url="http://10.0.0.1:9/x.exe")),
    ("outside window", f1_story(extra=[made(21, 500)], marker_at=501)),
    ("duplicate rows", _twice(f1_story())),
    ("late marker, other hash", [dict(r, data={**r["data"], "Hash": "SHA256=" + "12" * 32}) if r.get("event_id") == 15 else r
                                 for r in f1_story(marker_at=1500)]),
    ("placeholder content", r2_story(y_hash="ok")),
    ("empty command line", r4_story(cmd="")),
    ("marker without host", f1_story(url="")),
])
def test_false_fact_attack(tmp_path, name, recs):
    if name == "placeholder content":
        for r in recs:
            if r.get("type") == "FILE_HASH":
                r["data"]["sha256"] = "0" * 64
            if r.get("event_id") == 1 and r["data"]["ProcessGuid"] == BB:
                r["data"]["Hashes"] = "SHA256=" + "0" * 64
    G, store = graph(tmp_path, recs, hypotheses=L2(file=0.002, child=0.002))
    assert_no_false_fact(G, store)


def test_false_fact_attack_out_of_order_rows_and_other_host(tmp_path):
    recs = list(reversed(f1_story()))
    G, store = graph(tmp_path / "a", recs, hypotheses=L2(file=0.002))
    assert_no_false_fact(G, store)
    assert one(G, "content_from")[2]["band"] == "high"
    recs = r2_story()
    for r in recs:
        if r.get("event_id") == 11 and r["data"]["TargetFilename"] == X or (r.get("type") == "FILE_HASH" and r["data"]["TargetFilename"] == X):
            r["host"] = "PC2"
    G, store = graph(tmp_path / "b", recs, hypotheses=L2())
    assert_no_false_fact(G, store)
    assert hyps(G, "copy_of") == [] and not any(d["kind"] == "same_content" for _, _, d in facts(G))


# -- plumbing ------------------------------------------------------------------------------------------
def test_pool_file_round_trip_and_cli(tmp_path, capsys):
    path = tmp_path / "pool.json"
    sha = pool(file=0.002).save(str(path))
    l2 = Layer2.from_pool_file(str(path), CFG)
    G, _ = graph(tmp_path, t1_story(), hypotheses=l2)
    assert one(G, "content_from")[2]["band"] == "medium" and l2.pool_sha256 == sha
    from engine.graph import main
    main(["--db", str(tmp_path / "g.db"), "--pool", str(path)])
    out_ = capsys.readouterr().out
    assert "hypotheses" in out_ and "sigma_p" in out_


def test_empty_store_with_layer2(tmp_path):
    G, _ = graph(tmp_path, [], hypotheses=L2())
    assert hyps(G) == [] and G.graph["layer2"]["sigma_p"] == 0.0

def test_frozen_settings_make_t3_a_lead_and_timing_grades_final(tmp_path):
    """Package J (2026-10-24): with the frozen burst factor (2.5) and T2/T3 leads only, the T3
    story above is graded LOW (it was high at factor 1) and nothing is provisional any more."""
    G, _ = graph(tmp_path, t3_story(), hypotheses=Layer2(pool(child=0.0001), C.load_config()))
    u, v, d = one(G, "fetched_then_ran")
    assert d["band"] == "low" and d["provisional"] is False and "lead only" in d["reason"]
    assert d["p"] == pytest.approx(-math.expm1(-2.5 * 12 / 1800))     # within-life rate x 2.5 over 12 s: 1.65 %
