"""Stage 9: evidence graph layers 0-1 (facts and gaps only), golden tests.

Each test builds a small hand-made event set whose correct graph is known, stores it in a real
EventStore (the graph is always built from the store, as in production) and checks the graph.
"""

import os
from datetime import timedelta

import yaml

from engine.graph import ZERO_GUID, build_graph, facts, parse_time, subgraph_around, timeline
from engine.store import EventStore

HERE = os.path.dirname(os.path.abspath(__file__))
CH = "Microsoft-Windows-Sysmon/Operational"
T0 = "2026-10-20 10:00:00.000"


def at(seconds):
    """UtcTime `seconds` after T0, in Sysmon's own format."""
    t = parse_time(T0) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def ev(record_id, event_id, seconds, origin="normal", host="PC", **data):
    """A Sysmon event as the agent records it; the record time is a little after UtcTime."""
    t = parse_time(at(seconds)) + timedelta(milliseconds=5)
    data = {"UtcTime": at(seconds), **data}
    return {"host": host, "label": "host", "session": "s1", "source": "sysmon", "channel": CH,
            "record_id": record_id, "event_id": event_id, "provider": "Microsoft-Windows-Sysmon",
            "time": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z", "origin": origin, "data": data}


def start(record_id, seconds, guid, pid, image, parent_guid, parent_pid=1, parent_image=r"C:\p.exe",
          sha="A1", **kw):
    return ev(record_id, 1, seconds, ProcessGuid=guid, ProcessId=pid, Image=image,
              ParentProcessGuid=parent_guid, ParentProcessId=parent_pid, ParentImage=parent_image,
              Hashes=f"SHA256={sha}", **kw)


def agent(seq, seconds, type_, origin="normal", **data):
    t = parse_time(at(seconds))
    return {"host": "PC", "label": "host", "session": "s1", "source": "agent", "seq": seq,
            "type": type_, "time": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z", "origin": origin, "data": data}


def file_hash(seq, seconds, created, status="ok", sha="B1"):
    """A FILE_HASH for the event 11 `created`, exactly as agent/main.py emits it."""
    return agent(seq, seconds, "FILE_HASH", TargetFilename=created["data"]["TargetFilename"],
                 ProcessGuid=created["data"]["ProcessGuid"], hash_status=status,
                 sha256=sha if status == "ok" else None, size=10 if status == "ok" else None,
                 ref_record_id=created["record_id"], ref_time=created["time"])


def graph(tmp_path, records, **kw):
    store = EventStore(str(tmp_path / "g.db"))
    store.insert(records)
    return build_graph(store, **kw), store


def P(guid):
    return f"proc:PC:{guid}"


def edges(G, kind=None):
    return {(u, v, d["kind"]) for u, v, d in facts(G) if kind is None or d["kind"] == kind}


def gaps(G, kind=None):
    return [g for g in G.graph["gaps"] if kind is None or g["kind"] == kind]


ROOT = "{10000000-0000-0000-0000-000000000000}"   # a process whose own start we also record


def root():
    return start(1, 0, ROOT, 100, r"C:\Windows\explorer.exe", ZERO_GUID, parent_image="-")


# -- layer 0: process tree ------------------------------------------------------------------------
def test_reused_pid_with_different_guids_is_not_linked(tmp_path):
    # Two different programs get PID 500 one after the other; the child names the SECOND as its
    # parent (by GUID). Linking by PID would wrongly pick the first.
    a, b, child = "{A0000000-0000-0000-0000-000000000000}", "{B0000000-0000-0000-0000-000000000000}", "{C0000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [
        root(),
        start(2, 1, a, 500, r"C:\first.exe", ROOT, 100),
        ev(3, 5, 2, ProcessGuid=a, ProcessId=500, Image=r"C:\first.exe"),
        start(4, 3, b, 500, r"C:\second.exe", ROOT, 100),
        start(5, 4, child, 600, r"C:\child.exe", b, 500, r"C:\second.exe"),
        ev(6, 3, 5, ProcessGuid=a, ProcessId=500, Image=r"C:\first.exe", Initiated="true",
           DestinationIp="10.0.0.1", DestinationPort=80),
    ])
    assert (P(b), P(child), "started") in edges(G)
    assert (P(a), P(child), "started") not in edges(G)
    assert G.in_degree(P(child)) == 1
    assert G.nodes[P(a)]["pid"] == G.nodes[P(b)]["pid"] == 500          # same PID, two nodes
    assert edges(G, "started") == {(P(ROOT), P(a), "started"), (P(ROOT), P(b), "started"),
                                   (P(b), P(child), "started")}


def test_zero_parent_guid_is_a_gap_never_a_node(tmp_path):
    G, _ = graph(tmp_path, [root()])
    assert [n for n in G if "00000000-0000-0000-0000-000000000000" in n] == []
    (g,) = gaps(G, "parent_unknown")
    assert g["node"] == P(ROOT) and g["evidence"][0]["record_id"] == 1
    assert G.nodes[P(ROOT)]["gaps"] == [g]
    assert edges(G) == set()


def test_parent_never_seen_is_a_stub_with_an_origin_gap(tmp_path):
    # Sysmon names a real (non-zero) parent GUID, but the parent's own start isn't recorded.
    parent, child = "{D0000000-0000-0000-0000-000000000000}", "{E0000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [start(7, 1, child, 700, r"C:\c.exe", parent, 70, r"C:\svc.exe")])
    assert (P(parent), P(child), "started") in edges(G)        # event 1 states it: a fact
    d = G.nodes[P(parent)]
    assert d["start_recorded"] is False and d["image"] == r"C:\svc.exe" and d["pid"] == 70
    (g,) = gaps(G, "origin_unknown")
    assert g["node"] == P(parent) and g["evidence"][0]["record_id"] == 7
    assert gaps(G, "parent_unknown") == []


def test_guid_case_does_not_split_a_process(tmp_path):
    child = "{F0000000-0000-0000-0000-00000000000A}"
    G, _ = graph(tmp_path, [root(), start(2, 1, child.lower(), 5, r"C:\x.exe", ROOT.lower(), 100)])
    assert (P(ROOT), P(child), "started") in edges(G)


# -- layer 0: other facts -------------------------------------------------------------------------
def test_connections_dns_files_and_inbound(tmp_path):
    g = "{AB000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [
        root(), start(2, 1, g, 9, r"C:\app.exe", ROOT, 100),
        ev(3, 22, 2, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", QueryName="Example.TEST", QueryStatus="0"),
        ev(4, 3, 3, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", Initiated="true",
           SourceIp="192.168.1.5", SourcePort=50000, DestinationIp="10.0.0.1", DestinationPort=443),
        ev(5, 3, 4, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", Initiated="false",
           SourceIp="10.0.0.9", SourcePort=51000, DestinationIp="192.168.1.5", DestinationPort=8080),
        ev(6, 11, 5, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", TargetFilename=r"C:\Users\u\Downloads\a.txt"),
        ev(7, 26, 6, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", TargetFilename=r"C:\Users\u\Downloads\a.txt",
           Hashes="SHA256=CC"),
    ])
    assert edges(G) - edges(G, "started") == {
        (P(g), "dns:PC:example.test", "looked_up"),
        (P(g), "net:PC:10.0.0.1:443", "connected_to"),
        (P(g), "net:PC:10.0.0.9", "accepted_from"),                 # inbound: the remote is the source
        (P(g), r"file:PC:c:\users\u\downloads\a.txt", "created"),
        (P(g), r"file:PC:c:\users\u\downloads\a.txt|CC", "deleted"),  # Sysmon hashed the deleted file
    }
    inbound = next(d for _, _, d in facts(G) if d["kind"] == "accepted_from")
    assert inbound["local_port"] == 8080
    assert gaps(G, "content_unknown") == []        # a .txt is never fingerprinted: no gap expected


def test_every_fact_cites_stored_rows(tmp_path):
    g = "{AC000000-0000-0000-0000-000000000000}"
    G, store = graph(tmp_path, [
        root(), start(2, 1, g, 9, r"C:\app.exe", ROOT, 100),
        ev(3, 3, 3, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe", Initiated="true",
           DestinationIp="10.0.0.1", DestinationPort=443),
    ])
    for _, _, d in facts(G):
        assert d["grade"] == "fact" and d["evidence"]
        for e in d["evidence"]:
            row = store.db.execute("SELECT id, record_id FROM events WHERE dedup_key=?", (e["key"],)).fetchone()
            assert row == (e["id"], e["record_id"])


# -- layer 1 and file gaps ------------------------------------------------------------------------
DROP = r"C:\Users\u\AppData\Local\Temp\drop.exe"


def dropper_then_run(run_sha, hash_status="ok", file_sha="B1"):
    maker, runner = "{AD000000-0000-0000-0000-000000000000}", "{AE000000-0000-0000-0000-000000000000}"
    created = ev(3, 11, 2, ProcessGuid=maker, ProcessId=9, Image=r"C:\maker.exe", TargetFilename=DROP)
    return maker, runner, [
        root(), start(2, 1, maker, 9, r"C:\maker.exe", ROOT, 100),
        created, file_hash(1, 3, created, hash_status, file_sha),
        start(4, 4, runner, 10, DROP.upper(), maker, 9, r"C:\maker.exe", sha=run_sha),   # path case differs
    ]


def test_same_path_and_same_hash_is_a_layer1_fact(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    G, _ = graph(tmp_path, recs)
    f = "file:PC:" + DROP.lower() + "|B1"
    assert (P(maker), f, "created") in edges(G)
    assert (f, P(runner), "ran_as") in edges(G)
    ran = next(d for u, v, d in facts(G) if d["kind"] == "ran_as")
    assert ran["layer"] == 1 and [e["event"] for e in ran["evidence"]] == ["FILE_HASH", 1]
    assert gaps(G, "content_unknown") == [] and G.graph["layer2_candidates"] == []


def test_short_name_path_matches_through_the_agents_final_path(tmp_path):
    # the file was created under an 8.3 short name; the agent's FILE_HASH carries Windows' full
    # path (GetFinalPathNameByHandle), which equals the program's long path (decided 2026-10-17)
    maker, runner = "{AD100000-0000-0000-0000-000000000000}", "{AE100000-0000-0000-0000-000000000000}"
    short = r"C:\Users\ADMINI~1\AppData\Local\Temp\drop.exe"
    created = ev(3, 11, 2, ProcessGuid=maker, ProcessId=9, Image=r"C:\maker.exe", TargetFilename=short)
    fh = file_hash(1, 3, created)
    fh["data"]["final_path"] = r"C:\Users\Administrator\AppData\Local\Temp\drop.exe"
    G, _ = graph(tmp_path, [root(), start(2, 1, maker, 9, r"C:\maker.exe", ROOT, 100), created, fh,
                            start(4, 4, runner, 10, r"C:\Users\Administrator\AppData\Local\Temp\drop.exe",
                                  maker, 9, r"C:\maker.exe", sha="B1")])
    assert len(edges(G, "ran_as")) == 1


def test_short_name_without_final_path_stays_a_candidate(tmp_path):
    maker, runner = "{AD200000-0000-0000-0000-000000000000}", "{AE200000-0000-0000-0000-000000000000}"
    created = ev(3, 11, 2, ProcessGuid=maker, ProcessId=9, Image=r"C:\maker.exe",
                 TargetFilename=r"C:\Users\ADMINI~1\AppData\Local\Temp\drop.exe")
    G, _ = graph(tmp_path, [root(), start(2, 1, maker, 9, r"C:\maker.exe", ROOT, 100), created,
                            file_hash(1, 3, created),
                            start(4, 4, runner, 10, r"C:\Users\Administrator\AppData\Local\Temp\drop.exe",
                                  maker, 9, r"C:\maker.exe", sha="B1")])
    assert edges(G, "ran_as") == set() and len(G.graph["layer2_candidates"]) == 1   # old agents: no guess


def test_same_path_different_hash_is_not_a_fact(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="99")
    G, _ = graph(tmp_path, recs)
    assert edges(G, "ran_as") == set()
    assert (P(maker), P(runner), "started") in edges(G)                    # still a layer 0 fact
    (c,) = G.graph["layer2_candidates"]
    assert c["process"] == P(runner) and "content different" in c["reason"]


def test_file_hash_busy_timeout_is_a_gap_and_not_a_fact(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1", hash_status="busy_timeout")
    G, _ = graph(tmp_path, recs)
    assert edges(G, "ran_as") == set()
    (g,) = gaps(G, "content_unknown")
    assert g["node"] == "file:PC:" + DROP.lower() and "busy_timeout" in g["reason"]
    assert [e["event"] for e in g["evidence"]] == [11, "FILE_HASH"]
    assert len(G.graph["layer2_candidates"]) == 1                          # left for layer 2


def test_new_folder_is_a_created_fact_not_a_content_gap(tmp_path):
    # Sysmon records folder creation under \AnalystLab\ as event 11; the agent marks it
    # "directory" (found in the first S1 run, 2026-10-17). A folder has no content to prove.
    g = "{AC000000-0000-0000-0000-000000000000}"
    folder = ev(3, 11, 2, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe",
                TargetFilename=r"C:\AnalystLab\scenarios\s1\payload")
    G, _ = graph(tmp_path, [root(), start(2, 1, g, 9, r"C:\app.exe", ROOT, 100), folder,
                            file_hash(1, 2.1, folder, status="directory")])
    assert (P(g), r"file:PC:c:\analystlab\scenarios\s1\payload", "created") in edges(G)
    assert gaps(G, "content_unknown") == []


def test_fingerprintable_file_without_file_hash_is_a_gap(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    recs = [r for r in recs if r.get("type") != "FILE_HASH"]   # e.g. the agent was killed first
    G, _ = graph(tmp_path, recs)
    (g,) = gaps(G, "content_unknown")
    assert "no FILE_HASH" in g["reason"] and edges(G, "ran_as") == set()


def test_file_hash_for_a_different_event_is_not_borrowed(tmp_path):
    # FILE_HASH links to its event 11 by (record id, time); a different creation must not borrow
    # it, and a fingerprint not tied to a recorded creation proves nothing about any process
    maker, runner, recs = dropper_then_run(run_sha="B1")
    fh = next(r for r in recs if r.get("type") == "FILE_HASH")
    fh["data"]["ref_record_id"] = 999
    G, _ = graph(tmp_path, recs)
    assert (P(maker), "file:PC:" + DROP.lower(), "created") in edges(G)
    assert len(gaps(G, "content_unknown")) == 1
    assert edges(G, "ran_as") == set()


# -- listening ports ------------------------------------------------------------------------------
def test_port_owner_by_pid_only_when_unique_and_alive(tmp_path):
    old, new = "{AF000000-0000-0000-0000-000000000000}", "{B1000000-0000-0000-0000-000000000000}"
    recs = [
        root(),
        start(2, 1, old, 4242, r"C:\srv.exe", ROOT, 100),
        ev(3, 5, 5, ProcessGuid=old, ProcessId=4242, Image=r"C:\srv.exe"),
        start(4, 30, new, 4242, r"C:\srv.exe", ROOT, 100),                   # PID reused, same program
        agent(1, 40, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=8000, ProcessId=4242, Image=r"C:\srv.exe"),
        agent(2, 41, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=9000, ProcessId=777, Image=r"C:\svc.exe"),
    ]
    G, _ = graph(tmp_path, recs)
    assert (P(new), "port:PC:0.0.0.0:8000", "listen_started") in edges(G)
    assert (P(old), "port:PC:0.0.0.0:8000", "listen_started") not in edges(G)
    (g,) = gaps(G, "owner_unknown")                                            # PID 777 never recorded
    assert g["node"] == "port:PC:0.0.0.0:9000"


def test_port_owner_by_start_time_is_exact(tmp_path):
    # newer agents record the owner's start time: the port goes to exactly that process, even
    # where PID + program + lifetime alone would be ambiguous (decided 2026-10-17)
    a, b = "{B6000000-0000-0000-0000-000000000000}", "{B7000000-0000-0000-0000-000000000000}"
    recs = [root(), start(2, 1, a, 4242, r"C:\srv.exe", ROOT, 100),
            start(3, 30, b, 4242, r"C:\srv.exe", ROOT, 100),          # same PID + program, both "alive"
            agent(1, 40, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=8000, ProcessId=4242,
                  Image=r"C:\srv.exe", ProcessStartUtc=at(1))]
    G, _ = graph(tmp_path, recs)
    assert edges(G, "listen_started") == {(P(a), "port:PC:0.0.0.0:8000", "listen_started")}
    (fact,) = [d for u, v, d in facts(G) if d["kind"] == "listen_started"]
    assert fact["basis"] == "pid+image+start time"


def test_port_with_a_start_time_matching_no_process_is_a_gap(tmp_path):
    p = "{B8000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [root(), start(2, 1, p, 4242, r"C:\srv.exe", ROOT, 100),
                            agent(1, 40, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=8000, ProcessId=4242,
                                  Image=r"C:\srv.exe", ProcessStartUtc=at(20))])     # a different process
    assert edges(G, "listen_started") == set()
    (g,) = gaps(G, "owner_unknown")
    assert "start time" in g["reason"]


def test_port_owner_is_a_gap_after_a_sysmon_restart(tmp_path):
    p = "{B2000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [
        root(), start(2, 1, p, 4242, r"C:\srv.exe", ROOT, 100),
        ev(3, 4, 20, State="Started"),                                         # e.g. a reboot
        agent(1, 40, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=8000, ProcessId=4242, Image=r"C:\srv.exe"),
    ])
    assert edges(G, "listen_started") == set()
    assert len(gaps(G, "owner_unknown")) == 1


# -- origin filter --------------------------------------------------------------------------------
def test_project_activity_can_be_filtered_out(tmp_path):
    tool, browser, git = ("{B3000000-0000-0000-0000-000000000000}", "{B4000000-0000-0000-0000-000000000000}",
                          "{B5000000-0000-0000-0000-000000000000}")
    recs = [
        root(),
        start(2, 1, tool, 20, r"C:\claude.exe", ROOT, 100, origin="project"),
        start(3, 2, browser, 21, r"C:\browser.exe", tool, 20, r"C:\claude.exe"),     # tagged normal
        start(4, 3, git, 22, r"C:\git.exe", tool, 20, r"C:\claude.exe", origin="project"),
        ev(5, 3, 4, ProcessGuid=git, ProcessId=22, Image=r"C:\git.exe", Initiated="true",
           DestinationIp="10.0.0.2", DestinationPort=443),                              # untagged later event
        agent(1, 5, "PORT_LISTEN_START", LocalIp="127.0.0.1", LocalPort=7000, ProcessId=22, Image=r"C:\git.exe"),
    ]
    full, _ = graph(tmp_path, recs)
    assert P(tool) in full and P(git) in full and len(edges(full, "listen_started")) == 1
    (tmp_path / "f").mkdir()
    G, _ = graph(tmp_path / "f", recs, include_project=False)
    assert P(tool) not in G and P(git) not in G and "net:PC:10.0.0.2:443" not in G
    assert G.nodes[P(browser)]["parent_hidden"].startswith("project")
    assert gaps(G, "origin_unknown") == [] and gaps(G, "owner_unknown") == []
    assert "port:PC:127.0.0.1:7000" not in G


# -- scenario S1 (shape of a real run, never its GUIDs) -------------------------------------------
RUNNER, FETCH, PAYLOAD = ("{C1000000-0000-0000-0000-000000000000}", "{C2000000-0000-0000-0000-000000000000}",
                          "{C3000000-0000-0000-0000-000000000000}")
PAYLOAD_PATH = r"C:\AnalystLab\scenarios\s1\payload\s1_payload.exe"
FETCH_PATH = r"C:\AnalystLab\scenarios\bin\s1_fetch.exe"


def s1_records():
    created = ev(13, 11, 2.1, ProcessGuid=FETCH, ProcessId=31, Image=FETCH_PATH, TargetFilename=PAYLOAD_PATH)
    return [
        root(),
        start(10, 0.5, RUNNER, 30, r"C:\Windows\System32\cmd.exe", ROOT, 100),
        start(11, 1.0, FETCH, 31, FETCH_PATH, RUNNER, 30, r"C:\Windows\System32\cmd.exe", sha="F1"),
        # Sysmon often logs event 3 late: higher record number than the 11 that followed it
        ev(14, 3, 1.5, ProcessGuid=FETCH, ProcessId=31, Image=FETCH_PATH, Initiated="true",
           SourceIp="10.0.2.15", SourcePort=49800, DestinationIp="10.0.2.2", DestinationPort=8765),
        created,
        file_hash(1, 2.6, created, "ok", "5A"),
        start(15, 2.5, PAYLOAD, 32, PAYLOAD_PATH, FETCH, 31, FETCH_PATH, sha="5A"),
        ev(16, 5, 4.5, ProcessGuid=PAYLOAD, ProcessId=32, Image=PAYLOAD_PATH),
        ev(17, 5, 4.6, ProcessGuid=FETCH, ProcessId=31, Image=FETCH_PATH),
    ]


def test_s1_sequence_gives_exactly_the_ground_truth_facts(tmp_path):
    with open(os.path.join(HERE, "..", "scenarios", "s1", "ground_truth.yaml"), encoding="utf-8") as f:
        truth = yaml.safe_load(f)["expected_graph"]
    G, _ = graph(tmp_path, s1_records())
    pay_file = "file:PC:" + PAYLOAD_PATH.lower() + "|5A"
    server = "net:PC:10.0.2.2:8765"
    # ground_truth.yaml expected_graph.facts, in order
    expected = [(P(FETCH), P(PAYLOAD), "started"),        # fetch started payload
                (P(FETCH), server, "connected_to"),        # fetch connected to test server
                (P(FETCH), pay_file, "created"),           # fetch created payload file
                (pay_file, P(PAYLOAD), "ran_as")]          # payload process runs the payload file
    assert len(expected) == len(truth["facts"])
    s1_nodes = {P(FETCH), P(PAYLOAD), pay_file, server}
    s1_facts = {(u, v, d["kind"]) for u, v, d in facts(G) if u in s1_nodes and v in s1_nodes}
    assert s1_facts == set(expected)
    # the hypothesis "content came from the server" is layer 2: no edge of any kind joins them
    assert not G.has_edge(server, pay_file) and not G.has_edge(pay_file, server)
    assert truth["hypotheses"] and all(d["grade"] == "fact" for _, _, d in G.edges(data=True))
    # gaps: [] for the S1 entities
    assert [g for g in G.graph["gaps"] if g["node"] in s1_nodes] == truth["gaps"] == []


def test_s1_subgraph_from_the_payload_finds_the_whole_story(tmp_path):
    G, store = graph(tmp_path, s1_records())
    H = subgraph_around(G, PAYLOAD)
    kinds = {(u, v, d["kind"]) for u, v, d in facts(H)}
    assert (P(FETCH), "net:PC:10.0.2.2:8765", "connected_to") in kinds      # backwards then forwards
    assert {"started", "connected_to", "created", "ran_as"} <= {k for *_, k in kinds}
    # seeding with the stored event 1 of the payload gives the same neighbourhood
    key = store.db.execute("SELECT dedup_key FROM events WHERE record_id=15").fetchone()[0]
    assert set(subgraph_around(G, key)) == set(H)


def test_timeline_is_ordered_by_event_time_not_record_number(tmp_path):
    G, _ = graph(tmp_path, s1_records())
    order = [i["what"] for i in timeline(G) if i["src"] == P(FETCH) and i["what"] != "ended"]
    assert order == ["connected_to", "created", "started"]       # event 3 (record 14) before 11 (13)
    times = [i["time"] for i in timeline(G)]
    assert times == sorted(times)


# -- subgraph bounds ------------------------------------------------------------------------------
def chain(n, step_seconds=1):
    """root -> p1 -> p2 -> ... -> pn, one start per step."""
    guids = [f"{{D{i:07d}-0000-0000-0000-000000000000}}" for i in range(1, n + 1)]
    recs, parent, ppid = [root()], ROOT, 100
    for i, g in enumerate(guids, start=1):
        recs.append(start(100 + i, i * step_seconds, g, 1000 + i, rf"C:\p{i}.exe", parent, ppid))
        parent, ppid = g, 1000 + i
    return guids, recs


def test_subgraph_depth_bound(tmp_path):
    guids, recs = chain(12)
    G, _ = graph(tmp_path, recs)
    H = subgraph_around(G, guids[5], max_depth=5)
    assert max(d for _, d in H.nodes(data="depth")) == 5
    assert set(H) == {P(g) for g in guids[0:11]}                # 5 back (p1..p5), 5 forward (p7..p11)


def test_subgraph_time_window(tmp_path):
    guids, recs = chain(6, step_seconds=600)                     # one start every 10 minutes
    G, _ = graph(tmp_path, recs)
    H = subgraph_around(G, guids[2])                              # p3, started at +30 min
    # edges within +-15 min of p3's start: p2->p3 (at 30), p3->p4 (at 40); p1->p2 (20) is too, p4->p5 (50) not
    assert set(H) == {P(guids[0]), P(guids[1]), P(guids[2]), P(guids[3])}
    assert all(abs(d["time"] - H.graph["at"]) <= timedelta(minutes=15) for *_, d in H.edges(data=True))


def test_subgraph_node_cap_and_expand_hook(tmp_path):
    hub = "{E1000000-0000-0000-0000-000000000000}"
    recs = [root(), start(2, 1, hub, 5, r"C:\hub.exe", ROOT, 100)]
    for i in range(100):
        recs.append(ev(10 + i, 3, 2 + i, ProcessGuid=hub, ProcessId=5, Image=r"C:\hub.exe", Initiated="true",
                       DestinationIp=f"10.1.0.{i}", DestinationPort=443))
    G, _ = graph(tmp_path, recs)
    H = subgraph_around(G, hub, max_nodes=60)
    assert H.number_of_nodes() == 60 and H.graph["truncated"] is True
    # the layer-3 hook: a node that is not expanded stops the walk there
    H2 = subgraph_around(G, ROOT, expand=lambda graph, node: node != P(hub))
    assert set(H2) == {P(ROOT), P(hub)}


def test_walking_forward_never_turns_back(tmp_path):
    # two unrelated programs connect to the same server; seeding one must not pull in the other
    a, b = "{E2000000-0000-0000-0000-000000000000}", "{E3000000-0000-0000-0000-000000000000}"
    recs = [start(1, 0, a, 5, r"C:\a.exe", ZERO_GUID), start(2, 0, b, 6, r"C:\b.exe", ZERO_GUID)]
    for i, g in enumerate((a, b)):
        recs.append(ev(10 + i, 3, 1 + i, ProcessGuid=g, ProcessId=5 + i, Image="x", Initiated="true",
                       DestinationIp="10.0.0.1", DestinationPort=443))
    G, _ = graph(tmp_path, recs)
    assert set(subgraph_around(G, a)) == {P(a), "net:PC:10.0.0.1:443"}


# -- independent review fixes (2026-10-16) ---------------------------------------------------------
from engine.graph import FILE_HASH_MAX_DELAY  # noqa: E402


def test_zero_actor_guid_never_becomes_a_process(tmp_path):
    # Sysmon emits an all-zero ProcessGuid for some kernel/System activity (seen 12x on real data)
    recs = [ev(1, 3, 1, ProcessGuid=ZERO_GUID, ProcessId=4, Image="System", Initiated="true",
               DestinationIp="10.0.0.1", DestinationPort=445),
            ev(2, 11, 2, ProcessGuid=ZERO_GUID, ProcessId=1234, Image="x", TargetFilename=r"C:\a.exe"),
            ev(3, 22, 3, ProcessGuid=ZERO_GUID.lower(), ProcessId=4, Image="System", QueryName="n.test"),
            ev(4, 26, 4, ProcessGuid=ZERO_GUID, ProcessId=4, Image="System", TargetFilename=r"C:\b.dll")]
    G, _ = graph(tmp_path, recs)
    assert [n for n, d in G.nodes(data=True) if d["kind"] == "process"] == []
    assert facts(G) == []
    assert {g["node"] for g in gaps(G, "actor_unknown")} == {
        "net:PC:10.0.0.1:445", r"file:PC:c:\a.exe", "dns:PC:n.test", r"file:PC:c:\b.dll"}


def test_zero_parent_guid_without_braces_is_still_a_gap(tmp_path):
    child = "{F1000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [start(1, 0, child, 5, r"C:\x.exe", "00000000-0000-0000-0000-000000000000")])
    assert len(gaps(G, "parent_unknown")) == 1 and G.number_of_nodes() == 1


def test_connection_with_unknown_direction_gives_no_edge(tmp_path):
    g = "{F2000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [root(), start(2, 1, g, 9, r"C:\app.exe", ROOT, 100),
                            ev(3, 3, 2, ProcessGuid=g, ProcessId=9, Image=r"C:\app.exe",   # no Initiated
                               SourceIp="192.168.1.5", DestinationIp="10.0.0.1", DestinationPort=443)])
    assert edges(G) == edges(G, "started") and G.graph["stats"]["event3_direction_unknown"] == 1


def test_ipv6_node_ids_cannot_collide(tmp_path):
    g = "{F3000000-0000-0000-0000-000000000000}"
    recs = [root(), start(2, 1, g, 9, r"C:\app.exe", ROOT, 100),
            ev(3, 3, 2, ProcessGuid=g, ProcessId=9, Image="a", Initiated="false", SourceIp="2001:db8::1:443",
               DestinationIp="2001:db8::5", DestinationPort=80),
            ev(4, 3, 3, ProcessGuid=g, ProcessId=9, Image="a", Initiated="true", DestinationIp="2001:db8::1",
               DestinationPort=443),
            ev(5, 3, 4, ProcessGuid=g, ProcessId=9, Image="a", Initiated="true", DestinationIp="::ffff:10.0.0.1",
               DestinationPort=443)]
    G, _ = graph(tmp_path, recs)
    assert edges(G) - edges(G, "started") == {
        (P(g), "net:PC:[2001:db8::1:443]", "accepted_from"),
        (P(g), "net:PC:[2001:db8::1]:443", "connected_to"),
        (P(g), "net:PC:10.0.0.1:443", "connected_to")}


def test_late_fingerprint_does_not_prove_what_the_creator_wrote(tmp_path):
    # A creates x.exe; much later (agent caught up after downtime) the file has other content,
    # and that is what P ran. "A created what P ran" must NOT follow.
    maker, runner, recs = dropper_then_run(run_sha="B1")
    fh = next(r for r in recs if r.get("type") == "FILE_HASH")
    late = parse_time(at(3)) + FILE_HASH_MAX_DELAY + timedelta(seconds=1)
    fh["time"] = late.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    G, _ = graph(tmp_path, recs)
    assert edges(G, "ran_as") == set()
    assert (P(maker), "file:PC:" + DROP.lower(), "created") in edges(G)
    (g,) = gaps(G, "content_unknown")
    assert "right after creation" in g["reason"]


def test_fingerprint_after_the_file_was_recreated_is_not_used(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    other = "{F4000000-0000-0000-0000-000000000000}"
    recs.append(ev(20, 11, 2.5, ProcessGuid=other, ProcessId=77, Image=r"C:\other.exe", TargetFilename=DROP))
    G, _ = graph(tmp_path, recs)
    assert edges(G, "ran_as") == set()
    assert any("again" in g["reason"] for g in gaps(G, "content_unknown"))


def test_conflicting_fingerprints_are_a_gap(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    created = next(r for r in recs if r.get("event_id") == 11)
    recs.append(file_hash(2, 3.5, created, "ok", "CC"))
    G, _ = graph(tmp_path, recs)
    assert edges(G, "ran_as") == set()
    assert any("conflicting" in g["reason"] for g in gaps(G, "content_unknown"))


def test_sysmon_delete_hash_also_proves_content_for_ran_as(tmp_path):
    p, killer = "{F5000000-0000-0000-0000-000000000000}", "{F6000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [
        root(), start(2, 1, p, 9, DROP, ROOT, 100, sha="E1"),
        start(3, 2, killer, 10, r"C:\clean.exe", ROOT, 100),
        ev(4, 26, 5, ProcessGuid=killer, ProcessId=10, Image=r"C:\clean.exe", TargetFilename=DROP, Hashes="SHA256=E1")])
    f = "file:PC:" + DROP.lower() + "|E1"
    assert {(f, P(p), "ran_as"), (P(killer), f, "deleted")} <= edges(G)


def test_short_name_with_same_content_is_a_candidate_not_a_fact(tmp_path):
    short = r"C:\Users\ADMINI~1\AppData\Local\Temp\drop.exe"
    maker, runner = "{F7000000-0000-0000-0000-000000000000}", "{F8000000-0000-0000-0000-000000000000}"
    created = ev(3, 11, 2, ProcessGuid=maker, ProcessId=9, Image=r"C:\maker.exe", TargetFilename=short)
    G, _ = graph(tmp_path, [root(), start(2, 1, maker, 9, r"C:\maker.exe", ROOT, 100), created,
                            file_hash(1, 3, created, "ok", "B1"),
                            start(4, 4, runner, 10, r"C:\Users\Administrator\AppData\Local\Temp\drop.exe",
                                  maker, 9, sha="B1")])
    assert edges(G, "ran_as") == set()
    (c,) = G.graph["layer2_candidates"]
    assert c["process"] == P(runner) and "different path" in c["reason"]


def test_long_path_prefix_does_not_hide_a_fact(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    next(r for r in recs if r.get("event_id") == 11)["data"]["TargetFilename"] = "\\\\?\\" + DROP
    for r in recs:
        if r.get("type") == "FILE_HASH":
            r["data"]["TargetFilename"] = "\\\\?\\" + DROP
    G, _ = graph(tmp_path, recs)
    assert len(edges(G, "ran_as")) == 1


SRV = "{F9000000-0000-0000-0000-000000000000}"


def port_rec(seq, seconds, type_="PORT_LISTEN_START", pid=4242, image=r"C:\srv.exe", session="s1", port=8000):
    r = agent(seq, seconds, type_, LocalIp="0.0.0.0", LocalPort=port, ProcessId=pid, Image=image)
    r["session"] = session
    return r


def test_port_owner_that_started_after_the_record_is_not_used(tmp_path):
    G, _ = graph(tmp_path, [root(), start(2, 41.5, SRV, 4242, r"C:\srv.exe", ROOT, 100), port_rec(1, 40)])
    assert edges(G, "listen_started") == set() and len(gaps(G, "owner_unknown")) == 1


def test_port_record_without_program_or_with_two_candidates_is_a_gap(tmp_path):
    other = "{FA000000-0000-0000-0000-000000000000}"
    recs = [root(), start(2, 1, SRV, 4242, r"C:\srv.exe", ROOT, 100),
            start(3, 2, other, 4242, r"C:\srv.exe", ROOT, 100),       # impossible live, but no end recorded
            port_rec(1, 40), port_rec(2, 41, pid=4242, image=None, port=9000)]
    G, _ = graph(tmp_path, recs)
    assert edges(G, "listen_started") == set()
    assert sorted(g["reason"].split(": ", 1)[1] for g in gaps(G, "owner_unknown")) == [
        "2 recorded processes match PID, program and lifetime", "no program path in the port record"]


def test_port_stop_goes_to_the_owner_of_the_start_in_the_same_session(tmp_path):
    recs = [root(), start(2, 1, SRV, 4242, r"C:\srv.exe", ROOT, 100),
            port_rec(1, 40), port_rec(2, 60, "PORT_LISTEN_STOP"),
            port_rec(1, 80, "PORT_LISTEN_STOP", session="s2", port=9000)]   # its start: another session
    G, _ = graph(tmp_path, recs)
    assert edges(G, "listen_stopped") == {(P(SRV), "port:PC:0.0.0.0:8000", "listen_stopped")}
    (g,) = gaps(G, "owner_unknown")
    assert g["node"] == "port:PC:0.0.0.0:9000" and "same agent session" in g["reason"]


def test_event_seed_walks_forward_only_from_the_object(tmp_path):
    a, b = "{FB000000-0000-0000-0000-000000000000}", "{FC000000-0000-0000-0000-000000000000}"
    recs = [start(1, 0, a, 5, r"C:\a.exe", ZERO_GUID), start(2, 0, b, 6, r"C:\b.exe", ZERO_GUID),
            ev(10, 3, 1, ProcessGuid=a, ProcessId=5, Image="x", Initiated="true", DestinationIp="10.0.0.1", DestinationPort=443),
            ev(11, 3, 2, ProcessGuid=b, ProcessId=6, Image="x", Initiated="true", DestinationIp="10.0.0.1", DestinationPort=443)]
    G, store = graph(tmp_path, recs)
    key = store.db.execute("SELECT dedup_key FROM events WHERE record_id=10").fetchone()[0]
    assert set(subgraph_around(G, key)) == {P(a), "net:PC:10.0.0.1:443"}


def test_start_event_seed_is_centred_on_the_start(tmp_path):
    recs = [start(1, 0, SRV, 4242, r"C:\srv.exe", ZERO_GUID),
            ev(2, 3, 5, ProcessGuid=SRV, ProcessId=4242, Image=r"C:\srv.exe", Initiated="true",
               DestinationIp="10.0.0.1", DestinationPort=443),
            port_rec(1, 3000)]                                           # 50 min later
    G, store = graph(tmp_path, recs)
    assert len(edges(G, "listen_started")) == 1                         # cites the event 1 as support
    key = store.db.execute("SELECT dedup_key FROM events WHERE record_id=1").fetchone()[0]
    H = subgraph_around(G, key)
    assert H.graph["at"] == parse_time(at(0)) and "net:PC:10.0.0.1:443" in H


def test_subgraph_gaps_are_limited_to_the_window(tmp_path):
    p = "{FD000000-0000-0000-0000-000000000000}"
    recs = [root(), start(2, 1, p, 9, r"C:\app.exe", ROOT, 100),
            ev(3, 11, 7200, ProcessGuid=p, ProcessId=9, Image=r"C:\app.exe", TargetFilename=r"C:\late.exe")]
    G, _ = graph(tmp_path, recs)
    assert len(gaps(G, "content_unknown")) == 1                         # at +2 h
    assert [g["kind"] for g in subgraph_around(G, p).graph["gaps"]] == ["parent_unknown"]


def test_bad_file_hash_reference_does_not_crash(tmp_path):
    maker, runner, recs = dropper_then_run(run_sha="B1")
    next(r for r in recs if r.get("type") == "FILE_HASH")["data"]["ref_record_id"] = "not-a-number"
    G, _ = graph(tmp_path, recs)
    assert G.graph["stats"]["file_hash_bad_reference"] == 1


def test_two_hosts_never_mix(tmp_path):
    g = "{FE000000-0000-0000-0000-000000000000}"
    G, _ = graph(tmp_path, [start(1, 0, g, 5, r"C:\a.exe", ROOT, 100),
                            start(1, 0, "{FE000000-0000-0000-0000-00000000000F}", 6, r"C:\b.exe", g, 5, host="VM"),
                            ev(2, 3, 1, ProcessGuid=g, ProcessId=5, Image="a", Initiated="true",
                               DestinationIp="10.0.0.1", DestinationPort=80, host="VM")])
    assert "proc:VM:" + g in G and P(g) in G
    assert not any(u == P(g) for u, _, _ in facts(G))                    # the VM's events stay on the VM


def test_project_parent_seen_only_by_name_is_hidden_when_filtered(tmp_path):
    tool, browser = "{FF100000-0000-0000-0000-000000000000}", "{FF200000-0000-0000-0000-000000000000}"
    recs = [start(3, 2, browser, 21, r"C:\browser.exe", tool, 20, r"C:\Programs\Claude\claude.exe")]
    G, _ = graph(tmp_path, recs, include_project=False)
    assert P(tool) not in G and gaps(G, "origin_unknown") == []
    assert G.nodes[P(browser)]["parent_hidden"].startswith("project")


def test_constants_match_the_agent():
    from agent import enrich, main
    from engine import graph as g
    assert g.DEV_TOOLS == enrich.DEV_TOOLS
    assert g.FILE_HASH_MAX_DELAY.total_seconds() >= main.HASH_WAIT_SECONDS