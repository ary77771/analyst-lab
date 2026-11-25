"""Package J part 1: the noise overlay (engine/overlay.py, tools/noise_overlay.py), the shared run
window (check_scenario.run_window), the graph checker's --store path and the experiment driver
(tools/overlay_experiment.py). Written before the code (docs/plans/package-j-design.md section 5).

Fixtures are hand-made: a tiny S1 VM run (the graph checker's own fixture plus three background
VM processes) and a tiny laptop dev snapshot with six 3-minute active stretches two hours apart,
each holding the same small story under its own identities (an app started by the desktop shell
that looks up a name, connects, downloads a tool, runs it, opens a port...), plus the cases the
design names: a process named like a scenario program, a child of a shell (never grafted), our
own tools, a paused row, events 4/16, a path that also exists in the VM window, and a seventh
stretch AFTER the dev cutoff that must never be used."""

import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import timedelta, timezone

import pytest
import yaml

from engine import confidence as C
from engine import overlay
from engine.graph import ZERO_GUID, Layer2, build_graph, facts, hypotheses, parse_time
from engine.store import EventStore
from tests.conftest import TEST_HUBS
from tests.test_check_graph_scenario import BASE, H, ev as vev, good_run, iso, pool_file
from tests.test_graph import agent, at, ev, start

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_alerts  # noqa: E402
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
import noise_overlay  # noqa: E402
import overlay_experiment  # noqa: E402

CFG = C.load_config()
RUN_ID = "20261017-180000-aaaa"
EXPLORER = r"C:\Windows\explorer.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
CMD = r"C:\Windows\System32\cmd.exe"
SHARED = r"C:\Users\vm\Downloads\shared.exe"           # created in the VM window AND by the laptop app
APP = r"C:\Users\u\AppData\Local\app\app.exe"
TOOL = r"C:\Users\u\Downloads\tool.exe"
OLD = r"C:\Users\u\Downloads\old.exe"
BUILD = r"C:\tools\build.exe"
SVC = r"C:\Program Files\thing\svc.exe"
FILL = "{FF000000-0000-0000-0000-000000000000}"
TOOL_SHA, SHARED_SHA, OLD_SHA, APP_SHA = "CD" * 32, "7788" * 16, "9A" * 32, "1A" * 32
LAPTOP_SHAS = {TOOL_SHA, SHARED_SHA, OLD_SHA, APP_SHA}


# -- fixtures ----------------------------------------------------------------------------------------
def vm_background():
    """Three VM processes outside the story: the desktop shell (a hub, created SHARED), a command
    shell (a role program of S4: never a grafting target) and a service host seen only through
    one event (a stub without a recorded start)."""
    return [vev(201, 1, 0, Image=EXPLORER, ProcessGuid="{E}", ProcessId=300, ParentProcessGuid=ZERO_GUID, Hashes="SHA256=" + "E0" * 32),
            vev(202, 11, 10, Image=EXPLORER, ProcessGuid="{E}", ProcessId=300, TargetFilename=SHARED),
            vev(203, 1, 12, Image=CMD, ProcessGuid="{C}", ProcessId=301, ParentProcessGuid="{E}", ParentImage=EXPLORER,
                Hashes="SHA256=" + "C0" * 32),
            vev(204, 3, 11, Image=SVCHOST, ProcessGuid="{SVH}", ProcessId=900, Protocol="udp", Initiated="true",
                SourceIp="10.0.2.15", SourcePort=5353, DestinationIp="10.0.2.3", DestinationPort=53)]


def run_record(**extra):
    return {"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0, "time": iso(0), "start": iso(0), "end": iso(20),
            "run_id": RUN_ID, "server": "http://10.0.2.2:8765", **extra}


def write_recordings(tmp_path, vm=None, runs=None):
    for label, rows in (("vm", vm if vm is not None else good_run() + vm_background()), ("vmruns", runs or [run_record()])):
        (tmp_path / label).mkdir(exist_ok=True)
        (tmp_path / label / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    pool_file(tmp_path)


def lguid(j, n):
    return f"{{{j:02X}{n:02X}0000-0000-0000-0000-000000000000}}"


def fhash(seq, seconds, created, sha, final_path):
    return agent(seq, seconds, "FILE_HASH", TargetFilename=created["data"]["TargetFilename"],
                 ProcessGuid=created["data"]["ProcessGuid"], hash_status="ok", sha256=sha, size=10,
                 final_path=final_path, ref_record_id=created["record_id"], ref_time=created["time"])


def stretch(j, length=180, marker_sha=TOOL_SHA):
    """One 3-minute active stretch of the laptop (fillers every 30 s), starting j*2 h after T0."""
    b, rid = j * 7200, 1000 * j
    L0, L1, L2, L3, L4, LC, L5, L6, LS = (lguid(j, n) for n in range(1, 10))
    rows = [ev(rid + 900 + i, 16, b + s, ProcessGuid=FILL, State="Started") for i, s in enumerate(range(0, length + 1, 30))]
    made = ev(rid + 4, 11, b + 31, ProcessGuid=L1, ProcessId=500, Image=APP, TargetFilename=TOOL)
    made2 = ev(rid + 6, 11, b + 33, ProcessGuid=L1, ProcessId=500, Image=APP, TargetFilename=SHARED)
    rows += [
        start(rid + 1, b + 20, L1, 500, APP, L0, 300, EXPLORER, sha=APP_SHA, User="PC\\u", CommandLine=f'"{APP}"'),
        ev(rid + 2, 22, b + 29, ProcessGuid=L1, ProcessId=500, Image=APP, QueryName="example.com", QueryStatus=0,
           QueryResults="type: 5 cdn.example.net;::ffff:8.8.4.4;"),
        ev(rid + 3, 3, b + 30, ProcessGuid=L1, ProcessId=500, Image=APP, Protocol="tcp", Initiated="true", User="PC\\u",
           SourceIp="192.168.1.5", SourcePort=50000, DestinationIp="8.8.4.4", DestinationPort=443, DestinationHostname="h"),
        made, fhash(rid * 10 + 1, b + 32, made, TOOL_SHA, TOOL),
        ev(rid + 5, 15, b + 31.5, ProcessGuid=L1, ProcessId=500, Image=APP, TargetFilename=TOOL + ":Zone.Identifier",
           Contents="[ZoneTransfer]  ZoneId=3  HostUrl=https://example.com/tool.exe", Hash="SHA256=" + marker_sha),
        made2, fhash(rid * 10 + 2, b + 34, made2, SHARED_SHA, SHARED),
        start(rid + 7, b + 35, L2, 600, TOOL, L1, 500, APP, sha=TOOL_SHA, CommandLine=f'"{TOOL}" shared.exe'),
        ev(rid + 8, 26, b + 36, ProcessGuid=L1, ProcessId=500, Image=APP, TargetFilename=OLD, Hashes="SHA256=" + OLD_SHA),
        ev(rid + 9, 5, b + 40, ProcessGuid=L2, ProcessId=600, Image=TOOL),
        agent(rid * 10 + 3, b + 50, "PORT_LISTEN_START", LocalIp="0.0.0.0", LocalPort=7777, ProcessId=500, Image=APP,
              ProcessStartUtc=at(b + 20)),
        agent(rid * 10 + 4, b + 60, "PORT_LISTEN_STOP", LocalIp="0.0.0.0", LocalPort=7777, ProcessId=500, Image=APP,
              ProcessStartUtc=at(b + 20)),
        # named like a scenario program: dropped with every row of it
        start(rid + 10, b + 80, L3, 700, r"C:\x\s1_fetch.exe", L1, 500, APP),
        ev(rid + 11, 3, b + 81, ProcessGuid=L3, ProcessId=700, Image=r"C:\x\s1_fetch.exe", Protocol="tcp", Initiated="true",
           SourceIp="192.168.1.5", SourcePort=50001, DestinationIp="8.8.8.8", DestinationPort=80),
        # a boundary orphan whose parent is a command shell (a role program of S4): never grafted
        start(rid + 12, b + 85, L4, 800, BUILD, LC, 900, CMD),
        # our own tools, a paused row, a Sysmon state event: never overlaid
        ev(rid + 13, 3, b + 90, origin="project", ProcessGuid=L5, ProcessId=950, Image=r"C:\proj\x.exe", Protocol="tcp",
           Initiated="true", SourceIp="192.168.1.5", SourcePort=50002, DestinationIp="8.8.8.8", DestinationPort=80),
        {**ev(rid + 14, 11, b + 91, ProcessGuid=L1, ProcessId=500, Image=APP, TargetFilename=r"C:\Users\u\paused.exe"), "paused": 1},
        ev(rid + 15, 4, b + 92, State="Started"),
        # a boundary orphan whose parent is a service host (the VM knows one only as a stub)
        start(rid + 17, b + 95, L6, 850, SVC, LS, 400, SVCHOST, sha="5566" * 16),
        # a process whose parent Sysmon never knew (all-zero GUID): a gap, never an identity to rewrite
        start(rid + 18, b + 96, lguid(j, 10), 860, r"C:\Windows\System32\taskhostw.exe", ZERO_GUID, parent_image="-", sha="6677" * 16),
        ev(rid + 16, 5, b + 100, ProcessGuid=L1, ProcessId=500, Image=APP),
    ]
    return rows


def laptop_db(tmp_path, stretches=range(6), cutoff="2026-10-22", after_cutoff=True, snapshot=True, length=180, name="dev-laptop.db",
              marker_sha=TOOL_SHA):
    rows = [r for j in stretches for r in stretch(j, length, marker_sha)]
    if after_cutoff:
        rows += stretch(36, length)                     # 3 days after T0 = 2026-10-23: test data
    path = str(tmp_path / name)
    st = EventStore(path)
    st.insert(rows)
    st.close()
    db = sqlite3.connect(path)
    if snapshot:
        db.execute("CREATE TABLE snapshot (key TEXT PRIMARY KEY, value TEXT)")
        db.executemany("INSERT INTO snapshot VALUES (?, ?)", [("cutoff_day_utc", cutoff), ("built_utc", "2026-10-23T00:00:00+00:00")])
        db.commit()
    db.execute("PRAGMA journal_mode=DELETE")
    db.close()
    return path


def build(tmp_path, volume, seed=1, graft=True, vm=None, laptop=None, **lap):
    write_recordings(tmp_path, vm)
    laptop = laptop or laptop_db(tmp_path, **lap)
    run = check_scenario.find_run(str(tmp_path), "s1", run_id=RUN_ID)
    return noise_overlay.build_for_run(str(tmp_path), "s1", run, volume, seed, graft, laptop=laptop)


def rows(path, where="1=1"):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(f"SELECT * FROM events WHERE {where} ORDER BY time, record_id, seq")]
    finally:
        con.close()


def overlay_rows(path, k=None):
    return rows(path, "overlay_slice IS NOT NULL" + (f" AND overlay_slice = {int(k)}" if k else ""))


def table(path):
    """Every row without its id, sorted: two stores with the same content compare equal."""
    con = sqlite3.connect(path)
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(events)") if r[1] != "id"]
        return sorted(tuple(r) for r in con.execute(f"SELECT {', '.join(cols)} FROM events"))
    finally:
        con.close()


def graph_of(path):
    return build_graph(path)


def layer2_for(tmp_path):
    return Layer2.from_pool_file(str(tmp_path / "confidence" / "pool.json"))


def truth_s1():
    with open(os.path.join(PROJECT_ROOT, "scenarios", "s1", "ground_truth.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def procs(G, label):
    return [n for n, d in G.nodes(data=True) if d.get("kind") == "process" and str(d.get("label")).lower() == label]


# -- 1. the shared run window ------------------------------------------------------------------------
def test_run_window_is_the_checkers_old_formula(tmp_path):
    def rec(s, e):
        return {"type": "SCENARIO_RUN", "scenario": "S1", "exit_code": 0, "time": iso(s), "start": iso(s), "end": iso(e)}
    runs = [rec(-3, 2), rec(0, 10), rec(70, 80), rec(200, 210)]
    (tmp_path / "vmruns").mkdir()
    (tmp_path / "vmruns" / "2026-10-17.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8")
    found = check_scenario.all_runs(str(tmp_path))
    for run in found:
        # the formula the three checkers each carried until package J
        start, end = parse_time(run["start"]), parse_time(run["end"])
        others = [r for r in found if r is not run and r.get("start") != run["start"]]
        prev_end = max((parse_time(r["end"]) for r in others if parse_time(r["start"]) < start), default=None)
        next_start = min((parse_time(r["start"]) for r in others if parse_time(r["start"]) > start), default=None)
        lo = max(start - check_scenario.SLACK_BEFORE, prev_end) if prev_end else start - check_scenario.SLACK_BEFORE
        hi = min(end + check_scenario.SLACK_AFTER, next_start) if next_start else end + check_scenario.SLACK_AFTER
        w = check_scenario.run_window(str(tmp_path), run)
        assert (w.lo, w.hi) == (lo, hi) == check_alerts.window(str(tmp_path), run)
        assert w.overlaps_previous == bool(prev_end and prev_end > start)
    assert [check_scenario.run_window(str(tmp_path), r).overlaps_previous for r in found] == [False, True, False, False]
    w = check_scenario.run_window(str(tmp_path), found[2])
    assert (w.lo, w.hi) == (parse_time(iso(65)), parse_time(iso(200)))      # cut at the next run's start


# -- 2. the 0x store and the checker's --store path -------------------------------------------------
def test_zero_store_equals_the_checkers_replay_store(tmp_path):
    path, meta = build(tmp_path, 0)
    run = check_scenario.find_run(str(tmp_path), "s1", run_id=RUN_ID)
    lo, hi, _ = check_scenario.run_window(str(tmp_path), run)
    ref = str(tmp_path / "replay.db")
    st = EventStore(ref)
    for r in check_graph_scenario.window_records(str(tmp_path), "vm", lo, hi):
        st.insert([r])
    st.close()
    assert table(path) == table(ref) and len(table(path)) == len(good_run() + vm_background())
    assert meta["volume"] == 0 and meta["overlay_rows"] == 0 and meta["slices"] == []
    assert overlay.read_meta(path)["window_lo"] == lo.isoformat()


def checker_output(tmp_path, capsys, extra=()):
    code = check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--run-id", RUN_ID, *extra])
    out = capsys.readouterr().out
    body = [l for l in out.splitlines() if not l.startswith(("replayed ", "read "))]      # the one line that names the source
    return code, body, out


def test_store_check_gives_the_classic_checkers_output_on_a_zero_store(tmp_path, capsys):
    path, _ = build(tmp_path, 0)
    code_a, body_a, out_a = checker_output(tmp_path, capsys)
    code_b, body_b, out_b = checker_output(tmp_path, capsys, ["--store", path])
    assert code_a == code_b == 0, out_a + out_b
    assert body_a == body_b
    assert "replayed " in out_a and "read " in out_b and "prepared store" in out_b and "0x, seed 1" in out_b


def test_store_check_refuses_another_runs_store_and_official_mode(tmp_path, capsys, monkeypatch):
    path, _ = build(tmp_path, 0)
    other = run_record(start=iso(3600), end=iso(3620), run_id="20261017-190000-bbbb", time=iso(3600))
    with open(tmp_path / "vmruns" / "2026-10-17.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(other) + "\n")
    code = check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--run-id", other["run_id"], "--store", path])
    assert code == 1 and "built for another run or window" in capsys.readouterr().out
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    code = check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--run-id", RUN_ID, "--store", path])
    assert code == 1 and "--store" in capsys.readouterr().out


# -- 3. identities, time, resolution ------------------------------------------------------------------
def test_identities_are_disjoint_on_every_node_kind(tmp_path):
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    assert ov and all(r["session"] == "overlay-1-1" and r["label"] == "overlay" and r["host"] == "VM" for r in ov)
    vm = rows(path, "overlay_slice IS NULL")
    vm_guids = {str(r[k]).upper() for r in vm for k in ("ProcessGuid", "ParentProcessGuid") if r[k]}
    for r in ov:
        if r["ProcessGuid"]:
            assert r["ProcessGuid"].startswith("{FE01") and r["ProcessGuid"] not in vm_guids
        if r["ParentProcessGuid"] and not r["overlay_grafted"] and r["ParentProcessGuid"] != ZERO_GUID:
            assert r["ParentProcessGuid"].startswith("{FE01")
        if r["ProcessId"] is not None:
            assert int(r["ProcessId"]) >= overlay.PID_STEP
        if r["record_id"] is not None:
            assert int(r["record_id"]) >= overlay.RECORD_STEP
        for f in ("sha256",):
            if r[f]:
                assert r[f] not in LAPTOP_SHAS and r[f] not in {H} and len(r[f]) == 64
        for f in ("Hashes", "Hash"):
            if r[f]:
                assert r[f].startswith("SHA256=") and r[f][7:] not in LAPTOP_SHAS
        for f in ("SourceIp", "DestinationIp", "LocalIp"):
            if r[f]:
                a = ipaddress.ip_address(r[f])
                assert a in ipaddress.ip_network("100.64.0.0/10") or a in ipaddress.ip_network("2001:db8::/32")
        if r["QueryName"]:
            assert r["QueryName"].endswith(".overlay.invalid") and "example" not in r["QueryName"]
        if r["QueryResults"]:
            assert "cdn" not in r["QueryResults"] and all(ipaddress.ip_address(x) in ipaddress.ip_network("100.64.0.0/10")
                                                           for x in r["QueryResults"].strip(";").split(";"))
        if r["Contents"]:
            assert "example.com" not in r["Contents"] and "HostUrl=https://n" in r["Contents"] and ".overlay.invalid" in r["Contents"]
        assert r["User"] is None and r["DestinationHostname"] is None
    # the same identity maps to the same new identity (the app's rows all share one GUID)
    app = {r["ProcessGuid"] for r in ov if r["Image"] == APP and r["ProcessGuid"]}
    assert len(app) == 1
    # the all-zero GUID means "unknown" and stays exactly that: a gap, never a node
    task = next(r for r in ov if r["event_id"] == 1 and r["Image"].lower().endswith("taskhostw.exe"))
    assert task["ParentProcessGuid"] == ZERO_GUID
    G = graph_of(path)
    assert any(g["kind"] == "parent_unknown" and g["node"] == f"proc:VM:{task['ProcessGuid']}" for g in G.graph["gaps"])
    assert not [n for n in G if "00000000-0000-0000-0000-000000000000" in n]
    classes = overlay.node_classes(G, path)
    assert "shared" not in classes.values()
    by_kind = {}
    for n, d in G.nodes(data=True):
        by_kind.setdefault(d["kind"], {"overlay": set(), "vm": set()})[classes[n]].add(n)
    assert set(by_kind) >= {"process", "file", "endpoint", "dns", "port"}
    for kind, sides in by_kind.items():
        assert sides["overlay"] and not (sides["overlay"] & sides["vm"]), kind
    s = overlay.cross_summary(G, path, grafts=meta["grafts"])
    assert s["cross_facts"] == [] and s["shared_nodes"] == []


def test_intervals_within_a_process_are_preserved(tmp_path):
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    app_guid = next(r["ProcessGuid"] for r in ov if r["Image"] == APP and r["event_id"] == 1)
    mine = [r for r in ov if r["ProcessGuid"] == app_guid]
    sysmon = sorted(parse_time(r["UtcTime"]) for r in mine if r["UtcTime"])
    t0 = sysmon[0]
    assert [round((t - t0).total_seconds(), 3) for t in sysmon] == [0.0, 9.0, 10.0, 11.0, 11.5, 13.0, 16.0, 80.0]
    port = next(r for r in ov if r["type"] == "PORT_LISTEN_START" and r["Image"] == APP)     # agent rows carry no GUID
    assert (parse_time(port["time"]) - t0).total_seconds() == 30.0
    assert parse_time(port["ProcessStartUtc"]) == t0                      # the owner's start moved with it
    fh = [r for r in mine if r["type"] == "FILE_HASH"]
    made = {r["record_id"]: r for r in mine if r["event_id"] == 11}
    for h in fh:
        assert h["ref_record_id"] in made and h["ref_time"] == made[h["ref_record_id"]]["time"]
        assert 0.9 < (parse_time(h["time"]) - parse_time(made[h["ref_record_id"]]["UtcTime"])).total_seconds() < 1.1
    # every record time landed inside the run window, shifted by one whole number of milliseconds
    lo, hi = parse_time(meta["window_lo"]), parse_time(meta["window_hi"])
    assert all(lo <= parse_time(r["time"]) <= hi for r in ov)
    assert meta["slices"][0]["shift_seconds"] * 1000 == int(meta["slices"][0]["shift_seconds"] * 1000)


def test_file_hash_and_port_owner_resolve_in_the_graph(tmp_path):
    path, meta = build(tmp_path, 1)
    G = graph_of(path)
    (app,) = procs(G, "app.exe")
    (tool,) = procs(G, "tool.exe")
    kinds = {(d["kind"], v) for _, v, d in G.out_edges(app, data=True)}
    created = [v for k, v in kinds if k == "created"]
    ns = overlay.Namespace(1, 1, 0)
    tool_file = next(v for v in created if G.nodes[v]["path"] == TOOL)
    assert G.nodes[tool_file]["sha256"] == ns.sha(TOOL_SHA) and G.nodes[tool_file]["sha256"] != TOOL_SHA
    assert (tool_file, tool, "ran_as") in {(u, v, d["kind"]) for u, v, d in facts(G)}          # layer 1 across two rows
    assert G.nodes[tool]["pid"] == 600 + overlay.PID_STEP
    port = next(v for k, v in kinds if k == "listen_started")
    assert G.nodes[port]["port"] == 7777 and G.nodes[port]["ip"] != "0.0.0.0"
    fact = next(d for _, v, d in G.out_edges(app, data=True) if d["kind"] == "listen_started")
    assert fact["basis"] == "pid+image+start time"
    assert any(k == "listen_stopped" for k, _ in kinds) and any(k == "looked_up" for k, _ in kinds)
    deleted = next(v for k, v in kinds if k == "deleted")
    assert G.nodes[deleted]["sha256"] == ns.sha(OLD_SHA)
    assert not [g for g in G.graph["gaps"] if g["node"] in (tool_file, port)]


def test_colliding_paths_are_rewritten_and_the_vm_file_stays_vm(tmp_path):
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    shared = [r for r in ov if r["TargetFilename"] and r["TargetFilename"].lower().endswith("shared.exe")]
    assert shared and all(r["TargetFilename"].startswith("C:\\overlay1\\") for r in shared)
    assert all(r["final_path"].startswith("C:\\overlay1\\") for r in shared if r["type"] == "FILE_HASH")
    assert meta["counts"]["path_collisions_rewritten"] == 3                 # event 11 + FILE_HASH TargetFilename + final_path
    tool_rows = [r for r in ov if r["TargetFilename"] and "tool.exe" in r["TargetFilename"].lower()]
    assert all(r["TargetFilename"].startswith(r"C:\Users\u") for r in tool_rows)   # no collision: unchanged
    G = graph_of(path)
    classes = overlay.node_classes(G, path)
    vm_shared = [n for n, d in G.nodes(data=True) if d.get("kind") == "file" and d.get("path") == SHARED]
    assert len(vm_shared) == 1 and classes[vm_shared[0]] == "vm"
    ov_shared = [n for n, d in G.nodes(data=True) if d.get("kind") == "file" and str(d.get("path")).startswith("C:\\overlay1\\")]
    assert ov_shared and all(classes[n] == "overlay" for n in ov_shared)


def test_a_program_path_the_vm_created_is_rewritten_too(tmp_path):
    # the VM window creates the laptop tool's path: the overlay tool's image and its created file move together
    vm = good_run() + vm_background() + [vev(205, 11, 13, Image=EXPLORER, ProcessGuid="{E}", ProcessId=300, TargetFilename=TOOL)]
    path, meta = build(tmp_path, 1, vm=vm)
    ov = overlay_rows(path)
    tool_start = next(r for r in ov if r["event_id"] == 1 and r["Image"].lower().endswith("tool.exe"))
    assert tool_start["Image"] == "C:\\overlay1\\C\\Users\\u\\Downloads\\tool.exe"
    assert meta["counts"]["image_collisions_rewritten"] == 2                     # the tool's event 1 and event 5
    G = graph_of(path)
    (tool,) = procs(G, "tool.exe")
    assert overlay.node_classes(G, path)[tool] == "overlay"
    assert any(d["kind"] == "ran_as" and v == tool for _, v, d in facts(G))        # still runs from "its" file
    assert overlay.cross_summary(G, path, grafts=meta["grafts"])["cross_facts"] == []


def test_scenario_named_processes_are_dropped_and_counted(tmp_path):
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    assert not [r for r in ov if "s1_fetch" in str(r["Image"]).lower() or "s1_fetch" in str(r["ParentImage"]).lower()]
    assert meta["counts"]["dropped_scenario_name_Image"] == 2
    assert {"s1_fetch.exe", "s1_payload.exe", "s2_checkin.exe", "c1_updater.exe"} <= set(meta["scenario_programs_dropped"])
    assert {"cmd.exe", "powershell.exe", "s4_viewer.exe"} <= set(meta["role_programs_never_grafted"])
    assert "cmd.exe" not in meta["scenario_programs_dropped"]
    # our own tools, paused rows and Sysmon state events never arrive
    assert not [r for r in ov if r["origin"] == "project" or r["paused"] or r["event_id"] in (4, 16)]


def test_grafting_attaches_boundary_orphans_to_live_vm_processes_never_role_programs(tmp_path):
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    app = next(r for r in ov if r["event_id"] == 1 and r["Image"] == APP)
    assert app["ParentProcessGuid"] == "{E}" and str(app["overlay_grafted"]) == "1" and app["ParentProcessId"] == 300
    svc = next(r for r in ov if r["event_id"] == 1 and r["Image"] == SVC)
    assert svc["ParentProcessGuid"] == "{SVH}" and str(svc["overlay_grafted"]) == "1"   # a VM stub counts as alive
    build_ = next(r for r in ov if r["event_id"] == 1 and r["Image"] == BUILD)
    assert build_["ParentProcessGuid"].startswith("{FE01") and not build_["overlay_grafted"]   # cmd.exe is a role program
    tool = next(r for r in ov if r["event_id"] == 1 and r["Image"] == TOOL)
    assert tool["ParentProcessGuid"] == app["ProcessGuid"] and not tool["overlay_grafted"]    # its parent is in the slice
    assert meta["counts"]["grafted"] == 2 and meta["counts"]["orphans_not_grafted"] == 1
    assert meta["counts"].get("grafted_parent_also_acts_in_slice", 0) == 0      # neither laptop parent acted in the slice
    assert sorted(g["parent"] for g in meta["grafts"]) == ["{E}", "{SVH}"]
    G = graph_of(path)
    s = overlay.cross_summary(G, path, grafts=meta["grafts"])
    assert s["graft_started"] == 2 and s["graft_started_to_role"] == 0 and s["cross_facts"] == []
    (explorer,) = procs(G, "explorer.exe")
    assert {G.nodes[v]["label"] for _, v, d in G.out_edges(explorer, data=True) if d["kind"] == "started"} == {"cmd.exe", "app.exe"}


def test_without_grafting_orphans_stay_overlay_stubs(tmp_path):
    path, meta = build(tmp_path, 1, graft=False)
    ov = overlay_rows(path)
    assert all(not r.get("overlay_grafted") for r in ov) and meta["counts"].get("grafted", 0) == 0
    assert meta["counts"]["orphans_not_grafted"] == 3 and meta["grafts"] == []
    app = next(r for r in ov if r["event_id"] == 1 and r["Image"] == APP)
    assert app["ParentProcessGuid"].startswith("{FE01")
    G = graph_of(path)
    assert overlay.cross_summary(G, path)["cross_facts"] == [] and overlay.cross_summary(G, path)["graft_started"] == 0
    assert any(g["kind"] == "origin_unknown" and G.nodes[g["node"]]["label"] == "explorer.exe"
               and overlay.node_classes(G, path)[g["node"]] == "overlay" for g in G.graph["gaps"])


def test_grafting_needs_the_vm_process_alive_at_that_moment(tmp_path):
    vm = good_run() + vm_background() + [vev(206, 5, 1, Image=EXPLORER, ProcessGuid="{E}", ProcessId=300)]   # shell ends at 1 s
    path, meta = build(tmp_path, 1, vm=vm)
    app = next(r for r in overlay_rows(path) if r["event_id"] == 1 and r["Image"] == APP)
    assert app["ParentProcessGuid"].startswith("{FE01") and meta["counts"]["grafted"] == 1        # only the service host


def test_reproducible_by_seed(tmp_path):
    path1, meta1 = build(tmp_path, 2, seed=7)
    (tmp_path / "b").mkdir()
    path2, meta2 = build(tmp_path / "b", 2, seed=7)
    assert table(path1) == table(path2) and meta1["slices"] == meta2["slices"] and meta1["grafts"] == meta2["grafts"]
    (tmp_path / "c").mkdir()
    path3, meta3 = build(tmp_path / "c", 2, seed=8)
    assert meta3["slices"] != meta1["slices"]
    assert {r["ProcessGuid"] for r in overlay_rows(path3) if r["Image"] == APP and r["ProcessGuid"]}.isdisjoint(
        {r["ProcessGuid"] for r in overlay_rows(path1) if r["Image"] == APP and r["ProcessGuid"]})   # another seed, another namespace


def test_five_slices_are_disjoint_and_each_inside_one_active_stretch(tmp_path):
    path, meta = build(tmp_path, 5)
    laptop = str(tmp_path / "dev-laptop.db")
    con = sqlite3.connect(laptop)
    times = sorted(parse_time(u or t).timestamp() for u, t in con.execute("SELECT UtcTime, time FROM events") if u or t)
    con.close()
    active = C.ActiveTime(times, CFG.sleep_gap_seconds)
    spans = []
    for s in meta["slices"]:
        a, b = parse_time(s["laptop_start_utc"]).timestamp(), parse_time(s["laptop_end_utc"]).timestamp()
        assert b - a == meta["window_seconds"]
        inside = [(lo, hi) for lo, hi in zip(active.starts, active.ends) if lo - 1e-3 <= a and b <= hi + 1e-3]
        assert len(inside) == 1, "a slice must lie inside one active stretch"
        assert a < parse_time("2026-10-23T00:00:00Z").timestamp(), "rows after the dev cutoff are never used"
        spans.append((a, b))
    spans.sort()
    assert all(x[1] < y[0] for x, y in zip(spans, spans[1:])), "slices never overlap"
    assert [s["session"] for s in meta["slices"]] == [f"overlay-1-{k}" for k in range(1, 6)]
    for k in range(1, 6):
        ov = overlay_rows(path, k)
        app = next(r for r in ov if r["event_id"] == 1 and r["Image"] == APP)
        assert app["ProcessGuid"].startswith(f"{{FE{k:02X}") and app["ProcessId"] == 500 + k * overlay.PID_STEP
        assert app["record_id"] % overlay.RECORD_STEP == app["record_id"] - k * overlay.RECORD_STEP
    guids = [{r["ProcessGuid"] for r in overlay_rows(path, k) if r["ProcessGuid"]} for k in range(1, 6)]
    assert all(a.isdisjoint(b) for i, a in enumerate(guids) for b in guids[i + 1:])
    G = graph_of(path)
    assert len(procs(G, "app.exe")) == 5


# -- 4. the whole-graph promises (design 1.8) at 1x and 5x --------------------------------------------
def checked(tmp_path, path, hubs=TEST_HUBS):
    run = check_scenario.find_run(str(tmp_path), "s1", run_id=RUN_ID)
    lo, hi, _ = check_scenario.run_window(str(tmp_path), run)
    G = build_graph(path, hypotheses=layer2_for(tmp_path))
    lines = []
    ok, c = check_graph_scenario.check_graph(truth_s1(), G, check_graph_scenario.records_from_store(path), lo, hi,
                                             check_scenario.run_server(run), hubs, say=lines.append)
    return G, ok, c, lines


@pytest.mark.parametrize("volume", [1, 5])
def test_whole_graph_promises_hold(tmp_path, volume):
    path, meta = build(tmp_path, volume)
    G, ok, c, lines = checked(tmp_path, path)
    assert ok, "\n".join(lines)
    role_nodes = {n for r in c.roles for n in c.nodes_of(r)}
    s = overlay.cross_summary(G, path, role_nodes, meta["grafts"])
    assert s["shared_nodes"] == [] and s["cross_facts"] == []
    assert s["overlay_scenario_edges"] == 0                     # no edge of any layer joins overlay and scenario nodes
    assert s["graft_started"] == 2 * volume and s["graft_started_to_role"] == 0
    hyp = s["hypotheses"]
    assert sum(n for (cls, row, band), n in hyp.items() if cls == "cross" and row != "R4") == 0, hyp     # R4 is the measurement
    assert sum(n for (cls, row, band), n in hyp.items() if cls.startswith("cross") and row in ("R1", "R2", "R3", "F1")) == 0
    assert sum(n for (cls, _, _), n in hyp.items() if cls == "overlay-internal") >= 3 * volume     # T1, R3, R4 ... per slice
    assert sum(n for (cls, _, _), n in hyp.items() if cls == "scenario-story") == 1                # S1's T1
    # the false name-only R4: each slice's tool names "shared.exe", a file the VM also created
    assert s["cross_r4"] == {"name-only": volume}
    assert G.graph["layer2"]["sigma_p"] > 0
    assert any("alert view" in l and "PASS" in l for l in lines) and any("runner view" in l and "PASS" in l for l in lines)


def test_cross_timing_links_are_zero_without_grafting(tmp_path):
    path, meta = build(tmp_path, 5, graft=False)
    G, ok, c, lines = checked(tmp_path, path)
    assert ok, "\n".join(lines)
    s = overlay.cross_summary(G, path, {n for r in c.roles for n in c.nodes_of(r)}, meta["grafts"])
    assert s["cross_t_observed"] == 0 and s["graft_started"] == 0 and s["cross_facts"] == []
    assert sum(n for (cls, row, band), n in s["hypotheses"].items() if cls.startswith("cross") and row != "R4") == 0
    assert s["cross_r4"] == {"name-only": 5}


def test_grafted_timing_links_are_classified_cross_graft(tmp_path):
    # the VM shell connects out 3 s before the grafted app "starts": a cross/graft T3 through the shell
    path, meta = build(tmp_path, 1)
    ov = overlay_rows(path)
    app = next(r for r in ov if r["event_id"] == 1 and r["Image"] == APP)
    t = parse_time(app["UtcTime"]) - timedelta(seconds=3)
    extra = vev(207, 3, (t - BASE.replace(tzinfo=timezone.utc)).total_seconds(), Image=EXPLORER, ProcessGuid="{E}", ProcessId=300, Protocol="tcp",
                Initiated="true", SourceIp="10.0.2.15", SourcePort=50500, DestinationIp="10.0.2.9", DestinationPort=80)
    (tmp_path / "b").mkdir()
    path2, meta2 = build(tmp_path / "b", 1, vm=good_run() + vm_background() + [extra])
    G, ok, c, lines = checked(tmp_path / "b", path2)
    assert ok, "\n".join(lines)
    s = overlay.cross_summary(G, path2, {n for r in c.roles for n in c.nodes_of(r)}, meta2["grafts"])
    assert sum(n for (cls, row, _), n in s["hypotheses"].items() if cls == "cross/graft" and row == "T3") == 1
    assert s["cross_t_observed"] == 1 and 0 < s["cross_t_sigma_p"] <= 1
    assert sum(n for (cls, row, band), n in s["hypotheses"].items() if cls == "cross" and row != "R4") == 0


def test_the_leak_detector_itself_sees_a_shared_node_and_a_graft_onto_a_role(tmp_path):
    # the promises are only as good as their detector: break a built store by hand and watch it tell
    path, meta = build(tmp_path, 1)
    build_guid = next(r["ProcessGuid"] for r in overlay_rows(path) if r["event_id"] == 1 and r["Image"] == BUILD)
    con = sqlite3.connect(path)
    con.execute("DELETE FROM events WHERE overlay_slice IS NOT NULL AND type = 'FILE_HASH' AND TargetFilename LIKE '%shared.exe'")
    con.execute("UPDATE events SET TargetFilename = ? WHERE overlay_slice IS NOT NULL AND event_id = 11 AND TargetFilename LIKE '%shared.exe'", (SHARED,))
    con.execute("UPDATE events SET ParentProcessGuid = '{F}', overlay_grafted = 1 WHERE overlay_slice IS NOT NULL AND ProcessGuid = ? AND event_id = 1", (build_guid,))
    con.commit()
    con.close()
    G, ok, c, lines = checked(tmp_path, path)
    role_nodes = {n for r in c.roles for n in c.nodes_of(r)}
    s = overlay.cross_summary(G, path, role_nodes, meta["grafts"] + [{"child": build_guid, "parent": "{F}", "slice": 1}])
    assert s["shared_nodes"] == [f"file:VM:{SHARED.lower()}"]
    assert s["graft_started_to_role"] == 1 and s["overlay_scenario_edges"] >= 1
    inv = overlay_experiment.invariants(s, True)
    assert not inv["ok"] and any("shared" in b for b in inv["broken"]) and any("role" in b for b in inv["broken"])
    # an un-grafted cross `started` edge is a fact across the two worlds
    s2 = overlay.cross_summary(G, path, role_nodes, meta["grafts"])
    assert "started" in {kind for _, kind, _ in s2["cross_facts"]} and s2["graft_started"] == 2
    assert not overlay_experiment.invariants(s2, True)["ok"]


# -- 5. refusals -----------------------------------------------------------------------------------------
def test_refuses_a_laptop_db_that_is_not_the_dev_snapshot_or_is_too_new(tmp_path):
    with pytest.raises(ValueError, match="later than the frozen dev cutoff"):
        build(tmp_path, 1, cutoff="2026-10-23")
    (tmp_path / "b").mkdir()
    with pytest.raises(ValueError, match="not a dev snapshot"):
        build(tmp_path / "b", 1, snapshot=False)
    (tmp_path / "c").mkdir()
    with pytest.raises(FileNotFoundError):
        build(tmp_path / "c", 1, laptop=str(tmp_path / "c" / "nowhere.db"))


def test_rows_after_the_cutoff_are_never_used_even_if_the_snapshot_holds_them(tmp_path):
    # only the post-cutoff stretch exists: no eligible stretch (enforced in SQL and on the active time)
    with pytest.raises(ValueError, match="no rows before the cutoff"):
        build(tmp_path, 1, stretches=[])
    laptop = str(tmp_path / "dev-laptop.db")
    con, snap = overlay.open_laptop(laptop, "2026-10-22")
    try:
        with pytest.raises(ValueError, match="no rows before the cutoff"):
            overlay.laptop_host(con, snap["_cutoff_end"])
        after = parse_time("2026-10-23T10:00:00Z").timestamp() * 1000
        assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0           # the rows ARE in the file...
        assert overlay.laptop_rows(con, "PC", int(after), int(after) + 200_000, snap["_cutoff_end"]) == []   # ...never selected
        assert overlay.laptop_active_time(con, "PC", snap["_cutoff_end"], CFG).total == 0                   # ...never active time
    finally:
        con.close()


def test_refuses_when_slices_cannot_fit(tmp_path):
    with pytest.raises(ValueError, match="no active stretch of the laptop is as long"):
        build(tmp_path, 1, length=120)                                     # stretches shorter than the 175 s window
    (tmp_path / "b").mkdir()
    with pytest.raises(ValueError, match="could not place 3 non-overlapping"):
        build(tmp_path / "b", 3, stretches=range(2))


def test_refuses_bad_volumes_and_a_multi_host_window(tmp_path):
    laptop = None
    for bad in (-1, 2.5, 256, True):
        with pytest.raises(ValueError):
            build(tmp_path, bad, laptop=laptop)
        laptop = str(tmp_path / "dev-laptop.db")
    (tmp_path / "b").mkdir()
    foreign = dict(vev(300, 1, 2, Image=r"C:\other.exe", ProcessGuid="{Z}", ProcessId=5, ParentProcessGuid=ZERO_GUID), host="OTHER")
    with pytest.raises(ValueError, match="VM hosts"):
        build(tmp_path / "b", 1, vm=good_run() + vm_background() + [foreign])


def test_cli_refusals_and_counts_only_output(tmp_path, capsys, monkeypatch):
    write_recordings(tmp_path)
    laptop = laptop_db(tmp_path)
    argv = ["s1", "--recordings", str(tmp_path), "--run-id", RUN_ID, "--laptop", laptop, "--volume", "1", "--seed", "3"]
    assert noise_overlay.main(argv) == 0
    out = capsys.readouterr().out
    assert "overlay rows from 1 slice(s)" in out and "grafted" in out and "dropped (named like a scenario program): 2" in out
    for private in ("Users", "example.com", "8.8.4.4", "app.exe", "tool.exe", "192.168"):
        assert private not in out, private
    assert os.path.exists(os.path.join(str(tmp_path), "scratch", "overlay", f"s1-{RUN_ID}-1x-s3.db"))
    assert noise_overlay.main(argv + ["--out", str(tmp_path / "elsewhere.db")]) == 1
    assert "must be under" in capsys.readouterr().out
    (tmp_path / "series").mkdir()
    (tmp_path / "series" / "x.json").write_text(json.dumps({"label": "official", "runs": [{"run_id": RUN_ID}]}), encoding="utf-8")
    assert noise_overlay.main(argv) == 1 and "official series" in capsys.readouterr().out
    (tmp_path / "series" / "x.json").unlink()
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    assert noise_overlay.main(argv) == 1 and "official mode" in capsys.readouterr().out
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    with open(tmp_path / "vmruns" / "2026-10-17.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(run_record(exit_code=1)) + "\n")
    assert noise_overlay.main(argv) == 1 and "exit code 1" in capsys.readouterr().out
    assert noise_overlay.main(argv[:-4] + ["--run-id", "nope", "--volume", "1"]) == 1


# -- 6. the rewriting table on its own -------------------------------------------------------------------
def test_shift_text_keeps_each_spelling():
    assert overlay.shift_text("2026-10-16 14:00:00.123", 1500) == "2026-10-16 14:00:01.623"
    assert overlay.shift_text("2026-10-16T14:00:00.1234567Z", -86400000) == "2026-10-15T14:00:00.1234567Z"
    assert overlay.shift_text("2026-10-16T14:00:00Z", 2000) == "2026-10-16T14:00:02Z"
    assert overlay.shift_text("2026-10-16T14:00:00Z", 2500) == "2026-10-16T14:00:02.500Z"
    assert overlay.shift_text("2026-10-16 23:59:59.999", 1) == "2026-10-17 00:00:00.000"
    with pytest.raises(ValueError):
        overlay.shift_text("yesterday", 1)


def test_namespace_maps_are_consistent_injective_and_keep_constant_hashes():
    ns, other = overlay.Namespace(1, 1, 0), overlay.Namespace(1, 2, 0)
    g = "{A1000000-0000-0000-0000-000000000000}"
    assert ns.guid(g) == ns.guid(g.lower()) and ns.guid(g) != other.guid(g) and ns.guid(ZERO_GUID) == ZERO_GUID
    assert re.fullmatch(r"\{FE01[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}", ns.guid(g))
    shas = ["AB" * 32, "CD" * 32, "ab" * 32, C.EMPTY_SHA256, "0" * 64]
    mapped = [ns.sha(s) for s in shas]
    assert mapped[0] == ns.sha("ab" * 32) and len({mapped[0], mapped[1]}) == 2 and mapped[3] == C.EMPTY_SHA256 and mapped[4] == "0" * 64
    assert ns.hashes("MD5=X,SHA256=" + "AB" * 32 + ",IMPHASH=Y") == "SHA256=" + ns.sha("AB" * 32) and ns.hashes("MD5=X") == "-"
    assert ns.ip("::ffff:8.8.4.4") == ns.ip("8.8.4.4") != other.ip("8.8.4.4") and ns.ip("-") == "-"
    assert ipaddress.ip_address(ns.ip("2606:4700::1111")) in ipaddress.ip_network("2001:db8::/32")
    assert ns.dns("Example.COM") == ns.dns("example.com.") and ns.dns("example.com").endswith(".overlay.invalid")
    assert ns.query_results("type: 5 cdn.x.net;1.2.3.4;::ffff:5.6.7.8;") == f"{ns.ip('1.2.3.4')};{ns.ip('5.6.7.8')};"
    assert ns.contents("[ZoneTransfer]  ZoneId=3  HostUrl=http://1.2.3.4:8080/x/y.exe") == \
        f"[ZoneTransfer]  ZoneId=3  HostUrl=http://{ns.ip('1.2.3.4')}:8080/"
    assert ns.path(r"C:\a\b.exe", {r"c:\a\b.exe"}) == r"C:\overlay1\C\a\b.exe" and ns.path(r"C:\a\b.exe", set()) == r"C:\a\b.exe"
    assert ns.path(r"\\?\C:\a\b.exe", {r"c:\a\b.exe"}) == r"C:\overlay1\C\a\b.exe"
    assert ns.pid("500") == 500 + overlay.PID_STEP and ns.record_id(7) == 7 + overlay.RECORD_STEP
    with pytest.raises(ValueError):
        overlay.Namespace(1, 0, 0)


# -- 7. the experiment driver -----------------------------------------------------------------------------
def test_garwood_interval_matches_known_values():
    for n, (lo, hi) in {0: (0.0, 3.6889), 1: (0.0253, 5.5716), 5: (1.6235, 11.6683), 10: (4.7954, 18.3904),
                        100: (81.3637, 121.6271)}.items():
        a, b = overlay_experiment.garwood_interval(n)
        assert abs(a - lo) < 2e-3 and abs(b - hi) < 2e-3, (n, a, b)
    with pytest.raises(ValueError):
        overlay_experiment.garwood_interval(-1)


def test_experiment_runs_the_matrix_and_writes_counts_only(tmp_path, capsys):
    write_recordings(tmp_path)
    laptop = laptop_db(tmp_path)
    md, js = tmp_path / "out.md", tmp_path / "out.json"
    code = overlay_experiment.main(["--recordings", str(tmp_path), "--laptop", laptop, "--runs", "s1:1", "--volumes", "0", "1", "2",
                                    "--seeds", "1", "2", "--r4-seeds", "3", "--out-md", str(md), "--out-json", str(js)])
    out = capsys.readouterr().out
    assert code == 0, out
    doc = json.loads(js.read_text(encoding="utf-8"))
    cells = doc["cells"]
    assert len(cells) == 1 + 2 * 2 + 1                                  # 0x once, 1x/2x x 2 seeds, one no-graft pass
    assert all(c["checker"]["pass"] for c in cells), [c["checker"]["fail_lines"] for c in cells]
    by = {(c["volume"], c["seed"], c["graft"]): c for c in cells}
    assert by[(1, 1, True)]["cross"]["cross_r4"] == {"name-only": 1} and by[(2, 2, True)]["cross"]["cross_r4"] == {"name-only": 2}
    assert by[(0, 1, True)]["cross"]["cross_r4"] == {} and by[(2, 1, False)]["cross"]["cross_t_observed"] == 0
    assert all(c["invariants"]["ok"] for c in cells)
    assert doc["r4"]["per_volume"]["1"]["graphs"] == 3 and doc["r4"]["per_volume"]["1"]["total"] == 3
    assert abs(doc["r4"]["per_volume"]["1"]["rate_ci95"][0] - 0.6187 / 3) < 0.002        # Garwood lower bound for n=3, per graph
    assert doc["band_changes"] == []                                  # S1's T1 stays "low" (short life) under noise
    text = md.read_text(encoding="utf-8")
    assert "## Smoke matrix" in text and "PASS" in text and "name-only" in text and "S1" in text
    for private in ("Users\\u", "example.com", "8.8.4.4", "app.exe", "tool.exe", "192.168", "C:\\overlay"):
        assert private not in text, private
    assert "sigma_p" in text.lower() or "Σp" in text
    assert overlay_experiment.summary_runtime(doc) > 0


def test_experiment_refuses_official_mode_and_needs_runs(tmp_path, capsys, monkeypatch):
    write_recordings(tmp_path)
    laptop = laptop_db(tmp_path)
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    assert overlay_experiment.main(["--recordings", str(tmp_path), "--laptop", laptop, "--runs", "s1:1",
                                    "--out-md", str(tmp_path / "o.md"), "--out-json", str(tmp_path / "o.json")]) == 2
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")
    assert overlay_experiment.main(["--recordings", str(tmp_path), "--laptop", laptop, "--runs", "s3:1",
                                    "--out-md", str(tmp_path / "o.md"), "--out-json", str(tmp_path / "o.json")]) == 2
    assert "no clean practice run" in capsys.readouterr().out

def test_a_realistic_download_marker_is_not_a_leak(tmp_path):
    """Review 2026-10-24 (finding 1): Sysmon's event 15 hashes the Zone.Identifier STREAM, so its
    Hash is almost never the file's own SHA256; the F1 marker fact then sits on a bare file node
    with only that layer-2 fact. The leak detector must class that node by the fact's own row."""
    path, meta = build(tmp_path, 1, marker_sha="EF" * 32)
    G = build_graph(path, hypotheses=layer2_for(tmp_path))
    s = overlay.cross_summary(G, path, grafts=meta["grafts"])
    assert s["cross_facts"] == [] and s["shared_nodes"] == []
    assert any(d.get("kind") == "download_marker" for _, _, d in G.edges(data=True))   # the case really occurs


def test_store_check_refuses_a_store_without_overlay_meta(tmp_path, capsys):
    import shutil
    path, _ = build(tmp_path, 0)
    bare = str(tmp_path / "bare.db")
    shutil.copy(path, bare)
    con = sqlite3.connect(bare)
    con.execute("DROP TABLE overlay_meta")
    con.commit()
    con.close()
    code = check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--run-id", RUN_ID, "--store", bare])
    assert code == 1 and "no overlay_meta table" in capsys.readouterr().out


def test_a_cross_r4_onto_a_scenario_node_is_measured_not_a_leak():
    """Decided before the run (review finding 2): an R4 name-only link between an overlay file and
    a scenario node is the measured false link, counted apart; any other overlay-scenario edge is a leak."""
    import networkx as nx
    G = nx.MultiDiGraph()
    G.add_node("proc:VM:{R}", kind="process", guid="{R}")
    G.add_node("file:VM:c:\\overlay\\note.ps1", kind="file")
    G.add_edge("file:VM:c:\\overlay\\note.ps1", "proc:VM:{R}", grade="hypothesis", row="R4", band="low",
               reason="name only", p=None)
    classes = {"proc:VM:{R}": "vm", "file:VM:c:\\overlay\\note.ps1": "overlay"}
    real = overlay.node_classes
    overlay.node_classes = lambda G_, path: classes
    try:
        s = overlay.cross_summary(G, "unused", role_nodes={"proc:VM:{R}"}, grafts=[])
    finally:
        overlay.node_classes = real
    assert s["cross_r4_on_scenario"] == 1 and s["overlay_scenario_edges"] == 0
