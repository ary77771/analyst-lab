"""Package E part 1: the confidence model (engine/confidence.py, DESIGN 4.7 link-type table).

Covers the reviewers' minimal test list (docs/plans/reports/confidence.md section 5):
formula and bands, active time and rates, the simulation check, T1-T3 windows, R1-R4 and F1.
"""

import math
from pathlib import Path
import sqlite3

import numpy as np
import pytest

from engine import confidence as C

CFG = C.ConfidenceConfig(band_high=0.01, band_medium=0.10, window_before_seconds=2, window_after_seconds=10,
                         sleep_gap_seconds=60, min_pool_events=5, competing_span_seconds=900,
                         lifetime_bands_seconds=(60, 3600))


def zero_pool():
    """A pool with a rate of 0 in every lifetime band (the within-life rate then decides). Every
    band is present: a missing band is an error, never a silent 0."""
    return C.Pool({k: {} for k in C.KINDS}, {k: {b: (0, 1.0) for b in C.lifetime_bands(CFG)} for k in C.KINDS},
                  C.pool_settings(CFG))


# -- formula --------------------------------------------------------------------------------------
@pytest.mark.parametrize("lam,t,expected", [
    (0.01, 2, 0.0198013267),           # DESIGN's example: "about 2 %"  (x - x^2/2 + x^3/6, x = 0.02)
    (1 / 60, 60, 0.6321205588),        # 1 - 1/e
    (0.001, 10, 0.0099501663),         # x = 0.01: 0.01 - 0.00005 + 0.000000167
    (0.0019, 12, 0.0225420440),        # x = 0.0228: 0.0228 - 0.00025992 + 0.00000198 - 0.00000001
])
def test_chance_hand_values(lam, t, expected):
    assert C.chance(lam, t) == pytest.approx(expected, rel=1e-8, abs=0)


def test_chance_edges():
    assert C.chance(0, 12) == 0.0
    assert C.chance(0.5, 0) == 0.0
    assert C.chance(1e6, 1e6) == 1.0
    assert C.chance(math.inf, 12) == 1.0
    tiny = C.chance(1e-12, 1)          # plain 1 - exp(-x) gives 1.0000889e-12; expm1 keeps it exact
    assert tiny == pytest.approx(1e-12, rel=1e-9, abs=0) and tiny > 0
    for bad in (-1, float("nan"), None, "x"):
        with pytest.raises(ValueError):
            C.chance(bad, 1)
        with pytest.raises(ValueError):
            C.chance(1, bad)


def test_competing_causes():
    p1 = 0.05
    assert C.competing(p1, 1) == pytest.approx(p1)
    assert C.competing(p1, 2) == pytest.approx(1 - 0.95 ** 2)
    assert C.competing(1e-12, 1000) == pytest.approx(1e-9, rel=1e-6, abs=0)   # 1 - (1 - p)^N would be off by 1e-4
    assert C.competing(1.0, 5) == 1.0
    assert C.competing(0.0, 5) == 0.0
    for bad in (0, -1, 1.5):
        with pytest.raises(ValueError):
            C.competing(0.1, bad)
    with pytest.raises(ValueError):
        C.competing(1.01, 1)


@pytest.mark.parametrize("p,expected", [
    (0.0, "high"), (0.0099999, "high"), (0.01, "medium"), (0.0100001, "medium"),
    (0.0999999, "medium"), (0.10, "low"), (0.1000001, "low"), (1.0, "low"),
])
def test_band_edges_go_to_the_weaker_band(p, expected):
    assert C.band(p, CFG) == expected


# -- config -----------------------------------------------------------------------------------------
def test_frozen_file_loads_and_official_refuses_open_values(tmp_path):
    cfg = C.load_config()
    assert (cfg.band_high, cfg.band_medium, cfg.window, cfg.sleep_gap_seconds) == (0.01, 0.10, 12, 60)
    assert cfg.burst == 2.5                                   # decided 2026-10-24 (package J)
    official = C.load_config(official=True)                   # every official value chosen (pool hash 2026-10-30)
    assert official.pool_sha256.startswith("3e39f2cf")
    p = tmp_path / "open.yaml"
    p.write_text(Path(C.FROZEN).read_text(encoding="utf-8").replace("burst_factor: 2.5", "burst_factor: null"), encoding="utf-8")
    with pytest.raises(ValueError, match="burst_factor"):    # an open value is still refused in an official run
        C.load_config(str(p), official=True)


def _yaml(tmp_path, text):
    p = tmp_path / "frozen.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_config_refuses_null_unknown_and_disordered(tmp_path):
    base = ("confidence:\n  band_high: 0.01\n  band_medium: 0.10\n  window_before_seconds: 2\n"
            "  window_after_seconds: 10\n  sleep_gap_seconds: 60\n  min_pool_events: 5\n"
            "  competing_span_seconds: 900\n  lifetime_bands_seconds: [60, 3600]\n")
    assert C.load_config(_yaml(tmp_path, base)).window == 12
    with pytest.raises(ValueError, match="null"):
        C.load_config(_yaml(tmp_path, base.replace("band_high: 0.01", "band_high: null")))
    with pytest.raises(ValueError, match="unknown"):
        C.load_config(_yaml(tmp_path, base + "  band_hihg: 0.02\n"))
    with pytest.raises(ValueError):
        C.load_config(_yaml(tmp_path, base.replace("band_high: 0.01", "band_high: 0.2")))
    with pytest.raises(ValueError):
        C.load_config(_yaml(tmp_path, base + "  burst_factor: 0.5\n"))


# -- timing grade -----------------------------------------------------------------------------------
def test_within_life_rate_counts_the_effect_under_test():
    # one effect in a 1,000 s life: within-life rate 0.001/s, pool says 0 -> lambda = 0.001
    g = C.timing_grade(CFG, pool_rate=0.0, pool_source="x", n_effects=1, life_seconds=1000, n_causes=1)
    assert g.source == "within-life" and g.lam == pytest.approx(0.001)
    assert g.p == pytest.approx(C.chance(0.001, 12)) and g.band == "medium"   # 1.19 %
    with pytest.raises(ValueError):
        C.timing_grade(CFG, pool_rate=0.0, pool_source="x", n_effects=0, life_seconds=1000, n_causes=1)


def test_stricter_picture_wins():
    busy_pool = C.timing_grade(CFG, pool_rate=0.05, pool_source="program", n_effects=1, life_seconds=10_000, n_causes=1)
    assert busy_pool.source == "pool:program" and busy_pool.lam == 0.05
    busy_self = C.timing_grade(CFG, pool_rate=1e-6, pool_source="program", n_effects=50, life_seconds=10_000, n_causes=1)
    assert busy_self.source == "within-life" and busy_self.lam == pytest.approx(0.005)


def test_not_assessable_shorter_than_the_window():
    g = C.timing_grade(CFG, pool_rate=0.0, pool_source="x", n_effects=1, life_seconds=11.9, n_causes=1)
    assert g.band == "low" and g.p == 1.0 and "not assessable" in g.reason
    g = C.timing_grade(CFG, pool_rate=0.0, pool_source="x", n_effects=1, life_seconds=12.0, n_causes=1)
    assert g.source == "within-life"


def test_implied_lifetime_floors():
    # one effect, one cause: under ~114 s never better than low; under ~20 min never high
    assert C.timing_grade(CFG, pool_rate=0, pool_source="x", n_effects=1, life_seconds=113, n_causes=1).band == "low"
    assert C.timing_grade(CFG, pool_rate=0, pool_source="x", n_effects=1, life_seconds=120, n_causes=1).band == "medium"
    assert C.timing_grade(CFG, pool_rate=0, pool_source="x", n_effects=1, life_seconds=1190, n_causes=1).band == "medium"
    assert C.timing_grade(CFG, pool_rate=0, pool_source="x", n_effects=1, life_seconds=1200, n_causes=1).band == "high"


def test_competing_causes_lower_the_grade():
    one = C.timing_grade(CFG, pool_rate=0.0005, pool_source="x", n_effects=1, life_seconds=1e5, n_causes=1)
    many = C.timing_grade(CFG, pool_rate=0.0005, pool_source="x", n_effects=1, life_seconds=1e5, n_causes=5)
    assert one.band == "high" and many.band == "medium"          # 0.60 % -> 2.96 %
    assert many.p == pytest.approx(1 - (1 - one.p1) ** 5)
    lots = C.timing_grade(CFG, pool_rate=0.0005, pool_source="x", n_effects=1, life_seconds=1e5, n_causes=20)
    assert lots.band == "low"                                     # 11.3 %


def test_burst_factor_scales_lambda():
    cfg = C.ConfidenceConfig(**{**CFG.__dict__, "burst_factor": 3})
    g = C.timing_grade(cfg, pool_rate=0.0008, pool_source="x", n_effects=1, life_seconds=1e6, n_causes=1)
    assert g.lam == pytest.approx(0.0024)
    assert C.timing_grade(CFG, pool_rate=0.0008, pool_source="x", n_effects=1, life_seconds=1e6, n_causes=1).band == "high"
    assert g.band == "medium"          # the 0.96 % edge case the report warns about


# -- T1-T3 windows and pairs ------------------------------------------------------------------------
@pytest.mark.parametrize("dt,inside", [(-2.0, True), (-2.001, False), (0, True), (10.0, True), (10.001, False)])
def test_window_edges(dt, inside):
    assert C.in_window(100.0, 100.0 + dt, CFG) is inside


def test_effect_links_to_the_latest_cause_and_counts_competitors():
    causes = [100.0, 104.0, 2000.0]
    assert C.link_cause(causes, 105.0, CFG) == 104.0          # latest cause whose window contains it
    assert C.link_cause(causes, 102.5, CFG) == 104.0          # a cause up to 2 s AFTER the effect counts
    assert C.link_cause(causes, 115.0, CFG) is None
    assert C.n_competing(causes, 104.0, CFG) == 2             # 2000 is outside +-900 s
    assert C.n_competing([], 5.0, CFG) == 1


def test_pairs_only_within_one_process():
    pairs = C.timing_pairs([("A", 100.0), ("B", 200.0)], [("A", 103.0), ("B", 103.0), ("A", 300.0)], CFG)
    assert pairs == [("A", 103.0, 100.0, 1)]


def test_t1_folder_and_t2_inbound_filters():
    assert C.t1_effect_qualifies("ok") and C.t1_effect_qualifies(None)
    assert not C.t1_effect_qualifies("directory")
    assert C.t2_cause_qualifies("tcp", 445)
    assert not C.t2_cause_qualifies("udp", 53)                # a reply, not a request
    assert not C.t2_cause_qualifies("tcp", 50123)             # ephemeral, never listened
    assert C.t2_cause_qualifies("TCP", 50123, listened_ports=[50123])
    assert not C.t2_cause_qualifies("tcp", None)


# -- rule rows ----------------------------------------------------------------------------------------
def test_r1():
    a, b = "A1" * 32, "B2" * 32
    assert C.grade_r1(file_hash=a, process_hash=a.lower(), deleted_between=False).link == "fact"
    assert C.grade_r1(file_hash=a, process_hash=b, deleted_between=False).link == "none"
    assert C.grade_r1(file_hash=None, process_hash=b, deleted_between=False).band == "medium"
    assert C.grade_r1(file_hash=a, process_hash=None, deleted_between=False).band == "medium"
    assert C.grade_r1(file_hash=None, process_hash=None, deleted_between=True).band == "low"


H = "AB" * 32


def _r2(**kw):
    base = dict(content=H, x_fingerprint_time=100.0, y_creation_times=[150.0], start_time=200.0, n_other_paths=1)
    base.update(kw)
    return C.grade_r2(**base)


def test_r2_direction_supported():
    r = _r2()
    assert r["fact"] == "same content" and r["direction"].band == "high"
    assert _r2(n_other_paths=3)["direction"].band == "medium"
    assert _r2(n_other_paths=6)["direction"].band == "low"     # a low direction claim IS drawn


def test_r2_system32_and_fresh_recording_traps():
    # Y existed before the recording / before X (e.g. the real cmd.exe): no recorded creation since X
    r = _r2(y_creation_times=[])
    assert r["fact"] == "same content" and r["direction"] is None
    r = _r2(y_creation_times=[50.0])                           # Y created BEFORE X: X may be a copy of Y
    assert r["direction"] is None


def test_r2_source_must_still_exist_and_be_complete():
    assert _r2(x_deletion_times=[120.0])["direction"] is None          # X deleted before Y was created
    assert _r2(x_deletion_times=[180.0])["direction"].band == "high"   # deleted only after Y's creation
    assert _r2(sysmon_restart_times=[130.0])["direction"] is None       # e.g. a snapshot restore
    r = _r2(x_fingerprint_time=160.0)                                   # Y created before X's fingerprint
    assert r["direction"] is None and "fingerprint" in r["reason"]
    assert _r2(y_fingerprint="CD" * 32)["direction"] is None           # Y's own content differs
    assert _r2(x_known_only_from_deletion=True)["direction"] is None


def test_r2_constant_hashes_never_link():
    assert _r2(content=C.EMPTY_SHA256)["fact"] is None
    assert _r2(content="0" * 64)["fact"] is None


def test_r3_parsing_and_lookup_before_connection():
    ips = C.parse_query_results("type: 5 cdn.example;::ffff:192.0.2.7;2001:db8::1;")
    assert ips == {"192.0.2.7", "[2001:db8::1]"}
    lookups = [(100.0, "a.example", ips), (300.0, "b.example", {"192.0.2.7"})]
    assert C.names_for_connection(lookups, 200.0, "192.0.2.7", 900) == {"a.example"}   # b came AFTER
    assert C.names_for_connection(lookups, 1100.0, "192.0.2.7", 900) == {"b.example"}  # a is too old
    assert C.grade_r3(0).link == "none"
    assert [C.grade_r3(n).band for n in (1, 2, 4, 5)] == ["high", "medium", "medium", "low"]


def test_r4():
    assert C.grade_r4(full_path=True, deleted_between=False).band == "medium"
    assert C.grade_r4(full_path=False, deleted_between=False).band == "low"
    assert C.grade_r4(full_path=True, deleted_between=True).band == "low"


def test_f1_marker():
    assert C.marker_host("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://192.0.2.7:18765/payload\r\n") == "192.0.2.7"
    # the marker is the program's own statement: never a fact, at most a high hypothesis (2026-10-24)
    g = C.grade_f1(host="192.0.2.7", endpoint_ip="::ffff:192.0.2.7")
    assert g.link == "hypothesis" and g.band == "high"
    g = C.grade_f1(host="files.example", endpoint_ip="192.0.2.7", r3_high_names={"files.example"})
    assert g.link == "hypothesis" and g.band == "high"                  # never a fact through R3
    # ports must match too (graph endpoints are ip:port)
    assert C.grade_f1(host="192.0.2.7", endpoint_ip="192.0.2.7", endpoint_port=53, marker_port=8080).link == "none"
    assert C.grade_f1(host="192.0.2.7", endpoint_ip="192.0.2.7", endpoint_port=18765, marker_port=18765).band == "high"
    assert C.marker_port("x  HostUrl=http://192.0.2.7:18765/p") == 18765
    assert C.marker_port("HostUrl=https://a.example/p") == 443 and C.marker_port("HostUrl=gopher://a/p") is None
    assert C.marker_port("HostUrl=http://a.example:99999/p") is None and C.marker_port(None) is None
    assert C.marker_port("HostUrl=http://192.0.2.7:0/p") == 0            # a forged :0 is not "the default 80"
    assert C.grade_f1(host="192.0.2.7", endpoint_ip="192.0.2.7", endpoint_port=80,
                      marker_port=C.marker_port("HostUrl=http://192.0.2.7:0/p")).link == "none"
    assert C.grade_f1(host="other.example", endpoint_ip="192.0.2.7").link == "none"
    assert C.grade_f1(host=None, endpoint_ip="192.0.2.7").link == "none"


# -- active time --------------------------------------------------------------------------------------
def test_sleep_gap_exactly_60_is_active_61_is_not():
    assert C.ActiveTime([0, 60], 60).total == 60
    assert C.ActiveTime([0, 61], 60).total == 0
    assert C.ActiveTime([0, 59, 120, 150], 60).total == 59 + 30
    a = C.ActiveTime([0, 10, 1000, 1010], 60)
    assert a.seconds(5, 1005) == pytest.approx(10)            # 5 s before the sleep + 5 s after it
    assert a.at_position(15) == pytest.approx(1005)
    assert C.ActiveTime([], 60).total == 0


# -- a small read-only event store -------------------------------------------------------------------
COLS = ("id", "dedup_key", "host", "channel", "record_id", "event_id", "type", "time", "origin", "UtcTime",
        "ProcessGuid", "Image", "ParentProcessGuid", "ParentImage", "Initiated", "Protocol", "DestinationPort",
        "LocalPort", "hash_status", "ref_record_id", "ref_time")
G = "{11111111-1111-1111-1111-111111111111}"
P2 = "{22222222-2222-2222-2222-222222222222}"
PRJ = "{33333333-3333-3333-3333-333333333333}"


def _iso(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _store(tmp_path, rows):
    path = tmp_path / "events.db"
    db = sqlite3.connect(path)
    db.execute(f"CREATE TABLE events ({', '.join(COLS)})")
    for i, r in enumerate(rows, 1):
        r = {"id": i, "dedup_key": f"k{i}", "host": "h", "channel": C.SYSMON_CHANNEL, "record_id": i,
             "origin": "normal", **r}
        if "t" in r:
            r["UtcTime"] = _iso(r.pop("t"))
            r["time"] = r["UtcTime"].replace(" ", "T") + "Z"
        db.execute(f"INSERT INTO events ({', '.join(r)}) VALUES ({', '.join('?' * len(r))})", list(r.values()))
    db.commit()
    db.close()
    return C._open_ro(str(path))


T0 = 1_760_000_000.0


def _toy(tmp_path):
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image=r"C:\x\tool.exe", ParentProcessGuid=P2, ParentImage=r"C:\x\shell.exe"),
            dict(event_id=3, t=T0 + 5, ProcessGuid=G, Image=r"C:\x\tool.exe", Initiated="true"),
            dict(event_id=11, t=T0 + 6, ProcessGuid=G, Image=r"C:\x\tool.exe", record_id=900),
            dict(event_id=11, t=T0 + 7, ProcessGuid=G, Image=r"C:\x\tool.exe", record_id=901),
            dict(event_id=3, t=T0 + 8, ProcessGuid=G, Initiated="false", Protocol="udp", DestinationPort=5353),
            dict(event_id=3, t=T0 + 9, ProcessGuid=G, Initiated="false", Protocol="tcp", DestinationPort=445),
            dict(event_id=5, t=T0 + 40, ProcessGuid=G),
            # a sleep: nothing for 500 s, then the machine wakes up
            dict(event_id=3, t=T0 + 540, ProcessGuid=P2, Initiated="true"),
            dict(event_id=3, t=T0 + 550, ProcessGuid=PRJ, Initiated="true", origin="project"),
            dict(event_id=11, t=T0 + 560, ProcessGuid=PRJ, origin="project")]
    db = _store(tmp_path, rows)
    return db


def test_read_only_store_rates_and_project_exclusion(tmp_path):
    db = _toy(tmp_path)
    with pytest.raises(sqlite3.OperationalError):
        db.execute("INSERT INTO events (id) VALUES (999)")       # the connection really is read-only
    act = C.load_activity(db, CFG)
    assert act.active.total == pytest.approx(40 + 20)            # 0-40 s and 540-560 s; the 500 s sleep left out
    assert PRJ.upper() not in act.procs                           # our own tools' process is not a process here
    assert act.events["file"][G.upper()] == [T0 + 6, T0 + 7]
    assert act.events["in"][G.upper()] == [T0 + 9]                # UDP reply dropped, TCP 445 kept
    assert act.events["child"][P2.upper()] == [T0]
    assert act.procs[G.upper()]["life"] == pytest.approx(40)
    rate, n, secs = C.machine_rate(db, "event_id = ? AND Initiated = ?", (3, "true"), act.active)
    assert (n, secs) == (2, pytest.approx(60)) and rate == pytest.approx(2 / 60)   # project row excluded
    assert C.event_times(db, "Image = ?", ("C:\\x\\tool.exe' OR '1'='1",)) == []    # values never pasted into SQL


def test_folder_is_not_a_t1_effect(tmp_path):
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image="a.exe"),
            dict(event_id=11, t=T0 + 1, ProcessGuid=G, record_id=500),
            dict(event_id=11, t=T0 + 2, ProcessGuid=G, record_id=501),
            dict(channel=None, type="FILE_HASH", t=T0 + 3, hash_status="directory", ref_record_id=500,
                 ref_time=_iso(T0 + 1).replace(" ", "T") + "Z")]
    act = C.load_activity(_store(tmp_path, rows), CFG)
    assert act.events["file"][G.upper()] == [T0 + 2]


def test_pool_rate_is_the_larger_of_program_and_lifetime_band():
    """Yousif's decision 2026-10-23: lambda's pool part = max(program pool, lifetime-band pool)."""
    act = C.Activity(C.ActiveTime([0, 10_000], 1e9), {
        "a": {"program": "busy.exe", "life": 1000.0}, "b": {"program": "busy.exe", "life": 1000.0},
        "q": {"program": "calm.exe", "life": 2000.0},
        "c": {"program": "rare.exe", "life": 30.0}, "d": {"program": "other.exe", "life": 20.0}},
        {"file": {"a": [1, 2, 3, 4], "b": [5, 6, 7, 8], "q": [9, 10, 11, 12, 13], "c": [14], "d": [15, 16, 17]},
         "out": {}, "in": {}, "child": {}}, {})
    pool = C.Pool.build(act, CFG)
    # band 60-3600 s: 13 files over 4,000 s = 0.00325/s
    assert pool.rate("file", "busy.exe", 1000, CFG) == (pytest.approx(8 / 2000), "program")   # 0.004 > band
    assert pool.rate("file", "calm.exe", 1000, CFG) == (pytest.approx(13 / 4000), "lifetime 60-3600 s")  # 0.0025 < band
    rate, src = pool.rate("file", "rare.exe", 30, CFG)            # 1 event < 5: its lifetime band (< 60 s)
    assert src == "lifetime <60 s" and rate == pytest.approx(4 / 50)
    rate, src = pool.rate("file", "never-seen.exe", 5000, CFG)    # no laptop process lived >= 1 h
    assert rate == 0.0 and src == "lifetime >=3600 s"


def test_impostor_name_never_beats_a_new_name():
    """Re-check finding 3 (Yousif's decision 2026-10-23): a program named like a quiet laptop
    program, alive 1,500 s, one connection and one file 1 s later, must not get a better grade
    than the same behaviour under a never-seen name. Before the decision the quiet program's
    pool rate alone was used: 'high' under the borrowed name, 'low' under a new one."""
    procs = {f"q{i}": {"program": "quiet.exe", "life": 50_000.0} for i in range(4)}
    procs.update({f"m{i}": {"program": f"tool{i}.exe", "life": 1000.0} for i in range(5)})
    files = {"q0": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]}                    # quiet.exe: 6 files in 200,000 s
    files.update({f"m{i}": list(np.arange(0, 1000, 50.0)) for i in range(5)})  # 1-60 min band: 0.02 files/s
    pool = C.Pool.build(C.Activity(C.ActiveTime([0, 1e6], 1e9), procs,
                                   {"file": files, "out": {}, "in": {}, "child": {}}, {}), CFG)
    empty_state = {"program": None, "t0": 0.0, "t1": 1500.0, "life": 1500.0}
    grades = {}
    for name in ("quiet.exe", "brand-new.exe"):
        act = C.Activity(C.ActiveTime(list(range(0, 1501, 30)), 60), {"g": {**empty_state, "program": name}},
                         {"out": {"g": [700.0]}, "file": {"g": [701.0]}, "in": {}, "child": {}}, {})
        grades[name] = C.grade_process_link("T1", "g", 701.0, act, pool, CFG)[1]
    order = {"high": 0, "medium": 1, "low": 2}
    assert grades["quiet.exe"].p >= grades["brand-new.exe"].p
    assert order[grades["quiet.exe"].band] >= order[grades["brand-new.exe"].band]
    assert grades["quiet.exe"].band == grades["brand-new.exe"].band == "low"   # band 0.02/s: p1 = 21 %


def test_pool_save_load_and_sha_check(tmp_path):
    act = C.Activity(C.ActiveTime([0, 100], 1e9), {"a": {"program": "x.exe", "life": 100.0}},
                     {"file": {"a": [1]}, "out": {}, "in": {}, "child": {}}, {})
    pool = C.Pool.build(act, CFG)
    sha = pool.save(str(tmp_path / "pool.json"))
    again = C.Pool.load(str(tmp_path / "pool.json"), expect_sha256=sha)
    assert again.rate("file", "x.exe", 100, CFG) == pool.rate("file", "x.exe", 100, CFG)
    with pytest.raises(ValueError, match="SHA256"):
        C.Pool.load(str(tmp_path / "pool.json"), expect_sha256="0" * 64)


# -- simulation: the formula against random events at a known rate ------------------------------------
def _poisson_with_sleeps(rng, lam, stretches=60, length=4000.0, sleep=5000.0):
    """Events at rate `lam` inside active stretches, separated by sleeps longer than the gap.
    Each stretch also has a heartbeat every 30 s, so active time = the stretches."""
    effects, beats = [], []
    for i in range(stretches):
        s = i * (length + sleep)
        n = rng.poisson(lam * length)
        effects += list(s + rng.uniform(0, length, n))
        beats += list(np.arange(s, s + length, 30.0)) + [s + length]
    return np.sort(np.array(effects)), C.ActiveTime(beats + list(effects), CFG.sleep_gap_seconds)


def _hit(effects, a, cfg=CFG):
    lo = np.searchsorted(effects, a - cfg.window_before_seconds, side="left")
    hi = np.searchsorted(effects, a + cfg.window_after_seconds, side="right")
    return hi > lo


@pytest.mark.parametrize("lam", [0.0005, 0.002, 0.01])
def test_simulation_predicted_equals_observed_with_sleep_gaps(lam):
    """Random events at a known rate, with sleeps in between: lambda measured over ACTIVE time
    predicts how often a random moment has an event in its window. Tolerance: 4 standard
    errors of the anchor count plus a 3 % relative allowance for windows cut at stretch edges."""
    rng = np.random.default_rng(7)
    effects, active = _poisson_with_sleeps(rng, lam)
    lam_hat = len(effects) / active.total
    anchors = active.at_position(rng.uniform(0, active.total, 200_000))
    observed = _hit(effects, anchors).mean()
    predicted = C.chance(lam_hat, CFG.window)
    se = math.sqrt(predicted * (1 - predicted) / len(anchors))
    assert abs(observed - predicted) <= 4 * se + 0.03 * predicted, (observed, predicted)
    assert active.total == pytest.approx(60 * 4000, rel=1e-3)      # the sleeps were not counted


def test_simulation_competing_causes():
    """N causes with non-overlapping windows: the share of cause groups with at least one chance
    effect matches 1 - (1 - p1)^N."""
    rng = np.random.default_rng(11)
    lam, n = 0.002, 6
    effects, active = _poisson_with_sleeps(rng, lam)
    p1 = C.chance(len(effects) / active.total, CFG.window)
    starts = active.at_position(rng.uniform(0, active.total - 1000, 40_000))
    groups = np.stack([_hit(effects, starts + 100.0 * k) for k in range(n)])
    observed = groups.any(axis=0).mean()
    predicted = C.competing(p1, n)
    se = math.sqrt(predicted * (1 - predicted) / starts.size)
    assert abs(observed - predicted) <= 4 * se + 0.03 * predicted, (observed, predicted)


def test_demonstration_bursty_effects_break_the_poisson_assumption():
    """Not a pass/fail claim about reality, a demonstration of the direction of the error:
    effects that come in clumps (10 within 5 s) leave most windows empty, so the formula
    (which assumes evenly random events) over-predicts the chance at a random moment."""
    rng = np.random.default_rng(3)
    centres = np.sort(rng.uniform(0, 1e6, 500))
    effects = np.sort((centres[:, None] + rng.uniform(0, 5, (500, 10))).ravel())
    active = C.ActiveTime(np.concatenate([np.arange(0, 1e6, 30.0), effects]), 60)
    predicted = C.chance(len(effects) / active.total, 12)
    observed = _hit(effects, rng.uniform(0, 1e6, 100_000)).mean()
    assert observed < 0.25 * predicted                              # ~ 10x fewer windows hit than predicted


def test_demonstration_startup_burst_is_caught_by_the_within_life_rate():
    """A program connects and writes 5 files in its first seconds, then idles for 10 minutes:
    a quiet pool rate alone would call its connection->file pair "high"; the within-life rate
    (5 files in 600 s) makes it medium/low, which is why it is always included."""
    pool_only = C.timing_grade(CFG, pool_rate=1e-5, pool_source="program", n_effects=1, life_seconds=1e6, n_causes=1)
    real = C.timing_grade(CFG, pool_rate=1e-5, pool_source="program", n_effects=5, life_seconds=600, n_causes=5)
    assert pool_only.band == "high" and real.band == "low"


# -- review findings (2026-10-23): one test each ---------------------------------------------------------
def test_life_without_an_end_stops_at_reboot_or_last_stretch(tmp_path):
    """Finding 1: a 20 s process with no event 5, then a shutdown and later runs, must not be
    treated as alive for the rest of the recording."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image="s.exe"),
            dict(event_id=3, t=T0 + 1, ProcessGuid=G, Initiated="true"),
            dict(event_id=11, t=T0 + 2, ProcessGuid=G, record_id=700),
            dict(event_id=3, t=T0 + 20, ProcessGuid=P2, Initiated="true"),     # the machine's last sign before shutdown
            dict(event_id=4, t=T0 + 5000, ProcessGuid=None),                   # Sysmon starts again (new boot)
            dict(event_id=3, t=T0 + 5030, ProcessGuid=P2, Initiated="true"),
            dict(event_id=3, t=T0 + 5060, ProcessGuid=P2, Initiated="true")]
    act = C.load_activity(_store(tmp_path, rows), CFG)
    p = act.procs[G.upper()]
    assert p["life"] == pytest.approx(20)            # end of the active stretch holding its last event
    assert act.counts["no_recorded_end"] >= 1
    rows2 = rows[:3] + [dict(event_id=4, t=T0 + 10, ProcessGuid=None), dict(event_id=3, t=T0 + 40, ProcessGuid=P2, Initiated="true")]
    sub = tmp_path / "reboot"
    sub.mkdir()
    act2 = C.load_activity(_store(sub, rows2), CFG)
    assert act2.procs[G.upper()]["life"] == pytest.approx(10)    # cut at the next Sysmon start (reboot)


def test_life_without_an_end_or_a_reboot_stops_at_the_last_active_stretch(tmp_path):
    """Re-check finding 1: a sleep (gap > 60 s) with NO Sysmon restart, then hours of activity
    by other processes: the silent process is not assumed alive through them."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image="s.exe"),
            dict(event_id=11, t=T0 + 30, ProcessGuid=G, record_id=700),
            dict(event_id=3, t=T0 + 50, ProcessGuid=P2, Initiated="true"),
            *[dict(event_id=3, t=T0 + 1000 + s, ProcessGuid=P2, Initiated="true") for s in range(0, 3 * 3600, 30)]]
    act = C.load_activity(_store(tmp_path, rows), CFG)
    assert act.active.total == pytest.approx(50 + 3 * 3600 - 30)
    assert act.procs[G.upper()]["life"] == pytest.approx(50)      # its stretch ends at T0 + 50


def test_until_also_hides_later_listen_and_folder_records(tmp_path):
    """Re-check finding 6: a listen record or a folder FILE_HASH after `until` is not known yet."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image=r"C:\a\server.exe"),
            dict(event_id=3, t=T0 + 5, ProcessGuid=G, Initiated="false", Protocol="tcp", DestinationPort=50500),
            dict(event_id=11, t=T0 + 6, ProcessGuid=G, record_id=800),
            dict(event_id=3, t=T0 + 20, ProcessGuid=P2, Initiated="true"),
            dict(channel=None, type="PORT_LISTEN_START", t=T0 + 30, LocalPort=50500, Image=r"C:\a\server.exe"),
            dict(channel=None, type="FILE_HASH", t=T0 + 30, hash_status="directory", ref_record_id=800,
                 ref_time=_iso(T0 + 6).replace(" ", "T") + "Z")]
    db = _store(tmp_path, rows)
    early = C.load_activity(db, CFG, until=T0 + 20)
    assert early.until == T0 + 20
    assert G.upper() not in early.events["in"] and early.events["file"][G.upper()] == [T0 + 6]
    late = C.load_activity(db, CFG)
    assert late.events["in"][G.upper()] == [T0 + 5] and G.upper() not in late.events["file"]
    with pytest.raises(ValueError, match="until"):
        C.grade_process_link("T1", G.upper(), T0 + 25, early, zero_pool(), CFG)


def test_grade_process_link_exact_on_a_hand_built_process():
    """Re-check finding 5: every number of one grade, by hand. Process alive 1,000 s, files at
    100, 105, 500 s, connections at 99 and 400 s, empty pool:
    within-life rate = 3 files / 1,000 s = 0.003/s (the effect under test included);
    the file at 105 s links to the connection at 99 s; N = 2 (99 and 400 are within 15 min);
    p1 = 1 - e^(-0.003 * 12) = 0.0353597; p = 1 - (1 - p1)^2 = 0.0694691 -> medium."""
    act = C.Activity(C.ActiveTime([0, 1000] + list(range(0, 1001, 30)), 60),
                     {"g": {"program": "p.exe", "t0": 0.0, "t1": 1000.0, "life": 1000.0}},
                     {"out": {"g": [99.0, 400.0]}, "file": {"g": [100.0, 105.0, 500.0]}, "in": {}, "child": {}}, {})
    empty = zero_pool()
    tc, g = C.grade_process_link("T1", "g", 105.0, act, empty, CFG)
    assert tc == 99.0 and g.n_causes == 2 and g.source == "within-life"
    assert g.lam == pytest.approx(0.003, rel=1e-12, abs=0)
    assert g.p1 == pytest.approx(0.0353597, rel=1e-5, abs=0)
    assert g.p == pytest.approx(0.0694691, rel=1e-5, abs=0) and g.band == "medium"
    assert C.grade_process_link("T1", "g", 500.0, act, empty, CFG) is None    # no connection within its window


def test_several_machines_need_a_host(tmp_path):
    """Finding 2: one machine's events must not fill another machine's sleep."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image="a.exe", host="vm"),
            dict(event_id=5, t=T0 + 3000, ProcessGuid=G, host="vm"),
            *[dict(event_id=3, t=T0 + s, ProcessGuid=P2, Initiated="true", host="laptop") for s in range(0, 3000, 30)]]
    db = _store(tmp_path, rows)
    with pytest.raises(ValueError, match="machines"):
        C.load_activity(db, CFG)
    assert C.load_activity(db, CFG, host="vm").procs[G.upper()]["life"] == 0.0     # VM silent in between
    assert C.load_activity(db, CFG, host="laptop").active.total == pytest.approx(2970)


def test_until_hides_later_data(tmp_path):
    """Finding 5: grades use only data up to the graph's end time."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image="a.exe"),
            *[dict(event_id=11, t=T0 + s, ProcessGuid=G, record_id=1000 + s) for s in range(10, 200, 10)]]
    act = C.load_activity(_store(tmp_path, rows), CFG, until=T0 + 55)
    assert len(act.events["file"][G.upper()]) == 5 and act.procs[G.upper()]["life"] == pytest.approx(50)


def test_t2_port_must_be_listened_on_by_the_same_program(tmp_path):
    """Finding 6: an inbound TCP connection to an ephemeral port counts only if THIS program
    listened on it (another program's listener does not qualify)."""
    rows = [dict(event_id=1, t=T0, ProcessGuid=G, Image=r"C:\a\server.exe"),
            dict(channel=None, type="PORT_LISTEN_START", t=T0 + 1, LocalPort=50500, Image=r"C:\a\server.exe"),
            dict(channel=None, type="PORT_LISTEN_START", t=T0 + 1, LocalPort=50600, Image=r"C:\b\other.exe"),
            dict(event_id=3, t=T0 + 5, ProcessGuid=G, Initiated="false", Protocol="tcp", DestinationPort=50500),
            dict(event_id=3, t=T0 + 6, ProcessGuid=G, Initiated="false", Protocol="tcp", DestinationPort=50600)]
    act = C.load_activity(_store(tmp_path, rows), CFG)
    assert act.events["in"][G.upper()] == [T0 + 5]


def test_r1_placeholder_hashes_are_not_a_fact():
    """Finding 7."""
    g = C.grade_r1(file_hash="0" * 64, process_hash="0" * 64, deleted_between=True)
    assert g.link == "hypothesis" and g.band == "low"


def test_r2_boundaries():
    """Finding 8 and the missing boundaries."""
    assert _r2(sysmon_restart_times=[170.0])["direction"] is None       # restart after Y's creation, before the start
    assert _r2(y_deletion_times=[160.0])["direction"] is None           # Y deleted after creation, before the start
    assert _r2(x_deletion_times=[150.0])["direction"] is None           # deletion exactly at Y's creation
    assert _r2(y_fingerprint=H.lower())["direction"].band == "high"     # case does not matter
    assert [_r2(n_other_paths=n)["direction"].band for n in (2, 4, 5)] == ["medium", "medium", "low"]
    with pytest.raises(ValueError):
        _r2(n_other_paths=0)
    assert _r2(y_creation_times=[50.0, 150.0])["direction"].band == "high"   # the later creation counts
    assert "possibly before X existed" in _r2(y_creation_times=[50.0])["reason"]


def test_input_checks_finding_9():
    assert C.chance(np.int64(1), 12) == pytest.approx(1 - math.exp(-12))
    assert C.chance(np.float64(0.01), np.float32(2)) == pytest.approx(0.0198013267, rel=1e-6)
    for bad in (True, False):
        with pytest.raises(ValueError):
            C.chance(bad, 1)
    with pytest.raises(ValueError):
        C.competing(0.1, math.inf)
    with pytest.raises(ValueError):
        C.timing_grade(CFG, pool_rate=0.0, pool_source="x", n_effects=1, life_seconds=math.inf, n_causes=1)
    with pytest.raises(ValueError):
        C.ActiveTime([], 60).at_position(0)
    assert C.ActiveTime([], 60).seconds(0, 10) == 0.0


def test_unknown_program_is_not_pooled_as_a_program():
    act = C.Activity(C.ActiveTime([0, 100], 1e9), {"a": {"program": "?", "life": 100.0}},
                     {"file": {"a": [1, 2, 3, 4, 5, 6]}, "out": {}, "in": {}, "child": {}}, {})
    pool = C.Pool.build(act, CFG)
    assert "?" not in pool.per_program["file"]
    assert pool.rate("file", "?", 100, CFG)[1].startswith("lifetime")


def test_active_time_positions_around_gaps():
    a = C.ActiveTime([0, 10, 1000, 1010], 60)
    assert a.position(-5) == 0 and a.position(5) == 5 and a.position(500) == 10   # inside the sleep: end of stretch
    assert a.position(1000) == 10 and a.position(2000) == 20
    assert a.at_position(10) == pytest.approx(1000)           # the boundary maps to the next stretch's start
    assert a.at_position(0) == 0 and a.at_position(20) == pytest.approx(1010)
    assert a.stretch_end(5) == 10 and a.stretch_end(1005) == 1010 and a.stretch_end(500) == 10


# -- A16 machinery on a synthetic recording ------------------------------------------------------------
def _one_process(causes, effects, active):
    return C.Activity(active, {"g": {"program": "p.exe", "t0": float(active.starts[0]), "t1": float(active.ends[-1]),
                                     "life": active.total}},
                      {"out": {"g": list(causes)}, "file": {"g": list(effects)}, "in": {}, "child": {}}, {})


def test_a16_linked_effects_show_up_only_in_the_real_window():
    """Finding 11: effects 1 s after every cause -> real ~ 1, while the controls (rotate, shifted)
    still show only chance; a broken rotation (offset 0) would make rotate ~ 1 as well."""
    rng = np.random.default_rng(9)
    causes, active = _poisson_with_sleeps(rng, 0.002)
    effects = np.sort(causes + 1.0)
    act = _one_process(causes, effects, active)
    res = C.a16_check(act, C.Pool.build(act, CFG), CFG)["T1"]["all"]
    assert res["real"] > 0.99
    assert res["rotate"] < 3 * res["predicted"] and res["control"] < 3 * res["predicted"]


def test_a16_skips_processes_without_effects_and_out_of_life_shifts():
    """Finding 4 and 3: a process with causes but no effects is not counted; a shifted window
    that falls outside the process's life is not used."""
    active = C.ActiveTime(np.arange(0, 41, 1.0), 60)
    act = C.Activity(active, {"a": {"program": "x.exe", "t0": 0.0, "t1": 40.0, "life": 40.0},
                              "b": {"program": "y.exe", "t0": 0.0, "t1": 40.0, "life": 40.0}},
                     {"out": {"a": [32.0], "b": [5.0, 6.0, 7.0]}, "file": {"a": [1.0, 2.0, 33.0]}, "in": {}, "child": {}}, {})
    res = C.a16_check(act, C.Pool.build(act, CFG), CFG)["T1"]
    assert res["causes"] == 1                                   # b has no files: not in A16
    assert res["all"]["controlled_causes"] == 1                # the -30 s shift fits inside 0-40 s ...
    assert res["all"]["control"] == 1.0                         # ... and holds the files at 1 s and 2 s
    assert res["all"]["real"] == 1.0


def test_simulation_through_the_production_path():
    """Independent cause and effect streams in one process: the share of causes with an effect in
    their window matches grade_process_link's p1 (pool empty -> the within-life rate decides)."""
    rng = np.random.default_rng(13)
    effects, active = _poisson_with_sleeps(rng, 0.004)
    causes, _ = _poisson_with_sleeps(np.random.default_rng(14), 0.004)
    act = _one_process(causes, effects, active)
    empty = zero_pool()
    grades = [C.grade_process_link("T1", "g", te, act, empty, CFG) for te in effects]
    linked = [g for g in grades if g is not None]
    p1 = linked[0][1].p1
    assert all(g[1].source == "within-life" and g[1].p1 == p1 for g in linked)
    observed = _hit(effects, causes).mean()            # share of causes with an effect in their window
    se = math.sqrt(p1 * (1 - p1) / len(causes))
    assert abs(observed - p1) <= 4 * se + 0.03 * p1, (observed, p1)
def test_a16_check_runs_and_matches_on_random_data():
    effects, active = _poisson_with_sleeps(np.random.default_rng(5), 0.01)
    causes, _ = _poisson_with_sleeps(np.random.default_rng(6), 0.01)
    act = C.Activity(active, {"g": {"program": "p.exe", "t0": 0.0, "t1": float(active.ends[-1]), "life": active.total}},
                     {"out": {"g": list(causes)}, "file": {"g": list(effects)}, "in": {}, "child": {}}, {})
    pool = C.Pool.build(act, CFG)
    res = C.a16_check(act, pool, CFG)
    t1 = res["T1"]["all"]
    assert res["T1"]["causes"] == len(causes)
    # independent streams: the real window, the shifted windows and the rotation all show chance only
    se = math.sqrt(t1["predicted"] * (1 - t1["predicted"]) / len(causes))
    for k in ("real", "control", "rotate"):
        assert abs(t1[k] - t1["predicted"]) <= 4 * se + 0.03 * t1["predicted"], (k, t1)


def test_marker_host_reads_real_sysmon_rendering():
    from engine.confidence import marker_host
    real_shape = "[ZoneTransfer]  ZoneId=3  ReferrerUrl=https://ref.example/page  HostUrl=https://dl.example.test:8443/a.exe"
    assert marker_host(real_shape) == "dl.example.test"
    assert marker_host("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://10.0.2.2:18765/x.exe\r\n") == "10.0.2.2"
    assert marker_host("[ZoneTransfer]  ZoneId=3") is None and marker_host(None) is None
    assert marker_host("NotHostUrl=https://x.test/") is None

def test_leads_only_rows_are_never_above_low():
    """Package J (2026-10-24): T2 and T3 are leads only. The same hand-built numbers as above, as
    a T3 link (connection -> child start): the formula says medium, the grade says low, the chance
    is still reported; T1 is untouched."""
    from dataclasses import replace
    act = C.Activity(C.ActiveTime([0, 1000] + list(range(0, 1001, 30)), 60),
                     {"g": {"program": "p.exe", "t0": 0.0, "t1": 1000.0, "life": 1000.0}},
                     {"out": {"g": [99.0, 400.0]}, "file": {"g": [100.0, 105.0, 500.0]}, "in": {},
                      "child": {"g": [100.0, 105.0, 500.0]}}, {})
    cfg = replace(CFG, leads_only=("T2", "T3"))
    _, t3 = C.grade_process_link("T3", "g", 105.0, act, zero_pool(), cfg)
    assert t3.band == "low" and t3.p == pytest.approx(0.0694691, rel=1e-5) and "lead only" in t3.reason
    _, t1 = C.grade_process_link("T1", "g", 105.0, act, zero_pool(), cfg)
    assert t1.band == "medium"
    _, free = C.grade_process_link("T3", "g", 105.0, act, zero_pool(), CFG)       # without the setting: medium
    assert free.band == "medium"
    with pytest.raises(ValueError, match="leads_only"):
        replace(CFG, leads_only=("T9",))


def test_frozen_burst_factor_and_leads_only():
    cfg = C.load_config()
    assert cfg.burst_factor == 2.5 and set(cfg.leads_only) == {"T2", "T3"}

def test_the_frozen_pool_hash_refuses_any_other_pool(tmp_path):
    """confidence.pool_sha256 is set (2026-10-30): the real loading path refuses a pool that is not
    the frozen laptop pool (tests normally skip this check for their hand-made pools)."""
    from tests.conftest import REAL_FROM_POOL_FILE
    from engine.graph import Layer2
    cfg = C.load_config()
    assert cfg.pool_sha256 and len(cfg.pool_sha256) == 64
    pool = zero_pool()
    pool.save(str(tmp_path / "pool.json"))
    with pytest.raises(ValueError):
        REAL_FROM_POOL_FILE(Layer2, str(tmp_path / "pool.json"), cfg)
