"""Integration fixes 2026-10-24 (findings 1-7 of the integration review, the report/dashboard side):
the view bounds come from config/frozen.yaml, a pool must match the confidence config, official
mode is enforced, the report's view is centred on the alert, the dashboard reads the frozen
default / sees WAL rows / warns about another store / shapes endpoints, and the scenario graph
checker re-tags like the live loop. Every test uses its own fixtures (never recordings/)."""

import hashlib
import json
import os
import re
from datetime import timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

from engine import config, report
from engine import confidence as C
from engine import hubs as hubs_mod
from engine.alerts import LEVELS, Alert, AlertStore
from engine.graph import Layer2, build_graph, parse_time
from engine.store import EventStore
from tests.test_detect import ev
from tests.test_report import s1_like

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(PROJECT_ROOT, "engine", "dashboard", "static")
REAL_CFG = C.load_config()


# -- 1. the view bounds come from the frozen file ---------------------------------------------------
def test_graph_view_reads_the_frozen_numbers_and_refuses_nulls(tmp_path):
    assert config.graph_view() == (timedelta(minutes=15), 5, 60)
    gv = config.graph_view()
    assert gv.window == timedelta(minutes=15) and gv.max_depth == 5 and gv.max_nodes == 60
    f = tmp_path / "frozen.yaml"
    for bad in ("graph: {window_minutes: null, max_depth: 5, max_nodes: 60}",
                "graph: {window_minutes: 15, max_depth: 5}",
                "graph: {window_minutes: 15, max_depth: 0, max_nodes: 60}",
                "graph: {window_minutes: 15, max_depth: 2.5, max_nodes: 60}",
                "{}"):
        f.write_text(bad + "\n", encoding="utf-8")
        with pytest.raises(ValueError):
            config.graph_view(str(f))
    f.write_text("graph: {window_minutes: 7.5, max_depth: 3, max_nodes: 20}\n", encoding="utf-8")
    assert config.graph_view(str(f)) == (timedelta(minutes=7.5), 3, 20)


def test_report_view_and_its_limitations_use_the_configured_bounds(tmp_path, monkeypatch):
    con, alert, G = s1_like(tmp_path)
    monkeypatch.setattr(config, "graph_view", lambda path=None: config.GraphView(timedelta(minutes=7), 3, 2))
    c = report.build(alert, G)
    assert c["graph"]["nodes"] == 2 and c["graph"]["truncated"]            # the configured cap, not 60
    text = " ".join(c["limitations"])
    assert "7 minutes around the alert, at most 3 steps and 2 nodes" in text
    assert "hit the 2-node limit" in text and "60" not in text
    H = report.view(G, c["graph"]["seed"])                                  # the dashboard / checker path
    assert H.number_of_nodes() == 2 and H.graph["max_nodes"] == 2 and H.graph["window"] == timedelta(minutes=7)


def test_default_limitation_strings_match_the_frozen_file(tmp_path):
    con, alert, G = s1_like(tmp_path)
    assert "The view is bounded: 15 minutes around the alert, at most 5 steps and 60 nodes." in report.build(alert, G)["limitations"]


def _confidence_yaml(span=900, window=15, extra=""):
    return ("confidence:\n  band_high: 0.01\n  band_medium: 0.10\n  window_before_seconds: 2\n"
            "  window_after_seconds: 10\n  sleep_gap_seconds: 60\n  min_pool_events: 5\n"
            f"  competing_span_seconds: {span}\n  lifetime_bands_seconds: [60, 3600]\n{extra}"
            + (f"graph:\n  window_minutes: {window}\n" if window is not None else ""))


def test_competing_span_must_equal_the_graph_window(tmp_path):
    f = tmp_path / "frozen.yaml"
    f.write_text(_confidence_yaml(900, 15), encoding="utf-8")
    assert C.load_config(str(f)).competing_span_seconds == 900
    f.write_text(_confidence_yaml(900, 10), encoding="utf-8")
    with pytest.raises(ValueError, match="window_minutes"):
        C.load_config(str(f))
    f.write_text(_confidence_yaml(600, 10), encoding="utf-8")
    assert C.load_config(str(f)).competing_span_seconds == 600
    assert REAL_CFG.competing_span_seconds == config.graph_view().window.total_seconds()   # the real file agrees


# -- 2. a pool must match the confidence config ------------------------------------------------------
def _built_pool(cfg=REAL_CFG):
    act = C.Activity(C.ActiveTime([0, 100], 1e9), {"a": {"program": "x.exe", "life": 100.0}},
                     {"file": {"a": [1]}, "out": {}, "in": {}, "child": {}}, {})
    return C.Pool.build(act, cfg)


def test_pool_built_with_other_settings_is_refused(tmp_path):
    path = str(tmp_path / "pool.json")
    _built_pool().save(path)
    assert C.Pool.load(path, cfg=REAL_CFG).meta["sleep_gap_seconds"] == REAL_CFG.sleep_gap_seconds
    assert Layer2.from_pool_file(path, REAL_CFG).pool.meta["min_pool_events"] == REAL_CFG.min_pool_events
    for change in ({"sleep_gap_seconds": 300}, {"min_pool_events": 3}, {"lifetime_bands_seconds": (30, 3600)}):
        other = C.ConfidenceConfig(**{**REAL_CFG.__dict__, **change})
        with pytest.raises(ValueError, match="other confidence settings"):
            C.Pool.load(path, cfg=other)
        with pytest.raises(ValueError, match="other confidence settings"):
            Layer2.from_pool_file(path, other)


def test_pool_without_recorded_settings_is_refused(tmp_path):
    path = str(tmp_path / "pool.json")
    per_band = {k: {b: (1, 100.0) for b in C.lifetime_bands(REAL_CFG)} for k in C.KINDS}
    C.Pool({k: {} for k in C.KINDS}, per_band).save(path)                  # no meta at all
    with pytest.raises(ValueError, match="does not record the settings"):
        Layer2.from_pool_file(path, REAL_CFG)


def test_a_missing_band_is_an_error_not_a_zero_rate(tmp_path):
    per_band = {k: {"<60": (5, 100.0), ">=3600": (5, 100.0)} for k in C.KINDS}   # no "60-3600"
    pool = C.Pool({k: {} for k in C.KINDS}, per_band, C.pool_settings(REAL_CFG))
    assert pool.rate("file", "x.exe", 10, REAL_CFG)[0] == pytest.approx(0.05)
    with pytest.raises(ValueError, match="60-3600"):
        pool.rate("file", "x.exe", 600, REAL_CFG)                             # was (0, 0.0): no band floor
    path = str(tmp_path / "pool.json")
    pool.save(path)
    with pytest.raises(ValueError, match="lifetime band"):
        C.Pool.load(path, cfg=REAL_CFG)                                       # refused at load already


def test_pool_build_writes_every_band_even_an_empty_one():
    pool = _built_pool()                                                      # one process, 100 s: band 60-3600
    for k in C.KINDS:
        assert set(pool.per_band[k]) == set(C.lifetime_bands(REAL_CFG))
    assert pool.per_band["file"]["<60"] == (0, 0.0)
    pool.check_config(REAL_CFG)


# -- 3. official mode --------------------------------------------------------------------------------
def test_is_official_only_for_exactly_1(monkeypatch):
    assert not config.is_official()
    for value, want in (("1", True), ("0", False), ("true", False), ("", False)):
        monkeypatch.setenv("ANALYSTLAB_OFFICIAL", value)
        assert config.is_official() is want


def official_tree(tmp_path, burst="1.5", pool_sha=None, baseline_sha=None, hub_file="recordings/hubs/hubs.json"):
    """A complete hand-made project tree for verify_official: config/frozen.yaml, a pool, two
    baselines and a hub list, all with their right hashes (unless overridden)."""
    root = tmp_path / "proj"
    (root / "config").mkdir(parents=True)
    (root / "recordings" / "confidence").mkdir(parents=True)
    (root / "recordings" / "baselines").mkdir(parents=True)
    sha = _built_pool().save(str(root / "recordings" / "confidence" / "pool.json"))
    base = []
    for name in ("laptop", "vm"):
        p = root / "recordings" / "baselines" / f"{name}.json"
        p.write_text(json.dumps({"hosts": {name: {}}}), encoding="utf-8")
        base.append({"file": f"recordings/baselines/{name}.json",
                     "sha256": baseline_sha or hashlib.sha256(p.read_bytes()).hexdigest().upper(),   # any case
                     "learned_from": "test"})
    learned = {"method": "distinct_children", "top_share": 0.01, "min_children": 2, "hubs": [r"C:\A\X.exe"]}
    hub_sha = hubs_mod.save(learned, str(root / "recordings" / "hubs" / "hubs.json"), "test")
    doc = yaml.safe_load(_confidence_yaml())
    doc["confidence"].update(burst_factor=None if burst is None else float(burst), pool_sha256=pool_sha or sha)
    doc["sigma"] = {"min_level": "medium"}
    doc["baselines"] = base
    doc["graph"].update(max_depth=5, max_nodes=60,
                        hub_rule={"method": "distinct_children", "top_share": 0.01, "min_children": 2,
                                  "file": hub_file, "sha256": hub_sha})
    path = root / "config" / "frozen.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return str(path), root


def test_verify_official_passes_a_complete_tree(tmp_path):
    path, root = official_tree(tmp_path)
    assert config.verify_official(path) == []
    assert config.verify_official(path, pool=str(root / "recordings" / "confidence" / "pool.json")) == []


def test_verify_official_lists_every_problem(tmp_path):
    path, _ = official_tree(tmp_path / "a", burst=None)
    assert any("burst_factor" in p for p in config.verify_official(path))
    path, _ = official_tree(tmp_path / "b", pool_sha="0" * 64)
    assert any("pool" in p and "SHA256" in p for p in config.verify_official(path))
    path, root = official_tree(tmp_path / "c")
    os.remove(root / "recordings" / "confidence" / "pool.json")
    assert any("pool of normal rates missing" in p for p in config.verify_official(path))
    path, _ = official_tree(tmp_path / "d", baseline_sha="ab" * 32)
    assert sum("changed since it was frozen" in p for p in config.verify_official(path)) == 2
    path, root = official_tree(tmp_path / "e")
    os.remove(root / "recordings" / "baselines" / "vm.json")
    assert [p for p in config.verify_official(path) if "baseline" in p] == \
        ["baseline recordings/baselines/vm.json is missing on this machine"]
    path, _ = official_tree(tmp_path / "f", hub_file="recordings/hubs/missing.json")
    assert any(p.startswith("hub list:") for p in config.verify_official(path))
    path, root = official_tree(tmp_path / "g")
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    doc["baselines"] = []
    doc["graph"]["max_nodes"] = None
    open(path, "w", encoding="utf-8").write(yaml.safe_dump(doc))
    problems = config.verify_official(path)
    assert any("no learned-normal file" in p for p in problems) and any("max_nodes" in p for p in problems)
    doc["baselines"] = [{"file": "recordings/baselines/vm.json"}]          # no sha256 / learned_from
    open(path, "w", encoding="utf-8").write(yaml.safe_dump(doc))
    assert any("needs file, sha256 and learned_from" in p for p in config.verify_official(path))


def test_verify_official_refuses_a_pool_built_with_other_settings(tmp_path):
    path, root = official_tree(tmp_path)
    other = C.ConfidenceConfig(**{**REAL_CFG.__dict__, "sleep_gap_seconds": 300})
    sha = _built_pool(other).save(str(root / "recordings" / "confidence" / "pool.json"))
    doc = yaml.safe_load(open(path, encoding="utf-8"))
    doc["confidence"]["pool_sha256"] = sha                                  # the hash matches, the settings don't
    open(path, "w", encoding="utf-8").write(yaml.safe_dump(doc))
    assert any("other confidence settings" in p for p in config.verify_official(path))


def test_checker_and_report_refuse_to_start_in_official_mode_with_problems(tmp_path, capsys, monkeypatch):
    import check_graph_scenario
    from tests.test_check_graph_scenario import good_run, run
    seen = []
    monkeypatch.setattr(config, "verify_official", lambda path=None, pool=None: seen.append(pool) or ["burst_factor is null"])
    monkeypatch.setenv("ANALYSTLAB_OFFICIAL", "1")
    code, out = run(tmp_path, capsys, good_run())
    assert code == 1 and "FAIL  official run: burst_factor is null" in out and "RESULT: FAIL" in out
    assert seen == [os.path.join(str(tmp_path), "confidence", "pool.json")]   # the pool the checker would use
    monkeypatch.setattr(config, "verify_official", lambda path=None, pool=None: [])
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path)]) == 0
    assert "official run: frozen values, pool, baselines and hub list verified" in capsys.readouterr().out
    assert check_graph_scenario.main(["s1", "--recordings", str(tmp_path), "--no-hubs"]) == 1   # not in official
    monkeypatch.setattr(config, "verify_official", lambda path=None, pool=None: ["pool missing"])
    with pytest.raises(SystemExit) as e:
        report.main(["--db", "x.db", "--alerts", "a.db", "--alert", "1", "--out", str(tmp_path / "r.html")])
    assert e.value.code == 1 and "FAIL  official run: pool missing" in capsys.readouterr().out
    from engine.dashboard import app as dash
    with pytest.raises(SystemExit) as e:
        dash.main(["--events", "x.db", "--alerts", "a.db"])
    assert e.value.code == 1 and "FAIL  official run: pool missing" in capsys.readouterr().out
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL")                                # not official: no check at all
    monkeypatch.setattr(config, "verify_official", lambda path=None, pool=None: pytest.fail("checked outside official mode"))
    report.official_or_exit(None)


# -- 4. the report's view is centred on the alert ----------------------------------------------------
POLLER = r"C:\x\poller.exe"


def beacon_store(tmp_path, at=(60, 660, 1260, 1860)):
    """A poller connecting every 10 minutes: its evidence spans 30 min, twice the view window."""
    recs = [ev(1, 0, happened=0, ProcessGuid="{B}", Image=POLLER, ProcessId=5, ParentProcessGuid="{A}")]
    recs += [ev(3, s, happened=s, ProcessGuid="{B}", Image=POLLER, Protocol="tcp", Initiated="true", SourceIp="10.0.0.2",
                SourcePort=50000 + i, DestinationIp="10.0.0.9", DestinationPort=443) for i, s in enumerate(at)]
    path = str(tmp_path / "b.db")
    st = EventStore(path)
    st.insert(recs)
    st.close()
    return path, recs[1:]


def test_beacon_view_contains_the_alert_time(tmp_path):
    path, conns = beacon_store(tmp_path)
    G = build_graph(path)
    alert = Alert("beacon", "Regular check-ins", "beacon", "medium", conns[-1]["time"], "h1", "every 600 s",
                  tuple(EventStore.dedup_key(r) for r in conns))                 # evidence in time order
    c = report.build(alert, G)
    times = {f["time"] for f in c["facts"] if f["kind"] == "connected_to"}
    last = report._time(parse_time(conns[-1]["time"]))
    assert last in times and report._time(parse_time(conns[0]["time"])) not in times   # centred on the alert
    assert c["graph"]["seed"] == EventStore.dedup_key(conns[-1]) and c["graph"]["at"] == last
    assert report.BEACON_LIMITATION in c["limitations"]


def test_seed_is_the_evidence_nearest_the_alert_time_whatever_the_key_order(tmp_path):
    path, conns = beacon_store(tmp_path)
    G = build_graph(path)
    keys = sorted(EventStore.dedup_key(r) for r in conns)
    keys.reverse()                                                              # an arbitrary (sorted) order
    alert = Alert("sigma-x", "Correlation", "sigma", "high", conns[1]["time"], "h1", "x", tuple(keys))
    seed, at = report.alert_seed(alert, G)
    assert seed == EventStore.dedup_key(conns[1]) and at == parse_time(conns[1]["time"])
    assert report.BEACON_LIMITATION not in report.build(alert, G)["limitations"]   # only for beacon alerts
    lost = Alert("r", "Lost", "sigma", "low", "not a time", "h1", "x", ("nowhere", keys[0]))
    assert report.alert_seed(lost, G) == (keys[0], None)                        # unreadable time: first resolvable


# -- 5. dashboard ------------------------------------------------------------------------------------
def dash_client(tmp_path, events_db_recorded=None, **kw):
    from engine.dashboard.app import create_app
    tmp_path.mkdir(parents=True, exist_ok=True)
    con, alert, G = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert], events_db=events_db_recorded)
    s.close()
    (tmp_path / "rec" / "scenario_runs").mkdir(parents=True)
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"), **kw)), alert


def test_api_config_gives_the_frozen_default_and_the_page_uses_it(tmp_path):
    c, _ = dash_client(tmp_path)
    assert c.get("/api/config").json() == {"min_level": config.min_level(), "levels": list(LEVELS)}
    page = c.get("/classic").text      # debate 11: "/" serves the new dashboard once built; the freeze-v4 page stays at /classic
    assert "<option selected>" not in page and 'id="min-level"' in page
    js = c.get("/static/app.js").text
    assert '"/api/config"' in js and "cfg.min_level" in js


def test_graph_cache_sees_new_rows_in_the_wal(tmp_path, monkeypatch):
    from engine.dashboard import app as dash
    builds = []
    real = dash.build_graph
    monkeypatch.setattr(dash, "build_graph", lambda *a, **k: builds.append(1) or real(*a, **k))
    c, alert = dash_client(tmp_path)
    db = str(tmp_path / "s.db")
    assert c.get(f"/api/alerts/{alert.alert_id}").status_code == 200 and len(builds) == 1
    c.get(f"/api/alerts/{alert.alert_id}")
    assert len(builds) == 1                                                     # nothing new: cached
    mtime = os.stat(db).st_mtime_ns
    writer = EventStore(db)                                                     # the live loop: WAL, kept open
    try:
        writer.insert([ev(1, 9, ProcessGuid="{N}", ParentProcessGuid="{C}", Image=r"C:\x\new.exe", ProcessId=12)])
        os.utime(db, ns=(mtime, mtime))                                         # the main file looks unchanged
        assert os.path.exists(db + "-wal")
        inv = c.get(f"/api/alerts/{alert.alert_id}").json()
        assert len(builds) == 2 and any(n["label"].startswith("new.exe") for n in inv["nodes"])
    finally:
        writer.close()


def test_warning_when_the_alert_names_another_store(tmp_path):
    c, alert = dash_client(tmp_path, events_db_recorded=str(tmp_path / "other.db"))
    inv = c.get(f"/api/alerts/{alert.alert_id}").json()
    assert len(inv["warnings"]) == 1 and "other.db" in inv["warnings"][0] and "s.db" in inv["warnings"][0]
    assert inv["warnings"][0] in inv["report"]["limitations"]
    assert "other.db" in c.get(f"/api/alerts/{alert.alert_id}/report").text
    js = open(os.path.join(STATIC, "app.js"), encoding="utf-8").read()
    assert "inv.warnings" in js
    c2, alert2 = dash_client(tmp_path / "same", events_db_recorded=str(tmp_path / "same" / "s.db"))
    assert c2.get(f"/api/alerts/{alert2.alert_id}").json()["warnings"] == []


def test_every_graph_node_kind_has_its_shape():
    js = open(os.path.join(STATIC, "app.js"), encoding="utf-8").read()
    shapes = re.search(r"const SHAPES = \{([^}]*)\}", js).group(1)
    keys = set(re.findall(r"(\w+):", shapes))
    graph_src = open(os.path.join(PROJECT_ROOT, "engine", "graph.py"), encoding="utf-8").read()
    kinds = set(re.findall(r'kind="(\w+)", host=', graph_src)) | set(re.findall(r'self\.other\("(\w+)"', graph_src))
    assert kinds == {"process", "file", "endpoint", "dns", "port", "autostart"} and kinds <= keys


# -- 6. the scenario graph checker re-tags like the live loop ----------------------------------------
def test_checker_retags_vm_records_with_the_strict_rules(tmp_path, capsys):
    """An old VM agent tagged the story "project" (its command line mentioned the tools folder);
    today's strict rules (engine/retag.py) say normal, as the live loop and engine.load re-tag it.
    Without re-tagging, layer 2 never sees the downloader and its hypothesis is missing."""
    from tests.test_check_graph_scenario import good_run, run
    rows = good_run()
    for r in rows:
        r["origin"] = "project"
    code, out = run(tmp_path, capsys, rows)
    assert code == 0, out
    assert "hypothesis  PASS" in out


def test_checker_retags_the_whole_stream_before_cutting_the_window(tmp_path, capsys, monkeypatch):
    import check_graph_scenario
    from tests.test_check_graph_scenario import good_run, run
    calls = []
    real = check_graph_scenario.read_recordings
    monkeypatch.setattr(check_graph_scenario, "read_recordings",
                        lambda paths, retag=False: calls.append((list(paths), retag)) or real(paths, retag=retag))
    code, out = run(tmp_path, capsys, good_run())
    assert code == 0, out
    (paths, retag), = calls
    assert retag is True and [os.path.basename(p) for p in paths] == ["2026-10-17.jsonl"]   # every file of the label
