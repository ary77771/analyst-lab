"""Package I: the dashboard's JSON API (engine/dashboard/app.py) against fixed shapes."""

import sys
import time

from fastapi.testclient import TestClient

from engine.alerts import AlertStore
from engine.dashboard.app import Runner, create_app
from tests.test_report import s1_like


def client_for(tmp_path, runner=None):
    con, alert, G = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert])
    s.close()
    rec = tmp_path / "rec"
    (rec / "scenario_runs").mkdir(parents=True)
    return TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(rec), runner=runner)), alert


def test_vm_host_name_refused_laptop_names_accepted(tmp_path):
    """The VM reaches the laptop's loopback as 10.0.2.2: it must not read pages or start a run."""
    from engine.dashboard.app import DASHBOARD_HOSTS

    class NoRun:
        def start(self, scenario):
            raise AssertionError("a run was started from a refused Host")

    con, alert, G = s1_like(tmp_path)
    con.close()
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"),
                              runner=NoRun(), allowed_hosts=DASHBOARD_HOSTS))
    for vm_name in ("10.0.2.2:8780", "10.0.2.2", "evil.example"):
        assert c.get("/api/alerts", headers={"host": vm_name}).status_code == 421
        assert c.post("/api/scenarios/s1/run", headers={"host": vm_name}).status_code == 421
    assert c.get("/api/alerts", headers={"host": "127.0.0.1:8780"}).status_code == 200
    assert c.get("/api/alerts", headers={"host": "localhost:8780"}).status_code == 200


def test_main_serves_with_the_laptop_only_host_list(monkeypatch, tmp_path):
    import engine.dashboard.app as dash
    seen = {}
    monkeypatch.setattr(dash.report_mod, "official_or_exit", lambda *a: None)
    monkeypatch.setattr(dash.report_mod, "layer2_from", lambda pool: None)
    monkeypatch.setattr(dash, "create_app", lambda *a, **kw: seen.update(kw) or object())
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    dash.main(["--events", str(tmp_path / "s.db"), "--alerts", str(tmp_path / "a.db"), "--no-hubs"])
    assert seen["allowed_hosts"] == dash.DASHBOARD_HOSTS and "10.0.2.2" not in dash.DASHBOARD_HOSTS


def test_alert_list_and_levels(tmp_path):
    c, alert = client_for(tmp_path)
    rows = c.get("/api/alerts").json()
    assert [r["id"] for r in rows] == [alert.alert_id]
    assert set(rows[0]) == {"id", "title", "rule", "source", "level", "time", "host", "reason", "events"}
    assert c.get("/api/alerts?min_level=high").json() == []          # the alert is medium
    assert c.get("/api/alerts?min_level=nonsense").status_code == 400


def test_investigation_graph_matches_the_engine(tmp_path):
    c, alert = client_for(tmp_path)
    inv = c.get(f"/api/alerts/{alert.alert_id}").json()
    assert set(inv) == {"alert", "nodes", "edges", "report", "warnings"} and inv["warnings"] == []
    ids = {n["id"] for n in inv["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in inv["edges"])
    assert any(n["seed"] for n in inv["nodes"])
    assert {e["grade"] for e in inv["edges"]} == {"fact"} and all(e["evidence"] for e in inv["edges"])
    # same facts as the report built straight from the engine
    assert sorted(e["sentence"] for e in inv["edges"]) == sorted(f["sentence"] for f in inv["report"]["facts"])
    ev = c.get("/api/events/" + inv["edges"][0]["evidence"][0]).json()
    assert ev["dedup_key"] == inv["edges"][0]["evidence"][0] and "raw_xml" not in ev
    assert c.get("/api/events/nope").status_code == 404
    assert c.get("/api/alerts/nope").status_code == 404


def test_report_page_and_static_files(tmp_path):
    c, alert = client_for(tmp_path)
    page = c.get(f"/api/alerts/{alert.alert_id}/report")
    assert page.status_code == 200 and "4. Established facts" in page.text
    assert "cytoscape.min.js" in c.get("/").text
    assert c.get("/static/vendor/cytoscape.min.js").status_code == 200
    assert c.get("/static/app.js").status_code == 200


def test_scenarios_and_one_run_at_a_time(tmp_path):
    fake = [sys.executable, "-c", "import time, sys; print('fake run', sys.argv[1:]); time.sleep(1.5)"]
    runner = Runner(str(tmp_path / "rec"), command=fake)
    c, _ = client_for(tmp_path, runner=runner)
    ids = [s["id"] for s in c.get("/api/scenarios").json()]
    assert {"s0", "s1", "s5"} <= set(ids)
    assert c.post("/api/scenarios/nope/run").status_code == 404
    first = c.post("/api/scenarios/s1/run").json()
    assert first["running"] and first["scenario"] == "s1"
    assert c.post("/api/scenarios/s2/run").status_code == 409          # one at a time
    for _ in range(50):
        st = c.get("/api/run").json()
        if not st["running"]:
            break
        time.sleep(0.1)
    assert st["exit_code"] == 0 and any("fake run" in l for l in st["log_tail"])
    assert "--headless" in " ".join(st["log_tail"])

def test_hubs_and_hypotheses_reach_the_api(tmp_path):
    from engine import confidence as C
    from engine.graph import Layer2, norm_path
    con, alert, G = s1_like(tmp_path)
    con.close()
    s = AlertStore(str(tmp_path / "alerts.db"))
    s.write([alert])
    s.close()
    per_band = {k: {b: (1, 100.0) for b in ("<60", "60-3600", ">=3600")} for k in C.KINDS}
    C.Pool({k: {} for k in C.KINDS}, per_band, C.pool_settings(C.load_config())).save(str(tmp_path / "pool.json"))
    (tmp_path / "rec" / "scenario_runs").mkdir(parents=True)
    # the view is seeded on the evidence nearest the alert time (the payload's start, 2026-10-24
    # integration fix 4), and a seed is always walked: the hub is its parent
    hubs = frozenset({norm_path(r"C:\Users\u\fetch.exe")})
    c = TestClient(create_app(str(tmp_path / "s.db"), str(tmp_path / "alerts.db"), recordings=str(tmp_path / "rec"),
                              hypotheses=Layer2.from_pool_file(str(tmp_path / "pool.json")), hubs=hubs))
    inv = c.get(f"/api/alerts/{alert.alert_id}").json()
    assert {"hub", "hop"} <= set(inv["nodes"][0])
    assert [n["label"] for n in inv["nodes"] if n["hub"]] == ["fetch.exe (PID 10)"]
    assert "hypothesis" in {e["grade"] for e in inv["edges"]}         # layer 2 is on
    assert inv["report"]["graph"]["sigma_p"] is not None
    from engine import report
    from engine.graph import build_graph, parse_time
    G = build_graph(str(tmp_path / "s.db"), hypotheses=Layer2.from_pool_file(str(tmp_path / "pool.json")))
    assert {n["id"] for n in inv["nodes"]} == set(report.view(G, inv["report"]["graph"]["seed"], hubs,
                                                              at=parse_time(alert.time)))
