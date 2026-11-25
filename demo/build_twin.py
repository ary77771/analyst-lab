"""Build docs/results/v4/twin.json for the "Evil twin" screen (debate 12 E10): two blind round-4
stories that look alike, one innocent and one an attack, as frozen v4 saw them (replayed by
tools/demo_replay.py from their official lived-in runs; nothing re-scored by hand).

    .venv\\Scripts\\python.exe demo\\build_twin.py
"""

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "docs", "results", "v4", "twin.json")

PAIR = [  # (scenario, official round-4 run used, kind written by the blind writer on the answer sheet)
    ("B19", "20261120-013940-301b", "innocent"),
    ("B18", "20261120-011832-4287", "attack"),
]


def newest_store(run_id):
    folders = sorted(glob.glob(os.path.join(ROOT, "recordings", "demo", f"{run_id}-*")))
    if not folders:
        raise SystemExit(f"no replay store for {run_id}: run tools/demo_replay.py <scenario> --run-id {run_id} --speed 0 --no-serve --exit")
    return os.path.join(folders[-1], "events.db"), os.path.join(folders[-1], "alerts.db")


def title_of(scenario, run_id):
    sheet = os.path.join(ROOT, "recordings", "blind", scenario.lower(), run_id, "ground_truth.yaml")
    import yaml
    with open(sheet, encoding="utf-8") as f:
        return (yaml.safe_load(f) or {}).get("title", scenario)


def build():
    from fastapi.testclient import TestClient
    from engine import config, report as R
    from engine.alerts import LEVELS, AlertStore
    from engine.dashboard.app import create_app
    floor = LEVELS.index(config.min_level())
    sides = []
    for scenario, run_id, kind in PAIR:
        store, alerts_db = newest_store(run_id)
        s = AlertStore(alerts_db)
        every = sorted(s.read(), key=lambda a: a.time)
        s.close()
        c = TestClient(create_app(store, alerts_db, hypotheses=R.layer2_from(R.DEFAULT_POOL), hubs=config.hubs()))
        side = {"scenario": scenario, "run_id": run_id, "kind": kind, "title": title_of(scenario, run_id),
                "raised": [], "below_floor": []}
        for a in every:
            item = {"title": a.title, "level": a.level, "rule": a.rule_id}
            if LEVELS.index(a.level) >= floor:
                inv = c.get(f"/api/alerts/{a.alert_id}").json()
                v = inv["report"].get("verdict") or {}
                item["steps"] = [st["text"] for st in v.get("steps", [])]
                item["counts"] = inv["report"].get("counts")
                side["raised"].append(item)
            else:
                side["below_floor"].append(item)
        sides.append(side)
    out = {"source": "official blind round-4 runs on the lived-in VM, replayed through frozen v4 (tools/demo_replay.py)",
           "floor": config.min_level(), "sides": sides}
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    for sd in sides:
        print(sd["scenario"], sd["kind"], "raised", len(sd["raised"]), "below floor", len(sd["below_floor"]))
    return out


if __name__ == "__main__":
    build()
