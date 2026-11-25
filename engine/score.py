"""One scoring pass over an event store: EVERY detector, the same way for the live loop and for
batch use (integration review 2026-10-24: the check-in rhythm rule was wired into neither, and
no batch command wrote our own rules' alerts).

    python -m engine.score --db <event store> --alerts <alert db>

Detectors: the Sigma rules (engine/detect.py: community rules + ours), our own rules
(engine/own_rules.py, with the learned-normal baselines listed in config/frozen.yaml), and the
check-in rhythm rule (engine/beacon.py). Every alert is returned whatever its level; the frozen
floor (config.min_level) only decides which are RAISED (shown, counted as alerts).
Counts only on screen (privacy rule 7).
"""

import argparse
import os
import time

from . import beacon, config, detect, own_rules
from .alerts import AlertStore

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_rules():
    """Community Sigma rules + our own Sigma folder (when present), as engine.detect loads them."""
    rules = []
    for paths, source in (([detect.COMMUNITY_RULES], "sigma"), ([detect.OWN_RULES], "analystlab")):
        if all(os.path.exists(p) for p in paths):
            rules += detect.load_rules(paths, source)[0]
    return rules


def baseline_files(path=config.FROZEN) -> list:
    """The learned-normal files config/frozen.yaml lists (`baselines:`), as absolute paths."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    return [os.path.normpath(os.path.join(root, e["file"])) for e in (config.load(path).get("baselines") or [])]


def load_baseline(files=None):
    """engine.baseline.load over the frozen list (or the given files); None when there are none.
    A listed file that is missing is an error: the learned-normal rules would silently be off."""
    from .baseline import load
    files = baseline_files() if files is None else files
    missing = [f for f in files if not os.path.exists(f)]
    if missing:
        raise FileNotFoundError(f"learned-normal baseline(s) missing: {', '.join(os.path.basename(m) for m in missing)}")
    return load(files) if files else None


def connectors_of(baseline):
    """v4 F2: {host: set of programs seen connecting} for the hosts whose learned files include a
    connector list (engine/baseline.load leaves the others None), or None without a baseline."""
    if not baseline:
        return None
    return {h: v["connectors"] for h, v in baseline.items() if v.get("connectors") is not None}


def score(con, rules, baseline=None, beacon_cfg=None, after_id=0, errors=None, timings=None,
          min_level="informational") -> list:
    """Every detector's alerts over the store `con` (opened with detect.open_store). Errors of one
    detector are recorded in `errors` as (detector, message) and never stop the others."""
    errors = [] if errors is None else errors
    timings = {} if timings is None else timings
    alerts = detect.detect(con, rules, min_level, timings, after_id=after_id)
    errors.extend(timings.pop("_errors", []))
    try:
        alerts += own_rules.run_all(con, baseline=baseline)
    except Exception as e:
        errors.append(("own_rules", f"{type(e).__name__}: {e}"))
    try:
        alerts += beacon.beacon_alerts(con, beacon_cfg or beacon.load_config(), connectors=connectors_of(baseline))
    except Exception as e:
        errors.append((beacon.RULE_ID, f"{type(e).__name__}: {e}"))
    return alerts


def raised(alerts, min_level=None):
    """The alerts at or above the frozen floor (what the lab counts as raised)."""
    floor = detect.LEVELS.index(min_level or config.min_level())
    return [a for a in alerts if detect.LEVELS.index(a.level) >= floor]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run every detector over an event store and write the alerts (counts only)")
    ap.add_argument("--db", required=True, help="event store (opened read-only)")
    ap.add_argument("--alerts", required=True, help="alert database to write")
    ap.add_argument("--baseline", nargs="*", help="learned-normal files (default: the ones config/frozen.yaml lists)")
    a = ap.parse_args(argv)
    rules = load_rules()
    baseline = load_baseline(a.baseline)
    con = detect.open_store(a.db)
    errors = []
    t0 = time.perf_counter()
    alerts = score(con, rules, baseline, errors=errors)
    took = time.perf_counter() - t0
    store = AlertStore(a.alerts)
    new = store.write(alerts, events_db=os.path.abspath(a.db))
    store.close()
    by_level = {lvl: sum(1 for x in alerts if x.level == lvl) for lvl in detect.LEVELS}
    print(f"{len(rules)} Sigma rules + {len(own_rules.RULES) + (len(own_rules.BASELINE_RULES) if baseline else 0)} own "
          f"rules + the check-in rhythm rule in {took:.1f} s; errors: {len(errors)}; alerts: {len(alerts)} ({new} new) "
          f"{by_level}; raised (>= {config.min_level()}): {len(raised(alerts))}")
    for rid, err in errors[:5]:
        print(f"   error in {rid[:24]}: {err[:120]}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
