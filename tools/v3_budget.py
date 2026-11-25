"""v3 pre-registration section 1.8: the pass/fail false-alarm budgets of the v3 rules on the v3 laptop
test week, computed by frozen code (this file is under the code gate).

    set ANALYSTLAB_OFFICIAL=1
    python tools/v3_budget.py --label official          # reads recordings/scratch/test/test-laptop-v3.db

(a) embedded_system_name and drop_run_delete: at most 0.1 alerts per AWAKE hour each, awake hours =
    engine/beacon.host_segments over every host in the snapshot (the same stretches the beacon rule uses);
(b) the short check-in test: at most +10 % alerted series over the RITA gate alone, a series = (host,
    program, destination ip, port, awake window), counted with the frozen beacon config with and without
    the short gate. Aggregates only (privacy rule 7). Exit 0 = computed (pass or fail is in the output),
    2 = refused.
(c) v4 pre-registration 3c: v4's raised DECLARED alerts (F7 + F8 together, details.derived_from =
    "command_line"), from every detector run by engine.score, at most 0.1 per awake hour.
"""
import argparse
import json
import os
import sqlite3
import sys
from dataclasses import replace

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, HERE)
from engine import beacon as B  # noqa: E402
from engine import own_rules as O  # noqa: E402
from engine import score as S  # noqa: E402
from engine.config import declared_kinds, own_rule_params  # noqa: E402
from engine.detect import SCRIPT_EVENT_ID  # noqa: E402

PER_HOUR = 0.1          # (a)
EXTRA_SHARE = 0.10      # (b)
DECLARED_PER_HOUR = 0.1  # (c) v4 pre-registration 3c
NEW_RULES = ("analystlab.embedded_system_name", "analystlab.drop_run_delete")


def awake_hours(con, cfg):
    total = 0.0
    for (h,) in con.execute("SELECT DISTINCT host FROM events"):
        total += sum(e - a for a, e in B.host_segments(con, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds))
    return total / 3600


def series_key(a):
    d = a.details
    return (a.host, d["image"], d["destination_ip"], d["destination_port"], d["window_start"])


def official_connectors(con, cfg=None):
    """v4 F2: the frozen learned connector lists for the machines in this store (what main() passes), None
    while F2 is off; refuses (ValueError) a judged machine without a list while F2 is on (its F2 alerts
    would otherwise silently count as 0; review 2026-11-17)."""
    cfg = cfg or B.load_config()
    if not cfg.short_unseen:
        return None
    from engine import score as S
    lists = S.connectors_of(S.load_baseline()) or {}
    hosts = {str(h).lower() for (h,) in con.execute("SELECT DISTINCT host FROM events") if h is not None}
    missing = sorted(hosts - set(lists))
    if missing:
        raise ValueError(f"no learned connector list for {len(missing)} machine(s) in this store while F2 is on")
    return {h: lists[h] for h in hosts}


def declared_kind(alert):
    """"script" (F8, a PowerShell script block) or "registry" (F7) for a declared alert, else None."""
    d = alert.details or {}
    if d.get("derived_from") != "command_line":
        return None
    eid = (d.get("declared") or {}).get("event_id")
    if eid == SCRIPT_EVENT_ID:
        return "script"
    if eid in (12, 13, 14):
        return "registry"
    raise ValueError(f"declared alert of an unknown kind (event {eid}): refusing to guess F7 or F8")  # review 11-17


def declared_budget(alerts, hours):
    """(c): the raised declared alerts among `alerts` (every detector's, engine.score), per awake hour."""
    kinds = [k for k in map(declared_kind, S.raised(alerts)) if k]
    per = len(kinds) / hours if hours else None
    return {"alerts": len(kinds), "registry": kinds.count("registry"), "script": kinds.count("script"),
            "per_hour": per, "pass": per is not None and per <= DECLARED_PER_HOUR}


def budget(con, cfg=None, params=None, connectors=None, alerts=None, kinds=None):
    """{"awake_hours", "rules": {rule: {alerts, per_hour, pass}}, "short": {rita, both, extra, share, pass},
    "declared": {alerts, registry, script, per_hour, pass}}.
    v4 F2: with `connectors` ({host: programs seen connecting}, engine/score.connectors_of) the short
    gate also counts the never-seen-connecting series; main() passes the frozen lists, so v4's brake
    counts every short alert v4 raises. While F2 is on, lists are REQUIRED (refused without).
    v4 3c: `alerts` = every detector's alerts over this store (engine.score); REQUIRED while a declared
    feature is on (`kinds`, default config.declared_kinds()), so the declared count can never silently be 0."""
    cfg = cfg or B.load_config()
    if cfg.short_unseen and connectors is None:
        raise ValueError("F2 (beacon.short_unseen) is on: pass the learned connector lists (official_connectors)")
    kinds = declared_kinds() if kinds is None else kinds
    if kinds and alerts is None:
        raise ValueError(f"declared features on ({', '.join(sorted(kinds))}): pass every detector's alerts (engine.score)")
    params = params or own_rule_params()
    hours = awake_hours(con, cfg)
    out = {"awake_hours": round(hours, 2), "rules": {}}
    for rid in NEW_RULES:
        n = len(O.RULES[rid](con, **(params.get(rid) or {})))
        per = n / hours if hours else None
        out["rules"][rid] = {"alerts": n, "per_hour": per, "pass": per is not None and per <= PER_HOUR}
    rita = {series_key(a) for a in B.beacon_alerts(con, replace(cfg, short_min=None, short_cutoffs=None))}
    both = {series_key(a) for a in B.beacon_alerts(con, cfg, connectors=connectors)}
    extra = len(both - rita)
    share = extra / len(rita) if rita else (0.0 if not extra else None)
    out["short"] = {"rita_series": len(rita), "with_short_gate": len(both), "extra": extra, "share": share,
                    "pass": share is not None and share <= EXTRA_SHARE}
    if connectors is not None:
        hosts = {str(h).lower() for (h,) in con.execute("SELECT DISTINCT host FROM events") if h is not None}
        out["short"]["hosts_with_list"] = len(hosts & set(connectors))
        out["short"]["hosts_without_list"] = len(hosts - set(connectors))
    if alerts is not None:
        out["declared"] = declared_budget(alerts, hours)
    return out


def markdown(doc):
    L = ["# v3 rules: false-alarm budgets on the v3 laptop test week (pre-registered, section 1.8)", "",
         f"*Made by `tools/v3_budget.py` on the frozen code of the worktree it ran from (v3 or v4); snapshot days {doc.get('days', '?')}; awake hours "
         f"{doc['awake_hours']}. Pass/fail fixed before the week was opened; a failed rule is reported, never re-tuned.*", "",
         "| rule | alerts | per awake hour | budget | result |", "|---|---:|---:|---:|---|"]
    for rid, r in doc["rules"].items():
        per = "-" if r["per_hour"] is None else f"{r['per_hour']:.3f}"
        L.append(f"| {rid} | {r['alerts']} | {per} | {PER_HOUR} | {'PASS' if r['pass'] else 'FAIL'} |")
    s = doc["short"]
    share = "-" if s["share"] is None else f"{100 * s['share']:+.1f} %"
    L += ["", f"Short check-in test: RITA gate alone {s['rita_series']} alerted series; with the short gate {s['with_short_gate']}; "
              f"extra {s['extra']} ({share}; budget +{100 * EXTRA_SHARE:.0f} %): **{'PASS' if s['pass'] else 'FAIL'}**."]
    d = doc.get("declared")
    if d is None:
        L += ["", "Declared alerts (v4 pre-registration 3c): declared features off, not applicable."]
    else:
        per = "-" if d["per_hour"] is None else f"{d['per_hour']:.3f}"
        L += ["", f"Declared alerts (v4 pre-registration 3c; read from command lines, F7 registry {d['registry']} + "
                  f"F8 PowerShell {d['script']}): {d['alerts']} raised = {per} per awake hour (budget {DECLARED_PER_HOUR}): "
                  f"**{'PASS' if d['pass'] else 'FAIL'}**."]
    return "\n".join(L)


def score_store(path, lab):
    """(every detector's alerts over the store at `path`, None) or (None, why refused): engine.score with
    the frozen rules and learned files, exactly as experiments.py's false-alarm week scores it; a
    detector error refuses (a failed detector would silently count 0)."""
    from engine import detect
    con = detect.open_store(path)
    try:
        errors = []
        alerts = S.score(con, lab.rules(), lab.baseline(), errors=errors)
    finally:
        con.close()
    if errors:
        return None, f"{len(errors)} detector error(s) while scoring the store"
    return alerts, None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", choices=["official"], required=True)
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    a = ap.parse_args(argv)
    import experiments as X
    lab = X.Lab("official", a.recordings)
    problems = lab.problems()
    if problems:
        print("Refusing:", *problems, sep="\n  ")
        return 2
    try:
        path = lab.laptop_db()                     # exactly the frozen v3 test days, or refused
    except (ValueError, FileNotFoundError) as e:
        print(f"Refusing: {e}")
        return 2
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        try:
            lists = official_connectors(con)                        # v4 F2: every short alert counts
        except (ValueError, FileNotFoundError) as e:
            print(f"Refusing: {e}")
            return 2
        alerts = None
        if declared_kinds():                                        # v4 3c: every detector, as the false-alarm week
            alerts, problem = score_store(path, lab)
            if problem:
                print(f"Refusing: {problem}")
                return 2
        doc = budget(con, connectors=lists, alerts=alerts)
        meta = dict(con.execute("SELECT key, value FROM snapshot").fetchall())
        doc["days"] = f"{meta.get('from_day_utc')} .. {meta.get('cutoff_day_utc')}"
    finally:
        con.close()
    os.makedirs(lab.out_dir, exist_ok=True)
    os.makedirs(lab.results_dir, exist_ok=True)
    with open(os.path.join(lab.out_dir, "v3-budget.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    md = markdown(doc)
    with open(os.path.join(lab.results_dir, "v3-budget-official.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
