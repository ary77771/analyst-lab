"""v3 pre-registration section 1.4: development-data cost of the three v3 rules. Counts only (no program
names, paths, IPs or domains: CLAUDE.md rule 7).

    python docs/plans/v3/v3_cost.py <wt\\v3 root> <dev laptop db> <vm dev db> <b2_crit.json>
"""
import json
import sqlite3
import sys
from dataclasses import replace

root, laptop_db, vm_db, crit_path = sys.argv[1:5]
sys.path.insert(0, root)
from engine import beacon as B  # noqa: E402
from engine import own_rules as O  # noqa: E402

crit = json.load(open(crit_path, encoding="utf-8"))
cfg = replace(B.load_config(), short_min=None, short_cutoffs=None)     # the v2 gate alone (short test off)


def awake_hours(con):
    total = 0.0
    for (h,) in con.execute("SELECT DISTINCT host FROM events"):
        total += sum(e - a for a, e in B.host_segments(con, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds))
    return total / 3600


def key(a):
    d = a.details
    return (a.host, d["image"], d["destination_ip"], d["destination_port"], d["window_start"])


for label, path in (("DEV laptop (chooses)", laptop_db), ("VM dev store (reported only)", vm_db)):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    hours = awake_hours(con)
    print(f"== {label}: awake hours {hours:.1f}")
    from engine.config import own_rule_params
    extra = own_rule_params()["analystlab.embedded_system_name"].get("extra_references") or ()
    for L in (6, 7):
        n = len(O.embedded_system_name(con, min_ref_length=L, extra_references=extra))
        print(f"  1.1 embedded_system_name L={L} (+{len(extra)} listed names, 1.7): {n} alerts (budget 5)")
    for refs, what in (((), "running names only (v2)"), (extra, "+ listed names (v3 1.7)")):
        print(f"  1.7 lookalike_name, {what}: {len(O.lookalike_name(con, extra_references=refs))} alerts")
    for variant in ("any", "shells"):
        n = len(O.drop_run_delete(con, writers=variant))
        print(f"  1.2 drop_run_delete writers={variant}: {n} alerts (budget 5)")
    rita = B.beacon_alerts(con, cfg)
    rita_keys = {key(a) for a in rita}
    print(f"  1.3 RITA gate alone: {len(rita)} alerted series; budget +10 % = {0.1 * len(rita):.1f}")
    for m in range(4, 10):
        c = replace(cfg, short_min=m, short_cutoffs={int(k): v for k, v in crit[str(m)]["c"].items()})
        both = B.beacon_alerts(con, c)
        extra = sum(1 for a in both if key(a) not in rita_keys)
        earlier = sum(1 for a in both if key(a) in rita_keys and a.details.get("gate") == "short")
        print(f"     m={m}: extra series {extra} ({100 * extra / max(len(rita), 1):+.1f} %), RITA series fired earlier by the short test {earlier}")
    con.close()
