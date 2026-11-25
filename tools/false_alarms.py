"""How often do the rules fire on NORMAL use? (package C; later experiment J4 on test data)

    python tools/false_alarms.py --events recordings/scratch/dev/dev-laptop.db \
        --alerts recordings/scratch/dev/alerts-laptop-community.db recordings/scratch/dev/alerts-laptop-own.db \
        --out docs/results/c-dev-false-alarms.md

On data where no attack ran (the laptop's normal use), every alert is a false alarm by
definition. This counts them per ACTIVE hour (an active minute = a minute with at least one
normal-use Sysmon event; our own tools and paused rows excluded). Same idea as
statusapp/stats.py, slightly different in detail: here the minute of when the event HAPPENED
(UtcTime) and every Sysmon event type; stats.py uses the logged time and its own list of event
types (the difference is a few minutes a day), per level and per rule, and describes each rule's alerts only in counts: how many
days, how many different programs (anonymous), and where those programs live (Windows /
Program Files / ProgramData / user folders / other). It never prints a path, file name,
command line, address or domain (privacy rule 7). It only measures: choosing what to change is
a separate, written decision.
"""

import argparse
import collections
import hashlib
import json
import os
import sqlite3
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from engine.alerts import LEVELS, AlertStore  # noqa: E402
from engine.detect import SYSMON_CHANNEL  # noqa: E402

NORMAL = f"channel = '{SYSMON_CHANNEL}' AND COALESCE(origin, '') <> 'project' AND COALESCE(paused, 0) = 0"


def active_minutes(con) -> int:
    return con.execute(f"SELECT COUNT(DISTINCT CAST(julianday(COALESCE(UtcTime, time)) * 1440 AS INTEGER)) "
                       f"FROM events WHERE {NORMAL}").fetchone()[0]


def place(path) -> str:
    p = str(path or "").lower().replace("/", "\\")
    if not p:
        return "unknown"
    for prefix, name in (("c:\\windows\\", "Windows"), ("c:\\program files", "Program Files"),
                         ("c:\\programdata\\", "ProgramData"), ("c:\\users\\", "user folders")):
        if p.startswith(prefix):
            return name
    return "other"


def _program(con, key):
    row = con.execute("SELECT Image FROM events WHERE dedup_key = ?", (key,)).fetchone()
    return row[0] if row else None


def analyse(events_con, alerts):
    minutes = active_minutes(events_con)
    hours = minutes / 60
    rules = collections.defaultdict(lambda: {"n": 0, "days": set(), "programs": set(), "places": collections.Counter()})
    by_level = collections.Counter()
    for a in alerts:
        r = rules[(a.source, a.level, a.title, a.rule_id)]
        r["n"] += 1
        r["days"].add(a.time[:10])
        image = _program(events_con, a.evidence[0])
        r["programs"].add(hashlib.sha1(str(image).lower().encode()).hexdigest()[:8])   # anonymous
        r["places"][place(image)] += 1
        by_level[a.level] += 1
    return {"active_hours": round(hours, 1), "hours_exact": hours, "alerts": len(alerts),
            "per_active_hour": round(len(alerts) / hours, 2) if hours else None,
            "by_level": {lvl: (by_level[lvl], round(by_level[lvl] / hours, 3) if hours else None) for lvl in LEVELS},
            "rules": sorted(((k, v) for k, v in rules.items()), key=lambda kv: -kv[1]["n"])}


def report(res, title, sources) -> str:
    h = res.get("hours_exact", res["active_hours"])
    lines = [f"# {title}", "",
             f"*Made by `tools/false_alarms.py` from: {', '.join(sources)}. Counts only (privacy rule 7). "
             f"On normal use every alert is a false alarm. Nothing here was tuned.*", "",
             f"- Active hours: **{res['active_hours']}**",
             f"- Alerts: **{res['alerts']:,}** = **{res['per_active_hour']} per active hour**", "",
             "| Level | Alerts | Per active hour |", "|---|---:|---:|"]
    lines += [f"| {lvl} | {n:,} | {r} |" for lvl, (n, r) in res["by_level"].items()]
    total = res["alerts"] or 1
    lines += ["", "## Per rule (most alerts first)", "",
              "| Source | Level | Rule | Alerts | Share | Per active hour | Days | Programs | Where the programs live |",
              "|---|---|---|---:|---:|---:|---:|---:|---|"]
    for (source, level, title_, _rid), v in res["rules"]:
        places = ", ".join(f"{k} {n}" for k, n in v["places"].most_common())
        lines.append(f"| {source} | {level} | {title_} | {v['n']:,} | {100 * v['n'] / total:.1f} % | "
                     f"{(v['n'] / h if h else 0):.3f} | {len(v['days'])} | {len(v['programs'])} | {places} |")
    top5 = sum(v["n"] for _, v in res["rules"][:5])
    lines += ["", f"The 5 noisiest rules make **{100 * top5 / total:.1f} %** of all alerts; "
                  f"{len(res['rules'])} rules fired at least once."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="False alarms on normal use, per active hour (counts only)")
    ap.add_argument("--events", required=True)
    ap.add_argument("--alerts", nargs="+", required=True)
    ap.add_argument("--out", help="write the Markdown report here (else print a summary)")
    ap.add_argument("--title", default="False alarms on normal use")
    a = ap.parse_args(argv)
    con = sqlite3.connect("file:" + os.path.abspath(a.events).replace("\\", "/") + "?mode=ro", uri=True)
    alerts = []
    for p in a.alerts:
        s = AlertStore(p)
        alerts += s.read()
        s.close()
    res = analyse(con, alerts)
    names = [os.path.basename(p) for p in [a.events] + a.alerts]
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(report(res, a.title, names))
    print(json.dumps({k: res[k] for k in ("active_hours", "alerts", "per_active_hour", "by_level")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
