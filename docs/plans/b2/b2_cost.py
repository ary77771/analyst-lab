"""B2 spike, part B: dev-week cost of the short test, per candidate minimum m.
Counts and program FILE names only (no paths, IPs, domains)."""
import json, sqlite3, sys
from collections import Counter
import numpy as np
root, db_path, crit_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from engine import beacon as b

from dataclasses import replace
cfg = replace(b.load_config(), short_min=None, short_cutoffs=None)   # v1/v2's RITA gate alone (v3 sets a short gate)
crit = json.load(open(crit_path))
con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

v1 = b.beacon_alerts(con, cfg)
v1_keys = {(a.host, a.details["image"], a.details["destination_ip"], a.details["destination_port"], a.details["window_start"]) for a in v1}

series = b.series_from_store(con, None, cfg.unicast_only)
segs, awake = {}, 0.0
for h in {k[0] for k in series}:
    segs[h] = b.host_segments(con, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds)
# awake hours over all hosts in the store (not only hosts with series)
for (h,) in con.execute("SELECT DISTINCT host FROM events"):
    s = segs.get(h) or b.host_segments(con, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds)
    awake += sum(e - a for a, e in s)
hours = awake / 3600

chunks = []
for key, conns in series.items():
    for seg, chunk in b.split_by_segment(conns, segs[key[0]]):
        ci = b.checkin_times([c[0] for c in chunk], cfg.time_resolution_seconds)
        chunks.append((key, seg, ci))

def greenwood(g):
    g = np.asarray(g, float); return float((g ** 2).sum() / g.sum() ** 2)

def short_fires(ci, m, c):
    for k in range(m, min(9, len(ci)) + 1):
        g = np.diff(ci[:k])
        if np.median(g) >= cfg.min_median_gap_seconds and greenwood(g) <= c[str(k)]:
            return k
    return None

print(f"dev store: awake hours {hours:.1f}; series-windows {len(chunks)}; v1 alerts {len(v1)} ({len(v1)/hours:.2f}/h)")
cand = Counter(min(len(ci), 10) for _, _, ci in chunks if len(ci) >= 4 and np.median(np.diff(ci[:min(len(ci), 9)])) >= 10)
print("candidates (check-ins capped at 10, median of first<=9 gaps >= 10 s):", dict(sorted(cand.items())))
budget = 0.10 * len(v1)
for m in range(4, 10):
    c = crit[str(m)]["c"]
    extra, earlier, rhythms = [], 0, Counter()
    for key, seg, ci in chunks:
        k = short_fires(ci, m, c)
        if k is None:
            continue
        if (key[0], key[1], key[2], key[3], seg[0]) in v1_keys:
            earlier += 1
        else:
            name = str(key[1]).replace("/", "\\").rsplit("\\", 1)[-1]
            extra.append((name, key[3], len(ci), k, float(np.median(np.diff(ci[:k])))))
            rhythms[(name, key[3])] += 1
    ok = "WITHIN" if len(extra) <= budget else "OVER"
    print(f"m={m}: extra series {len(extra)} ({len(extra)/hours:.3f}/h, +{len(extra)/len(v1):.1%}) {ok} budget {budget:.1f}; "
          f"v1 series fired earlier by short test {earlier}; distinct (program, port) {len(rhythms)}")
    if m in (4, 6, 9) or ok == "WITHIN":
        byn = Counter(min(e[2], 10) for e in extra)
        print("    extra by series length:", dict(sorted(byn.items())))
        print("    top:", rhythms.most_common(12))
