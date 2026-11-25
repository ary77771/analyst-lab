"""B2 spike, part A: Greenwood critical values per prefix length, calibrated so that the
series-level chance that ANY judged prefix (m..9 check-ins) of a random-arrivals series passes
is <= ALPHA at the worst mean period. Production front end: 1 s chained fold, median gap >= 10 s.
Prints numbers only; writes JSON with the critical values."""
import json, sys
import numpy as np

ALPHA = 0.01
PERIODS = [10, 12, 15, 20, 30, 60, 120, 300, 900]
TRIALS = 50_000
KMAX = 9
RES, MINMED = 1.0, 10.0
rng = np.random.default_rng(2026)


def greenwood(g):
    g = np.asarray(g, float)
    return float((g ** 2).sum() / g.sum() ** 2)


# pure-exponential reference distribution of G for k check-ins (k-1 gaps), to define c_k(q)
REF = {}
for k in range(4, KMAX + 1):
    gaps = rng.exponential(1.0, size=(400_000, k - 1))
    REF[k] = np.sort((gaps ** 2).sum(1) / gaps.sum(1) ** 2)


def ck(k, q):
    return float(np.quantile(REF[k], q))


def checkins(arr):
    d = np.diff(arr)
    keep = np.concatenate([[True], d >= RES])
    return arr[keep]


def null_prefix_stats(P):
    """For each trial: dict k -> G_k if median gap >= 10 s else inf (not judged)."""
    out = np.full((TRIALS, KMAX + 1), np.inf)
    arr = np.cumsum(rng.exponential(P, size=(TRIALS, 60)), axis=1)
    for i in range(TRIALS):
        c = checkins(arr[i])[:KMAX]
        if len(c) < KMAX:
            continue
        g = np.diff(c)
        for k in range(4, KMAX + 1):
            gk = g[:k - 1]
            if np.median(gk) >= MINMED:
                out[i, k] = (gk ** 2).sum() / gk.sum() ** 2
    return out


STATS = {P: null_prefix_stats(P) for P in PERIODS}


def series_rate(m, q):
    worst, per = 0.0, {}
    cks = {k: ck(k, q) for k in range(m, KMAX + 1)}
    for P, S in STATS.items():
        hit = np.zeros(TRIALS, bool)
        for k in range(m, KMAX + 1):
            hit |= S[:, k] <= cks[k]
        r = hit.mean()
        per[P] = r
        worst = max(worst, r)
    return worst, per


result = {}
for m in range(4, KMAX + 1):
    lo, hi = 1e-6, ALPHA
    for _ in range(30):
        mid = (lo + hi) / 2
        if series_rate(m, mid)[0] <= ALPHA:
            lo = mid
        else:
            hi = mid
    worst, per = series_rate(m, lo)
    result[m] = {"q": lo, "c": {k: ck(k, lo) for k in range(m, KMAX + 1)}, "worst": worst,
                 "per_period": {str(P): round(float(r), 5) for P, r in per.items()}}
    print(f"m={m}: per-look q={lo:.5f} worst={worst:.4f} c_k=" +
          ", ".join(f"{k}:{v:.4f}" for k, v in result[m]["c"].items()))
    print("   per period:", {P: f"{r:.3%}" for P, r in per.items()})

json.dump(result, open(sys.argv[1], "w"), indent=1)
