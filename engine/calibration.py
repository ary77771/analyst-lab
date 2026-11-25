"""Burst-factor calibration: the sideband control on the laptop dev week (package J part 1).

PRE-REGISTERED: docs/plans/package-j-design.md section 2 fixes the population, the control
windows, the statistic, the uncertainty, the decidability thresholds and the decision rule. This
module implements them; it must not be tuned after the analysis has run on real data.

The question. A timing hypothesis (T1 connection -> file, T2 inbound -> child, T3 connection ->
child; DESIGN 4.7) is graded by the Poisson chance that an effect lands in the 12 s window
[x - 2, x + 10] around a cause at x by luck. Programs act in bursts: a process that connects also
writes and starts things in the same seconds without one causing the other, so the real chance of
such a coincidence is larger than the Poisson formula says. The burst factor beta multiplies lambda
to make up for it. The A16 check (engine/confidence.py) measured it with windows 30-60 s away, too
far to see same-burst coincidences. Here the control window sits right NEXT to the true window.

The control at offset s. For every cause at active position x of a process alive >= 12 s with at
least one effect of the row's kind: the window [x - 2 + s, x + 10 + s], in the process's ACTIVE
seconds (sleeps skipped), used only when it lies inside the process's life [0, L]. s = -12 gives
[x - 14, x - 2]: the effects there came 2-14 s BEFORE the cause, so the cause cannot have made
them, yet they belong to the same burst. s = +12 gives [x + 10, x + 22]: late true effects can
leak in, which is the cautious side. -12 and +12 decide; +-30 and +-60 are reported as a curve.

The statistic. o = the share of control windows holding an effect, p = the Poisson prediction for
the SAME causes (production lambda rule, burst factor 1). The implied factor is
    beta_hat = ln(1 - o) / ln(1 - p)
because o = 1 - exp(-beta * lambda * t) and p = 1 - exp(-lambda * t). Per process (each process
weighs once: a graph grades a handful of processes) and per cause (busy processes dominate).

Uncertainty: a cluster bootstrap over PROCESSES (B = 10,000, fixed seed) for the one-sided 95 %
upper bound used by the rule; exact Clopper-Pearson (binomial) and Garwood (Poisson) intervals by
bisection on the per-cause counts, for comparison (they ignore the clustering).

Decision (fixed): a row/band is decidable with >= 30 processes and >= 10 control hits at a
decision offset, else the bands are pooled, else the row does not decide. U_r = max over
s in {-12, +12} of the upper bound of beta_hat in the medium band (fallback pooled). beta* = the
smallest grid value in {1, 1.5, 2, 2.5, 3, 4, 5} >= max_r U_r, one factor for all rows. If
max U_r > 5: stop and ask Yousif (the Poisson picture would be too wrong).

Everything here is counts and rates: no program names, paths or times leave this module.
numpy + math only (scipy is not installed).
"""

import math
from dataclasses import dataclass, replace

import numpy as np

from engine.confidence import TIMING_ROWS, Activity, ConfidenceConfig, Pool, band, chance

FROZEN_POOL_SHA256 = "3e39f2cfd5c5263c8e483a82e427683cc5f0b9b6f5a36afe9e8a25f78946b1bb"   # the dev pool (design 2)
GRID = (1, 1.5, 2, 2.5, 3, 4, 5)                  # beta* candidates (decision Q3)
DECISION_OFFSETS = (-12.0, 12.0)                  # the sidebands that decide
CURVE_OFFSETS = (-60.0, -30.0, 30.0, 60.0)        # reported as a curve (the A16 distances)
ALL_OFFSETS = tuple(sorted(DECISION_OFFSETS + CURVE_OFFSETS))
MIN_PROCESSES = 30                                # decidable: at least this many processes ...
MIN_HITS = 10                                     # ... and this many control hits
STOP_ABOVE = 5                                    # max U_r above this: stop and ask
BOOTSTRAP_B = 10_000
BOOTSTRAP_SEED = 20261024
ALPHA = 0.05
BANDS = ("high", "medium", "low")
POOLED = "pooled"
DESIGN = "docs/plans/package-j-design.md section 2"


def offset_key(s) -> str:
    """'-12', '+12', '+60': the JSON key of an offset."""
    return f"{float(s):+g}"


# -- the statistic -------------------------------------------------------------------------------------
def beta_hat(o: float, p: float) -> float:
    """The multiplier on lambda that turns the prediction p into the observed share o:
    ln(1 - o) / ln(1 - p). 0 when nothing was observed, inf when every window was hit."""
    if not 0 < p < 1:
        return math.nan
    if o <= 0:
        return 0.0
    if o >= 1:
        return math.inf
    return math.log1p(-o) / math.log1p(-p)


def _beta_vec(o, p):
    o, p = np.asarray(o, float), np.asarray(p, float)
    out = np.full(o.shape, math.nan)
    ok = (p > 0) & (p < 1)
    with np.errstate(divide="ignore", invalid="ignore"):
        b = np.log1p(-np.clip(o, 0, 1)) / np.log1p(-p)
    out[ok] = b[ok]
    out[ok & (o <= 0)] = 0.0
    out[ok & (o >= 1)] = math.inf
    return out


# -- exact intervals (bisection, numpy + math only) ----------------------------------------------------------
def _logsumexp(a):
    a = np.asarray(a, float)
    m = a.max()
    return float(m + math.log(np.exp(a - m).sum()))


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), from log terms with lgamma (exact to rounding)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0:
        return 1.0
    if p >= 1:
        return 0.0
    i = np.arange(0, k + 1)
    lg = math.lgamma(n + 1) - np.array([math.lgamma(x + 1) + math.lgamma(n - x + 1) for x in i])
    terms = lg + i * math.log(p) + (n - i) * math.log1p(-p)
    return min(1.0, math.exp(_logsumexp(terms)))


def poisson_cdf(k: int, mu: float) -> float:
    """P(X <= k) for X ~ Poisson(mu)."""
    if k < 0:
        return 0.0
    if mu <= 0:
        return 1.0
    i = np.arange(0, k + 1)
    terms = -mu + i * math.log(mu) - np.array([math.lgamma(x + 1) for x in i])
    return min(1.0, math.exp(_logsumexp(terms)))


def _bisect(f, lo: float, hi: float, iters: int = 200) -> float:
    """Root of a monotone f on [lo, hi] with f(lo) and f(hi) of opposite signs."""
    flo = f(lo)
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        fm = f(mid)
        if (fm < 0) == (flo < 0):
            lo, flo = mid, fm
        else:
            hi = mid
        if hi - lo <= 1e-13 * max(1.0, abs(hi)):
            break
    return 0.5 * (lo + hi)


def clopper_pearson(k: int, n: int, alpha: float = ALPHA) -> tuple:
    """Exact two-sided (1 - alpha) interval for a binomial share with k hits in n trials."""
    if k < 0 or n < 0 or k > n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")
    if n == 0:
        return (0.0, 1.0)
    lo = 0.0 if k == 0 else _bisect(lambda p: (1.0 - binom_cdf(k - 1, n, p)) - alpha / 2, 0.0, 1.0)
    hi = 1.0 if k == n else _bisect(lambda p: binom_cdf(k, n, p) - alpha / 2, 0.0, 1.0)
    return (lo, hi)


def garwood(k: int, alpha: float = ALPHA) -> tuple:
    """Exact two-sided (1 - alpha) interval for the mean of a Poisson count k (Garwood 1936):
    the chi-square form, found by bisection on the Poisson distribution function."""
    if k < 0:
        raise ValueError(f"need k >= 0, got {k}")
    top = k + 20.0 * math.sqrt(k + 1) + 50.0            # P(X <= k | top) is far below alpha / 2 there
    lo = 0.0 if k == 0 else _bisect(lambda mu: (1.0 - poisson_cdf(k - 1, mu)) - alpha / 2, 0.0, top)
    hi = _bisect(lambda mu: poisson_cdf(k, mu) - alpha / 2, 0.0, top)
    return (lo, hi)


# -- the cluster bootstrap -------------------------------------------------------------------------------
def _quantile(x, q):
    x = np.asarray(x, float)
    x = x[~np.isnan(x)]
    if x.size == 0:
        return math.nan
    # an order statistic (no interpolation): safe with infinities; 'higher' errs to caution
    return float(np.quantile(x, q, method="higher" if q >= 0.5 else "lower"))


def cluster_bootstrap(o, q, hits=None, counts=None, B: int = BOOTSTRAP_B, seed=BOOTSTRAP_SEED) -> dict:
    """Resample PROCESSES with replacement (the cluster: a process's causes share its bursts).
    `o[i]`, `q[i]` = process i's control hit rate and predicted chance over its controlled causes;
    `hits[i]`, `counts[i]` (optional) = its hit and controlled-cause counts, for the per-cause
    statistic. Returns the 5 %, 50 % and 95 % points of the resampled per-process beta_hat and
    hit rate (and per cause, when counts are given). The one-sided 95 % upper bound used by the
    decision rule is `per_process.beta_upper95`."""
    o, q = np.asarray(o, float), np.asarray(q, float)
    n = o.size
    if n == 0:
        raise ValueError("no processes to resample")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(int(B), n))
    o_star, q_star = o[idx].mean(axis=1), q[idx].mean(axis=1)
    b_star = _beta_vec(o_star, q_star)
    out = {"per_process": {"o_lower05": _quantile(o_star, 0.05), "o_upper95": _quantile(o_star, 0.95),
                           "beta_lower05": _quantile(b_star, 0.05), "beta_median": _quantile(b_star, 0.5),
                           "beta_upper95": _quantile(b_star, 0.95)},
           "B": int(B), "seed": seed}
    if hits is not None and counts is not None:
        hits, counts = np.asarray(hits, float), np.asarray(counts, float)
        n_star = counts[idx].sum(axis=1)
        oc = hits[idx].sum(axis=1) / n_star
        qc = (q * counts)[idx].sum(axis=1) / n_star
        bc = _beta_vec(oc, qc)
        out["per_cause"] = {"o_lower05": _quantile(oc, 0.05), "o_upper95": _quantile(oc, 0.95),
                            "beta_lower05": _quantile(bc, 0.05), "beta_median": _quantile(bc, 0.5),
                            "beta_upper95": _quantile(bc, 0.95)}
    return out


# -- the sideband control -----------------------------------------------------------------------------------
@dataclass
class _ProcessRecord:
    p1: float          # the production prediction for one cause (burst factor 1), same for every cause
    band: str          # the band p1 falls in
    real: np.ndarray   # per cause: an effect in the TRUE window
    controls: dict     # offset -> (valid mask, hit mask) per cause


def sideband_controls(activity: Activity, pool: Pool, cfg: ConfidenceConfig, offsets=ALL_OFFSETS) -> dict:
    """Row -> list of per-process records (the population of design section 2: processes alive
    >= one window with >= 1 effect of the row's kind; prediction = production lambda rule at burst
    factor 1). All positions are ACTIVE seconds from the process's start."""
    cfg = replace(cfg, burst_factor=None)                       # the factor under study is 1 here
    act = activity.active
    before, after = cfg.window_before_seconds, cfg.window_after_seconds
    out = {}
    for row, (kc, ke) in TIMING_ROWS.items():
        recs = []
        for g, causes in activity.events[kc].items():
            p = activity.procs[g]
            effects = activity.events[ke].get(g)
            if p["life"] < cfg.window or not effects or not causes:
                continue
            rate, _ = pool.rate(ke, p["program"], p["life"], cfg)
            lam = max(rate, len(effects) / p["life"]) * cfg.burst
            p1 = chance(lam, cfg.window)
            p0 = float(act.position(p["t0"]))
            eff = np.sort(np.asarray(act.position(effects), float) - p0)  # sorted for searchsorted (review F1)
            cp = np.asarray(act.position(causes), float) - p0
            lo, hi = cp - before, cp + after
            real = np.searchsorted(eff, hi, side="right") > np.searchsorted(eff, lo, side="left")
            controls = {}
            for s in offsets:
                s = float(s)
                valid = (lo + s >= 0.0) & (hi + s <= p["life"])
                hit = np.searchsorted(eff, hi + s, side="right") > np.searchsorted(eff, lo + s, side="left")
                controls[s] = (valid, hit & valid)
            recs.append(_ProcessRecord(p1, band(p1, cfg), real, controls))
        out[row] = recs
    return out


def _group_stats(recs, s: float, B: int, seed) -> dict:
    """The statistics of one (row, offset, band group): processes with >= 1 controlled cause at
    offset s. The prediction is averaged over the SAME causes as the control."""
    rows = []
    for r in recs:
        valid, hit = r.controls[s]
        n = int(valid.sum())
        if n:
            rows.append((r.p1, n, int(hit.sum()), int((r.real & valid).sum())))
    if not rows:
        return None
    a = np.array(rows, float)
    q, n, k, rl = a[:, 0], a[:, 1], a[:, 2], a[:, 3]
    o_pp, real_pp = k / n, rl / n
    o_bar, p_bar = float(o_pp.mean()), float(q.mean())
    boot = cluster_bootstrap(o_pp, q, hits=k, counts=n, B=B, seed=seed)
    per_process = {"o": o_bar, "p": p_bar, "real": float(real_pp.mean()), "ratio": o_bar / p_bar,
                   "beta": beta_hat(o_bar, p_bar), **boot["per_process"]}
    K, N = int(k.sum()), int(n.sum())
    expected = float((q * n).sum())                      # the predicted number of control hits
    o_c, p_c = K / N, expected / N
    cp = clopper_pearson(K, N)
    gw = garwood(K)
    per_cause = {"o": o_c, "p": p_c, "real": float(rl.sum()) / N, "ratio": o_c / p_c, "beta": beta_hat(o_c, p_c),
                 "cp": list(cp), "beta_cp": [beta_hat(cp[0], p_c), beta_hat(cp[1], p_c)],
                 "expected_hits": expected, "garwood": list(gw),
                 "garwood_ratio": [gw[0] / expected, gw[1] / expected], **boot["per_cause"]}
    st = {"processes": len(rows), "controlled_causes": N, "control_hits": K, "real_hits": int(rl.sum()),
          "per_process": per_process, "per_cause": per_cause}
    st["decidable"] = decidable(st)
    return st


def sideband_analysis(activity: Activity, pool: Pool, cfg: ConfidenceConfig, offsets=ALL_OFFSETS,
                      B: int = BOOTSTRAP_B, seed=BOOTSTRAP_SEED) -> dict:
    """The whole analysis of one machine: for every timing row, offset and band (plus the bands
    pooled), the per-process and per-cause statistics with their intervals. Counts and rates only.
    Each bootstrap gets its own seed derived from (seed, row, offset, band), so a group's numbers
    do not depend on which other groups exist."""
    offsets = tuple(sorted(float(s) for s in offsets))
    controls = sideband_controls(activity, pool, cfg, offsets)
    rows = {}
    for ri, (row, recs) in enumerate(controls.items()):
        by_band = {b: [r for r in recs if r.band == b] for b in BANDS}
        population = {"processes": len(recs), "causes": int(sum(r.real.size for r in recs)),
                      "bands": {b: {"processes": len(v), "causes": int(sum(r.real.size for r in v))}
                                for b, v in by_band.items() if v}}
        offs = {}
        for si, s in enumerate(offsets):
            bands_ = {}
            groups = [(b, by_band[b]) for b in BANDS] + [(POOLED, recs)]
            for bi, (name, members) in enumerate(groups):
                st = _group_stats(members, s, B, [int(seed), ri, si, bi]) if members else None
                if st:
                    bands_[name] = st
            offs[offset_key(s)] = {"bands": bands_}
        rows[row] = {"population": population, "offsets": offs}
    meta = {"design": DESIGN, "offsets": [offset_key(s) for s in offsets],
            "decision_offsets": [offset_key(s) for s in DECISION_OFFSETS],
            "window": [cfg.window_before_seconds, cfg.window_after_seconds], "burst_factor_used": 1,
            "bands": {"high": cfg.band_high, "medium": cfg.band_medium}, "bootstrap": {"B": int(B), "seed": seed},
            "min_processes": MIN_PROCESSES, "min_hits": MIN_HITS, "grid": list(GRID), "stop_above": STOP_ABOVE,
            "processes_in_activity": len(activity.procs), "active_hours": round(activity.active.total / 3600, 2)}
    return {"meta": meta, "rows": rows}


# -- the pre-registered decision rule ----------------------------------------------------------------------
def decidable(stats: dict) -> bool:
    """>= 30 processes and >= 10 control hits (design section 2)."""
    return stats["processes"] >= MIN_PROCESSES and stats["control_hits"] >= MIN_HITS


def choose_burst_factor(results: dict, decision_offsets=DECISION_OFFSETS, grid=GRID, stop_above=STOP_ABOVE) -> dict:
    """The rule, exactly as pre-registered. For each row and decision offset: the medium band if
    decidable there, else the pooled bands if decidable, else nothing. U_r = the max over the
    offsets that have a source of the per-process bootstrap upper bound; a row with no source at
    either offset is reported but does not decide. beta* = the smallest grid value >= max_r U_r.
    max_r U_r > stop_above (or not finite) -> beta* None, stop = True: ask Yousif."""
    rows_out, uppers = {}, []
    for row, r in results["rows"].items():
        per_offset, used = {}, []
        for s in decision_offsets:
            key = offset_key(s)
            bands_ = r.get("offsets", {}).get(key, {}).get("bands", {})
            chosen = None
            for cand in ("medium", POOLED):
                st = bands_.get(cand)
                if st and decidable(st):
                    chosen = cand
                    break
            if chosen:
                u = float(bands_[chosen]["per_process"]["beta_upper95"])
                per_offset[key] = {"band": chosen, "upper": u, "processes": bands_[chosen]["processes"],
                                   "control_hits": bands_[chosen]["control_hits"]}
                used.append(u)
            else:
                have = {b: (st["processes"], st["control_hits"]) for b, st in bands_.items() if b in ("medium", POOLED)}
                per_offset[key] = {"band": None, "upper": None,
                                   "reason": f"not decidable (needs >= {MIN_PROCESSES} processes and >= {MIN_HITS} "
                                             f"control hits; medium/pooled have {have})"}
        u_row = max(used) if used else None
        rows_out[row] = {"decides": bool(used), "partial": len(used) == 1, "upper": u_row, "offsets": per_offset}
        if used:
            uppers.append(u_row)
    out = {"grid": list(grid), "stop_above": stop_above, "decision_offsets": [offset_key(s) for s in decision_offsets],
           "rows": rows_out, "deciding_rows": [k for k, v in rows_out.items() if v["decides"]]}
    if not uppers:
        return {**out, "beta_star": None, "max_upper": None, "stop": False,
                "reason": "no decidable row: the factor is not set by this run"}
    m = max(uppers)
    if math.isnan(m) or m > stop_above:
        return {**out, "beta_star": None, "max_upper": m, "stop": True,
                "reason": f"max U_r = {m:.3g} > {stop_above}: stop and ask Yousif (the Poisson picture would be too "
                          f"wrong; the plan's fallback 'use measured rates directly' becomes a design question)"}
    beta_star = min(g for g in grid if g >= m)
    return {**out, "beta_star": beta_star, "max_upper": m, "stop": False,
            "reason": f"max U_r = {m:.3f}; the smallest grid value >= it is {beta_star:g}"}


# -- the written summary (counts and rates only) -----------------------------------------------------------
def _f(x, nd=4):
    if x is None:
        return "-"
    if isinstance(x, float):
        if math.isnan(x):
            return "nan"
        if math.isinf(x):
            return "inf"
        return f"{x:.{nd}f}"
    return str(x)


def summary_markdown(results: dict, decision: dict) -> str:
    """docs/results/j-burst-factor-dev.md: counts, rates, ratios, intervals and the decision.
    Never names, paths, addresses or command lines (privacy rule 7)."""
    meta = results["meta"]
    L = ["# Package J part 1: burst factor from the sideband control (dev laptop week)", "",
         f"*Pre-registered design: `{meta.get('design', DESIGN)}`. Counts and rates only.*", ""]
    L += ["## Set-up", ""]
    for k in ("store", "store_cutoff_day_utc", "frozen_dev_cutoff_day_utc", "pool_sha256", "pool_processes",
              "pool_active_hours", "processes_in_activity", "active_hours", "analysis_commit", "created_utc"):
        if k in meta:
            L.append(f"- {k}: `{meta[k]}`")
    L += [f"- window: [x - {meta['window'][0]:g}, x + {meta['window'][1]:g}] s; control at offset s = that window shifted "
          f"by s ACTIVE seconds, inside the process's life; burst factor used in the prediction: {meta['burst_factor_used']}",
          f"- offsets: {', '.join(meta['offsets'])} (decision: {', '.join(meta['decision_offsets'])})",
          f"- bootstrap: B = {meta['bootstrap']['B']}, seed {meta['bootstrap']['seed']}, clusters = processes; "
          f"decidable = >= {meta['min_processes']} processes and >= {meta['min_hits']} control hits",
          f"- grid {meta['grid']}, stop above {meta['stop_above']}", ""]
    L += ["## Decision", "", f"- **beta-star = {decision['beta_star']}**; max U_r = {_f(decision['max_upper'], 3)}; "
          f"stop = {decision['stop']}", f"- {decision['reason']}", ""]
    L += ["| row | decides | U_r | -12 source (processes, hits, U) | +12 source (processes, hits, U) |", "|---|---|---|---|---|"]
    for row, d in decision["rows"].items():
        cells = []
        for key in decision["decision_offsets"]:
            o = d["offsets"].get(key, {})
            cells.append(f"{o['band']} ({o['processes']}, {o['control_hits']}, {_f(o['upper'], 3)})" if o.get("band")
                         else "not decidable")
        L.append(f"| {row} | {'yes' + (' (one sideband)' if d['partial'] else '') if d['decides'] else 'no'} | "
                 f"{_f(d['upper'], 3)} | {cells[0]} | {cells[1]} |")
    L.append("")
    for row, r in results["rows"].items():
        pop = r["population"]
        L += [f"## {row}", "", f"Population: {pop['processes']} processes, {pop['causes']} causes; by band of p1: "
              + (", ".join(f"{b} {v['processes']} processes / {v['causes']} causes" for b, v in pop["bands"].items()) or "none"), ""]
        L += ["| offset | band | processes | controlled causes | control hits | real hits | per process: o / p / real | "
              "ratio | beta | boot 5 % / 50 % / 95 % | per cause: o / p | beta | Clopper-Pearson beta | Garwood ratio | decidable |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for key, off in r["offsets"].items():
            for b, st in off["bands"].items():
                pp, pc = st["per_process"], st["per_cause"]
                L.append(f"| {key} | {b} | {st['processes']} | {st['controlled_causes']} | {st['control_hits']} | {st['real_hits']} | "
                         f"{_f(pp['o'])} / {_f(pp['p'])} / {_f(pp['real'])} | {_f(pp['ratio'], 2)} | {_f(pp['beta'], 2)} | "
                         f"{_f(pp['beta_lower05'], 2)} / {_f(pp['beta_median'], 2)} / {_f(pp['beta_upper95'], 2)} | "
                         f"{_f(pc['o'])} / {_f(pc['p'])} | {_f(pc['beta'], 2)} | "
                         f"[{_f(pc['beta_cp'][0], 2)}, {_f(pc['beta_cp'][1], 2)}] | "
                         f"[{_f(pc['garwood_ratio'][0], 2)}, {_f(pc['garwood_ratio'][1], 2)}] | {'yes' if st['decidable'] else 'no'} |")
        L.append("")
    L += ["## How to read it", "",
          "- `o` = share of control windows holding an effect of the row's kind; `p` = the Poisson prediction for the same "
          "causes at burst factor 1; `real` = the same share in the true window (causation plus same-burst chance).",
          "- `beta` = ln(1 - o) / ln(1 - p): the factor on lambda that would make the prediction match the control.",
          "- Per process: each process weighs once (what a graph grades). Per cause: busy processes dominate.",
          "- The bootstrap resamples processes (the cluster); Clopper-Pearson and Garwood are exact per-cause intervals that "
          "ignore the clustering, shown for comparison. The decision uses the per-process bootstrap upper bound.",
          "- Known limits (design section 2): a -12 window needs 14 s of life before the cause; +12 can hold late true "
          "effects (cautious side; the rule takes the max); in bursts shorter than the sideband distance both sidebands "
          "look partly outside the burst and under-estimate same-burst coincidence (tests: short-burst simulation); "
          "the high band has no causes under the band-always rule. Timing rows are leads.", ""]
    return "\n".join(L)
