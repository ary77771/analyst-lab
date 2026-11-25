"""Package J part 1: the burst-factor sideband control (engine/calibration.py, tools/burst_factor.py).

Pre-registered design: docs/plans/package-j-design.md section 2. These tests were written before
the module and before any analysis ran on the laptop week. They cover: the exact interval maths
against known values; the cluster bootstrap (reproducible, really over processes); the window
arithmetic in ACTIVE seconds; three simulations (plain Poisson with sleeps -> ratio 1; a common
driver burst -> +-12 recovers the truth and +-60 under-estimates; a causal chain -> the sideband
stays at background); the decision rule on hand-made tables; and the CLI's refusals.
"""

import json
import math
import sqlite3
import sys
import os

import numpy as np
import pytest

from engine import calibration as K
from engine import confidence as C

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import burst_factor  # noqa: E402

CFG = C.ConfidenceConfig(band_high=0.01, band_medium=0.10, window_before_seconds=2, window_after_seconds=10,
                         sleep_gap_seconds=60, min_pool_events=5, competing_span_seconds=900,
                         lifetime_bands_seconds=(60, 3600))
# a rate of 0 in every lifetime band (the within-life rate then decides): every band present, since a
# missing band is an error (integration fix 2026-10-24), never a silent 0
EMPTY_POOL = C.Pool({k: {} for k in C.KINDS}, {k: {b: (0, 1.0) for b in C.lifetime_bands(CFG)} for k in C.KINDS},
                    C.pool_settings(CFG))

FAST_B = 2000          # bootstrap replicates in tests (the real run uses K.BOOTSTRAP_B = 10,000)
POISSON_SEED = 100     # a seed whose 90 % intervals hold 1 at all six offsets (coverage study: 32 of 60 seeds do)


# -- exact intervals ---------------------------------------------------------------------------------
def test_binomial_and_poisson_cdf_hand_values():
    assert K.binom_cdf(1, 3, 0.5) == pytest.approx(0.5)
    assert K.binom_cdf(3, 3, 0.5) == pytest.approx(1.0)
    assert K.binom_cdf(0, 10, 0.1) == pytest.approx(0.9 ** 10)
    assert K.poisson_cdf(0, 2.0) == pytest.approx(math.exp(-2))
    assert K.poisson_cdf(2, 1.0) == pytest.approx(math.exp(-1) * (1 + 1 + 0.5))


@pytest.mark.parametrize("k,n,lo,hi", [
    (0, 10, 0.0, 0.3085),          # 1 - 0.025^(1/10)
    (5, 10, 0.1871, 0.8129),       # the textbook value
    (10, 10, 0.6915, 1.0),
    (1, 1, 0.025, 1.0),
])
def test_clopper_pearson_known_values(k, n, lo, hi):
    got = K.clopper_pearson(k, n)
    assert got[0] == pytest.approx(lo, abs=5e-4) and got[1] == pytest.approx(hi, abs=5e-4)


def test_clopper_pearson_edges():
    assert K.clopper_pearson(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        K.clopper_pearson(3, 2)
    with pytest.raises(ValueError):
        K.clopper_pearson(-1, 2)


@pytest.mark.parametrize("k,lo,hi", [
    (0, 0.0, 3.6889),              # -ln(0.025)
    (3, 0.6187, 8.7673),           # chi2 quantiles: 0.025 of 6 df / 2, 0.975 of 8 df / 2
    (100, 81.36, 121.63),
])
def test_garwood_known_values(k, lo, hi):
    got = K.garwood(k)
    assert got[0] == pytest.approx(lo, abs=5e-3) and got[1] == pytest.approx(hi, abs=5e-3)


def test_beta_hat_is_the_implied_multiplier():
    assert K.beta_hat(0.1, 0.1) == pytest.approx(1.0)
    assert K.beta_hat(0.0, 0.1) == 0.0
    assert K.beta_hat(1.0, 0.1) == math.inf
    assert K.beta_hat(1 - 0.9 ** 2, 0.1) == pytest.approx(2.0)        # o = 1 - (1 - p)^2 -> factor 2
    assert K.beta_hat(1 - 0.9 ** 0.5, 0.1) == pytest.approx(0.5)


# -- the cluster bootstrap -------------------------------------------------------------------------
def test_bootstrap_is_reproducible_and_seed_dependent():
    rng = np.random.default_rng(0)
    o, q = rng.uniform(0, 0.3, 30), rng.uniform(0.05, 0.1, 30)
    a = K.cluster_bootstrap(o, q, B=500, seed=1)
    b = K.cluster_bootstrap(o, q, B=500, seed=1)
    c = K.cluster_bootstrap(o, q, B=500, seed=2)
    assert a == b
    assert a["per_process"]["beta_upper95"] != c["per_process"]["beta_upper95"]
    assert a["per_process"]["beta_lower05"] <= a["per_process"]["beta_median"] <= a["per_process"]["beta_upper95"]


def test_bootstrap_handles_all_hits_and_no_hits():
    q = np.full(5, 0.05)
    assert K.cluster_bootstrap(np.zeros(5), q, B=50, seed=3)["per_process"]["beta_upper95"] == 0.0
    assert K.cluster_bootstrap(np.ones(5), q, B=50, seed=3)["per_process"]["beta_upper95"] == math.inf


# -- building activities by hand -----------------------------------------------------------------------
def _machine(n_stretches, length=4000.0, sleep=5000.0):
    """One machine's active time: stretches of `length` s with a heartbeat every 30 s, separated
    by sleeps longer than the 60 s gap."""
    beats = []
    for i in range(n_stretches):
        s = i * (length + sleep)
        beats += list(np.arange(s, s + length, 30.0)) + [s + length]
    return C.ActiveTime(beats, CFG.sleep_gap_seconds)


def _spans(n_procs, per=2, length=4000.0, sleep=5000.0):
    """Process i lives across `per` consecutive stretches (so its life crosses sleeps)."""
    return [(per * i * (length + sleep), (per * i + per - 1) * (length + sleep) + length) for i in range(n_procs)]


def _activity(active, spans, causes, effects, kinds=("out", "file"), program="p.exe"):
    procs, ev = {}, {k: {} for k in C.KINDS}
    for i, (t0, t1) in enumerate(spans):
        g = f"g{i}"
        procs[g] = {"program": program, "t0": float(t0), "t1": float(t1), "life": active.seconds(t0, t1)}
        ev[kinds[0]][g] = sorted(float(t) for t in causes[i])
        ev[kinds[1]][g] = sorted(float(t) for t in effects[i])
    return C.Activity(active, procs, ev, {})


def _poisson_in_life(rng, active, t0, life, rate):
    """Poisson events at `rate` per ACTIVE second inside a process's life (sleeps skipped)."""
    pos0 = float(active.position(t0))
    n = rng.poisson(rate * life)
    return np.sort(active.at_position(pos0 + rng.uniform(0, life, n)))


def _pooled(res, row, s):
    return res["rows"][row]["offsets"][K.offset_key(s)]["bands"][K.POOLED]


# -- window arithmetic -------------------------------------------------------------------------------
def test_offset_keys():
    assert K.offset_key(-12) == "-12" and K.offset_key(12.0) == "+12" and K.offset_key(60) == "+60"


def test_control_windows_are_shifted_in_active_seconds_not_wall_clock():
    """A cause just before a sleep and an effect just after it: 15 ACTIVE seconds apart, so the
    +12 control window [x+10, x+22] holds it. In wall-clock seconds they are 5,115 s apart and a
    wall-clock shift would miss it (the review's finding 3 on A16)."""
    beats = list(np.arange(0, 201, 10.0)) + list(np.arange(5300, 5501, 10.0))
    active = C.ActiveTime(beats, CFG.sleep_gap_seconds)
    assert active.total == 400
    act = _activity(active, [(0.0, 5500.0)], [[190.0]], [[5305.0]])
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, offsets=(-12.0, 12.0), B=50)
    plus = _pooled(res, "T1", 12)
    assert plus["controlled_causes"] == 1 and plus["control_hits"] == 1
    minus = _pooled(res, "T1", -12)
    assert minus["controlled_causes"] == 1 and minus["control_hits"] == 0     # [176, 188] is empty


def test_control_window_must_lie_inside_the_life_and_is_adjacent_to_the_true_window():
    """Life 0-100 s, causes at 5 s (the -12 window [-9, 3] is outside the life -> not controlled;
    the +12 window [15, 27] is inside) and at 50 s. Effects at 37 s (= 50 - 13: inside the -12
    window [36, 48] of the second cause), 62 s (inside [60, 72] = its +12 window) and 55 s (in the
    TRUE window [48, 60] only: no control window may hold it)."""
    active = C.ActiveTime(np.arange(0, 101, 10.0), CFG.sleep_gap_seconds)
    act = _activity(active, [(0.0, 100.0)], [[5.0, 50.0]], [[37.0, 55.0, 62.0]])
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, offsets=(-12.0, 12.0), B=50)
    minus, plus = _pooled(res, "T1", -12), _pooled(res, "T1", 12)
    assert minus["controlled_causes"] == 1 and minus["control_hits"] == 1
    assert plus["controlled_causes"] == 2 and plus["control_hits"] == 1
    assert plus["real_hits"] == 1 and minus["real_hits"] == 1              # the real window of the cause at 50 s
    # the 55 s effect is in no control window: shift the effects so that only it exists
    act2 = _activity(active, [(0.0, 100.0)], [[5.0, 50.0]], [[55.0]])
    res2 = K.sideband_analysis(act2, EMPTY_POOL, CFG, offsets=(-12.0, 12.0), B=50)
    assert _pooled(res2, "T1", -12)["control_hits"] == 0 and _pooled(res2, "T1", 12)["control_hits"] == 0
    assert res2["rows"]["T1"]["population"]["processes"] == 1


def test_population_rule_life_and_effects_and_all_three_rows():
    """Processes shorter than 12 s or without an effect of the row's kind are not in the row's
    population (as production never grades them); T2 and T3 use inbound / child events."""
    active = C.ActiveTime(np.arange(0, 1001, 10.0), CFG.sleep_gap_seconds)
    procs = {"long": {"program": "a.exe", "t0": 0.0, "t1": 1000.0, "life": 1000.0},
             "short": {"program": "b.exe", "t0": 0.0, "t1": 11.0, "life": 11.0},
             "noeff": {"program": "c.exe", "t0": 0.0, "t1": 1000.0, "life": 1000.0}}
    ev = {"out": {"long": [100.0], "short": [1.0], "noeff": [100.0]},
          "in": {"long": [300.0]},
          "file": {"long": [400.0], "short": [2.0]},
          "child": {"long": [288.0, 500.0]}}
    res = K.sideband_analysis(C.Activity(active, procs, ev, {}), EMPTY_POOL, CFG, offsets=(-12.0, 12.0), B=50)
    assert res["rows"]["T1"]["population"]["processes"] == 1
    assert res["rows"]["T2"]["population"]["processes"] == 1 and res["rows"]["T3"]["population"]["processes"] == 1
    assert _pooled(res, "T2", -12)["control_hits"] == 1       # child at 288 = inbound 300 - 12: in [286, 298]
    assert _pooled(res, "T3", -12)["control_hits"] == 0
    assert res["meta"]["burst_factor_used"] == 1


def test_prediction_is_averaged_over_the_same_controlled_causes():
    """Process A: busy (high p1), but all its causes sit in the first 14 s of its life, so none
    has a -12 control window. Process B: quiet, controllable causes. The -12 statistics must be
    built from B alone: processes = 1 and the predicted chance = B's p1 (per cause and per
    process), not a mixture with A's."""
    active = C.ActiveTime(np.arange(0, 2001, 10.0), CFG.sleep_gap_seconds)
    a_eff = list(np.arange(20.0, 2000.0, 5.0))                     # 396 effects: p1 ~ 1 - e^-2.4
    act = _activity(active, [(0.0, 2000.0), (0.0, 2000.0)], [[3.0, 8.0, 13.0], [500.0, 1000.0, 1500.0]],
                    [a_eff, [100.0]])
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, offsets=(-12.0, 12.0), B=50)
    minus = _pooled(res, "T1", -12)
    p1_b = C.chance(1 / 2000.0, 12)
    assert minus["processes"] == 1 and minus["controlled_causes"] == 3
    assert minus["per_process"]["p"] == pytest.approx(p1_b) and minus["per_cause"]["p"] == pytest.approx(p1_b)
    plus = _pooled(res, "T1", 12)
    assert plus["processes"] == 2 and plus["controlled_causes"] == 6
    assert plus["per_cause"]["p"] > 10 * p1_b                      # now A's causes count too


def test_bootstrap_resamples_processes_not_causes():
    """40 processes x 50 causes each; 20 processes hit at every -12 window, 20 never. The share is
    0.5 either way, but its uncertainty is a 40-process question (sd ~ 0.079: the 95 % upper
    bound of the resampled mean is ~0.63), not a 2,000-cause one (sd ~ 0.011: ~0.52)."""
    active = C.ActiveTime(np.arange(0, 10001, 10.0), CFG.sleep_gap_seconds)
    causes = [list(np.arange(100.0, 5001.0, 100.0))] * 40
    effects = [[c - 8.0 for c in causes[0]] if i < 20 else [9000.0] for i in range(40)]
    act = _activity(active, [(0.0, 10000.0)] * 40, causes, effects)
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, offsets=(-12.0,), B=FAST_B)
    st = _pooled(res, "T1", -12)
    assert st["processes"] == 40 and st["controlled_causes"] == 2000 and st["control_hits"] == 1000
    assert st["per_process"]["o"] == pytest.approx(0.5)
    assert 0.60 <= st["per_process"]["o_upper95"] <= 0.70, st["per_process"]
    assert 0.30 <= st["per_process"]["o_lower05"] <= 0.40, st["per_process"]


# -- simulations ----------------------------------------------------------------------------------------
def _independent_streams(seed, n=40, lam_c=0.02, lam_e=0.02):
    """Independent Poisson cause and effect streams in n processes, each living across a sleep."""
    rng = np.random.default_rng(seed)
    active, spans = _machine(2 * n), _spans(n)
    causes, effects = [], []
    for t0, t1 in spans:
        life = active.seconds(t0, t1)
        causes.append(_poisson_in_life(rng, active, t0, life, lam_c))
        effects.append(_poisson_in_life(rng, active, t0, life, lam_e))
    return _activity(active, spans, causes, effects)


def test_simulation_poisson_with_sleeps_gives_ratio_one_at_every_offset():
    """Independent cause and effect streams: the control hit rate equals the Poisson prediction at
    every offset (ratio 1 inside the bootstrap interval and the exact intervals), and the per-cause
    rate equals the true chance within 4 standard errors. Fixed seed: the interval checks are a
    regression check (a 90 % interval misses by chance in some seeds; the unbiasedness itself is
    the next test; the coverage study is in the package J report)."""
    act = _independent_streams(POISSON_SEED)
    assert all(abs(p["life"] - 8000) < 1e-6 for p in act.procs.values())     # the sleeps were skipped
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, B=FAST_B)
    truth = C.chance(0.02, CFG.window)
    for s in K.ALL_OFFSETS:
        st = _pooled(res, "T1", s)
        pp, pc = st["per_process"], st["per_cause"]
        assert pp["beta_lower05"] <= 1.0 <= pp["beta_upper95"], (s, pp)
        se = math.sqrt(truth * (1 - truth) / st["controlled_causes"])
        assert abs(pc["o"] - truth) <= 4 * se + 0.03 * truth, (s, pc["o"], truth)
        assert pc["beta_cp"][0] <= 1.0 <= pc["beta_cp"][1], (s, pc)
        assert pc["garwood_ratio"][0] <= 1.0 <= pc["garwood_ratio"][1], (s, pc)


def test_simulation_poisson_sideband_is_unbiased_over_seeds():
    """The property behind the test above: over several independent simulations the mean error
    of the control rate against the true chance is zero (within 3 standard errors) at every offset."""
    truth = C.chance(0.02, CFG.window)
    err = {s: [] for s in K.ALL_OFFSETS}
    for seed in range(6):
        res = K.sideband_analysis(_independent_streams(seed, n=30), EMPTY_POOL, CFG, B=50)
        for s in K.ALL_OFFSETS:
            err[s].append(_pooled(res, "T1", s)["per_process"]["o"] - truth)
    for s, e in err.items():
        e = np.array(e)
        assert abs(e.mean()) <= 3 * e.std(ddof=1) / math.sqrt(len(e)) + 0.005 * truth, (s, e)


def _burst_activity(rng, n, burst_len, nu=1 / 1000.0, mean_causes=8, mean_effects=2, per=4):
    """Common-driver bursts: in each process bursts start as a Poisson process (rate nu per active
    second); inside a burst, causes and effects are placed independently and uniformly. There is
    NO causal link, so whatever lands in the true window is coincidence by construction."""
    active, spans = _machine(per * n), _spans(n, per=per)
    causes, effects = [], []
    for t0, t1 in spans:
        life = active.seconds(t0, t1)
        pos0 = float(active.position(t0))
        starts = pos0 + rng.uniform(0, life - burst_len, rng.poisson(nu * (life - burst_len)))
        cs, es = [], []
        for b in starts:
            cs += list(b + rng.uniform(0, burst_len, rng.poisson(mean_causes)))
            es += list(b + rng.uniform(0, burst_len, rng.poisson(mean_effects)))
        causes.append(active.at_position(np.sort(cs)) if cs else [])
        effects.append(active.at_position(np.sort(es)) if es else [])
    return _activity(active, spans, causes, effects)


def test_simulation_common_driver_bursts_recover_the_truth_at_12_and_underestimate_at_60():
    """Bursts of 400 s: the chance that a 12 s window next to a cause holds an unrelated effect is
    about 7x the Poisson prediction. The -12/+12 sidebands recover the real-window rate (the truth,
    since nothing is causal) inside their bootstrap interval; the +-60 sidebands fall outside the
    burst more often and under-estimate it."""
    act = _burst_activity(np.random.default_rng(7), n=60, burst_len=400.0)
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, B=FAST_B)
    for s in (-12.0, 12.0):
        pp = _pooled(res, "T1", s)["per_process"]
        assert pp["o_lower05"] <= pp["real"] <= pp["o_upper95"], (s, pp)
        assert pp["beta"] > 3.0                                           # far above Poisson
    for s in (-60.0, 60.0):
        pp = _pooled(res, "T1", s)["per_process"]
        assert pp["o_upper95"] < pp["real"], (s, pp)


def test_simulation_short_bursts_show_the_known_bias_direction():
    """Documented limit (design section 2, 'stated biases'): in bursts shorter than the sideband
    distance (15 s here) the sidebands look outside the burst and UNDER-estimate the same-burst
    coincidence; -12 less so than +12, and +-60 sees only other bursts. The report must say so."""
    act = _burst_activity(np.random.default_rng(11), n=60, burst_len=15.0, mean_causes=4, mean_effects=1.5)
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, offsets=(-60.0, -12.0, 12.0, 60.0), B=200)
    real = _pooled(res, "T1", -12)["per_process"]["real"]
    o = {s: _pooled(res, "T1", s)["per_process"]["o"] for s in (-60.0, -12.0, 12.0, 60.0)}
    assert o[12.0] < o[-12.0] < real
    assert max(o[-60.0], o[60.0]) < 0.3 * real


def test_simulation_causal_chain_keeps_the_sideband_at_background():
    """Every cause makes an effect 1 s later, plus background effects. The true window is almost
    always hit (that is the causation), but both decision sidebands see only the background and
    other causes' effects, which is exactly what the Poisson prediction counts: ratio 1."""
    rng = np.random.default_rng(3)
    n = 40
    active, spans = _machine(2 * n), _spans(n)
    causes, effects = [], []
    for t0, t1 in spans:
        life = active.seconds(t0, t1)
        c = _poisson_in_life(rng, active, t0, life, 0.003)
        bg = _poisson_in_life(rng, active, t0, life, 0.0005)
        caused = active.at_position(np.asarray(active.position(c)) + 1.0)
        causes.append(c)
        effects.append(np.sort(np.concatenate([caused, bg])))
    res = K.sideband_analysis(act := _activity(active, spans, causes, effects), EMPTY_POOL, CFG, B=FAST_B)
    assert len(act.procs) == n
    for s in (-12.0, 12.0):
        pp = _pooled(res, "T1", s)["per_process"]
        assert pp["real"] > 0.95 and pp["o"] < 0.1, (s, pp)
        assert pp["beta_lower05"] <= 1.0 <= pp["beta_upper95"], (s, pp)


# -- the pre-registered decision rule on hand-made tables ------------------------------------------------
def _stats(processes=50, hits=40, upper=1.0):
    return {"processes": processes, "control_hits": hits, "controlled_causes": 1000,
            "per_process": {"beta_upper95": upper}}


def _table(**rows):
    """rows: T1={"-12": {"medium": stats, "pooled": stats}, "+12": {...}}"""
    return {"rows": {row: {"offsets": {key: {"bands": bands} for key, bands in offs.items()}}
                     for row, offs in rows.items()}}


def test_decidable_thresholds():
    assert K.decidable(_stats(30, 10))
    assert not K.decidable(_stats(29, 10)) and not K.decidable(_stats(30, 9))
    assert K.MIN_PROCESSES == 30 and K.MIN_HITS == 10
    assert K.GRID == (1, 1.5, 2, 2.5, 3, 4, 5) and K.DECISION_OFFSETS == (-12.0, 12.0) and K.STOP_ABOVE == 5


@pytest.mark.parametrize("u,expected", [
    (0.7, 1), (1.0, 1), (1.01, 1.5), (1.5, 1.5), (2.01, 2.5), (2.5, 2.5), (3.2, 4), (4.01, 5), (5.0, 5),
])
def test_grid_rounding_goes_up_to_the_smallest_value_at_or_above(u, expected):
    d = K.choose_burst_factor(_table(T3={"-12": {"medium": _stats(upper=u)}, "+12": {"medium": _stats(upper=u - 0.2)}}))
    assert d["beta_star"] == expected and d["max_upper"] == pytest.approx(u) and not d["stop"]
    assert d["rows"]["T3"]["upper"] == pytest.approx(u) and d["rows"]["T3"]["offsets"]["-12"]["band"] == "medium"


def test_decision_takes_the_max_over_rows_and_sidebands():
    d = K.choose_burst_factor(_table(
        T1={"-12": {"medium": _stats(upper=1.2)}, "+12": {"medium": _stats(upper=1.9)}},
        T3={"-12": {"medium": _stats(upper=2.2)}, "+12": {"medium": _stats(upper=1.1)}}))
    assert d["max_upper"] == pytest.approx(2.2) and d["beta_star"] == 2.5
    assert d["rows"]["T1"]["upper"] == pytest.approx(1.9) and d["rows"]["T3"]["upper"] == pytest.approx(2.2)


def test_stop_condition_above_five_returns_none_with_the_reason():
    d = K.choose_burst_factor(_table(T3={"-12": {"medium": _stats(upper=5.01)}, "+12": {"medium": _stats(upper=1.0)}}))
    assert d["beta_star"] is None and d["stop"] and "Yousif" in d["reason"]
    d = K.choose_burst_factor(_table(T3={"-12": {"medium": _stats(upper=math.inf)}, "+12": {"medium": _stats(upper=1.0)}}))
    assert d["beta_star"] is None and d["stop"]


def test_pooling_fallback_and_undecidable_rows():
    # medium has too few processes at -12 -> pooled decides there; +12 medium is fine
    d = K.choose_burst_factor(_table(
        T1={"-12": {"medium": _stats(processes=29, upper=9.0), "pooled": _stats(upper=1.4)},
            "+12": {"medium": _stats(upper=1.1), "pooled": _stats(upper=3.0)}}))
    assert d["rows"]["T1"]["offsets"]["-12"]["band"] == "pooled" and d["rows"]["T1"]["offsets"]["+12"]["band"] == "medium"
    assert d["max_upper"] == pytest.approx(1.4) and d["beta_star"] == 1.5
    # too few hits in medium AND pooled at both offsets -> the row is reported but does not decide
    d = K.choose_burst_factor(_table(
        T2={"-12": {"medium": _stats(hits=3, upper=20.0), "pooled": _stats(hits=9, upper=10.0)},
            "+12": {"medium": _stats(hits=2, upper=20.0), "pooled": _stats(hits=5, upper=10.0)}},
        T3={"-12": {"medium": _stats(upper=1.7)}, "+12": {"medium": _stats(upper=1.6)}}))
    assert not d["rows"]["T2"]["decides"] and d["rows"]["T3"]["decides"]
    assert d["beta_star"] == 2 and d["deciding_rows"] == ["T3"]
    # one sideband decidable only: the row still decides, flagged partial
    d = K.choose_burst_factor(_table(T3={"-12": {"medium": _stats(upper=1.7)}, "+12": {"medium": _stats(hits=1, upper=9.0)}}))
    assert d["rows"]["T3"]["decides"] and d["rows"]["T3"]["partial"] and d["beta_star"] == 2
    # nothing decidable anywhere
    d = K.choose_burst_factor(_table(T2={"-12": {"medium": _stats(hits=1)}, "+12": {"pooled": _stats(hits=1)}}))
    assert d["beta_star"] is None and not d["stop"] and "no decidable row" in d["reason"]


def test_decision_runs_on_a_real_result_table():
    act = _burst_activity(np.random.default_rng(5), n=40, burst_len=400.0)
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, B=200)
    d = K.choose_burst_factor(res)
    assert d["rows"]["T1"]["decides"] and d["rows"]["T1"]["offsets"]["-12"]["band"] in ("medium", K.POOLED)
    assert not d["rows"]["T2"]["decides"]                                                           # no T2 data at all
    assert d["stop"] or d["beta_star"] in K.GRID


# -- privacy and output --------------------------------------------------------------------------------
def test_results_and_summary_hold_counts_only(tmp_path):
    act = _burst_activity(np.random.default_rng(5), n=35, burst_len=400.0)
    for p in act.procs.values():
        p["program"] = "secret_name.exe"
    res = K.sideband_analysis(act, EMPTY_POOL, CFG, B=100)
    res["meta"]["store"] = "dev-laptop.db"
    text = json.dumps(res)
    md = K.summary_markdown(res, K.choose_burst_factor(res))
    for forbidden in ("secret", ".exe", "\\", "g0", "C:"):
        assert forbidden not in text and forbidden not in md, forbidden
    assert "T1" in md and "T3" in md and "decision" in md.lower()
    json.loads(text)                                                   # serialisable


# -- the CLI: refusals and an end-to-end run on a toy store ------------------------------------------------
COLS = ("id", "dedup_key", "host", "channel", "record_id", "event_id", "type", "time", "origin", "UtcTime",
        "ProcessGuid", "Image", "ParentProcessGuid", "ParentImage", "Initiated", "Protocol", "DestinationPort",
        "LocalPort", "hash_status", "ref_record_id", "ref_time", "ConfigurationFileHash")
T0 = 1_760_000_000.0


def _iso(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _toy_store(path, cutoff="2026-10-22", snapshot=True, guid="{11111111-1111-1111-1111-111111111111}"):
    db = sqlite3.connect(path)
    db.execute(f"CREATE TABLE events ({', '.join(COLS)})")
    rows = [dict(event_id=1, t=T0, ProcessGuid=guid, Image=r"C:\x\tool.exe")]
    rows += [dict(event_id=3, t=T0 + 100 + 50 * i, ProcessGuid=guid, Initiated="true") for i in range(10)]
    rows += [dict(event_id=11, t=T0 + 130 + 50 * i, ProcessGuid=guid, record_id=900 + i) for i in range(10)]
    rows += [dict(event_id=3, t=T0 + 10 * i, ProcessGuid=guid, Initiated="false", Protocol="udp", DestinationPort=5353)
             for i in range(80)]
    rows.append(dict(event_id=5, t=T0 + 800, ProcessGuid=guid))
    for i, r in enumerate(rows, 1):
        r = {"id": i, "dedup_key": f"k{i}", "host": "h", "channel": C.SYSMON_CHANNEL, "record_id": i, "origin": "normal", **r}
        r["UtcTime"] = _iso(r.pop("t"))
        r["time"] = r["UtcTime"].replace(" ", "T") + "Z"
        db.execute(f"INSERT INTO events ({', '.join(r)}) VALUES ({', '.join('?' * len(r))})", list(r.values()))
    if snapshot:
        db.execute("CREATE TABLE snapshot (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO snapshot VALUES ('cutoff_day_utc', ?)", (cutoff,))
    db.commit()
    db.close()


def _toy_pool(path):
    pool = C.Pool({k: {} for k in C.KINDS}, {k: {"60-3600": (1, 100000.0)} for k in C.KINDS}, {"processes": 1})
    return pool.save(path)


def test_cli_refuses_a_store_without_a_dev_snapshot_or_after_the_cutoff(tmp_path, capsys):
    db, pool = str(tmp_path / "x.db"), str(tmp_path / "pool.json")
    _toy_pool(pool)
    _toy_store(db, snapshot=False)
    assert burst_factor.main(["--db", db, "--pool", pool, "--out-dir", str(tmp_path), "--summary", str(tmp_path / "s.md")]) == 2
    assert "snapshot" in capsys.readouterr().out.lower()
    db2 = str(tmp_path / "y.db")
    _toy_store(db2, cutoff="2099-01-01")
    assert burst_factor.main(["--db", db2, "--pool", pool, "--out-dir", str(tmp_path), "--summary", str(tmp_path / "s.md")]) == 2
    assert "cutoff" in capsys.readouterr().out.lower()
    assert not (tmp_path / "s.md").exists()


def test_cli_refuses_a_pool_with_the_wrong_fingerprint(tmp_path, capsys):
    db, pool = str(tmp_path / "x.db"), str(tmp_path / "pool.json")
    _toy_store(db)
    _toy_pool(pool)
    assert K.FROZEN_POOL_SHA256 == "3e39f2cfd5c5263c8e483a82e427683cc5f0b9b6f5a36afe9e8a25f78946b1bb"
    assert burst_factor.main(["--db", db, "--pool", pool, "--out-dir", str(tmp_path), "--summary", str(tmp_path / "s.md")]) == 2
    assert "pool" in capsys.readouterr().out.lower()


def test_cli_end_to_end_on_a_toy_store(tmp_path, capsys, monkeypatch):
    db, pool = str(tmp_path / "x.db"), str(tmp_path / "pool.json")
    _toy_store(db)
    monkeypatch.setattr(K, "FROZEN_POOL_SHA256", _toy_pool(pool))
    monkeypatch.setattr(burst_factor, "BOOTSTRAP_B", 100)
    from dataclasses import replace
    real_load = burst_factor.C.load_config              # the frozen pool hash names the real pool, not the toy one
    monkeypatch.setattr(burst_factor.C, "load_config", lambda *a, **k: replace(real_load(*a, **k), pool_sha256=None))
    out, summary = tmp_path / "j", tmp_path / "docs" / "j.md"
    rc = burst_factor.main(["--db", db, "--pool", pool, "--out-dir", str(out), "--summary", str(summary)])
    printed = capsys.readouterr().out
    assert rc == 0, printed
    files = list(out.glob("*.json"))
    assert len(files) == 1 and summary.exists()
    res = json.loads(files[0].read_text(encoding="utf-8"))
    assert res["rows"]["T1"]["population"]["processes"] == 1 and res["rows"]["T1"]["population"]["causes"] == 10
    assert res["decision"]["beta_star"] is None and "no decidable row" in res["decision"]["reason"]
    assert res["meta"]["store_cutoff_day_utc"] == "2026-10-22"
    for forbidden in ("tool.exe", "C:\\x", "11111111"):
        assert forbidden not in printed and forbidden not in files[0].read_text(encoding="utf-8")
        assert forbidden not in summary.read_text(encoding="utf-8")

def test_unsorted_effects_give_the_same_result():
    """The control counts must not depend on the order effects are listed in (review F1:
    searchsorted needs sorted positions; load_activity sorts, the function must not rely on it)."""
    active = C.ActiveTime(np.arange(0, 1001, 10.0), CFG.sleep_gap_seconds)
    procs = {"p": {"program": "a.exe", "t0": 0.0, "t1": 1000.0, "life": 1000.0}}
    out = {"p": [312.0, 512.0]}
    sorted_ev = {"out": out, "in": {}, "child": {}, "file": {"p": [100.0, 300.0, 500.0, 700.0]}}
    shuffled = {"out": out, "in": {}, "child": {}, "file": {"p": [700.0, 100.0, 500.0, 300.0]}}
    a = K.sideband_analysis(C.Activity(active, procs, sorted_ev, {}), EMPTY_POOL, CFG, offsets=(-12.0,), B=50)
    b = K.sideband_analysis(C.Activity(active, procs, shuffled, {}), EMPTY_POOL, CFG, offsets=(-12.0,), B=50)
    assert _pooled(a, "T1", -12)["control_hits"] == _pooled(b, "T1", -12)["control_hits"] == 2
