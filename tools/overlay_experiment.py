"""Package J part 1, sections 2.5 and 3 of docs/plans/package-j-design.md: the noise-overlay
smoke test of package G and the overlay measurements, on DEV data only.

    python tools/overlay_experiment.py                      # the pre-registered matrix (about 30 + 30 min)
    python tools/overlay_experiment.py --runs s1:1 --volumes 0 1 --seeds 1 --r4-seeds 2   # a quick look

Matrix: scenarios S1 (3 runs), S2, S2J, S3, S4, S5, C1 (the newest clean practice runs; official
series never); volumes 0x, 1x, 5x; seeds 1-3; grafting on, plus one --no-graft pass at the highest
volume. For every cell: the overlay store (tools/noise_overlay.py), the graph with layer 2, the
full graph checker on the store (with the frozen hub list, and once more without hubs), and:
  - hypotheses by source class (scenario-story, scenario-vm, vm-background, overlay-internal,
    cross/graft, cross) and band; sigma-p;
  - the whole-graph promises (design 1.8): no shared node, no fact across the two worlds except
    grafted `started` edges (never to a role), no cross R1/R2/R3/F1, no cross T1-T3 without grafting;
  - graft-induced cross T2/T3: observed vs their sigma-p (an independence check, never used for beta);
  - the view's size, truncation and hubs not followed; `--no-hubs` / `--no-graft` differences.
Then the false name-only R4 rate: cross R4 links (an overlay process named a file the VM created, or
the reverse: provably false, the two worlds never met) per graph over >= 10 seeds at every volume,
with the exact Poisson (Garwood) 95 % interval. And every band change of the scenario's own
hypotheses between 0x and 1x/5x (design 1.9).

Pass criteria (decision Q7): no crash and bounded views at every volume; facts and gaps PASS at
every volume and seed; at 1x the full checker passes for every scenario and seed; 5x is reported
as measured degradation with every lost expected edge listed.

Writes docs/results/j-noise-overlay-dev.md (counts, bands, scenario program names only) and the
JSON next to the stores under recordings/scratch/overlay/.
Package J part 2 (docs/plans/package-j2-prereg.md, experiment J6): with ANALYSTLAB_OFFICIAL=1 the
matrix runs on the OFFICIAL runs instead (every official run of each scenario, after
engine.config.verify_official() passes; practice runs are then refused by tools/noise_overlay.py);
tools/experiments.py drives it and names the outputs. Without the variable, official runs are
never touched (part 1 behaviour).
engine/calibration.py (the sideband analysis) is built separately; the Garwood interval here is
a small local implementation (numpy/math only) so this file does not depend on it.
"""

import argparse
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
import noise_overlay  # noqa: E402
from engine import config, overlay  # noqa: E402
from engine.graph import Layer2, build_graph  # noqa: E402

DEFAULT_RUNS = ["s1:3", "s2", "s2j", "s3", "s4", "s5", "c1"]
DEFAULT_VOLUMES = [0, 1, 5]
DEFAULT_SEEDS = [1, 2, 3]
DEFAULT_R4_SEEDS = 10
CLASSES = ("scenario-story", "scenario-vm", "vm-background", "overlay-internal", "cross/graft", "cross-r4", "cross")
ROWS = ("T1", "T2", "T3", "R1", "R2", "R3", "R4")
BANDS = ("high", "medium", "low")


# -- exact Poisson interval (Garwood), math only -------------------------------------------------------
def _gammainc(a, x):
    """Regularized lower incomplete gamma P(a, x) (Numerical Recipes: series for x < a + 1, Lentz's
    continued fraction otherwise)."""
    if x <= 0:
        return 0.0
    lg = math.lgamma(a)
    if x < a + 1:
        term = total = 1.0 / a
        n = a
        for _ in range(10000):
            n += 1
            term *= x / n
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return total * math.exp(-x + a * math.log(x) - lg)
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return 1.0 - math.exp(-x + a * math.log(x) - lg) * h


def chi2_ppf(p, df):
    """The chi-square quantile by bisection on the regularized gamma function."""
    if not 0 < p < 1 or df <= 0:
        raise ValueError("chi2_ppf needs 0 < p < 1 and df > 0")
    lo, hi = 0.0, max(10.0, df * 4.0)
    while _gammainc(df / 2, hi / 2) < p:
        hi *= 2
    for _ in range(200):
        mid = (lo + hi) / 2
        if _gammainc(df / 2, mid / 2) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def garwood_interval(n, conf=0.95):
    """Exact two-sided interval for a Poisson mean given `n` observed events (Garwood 1936)."""
    if isinstance(n, bool) or int(n) != n or n < 0:
        raise ValueError("n must be a whole number >= 0")
    alpha = 1 - conf
    lo = 0.0 if n == 0 else 0.5 * chi2_ppf(alpha / 2, 2 * n)
    hi = 0.5 * chi2_ppf(1 - alpha / 2, 2 * n + 2)
    return lo, hi


# -- the matrix -----------------------------------------------------------------------------------------
def plan_runs(recordings, specs, say=print, official=False, until=None, skip_missing=False, skipped=None):
    """[(scenario, run record)]: the newest clean, non-overlapping PRACTICE runs (no official run,
    none started after the first official series began), `n` per scenario for a spec "s1:3" (1 by
    default); `until` = only runs started on or before that UTC day. With official=True (package J
    part 2): every clean OFFICIAL run of each scenario instead (a spec's n then caps it).
    A scenario without a clean run raises ValueError, or with skip_missing=True is noted (and
    appended to `skipped`) and left out so the other scenarios still run (review 2026-10-30)."""
    ids = noise_overlay.official_run_ids(recordings)                   # once per call, not per run
    periods = noise_overlay.official_periods(recordings)
    all_runs = check_scenario.all_runs(recordings)
    kind = "official" if official else "practice"
    out = []
    for spec in specs:
        name, _, n = spec.partition(":")
        n = int(n) if n else (None if official else 1)
        runs = [r for r in all_runs if str(r.get("scenario", "")).upper() == name.upper() and r.get("exit_code") == 0
                and ((r.get("run_id") in ids) if official else noise_overlay.is_practice_run(recordings, r, ids=ids, periods=periods))
                and (until is None or str(r.get("start", ""))[:10] <= until)
                and not check_scenario.run_window(recordings, r, all_runs).overlaps_previous]
        if not runs:
            msg = f"no clean {kind} run of {name.upper()} in {recordings} (recordings/vmruns)"
            if not skip_missing:
                raise ValueError(msg)
            say(f"  note: {msg}: skipped")
            if skipped is not None:
                skipped.append(name.upper())
            continue
        if n is not None and len(runs) < n:
            say(f"  note: only {len(runs)} clean {kind} run(s) of {name.upper()}, {n} wanted")
        out += [(name.lower(), r) for r in (runs if n is None else runs[-n:])]
    return out


def _view_numbers(lines):
    """From the checker's lines: the alert view's node count, truncation, hubs not followed; the
    runner view's node count."""
    out = {"alert_nodes": None, "truncated": False, "hubs_not_followed": 0, "runner_nodes": None}
    for l in lines:
        m = re.search(r"alert view \(.*?(\d+) nodes(, truncated)?", l)
        if m:
            out["alert_nodes"], out["truncated"] = int(m.group(1)), bool(m.group(2))
            h = re.search(r"(\d+) hub\(s\) not followed", l)
            out["hubs_not_followed"] = int(h.group(1)) if h else 0
        m = re.search(r"runner view \(.*?, (\d+) nodes\)", l)
        if m:
            out["runner_nodes"] = int(m.group(1))
    return out


def _hyp_table(counter):
    """Counter[(class, row, band)] -> {class: {row: {band: n}}} (JSON-friendly)."""
    out = defaultdict(lambda: defaultdict(dict))
    for (cls, row, band), n in sorted(counter.items(), key=lambda x: (str(x[0][0]), str(x[0][1]), str(x[0][2]))):
        out[cls][str(row)][str(band)] = n
    return {c: {r: dict(b) for r, b in rows.items()} for c, rows in out.items()}


def invariants(summary, graft):
    """The design's promises on one graph (section 1.8), each named when broken."""
    broken = []
    if summary["shared_nodes"]:
        broken.append(f"{len(summary['shared_nodes'])} node(s) shared by both worlds")
    if summary["cross_facts"]:
        broken.append(f"{len(summary['cross_facts'])} fact(s) join the two worlds")
    if summary["graft_started_to_role"]:
        broken.append(f"{summary['graft_started_to_role']} graft(s) onto a role process")
    if summary["overlay_scenario_edges"]:
        broken.append(f"{summary['overlay_scenario_edges']} edge(s) join an overlay node and a scenario node")
    # cross-r4 (a file-name match across the two worlds) is the MEASURED false link, not a leak
    cross = sum(n for (c, r, _), n in summary["hypotheses"].items() if c == "cross")
    if cross:
        broken.append(f"{cross} cross hypothesis(es) not explained by grafting")
    rules = sum(n for (c, r, _), n in summary["hypotheses"].items() if c.startswith("cross") and r in ("R1", "R2", "R3", "F1"))
    if rules:
        broken.append(f"{rules} cross R1/R2/R3/F1 link(s)")
    if not graft and summary["cross_t_observed"]:
        broken.append(f"{summary['cross_t_observed']} cross timing link(s) without grafting")
    return {"ok": not broken, "broken": broken}


def evaluate(recordings, scenario, run, volume, seed, graft, laptop, layer2, hubs, truth, vm_records, check=True, pool=None):
    """One cell: build the store, the graph and (check=True) the checker's verdicts; the measurements."""
    t0 = time.perf_counter()
    path, meta = noise_overlay.build_for_run(recordings, scenario, run, volume, seed, graft, laptop, vm_records=vm_records, pool=pool)
    t_build = time.perf_counter() - t0
    G = build_graph(path, hypotheses=layer2)
    t_graph = time.perf_counter() - t0 - t_build
    lo, hi, _ = check_scenario.run_window(recordings, run)
    server = check_scenario.run_server(run)
    cell = {"scenario": scenario.upper(), "run_id": run.get("run_id"), "volume": volume, "seed": seed, "graft": graft,
            "store": os.path.basename(path), "vm_records": meta["vm_records"], "overlay_rows": meta["overlay_rows"],
            "counts": meta["counts"], "grafts": len(meta["grafts"]),
            "graph": {"nodes": G.number_of_nodes(), "facts": sum(1 for _, _, d in G.edges(data=True) if d.get("grade") == "fact"),
                      "hypotheses": sum(1 for _, _, d in G.edges(data=True) if d.get("grade") == "hypothesis"),
                      "gaps": len(G.graph["gaps"])},
            "layer2": {k: G.graph["layer2"].get(k) for k in ("counts", "sigma_p", "sigma_p_assessable", "not_drawn", "tested", "linked", "until")},
            "seconds": {"build": round(t_build, 2), "graph": round(t_graph, 2)}}
    role_nodes = set()
    if check:
        raw = check_graph_scenario.records_from_store(path)
        lines, lines_nh = [], []
        ok, c = check_graph_scenario.check_graph(truth, G, raw, lo, hi, server, hubs, say=lines.append)
        ok_nh, _ = check_graph_scenario.check_graph(truth, G, raw, lo, hi, server, None, say=lines_nh.append)
        role_nodes = {n for r in c.roles for n in c.nodes_of(r)}
        sections = {"facts": not any(l.startswith("  FAIL  fact") or "unexpected fact" in l or "other file node" in l for l in lines),
                    "gaps": any(l.startswith("  gaps  PASS") for l in lines),
                    "hypotheses": not any("hypothesis" in l and l.startswith("  FAIL") for l in lines),
                    "alert_view": any("alert view" in l and l.rstrip().endswith("PASS") for l in lines),
                    "runner_view": any("runner view" in l and l.rstrip().endswith("PASS") for l in lines),
                    "trace": any(l.startswith("  trace  PASS") for l in lines)}
        cell["checker"] = {"pass": ok, "sections": sections, "fail_lines": [l.strip() for l in lines if l.startswith("  FAIL")],
                           "view": _view_numbers(lines), "lines": lines}
        cell["checker_no_hubs"] = {"pass": ok_nh, "fail_lines": [l.strip() for l in lines_nh if l.startswith("  FAIL")],
                                   "view": _view_numbers(lines_nh)}
        cell["expected_hypotheses"] = [{"claim": h["claim"], "row": d["row"], "band": d["band"], "p": d.get("p"),
                                        "life_seconds": d.get("life_seconds"), "assessable": d.get("assessable"), "basis": d.get("basis")}
                                       for h, d, _, _ in c.found_hyps]
    s = overlay.cross_summary(G, path, role_nodes, meta["grafts"])
    cell["hypotheses_by_class"] = _hyp_table(s["hypotheses"])
    cell["cross"] = {"shared_nodes": len(s["shared_nodes"]), "cross_facts": len(s["cross_facts"]),
                     "graft_started": s["graft_started"], "graft_started_to_role": s["graft_started_to_role"],
                     "overlay_scenario_edges": s["overlay_scenario_edges"], "cross_r4_on_scenario": s["cross_r4_on_scenario"],
                     "cross_t_observed": s["cross_t_observed"],
                     "cross_t_sigma_p": round(s["cross_t_sigma_p"], 4), "cross_r4": dict(s["cross_r4"]),
                     "nodes": dict(s["classes"])}
    cell["invariants"] = invariants(s, graft)
    cell["seconds"]["total"] = round(time.perf_counter() - t0, 2)
    return cell


def band_changes(cells):
    """Every change of an expected hypothesis's band (or life) between 0x and a noisier volume of
    the same run (grafting on; 0x is the same for every seed)."""
    base = {}
    for c in cells:
        if c["volume"] == 0 and c.get("expected_hypotheses") is not None:
            base[c["run_id"]] = {h["claim"]: h for h in c["expected_hypotheses"]}
    out = []
    for c in cells:
        if c["volume"] == 0 or not c["graft"] or c.get("expected_hypotheses") is None:
            continue
        for h in c["expected_hypotheses"]:
            b = base.get(c["run_id"], {}).get(h["claim"])
            if b is None:
                continue
            if b["band"] != h["band"] or (b.get("life_seconds") or 0) != (h.get("life_seconds") or 0):
                out.append({"scenario": c["scenario"], "run_id": c["run_id"], "seed": c["seed"], "volume": c["volume"],
                            "claim": h["claim"], "row": h["row"], "band_0x": b["band"], "band": h["band"],
                            "life_0x": b.get("life_seconds"), "life": h.get("life_seconds"), "p_0x": b.get("p"), "p": h.get("p")})
    return out


def r4_summary(graphs):
    """graphs: [(volume, cross_r4 dict)] -> per volume: graphs, total, name-only, full-path, rate per
    graph with its exact Poisson 95 % interval."""
    per = defaultdict(lambda: {"graphs": 0, "total": 0, "name-only": 0, "full-path": 0})
    for volume, r4 in graphs:
        p = per[str(volume)]
        p["graphs"] += 1
        p["name-only"] += r4.get("name-only", 0)
        p["full-path"] += r4.get("full-path", 0)
        p["total"] += sum(r4.values())
    for p in per.values():
        lo, hi = garwood_interval(p["total"])
        p["rate_per_graph"] = p["total"] / p["graphs"] if p["graphs"] else None
        p["rate_ci95"] = [lo / p["graphs"], hi / p["graphs"]] if p["graphs"] else None
    return {"per_volume": dict(per)}


def summary_runtime(doc):
    return sum(c["seconds"]["total"] for c in doc["cells"]) + sum(x.get("seconds", 0) for x in doc["r4"].get("extra_graphs", []))


# -- the report -----------------------------------------------------------------------------------------
def _fmt(x, digits=3):
    return "-" if x is None else (f"{x:.{digits}f}" if isinstance(x, float) else str(x))


def write_markdown(doc, path):
    L = []
    official = doc["inputs"].get("official")
    if official:
        L.append("# Package J part 2 (J6): noise overlay on the OFFICIAL runs")
        L.append("")
        L.append(f"*Run {doc['started_utc']} by tools/overlay_experiment.py in official mode on TEST data: {doc['inputs']['runs']} official run(s) "
                 f"(noise from the laptop DEV snapshot, cutoff {doc['inputs']['laptop_cutoff']}), volumes {doc['inputs']['volumes']}, seeds {doc['inputs']['seeds']}, "
                 f"R4 seeds 1-{doc['inputs']['r4_seeds']}, hub list {doc['inputs']['hubs']} program(s), pool sha256 {doc['inputs']['pool_sha256']}. "
                 "Counts, bands and scenario program names only (privacy rule 7). Pre-registered: docs/plans/package-j2-prereg.md (J6), "
                 "criteria as in docs/plans/package-j-design.md decision Q7.*")
        if doc["inputs"].get("skipped_scenarios"):
            L.append("")
            L.append(f"**Scenarios without a clean official run, skipped:** {', '.join(doc['inputs']['skipped_scenarios'])}.")
    else:
        L.append("# Package J part 1: noise overlay on the dev runs (smoke test of package G, overlay measurements)")
        L.append("")
        L.append(f"*Run {doc['started_utc']} by tools/overlay_experiment.py on DEV data only: {doc['inputs']['runs']} practice run(s), "
                 f"laptop dev snapshot cutoff {doc['inputs']['laptop_cutoff']}, volumes {doc['inputs']['volumes']}, seeds {doc['inputs']['seeds']}, "
                 f"R4 seeds 1-{doc['inputs']['r4_seeds']}, hub list {doc['inputs']['hubs']} program(s), pool sha256 {doc['inputs']['pool_sha256']}. "
                 "Counts, bands and scenario program names only (privacy rule 7). Pre-registered: docs/plans/package-j-design.md.*")
    L.append("")
    cells = doc["cells"]
    L.append("## Smoke matrix")
    L.append("")
    L.append("Pass criteria (decision Q7): no crash and bounded views at every volume; facts and gaps PASS at every volume and seed; "
             "at 1x the full checker passes for every scenario and seed; 5x is reported as measured degradation.")
    L.append("")
    L.append("| scenario | run | vol | seed | graft | overlay rows | checker | facts | gaps | alert view | runner view | view nodes | trunc. | hubs not followed | no-hubs checker | no-hubs view nodes | hypotheses | Σp |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for c in cells:
        ch, nh = c.get("checker", {}), c.get("checker_no_hubs", {})
        sec = ch.get("sections", {})
        view, nview = ch.get("view", {}), nh.get("view", {})
        L.append(f"| {c['scenario']} | {c['run_id']} | {c['volume']}x | {c['seed']} | {'on' if c['graft'] else 'off'} | {c['overlay_rows']} | "
                 f"{'PASS' if ch.get('pass') else 'FAIL'} | {'PASS' if sec.get('facts') else 'FAIL'} | {'PASS' if sec.get('gaps') else 'FAIL'} | "
                 f"{'PASS' if sec.get('alert_view') else 'FAIL'} | {'PASS' if sec.get('runner_view') else 'FAIL'} | {_fmt(view.get('alert_nodes'))} | "
                 f"{'yes' if view.get('truncated') else 'no'} | {_fmt(view.get('hubs_not_followed'))} | {'PASS' if nh.get('pass') else 'FAIL'} | "
                 f"{_fmt(nview.get('alert_nodes'))} | {c['graph']['hypotheses']} | {_fmt(c['layer2'].get('sigma_p'))} |")
    L.append("")
    verdict = {v: all(c["checker"]["pass"] for c in cells if c["volume"] == v and c["graft"] and "checker" in c) for v in doc["inputs"]["volumes"]}
    L.append("Verdict per volume (grafting on, full checker): " + ", ".join(f"{v}x {'PASS' if ok else 'FAIL'}" for v, ok in verdict.items()) + ".")
    facts_gaps = all(c["checker"]["sections"]["facts"] and c["checker"]["sections"]["gaps"] for c in cells if "checker" in c)
    sizes = [c["checker"]["view"]["alert_nodes"] for c in cells if "checker" in c]
    unknown = sum(1 for s in sizes if s is None)
    L.append(f"Facts and gaps PASS in every cell: {'yes' if facts_gaps else 'NO'}. Views bounded (never above the frozen node cap) in every cell "
             f"with a known size: {'yes' if all(s <= doc['inputs']['max_nodes'] for s in sizes if s is not None) else 'NO'}"
             f"{f'; size unknown (alert view failed) in {unknown} cell(s)' if unknown else ''}.")
    L.append("")
    fails = [(c, l) for c in cells if "checker" in c for l in c["checker"]["fail_lines"]]
    L.append("### Lost expected edges and other checker failures, each explained")
    L.append("")
    if not fails:
        L.append("None: every expected fact and hypothesis was shown at every volume and seed.")
    for c, l in fails:
        why = "the view hit the node cap (truncated)" if c["checker"]["view"].get("truncated") else "see the checker line"
        L.append(f"- {c['scenario']} {c['run_id']} {c['volume']}x seed {c['seed']} graft {'on' if c['graft'] else 'off'}: `{l}` — {why}")
    L.append("")
    diffs = [c for c in cells if "checker" in c and (c["checker"]["pass"] != c["checker_no_hubs"]["pass"]
                                                      or c["checker"]["view"].get("alert_nodes") != c["checker_no_hubs"]["view"].get("alert_nodes"))]
    L.append(f"`--no-hubs` differences (verdict or alert-view size): {len(diffs)} cell(s)" +
             (": " + "; ".join(f"{c['scenario']} {c['volume']}x s{c['seed']} hubs {c['checker']['view'].get('alert_nodes')} nodes "
                                f"{'PASS' if c['checker']['pass'] else 'FAIL'} vs no-hubs {c['checker_no_hubs']['view'].get('alert_nodes')} nodes "
                                f"{'PASS' if c['checker_no_hubs']['pass'] else 'FAIL'}" for c in diffs) if diffs else "."))
    ng = [c for c in cells if not c["graft"]]
    for c in ng:
        twin = next((t for t in cells if t["graft"] and t["run_id"] == c["run_id"] and t["volume"] == c["volume"] and t["seed"] == c["seed"]), None)
        if twin:
            L.append(f"`--no-graft` at {c['volume']}x ({c['scenario']} {c['run_id']} seed {c['seed']}): checker {'PASS' if c['checker']['pass'] else 'FAIL'} "
                     f"vs {'PASS' if twin['checker']['pass'] else 'FAIL'} with grafting; alert view {c['checker']['view'].get('alert_nodes')} vs "
                     f"{twin['checker']['view'].get('alert_nodes')} nodes; hypotheses {c['graph']['hypotheses']} vs {twin['graph']['hypotheses']}; "
                     f"grafts {c['grafts']} vs {twin['grafts']}.")
    L.append("")
    L.append("## Hypotheses by source class and band (summed over the matrix cells, grafting on)")
    L.append("")
    L.append("| volume | class | row | high | medium | low |")
    L.append("|---|---|---|---|---|---|")
    agg = defaultdict(Counter)
    for c in cells:
        if not c["graft"]:
            continue
        for cls, rows in c["hypotheses_by_class"].items():
            for row, bands in rows.items():
                for band, n in bands.items():
                    agg[(c["volume"], cls, row)][band] += n
    for (v, cls, row), bands in sorted(agg.items(), key=lambda x: (x[0][0], CLASSES.index(x[0][1]) if x[0][1] in CLASSES else 9, x[0][2])):
        L.append(f"| {v}x | {cls} | {row} | {bands.get('high', 0)} | {bands.get('medium', 0)} | {bands.get('low', 0)} |")
    L.append("")
    sig = defaultdict(list)
    for c in cells:
        if c["graft"] and c["layer2"].get("sigma_p") is not None:
            sig[c["volume"]].append(c["layer2"]["sigma_p"])
    L.append("Σp over the whole graph (mean per volume): " + ", ".join(f"{v}x {sum(x) / len(x):.3f} (n={len(x)})" for v, x in sorted(sig.items())) + ".")
    L.append("")
    L.append("## The promises (design 1.8), checked on every graph")
    L.append("")
    bad = [c for c in cells if not c["invariants"]["ok"]]
    L.append(f"Cells: {len(cells)}; cells where a promise broke: {len(bad)}.")
    for c in bad:
        L.append(f"- {c['scenario']} {c['run_id']} {c['volume']}x seed {c['seed']} graft {'on' if c['graft'] else 'off'}: {'; '.join(c['invariants']['broken'])}")
    tot = Counter()
    for c in cells:
        for k in ("shared_nodes", "cross_facts", "graft_started", "graft_started_to_role", "overlay_scenario_edges",
                  "cross_r4_on_scenario", "cross_t_observed"):
            tot[k] += c["cross"][k]
        tot["grafted_parent_also_acts"] += (c.get("counts") or {}).get("grafted_parent_also_acts_in_slice", 0)
    L.append(f"Totals: shared nodes {tot['shared_nodes']}, facts across the two worlds {tot['cross_facts']}, grafted `started` edges "
             f"{tot['graft_started']} (onto a role process: {tot['graft_started_to_role']}), edges joining an overlay node and a scenario node "
             f"{tot['overlay_scenario_edges']}, cross T2/T3 {tot['cross_t_observed']} (all through grafted parents when grafting is on); "
             f"cross R4 onto a scenario node (measured false link, not a leak) {tot['cross_r4_on_scenario']}; grafted children whose laptop "
             f"parent also acted in the slice {tot['grafted_parent_also_acts']}.")
    L.append("")
    L.append("## Graft-induced cross T2/T3: observed vs Σp (independence check; never used for the burst factor)")
    L.append("")
    L.append("| volume | graphs | observed cross T2/T3 | Σp of those edges | observed / Σp |")
    L.append("|---|---|---|---|---|")
    gt = defaultdict(lambda: [0, 0, 0.0])
    for c in cells:
        if c["graft"]:
            g = gt[c["volume"]]
            g[0] += 1
            g[1] += c["cross"]["cross_t_observed"]
            g[2] += c["cross"]["cross_t_sigma_p"]
    for v, (n, obs, sp) in sorted(gt.items()):
        L.append(f"| {v}x | {n} | {obs} | {sp:.3f} | {'-' if sp == 0 else f'{obs / sp:.2f}'} |")
    L.append("")
    L.append("## False name-only R4 links per graph (cross R4: the two worlds never met, so every one is false)")
    L.append("")
    L.append("| volume | graphs (seeds) | cross R4 total | name-only | full-path | per graph (all cross R4) | exact Poisson 95 % interval per graph (all cross R4) |")
    L.append("|---|---|---|---|---|---|---|")
    for v, p in sorted(doc["r4"]["per_volume"].items(), key=lambda x: int(x[0])):
        ci = p["rate_ci95"]
        L.append(f"| {v}x | {p['graphs']} | {p['total']} | {p['name-only']} | {p['full-path']} | {_fmt(p['rate_per_graph'])} | "
                 f"[{ci[0]:.3f}, {ci[1]:.3f}] |" if ci else f"| {v}x | 0 | - | - | - | - | - |")
    L.append("")
    L.append("## Band changes of the scenario's own hypotheses, 0x -> 1x/5x (design 1.9)")
    L.append("")
    if not doc["band_changes"]:
        L.append("None: every expected hypothesis kept its band and its process's life at every volume and seed.")
    else:
        L.append("| scenario | run | seed | volume | hypothesis | row | band 0x | band | life 0x (s) | life (s) | p 0x | p |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for b in doc["band_changes"]:
            L.append(f"| {b['scenario']} | {b['run_id']} | {b['seed']} | {b['volume']}x | {b['claim']} | {b['row']} | {b['band_0x']} | {b['band']} | "
                     f"{_fmt(b['life_0x'], 1)} | {_fmt(b['life'], 1)} | {_fmt(b['p_0x'], 4)} | {_fmt(b['p'], 4)} |")
    L.append("")
    L.append("Noise lengthens the active time of VM processes without a recorded end (their life ends at the end of the active "
             "stretch holding their last event), which can move a lifetime band and so a grade: that is the side effect the "
             "design says to report, and the table above is its measurement.")
    L.append("")
    L.append("## Runtime")
    L.append("")
    L.append(f"{len(cells)} matrix cells and {len(doc['r4'].get('extra_graphs', []))} extra R4 graphs in {summary_runtime(doc) / 60:.1f} min "
             f"(build + graph + checks). JSON: `{os.path.basename(doc['json'])}` next to the stores under recordings/scratch/overlay/.")
    L.append("")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))


def _save_json(doc, out_json):
    os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, default=str)


# -- main -----------------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Noise-overlay smoke matrix and measurements on dev runs (counts only)")
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--laptop", help="the dev laptop snapshot (default <recordings>/scratch/dev/dev-laptop.db)")
    ap.add_argument("--pool", help="pool of normal rates (default <recordings>/confidence/pool.json)")
    ap.add_argument("--runs", nargs="+", default=DEFAULT_RUNS, help="scenario[:n newest runs], e.g. s1:3 s2")
    ap.add_argument("--volumes", nargs="+", type=int, default=DEFAULT_VOLUMES)
    ap.add_argument("--seeds", nargs="+", type=int, default=DEFAULT_SEEDS)
    ap.add_argument("--r4-seeds", type=int, default=DEFAULT_R4_SEEDS, help="seeds 1..N for the false-R4 rate (>= 10 in the design)")
    ap.add_argument("--out-md", default=os.path.join(PROJECT_ROOT, "docs", "results", "j-noise-overlay-dev.md"))
    ap.add_argument("--out-json", help="default <recordings>/scratch/overlay/j-noise-overlay-dev.json")
    ap.add_argument("--label", default="vm")
    ap.add_argument("--until", help="practice mode: only runs started on or before this UTC day (YYYY-MM-DD)")
    a = ap.parse_args(argv)
    official = config.is_official()
    pool = a.pool or os.path.join(a.recordings, "confidence", "pool.json")
    if official:
        # version 2 (docs/plans/v2-prereg.md section 7): J6 on the official runs is a v1 result (made at freeze-v1);
        # v2's code does not re-run it (it would pool v1's and v2's official runs and write v1's files)
        print("  FAIL  official mode: the noise overlay (J6) is a v1 result; v2's code does not run it officially")
        return 2
    out_json = a.out_json or os.path.join(noise_overlay.out_folder(a.recordings),
                                          "j-noise-overlay-official.json" if official else "j-noise-overlay-dev.json")
    if not os.path.exists(pool):
        print(f"no pool of normal rates at {pool}")
        return 2
    skipped = []
    try:
        layer2 = Layer2.from_pool_file(pool)
        hubs = check_graph_scenario.load_hubs()
        # official mode: a scenario without a clean official run is noted and skipped, never the
        # whole matrix (review 2026-10-30); practice mode keeps part 1's refusal
        plan = plan_runs(a.recordings, a.runs, official=official, until=None if official else a.until,
                         skip_missing=official, skipped=skipped)
        if not plan:
            raise ValueError("no scenario has a clean official run")
    except (OSError, ValueError, KeyError) as e:
        print(f"cannot start: {e}")
        return 2
    laptop = a.laptop or os.path.join(a.recordings, *noise_overlay.DEFAULT_LAPTOP)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    volumes = sorted(set(a.volumes))
    doc = {"started_utc": started, "json": out_json,
           "inputs": {"runs": len(plan), "volumes": volumes, "seeds": a.seeds, "r4_seeds": a.r4_seeds,
                      "hubs": len(hubs) if hubs else 0, "pool_sha256": (layer2.pool_sha256 or "?")[:12],
                      "laptop_cutoff": None, "max_nodes": config.graph_view().max_nodes, "official": official,
                      "run_ids": [r.get("run_id") for _, r in plan], "skipped_scenarios": skipped},
           "cells": [], "r4": {"per_volume": {}, "extra_graphs": []}, "band_changes": []}
    r4_graphs = []
    t_all = time.perf_counter()
    for scenario, run in plan:
        with open(os.path.join(PROJECT_ROOT, "scenarios", scenario, "ground_truth.yaml"), encoding="utf-8") as f:
            truth = yaml.safe_load(f)
        lo, hi, _ = check_scenario.run_window(a.recordings, run)
        vm_records = check_graph_scenario.window_records(a.recordings, a.label, lo, hi)
        print(f"{scenario.upper()} {run.get('run_id')}: {len(vm_records)} VM records in the window")
        for volume in volumes:
            for seed in (a.seeds[:1] if volume == 0 else a.seeds):      # 0x does not depend on the seed
                try:
                    cell = evaluate(a.recordings, scenario, run, volume, seed, True, laptop, layer2, hubs, truth, vm_records, pool=pool)
                except (ValueError, FileNotFoundError, RuntimeError) as e:
                    print(f"  {volume}x seed {seed}: cannot build ({e})")
                    doc["stopped"] = f"{scenario.upper()} {run.get('run_id')} {volume}x seed {seed}: {e}"
                    _save_json(doc, out_json)                    # keep what was measured (review 7c)
                    return 2
                doc["inputs"]["laptop_cutoff"] = overlay.read_meta(os.path.join(noise_overlay.out_folder(a.recordings), cell["store"])).get("laptop_cutoff_day_utc")
                doc["cells"].append(cell)
                if volume > 0:
                    r4_graphs.append((volume, cell["cross"]["cross_r4"]))
                print(f"  {volume}x seed {seed}: {cell['overlay_rows']} overlay rows, checker {'PASS' if cell['checker']['pass'] else 'FAIL'}, "
                      f"{cell['graph']['hypotheses']} hypotheses, sigma_p {cell['layer2']['sigma_p']:.3f}, promises "
                      f"{'kept' if cell['invariants']['ok'] else 'BROKEN: ' + '; '.join(cell['invariants']['broken'])} ({cell['seconds']['total']} s)")
        top = max(volumes)
        if top > 0:
            cell = evaluate(a.recordings, scenario, run, top, a.seeds[0], False, laptop, layer2, hubs, truth, vm_records, pool=pool)
            doc["cells"].append(cell)
            print(f"  {top}x seed {a.seeds[0]} no-graft: checker {'PASS' if cell['checker']['pass'] else 'FAIL'}, cross T {cell['cross']['cross_t_observed']}, "
                  f"promises {'kept' if cell['invariants']['ok'] else 'BROKEN: ' + '; '.join(cell['invariants']['broken'])}")
        # the false-R4 rate needs >= 10 seeds: the extra graphs are built without the checker
        for volume in volumes:
            if volume == 0:
                continue
            for seed in range(1, a.r4_seeds + 1):
                if seed in a.seeds:
                    continue
                t0 = time.perf_counter()
                cell = evaluate(a.recordings, scenario, run, volume, seed, True, laptop, layer2, hubs, truth, vm_records, check=False, pool=pool)
                r4_graphs.append((volume, cell["cross"]["cross_r4"]))
                doc["r4"]["extra_graphs"].append({"scenario": scenario.upper(), "run_id": run.get("run_id"), "volume": volume, "seed": seed,
                                                  "cross_r4": cell["cross"]["cross_r4"], "invariants": cell["invariants"],
                                                  "seconds": round(time.perf_counter() - t0, 2)})
    doc["r4"].update(r4_summary(r4_graphs))
    doc["band_changes"] = band_changes(doc["cells"])
    doc["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _save_json(doc, out_json)
    write_markdown(doc, a.out_md)
    broken = [c for c in doc["cells"] if not c["invariants"]["ok"]] + [g for g in doc["r4"]["extra_graphs"] if not g["invariants"]["ok"]]
    print(f"\n{len(doc['cells'])} cells, {len(doc['r4']['extra_graphs'])} extra R4 graphs, {len(doc['band_changes'])} band change(s), "
          f"promises broken in {len(broken)} graph(s), {(time.perf_counter() - t_all) / 60:.1f} min")
    for v, p in sorted(doc["r4"]["per_volume"].items(), key=lambda x: int(x[0])):
        print(f"  false R4 per graph at {v}x: {p['rate_per_graph']:.3f} [{p['rate_ci95'][0]:.3f}, {p['rate_ci95'][1]:.3f}] over {p['graphs']} graphs")
    print(f"report: {a.out_md}\njson: {out_json}")
    return 0 if not broken else 1


if __name__ == "__main__":
    raise SystemExit(main())
