"""Burst-factor calibration on the laptop DEV snapshot (package J part 1; the pre-registered
sideband control of docs/plans/package-j-design.md section 2; maths in engine/calibration.py).

    python tools/burst_factor.py --db recordings/scratch/dev/dev-laptop.db --pool recordings/confidence/pool.json

Refuses (fairness, enforced twice): a store that is not a dev snapshot (no `snapshot` table), a
snapshot whose cutoff day is after config/frozen.yaml data.dev_cutoff_day_utc, any event after
that day, and a pool file whose SHA256 is not the frozen dev pool's. Prints COUNTS ONLY (privacy
rule 7), writes the full result as JSON under recordings/confidence/j/ (git-ignored) and a
markdown summary (counts, rates, ratios, intervals, the decision) to docs/results/.
It does not write config/frozen.yaml: the main session records the decision there.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from engine import calibration as K  # noqa: E402
from engine import config as frozen_config  # noqa: E402
from engine import confidence as C  # noqa: E402

BOOTSTRAP_B = K.BOOTSTRAP_B
DEFAULT_OUT = os.path.join(PROJECT_ROOT, "recordings", "confidence", "j")
DEFAULT_SUMMARY = os.path.join(PROJECT_ROOT, "docs", "results", "j-burst-factor-dev.md")


def store_cutoff(db) -> str:
    """The snapshot's cutoff day (tools/build_dev_snapshot.py writes it); ValueError if the store
    is not a dev snapshot."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'snapshot'").fetchone():
        raise ValueError("this store has no `snapshot` table: not a dev snapshot (tools/build_dev_snapshot.py)")
    row = db.execute("SELECT value FROM snapshot WHERE key = 'cutoff_day_utc'").fetchone()
    if not row or not row[0]:
        raise ValueError("the snapshot table has no cutoff_day_utc")
    return str(row[0])


def check_dev_store(db, frozen_cutoff: str) -> str:
    """Refuse anything after the frozen dev cutoff: by the snapshot's own cutoff and by the data."""
    cutoff = store_cutoff(db)
    if cutoff > frozen_cutoff:
        raise ValueError(f"snapshot cutoff {cutoff} is after the frozen dev cutoff {frozen_cutoff}: test data, refused")
    end = (datetime.strptime(frozen_cutoff, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    last = db.execute("SELECT MAX(time) FROM events").fetchone()[0]
    if last is not None and str(last)[:10] >= end:
        raise ValueError(f"the store holds events on or after {end} (after the frozen dev cutoff): refused")
    return cutoff


def file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, capture_output=True, text=True,
                              timeout=10).stdout.strip() or None
    except Exception:          # noqa: BLE001 - the commit is a convenience in the record, never a reason to fail
        return None


def _print_counts(results: dict, decision: dict):
    for row, r in results["rows"].items():
        pop = r["population"]
        print(f"{row}: {pop['processes']} processes, {pop['causes']} causes; by band: "
              + ", ".join(f"{b} {v['processes']}/{v['causes']}" for b, v in pop["bands"].items()))
        for key, off in r["offsets"].items():
            for b, st in off["bands"].items():
                pp, pc = st["per_process"], st["per_cause"]
                print(f"  s={key:>3} {b:7s} proc {st['processes']:4d} causes {st['controlled_causes']:6d} hits {st['control_hits']:5d} "
                      f"| per process o {pp['o']:.4f} p {pp['p']:.4f} real {pp['real']:.4f} beta {pp['beta']:.2f} "
                      f"U95 {pp['beta_upper95']:.2f} | per cause o {pc['o']:.4f} p {pc['p']:.4f} beta {pc['beta']:.2f} "
                      f"CP [{pc['beta_cp'][0]:.2f}, {pc['beta_cp'][1]:.2f}]"
                      + ("  decidable" if st["decidable"] else ""))
    print(f"DECISION: beta* = {decision['beta_star']}, max U_r = {decision['max_upper']}, stop = {decision['stop']}")
    print(f"  {decision['reason']}")
    for row, d in decision["rows"].items():
        print(f"  {row}: decides {d['decides']}{' (one sideband only)' if d['partial'] else ''}, U_r {d['upper']}, "
              + ", ".join(f"{k} <- {v['band']}" for k, v in d["offsets"].items()))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Burst factor: the pre-registered sideband control on the dev laptop week (counts only).")
    ap.add_argument("--db", required=True, help="the dev laptop snapshot (opened read-only)")
    ap.add_argument("--pool", required=True, help="the frozen dev pool file (SHA256 checked)")
    ap.add_argument("--out-dir", default=DEFAULT_OUT, help="where the JSON result goes (git-ignored)")
    ap.add_argument("--summary", default=DEFAULT_SUMMARY, help="the markdown summary (counts and rates only)")
    ap.add_argument("--config", default=C.FROZEN)
    ap.add_argument("--host", help="the machine, when the store holds several")
    a = ap.parse_args(argv)

    frozen_cutoff = str(frozen_config.load(a.config)["data"]["dev_cutoff_day_utc"])
    cfg = C.load_config(a.config)
    try:
        db = C._open_ro(a.db)
        cutoff = check_dev_store(db, frozen_cutoff)
    except Exception as e:                      # noqa: BLE001 - every refusal reason is printed, nothing runs
        print(f"Refusing: {e}")
        return 2
    sha = file_sha256(a.pool)
    if sha != K.FROZEN_POOL_SHA256 or (cfg.pool_sha256 and cfg.pool_sha256.lower() != sha):
        print(f"Refusing: pool file SHA256 {sha[:12]}... is not the frozen dev pool {K.FROZEN_POOL_SHA256[:12]}... "
              "(design section 2)")
        return 2
    hs = C.hosts(db)
    if a.host is None and len(hs) > 1:
        print(f"Refusing: the store holds {len(hs)} machines; pass --host")
        return 2
    if a.host is not None and a.host not in hs:
        print("Refusing: --host names no machine in the store")
        return 2
    host = a.host if a.host is not None else (hs[0] if hs else None)

    pool = C.Pool.load(a.pool, expect_sha256=sha)
    configs = C.sysmon_configs(db, host)[-1:]
    if pool.meta.get("sysmon_config") is not None and sorted(pool.meta["sysmon_config"]) != sorted(configs):
        print("WARNING: Sysmon config differs between the pool and this store (file filters set file-creation rates)")
    act = C.load_activity(db, cfg, host)
    print(f"activity: {len(act.procs)} processes, {act.active.total / 3600:.1f} active hours, "
          + ", ".join(f"{k} {sum(len(v) for v in act.events[k].values())}" for k in C.KINDS)
          + f"; {dict(sorted(act.counts.items()))}")
    print(f"sideband analysis: offsets {[K.offset_key(s) for s in K.ALL_OFFSETS]}, bootstrap B = {BOOTSTRAP_B} ...")
    results = K.sideband_analysis(act, pool, cfg, B=BOOTSTRAP_B)
    decision = K.choose_burst_factor(results)
    now = datetime.now(timezone.utc)
    results["meta"].update({
        "created_utc": now.isoformat(timespec="seconds"), "store": os.path.basename(a.db),
        "store_cutoff_day_utc": cutoff, "frozen_dev_cutoff_day_utc": frozen_cutoff, "pool_sha256": sha,
        "pool_processes": pool.meta.get("processes"), "pool_active_hours": pool.meta.get("active_hours"),
        "config_burst_factor_at_run": cfg.burst_factor, "analysis_commit": _git_commit(),
        "activity_counts": dict(sorted(act.counts.items()))})
    results["decision"] = decision

    os.makedirs(a.out_dir, exist_ok=True)
    out_path = os.path.join(a.out_dir, f"burst-factor-{now.strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    os.makedirs(os.path.dirname(os.path.abspath(a.summary)), exist_ok=True)
    with open(a.summary, "w", encoding="utf-8") as f:
        f.write(K.summary_markdown(results, decision))
    _print_counts(results, decision)
    print(f"written: {out_path} and {a.summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
