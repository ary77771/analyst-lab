"""Package J part 2: the pre-registered experiments of DESIGN 8, one command per question
(docs/plans/package-j2-prereg.md fixes every definition BEFORE any test data is scored).

    python tools/experiments.py detection    --label practice [--until 2026-10-24] [--last 3]
    python tools/experiments.py story        --label practice
    python tools/experiments.py blind        --label official
    python tools/experiments.py false-alerts --label practice [--laptop <db>] [--alerts <db> ...]
    python tools/experiments.py a16          --label practice
    python tools/experiments.py overlay      --label practice [--runs s1:1 ...] [--volumes 0 1 5] [--seeds 1 2 3]
    python tools/experiments.py calibration  --label practice        (reads the overlay JSON)
    python tools/experiments.py performance  --label practice [--big <recording.jsonl>]
    python tools/experiments.py all          --label official

Questions (J1-J7): J1 detection rate + time to detect (tools/check_alerts.py per run); J2 story
accuracy = graph vs answer sheet (tools/check_graph_scenario.py per run: edge precision / recall,
fact vs hypothesis correctness); J3 the blind scenarios B1/B2 with the same metrics; J4 false alerts
per active hour on normal use (tools/false_alarms.py); J5 A16 agreement (engine.confidence.a16_check
+ the +-12 s sideband of engine.calibration) and calibration = share of correct hypotheses per band on
the noise overlay; J6 the noise overlay matrix (tools/overlay_experiment.py); J7 performance.

Labels:
  practice  DEV data: clean practice VM runs (never a run of an official series, never a blind
            scenario), the laptop DEV snapshot (recordings/scratch/dev/dev-laptop.db, cutoff <= the
            frozen data.dev_cutoff_day_utc). Refused while ANALYSTLAB_OFFICIAL=1 is set.
  official  TEST data: the runs of the official series (recordings/series/*.json, label official),
            the blind runs' answer sheets under recordings/blind/<id>/<run id>/, the laptop TEST
            snapshot (recordings/scratch/test/test-laptop.db, tools/build_test_snapshot.py: days after
            the cutoff) and friends' statistics files. Needs ANALYSTLAB_OFFICIAL=1 AND
            engine.config.verify_official() == [] (refused otherwise: fair-test rule 2).

Outputs: docs/results/<version>/<question>-<label>[-<of>runs].md (aggregate numbers, rule ids, bands and
the lab's own scenario program names only: privacy rule 7; never a laptop path, name, command line or
address) and the full numbers as JSON under <project>/recordings/experiments/<version>/<label>[-<of>runs]/
(git-ignored). <version> = engine/evaluation.CURRENT (v3). Nothing here changes a detector, a grade or a
frozen value: it only measures.

Evaluations (engine/evaluation.py; docs/plans/v2-prereg.md, v3-prereg.md): this code is v3. Earlier
results are never written to again. Official mode scores the runs of ONE evaluation: `--of v3`
(default) = the series stamped freeze-v3 (blind round 3, B10-B17; v3 has no new own scenario), the
laptop days of data.v3_test_* (test-laptop-v3.db); `--of v2` / `--of v1` = that evaluation's official
runs and test week re-scored with this code (the regression; outputs end in -v2runs / -v1runs). In
official mode only detection, story, blind and false-alerts are run (J5-J7 are v1 results, not re-run).
Practice mode may score the dummy blind scenario B9 (`blind --runs b9`).
"""

import argparse
import glob
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
import check_alerts  # noqa: E402
import check_graph_scenario  # noqa: E402
import check_scenario  # noqa: E402
import false_alarms  # noqa: E402
import noise_overlay  # noqa: E402
import overlay_experiment  # noqa: E402
from engine import calibration as K  # noqa: E402
from engine import config, detect, evaluation, score  # noqa: E402
from engine import confidence as C  # noqa: E402
from engine.alerts import AlertStore  # noqa: E402
from engine.graph import Layer2, build_graph  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402
from engine.replay import parse_time, read_recordings, replay  # noqa: E402
from engine.store import EventStore  # noqa: E402

QUESTIONS = ("detection", "story", "blind", "false-alerts", "a16", "overlay", "calibration", "performance")
SCENARIOS = ("s1", "s2", "s2j", "s3", "s4", "s5", "c1")      # v1's own scenarios (answer sheets in scenarios/; J6/J7 too)
BLIND = ("b1", "b2")                                          # v1's blind scenarios (sheets only under recordings/blind/)
OWN = {"v1": SCENARIOS, "v2": ("s6",), "v3": (), "v4": ()}       # v3 adds no own scenario (its own runs: --of v1/v2)                        # each evaluation's own scenarios with official runs
BLIND_IDS = {"v1": BLIND, "v2": ("b3", "b4", "b5"), "v3": tuple(f"b{i}" for i in range(10, 18)), "v4": ()}   # round 3: B10-B17           # each evaluation's blind scenarios
DUMMY_BLIND = ("b9",)                                         # the dummy blind scenario: practice only, never official
OFFICIAL_QUESTIONS = ("detection", "story", "blind", "false-alerts")  # what official mode runs (J5-J7 stay v1 results)
FALSE_CLASSES = ("cross", "cross/graft", "cross-r4")          # overlay classes that are false by construction (J5b)
BANDS = ("high", "medium", "low")
MIN_BAND_N = 10                                               # J5b: no share is claimed below this many judged links
AGREE_LO, AGREE_HI = 0.5, 2.0                                 # J5a: "agrees within a factor of 2"
PREREG = evaluation.PREREG[evaluation.CURRENT]


def is_blind_id(s):
    """B1 ... B99, exactly as tools/run_blind.py's BLIND_ID (v3: round 3 uses B10 onwards)."""
    import re
    return bool(re.fullmatch(r"[Bb][1-9][0-9]?", str(s)))


# v3 pre-registration section 2: the round-3 answer sheets' SHA-256, fixed before any run. A run whose
# opened sheet differs is NOT CHECKED (the sheet is not the one registered).
SHEET_SHA256 = {
    "B10": "FBBD693704F9F8BA4B3D4D89D19D75095800178E82AE337F7383C3115507CB04",
    "B11": "D5DE0EF55713C960522B475280FA1CBF73F5839986D7E702108F97D1DE119273",
    "B12": "030A0DEDFB2ADBEAC41211D7B287051358E27195056681ED99EB91A863704E0D",
    "B13": "6C8C2971D194C04D2BA21456793D31A620AED89E7A763B878B23AE234F816A52",
    "B14": "BBDE59A70F5E39671474110F3CEA3504A243CC0D0866B2853A3AADDE3D0CEDB5",
    "B15": "2416507457531638AA241A9D47B9A090A18853C3DD7C3E7F33727AE9DF7911E9",
    "B16": "E62D6842153152A194E6E47F4B0ADB951150BD4ADFDBAB28FF57D99B31517C59",
    "B17": "C558C4CBC1767E284903AB6ECABB30D2AC8A64F4DBB2B10868B6E56DA4C207A1",
}


def sheet_sha256(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest().upper()


# -- helpers --------------------------------------------------------------------------------------------
def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ro(path):
    return sqlite3.connect(f"file:{os.path.abspath(path).replace(os.sep, '/')}?mode=ro", uri=True)


def share(k, n):
    """(share, lo, hi): a proportion with its exact two-sided 95 % Clopper-Pearson interval
    (engine.calibration.clopper_pearson); None when n = 0."""
    if not n:
        return None
    lo, hi = K.clopper_pearson(int(k), int(n))
    return {"share": k / n, "lo": lo, "hi": hi, "k": int(k), "n": int(n)}


def pct(s, digits=0):
    if s is None:
        return "-"
    return f"{100 * s['share']:.{digits}f} % ({s['k']}/{s['n']}; 95 % [{100 * s['lo']:.0f}, {100 * s['hi']:.0f}] %)"


def fmt(x, digits=3):
    if x is None:
        return "-"
    return f"{x:.{digits}f}" if isinstance(x, float) else str(x)


def median(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def load_sheet(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def laptop_snapshot_kind(db):
    """('dev' | 'test', meta) from a snapshot's own table; ValueError for any other store."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'snapshot'").fetchone():
        raise ValueError("not a snapshot built by tools/build_dev_snapshot.py or tools/build_test_snapshot.py (no `snapshot` table)")
    meta = dict(db.execute("SELECT key, value FROM snapshot"))
    return (meta.get("kind") or "dev"), meta


# -- the data of one label ---------------------------------------------------------------------------
class RunItem:
    def __init__(self, scenario, run, sheet, truth, status="ok"):
        self.scenario, self.run, self.sheet, self.truth, self.status = scenario, run, sheet, truth, status

    @property
    def run_id(self):
        return self.run.get("run_id") or str(self.run.get("start"))

    @property
    def ok(self):
        return self.status == "ok"


class Lab:
    """Everything one label may read, resolved once; refuses the wrong data for the mode."""

    def __init__(self, label, recordings=None, pool=None, out_dir=None, results_dir=None, vm_label="vm", until=None, last=None,
                 of=None):
        if label not in ("practice", "official"):
            raise ValueError("label must be practice or official")
        self.label, self.official = label, label == "official"
        self.of = of or evaluation.CURRENT                  # whose official runs: v2's own, or v1's re-scored (regression)
        if self.of not in evaluation.TAGS:
            raise ValueError(f"--of must be one of {', '.join(evaluation.TAGS)}")
        if self.of != evaluation.CURRENT and not self.official:
            raise ValueError(f"--of {self.of}: another evaluation's runs are official data (official mode only)")
        self.suffix = "" if self.of == evaluation.CURRENT else f"-{self.of}runs"
        self.recordings = recordings or os.path.join(PROJECT_ROOT, "recordings")
        self.pool = pool or os.path.join(self.recordings, "confidence", "pool.json")
        # v2's outputs live apart from v1's (docs/results/j2-*-official.md are never written again)
        self.out_dir = out_dir or os.path.join(PROJECT_ROOT, "recordings", "experiments", evaluation.CURRENT, label + self.suffix)
        self.results_dir = results_dir or os.path.join(PROJECT_ROOT, "docs", "results", evaluation.CURRENT)
        self.vm_label, self.until, self.last = vm_label, until, last
        self._stream = self._runs = self._layer2 = self._hubs = self._rules = self._baseline = None

    # -- gate --
    def problems(self):
        """Why this label may not run now: [] = go."""
        if self.official:
            if not config.is_official():
                return [f"--label official needs {config.OFFICIAL_ENV}=1 (fair-test rule 2: test data is scored only in official mode)"]
            # the frozen code only (review 2026-11-13: scoring test data, even v1's, with unfrozen code is tuning on it)
            return [f"official mode: {p}" for p in evaluation.code_problems() + config.verify_official(pool=self.pool)]
        if config.is_official():
            return [f"{config.OFFICIAL_ENV}=1 is set but --label practice was given (a contradiction, refused)"]
        return []

    # -- VM runs --
    def all_runs(self):
        if self._runs is None:
            self._runs = check_scenario.all_runs(self.recordings)
        return self._runs

    def official_ids(self):
        return noise_overlay.official_run_ids(self.recordings)

    def stream(self):
        """The VM label's whole stream, re-tagged like every checker (read once, cut per run).
        Why this is no leak in practice mode: re-tagging needs the whole stream (a window alone
        loses process trees started before it, as every checker says), but only the windows of the
        SELECTED runs are ever scored, and select_runs never selects an official run or anything
        recorded after the first official series began; the rest of the stream is read and dropped."""
        if self._stream is None:
            self._stream = read_recordings(recording_files(os.path.join(self.recordings, self.vm_label)), retag=True)
        return self._stream

    def _status(self, run):
        if run.get("exit_code") != 0:
            return f"run failed (exit code {run.get('exit_code')})"
        if check_scenario.run_window(self.recordings, run, self.all_runs()).overlaps_previous:
            return "overlaps the previous run"
        return "ok"

    def _item(self, sc, run, blind, status):
        if blind:
            sheet = os.path.join(self.recordings, "blind", sc.upper(), run.get("run_id") or "", "ground_truth.yaml")
            if not os.path.exists(sheet):
                return RunItem(sc, run, sheet, None, "answer sheet not opened for this run")
            want = SHEET_SHA256.get(sc.upper())
            if want and sheet_sha256(sheet) != want:
                return RunItem(sc, run, sheet, None, "answer sheet differs from the registered SHA-256 (v3 prereg 2): NOT CHECKED")
        else:
            sheet = check_scenario.sheet_path(sc)
        try:
            truth = load_sheet(sheet)
        except (OSError, ValueError, yaml.YAMLError) as e:    # a malformed blind sheet is that run's status, not J3's end
            return RunItem(sc, run, sheet, None, f"answer sheet unreadable: {type(e).__name__}")
        return RunItem(sc, run, sheet, truth, status)

    def window(self, run):
        lo, hi, _ = check_scenario.run_window(self.recordings, run, self.all_runs())
        return [r for r in self.stream() if r.get("time") and lo <= parse_time(r["time"]) <= hi], lo, hi

    def select_runs(self, scenarios=None, blind=False):
        """[RunItem] in start order. practice: clean practice runs of the lab's scenarios (blind ids
        never); official: every run of the official series (a failed or overlapping run is listed
        with its status and not scored). Blind runs need their opened sheet under recordings/blind/."""
        if blind and not self.official and not (scenarios and all(str(s).lower() in DUMMY_BLIND for s in scenarios)):
            raise ValueError("blind scenarios are test data: only --label official (after their official runs); "
                             f"practice mode scores only the dummy {', '.join(DUMMY_BLIND).upper()} (--runs {' '.join(DUMMY_BLIND)})")
        if self.official and (self.last or scenarios):
            raise ValueError("official mode scores every run of the official series: --last and --runs are refused (no cherry-picking)")
        if blind:
            default = BLIND_IDS[self.of] if self.official else DUMMY_BLIND
        else:
            default = OWN[self.of] if self.official else OWN["v1"] + OWN["v2"]
        wanted = [s.lower() for s in (scenarios or default)]
        if not blind and any(is_blind_id(s) for s in wanted):
            raise ValueError("blind scenarios are evaluated by the `blind` command only")
        if self.official:
            return self._official_items(wanted, blind)
        periods = noise_overlay.official_periods(self.recordings)
        ids = self.official_ids()
        items = []
        for run in self.all_runs():
            sc = str(run.get("scenario", "")).lower()
            if sc not in wanted or run.get("run_id") in ids:
                continue
            if not noise_overlay.is_practice_run(self.recordings, run, ids=ids, periods=periods):
                continue                                      # recorded in an official period: never practice data
            if self.until and str(run.get("start", ""))[:10] > self.until:
                continue
            status = self._status(run)
            if status != "ok":
                continue                                      # practice: only clean runs are worth a line
            items.append(self._item(sc, run, blind, status))
        if self.last:
            by = defaultdict(list)
            for it in items:
                by[it.scenario].append(it)
            items = [it for s in by for it in by[s][-self.last:]]
            items.sort(key=lambda it: parse_time(it.run["start"]))
        return items

    def _official_items(self, wanted, blind):
        """Every entry of every official series (in series order), plus official runs known only by
        their own summary: an entry without a recorded run (run_id None, a crash before the summary,
        exit 2/3) is listed as "could not run", never dropped."""
        by_id = {r.get("run_id"): r for r in self.all_runs() if r.get("run_id")}
        summary_ids = noise_overlay.official_summary_ids(self.recordings, self.of)        # once, not per run
        items, seen = [], set()
        for s in noise_overlay.official_series(self.recordings, self.of):     # this evaluation's series only
            for e in s["runs"]:
                sc = str(e.get("scenario", "")).lower()
                if sc not in wanted:
                    continue
                rid = e.get("run_id")
                run = by_id.get(rid)
                if run is None:
                    stub = {"run_id": rid, "scenario": sc.upper(), "start": s.get("started"), "exit_code": e.get("exit_code")}
                    items.append(RunItem(sc, stub, None, None, f"could not run (series {s['series']} #{e.get('n')}: "
                                                                f"{e.get('result') or 'no result'}, exit code {e.get('exit_code')}, no run record)"))
                    continue
                seen.add(rid)
                if s["version"] != "v1" and e.get("exit_code") not in (0, 1):
                    # v2 pre-registration section 6: the program RAN (its run record exists) but the runner's VM
                    # step failed afterwards (flush barrier, shutdown, an error): listed, never scored, never repeated
                    items.append(RunItem(sc, run, None, None, f"VM step failed after the program ran (series {s['series']} "
                                                              f"#{e.get('n')}: runner exit code {e.get('exit_code')}): not scored"))
                    continue
                items.append(self._item(sc, run, blind, self._status(run)))
        for run in self.all_runs():                           # official by its own summary (run_blind.py --label official)
            sc = str(run.get("scenario", "")).lower()
            if sc in wanted and run.get("run_id") in summary_ids and run.get("run_id") not in seen:
                code = self._summary_exit(run["run_id"])
                if self.of != "v1" and code not in (0, 1):     # the same rule as for series entries (review 2026-11-13)
                    items.append(RunItem(sc, run, None, None, f"VM step failed after the program ran (its own summary: runner "
                                                              f"exit code {code}): not scored"))
                    continue
                items.append(self._item(sc, run, blind, self._status(run)))
        return items

    def _summary_exit(self, run_id):
        """The runner's exit code from a run's own summary (recordings/scenario_runs/<run id>.json), or None."""
        try:
            with open(os.path.join(self.recordings, "scenario_runs", f"{run_id}.json"), encoding="utf-8") as f:
                return json.load(f).get("exit_code")
        except (OSError, ValueError):
            return None

    # -- laptop --
    def laptop_db(self, path=None):
        """The laptop snapshot of this label, checked by its own table: dev (cutoff <= frozen) for
        practice, test (from_day > frozen cutoff) for official. Never the other one."""
        data = config.load()["data"]
        cutoff = data["dev_cutoff_day_utc"]
        # v1's test week (re-scored by v2's code: --of v1), or v2's own test days (after the v2 freeze)
        test_name = "test-laptop.db" if self.of == "v1" else f"test-laptop-{self.of}.db"
        path = path or (os.path.join(self.recordings, "scratch", "test", test_name) if self.official
                        else os.path.join(self.recordings, *noise_overlay.DEFAULT_LAPTOP))
        if not os.path.exists(path):
            raise FileNotFoundError(f"no laptop snapshot at {path} (tools/build_{'test' if self.official else 'dev'}_snapshot.py)")
        db = ro(path)
        try:
            kind, meta = laptop_snapshot_kind(db)
            if self.official:
                if kind != "test" or not meta.get("from_day_utc") or meta["from_day_utc"] <= cutoff:
                    raise ValueError(f"{os.path.basename(path)} is not a TEST snapshot starting after the dev cutoff {cutoff}")
                # v2 and later: each evaluation's own laptop test days, exactly as frozen (data.<v>_test_from/to_day_utc)
                v_from, v_to = data.get(f"{self.of}_test_from_day_utc"), data.get(f"{self.of}_test_to_day_utc")
                if self.of != "v1" and (not v_from or not v_to or meta["from_day_utc"] != str(v_from)
                                        or str(meta.get("cutoff_day_utc")) != str(v_to)):
                    raise ValueError(f"{os.path.basename(path)} holds {meta['from_day_utc']} .. {meta.get('cutoff_day_utc')}: {self.of}'s laptop "
                                     f"test days are exactly the frozen data.{self.of}_test_from_day_utc .. {self.of}_test_to_day_utc "
                                     f"({v_from or 'not chosen'} .. {v_to or 'not chosen'})")
                first = db.execute("SELECT MIN(time) FROM events").fetchone()[0]
                if first is not None and str(first)[:10] < meta["from_day_utc"]:
                    raise ValueError(f"{os.path.basename(path)} holds events before its first test day")
            else:
                if kind != "dev":
                    raise ValueError(f"{os.path.basename(path)} is a {kind} snapshot: practice mode reads the DEV snapshot only")
                if str(meta.get("cutoff_day_utc", "")) > cutoff:
                    raise ValueError(f"{os.path.basename(path)} cutoff {meta.get('cutoff_day_utc')} is after the frozen dev cutoff {cutoff}")
                last = db.execute("SELECT MAX(time) FROM events").fetchone()[0]
                if last is not None and str(last)[:10] > cutoff:
                    raise ValueError(f"{os.path.basename(path)} holds events after the dev cutoff {cutoff}: refused")
        finally:
            db.close()
        return path

    def host_day_files(self):
        """The laptop's raw day files of this label's side of the split (J7's large recordings)."""
        import build_dev_snapshot as dev
        cutoff = config.load()["data"]["dev_cutoff_day_utc"]
        out = []
        for path in recording_files(os.path.join(self.recordings, "host")):
            m = dev.DAY.search(os.path.basename(path))
            if m and ((m.group(1) > cutoff) == self.official):
                out.append(path)
        return out

    # -- engine pieces --
    def layer2(self):
        if self._layer2 is None:
            self._layer2 = Layer2.from_pool_file(self.pool)
        return self._layer2

    def hubs(self):
        if self._hubs is None:
            self._hubs = check_graph_scenario.load_hubs()
        return self._hubs

    def rules(self):
        if self._rules is None:
            self._rules = score.load_rules()
        return self._rules

    def baseline(self):
        if self._baseline is None:
            self._baseline = score.load_baseline()
        return self._baseline

    # -- outputs --
    def write(self, name, doc, md_lines):
        os.makedirs(self.out_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
        js = os.path.join(self.out_dir, f"{name}.json")
        md = os.path.join(self.results_dir, f"{name}-{self.label}{self.suffix}.md")
        doc = dict(doc, label=self.label, finished_utc=utc_now(), prereg=PREREG, json=js, of=self.of,
                   code=evaluation.code_state())      # which code made it (tools/compare_v1_v2.py checks it)
        with open(js, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, default=str)
        with open(md, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(md_lines) + "\n")
        return js, md

    def header(self, title, what):
        runs = f", {self.of}'s official runs re-scored with {evaluation.CURRENT}'s code" if self.suffix else ""
        return [f"# Version {evaluation.CURRENT[1:]} evaluation: {title} ({self.label}{runs})", "",
                f"*Made {utc_now()} by `tools/experiments.py` ({evaluation.CURRENT} code) on {'TEST' if self.official else 'DEV'} data: {what}. "
                f"Pre-registered in `{PREREG}`. Aggregate numbers, rule ids, bands and the lab's own scenario program "
                f"names only (privacy rule 7). Nothing was tuned on these numbers.*", ""]


def fresh_store(tmp, records):
    db = os.path.join(tmp, "run.db")
    st = EventStore(db)
    st.insert(records)
    st.close()
    return db


def run_line(it):
    return f"{it.scenario.upper()} {it.run_id} ({str(it.run.get('start') or '')[:16]}Z)"


def scored(items, fn, say=print):
    """fn(item) for every scorable item; a run whose scoring raises (an odd blind sheet, a missing
    field) gets that recorded as its status and the others go on (prereg section 3)."""
    rows = []
    for it in items:
        if not it.ok:
            say(f"  {run_line(it)}: {it.status}")
            continue
        try:
            rows.append(fn(it))
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            it.status = f"could not score: {type(e).__name__}: {str(e)[:80]}"
            say(f"  {run_line(it)}: {it.status}")
    return rows


# -- J1: detection ------------------------------------------------------------------------------------
def detection_of(lab, it):
    """One run: tools/check_alerts.py's verdict, time to detect per expected alert, other alerts."""
    records, lo, hi = lab.window(it.run)
    truth = it.truth
    server = check_scenario.run_server(it.run)
    steps = {}
    with tempfile.TemporaryDirectory() as tmp:
        con = detect.open_store(fresh_store(tmp, records))
        try:
            errors = []
            alerts = score.score(con, lab.rules(), lab.baseline(), errors=errors)
            lines = []
            verdict, found, missing, other = check_alerts.check(
                truth, alerts, con, say=lines.append, records=records, server=server, detail=steps,
                follow=check_alerts.incident_view(con, alerts, say=lines.append))     # v4 F1: the incident column
        finally:
            con.close()
    # t0 = the first program's recorded start (event 1 UtcTime), anchored like check_scenario does
    chk = check_scenario.Checker(truth, records, server)
    anchored = chk.anchor()
    first = next(iter(truth.get("programs") or {}), None)
    t0 = chk.start_of.get(first, (None, None))[1] if anchored else None
    ttd = []
    for e, hits in found:
        a = min(hits, key=lambda a: a.time)
        # None when the first program could not be anchored: reported as "not anchored", never a number
        secs = (parse_time(a.time) - t0).total_seconds() if t0 is not None else None
        ttd.append({"rule_id": e["rule_id"], "level": e["level"], "involves": e["involves"], "seconds": secs, "alerts": len(hits)})
    return {"scenario": it.scenario.upper(), "run_id": it.run_id, "start": it.run.get("start"), "records": len(records),
            "verdict": "NOT CHECKED" if errors else verdict, "errors": len(errors), "anchored": bool(anchored),
            "expected": len(found) + len(missing), "found": len(found), "missed": [f"{e['rule_id']}[{e['level']}]" for e, _ in missing],
            "time_to_detect": ttd, "other_alerts": len(other),
            "other_by_rule": dict(Counter(f"{a.rule_id}[{a.level}]" for a in other)), "lines": lines,
            **({"steps": steps} if steps else {})}          # blind round 2: suspicious steps flagged (check_alerts.check_steps)


def summarize_detection(rows):
    per = {}
    for sc in sorted({r["scenario"] for r in rows}):
        mine = [r for r in rows if r["scenario"] == sc]
        judged = [r for r in mine if r["verdict"] in ("DETECTED", "MISSED")]
        detected = [r for r in judged if r["verdict"] == "DETECTED"]
        all_secs = [t["seconds"] for r in detected for t in r["time_to_detect"]]
        secs = [s for s in all_secs if s is not None]           # a run whose first program was not anchored has no number
        per[sc] = {"runs": len(mine), "judged": len(judged), "detected": len(detected),
                   "none_expected": sum(r["verdict"] == "NONE EXPECTED" for r in mine),
                   "not_checked": sum(r["verdict"] == "NOT CHECKED" for r in mine),
                   "rate": share(len(detected), len(judged)),
                   "ttd_seconds": {"n": len(secs), "not_anchored": len(all_secs) - len(secs),
                                   "min": min(secs) if secs else None, "median": median(secs), "max": max(secs) if secs else None},
                   "other_alerts_per_run": sum(r["other_alerts"] for r in mine) / len(mine) if mine else None,
                   "other_by_rule": dict(sum((Counter(r["other_by_rule"]) for r in mine), Counter()))}
        st = [r["steps"] for r in mine if r.get("steps", {}).get("anchored") and r["verdict"] != "NOT CHECKED"]
        if st:                                   # blind round 2 (v2 pre-registration)
            n_sus = sum(len(s["suspicious"]) for s in st)
            per[sc]["steps"] = {
                "innocent_runs": sum(not s["suspicious"] for s in st),
                "clean": sum(r["verdict"] == "CLEAN" for r in mine), "false_alarm": sum(r["verdict"] == "FALSE ALARM" for r in mine),
                "suspicious_steps": n_sus, "flagged": sum(len(s["flagged"]) for s in st),
                "step_rate": share(sum(len(s["flagged"]) for s in st), n_sus),
                "flagged_by_program_only": sum(len(s["flagged_by_program_only"]) for s in st),
                "unrecorded": sum(len(s["unrecorded"]) for s in st),
                "alerts_on_other_steps": sum(s["alerts_on_other_steps"] for s in st)}
            inc = [s["incident"] for s in st if s.get("incident")]
            if inc:                              # v4 F1 (v4-prereg 3b): a second column, never summed with the strict one
                per[sc]["steps"]["incident"] = {
                    "runs": len(inc), "detected": sum(i["verdict"] == "DETECTED" for i in inc),
                    "missed": sum(i["verdict"] == "MISSED" for i in inc),
                    "clean": sum(i["verdict"] == "CLEAN" for i in inc),
                    "false_alarm": sum(i["verdict"] == "FALSE ALARM" for i in inc),
                    "flagged": sum(len(i["flagged"]) for i in inc),
                    "by_follow_through_only": sum(len(i["flagged_by_follow_through_only"]) for i in inc),
                    "innocent_steps_reached": sum(len(i["innocent_steps_reached"]) for i in inc),
                    "alerts_rooted_outside": sum(i["alerts_rooted_outside"] for i in inc)}
    judged = [r for r in rows if r["verdict"] in ("DETECTED", "MISSED")]
    return {"per_scenario": per, "pooled": share(sum(r["verdict"] == "DETECTED" for r in judged), len(judged)),
            "other_alerts_total": sum(r["other_alerts"] for r in rows)}


def detection_markdown(lab, items, rows, summary):
    L = lab.header("J1 detection rate and time to detect",
                   f"{len(rows)} {'official' if lab.official else 'practice'} run(s) replayed and scored with every detector "
                   f"(tools/check_alerts.py per run)")
    L += ["Definitions (pre-registered): a run is DETECTED when every alert its answer sheet lists under "
          "`alert_expected.check` (rule id, level, involved program) was raised on an instant replay of the run's window; "
          "time to detect = the first such alert's time (`Alert.time`: when the rule's condition became true, on the "
          "recorded clock) minus the scenario's first program's recorded start (its event 1); other alerts = alerts at or "
          "above the frozen floor in the run window that name none of the scenario's programs (false alarms during a run). "
          "Runs whose scenario check failed are listed and not scored.", "",
          "| scenario | runs scored | judged | detected | none expected | not checked | rate (95 % CP) | time to detect s: min / median / max (n anchored of detected) | other alerts per run |",
          "|---|---|---|---|---|---|---|---|---|"]
    for sc, p in summary["per_scenario"].items():
        t = p["ttd_seconds"]
        L.append(f"| {sc} | {p['runs']} | {p['judged']} | {p['detected']} | {p['none_expected']} | {p['not_checked']} | {pct(p['rate'])} | "
                 f"{fmt(t['min'], 1)} / {fmt(t['median'], 1)} / {fmt(t['max'], 1)} ({t['n']} of {t['n'] + t['not_anchored']}) | {fmt(p['other_alerts_per_run'], 2)} |")
    L += ["", f"Pooled detection rate over every judged run: {pct(summary['pooled'])}. "
              f"Other alerts (>= frozen floor, not involving the scenario) over all runs: {summary['other_alerts_total']}.", ""]
    stepped = {sc: p["steps"] for sc, p in summary["per_scenario"].items() if "steps" in p}
    if stepped:
        L += ["## Blind round 2: suspicious steps (v2 pre-registration)", "",
              "A step is FLAGGED when a raised alert (>= the frozen floor) cites at least one of the records the scenario "
              "checker matches to that step's evidence. A run is DETECTED when every suspicious step its sheet names is "
              "flagged; an innocent sheet (no suspicious step) is CLEAN when no raised alert flags a step or names a scenario "
              "program, else FALSE ALARM. 'Program only' = an alert names the step's program but cites none of its events "
              "(secondary, not counted as flagged).", "",
              "| scenario | suspicious steps (all runs) | flagged (95 % CP) | program only | not recorded | alerts on other steps | innocent runs: clean / false alarm |",
              "|---|---|---|---|---|---|---|"]
        for sc, s in stepped.items():
            inn = f"{s['clean']} / {s['false_alarm']}" if s["innocent_runs"] else "-"
            L.append(f"| {sc} | {s['suspicious_steps']} | {pct(s['step_rate'])} | {s['flagged_by_program_only']} | {s['unrecorded']} | "
                     f"{s['alerts_on_other_steps']} | {inn} |")
        L.append("")
        if any("incident" in s for s in stepped.values()):
            L += ["## Incident level (v4 F1, v4-prereg 3b): a second column, never the verdict", "",
                  "A suspicious step also counts here when it lies in a raised alert's FOLLOW-THROUGH (the later recorded "
                  "actions of the process the alert is about and of its descendants, 10 minutes, hubs not followed). "
                  "'Flagged by a rule' above stays the comparison with earlier versions. Symmetric: an innocent run is "
                  "clean here only when no raised alert's evidence or follow-through reaches it. The price of following: "
                  "steps NOT marked suspicious that follow-through alone also holds.", "",
                  "| scenario | runs | incident: detected / missed | innocent: clean / false alarm | suspicious steps reached "
                  "(by follow-through only) | innocent steps reached by following | alerts rooted outside the scenario |",
                  "|---|---|---|---|---|---|---|"]
            for sc, s in stepped.items():
                i = s.get("incident")
                if i:
                    L.append(f"| {sc} | {i['runs']} | {i['detected']} / {i['missed']} | {i['clean']} / {i['false_alarm']} | "
                             f"{i['flagged']} ({i['by_follow_through_only']}) | {i['innocent_steps_reached']} | "
                             f"{i['alerts_rooted_outside']} |")
            L.append("")
    skipped = [it for it in items if not it.ok]
    if skipped:
        L += [f"Runs listed but not scored ({len(skipped)}): " + "; ".join(f"{run_line(it)}: {it.status}" for it in skipped), ""]
    L += ["## Per run", "", "| scenario | run | records | verdict | expected | found | time to detect (s) | other alerts (rule[level]: n) |",
          "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        ttd = ", ".join(f"{t['rule_id']}[{t['level']}] {fmt(t['seconds'], 1) if t['seconds'] is not None else 'not anchored'}"
                        for t in r["time_to_detect"]) or "-"
        other = ", ".join(f"{k}: {v}" for k, v in sorted(r["other_by_rule"].items())) or "-"
        L.append(f"| {r['scenario']} | {r['run_id']} | {r['records']} | {r['verdict']}{' (missed: ' + ', '.join(r['missed']) + ')' if r['missed'] else ''} | "
                 f"{r['expected']} | {r['found']} | {ttd} | {other} |")
    return L


def cmd_detection(lab, scenarios=None, blind=False, name="detection"):
    items = lab.select_runs(scenarios, blind=blind)

    def one(it):
        r = detection_of(lab, it)
        print(f"  {run_line(it)}: {r['verdict']}" + (f" ({len(r['time_to_detect'])} alert(s), other {r['other_alerts']})" if r["verdict"] != "NOT CHECKED" else ""))
        return r
    rows = scored(items, one)
    summary = summarize_detection(rows)
    doc = {"question": "J1" if not blind else "J3-detection", "runs": [{k: v for k, v in r.items() if k != "lines"} for r in rows],
           "skipped": [{"scenario": it.scenario.upper(), "run_id": it.run_id, "status": it.status} for it in items if not it.ok],
           "summary": summary}
    js, md = lab.write(name, doc, detection_markdown(lab, items, rows, summary))
    print(f"J1 detection: {md}")
    return 0 if rows or not items else 2


# -- J2: story accuracy ----------------------------------------------------------------------------------
def story_of(lab, it):
    """One run: the graph checker's counts (GraphCheck.tally) behind precision / recall."""
    records, lo, hi = lab.window(it.run)
    server = check_scenario.run_server(it.run)
    with tempfile.TemporaryDirectory() as tmp:
        db = fresh_store(tmp, records)
        t0 = time.perf_counter()
        G = build_graph(db, hypotheses=lab.layer2())
        t_graph = time.perf_counter() - t0
    raw_by_key = {EventStore.dedup_key(r): r for r in records}
    lines = []
    ok, c = check_graph_scenario.check_graph(it.truth, G, raw_by_key, lo, hi, server, lab.hubs(), say=lines.append)
    tally = dict(c.tally)
    fails = [l.strip() for l in lines if l.startswith("  FAIL")]
    eg = it.truth.get("expected_graph") or {}
    resolved = hasattr(c, "found")                          # check_facts (which sets it) runs only once every role resolved
    if not resolved:
        # the checker could not resolve the roles, so it never counted: the sheet still says what was
        # expected, and every one of those edges is missing (review 2026-10-30: 0/0 hid the worst runs)
        tally["facts_expected"] = sum(f.get("count", 1) for f in eg.get("facts", []))
        tally["hyps_expected"] = sum(1 for h in eg.get("hypotheses", []) if not h.get("optional"))
    # a found hypothesis is CORRECT only if its method check and its trace back to the raw events
    # also passed (the checker names the claim in its FAIL line); the checker's output is unchanged
    hyps = [{"claim": h["claim"], "row": d["row"], "kind": d["kind"], "band": d["band"], "p": d.get("p"), "basis": d.get("basis"),
             "assessable": d.get("assessable"), "correct": not any(f"'{h['claim']}'" in l for l in fails)} for h, d, _, _ in c.found_hyps]
    tally["hyps_correct"] = sum(h["correct"] for h in hyps)
    l2 = G.graph.get("layer2") or {}
    return {"scenario": it.scenario.upper(), "run_id": it.run_id, "start": it.run.get("start"), "records": len(records),
            "pass": bool(ok), "resolved": resolved, "tally": tally, "hypotheses": hyps,
            "sigma_p": l2.get("sigma_p"), "graph": {"nodes": G.number_of_nodes(), "facts": sum(1 for _, _, d in G.edges(data=True) if d.get("grade") == "fact"),
                                                    "hypotheses": sum(1 for _, _, d in G.edges(data=True) if d.get("grade") == "hypothesis"),
                                                    "gaps": len(G.graph.get("gaps", []))},
            "fail_lines": fails, "seconds_graph": round(t_graph, 2), "lines": lines}


def story_metrics(rows):
    """Pooled counts -> precision / recall of facts and hypotheses, correctness of grades. Every
    scored run is in every denominator: a run that never reached the views or the trace (an earlier
    step failed) counts as "not ok" there, not as absent."""
    t = Counter()
    for r in rows:
        t.update(r["tally"])
    n = len(rows)
    found_f, exp_f, unexp_f = t["facts_found"], t["facts_expected"], t["facts_unexpected"] + t["facts_surplus"]
    correct_h, exp_h = t["hyps_correct"], t["hyps_expected"]
    wrong_h = t["hyps_unlisted"] + t["hyps_as_fact"] + (t["hyps_found"] - correct_h)
    return {"runs": n, "checker_pass": sum(r["pass"] for r in rows), "resolved": sum(r["resolved"] for r in rows),
            "facts": {"expected": exp_f, "found": found_f, "unexpected": unexp_f,
                      "recall": share(found_f, exp_f), "precision": share(found_f, found_f + unexp_f)},
            "hypotheses": {"expected": exp_h, "found": t["hyps_found"], "correct": correct_h, "unlisted": t["hyps_unlisted"],
                           "graded_as_fact": t["hyps_as_fact"], "optional_absent": t["hyps_optional_absent"], "touching_unjudged": t["hyps_touching"],
                           "recall": share(correct_h, exp_h), "precision": share(correct_h, correct_h + wrong_h)},
            "gaps_ok": share(t["gaps_ok"], n), "alert_view_ok": share(t["view_ok"], n),
            "runner_view_ok": share(t["runner_view_ok"], n), "trace_ok": share(t["trace_ok"], n),
            "files_unexpected": t["files_unexpected"],
            "bands": {f"{row}/{band_}": c for (row, band_), c in sorted(Counter((h["row"], h["band"]) for r in rows for h in r["hypotheses"] if h["correct"]).items())}}


def summarize_story(rows):
    per = {sc: story_metrics([r for r in rows if r["scenario"] == sc]) for sc in sorted({r["scenario"] for r in rows})}
    return {"per_scenario": per, "pooled": story_metrics(rows)}


def story_markdown(lab, items, rows, summary):
    L = lab.header("J2 story accuracy (graph vs answer sheet)",
                   f"{len(rows)} {'official' if lab.official else 'practice'} run(s) replayed into a fresh store, graph with layer 2, "
                   f"tools/check_graph_scenario.py per run")
    L += ["Definitions (pre-registered): expected edges = the sheet's `expected_graph.facts` (with their counts) and `hypotheses` "
          "(an `optional` one counts only when the raw records hold its cause and effect inside the timing window); a fact edge is "
          "TRUE when it joins the right two scenario nodes with the right kind; recall = found / expected; precision = found / "
          "(found + other facts between scenario nodes, incl. surplus copies); a hypothesis is correct when exactly one layer-2 "
          "edge of the listed kind joins its roles through a scenario process with band, reason, alternative and cited events AND "
          "its method check and trace back to the raw events pass; wrong = an unlisted hypothesis between two scenario nodes, an "
          "expected hypothesis graded as a FACT (the worst error: counted against both), or a found one whose method check or "
          "trace failed. A run whose roles could not be resolved counts every sheet edge as missing. Hypotheses that touch only "
          "one scenario node are not judged by the sheet (counted, not scored). Gaps, the alert view, the strict runner view and "
          "the trace back to the raw events are pass counts over every scored run (a run that never reached a step is 'not ok'). "
          "The intervals treat edges of one run as independent trials, which they are not: read the per-run lines.", "",
          "| scenario | runs | checker PASS | fact recall | fact precision | hyp. recall | hyp. precision | graded as fact | gaps ok | alert view ok | runner view ok | trace ok |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for sc, m in list(summary["per_scenario"].items()) + [("all", summary["pooled"])]:
        f, h = m["facts"], m["hypotheses"]
        L.append(f"| {sc} | {m['runs']} | {m['checker_pass']} | {pct(f['recall'])} | {pct(f['precision'])} | {pct(h['recall'])} | "
                 f"{pct(h['precision'])} | {h['graded_as_fact']} | {pct(m['gaps_ok'])} | {pct(m['alert_view_ok'])} | {pct(m['runner_view_ok'])} | {pct(m['trace_ok'])} |")
    p = summary["pooled"]
    L += ["", f"Pooled: facts {p['facts']['found']} of {p['facts']['expected']} expected found, {p['facts']['unexpected']} other fact(s) between scenario nodes; "
              f"hypotheses {p['hypotheses']['correct']} of {p['hypotheses']['expected']} expected correct ({p['hypotheses']['found']} found), "
              f"{p['hypotheses']['unlisted']} unlisted between scenario nodes, "
              f"{p['hypotheses']['graded_as_fact']} graded as a fact, {p['hypotheses']['optional_absent']} optional one(s) rightly absent, "
              f"{p['hypotheses']['touching_unjudged']} touching one scenario node (not judged); {p['files_unexpected']} unexpected file(s) in scenario folders.", "",
          "## Bands of the expected hypotheses that were found (row, band: count)", ""]
    for key, n in p["bands"].items():
        L.append(f"- {key.replace('/', ' ')}: {n}")
    if not p["bands"]:
        L.append("- none")
    skipped = [it for it in items if not it.ok]
    if skipped:
        L += ["", f"Runs listed but not scored ({len(skipped)}): " + "; ".join(f"{run_line(it)}: {it.status}" for it in skipped)]
    L += ["", "## Per run", "", "| scenario | run | records | checker | facts found/expected | other facts | hyps correct/expected | unlisted | as fact | touching | Σp | graph s | failures |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        t = r["tally"]
        L.append(f"| {r['scenario']} | {r['run_id']} | {r['records']} | {'PASS' if r['pass'] else 'FAIL'} | {t.get('facts_found', 0)}/{t.get('facts_expected', 0)} | "
                 f"{t.get('facts_unexpected', 0) + t.get('facts_surplus', 0)} | {t.get('hyps_correct', 0)}/{t.get('hyps_expected', 0)} | {t.get('hyps_unlisted', 0)} | "
                 f"{t.get('hyps_as_fact', 0)} | {t.get('hyps_touching', 0)} | {fmt(r['sigma_p'])} | {r['seconds_graph']} | "
                 f"{'; '.join(r['fail_lines']) or '-'} |")
    return L


def cmd_story(lab, scenarios=None, blind=False, name="story"):
    items = [it for it in lab.select_runs(scenarios, blind=blind)]
    for it in items:
        if it.ok and not (it.truth or {}).get("expected_graph"):
            it.status = "the answer sheet has no expected_graph"

    def one(it):
        r = story_of(lab, it)
        t = r["tally"]
        print(f"  {run_line(it)}: {'PASS' if r['pass'] else 'FAIL'} facts {t.get('facts_found', 0)}/{t.get('facts_expected', 0)} "
              f"hyps {t.get('hyps_correct', 0)}/{t.get('hyps_expected', 0)}")
        return r
    rows = scored(items, one)
    summary = summarize_story(rows)
    doc = {"question": "J2" if not blind else "J3-story", "runs": [{k: v for k, v in r.items() if k != "lines"} for r in rows],
           "skipped": [{"scenario": it.scenario.upper(), "run_id": it.run_id, "status": it.status} for it in items if not it.ok],
           "summary": summary}
    js, md = lab.write(name, doc, story_markdown(lab, items, rows, summary))
    print(f"J2 story: {md}")
    return 0 if rows or not items else 2


# -- J3: blind ----------------------------------------------------------------------------------------------
def cmd_blind(lab, scenarios=None):
    """B1/B2 with J1's and J2's metrics, reported whatever they are (official mode only)."""
    a = cmd_detection(lab, scenarios, blind=True, name="blind-detection")
    b = cmd_story(lab, scenarios, blind=True, name="blind-story")
    return max(a, b)


# -- J4: false alerts per active hour -------------------------------------------------------------------------
def score_laptop(lab, laptop, out_db, rescore=False):
    """Every detector over the snapshot, once (the alert db is reused unless --rescore)."""
    if os.path.exists(out_db) and not rescore:
        st = AlertStore(out_db)
        try:
            return st.read(), "reused"
        finally:
            st.close()
    con = detect.open_store(laptop)
    try:
        errors, timings = [], {}
        t0 = time.perf_counter()
        alerts = score.score(con, lab.rules(), lab.baseline(), errors=errors, timings=timings)
        took = time.perf_counter() - t0
    finally:
        con.close()
    if errors:
        raise RuntimeError(f"{len(errors)} detector error(s) while scoring: " + "; ".join(f"{r[:24]}: {e[:80]}" for r, e in errors[:3]))
    if os.path.exists(out_db):
        os.remove(out_db)
    os.makedirs(os.path.dirname(out_db), exist_ok=True)
    st = AlertStore(out_db)
    st.write(alerts, events_db=os.path.basename(laptop))
    st.close()
    return alerts, f"scored in {took / 60:.1f} min"


def friends_table(root):
    """Friends' statistics files (counts only): active hours and event rates per friend, newest file
    each. No alert rate exists in those files (stated in the pre-registration). Friends are
    numbered "friend 1, 2, ..." (folder names sorted) in everything printed; the folder name stays
    only in the git-ignored JSON (privacy rule 7, review 2026-10-30)."""
    import friend_stats
    paths = sorted(glob.glob(os.path.join(root, "*", "*.txt")))
    if not paths:
        return None
    rows = friend_stats.collect(paths, root)
    newest = {}
    for friend, date, path, s, err in rows:
        if s is not None and (friend not in newest or friend_stats.newness(date, s) >= friend_stats.newness(*newest[friend])):
            newest[friend] = (date, s)
    kinds = ["process starts", "network connections", "DNS lookups", "files created (watched kinds)"]
    numbered = {f"friend {i}": name for i, name in enumerate(sorted(newest), 1)}
    return {"files": len(paths), "refused": sum(1 for r in rows if r[3] is None), "folders": numbered,
            "friends": {label: {"made_on": newest[name][0], "days": newest[name][1]["days_recorded"], "active_hours": newest[name][1]["active_hours"],
                                "per_active_hour": {k: newest[name][1]["events_per_active_hour"].get(k, 0) for k in kinds}}
                        for label, name in numbered.items()}}


def cmd_false_alerts(lab, laptop=None, alerts=None, rescore=False, friends_root=None):
    if alerts and lab.official:
        raise ValueError("official mode scores the TEST snapshot itself (--alerts would let any alert database stand in for it)")
    laptop = lab.laptop_db(laptop)
    con = ro(laptop)
    try:
        meta = dict(con.execute("SELECT key, value FROM snapshot"))
        if alerts:
            all_alerts = []
            for p in alerts:
                st = AlertStore(p)
                all_alerts += st.read()
                st.close()
            how = f"alerts read from {len(alerts)} alert database(s) given on the command line"
        else:
            # official: always scored afresh (review 2026-11-13: a reused alert db names neither its code nor its snapshot)
            all_alerts, how = score_laptop(lab, laptop, os.path.join(lab.out_dir, "laptop-alerts.db"), rescore or lab.official)
            how = f"every detector run over the snapshot by engine.score ({how})"
        res_all = false_alarms.analyse(con, all_alerts)
        raised = score.raised(all_alerts)
        res_raised = false_alarms.analyse(con, raised)
    finally:
        con.close()
    days = meta.get("from_day_utc", "?") + " .. " + meta.get("cutoff_day_utc", "?") if lab.official else "dev days up to " + meta.get("cutoff_day_utc", "?")
    L = lab.header("J4 false alerts per active hour (normal use)",
                   f"laptop {'TEST' if lab.official else 'DEV'} snapshot ({days}, {meta.get('events', '?')} events), {how}")
    L += ["Definitions (pre-registered, reused from `tools/false_alarms.py`): on normal use every alert is a false alarm; an "
          "ACTIVE minute is a minute (of the event's UtcTime) with at least one normal-use Sysmon event (our own tools and paused "
          "rows excluded); the rate is alerts per active hour. RAISED = at or above the frozen floor "
          f"(`sigma.min_level` = {config.min_level()}); the lower levels are stored but never shown. Each rule is categorised by its "
          "source (sigma = community rule, analystlab = our own rule, beacon = check-in rhythm), level, how many days and how many "
          "different programs (anonymous) it fired on, and where those programs live.", "",
          f"- Active hours: **{res_all['active_hours']}**",
          f"- RAISED alerts (>= {config.min_level()}): **{res_raised['alerts']:,}** = **{fmt(res_raised['per_active_hour'], 2)} per active hour**",
          f"- All levels: {res_all['alerts']:,} = {fmt(res_all['per_active_hour'], 2)} per active hour", "",
          "| level | alerts | per active hour |", "|---|---:|---:|"]
    L += [f"| {lvl} | {n:,} | {fmt(r, 3)} |" for lvl, (n, r) in res_all["by_level"].items()]
    L += ["", "## Raised alerts by rule (the ones an analyst would see)", "",
          "| source | level | rule | alerts | per active hour | days | programs | where the programs live |", "|---|---|---|---:|---:|---:|---:|---|"]
    h = res_raised.get("hours_exact") or 1
    for (source, level, title, _rid), v in res_raised["rules"]:
        places = ", ".join(f"{k} {n}" for k, n in v["places"].most_common())
        L.append(f"| {source} | {level} | {title} | {v['n']:,} | {v['n'] / h:.3f} | {len(v['days'])} | {len(v['programs'])} | {places} |")
    if not res_raised["rules"]:
        L.append("| - | - | none raised | 0 | 0 | 0 | 0 | - |")
    L += ["", "## Every level, per rule (tools/false_alarms.py's own report)", ""]
    L += false_alarms.report(res_all, "all levels", [os.path.basename(laptop)]).splitlines()[4:]
    doc = {"question": "J4", "snapshot": {k: meta.get(k) for k in ("kind", "from_day_utc", "cutoff_day_utc", "events", "built_utc")},
           "how": how, "all": {k: res_all[k] for k in ("active_hours", "alerts", "per_active_hour", "by_level")},
           "raised": {k: res_raised[k] for k in ("active_hours", "alerts", "per_active_hour", "by_level")},
           "raised_rules": [{"source": s, "level": l, "title": t, "rule_id": r, "n": v["n"], "days": len(v["days"]), "programs": len(v["programs"]),
                             "places": dict(v["places"])} for (s, l, t, r), v in res_raised["rules"]],
           "all_rules": [{"source": s, "level": l, "title": t, "rule_id": r, "n": v["n"], "days": len(v["days"]), "programs": len(v["programs"])}
                         for (s, l, t, r), v in res_all["rules"]]}
    if lab.official:
        fr = friends_table(friends_root or os.path.join(lab.recordings, "friends"))
        doc["friends"] = fr
        L += ["", "## Friends' laptops (statistics files: counts only)", ""]
        if not fr:
            L.append("No friends' statistics files under recordings/friends/.")
        else:
            L += ["Friends' exports hold event counts and active time only, never alerts (the friend package records, it does not "
                  "detect), so no false-alert rate exists for them (pre-registered fallback: their event rates per active hour show "
                  "how representative Yousif's laptop is).", "",
                  "| friend | made on | days | active hours | process starts /h | connections /h | DNS /h | files created /h |", "|---|---|---|---|---|---|---|---|"]
            for f, s in fr["friends"].items():
                p = s["per_active_hour"]
                L.append(f"| {f} | {s['made_on']} | {s['days']} | {s['active_hours']} | {p['process starts']} | {p['network connections']} | "
                         f"{p['DNS lookups']} | {p['files created (watched kinds)']} |")
            L.append(f"\n{fr['files']} file(s), {fr['refused']} refused as not an untouched export.")
    js, md = lab.write("false-alerts", doc, L)
    print(f"J4 false alerts: {md} (active hours {res_all['active_hours']}, raised {res_raised['alerts']} = {fmt(res_raised['per_active_hour'], 2)}/h)")
    return 0


# -- J5a: A16 agreement -------------------------------------------------------------------------------------
def a16_agreement(res, side, cfg):
    """The pre-registered reading: (a) A16 +-30/+-60 shifted control vs prediction (with the frozen
    factor) per band, agreeing when the per-process ratio lies within [0.5, 2]; (b) the +-12 s
    sideband's implied factor beta_hat (at factor 1), covered when its 95 % upper bound <= the
    frozen burst factor. T2/T3 are leads only (never above low): reported, no consequence."""
    a16 = {}
    for row, r in res.items():
        a16[row] = {}
        for band_, d in r["bands"].items():
            pp = d["per_process"]
            ratio = (pp["control"] / pp["predicted_controlled"]) if pp.get("control") is not None and pp.get("predicted_controlled") else None
            a16[row][band_] = {"causes": d["causes"], "processes": d["processes"], "predicted": d["predicted"], "control": d["control"],
                               "rotate": d["rotate"], "real": d["real"], "per_process_ratio": ratio,
                               "agrees": None if ratio is None else bool(AGREE_LO <= ratio <= AGREE_HI),
                               # which way it misses: over-confident = chance more common than predicted (the unsafe side)
                               "direction": None if ratio is None else ("over-confident" if ratio > AGREE_HI else "over-cautious" if ratio < AGREE_LO else "agrees")}
    sb = {}
    for row, r in side["rows"].items():
        sb[row] = {}
        for key, off in r["offsets"].items():
            for band_, st in off["bands"].items():
                pp = st["per_process"]
                sb[row][f"{key}/{band_}"] = {"processes": st["processes"], "hits": st["control_hits"], "beta": pp["beta"],
                                             "upper95": pp.get("beta_upper95"), "decidable": st["decidable"],
                                             "covered": (pp.get("beta_upper95") is not None and pp["beta_upper95"] <= cfg.burst) if st["decidable"] else None}
    t1 = [v for k, v in sb.get("T1", {}).items() if k.endswith("/medium") and v["decidable"]]
    verdict = ("T1 medium band: the frozen factor covers the +-12 s sideband" if t1 and all(v["covered"] for v in t1)
               else "T1 medium band: the frozen factor does NOT cover the +-12 s sideband (reported, not re-tuned)" if t1
               else "T1 medium band not decidable on this data (fallback: reported only)")
    return {"a16": a16, "sideband": sb, "verdict": verdict, "burst_factor": cfg.burst}


def cmd_a16(lab, laptop=None, host=None, bootstrap=K.BOOTSTRAP_B):
    laptop = lab.laptop_db(laptop)
    cfg = C.load_config(official=lab.official)
    db = ro(laptop)
    try:
        hosts = C.hosts(db)
        if len(hosts) > 1 and not host:
            raise ValueError(f"the snapshot holds {len(hosts)} machines: pass --host")
        act = C.load_activity(db, cfg, host or (hosts[0] if hosts else None))
        pool = C.Pool.load(lab.pool, expect_sha256=cfg.pool_sha256, cfg=cfg)
        meta = dict(db.execute("SELECT key, value FROM snapshot"))
    finally:
        db.close()
    t0 = time.perf_counter()
    res = C.a16_check(act, pool, cfg)
    side = K.sideband_analysis(act, pool, cfg, offsets=K.DECISION_OFFSETS, B=bootstrap)
    took = time.perf_counter() - t0
    os.makedirs(lab.out_dir, exist_ok=True)
    png = os.path.join(lab.results_dir, f"j2-a16-{lab.label}.png")
    try:
        C._chart(res, png)
    except Exception as e:                                  # noqa: BLE001 - a chart never blocks the numbers
        png = f"(chart not written: {e})"
    ag = a16_agreement(res, side, cfg)
    days = (meta.get("from_day_utc", "?") + " .. " + meta.get("cutoff_day_utc", "?")) if lab.official else "dev days up to " + meta.get("cutoff_day_utc", "?")
    L = lab.header("J5a A16: predicted vs observed coincidence rates",
                   f"laptop {'TEST' if lab.official else 'DEV'} snapshot ({days}): {len(act.procs)} processes, "
                   f"{act.active.total / 3600:.1f} active hours; frozen pool {cfg.pool_sha256[:12] if cfg.pool_sha256 else '?'}; "
                   f"burst factor {cfg.burst}; {took / 60:.1f} min")
    L += ["Definitions (pre-registered, reused): `engine.confidence.a16_check`: for every cause of a timing row in processes alive "
          "at least one window with at least one effect of that kind, the PREDICTED one-cause chance p1 under the frozen rule (lambda = "
          "max of the band pool, the program pool and the within-life rate, times the frozen burst factor) against OBSERVED chance "
          "rates that cannot hold the cause's own effect: the same-length window shifted by +-30 / +-60 s of active time inside the "
          "process's life (keeps the bursts), and the effects rotated within the life; plus the real window. Per process = each "
          "process weighs once (what a graph grades). `engine.calibration.sideband_analysis` at -12 / +12 s (the control right next "
          "to the true window) gives the implied factor beta_hat at factor 1 with its per-process bootstrap 95 % upper bound.",
          f"Agreement rule (fixed in advance): a band AGREES when the per-process ratio shifted / predicted lies within [{AGREE_LO}, {AGREE_HI}]; "
          f"the frozen factor {cfg.burst} COVERS a decidable sideband group when its upper bound <= {cfg.burst}. T2 and T3 are leads only "
          "(`confidence.leads_only`): shown, no consequence. Whatever the outcome, nothing is re-tuned after the freeze.", "",
          f"**Verdict:** {ag['verdict']}.", "",
          "## A16 by row and band of p1 (prediction with the frozen factor)", "",
          "| row | band | causes | processes | predicted p1 | shifted +-30/60 (per cause) | rotated | real window | per process shifted / predicted | reading |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for row, bands_ in ag["a16"].items():
        for band_, d in bands_.items():
            L.append(f"| {row} | {band_} | {d['causes']} | {d['processes']} | {fmt(d['predicted'], 4)} | {fmt(d['control'], 4)} | {fmt(d['rotate'], 4)} | "
                     f"{fmt(d['real'], 4)} | {fmt(d['per_process_ratio'], 2)} | {d['direction'] or '-'} |")
    L += ["", f"Graded pairs as the graph would show them (with N), per row: " + "; ".join(f"{row} {r['graded_pairs']}" for row, r in res.items()), "",
          "## +-12 s sideband (engine.calibration): implied factor at factor 1 vs the frozen factor", "",
          "| row | offset / band | processes | control hits | beta_hat per process | upper 95 % | decidable | covered by the frozen factor |",
          "|---|---|---|---|---|---|---|---|"]
    for row, groups in ag["sideband"].items():
        for key, v in groups.items():
            L.append(f"| {row} | {key} | {v['processes']} | {v['hits']} | {fmt(v['beta'], 2)} | {fmt(v['upper95'], 2)} | {'yes' if v['decidable'] else 'no'} | "
                     f"{'-' if v['covered'] is None else ('yes' if v['covered'] else 'no')} |")
    L += ["", f"Chart: `{os.path.basename(png) if png.endswith('.png') else png}` (A16, counts only)."]
    doc = {"question": "J5a", "snapshot": {k: meta.get(k) for k in ("kind", "from_day_utc", "cutoff_day_utc", "events")},
           "processes": len(act.procs), "active_hours": act.active.total / 3600, "burst_factor": cfg.burst, "a16": res,
           "sideband": side, "agreement": ag, "chart": png, "seconds": took}
    js, md = lab.write("a16", doc, L)
    print(f"J5a A16: {md}\n  {ag['verdict']}")
    return 0


# -- J6: the noise overlay matrix ----------------------------------------------------------------------------
def overlay_json(lab):
    return os.path.join(lab.out_dir, "noise-overlay.json")


def cmd_overlay(lab, runs=None, volumes=None, seeds=None, r4_seeds=None):
    if lab.official and (runs or volumes or seeds or r4_seeds):
        raise ValueError("official mode runs the pre-registered matrix on every official run: --runs/--volumes/--seeds/--r4-seeds are refused")
    os.makedirs(lab.out_dir, exist_ok=True)
    argv = ["--recordings", lab.recordings, "--pool", lab.pool, "--label", lab.vm_label,
            "--out-md", os.path.join(lab.results_dir, f"j2-noise-overlay-{lab.label}.md"), "--out-json", overlay_json(lab)]
    argv += ["--runs"] + list(runs or (list(SCENARIOS) if lab.official else overlay_experiment.DEFAULT_RUNS))
    if volumes:
        argv += ["--volumes"] + [str(v) for v in volumes]
    if seeds:
        argv += ["--seeds"] + [str(s) for s in seeds]
    if r4_seeds:
        argv += ["--r4-seeds", str(r4_seeds)]
    if lab.until and not lab.official:
        argv += ["--until", lab.until]
    code = overlay_experiment.main(argv)
    print(f"J6 overlay: exit {code}")
    return code


# -- J5b: calibration on the overlay ---------------------------------------------------------------------------
def calibration_from(doc):
    """Per volume and band: correct = the scenario's expected hypotheses the checker verified (one per
    graph, grafting on), false = every hypothesis of a class that is false by construction (cross,
    cross/graft, cross-r4), unknown = the rest (VM background, overlay-internal). Share correct with
    its Clopper-Pearson interval; claimed only from MIN_BAND_N judged links. Also the independence
    check: graft-induced cross T2/T3 observed vs their sigma-p."""
    per = defaultdict(lambda: {"correct": 0, "false": 0, "unknown": 0, "by_row": defaultdict(lambda: {"correct": 0, "false": 0})})
    indep = defaultdict(lambda: {"graphs": 0, "observed": 0, "sigma_p": 0.0})
    for c in doc["cells"]:
        if not c.get("graft"):
            continue
        v = c["volume"]
        expected = Counter()
        for h in c.get("expected_hypotheses") or []:
            per[(v, h["band"])]["correct"] += 1
            per[(v, h["band"])]["by_row"][h["row"]]["correct"] += 1
            expected[(h["row"], h["band"])] += 1
        for cls, rows in (c.get("hypotheses_by_class") or {}).items():
            for row, bands_ in rows.items():
                for band_, n in bands_.items():
                    if cls == "scenario-story":
                        # links between two scenario nodes: the sheet's expected ones are the correct
                        # ones above; any OTHER one is false (an unlisted link between role nodes)
                        n = max(n - expected[(row, band_)], 0)
                        key = "false"
                    else:
                        key = "false" if cls in FALSE_CLASSES else "unknown"
                    per[(v, band_)][key] += n
                    if key == "false":
                        per[(v, band_)]["by_row"][row]["false"] += n
        g = indep[v]
        g["graphs"] += 1
        g["observed"] += c["cross"]["cross_t_observed"]
        g["sigma_p"] += c["cross"]["cross_t_sigma_p"]
    out = {}
    for (v, band_), d in sorted(per.items(), key=lambda x: (x[0][0], BANDS.index(x[0][1]) if x[0][1] in BANDS else 9)):
        judged = d["correct"] + d["false"]
        out[f"{v}x/{band_}"] = {"volume": v, "band": band_, "correct": d["correct"], "false": d["false"], "unknown": d["unknown"],
                                "share_correct": share(d["correct"], judged) if judged >= MIN_BAND_N else None, "judged": judged,
                                "by_row": {r: dict(x) for r, x in d["by_row"].items()}}
    for v, g in indep.items():
        g["ratio"] = (g["observed"] / g["sigma_p"]) if g["sigma_p"] else None
    return {"per_band": out, "independence": {str(v): g for v, g in sorted(indep.items())}, "min_n": MIN_BAND_N}


def cmd_calibration(lab, overlay=None):
    path = overlay or overlay_json(lab)
    if not os.path.exists(path):
        print(f"no overlay results at {path}: run `experiments.py overlay --label {lab.label}` first")
        return 2
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if bool(doc.get("inputs", {}).get("official")) != lab.official:
        print(f"{path} was made in {'official' if doc.get('inputs', {}).get('official') else 'practice'} mode, not {lab.label}: refused")
        return 2
    cal = calibration_from(doc)
    L = lab.header("J5b calibration: share of correct hypotheses per band (noise overlay)",
                   f"the overlay matrix of {doc['inputs']['runs']} run(s) (volumes {doc['inputs']['volumes']}, seeds {doc['inputs']['seeds']}, grafting on)")
    L += ["Definitions (pre-registered): per graph, CORRECT = an expected hypothesis of the scenario's answer sheet that the checker "
          "verified (right roles, kind, band, reason, cited events); FALSE = a hypothesis of a class that is false by construction "
          "(an overlay node and a scenario node never met: cross, cross/graft = a timing link through a grafted parent, cross-r4 = a "
          "name-only file match across the two worlds) and any other link between two scenario nodes beyond the expected ones; "
          "UNKNOWN = VM-background and overlay-internal links (their truth is not "
          f"recorded: counted, not scored). The share correct = correct / (correct + false), with its exact 95 % interval, claimed only "
          f"when at least {MIN_BAND_N} links were judged in that band. Caveat stated in advance: the correct side holds only the few "
          "scenario links (mostly low: short-lived programs), the false side is dominated by low-band name-only and graft links, so "
          "the high and medium bands may stay below the threshold; then only the counts are reported. The independence check "
          "(graft-induced cross T2/T3 observed vs their sigma-p) is the calibration of the chance values themselves.", "",
          "| volume | band | correct | false | share correct (95 % CP) | unknown (not scored) | by row (correct / false) |", "|---|---|---|---|---|---|---|"]
    for key, d in cal["per_band"].items():
        rows = "; ".join(f"{r} {x['correct']}/{x['false']}" for r, x in sorted(d["by_row"].items()))
        claim = pct(d["share_correct"]) if d["share_correct"] else f"not claimed ({d['judged']} judged < {MIN_BAND_N})"
        L.append(f"| {d['volume']}x | {d['band']} | {d['correct']} | {d['false']} | {claim} | {d['unknown']} | {rows or '-'} |")
    L += ["", "## Independence check: graft-induced cross T2/T3, observed vs Σp", "", "| volume | graphs | observed | Σp | observed / Σp |", "|---|---|---|---|---|"]
    for v, g in cal["independence"].items():
        L.append(f"| {v}x | {g['graphs']} | {g['observed']} | {fmt(g['sigma_p'])} | {fmt(g['ratio'], 2)} |")
    r4 = doc.get("r4", {}).get("per_volume", {})
    if r4:
        L += ["", "False name-only R4 per graph (from the overlay run): " + "; ".join(
            f"{v}x {fmt(p['rate_per_graph'])} [{fmt(p['rate_ci95'][0])}, {fmt(p['rate_ci95'][1])}] over {p['graphs']} graphs" for v, p in sorted(r4.items(), key=lambda x: int(x[0])))]
    if doc.get("inputs", {}).get("skipped_scenarios"):
        L += ["", f"Scenarios without a clean official run, not in the matrix: {', '.join(doc['inputs']['skipped_scenarios'])}."]
    js, md = lab.write("calibration", {"question": "J5b", "overlay_json": path, "overlay_inputs": doc.get("inputs"), **cal}, L)
    print(f"J5b calibration: {md}")
    return 0


# -- J7: performance ----------------------------------------------------------------------------------------
def rss_mb():
    try:
        import psutil
        return psutil.Process().memory_info().rss / 2 ** 20
    except Exception:          # noqa: BLE001
        return None


def peak_mb():
    try:
        import psutil
        m = psutil.Process().memory_info()
        return getattr(m, "peak_wset", None) / 2 ** 20 if getattr(m, "peak_wset", None) else None
    except Exception:          # noqa: BLE001
        return None


def timed_graph(db, layer2, cap_seconds):
    """build_graph in a thread; None when it does not finish within the cap (the thread is left to
    finish or die with the process: a measurement, never a crash)."""
    out = {}

    def work():
        try:
            out["G"] = build_graph(db, hypotheses=layer2)
        except Exception as e:                     # noqa: BLE001
            out["error"] = repr(e)
    t = threading.Thread(target=work, daemon=True)
    t0 = time.perf_counter()
    t.start()
    t.join(cap_seconds)
    took = time.perf_counter() - t0
    if t.is_alive():
        return None, took, "not finished within the cap"
    if "error" in out:
        return None, took, out["error"]
    G = out["G"]
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}, took, "ok"


def measure(lab, records, tmp, cap_seconds, what):
    """Instant replay into a fresh store, one scoring pass, the graph (layers 0-2): seconds, events/s, memory."""
    n = len(records)
    db = os.path.join(tmp, "perf.db")
    for name in ("perf.db", "load.db"):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(os.path.join(tmp, name + suffix)):
                os.remove(os.path.join(tmp, name + suffix))
    m0 = rss_mb()
    # (a) a batch load, as engine.load does it (one insert call, one commit)
    st = EventStore(os.path.join(tmp, "load.db"))
    t0 = time.perf_counter()
    st.insert(records)
    t_load = time.perf_counter() - t0
    st.close()
    # (b) the replay path every checker and the demo use (one record at a time, a commit each)
    st = EventStore(db)
    t0 = time.perf_counter()
    replay(records, lambda r: st.insert([r]), speed=0)
    t_replay = time.perf_counter() - t0
    st.close()
    con = detect.open_store(db)
    try:
        errors = []
        t0 = time.perf_counter()
        alerts = score.score(con, lab.rules(), lab.baseline(), errors=errors)
        t_score = time.perf_counter() - t0
    finally:
        con.close()
    m1 = rss_mb()
    g, t_graph, status = timed_graph(db, lab.layer2(), cap_seconds)
    m2 = rss_mb()
    return {"what": what, "events": n, "load_seconds": t_load, "load_events_per_second": n / t_load if t_load else None,
            "replay_seconds": t_replay, "replay_events_per_second": n / t_replay if t_replay else None,
            "score_seconds": t_score, "score_events_per_second": n / t_score if t_score else None, "alerts": len(alerts), "detector_errors": len(errors),
            "graph_seconds": t_graph, "graph": g, "graph_status": status, "rss_mb_before": m0, "rss_mb_after_score": m1, "rss_mb_after_graph": m2}


def cmd_performance(lab, scenarios=None, big=None, cap_minutes=20.0, skip_big=False):
    items = [it for it in lab.select_runs(scenarios) if it.ok]
    rows = []
    cap = cap_minutes * 60
    with tempfile.TemporaryDirectory() as tmp:
        for it in items:
            records, _, _ = lab.window(it.run)
            r = measure(lab, records, tmp, cap, f"{it.scenario.upper()} {it.run_id}")
            r.update({"scenario": it.scenario.upper(), "run_id": it.run_id})
            rows.append(r)
            print(f"  {run_line(it)}: {r['events']} events, load {fmt(r['load_events_per_second'], 0)}/s, replay {fmt(r['replay_events_per_second'], 0)}/s, "
                  f"score {fmt(r['score_events_per_second'], 0)}/s, graph {r['graph_seconds']:.1f} s ({r['graph_status']})")
        big_row = None
        if not skip_big:
            if lab.official and big:
                raise ValueError("official mode measures the largest laptop TEST day: --big is refused")
            chosen = big is None
            if chosen:
                files = lab.host_day_files()
                big = max(files, key=os.path.getsize) if files else None
            if big:
                import build_dev_snapshot as dev
                m = dev.DAY.search(os.path.basename(big))
                day = m.group(1) if m else None
                what = (f"largest laptop day file of the {'test' if lab.official else 'dev'} days ({day})" if chosen
                        else f"recording given with --big ({'laptop day ' + day if day else 'a file'})")
                t0 = time.perf_counter()
                records = read_recordings([big], retag=True)
                t_read = time.perf_counter() - t0
                big_row = measure(lab, records, tmp, cap, what)
                big_row.update({"file_day": day, "file_mb": os.path.getsize(big) / 2 ** 20, "read_seconds": t_read,
                                "read_events_per_second": len(records) / t_read if t_read else None, "largest_of_label": chosen})
                print(f"  {what}: {big_row['events']} events, read {fmt(big_row['read_events_per_second'], 0)}/s, load "
                      f"{fmt(big_row['load_events_per_second'], 0)}/s, replay {fmt(big_row['replay_events_per_second'], 0)}/s, score "
                      f"{fmt(big_row['score_events_per_second'], 0)}/s, graph {big_row['graph_seconds']:.1f} s ({big_row['graph_status']})")
    peak = peak_mb()
    L = lab.header("J7 performance (instant replay)", f"{len(rows)} run window(s)" + (f" and the {big_row['what']}" if big_row else ""))
    L += ["Definitions (pre-registered): events/second of (a) reading + re-tagging a recording file, (b) a batch load into a fresh "
          "event store (`EventStore.insert` once, as `engine.load` does), (c) instant replay (`engine.replay.replay`, speed 0: one record "
          "at a time with a commit each, the path every checker and the demo use), (d) one pass of every detector (`engine.score.score`); "
          f"graph-build time = `engine.graph.build_graph` with layer 2 on that store (capped at {cap_minutes:g} min: a timeout is reported as "
          "such); memory = the process's resident set before and after, and its peak working set at the end (psutil). One machine, one "
          "process, nothing warmed up: the first run also pays for loading the Sigma rules.", "",
          "| recording | events | load events/s | replay events/s | score events/s | alerts | graph build s | graph nodes / edges | graph status | RSS MB before / after score / after graph |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows + ([big_row] if big_row else []):
        g = r["graph"] or {}
        L.append(f"| {r['what']} | {r['events']} | {fmt(r['load_events_per_second'], 0)} | {fmt(r['replay_events_per_second'], 0)} | {fmt(r['score_events_per_second'], 0)} | {r['alerts']} | "
                 f"{r['graph_seconds']:.1f} | {g.get('nodes', '-')} / {g.get('edges', '-')} | {r['graph_status']} | "
                 f"{fmt(r['rss_mb_before'], 0)} / {fmt(r['rss_mb_after_score'], 0)} / {fmt(r['rss_mb_after_graph'], 0)} |")
    if rows:
        L += ["", f"Run windows: median batch load {fmt(median([r['load_events_per_second'] for r in rows]), 0)} events/s, median replay "
                  f"{fmt(median([r['replay_events_per_second'] for r in rows]), 0)} events/s, median scoring "
                  f"{fmt(median([r['score_events_per_second'] for r in rows]), 0)} events/s, median graph build {fmt(median([r['graph_seconds'] for r in rows]), 1)} s."]
    if big_row:
        L += [f"The {big_row['what']}, {big_row['file_mb']:.0f} MiB: read + re-tag {fmt(big_row['read_events_per_second'], 0)} events/s."]
    L += [f"Peak working set of this process: {fmt(peak, 0)} MB."]
    doc = {"question": "J7", "runs": rows, "big": big_row, "peak_working_set_mb": peak, "cap_minutes": cap_minutes}
    js, md = lab.write("performance", doc, L)
    print(f"J7 performance: {md}")
    return 0


# -- main ------------------------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Package J part 2: the pre-registered experiments, one command per question (aggregate numbers only)")
    ap.add_argument("question", choices=QUESTIONS + ("all",))
    ap.add_argument("--label", choices=["practice", "official"], required=True)
    ap.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    ap.add_argument("--pool", help="pool of normal rates (default <recordings>/confidence/pool.json)")
    ap.add_argument("--out-dir", help="practice only: JSON output folder (default <project>/recordings/experiments/v2/<label>[-v1runs])")
    ap.add_argument("--results-dir", help="practice only: Markdown output folder (default docs/results/v2)")
    ap.add_argument("--vm-label", default="vm")
    ap.add_argument("--runs", nargs="+", help="scenarios (J1/J2/J7: s1 s2 ...; J6: overlay specs s1:3 ...; J3: b1 b2)")
    ap.add_argument("--until", help="practice only: runs started on or before this UTC day")
    ap.add_argument("--last", type=int, help="newest N runs per scenario (J1/J2/J7)")
    ap.add_argument("--laptop", help="laptop snapshot (J4/J5a; default by label)")
    ap.add_argument("--alerts", nargs="+", help="J4: alert databases to count instead of scoring the snapshot")
    ap.add_argument("--rescore", action="store_true", help="J4: score the snapshot again even if its alert db exists")
    ap.add_argument("--friends", help="J4 official: friends' statistics root (default <recordings>/friends)")
    ap.add_argument("--host", help="J5a: the machine when the snapshot holds several")
    ap.add_argument("--bootstrap", type=int, default=K.BOOTSTRAP_B, help="J5a: bootstrap replicates for the sideband")
    ap.add_argument("--volumes", nargs="+", type=int, help="J6")
    ap.add_argument("--seeds", nargs="+", type=int, help="J6")
    ap.add_argument("--r4-seeds", type=int, help="J6")
    ap.add_argument("--overlay-json", help="J5b: the overlay results to read (default this label's)")
    ap.add_argument("--big", help="J7: a recording file for the large-recording measurement (default: the largest laptop day of the label's days)")
    ap.add_argument("--skip-big", action="store_true", help="J7: run windows only")
    ap.add_argument("--graph-cap-minutes", type=float, default=20.0)
    ap.add_argument("--of", choices=sorted(evaluation.TAGS), default=evaluation.CURRENT,
                    help=f"official mode: whose official runs ({evaluation.CURRENT} = this evaluation's own, the default; "
                         "v1 = v1's runs and test week re-scored with this code: the regression)")
    a = ap.parse_args(argv)
    try:
        lab = Lab(a.label, a.recordings, a.pool, a.out_dir, a.results_dir, a.vm_label, a.until, a.last, of=a.of)
    except ValueError as e:
        print(f"Refusing: {e}")
        return 2
    if lab.official and a.question not in OFFICIAL_QUESTIONS + ("all",):
        print(f"Refusing: {a.question} is a v1 result (J5-J7), not part of the {evaluation.CURRENT} pre-registration "
              f"({PREREG}); official mode runs {', '.join(OFFICIAL_QUESTIONS)}")
        return 2
    problems = lab.problems()
    if problems:
        for p in problems:
            print(f"  FAIL  {p}")
        print("Refusing to run.")
        return 2
    if lab.official and (a.runs or a.last or a.until or a.big or a.alerts or a.volumes or a.seeds or a.r4_seeds or a.laptop or a.overlay_json
                         or a.friends or a.vm_label != "vm" or a.bootstrap != K.BOOTSTRAP_B or a.out_dir or a.results_dir):
        # official mode: the pre-registered data, every run, nothing chosen on the command line (review 2026-10-30); the
        # output folders too (review 2026-11-13: --out-dir could have overwritten v1's official JSON)
        print("  FAIL  official mode scores every official run and the TEST snapshot as pre-registered: --runs, --last, --until, --big, "
              "--alerts, --laptop, --overlay-json, --volumes, --seeds, --r4-seeds, --friends, --vm-label, --bootstrap, --out-dir and "
              "--results-dir are refused")
        return 2
    print(f"{a.label} mode" + (" (official: frozen values, pool, baselines and hub list verified)" if lab.official else " (dev data only)"))
    todo = list(OFFICIAL_QUESTIONS if lab.official else QUESTIONS) if a.question == "all" else [a.question]
    if a.question == "all" and not lab.official:
        todo.remove("blind")
    codes = {}
    for q in todo:
        print(f"\n== {q} ==")
        if lab.official and q in ("detection", "story") and not OWN[lab.of]:
            # v3 adds no own scenario: its own-scenario checks are the regression (--of v1 / --of v2)
            print(f"  {lab.of} has no own scenarios of its own: run detection/story with --of v1 or --of v2 (the regression)")
            codes[q] = 0
            continue
        try:
            if q == "detection":
                codes[q] = cmd_detection(lab, a.runs)
            elif q == "story":
                codes[q] = cmd_story(lab, a.runs)
            elif q == "blind":
                codes[q] = cmd_blind(lab, a.runs)
            elif q == "false-alerts":
                codes[q] = cmd_false_alerts(lab, a.laptop, a.alerts, a.rescore, a.friends)
            elif q == "a16":
                codes[q] = cmd_a16(lab, a.laptop, a.host, a.bootstrap)
            elif q == "overlay":
                codes[q] = cmd_overlay(lab, a.runs, a.volumes, a.seeds, a.r4_seeds)
            elif q == "calibration":
                codes[q] = cmd_calibration(lab, a.overlay_json)
            elif q == "performance":
                codes[q] = cmd_performance(lab, a.runs, a.big, a.graph_cap_minutes, a.skip_big)
        except (OSError, ValueError, RuntimeError, KeyError) as e:
            print(f"  FAIL  {q}: {e}")
            codes[q] = 2
    bad = {q: c for q, c in codes.items() if c}
    print("\n" + ("all questions done" if not bad else "not done: " + ", ".join(f"{q} (exit {c})" for q, c in bad.items())))
    return max(codes.values()) if codes else 2


if __name__ == "__main__":
    sys.exit(main())
