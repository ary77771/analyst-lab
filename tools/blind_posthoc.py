"""J3 post-hoc check of the official blind runs (LABELLED POST-HOC; the pre-registered J3 score is
`experiments.py blind --label official` and stands unchanged).

    python tools/blind_posthoc.py        # writes docs/results/v2/b1b2-seen-posthoc.md (v2 code; v1's
                                         # docs/results/j3-blind-posthoc.md is never overwritten)

Why: the blind writer's answer sheets used a slightly different layout than the checkers read
(`windows_programs` as a role map, a `files:` section, no `count`), and listed no
`alert_expected`, so the pre-registered score is "FAIL / NONE EXPECTED" by construction
(prereg section 3). This script reports, clearly separated from that score:
  1. the timeline and graph checkers run against a mechanical TRANSLATION of each sheet into the
     checkers' layout (docs/results/blind/b?.yaml; the writer's originals beside them; reviewed
     independently, VERIFICATION_LOG 2026-10-31);
  2. detection judged by the rule fixed BEFORE looking (VERIFICATION_LOG, commit 1df1ab2): a run
     is detected if an alert at or above the frozen floor has evidence naming one of the
     scenario's own files, or tied by process identity (Sysmon GUID; for agent port records,
     process number + owner start time, as the checker does) to an anchored scenario process;
  3. every hypothesis the graph drew between scenario nodes, with its truth judged by hand from
     the writer's source code (HYPOTHESIS_TRUTH below, each with its reason).
Detectors, frozen values and checkers are unchanged (official mode is verified first).
Prints and writes rule ids, titles, levels, roles and counts only (VM lab data).
"""

import json
import ntpath
import os
import re
import subprocess
import sys
import tempfile

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_alerts import window  # noqa: E402
from check_scenario import Checker, fill, find_run, guid, read_label, run_server  # noqa: E402
from engine import config, detect, score  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402
from engine.replay import parse_time, read_recordings  # noqa: E402
from engine.store import EventStore  # noqa: E402

REC = os.path.join(PROJECT_ROOT, "recordings")
SHEETS = os.path.join(PROJECT_ROOT, "docs", "results", "blind")
# v1's file (docs/results/j3-blind-posthoc.md, made at freeze-v1) is never written again: this code
# is version 2, and its re-score of B1/B2 is labelled SEEN (B1's look-alike rule was designed after
# B1's miss was known; v2 pre-registration).
OUT = os.path.join(PROJECT_ROOT, "docs", "results", "v2", "b1b2-seen-posthoc.md")
OUT_JSON = os.path.join(REC, "experiments", "v2", "b1b2-seen-posthoc.json")

# The official runs that were recorded (series 20261031-145346 and 20261031-163106; the 4 that
# could not start are listed by the pre-registered J3 table).
RUNS = {"b1": ["20261031-152821-38e3", "20261031-154813-994a", "20261031-160752-4131",
               "20261031-163107-62c9", "20261031-172403-c6c0"],
        "b2": ["20261031-145347-9e34", "20261031-151054-83bd", "20261031-164959-c775",
               "20261031-170648-0787", "20261031-174418-ea1a"]}
OWN_FILES = {"b1": {"b1_setup.exe", "scvhost.exe", "cleanup.cmd"},
             "b2": {"b2_sync.exe", "wsyncsvc.exe", "b2_job.ps1"}}
# Truth of each link the graph proposed, from the writer's code (b?/src/main.go), judged by hand.
HYPOTHESIS_TRUTH = {
    ("b1", "cleanup_script started_with_file_argument cleanup_shell"):
        (True, "scvhost.exe runs cmd.exe /c cleanup.cmd"),
    ("b1", "test_server content_from cleanup_script"):
        (False, "the batch text is built in the program; the beacons fetch nothing it uses"),
    ("b1", "test_server fetched_then_ran cleanup_shell"):
        (False, "cmd.exe is started by design after the 8th beacon, not because of a reply"),
    ("b2", "job_script started_with_file_argument renamed_shell"):
        (True, "wsyncsvc.exe /c powershell.exe ... -File b2_job.ps1"),
    ("b2", "job_script started_with_file_argument script_host"):
        (True, "powershell.exe -File b2_job.ps1"),
    ("b2", "test_server content_from job_script"):
        (False, "the script text is a constant in the program; the check-in reply is discarded"),
    ("b2", "test_server content_from shell_file"):
        (False, "wsyncsvc.exe is a copy of the VM's own cmd.exe"),
    ("b2", "test_server fetched_then_ran renamed_shell"):
        (False, "the renamed shell is started by design; the check-in reply is discarded"),
}


def run_checker(tool, scenario, rid):
    sheet = os.path.join(SHEETS, f"{scenario}.yaml")
    p = subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "tools", tool), scenario, "--run-id", rid,
                        "--recordings", REC, "--sheet", sheet], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.stdout


def judge_alerts(scenario, rid, truth):
    run = find_run(REC, scenario, 1, rid)
    lo, hi = window(REC, run)
    server = run_server(run)
    win = [r for r in read_label(REC, "vm") if r.get("time") and lo <= parse_time(r["time"]) <= hi]
    c = Checker(fill(truth, server), win, server)
    anchored = c.anchor()
    records = [r for r in read_recordings(recording_files(os.path.join(REC, "vm")), retag=True)
               if r.get("time") and lo <= parse_time(r["time"]) <= hi]
    floor = detect.LEVELS.index(config.min_level())
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "run.db")
        st = EventStore(db)
        st.insert(records)
        st.close()
        con = detect.open_store(db)
        try:
            errors = []
            alerts = score.score(con, score.load_rules(), score.load_baseline(), errors=errors)
            for a in alerts:
                names, roles = set(), set()
                for key in a.evidence:
                    cur = con.execute("SELECT * FROM events WHERE dedup_key = ?", (key,))
                    row = cur.fetchone()
                    if not row:
                        continue
                    d = {k[0]: v for k, v in zip(cur.description, row)}
                    names |= {ntpath.basename(str(d[f])).lower() for f in ("Image", "ParentImage", "TargetFilename") if d.get(f)}
                    if str(d.get("type") or "").startswith("PORT_LISTEN"):
                        roles |= {role for role in c.start_of if c.port_owner_ok(d, role)}
                    ids = {guid(d[f]) for f in ("ProcessGuid", "ParentProcessGuid") if d.get(f)}
                    roles |= {role for role, g in c.guid_of.items() if g in ids}
                rows.append({"rule": a.rule_id, "title": a.title, "level": a.level,
                             "raised": detect.LEVELS.index(a.level) >= floor,
                             "tied": bool(names & OWN_FILES[scenario] or roles), "roles": sorted(roles)})
        finally:
            con.close()
    return {"anchored": anchored, "errors": len(errors), "alerts": rows}


def main():
    from engine import evaluation
    problems = evaluation.code_problems() + config.verify_official()       # the frozen v2 code only (review 2026-11-13)
    if problems:
        print("official values do not verify:", *problems, sep="\n  ")
        return 2
    results = {}
    for scenario, ids in RUNS.items():
        with open(os.path.join(SHEETS, f"{scenario}.yaml"), encoding="utf-8") as f:
            truth = yaml.safe_load(f)
        for rid in ids:
            timeline = run_checker("check_scenario.py", scenario, rid)
            graph = run_checker("check_graph_scenario.py", scenario, rid)
            facts = re.findall(r"fact  PASS", graph)
            fails = re.findall(r"FAIL  fact '([^']+)'", graph)
            hyps = re.findall(r"unlisted hypothesis between scenario nodes: (.+?) \((\w+), (\w+)\)", graph)
            other = [ln.strip() for ln in graph.splitlines() if "FAIL" in ln and "hypothesis" not in ln
                     and "FAIL  fact" not in ln and "RESULT" not in ln]
            results[rid] = {"scenario": scenario,
                            "timeline": "PASS" if "RESULT: PASS" in timeline else "FAIL",
                            "facts_found": len(facts), "facts_expected": len(truth["expected_graph"]["facts"]),
                            "facts_missing": fails, "graph_other_fails": other,
                            "hypotheses": [{"link": h, "row": r, "band": b} for h, r, b in hyps],
                            **judge_alerts(scenario, rid, truth)}
            print(f"{scenario.upper()} {rid}: timeline {results[rid]['timeline']}, facts "
                  f"{len(facts)}/{results[rid]['facts_expected']}, alerts tied "
                  f"{sum(x['raised'] and x['tied'] for x in results[rid]['alerts'])}")
    write(results)
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)
    print("written:", OUT)
    return 0


def write(results):
    L = ["# B1/B2 re-scored with version 2's code (LABELLED SEEN and POST-HOC)", "",
         "*Generated by `python tools/blind_posthoc.py` with the v2 code (tag freeze-v2). v1's pre-registered J3 "
         "result (`j2-blind-*-official.md`) and v1's post-hoc check (`j3-blind-posthoc.md`) stand unchanged. B1 and B2 "
         "are SEEN: v2's look-alike rule was designed after B1's miss was known, so this is no test of it. Same "
         "method as v1's post-hoc check: the sheet translation (`docs/results/blind/`) and the detection rule "
         "fixed in VERIFICATION_LOG before v1's alerts were looked at (commit 1df1ab2).*", "",
         "## Per run", "",
         "| scenario | run | timeline (translated sheet) | graph facts | missing facts | other graph notes | raised alerts tied to the scenario | raised alerts not tied |",
         "|---|---|---|---|---|---|---|---|"]
    for rid, r in results.items():
        tied = sorted({f"{a['rule'] if a['rule'].startswith('analystlab') else a['title']}" for a in r["alerts"] if a["raised"] and a["tied"]})
        untied = sorted({f"{a['rule'] if a['rule'].startswith('analystlab') else a['title']}" for a in r["alerts"] if a["raised"] and not a["tied"]})
        L.append(f"| {r['scenario'].upper()} | {rid} | {r['timeline']} | {r['facts_found']}/{r['facts_expected']} | "
                 f"{'; '.join(r['facts_missing']) or '-'} | {'; '.join(r['graph_other_fails']) or '-'} | "
                 f"{', '.join(tied) or 'none'} | {', '.join(untied) or 'none'} |")
    L += ["", "## Hypotheses the graph drew between scenario nodes (truth judged from the writer's code)", "",
          "| scenario | link | row | band | runs | true? | why |", "|---|---|---|---|---|---|---|"]
    tally = {}
    for r in results.values():
        for h in r["hypotheses"]:
            k = (r["scenario"], h["link"], h["row"], h["band"])
            tally[k] = tally.get(k, 0) + 1
    by_truth = {True: {}, False: {}, None: {}}
    for (sc, link, row, band), n in sorted(tally.items()):
        known = HYPOTHESIS_TRUTH.get((sc, link))
        ok = known[0] if known else None
        by_truth[ok][band] = by_truth[ok].get(band, 0) + n
        L.append(f"| {sc.upper()} | {link} | {row} | {band} | {n} | "
                 f"{'yes' if ok else 'no' if ok is False else 'NOT JUDGED'} | {known[1] if known else '-'} |")
    L += ["", "Bands of true links: " + json.dumps(by_truth[True]) + "; of false links: " + json.dumps(by_truth[False])
          + ("; NOT JUDGED: " + json.dumps(by_truth[None]) if by_truth[None] else ""), ""]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    raise SystemExit(main())
