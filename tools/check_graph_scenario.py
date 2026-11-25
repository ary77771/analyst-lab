"""Week-2 checkpoint (VERIFICATION_PLAN stage 9, gate 1 "S1 replay vs ground truth"): does the
evidence graph, rebuilt by REPLAYING a recorded scenario run, match the scenario's answer sheet?

    python tools/check_graph_scenario.py s1                 # newest recorded run of S1
    python tools/check_graph_scenario.py s1 --run-id <id>   # the run tools/run_in_vm.py started
    python tools/check_graph_scenario.py s1 --speed 10      # replay at 10x real time (0 = instant)
    python tools/check_graph_scenario.py s1 --run-id <id> --store <db>   # a prepared store (noise overlay,
                                                            # package J) instead of replaying; never official

1. Finds the run's time window (recordings/vmruns, cut at neighbouring runs: the one window
   every checker uses, check_scenario.run_window).
2. Replays the VM recording of that window into a FRESH event store (engine/replay.py) and builds
   the evidence graph from it (engine/graph.py): the same path a demo by replay takes. Records are
   re-tagged with today's origin rules first (engine/retag.py, over the whole stream), as the live
   loop and engine.load do. With ANALYSTLAB_OFFICIAL=1, config.verify_official() runs first.
3. Resolves the answer sheet's roles to graph nodes by name and time only, exactly one each:
   the programs, <program>_file (the file named like the program, under payload_path_contains,
   with known content), test_server (the address this run recorded; see check_scenario) and
   listen_port (the port the answer sheet's `listen` names, with an edge in this run).
4. Checks: every expected fact exactly once; no other fact links two scenario nodes (a hypothesis
   must never be graded a fact); the scenario nodes carry exactly the expected gaps; the alert
   view (subgraph_around the payload's start) contains every expected fact and hypothesis.
4b. Layer 2 (package F, 2026-10-24; needs a pool of normal rates, --pool): every expected
   hypothesis (sheet keys: `claim`, `between`, optional `kind` and `optional: true` for a link the
   story produces only when its steps fall inside the timing window) is exactly one layer-2
   hypothesis edge between its two roles, with band, reason,
   alternative explanation and cited events; NO other hypothesis links two scenario nodes (so a
   scenario whose sheet lists none, like S2, can fail); what the method implies is re-derived from
   the RAW records alone (the process's life from its events 1 and 5: shorter than the window ->
   "not assessable"; too short to beat 10 % -> band "low"; N = that process's raw cause events
   within the competing span of the cited cause); the sheet's `expected_confidence`, if any, is
   printed but not checked (the band follows from the frozen method: hypotheses.md Q1). A true
   link graded low is printed as a LIMITATION, never hidden.
5. Traces every event each expected fact or hypothesis cites back to the raw recording and
   re-checks, field by field and without the graph code, that the event says what the edge claims
   (timing rows: the cause and the effect belong to the same process and the effect lies inside
   the window after the cause).
Expectations come only from the answer sheet (rule 8). Prints counts and the scenario's own
program names only. Exit 0 = PASS, 1 = FAIL.
"""

import argparse
import math
import ntpath
import os
import sqlite3
import sys
import tempfile
import time
from collections import Counter

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_graph import named_program  # noqa: E402  (its own parser, not the graph's)
from check_scenario import find_run, run_server, run_window, sheet_path  # noqa: E402
from engine import config  # noqa: E402
from engine.graph import Layer2, build_graph, subgraph_around  # noqa: E402
from engine.report import view as report_view  # noqa: E402
from engine.jsonl import recording_files  # noqa: E402
from engine.replay import parse_time, read_recordings, replay  # noqa: E402
from engine.store import CORE_NAMES, EventStore  # noqa: E402


def lower(s):
    return str(s or "").lower()


def same_path(a, b):
    """Independent of engine/graph.norm_path on purpose: case-insensitive, \\\\?\\ ignored."""
    strip = lambda p: lower(p).replace("/", "\\").removeprefix("\\\\?\\").removeprefix("\\??\\")
    return bool(a) and strip(a) == strip(b)


def same_start(a, b, slack=1.0):
    """Two "YYYY-MM-DD HH:MM:SS.fff" UTC times (a port owner's start, an event 1's UtcTime) agree
    within slack seconds. Independent of the graph code on purpose."""
    try:
        ta, tb = (parse_time(str(x).replace(" ", "T") + "Z") for x in (a, b))
    except (TypeError, ValueError):
        return False
    return ta is not None and tb is not None and abs((ta - tb).total_seconds()) <= slack


def sysmon_sha(rec):
    for part in str((rec.get("data") or {}).get("Hashes", "")).split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].upper()
    return None


def utc(rec):
    """A raw Sysmon record's UtcTime as a datetime (None if missing)."""
    try:
        return parse_time(str((rec.get("data") or {}).get("UtcTime")).replace(" ", "T") + "Z")
    except (TypeError, ValueError):
        return None


def frozen_confidence():
    """The frozen numbers the method checks need, read from config/frozen.yaml directly (not
    through the graph code): the window, the band edge and the competing span."""
    with open(os.path.join(PROJECT_ROOT, "config", "frozen.yaml"), encoding="utf-8") as f:
        c = yaml.safe_load(f)["confidence"]
    return {"before": float(c["window_before_seconds"]), "after": float(c["window_after_seconds"]),
            "band_medium": float(c["band_medium"]), "span": float(c["competing_span_seconds"])}


class GraphCheck:
    def __init__(self, truth, G, lo, hi, server, say=print, cfg=None):
        self.truth, self.G, self.lo, self.hi, self.say = truth, G, lo, hi, say
        self.server = server          # (ip, port) this run used (check_scenario.run_server)
        self.cfg = cfg or frozen_confidence()
        self.ok = True
        self.roles = {}
        self.found_hyps = []          # (sheet entry, edge data, from node, to node)
        # package J part 2 (tools/experiments.py): counts behind the verdict, for precision / recall.
        # Only counters: nothing here changes what is checked, printed or returned.
        self.tally = Counter()

    def fail(self, msg):
        self.ok = False
        self.say(f"  FAIL  {msg}")

    def _in_window(self, t):
        return t is not None and self.lo <= t <= self.hi

    # -- 3. roles -----------------------------------------------------------------------------
    def resolve(self):
        progs = {k: lower(v) for k, v in self.truth["programs"].items()}
        needed = {r for f in self.truth["expected_graph"]["facts"] for r in (f["from"], f["to"])}
        needed |= {r for h in self.truth["expected_graph"].get("hypotheses", []) for r in h.get("between", [])}
        # programs in the answer sheet's order: a later program must have been started by an
        # earlier one (cmd.exe / powershell.exe run elsewhere in the VM too, e.g. the runner)
        order = [r for r in progs if r in needed] + sorted(r for r in needed if r not in progs)
        groups = self.truth.get("file_groups", {})
        for role in order:
            if role in groups:                       # a group of files: exactly `count` file nodes
                g = groups[role]
                # only files a scenario process CREATED in this run (review 2026-10-19: the runner's
                # own clean-up just before a manual re-run fell inside the window)
                makers = {self.roles[r] for r in progs if r in self.roles}
                found = sorted(n for n, d in self.G.nodes(data=True) if d.get("kind") == "file"
                               and lower(g["path_contains"]) in lower(d.get("path"))
                               and lower(d.get("path")).endswith(lower(g["suffix"]))
                               and any(e.get("kind") == "created" and e.get("grade") == "fact" and u in makers
                                       and self._in_window(e.get("time")) for u, _, e in self.G.in_edges(n, data=True)))
                if len(found) != g["count"]:
                    self.fail(f"role {role}: {len(found)} matching file node(s) in this run, exactly {g['count']} expected")
                else:
                    self.roles[role] = found
                continue
            if role in progs:
                found = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "process"
                         and lower(d.get("label")) == progs[role] and d.get("start_recorded")
                         and self._in_window(d.get("start"))]
                earlier = [self.roles[r] for r in progs if r in self.roles and r != role]
                if list(progs).index(role) > 0 and len(found) > 1:
                    # only to pick among same-named processes: a single wrong one still fails
                    # later, with a clearer message, at its "started" fact
                    found = [n for n in found if any(
                        d.get("kind") == "started" and d.get("grade") == "fact"
                        for p in earlier for d in (self.G.get_edge_data(p, n) or {}).values())]
            elif role.endswith("_file") and role[:-5] in progs:
                inside = lower(self.truth.get("payload_path_contains"))
                found = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "file"
                         and lower(d.get("label")) == progs[role[:-5]] and inside in lower(d.get("path"))
                         and d.get("sha256")]
            elif role.endswith("_autostart") and role[:-10] in progs:
                # the autostart entries that program set in this run (version 2, event 13)
                maker = self.roles.get(role[:-10])
                found = sorted({v for _, v, e in (self.G.out_edges(maker, data=True) if maker else [])
                                if e.get("kind") == "set_autostart" and e.get("grade") == "fact"
                                and self._in_window(e.get("time"))})
            elif role == "test_server":
                ip, port = self.server
                found = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "endpoint"
                         and n.endswith(f":{ip}:{port}")]
            elif role == "listen_port" and self.truth.get("listen"):
                want = self.truth["listen"]          # the port the answer sheet says is opened
                found = [n for n, d in self.G.nodes(data=True) if d.get("kind") == "port"
                         and str(d.get("port")) == str(want["port"]) and str(d.get("ip")) == str(want["ip"])
                         and any(self._in_window(e.get("time")) for _, _, e in self.G.in_edges(n, data=True))]
            else:
                self.fail(f"role '{role}' is not defined by the answer sheet")
                continue
            if len(found) != 1:
                what = "with known content " if role.endswith("_file") else ""
                self.fail(f"role {role}: {len(found)} matching node(s) {what}in this run, exactly 1 expected")
                continue
            self.roles[role] = found[0]
        if self.ok:
            sizes = [f"{r} ({len(n)} files)" if isinstance(n, list) else r for r, n in sorted(self.roles.items())]
            self.say(f"  roles: {', '.join(sizes)} (one node each, file groups as counted)")
        return self.ok

    # -- 4. facts, hypotheses, gaps, alert view --------------------------------------------------
    def edges(self, u, v, kind=None):
        return [d for d in (self.G.get_edge_data(u, v) or {}).values()
                if d.get("grade") == "fact" and (kind is None or d["kind"] == kind)]

    def nodes_of(self, role):
        """A role's node(s): one node, or the list of a file group."""
        n = self.roles[role]
        return list(n) if isinstance(n, list) else [n]

    def role_names(self):
        return {n: r for r in self.roles for n in self.nodes_of(r)}

    def check_facts(self):
        expected = self.truth["expected_graph"]["facts"]
        self.found = []                               # (fact, edge, from node, to node)
        for f in expected:
            es = [(e, u, v) for u in self.nodes_of(f["from"]) for v in self.nodes_of(f["to"])
                  for e in self.edges(u, v, f["edge"])]
            n = f.get("count", 1)                     # "count": exactly N such facts (default 1)
            self.tally["facts_expected"] += n
            self.tally["facts_found"] += min(len(es), n)
            self.tally["facts_surplus"] += max(len(es) - n, 0)
            if len(es) == n:
                cited = sum(len(e["evidence"]) for e, _, _ in es)
                self.say(f"  fact  PASS  {f['says']}  ({n} edge(s), layer {es[0][0]['layer']}, {cited} cited event(s))")
                self.found += [(f, e, u, v) for e, u, v in es]
            else:
                self.fail(f"fact '{f['says']}': {len(es)} '{f['edge']}' fact edge(s), exactly {n} expected")
        allowed = {(u, f["edge"], v) for f in expected for u in self.nodes_of(f["from"]) for v in self.nodes_of(f["to"])}
        names = self.role_names()
        extra = 0
        for u in names:
            for v in names:
                for d in self.edges(u, v):
                    if (u, d["kind"], v) not in allowed:
                        extra += 1
                        self.fail(f"unexpected fact: {names[u]} {d['kind']} {names[v]}")
        self.tally["facts_unexpected"] += extra
        if not extra:
            self.say("  no other fact links two scenario nodes: PASS")
        # anything else the scenario wrote into its own folder in this run is part of its story too:
        # a second payload (e.g. one without a fingerprint) must not go unseen (review 2026-10-18)
        folders = [lower(x) for x in [self.truth.get("payload_path_contains")]
                   + [g["path_contains"] for g in self.truth.get("file_groups", {}).values()] if x]
        # ... by a scenario process (review 2026-10-19: not the runner's clean-up before a re-run)
        progs = {self.roles[r] for r in self.truth["programs"] if r in self.roles}
        touched = lambda n: any(self._in_window(e.get("time")) and (u in progs or v in progs)
                                for u, v, e in list(self.G.in_edges(n, data=True)) + list(self.G.out_edges(n, data=True)))
        self.scenario_files = [n for n, dd in self.G.nodes(data=True) if dd.get("kind") == "file"
                               and any(x in lower(dd.get("path")) for x in folders) and touched(n)]
        others = [n for n in self.scenario_files if n not in names]
        self.tally["files_unexpected"] += len(others)
        if others:
            self.fail(f"{len(others)} other file node(s) in the scenario's folder in this run (expected only the story's files)")
        else:
            self.say("  no other file in the scenario's folder: PASS")

    # -- 4b. hypotheses (layer 2) ----------------------------------------------------------------
    def hyp_edges(self, u, v):
        return [d for d in (self.G.get_edge_data(u, v) or {}).values()
                if d.get("grade") == "hypothesis" and d.get("layer") == 2]

    def check_hypotheses(self, raw_by_key):
        names = self.role_names()
        expected = self.truth["expected_graph"].get("hypotheses", [])
        listed = set()
        for h in expected:
            a, b = (self.roles[r] for r in h["between"])
            if self.edges(a, b) or self.edges(b, a):
                self.tally["hyps_expected"] += 1
                self.tally["hyps_as_fact"] += 1
                self.fail(f"hypothesis graded as a fact: {h['claim']}")
                continue
            es = [(d, a, b) for d in self.hyp_edges(a, b)] + [(d, b, a) for d in self.hyp_edges(b, a)]
            if h.get("kind"):
                es = [e for e in es if e[0]["kind"] == h["kind"]]
            if not es and h.get("optional"):
                # a link the story produces only when its steps fall inside the timing window
                # (e.g. S1's payload starting within 10 s of the connection): absent is fine ONLY
                # when the raw records show no such pair (review of the build, finding 8)
                if self.raw_pair_in_window(h, a, b, raw_by_key):
                    self.tally["hyps_expected"] += 1
                    self.fail(f"optional hypothesis '{h['claim']}': the raw records hold a cause and effect inside the "
                              f"timing window, but no layer-2 edge was drawn")
                else:
                    self.tally["hyps_optional_absent"] += 1
                    self.say(f"  hypothesis  note  optional, not produced in this run (and the raw records hold no "
                             f"cause/effect pair inside the window): {h['claim']}")
                continue
            self.tally["hyps_expected"] += 1
            if len(es) != 1:
                self.tally["hyps_wrong_count"] += 1
                self.fail(f"hypothesis '{h['claim']}': {len(es)} layer-2 hypothesis edge(s) between its roles, exactly 1 expected")
                continue
            d, u, v = es[0]
            listed.add((u, d["kind"], v))
            missing = [k for k in ("band", "claim", "reason", "alternative", "evidence", "row") if not d.get(k)]
            if missing:
                self.fail(f"hypothesis '{h['claim']}' lacks {missing}")
                continue
            if d.get("via") not in {self.roles[r] for r in self.truth["programs"] if r in self.roles}:
                self.fail(f"hypothesis '{h['claim']}' goes through a process that is not one of the scenario's programs")
                continue
            detail = f"{d['row']} {d['kind']}, band {d['band']} ({d['basis']})"
            if d["row"].startswith("T"):
                if d.get("p") is None or not d.get("n_causes"):
                    self.fail(f"hypothesis '{h['claim']}' is a timing row without p or N")
                    continue
                detail += f", p {d['p']:.2%}, N {d['n_causes']}, life {d['life_seconds']:.1f} s" + \
                          ("" if d["assessable"] else ", not assessable") + (", provisional" if d.get("provisional") else "")
            self.say(f"  hypothesis  PASS  {h['claim']}  ({detail}, {len(d['evidence'])} cited event(s))")
            if "expected_confidence" in h:
                self.say(f"    note: the sheet's expected_confidence '{h['expected_confidence']}' is not checked: the band "
                         f"follows from the frozen method (docs/plans/reports/hypotheses.md Q1)")
            if d["band"] == "low" and d["basis"] == "formula":
                self.say(f"    LIMITATION: a true link graded low: {d['reason']}")
            self.tally["hyps_found"] += 1
            self.found_hyps.append((h, d, u, v))
            self.method_check(h, d, raw_by_key)
        # no other hypothesis may link two scenario nodes (a sheet that lists none, like S2, can fail)
        unlisted = []
        for u in names:
            for v in names:
                for d in self.hyp_edges(u, v):
                    if (u, d["kind"], v) not in listed:
                        unlisted.append(f"{names[u]} {d['kind']} {names[v]} ({d['row']}, {d['band']})")
        self.tally["hyps_unlisted"] += len(unlisted)
        for x in unlisted:
            self.fail(f"unlisted hypothesis between scenario nodes: {x}")
        if not unlisted:
            self.say("  no other hypothesis links two scenario nodes: PASS")
        touching = sum(1 for u, v, d in self.G.edges(data=True) if d.get("grade") == "hypothesis"
                       and (u in names) != (v in names) and self._in_window(d.get("time")))
        self.tally["hyps_touching"] += touching
        if touching:
            self.say(f"  note: {touching} hypothesis edge(s) touch one scenario node and one other node in this run")
        # invariants over the whole graph
        bad = [d for _, _, d in self.G.edges(data=True) if d.get("grade") == "hypothesis"
               and (not d.get("alternative") or not d.get("reason")
                    or (d.get("assessable") is False and d.get("timing_band") != "low"))]
        if bad:
            self.fail(f"{len(bad)} hypothesis edge(s) break an invariant (reason, alternative, or 'not assessable' not low)")
        s = self.G.graph.get("layer2") or {}
        self.say(f"  layer 2 over the whole replay: {s.get('counts')} sigma_p {s.get('sigma_p', 0):.3f} "
                 f"(assessable {s.get('sigma_p_assessable', 0):.3f}), not drawn {s.get('not_drawn')}")

    def raw_pair_in_window(self, h, a, b, raw_by_key):
        """From the RAW records alone: does the story hold a cause (a connection of the effect's
        own process to/from the endpoint role) with the effect (the file's creation, the child's
        start) inside [cause - before, cause + after]? Then a timing hypothesis is expected."""
        G, R = self.G, self.roles
        kind = h.get("kind")
        data = lambda r: r.get("data") or {}
        ep = next((n for n in (a, b) if G.nodes[n].get("kind") == "endpoint"), None)
        eff = next((n for n in (a, b) if n != ep), None)
        if ep is None or eff is None or kind not in ("content_from", "fetched_then_ran", "remote_command"):
            return False
        ip, port = (self.server if ep == R.get("test_server") else (G.nodes[ep].get("ip"), G.nodes[ep].get("port")))
        effects = []                                           # (time, via guid)
        for r in raw_by_key.values():
            if kind == "content_from" and r.get("event_id") == 11 and same_path(data(r).get("TargetFilename"), G.nodes[eff].get("path")):
                effects.append((utc(r), lower(data(r).get("ProcessGuid"))))
            elif kind != "content_from" and r.get("event_id") == 1 and lower(data(r).get("ProcessGuid")) == lower(G.nodes[eff].get("guid")):
                effects.append((utc(r), lower(data(r).get("ParentProcessGuid"))))
        for te, via in effects:
            for r in raw_by_key.values():
                if r.get("event_id") != 3 or lower(data(r).get("ProcessGuid")) != via or utc(r) is None or te is None:
                    continue
                if kind == "remote_command":
                    ok = lower(data(r).get("Initiated")) == "false" and str(data(r).get("SourceIp")) == str(ip)
                else:
                    ok = (lower(data(r).get("Initiated")) == "true" and str(data(r).get("DestinationIp")) == str(ip)
                          and str(data(r).get("DestinationPort")) == str(port))
                if ok and -self.cfg["before"] <= (te - utc(r)).total_seconds() <= self.cfg["after"]:
                    return True
        return False

    def method_check(self, h, d, raw_by_key):
        """What the frozen method implies, re-derived from the RAW records (no graph code): the via
        process's life from its own events 1 and 5, and N from its raw cause events."""
        if not d["row"].startswith("T"):
            return
        via = lower(self.G.nodes[d["via"]].get("guid"))
        mine = [r for r in raw_by_key.values() if lower((r.get("data") or {}).get("ProcessGuid")) == via]
        t1 = next((utc(r) for r in mine if r.get("event_id") == 1), None)
        t5 = next((utc(r) for r in mine if r.get("event_id") == 5), None)
        if t1 is None or t5 is None:
            self.say("    note: the process has no event 1 or 5 in the raw recording; its life was not re-derived")
        else:
            life = (t5 - t1).total_seconds()                       # wall time >= active time: cautious
            window = self.cfg["before"] + self.cfg["after"]
            if life < window and d["assessable"]:
                self.fail(f"hypothesis '{h['claim']}': the process lived {life:.1f} s (< {window:g} s window) but is graded assessable")
            floor = window / -math.log1p(-self.cfg["band_medium"])   # life below this: within-life rate alone -> low
            if life < floor and d["basis"] == "formula" and d["band"] != "low":
                self.fail(f"hypothesis '{h['claim']}': the process lived {life:.1f} s (< {floor:.0f} s), so the method gives 'low', not '{d['band']}'")
            self.say(f"    method check from the raw records: life {life:.1f} s -> {'not assessable' if life < window else ('low at most' if life < floor else 'any band')}: consistent")
        cause = raw_by_key.get(d["cause"]["key"]) if d.get("cause") else None
        if d["row"] == "T2" or cause is None or utc(cause) is None:
            self.say("    note: N not re-derived (inbound causes need the agent's port records)" if d["row"] == "T2"
                     else "    note: N not re-derived (cited cause not found in the raw recording)")
            return
        tc = utc(cause)
        n = sum(1 for r in mine if r.get("event_id") == 3 and lower((r.get("data") or {}).get("Initiated")) == "true"
                and utc(r) is not None and abs((utc(r) - tc).total_seconds()) <= self.cfg["span"])
        if n != d["n_causes"]:
            self.fail(f"hypothesis '{h['claim']}': N {d['n_causes']} on the edge, {n} outgoing connections of the process within "
                      f"+-{self.cfg['span']:g} s in the raw recording")
        else:
            self.say(f"    N re-derived from the raw recording: {n}: consistent")

    def check_gaps(self):
        names = self.role_names()
        nodes = list(names) + [n for n in getattr(self, "scenario_files", []) if n not in names]
        names.update({n: "file in the scenario folder" for n in nodes if n not in names})
        actual = sorted((names[n], g["kind"]) for n in nodes for g in self.G.nodes[n]["gaps"]
                        if g["time"] is None or self._in_window(g["time"]))
        expected = sorted((g["node"], g["kind"]) for g in self.truth["expected_graph"].get("gaps", []))
        self.tally["gaps_expected"] += len(expected)
        self.tally["gaps_actual"] += len(actual)
        self.tally["gaps_ok"] += int(actual == expected)
        if actual == expected:
            self.say(f"  gaps  PASS  {len(actual)} on the scenario nodes, as expected")
        else:
            self.fail(f"gaps on the scenario nodes: {actual}, expected {expected}")

    def _lacks(self, H, hypotheses=True):
        """What a view does not show of the expected facts (and hypotheses)."""
        shown = lambda f, u, v: any(e.get("kind") == f["edge"] for e in (H.get_edge_data(u, v) or {}).values())
        groups = self.truth.get("file_groups", {})
        missing = []
        for says in dict.fromkeys(f["says"] for f, _, _, _ in self.found):
            pairs = [(f, u, v) for f, _, u, v in self.found if f["says"] == says]
            f = pairs[0][0]
            # a group (40 files) can't all fit a 60-node view: at least one of its edges must show
            if f["from"] in groups or f["to"] in groups:
                ok = any(shown(*p) for p in pairs)
            else:
                ok = all(shown(*p) for p in pairs)
            if not ok:
                missing.append(says)
        if hypotheses:
            for h, d, u, v in self.found_hyps:
                if not any(e.get("kind") == d["kind"] and e.get("grade") == "hypothesis"
                           for e in (H.get_edge_data(u, v) or {}).values()):
                    missing.append(h["claim"])
        return missing

    def _scenario_processes(self):
        return [self.roles[r] for r in self.truth["programs"] if r in self.roles
                and self.G.nodes[self.roles[r]].get("kind") == "process"]

    def _hubbed(self, H):
        """Scenario processes the view kept but did not walk through (hubs)."""
        names = self.role_names()
        return [names.get(n, n) for n in self._scenario_processes() if n in H and H.nodes[n].get("hub")]

    def check_alert_view(self, hubs=None):
        # the payload if there is one, else the answer sheet's first program (never an endpoint);
        # the view is the report's and the dashboard's own (report.view, with the frozen hub list)
        seed = self.roles.get("payload") or next((self.roles[r] for r in self.truth["programs"] if r in self.roles),
                                                 next(iter(self.roles.values())))
        H = report_view(self.G, seed, hubs)
        missing = self._lacks(H)
        self.tally["view_nodes"] = H.number_of_nodes()
        self.tally["view_truncated"] = int(bool(H.graph.get("truncated")))
        if missing:
            self.fail(f"alert view around the payload's start lacks: {missing}")
        elif self._hubbed(H):
            self.fail(f"alert view treats scenario process(es) as hubs: {self._hubbed(H)}")
        else:
            self.tally["view_ok"] = 1
            who = "payload" if "payload" in self.roles else "first program"
            n_hubs = sum(1 for n in H if H.nodes[n].get("hub"))
            self.say(f"  alert view (around the {who}'s start, {H.number_of_nodes()} nodes"
                     f"{', truncated' if H.graph['truncated'] else ''}"
                     f"{f', {n_hubs} hub(s) not followed' if hubs else ', hub suppression off'}): all "
                     f"{len({f['says'] for f, *_ in self.found})} expected facts"
                     f" and {len(self.found_hyps)} expected hypotheses: PASS")
        if hubs:
            self.check_runner_view(hubs)

    def check_runner_view(self, hubs):
        """The stricter view of the hub measurement (docs/results/options-g-hubs-dev.md): started
        ONE STEP AWAY, at the program that started the scenario's first program, at that start's
        time. Every scenario process must be in it and walked through (none treated as a hub), and
        every expected fact must show: hub suppression must never hide the story."""
        G = self.G
        procs = self._scenario_processes()
        if not procs:
            self.fail("runner view: no scenario process resolved, so the strict view cannot be checked")
            return
        first = procs[0]
        runners = [u for u, _, e in G.in_edges(first, data=True) if e.get("kind") == "started"]
        if not runners or G.nodes[first].get("start") is None:
            self.fail("runner view: the first program's starter is not recorded, so the strict view cannot be checked")
            return
        if runners[0] in procs:
            self.fail("runner view: the first program's starter is itself a scenario process (answer sheet order?)")
            return
        H = report_view(G, runners[0], hubs, at=G.nodes[first]["start"])
        names = self.role_names()
        lost = [names.get(n, n) for n in procs if n not in H]
        problems = ([f"lacks process(es) {lost}"] if lost else []) + \
                   ([f"treats scenario process(es) as hubs {self._hubbed(H)}"] if self._hubbed(H) else []) + \
                   ([f"lacks fact(s) {self._lacks(H, hypotheses=False)}"] if self._lacks(H, hypotheses=False) else [])
        if problems:
            self.fail(f"runner view (one step before the first program, hubs not followed): {'; '.join(problems)}")
        else:
            self.tally["runner_view_ok"] = 1
            self.say(f"  runner view (from the first program's starter, {H.number_of_nodes()} nodes): "
                     f"all {len(procs)} scenario process(es) walked, all expected facts shown: PASS")
    # -- 5. trace back to the raw recording ------------------------------------------------------
    def trace(self, raw_by_key):
        G, R = self.G, self.roles
        guid = lambda role: lower(G.nodes[R[role]].get("guid"))
        ip, port = self.server
        progs = {k: lower(v) for k, v in self.truth["programs"].items()}
        named = lambda path, role: lower(ntpath.basename(str(path or ""))) == progs.get(role)
        checked = 0
        groups = self.truth.get("file_groups", {})
        for f, d, u, v in self.found:
            recs = []
            for ev in d["evidence"]:
                rec = raw_by_key.get(ev["key"])
                if rec is None:
                    self.fail(f"'{f['says']}': cited event {ev['event']} not in the raw recording")
                else:
                    recs.append(rec)
            ev1 = lambda: [r for r in recs if r.get("event_id") == 1]
            data = lambda r: r.get("data") or {}
            fh = [r for r in recs if r.get("type") == "FILE_HASH"]
            # the file this fact is about: its target (created/deleted), or its source (ran_as)
            fnode = G.nodes[v] if (f["to"].endswith("_file") or f["to"] in groups) else G.nodes[u]
            if f["edge"] == "started":
                good = any(lower(data(r).get("ProcessGuid")) == guid(f["to"]) and
                           lower(data(r).get("ParentProcessGuid")) == guid(f["from"]) and
                           named(data(r).get("Image"), f["to"]) and named(data(r).get("ParentImage"), f["from"]) for r in ev1())
            elif f["edge"] == "connected_to":
                good = any(r.get("event_id") == 3 and lower(data(r).get("ProcessGuid")) == guid(f["from"]) and
                           named(data(r).get("Image"), f["from"]) and
                           str(data(r).get("DestinationIp")) == ip and
                           str(data(r).get("DestinationPort")) == str(port) and lower(data(r).get("Initiated")) == "true"
                           for r in recs)
            elif f["edge"] == "created":
                made = [r for r in recs if r.get("event_id") == 11 and lower(data(r).get("ProcessGuid")) == guid(f["from"])
                        and named(data(r).get("Image"), f["from"])
                        and same_path(data(r).get("TargetFilename"), fnode.get("path"))]
                # the file node's content: the agent's fingerprint of exactly that creation event
                good = any(r.get("type") == "FILE_HASH" and data(r).get("hash_status") == "ok"
                           and lower(data(r).get("sha256")) == lower(fnode.get("sha256"))
                           and data(r).get("ref_record_id") == m.get("record_id") and same_path(data(r).get("TargetFilename"), fnode.get("path"))
                           for m in made for r in raw_by_key.values())
            elif f["edge"] == "ran_as":
                good = any(lower(data(r).get("ProcessGuid")) == guid(f["to"]) and named(data(r).get("Image"), f["to"]) and
                           same_path(data(r).get("Image"), fnode.get("path")) and
                           lower(sysmon_sha(r)) == lower(fnode.get("sha256")) for r in ev1()) and \
                       any(data(r).get("hash_status") == "ok" and lower(data(r).get("sha256")) == lower(fnode.get("sha256"))
                           for r in fh)
            elif f["edge"] == "deleted":
                good = any(r.get("event_id") == 26 and lower(data(r).get("ProcessGuid")) == guid(f["from"])
                           and named(data(r).get("Image"), f["from"])
                           and same_path(data(r).get("TargetFilename"), fnode.get("path")) for r in recs)
            elif f["edge"] == "set_autostart":           # version 2: event 13 by that process, that value
                good = any(r.get("event_id") == 13 and lower(data(r).get("ProcessGuid")) == guid(f["from"])
                           and named(data(r).get("Image"), f["from"])
                           and lower(data(r).get("TargetObject")) == lower(G.nodes[v].get("key")) for r in recs)
            elif f["edge"] == "will_start":              # the same value's data names that file's full path
                good = any(r.get("event_id") == 13 and lower(data(r).get("TargetObject")) == lower(G.nodes[u].get("key"))
                           and same_path(named_program(data(r).get("Details")), fnode.get("path")) for r in recs)
            elif f["edge"] in ("listen_started", "listen_stopped"):
                want = self.truth["listen"]
                kind = "PORT_LISTEN_START" if f["edge"] == "listen_started" else "PORT_LISTEN_STOP"
                starts = [r for r in ev1() if lower(data(r).get("ProcessGuid")) == guid(f["from"])
                          and named(data(r).get("Image"), f["from"])]
                good = any(r.get("type") == kind and named(data(r).get("Image"), f["from"])
                           and str(data(r).get("LocalPort")) == str(want["port"])
                           and str(data(r).get("LocalIp")) == str(want["ip"])
                           and str(data(r).get("ProcessId")) == str(data(s).get("ProcessId"))
                           and same_start(data(r).get("ProcessStartUtc"), data(s).get("UtcTime"))
                           for r in recs for s in starts)
            else:
                good = False
            checked += len(recs)
            if not good:
                self.fail(f"'{f['says']}': the cited raw events don't say what the edge claims")
        checked += self.trace_hypotheses(raw_by_key)
        self.tally["trace_events"] += checked
        if self.ok:
            self.tally["trace_ok"] = 1
            self.say(f"  trace  PASS  {checked} cited events found in the raw recording and re-checked field by field")

    def trace_hypotheses(self, raw_by_key):
        """Timing rows: the cited cause (event 3) and effect (event 11 / event 1) belong to the via
        process, name the roles, and the effect lies within [cause - before, cause + after]. Rule
        rows: every cited event exists and names a role (its GUID or its path)."""
        G, R = self.G, self.roles
        ip, port = self.server
        data = lambda r: r.get("data") or {}
        guid = lambda node: lower(G.nodes[node].get("guid"))
        checked = 0
        for h, d, u, v in self.found_hyps:
            recs = []
            for ev in d["evidence"]:
                rec = raw_by_key.get(ev["key"])
                if rec is None:
                    self.fail(f"'{h['claim']}': cited event {ev['event']} not in the raw recording")
                else:
                    recs.append(rec)
            checked += len(recs)
            if len(recs) != len(d["evidence"]):
                continue
            via = guid(d["via"])
            if d["row"].startswith("T"):
                cause = next((r for r in recs if r.get("event_id") == 3), None)
                effect = next((r for r in recs if r.get("event_id") == (11 if d["row"] == "T1" else 1)), None)
                good = cause is not None and effect is not None and lower(data(cause).get("ProcessGuid")) == via
                if good and d["row"] in ("T1", "T3"):
                    ep = G.nodes[u]
                    want_ip, want_port = (ip, port) if u == R.get("test_server") else (ep.get("ip"), ep.get("port"))
                    good = (lower(data(cause).get("Initiated")) == "true" and str(data(cause).get("DestinationIp")) == str(want_ip)
                            and str(data(cause).get("DestinationPort")) == str(want_port))
                elif good:
                    good = lower(data(cause).get("Initiated")) == "false" and str(data(cause).get("SourceIp")) == str(G.nodes[u].get("ip"))
                if good and d["row"] == "T1":
                    good = lower(data(effect).get("ProcessGuid")) == via and same_path(data(effect).get("TargetFilename"), G.nodes[v].get("path"))
                elif good:
                    good = lower(data(effect).get("ProcessGuid")) == guid(v) and lower(data(effect).get("ParentProcessGuid")) == via
                if good:
                    tc, te = utc(cause), utc(effect)
                    good = tc is not None and te is not None and -self.cfg["before"] <= (te - tc).total_seconds() <= self.cfg["after"]
            else:
                role_guids = {guid(n) for n in self.role_names() if G.nodes[n].get("kind") == "process"}
                role_paths = [G.nodes[n].get("path") for n in self.role_names() if G.nodes[n].get("kind") == "file"]
                good = all(lower(data(r).get("ProcessGuid")) in role_guids or lower(data(r).get("ParentProcessGuid")) in role_guids
                           or any(same_path(data(r).get("TargetFilename"), p) or same_path(data(r).get("Image"), p) for p in role_paths)
                           for r in recs)
            if not good:
                self.fail(f"'{h['claim']}': the cited raw events don't say what the hypothesis claims")
        return checked


def load_hubs():
    """The frozen hub list (engine/config.hubs); the tests replace this with a hand-made list."""
    return config.hubs()


def window_records(recordings, label, lo, hi):
    """The raw records of the run's window, re-tagged with today's origin rules like engine/live.py,
    engine/load.py and engine/replay.py --db (layer 2 depends on origin), over the label's WHOLE
    stream and only then cut: re-tagging just the window would lose process trees that started
    before it (engine/retag.py). The noise overlay builds its 0x store from exactly this list."""
    paths = recording_files(os.path.join(recordings, label))
    return [r for r in read_recordings(paths, retag=True) if r.get("time") and lo <= parse_time(r["time"]) <= hi]


def records_from_store(db_path):
    """{dedup_key: record} for every row of a prepared store (--store), shaped like the raw
    recording's records (core columns on top, every other non-null column under `data`), so the
    trace back to the raw events works the same way. Rows the overlay added carry `overlay_slice`."""
    con = sqlite3.connect(f"file:{os.path.abspath(db_path).replace(os.sep, '/')}?mode=ro", uri=True)
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(events)")]
        core = {c for c in cols if c in CORE_NAMES}
        out = {}
        for row in con.execute("SELECT * FROM events ORDER BY id"):
            rec, data = {}, {}
            for name, value in zip(cols, row):
                if name in ("id", "dedup_key"):
                    continue
                if name in core:
                    if value is not None:
                        rec[name] = value
                elif value is not None:
                    data[name] = value
            rec["data"] = data
            out[row[cols.index("dedup_key")]] = rec
        return out
    finally:
        con.close()


def store_meta(db_path):
    """The `overlay_meta` table of a store built by tools/noise_overlay.py, or {} for any other store."""
    con = sqlite3.connect(f"file:{os.path.abspath(db_path).replace(os.sep, '/')}?mode=ro", uri=True)
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE name = 'overlay_meta'").fetchone():
            return {}
        return dict(con.execute("SELECT key, value FROM overlay_meta"))
    finally:
        con.close()


def check_graph(truth, G, raw_by_key, lo, hi, server, hubs, say=print):
    """Steps 3-5 on a built graph: the checker's verdict (True = PASS) and the GraphCheck (its
    found facts/hypotheses are what the noise-overlay experiment reads)."""
    c = GraphCheck(truth, G, lo, hi, server, say=say)
    if c.resolve():
        c.check_facts()
        c.check_hypotheses(raw_by_key)
        c.check_gaps()
        if c.ok:
            c.check_alert_view(hubs)
            c.trace(raw_by_key)
    return c.ok, c


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("scenario")
    p.add_argument("--run", type=int, default=1, help="1 = newest run, 2 = the one before, ...")
    p.add_argument("--run-id", help="the run with this id (from tools/run_in_vm.py)")
    p.add_argument("--speed", type=float, default=0, help="replay speed: 0 = instant, 1 = real time, 10 = 10x")
    p.add_argument("--recordings", default=os.path.join(PROJECT_ROOT, "recordings"))
    p.add_argument("--label", default="vm")
    p.add_argument("--pool", help="pool of normal rates for layer 2 (engine.confidence --build-pool); "
                                  "default <recordings>/confidence/pool.json")
    p.add_argument("--no-hubs", action="store_true", help="views without hub suppression (the frozen list otherwise)")
    p.add_argument("--store", help="check this prepared event store (tools/noise_overlay.py) instead of replaying "
                                   "the recording; its overlay_meta must name this scenario and run")
    p.add_argument("--sheet", help="answer sheet instead of scenarios/<s>/ground_truth.yaml (blind runs: "
                                   "tools/run_blind.py's copy, made after the run)")
    a = p.parse_args(argv)
    pool = a.pool or os.path.join(a.recordings, "confidence", "pool.json")
    if config.is_official():
        # an official run (ANALYSTLAB_OFFICIAL=1): every frozen value and file must be in place first
        problems = config.verify_official(pool=pool) + (["--no-hubs is not allowed in an official run"] if a.no_hubs else [])
        if a.store:
            problems.append("--store (a prepared store, e.g. a noise overlay) is not allowed in an official run")
        if problems:
            for x in problems:
                print(f"  FAIL  official run: {x}")
            print("\nRESULT: FAIL")
            return 1
        print("official run: frozen values, pool, baselines and hub list verified")
    try:
        hubs = None if a.no_hubs else load_hubs()
    except (OSError, ValueError, KeyError) as e:
        print(f"  FAIL  hub list: {e}\n\nRESULT: FAIL")
        return 1
    if not os.path.exists(pool):
        print(f"  FAIL  no pool of normal rates at {pool} (build it: python -m engine.confidence --build-pool "
              f"--db <dev snapshot> --out {pool})\n\nRESULT: FAIL")
        return 1
    layer2 = Layer2.from_pool_file(pool)

    with open(sheet_path(a.scenario, a.sheet), encoding="utf-8") as f:
        truth = yaml.safe_load(f)
    run = find_run(a.recordings, a.scenario, a.run, a.run_id)
    if run is None:
        print(f"No matching recorded run of {a.scenario.upper()} (recordings/vmruns).")
        return 1
    run_ok = True
    if run.get("exit_code") != 0:
        print(f"  FAIL  the scenario's run ended with exit code {run.get('exit_code')}")
        run_ok = False
    lo, hi, overlaps = run_window(a.recordings, run)
    if overlaps:
        print("  FAIL  this run overlaps the previous run; its evidence can't be separated")
        run_ok = False
    print(f"Scenario {truth['scenario']} '{truth['title']}': run {run['start']} -> {run['end']}"
          f"{' (run id ' + run['run_id'] + ')' if run.get('run_id') else ''}")

    if a.store:
        # 2'. a prepared store (the noise overlay's): the same window, checked without replaying
        if not os.path.exists(a.store):
            print(f"  FAIL  no store at {a.store}\n\nRESULT: FAIL")
            return 1
        meta = store_meta(a.store)
        if not meta:                                   # review 2026-10-24: nothing to check it against
            print("  FAIL  --store needs a store built by tools/noise_overlay.py (no overlay_meta table)\n\nRESULT: FAIL")
            return 1
        wrong = [f"{k}: store {meta.get(k)!r}, run {v!r}" for k, v in
                 (("scenario", truth["scenario"]), ("run_start", run["start"]), ("run_end", run["end"]),
                  ("window_lo", lo.isoformat()), ("window_hi", hi.isoformat()))
                 if meta and str(meta.get(k)) != str(v)]
        if wrong:
            print("  FAIL  the store was built for another run or window: " + "; ".join(wrong) + "\n\nRESULT: FAIL")
            return 1
        t0 = time.perf_counter()
        raw_by_key = records_from_store(a.store)
        G = build_graph(a.store, hypotheses=layer2)
        took = time.perf_counter() - t0
        n = len(raw_by_key)
        overlay_rows = sum(1 for r in raw_by_key.values() if r["data"].get("overlay_slice") is not None)
        how = (f"read {n} records from the prepared store {os.path.basename(a.store)} ({overlay_rows} overlay rows, "
               f"{meta.get('volume', '?')}x, seed {meta.get('seed', '?')})" if meta
               else f"read {n} records from the prepared store {os.path.basename(a.store)}")
    else:
        # 2. replay the window into a fresh store, then build the graph from the store
        records = window_records(a.recordings, a.label, lo, hi)
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "replay.db")
            store = EventStore(db)
            t0 = time.perf_counter()
            n = replay(records, lambda r: store.insert([r]), speed=a.speed)
            store.close()
            G = build_graph(db, hypotheses=layer2)
            took = time.perf_counter() - t0
        raw_by_key = {EventStore.dedup_key(r): r for r in records}
        how = f"replayed {n} records ({'instant' if not a.speed else f'{a.speed:g}x'}) into a fresh store"
    n_hyp = sum(1 for _, _, d in G.edges(data=True) if d.get("grade") == "hypothesis")
    print(f"{how}; graph: {G.number_of_nodes()} nodes, {G.number_of_edges() - n_hyp} fact edges, {n_hyp} hypotheses, "
          f"{len(G.graph['gaps'])} gaps ({took:.1f} s)\n")

    try:
        server = run_server(run)
    except ValueError as e:
        print(f"  FAIL  {e}\n\nRESULT: FAIL")
        return 1
    ok, _ = check_graph(truth, G, raw_by_key, lo, hi, server, hubs)
    ok = ok and run_ok
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
