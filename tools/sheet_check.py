"""Check an answer sheet's LAYOUT (not whether its story is true) against what the three checkers
read: tools/check_scenario.py (steps, not_expected), tools/check_graph_scenario.py (expected_graph,
roles) and tools/check_alerts.py (alert_expected).

    python tools/sheet_check.py scenarios/s1/ground_truth.yaml
    python tools/run_blind.py <blind folder> --dry-run --check-sheet     # the blind WRITER only

Why: the J3 blind sheets (2026-10-31) used a layout the checkers could not read, so the
pre-registered score measured the layout, not the lab (report 7.3). A writer who runs this before
handing in finds such problems while the sheet is still theirs to change. It opens the sheet, so
on a blind folder only the writer runs it, never us.

Prints one plain line per problem; exit 0 = the layout is readable, 1 = problems, 2 = unreadable.
"""

import argparse
import os
import re
import sys

import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
from check_scenario import NON_FIELD_KEYS, PORT_TYPES  # noqa: E402

# what engine/graph.py draws (facts: Builder.fact calls; gaps: Builder.gap; hypotheses: TIMING_KINDS)
FACT_EDGES = {"started", "connected_to", "accepted_from", "created", "deleted", "looked_up",
              "listen_started", "listen_stopped", "ran_as", "set_autostart", "will_start"}
GAP_KINDS = {"origin_unknown", "parent_unknown", "actor_unknown", "content_unknown", "owner_unknown"}
HYP_KINDS = {"content_from", "remote_command", "fetched_then_ran"}
AGENT_TYPES = set(PORT_TYPES) | {"FILE_HASH"}
SYSMON_EVENTS = {1, 3, 5, 11, 12, 13, 14, 15, 22, 23, 26}    # 12-14: registry, config v0.3
LEVELS = {"informational", "low", "medium", "high", "critical"}
TOP_KEYS = {"scenario", "title", "runs_in", "programs", "windows_programs", "file_groups", "steps",
            "not_expected", "notes", "expected_graph", "alert_expected", "test_server", "listen",
            "payload_path_contains", "checks_assumptions", "needs_calm_vm", "control", "baseline",
            "expected_story", "tricky_part"}          # the last two: for readers (blind sheets), never checked
FIELD_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]*")           # a record field, optionally + _endswith/_contains/_suffix
SCENARIO_ID = re.compile(r"(?:[SC]\d+[A-Z]?|B[1-9][0-9]?)", re.I)
GAP_OTHER_FILE = "file in the scenario folder"      # check_graph_scenario.check_gaps' name for them


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _int(x):
    return isinstance(x, int) and not isinstance(x, bool)


class Sheet:
    def __init__(self, truth, expect_id=None):
        self.t, self.expect_id, self.problems, self.warnings = truth, expect_id, [], []

    def bad(self, where, msg):
        self.problems.append(f"{where}: {msg}")

    # -- the parts --------------------------------------------------------------------------
    def check(self):
        t = self.t
        if not isinstance(t, dict):
            self.bad("sheet", "must be a YAML mapping (key: value lines), see the template")
            return self.problems
        for k in sorted(set(t) - TOP_KEYS):          # ignored by the checkers: fine for notes, fatal for a typo
            self.warnings.append(f"{k}: the checkers ignore this top-level key (they read only: "
                                 f"{', '.join(sorted(TOP_KEYS))})")
        sid = t.get("scenario")
        if not isinstance(sid, str) or not SCENARIO_ID.fullmatch(sid):
            self.bad("scenario", "must be the scenario id, e.g. B3")
        elif self.expect_id and sid.lower() != self.expect_id.lower():
            self.bad("scenario", f"is {sid}, but scenario.json says {self.expect_id.upper()}")
        if not isinstance(t.get("title"), str) or not t.get("title"):
            self.bad("title", "a short title is required")
        if t.get("runs_in") != "vm":
            self.bad("runs_in", "must be: vm")
        if t.get("baseline") is True:                # S0: a boot where nothing runs (no programs, no steps)
            return self.problems
        self.programs()
        self.file_groups()
        ids = self.steps()
        self.not_expected()
        self.graph()
        self.alerts(ids)
        return self.problems

    def programs(self):
        p = self.t.get("programs")
        if not isinstance(p, dict) or not p:
            self.bad("programs", "required: role -> program file name, e.g. main: b3_main.exe")
            self.roles = set()
            return
        for role, exe in p.items():
            if not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", role):
                self.bad(f"programs.{role}", "role names use lower-case letters, digits and _ only")
            if not isinstance(exe, str) or not exe.lower().endswith(".exe") or re.search(r"[\\/:]", exe):
                self.bad(f"programs.{role}", "must be a program FILE NAME ending in .exe, without a folder")
        self.roles = set(p)
        wp = self.t.get("windows_programs", [])
        if not isinstance(wp, list) or any(r not in p for r in wp):
            self.bad("windows_programs", "must be a LIST of roles that are also under programs (e.g. [shell])")

    def file_groups(self):
        g = self.t.get("file_groups", {})
        if not isinstance(g, dict):
            self.bad("file_groups", "must be role -> {path_contains, suffix, count}")
            return
        for role, d in g.items():
            if role in self.roles:
                self.bad(f"file_groups.{role}", "a role name is used twice (programs and file_groups)")
            if not isinstance(d, dict) or set(d) != {"path_contains", "suffix", "count"}:
                self.bad(f"file_groups.{role}", "needs exactly path_contains, suffix and count")
                continue
            if not isinstance(d["path_contains"], str) or not isinstance(d["suffix"], str) or not d["suffix"]:
                self.bad(f"file_groups.{role}", "path_contains and suffix are text")
            if not _int(d["count"]) or d["count"] < 1:
                self.bad(f"file_groups.{role}.count", "must be a whole number >= 1")

    def evidence(self, where, ev, earlier):
        if not isinstance(ev, dict) or not ev:
            self.bad(where, "evidence must be {sysmon_event: N, Field_endswith: ...} or a list of those")
            return
        has_s, has_a = "sysmon_event" in ev, "agent_type" in ev
        if has_s == has_a:
            self.bad(where, "needs exactly one of sysmon_event or agent_type")
        if has_s and ev["sysmon_event"] not in SYSMON_EVENTS:
            self.bad(where, f"sysmon_event must be one of {sorted(SYSMON_EVENTS)} (what the lab records)")
        if has_a and ev["agent_type"] not in AGENT_TYPES:
            self.bad(where, f"agent_type must be one of {sorted(AGENT_TYPES)}")
        for k, v in ev.items():
            if k in NON_FIELD_KEYS:
                continue
            if not isinstance(k, str) or not FIELD_KEY.fullmatch(k):
                self.bad(where, f"'{k}' is not a field pattern (e.g. Image_endswith, TargetFilename_contains)")
            elif isinstance(v, (dict, list)) or v is None:
                self.bad(where, f"'{k}' must be one value (text or number)")
        n = ev.get("count", 1)
        if not _int(n) or n < 1:
            self.bad(where, "count must be a whole number >= 1")
            n = 1
        if "within_seconds" in ev and not _num(ev["within_seconds"]):
            self.bad(where, "within_seconds must be a number")
        sa = ev.get("seconds_after")
        if sa is not None:
            if not isinstance(sa, dict) or set(sa) != {"step", "min", "max"} \
                    or not all(_num(sa.get(x)) for x in ("min", "max")) or sa["min"] > sa["max"]:
                self.bad(where, "seconds_after must be {step: <earlier step id>, min: N, max: N} with min <= max")
            elif sa["step"] not in earlier:
                self.bad(where, "seconds_after.step must name an EARLIER step id")
        if "same_target_as_step" in ev and ev["same_target_as_step"] not in earlier:
            self.bad(where, "same_target_as_step must name an EARLIER step id")
        iv = ev.get("interval_seconds")
        if iv is not None and (not isinstance(iv, dict) or set(iv) != {"min", "max"}
                               or not all(_num(iv.get(x)) for x in ("min", "max")) or iv["min"] > iv["max"]):
            self.bad(where, "interval_seconds must be {min: N, max: N} with min <= max")
        if "spread_seconds_min" in ev and not _num(ev["spread_seconds_min"]):
            self.bad(where, "spread_seconds_min must be a number")
        if (iv is not None or "spread_seconds_min" in ev) and n < 2:
            self.bad(where, "interval_seconds / spread_seconds_min need count >= 2")
        if "sha256_equals" in ev and ev.get("agent_type") != "FILE_HASH":
            self.bad(where, "sha256_equals only goes with agent_type: FILE_HASH")

    def steps(self):
        steps = self.t.get("steps")
        if not isinstance(steps, list) or not steps:
            self.bad("steps", "required: a list of {id, what, evidence}")
            return set()
        seen = set()
        for i, s in enumerate(steps):
            where = f"steps[{i}]"
            if not isinstance(s, dict) or not {"id", "what", "evidence"} <= set(s):
                self.bad(where, "each step needs id, what and evidence")
                continue
            for k in sorted(set(s) - {"id", "what", "evidence"}):
                self.bad(where, f"unknown key '{k}' (a step has only id, what, evidence)")
            if not (_int(s["id"]) or isinstance(s["id"], str)) or s["id"] in seen:
                self.bad(where, "id must be a number (or a short name like 3b), different for every step")
            where = f"step {s['id']}"
            evs = s["evidence"] if isinstance(s["evidence"], list) else [s["evidence"]]
            if not evs:
                self.bad(where, "evidence list is empty")
            for j, ev in enumerate(evs):
                self.evidence(f"{where} evidence[{j}]" if len(evs) > 1 else where, ev, set(seen))
            seen.add(s["id"])
        return seen

    def not_expected(self):
        ne = self.t.get("not_expected", [])
        if not isinstance(ne, list):
            self.bad("not_expected", "must be a list of {sysmon_event: N, why: ...}")
            return
        for i, item in enumerate(ne):
            where = f"not_expected[{i}]"
            if not isinstance(item, dict) or "why" not in item or (("sysmon_event" in item) == ("agent_type" in item)):
                self.bad(where, "each item is {sysmon_event: N, why: ...} or {agent_type: ..., why: ...}")
                continue
            if "sysmon_event" in item and item["sysmon_event"] not in SYSMON_EVENTS:
                self.bad(where, f"sysmon_event must be one of {sorted(SYSMON_EVENTS)}")
            if "agent_type" in item and item["agent_type"] not in AGENT_TYPES:
                self.bad(where, f"agent_type must be one of {sorted(AGENT_TYPES)}")
            for k in sorted(set(item) - {"sysmon_event", "agent_type", "why"}):
                self.bad(where, f"unknown key '{k}' (only sysmon_event or agent_type, and why)")

    def role_ok(self, role):
        """Can check_graph_scenario.resolve find this role? (its rules, in its order)"""
        t = self.t
        if not isinstance(role, str):
            return False
        if role in self.roles or role in (t.get("file_groups") or {}):
            return True
        if role.endswith("_file") and role[:-5] in self.roles:
            return bool(t.get("payload_path_contains"))
        if role.endswith("_autostart") and role[:-10] in self.roles:
            return True
        if role == "test_server":
            return True
        if role == "listen_port":
            lp = t.get("listen")
            return isinstance(lp, dict) and "ip" in lp and "port" in lp
        return False

    ROLE_HELP = ("a role under programs or file_groups, <program role>_file (needs payload_path_contains), "
                 "<program role>_autostart (the autostart entries it set), test_server, or listen_port "
                 "(needs listen: {ip, port})")

    def graph(self):
        g = self.t.get("expected_graph")
        if not isinstance(g, dict) or not isinstance(g.get("facts"), list):
            self.bad("expected_graph", "required: {facts: [...], gaps: [...]} (hypotheses optional)")
            return
        for k in sorted(set(g) - {"facts", "gaps", "hypotheses"}):
            self.bad("expected_graph", f"unknown key '{k}' (only facts, hypotheses, gaps)")
        for i, f in enumerate(g["facts"]):
            where = f"expected_graph.facts[{i}]"
            if not isinstance(f, dict) or not {"from", "edge", "to", "says"} <= set(f):
                self.bad(where, "each fact is {from: <role>, edge: <kind>, to: <role>, says: ...}")
                continue
            for k in sorted(set(f) - {"from", "edge", "to", "says", "count"}):
                self.bad(where, f"unknown key '{k}' (only from, edge, to, says, count)")
            if f["edge"] not in FACT_EDGES:
                self.bad(where, f"edge must be one of {sorted(FACT_EDGES)}")
            for end in ("from", "to"):
                if not self.role_ok(f[end]):
                    self.bad(where, f"{end} '{f[end]}' is not a role the checker can find: {self.ROLE_HELP}")
            if "count" in f and (not _int(f["count"]) or f["count"] < 1):
                self.bad(where, "count must be a whole number >= 1")
        for i, h in enumerate(g.get("hypotheses") or []):
            where = f"expected_graph.hypotheses[{i}]"
            if not isinstance(h, dict) or "claim" not in h or not isinstance(h.get("between"), list) \
                    or len(h["between"]) != 2:
                self.bad(where, "each hypothesis is {claim: ..., between: [<role>, <role>]}")
                continue
            for k in sorted(set(h) - {"claim", "between", "kind", "optional", "why", "why_not_fact",
                                      "expected_confidence"}):
                self.bad(where, f"unknown key '{k}'")
            for r in h["between"]:
                if not self.role_ok(r):
                    self.bad(where, f"'{r}' is not a role the checker can find: {self.ROLE_HELP}")
            if "kind" in h and h["kind"] not in HYP_KINDS:
                self.bad(where, f"kind must be one of {sorted(HYP_KINDS)}")
            if "optional" in h and not isinstance(h["optional"], bool):
                self.bad(where, "optional must be true or false")
        gaps = g.get("gaps", [])
        if not isinstance(gaps, list):
            self.bad("expected_graph.gaps", "must be a list (write [] for none)")
            return
        for i, x in enumerate(gaps):
            where = f"expected_graph.gaps[{i}]"
            if not isinstance(x, dict) or set(x) - {"node", "kind", "why"} or not {"node", "kind"} <= set(x):
                self.bad(where, "each gap is {node: <role>, kind: <gap kind>} (why optional)")
                continue
            if x["kind"] not in GAP_KINDS:
                self.bad(where, f"kind must be one of {sorted(GAP_KINDS)}")
            if x["node"] != GAP_OTHER_FILE and not self.role_ok(x["node"]):
                self.bad(where, f"node '{x['node']}' is not a role the checker can find: {self.ROLE_HELP}")

    def alerts(self, step_ids):
        a = self.t.get("alert_expected")
        blind = isinstance(self.t.get("scenario"), str) and self.t["scenario"].upper().startswith("B")
        if a is None:
            if blind:
                self.bad("alert_expected", "required for a blind scenario: {suspicious_steps: [...], why: ...} "
                                           "(an empty list if nothing should be flagged)")
            return
        if not isinstance(a, dict):
            self.bad("alert_expected", "must be a mapping")
            return
        for i, c in enumerate(a.get("check") or []):
            where = f"alert_expected.check[{i}]"
            if not isinstance(c, dict) or set(c) != {"rule_id", "level", "involves"}:
                self.bad(where, "each item is {rule_id, level, involves}")
                continue
            if c["level"] not in LEVELS:
                self.bad(where, f"level must be one of {sorted(LEVELS)}")
            if c["involves"] not in self.roles:
                self.bad(where, "involves must be a role under programs")
        if blind:
            if a.get("check"):
                self.bad("alert_expected.check", "a blind writer does not know the lab's rules: list "
                                                 "suspicious_steps instead")
            ss = a.get("suspicious_steps")
            if not isinstance(ss, list) or any(s not in step_ids for s in ss):
                self.bad("alert_expected.suspicious_steps", "must be a list of step ids an analyst should be "
                                                            "alerted to (an empty list: nothing should be flagged)")
            if not isinstance(a.get("why"), str) or not a.get("why"):
                self.bad("alert_expected.why", "say in a sentence why those steps (or none) are suspicious")


def check_sheet(truth, expect_id=None):
    """(problems, warnings) for a loaded answer sheet's layout; no problems = the checkers can read it.
    Warnings are things the checkers ignore (harmless as notes, wrong if meant as a check)."""
    s = Sheet(truth, expect_id)
    return s.check(), s.warnings


def check_file(path, expect_id=None):
    """(problems, warnings, error): error is set when the file can't be read as YAML at all."""
    try:
        with open(path, encoding="utf-8") as f:
            truth = yaml.safe_load(f)
    except (OSError, UnicodeError, yaml.YAMLError) as e:
        return [], [], f"could not read the sheet as YAML ({e.__class__.__name__}: {e})"
    return (*check_sheet(truth, expect_id), None)


def main(argv=None):
    p = argparse.ArgumentParser(description="Check an answer sheet's layout against what the checkers read")
    p.add_argument("sheet")
    p.add_argument("--id", help="the scenario id the sheet must carry (e.g. B3)")
    a = p.parse_args(argv)
    problems, warnings, err = check_file(a.sheet, a.id)
    if err:
        print(f"UNREADABLE: {err}")
        return 2
    for x in problems:
        print(f"  problem  {x}")
    for x in warnings:
        print(f"  note     {x}")
    print(f"SHEET LAYOUT: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
