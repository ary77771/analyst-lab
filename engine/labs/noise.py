"""Noise meter (Labs, night-hunt; VISION's idea 8): how many alerts an analyst would have been shown per
active hour on the laptop's ordinary weeks, version by version.

The numbers are READ from the committed official scoring results, never typed: each result file is read
from git at the commit that committed it ("committed before reading", VERIFICATION_LOG 2026-11-22), so a
later edit of a working copy cannot change what this page says. Only counts leave this module: the
results' rule names and program locations are not read out (privacy rule 7 / night rule 11).

    GET /api/labs/noise/
"""

import os
import re
import subprocess
import threading

from fastapi import APIRouter

router = APIRouter(prefix="/api/labs/noise", tags=["labs: noise"])

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# (version, commit that committed the official result, file, which laptop week, which code)
SOURCES = [
    ("v2", "a62afba", "docs/results/v2/false-alerts-official.md", "laptop week 2026-11-14 to 2026-11-20 (a test of normal use)",
     "counted with the v2 code"),
    ("v3", "244d740", "docs/results/v3/false-alerts-official.md", "laptop week 2026-11-15 to 2026-11-21 (a test of normal use)",
     "counted with the v3 code"),
    ("v4", "81afaf4", "docs/results/v4/false-alerts-official-v3runs.md",
     "laptop week 2026-11-15 to 2026-11-21 (a test of normal use; the same week as v3)", "counted with the v4 code"),
]
WORDS = {
    "title": "How noisy is it on an ordinary week?",
    "intro": "On the laptop's normal use nothing bad was happening, so every alert shown is a false alarm. "
             "Each bar is the number of alerts an analyst would have been shown per hour the laptop was in use, "
             "for each version, over a whole week.",
    "honest": "4 an hour is still more than one person wants.",
    "unit": "alerts shown per active hour",
    "active": "An active hour = 60 minutes with at least one ordinary event (the lab's own tools and paused time "
              "left out). Shown = medium level and above, the dashboard's frozen floor.",
    "source": "Read from the committed official results; nothing on this page is typed in. Each bar names its own "
              "week and file. Other pages may count a different week, so their active hours can differ (the alarm "
              "track record counts laptop week 2026-10-23 to 2026-10-29, a test of normal use).",
    "top_rule": "{share} % of them came from a single rule",
    "missing": "This result could not be read from git here ({why}).",
}
_NUM = r"([\d,]+(?:\.\d+)?)"
_cache, _lock = {}, threading.Lock()


def _num(text):
    return float(text.replace(",", ""))


def parse(markdown: str) -> dict:
    """The counts of one result file (raises ValueError when the headline lines are not there)."""
    active = re.search(rf"Active hours: \*\*{_NUM}\*\*", markdown)
    raised = re.search(rf"RAISED alerts \(>= medium\): \*\*{_NUM}\*\* = \*\*{_NUM} per active hour\*\*", markdown)
    every = re.search(rf"All levels: {_NUM} = {_NUM} per active hour", markdown)
    if not (active and raised and every):
        raise ValueError("headline numbers not found")
    levels = {m.group(1): int(_num(m.group(2))) for m in
              re.finditer(rf"^\| (informational|low|medium|high|critical) \| {_NUM} \| {_NUM} \|$", markdown, re.M)}
    # the by-rule table of RAISED alerts: only its alert counts are read (4th column), never names
    rule_counts = []
    table = markdown.split("## Raised alerts by rule", 1)
    if len(table) == 2:
        for line in table[1].splitlines()[1:]:
            if line.startswith("## "):
                break
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 5 and re.fullmatch(r"[\d,]+", cells[3]):
                rule_counts.append(int(_num(cells[3])))
    out = {"active_hours": _num(active.group(1)), "raised": int(_num(raised.group(1))),
           "per_hour": _num(raised.group(2)), "all_levels": int(_num(every.group(1))),
           "all_per_hour": _num(every.group(2)), "levels": levels, "rules": len(rule_counts)}
    if rule_counts and out["raised"]:
        out["top_rule_share"] = round(100 * max(rule_counts) / out["raised"])
    return out


def read(commit, path, git=None):
    """The file as committed (git show <commit>:<path>), or raises OSError/ValueError."""
    git = git or (lambda args: subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                                              encoding="utf-8", timeout=20))
    r = git(["show", f"{commit}:{path}"])
    if r.returncode != 0:
        raise ValueError((r.stderr or "git show failed").strip().splitlines()[-1][:160])
    return r.stdout


def meter(git=None) -> dict:
    versions = []
    for version, commit, path, week, code in SOURCES:
        v = {"version": version, "commit": commit, "path": path, "week": week, "code": code}
        try:
            v.update(parse(read(commit, path, git)), ok=True)
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            v.update(ok=False, problem=WORDS["missing"].format(why=str(e) or type(e).__name__))
        versions.append(v)
    return {"versions": versions, "words": WORDS}


@router.get("/")
def noise():
    with _lock:
        if "meter" not in _cache:
            _cache["meter"] = meter()
        return _cache["meter"]
