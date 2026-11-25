"""Which official evaluation this code belongs to (v2 plan, package F).

v1 was frozen at the git tag `freeze-v1` and officially run on 2026-10-30/31; its results in
docs/results/j2-*-official.md stay exactly as they are. This code is version 2: its official runs
need the tag `freeze-v2`, its series and run summaries carry `"freeze": "freeze-v2"`, and its
results go to docs/results/v2/ (never over v1's files). A series file or run summary written
before v2 carries no "freeze" field: it belongs to v1.

Official work (runs and scoring) also needs the code to be exactly the frozen code: no change to
engine/, tools/, config/, scenarios/ or rules/ since the tag, committed or not (review 2026-11-13:
scoring test data with unfrozen code would be tuning on it).
"""

import os
import re
import subprocess

CURRENT = "v4"                      # v4 development (branch v4); official only after the tag freeze-v4 exists
TAGS = {"v1": "freeze-v1", "v2": "freeze-v2", "v3": "freeze-v3", "v4": "freeze-v4"}
FREEZE_TAG = TAGS[CURRENT]
PREREG = {"v1": "docs/plans/package-j2-prereg.md", "v2": "docs/plans/v2-prereg.md", "v3": "docs/plans/v3-prereg.md",
          "v4": "docs/plans/v4-prereg.md"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_PATHS = ("engine", "tools", "config", "scenarios", "rules", "agent")   # v3: agent/ too (origin tagging decides what is scored)
V2_CODE_SINCE = "2026-11-13"        # the day v2's stamping code began: an unstamped official file after it is an error


def _day(when):
    """'2026-11-13...' or a run id '20261113-...' -> '2026-11-13'; None when unreadable."""
    text = str(when or "")
    if re.match(r"^\d{4}-\d{2}-\d{2}", text):
        return text[:10]
    m = re.match(r"^(\d{4})(\d{2})(\d{2})-", text)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def version_of(doc: dict, when=None) -> str:
    """The evaluation a series file or a run summary belongs to (its "freeze" field; none = v1).
    An unknown tag raises, and so does an UNSTAMPED official file from `when` on or after
    V2_CODE_SINCE (written by an old checkout?): a run whose version is unknown must never be
    counted anywhere."""
    tag = (doc or {}).get("freeze")
    if not tag:
        day = _day(when)
        if day is not None and day >= V2_CODE_SINCE:
            raise ValueError(f"an official file from {day} carries no freeze stamp: its evaluation version is unknown")
        tag = TAGS["v1"]
    for version, t in TAGS.items():
        if t == str(tag):
            return version
    raise ValueError(f"unknown freeze tag {tag!r}: this file's evaluation version is unknown")


def _git(*args, root=ROOT):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def has_tag(tag: str = FREEZE_TAG, root: str = ROOT) -> bool:
    """True when the git tag exists in the checkout at `root`."""
    p = _git("tag", "-l", tag, root=root)
    return p.returncode == 0 and p.stdout.strip() == tag


SIGMA_DIR = ("downloads", "sigma")                 # the community rules' git checkout (engine/detect.py loads rules/windows)
SIGMA_RULES = "rules/windows"


def sigma_problems(root: str = ROOT) -> list:
    """The community Sigma rules the detectors load are git-ignored here, so the project's own diff
    cannot see them (review 2026-11-13): their checkout must be exactly the frozen
    `sigma.rules_commit`, with no changed, deleted or extra file under rules/windows."""
    import yaml
    try:
        with open(os.path.join(root, "config", "frozen.yaml"), encoding="utf-8") as f:
            value = ((yaml.safe_load(f) or {}).get("sigma") or {}).get("rules_commit")
        pin = "" if value is None else str(value).strip().lower()      # an all-digit hash reads as a number in YAML
    except (OSError, ValueError) as e:
        return [f"config/frozen.yaml cannot be read: {e}"]
    sigma = os.path.join(root, *SIGMA_DIR)
    if not pin:
        return ["sigma.rules_commit is not set in config/frozen.yaml"]
    if not os.path.isdir(os.path.join(sigma, ".git")):
        return [f"the community rules' checkout {'/'.join(SIGMA_DIR)} is missing (tools/fetch_sigma_rules.ps1)"]
    head = _git("rev-parse", "HEAD", root=sigma)
    if head.returncode != 0 or head.stdout.strip().lower() != pin:
        return [f"the community rules are at {head.stdout.strip()[:12] or '?'}, not the frozen commit {pin[:12]}"]
    d = _git("diff", "--quiet", "HEAD", "--", SIGMA_RULES, root=sigma)
    s = _git("status", "--porcelain", "--untracked-files=all", "--", SIGMA_RULES, root=sigma)
    if d.returncode != 0 or s.returncode != 0 or s.stdout.strip():
        return [f"files under {'/'.join(SIGMA_DIR)}/{SIGMA_RULES} differ from the frozen commit (changed, deleted or extra)"]
    return []


def code_problems(tag: str = FREEZE_TAG, root: str = ROOT, check_sigma: bool = True) -> list:
    """Why official work may not run now ([] = go): the tag must exist and engine/, tools/, config/,
    scenarios/ and rules/ must equal it (no committed change after it, no uncommitted or untracked
    file), and the community rules must be the frozen ones (sigma_problems)."""
    if not has_tag(tag, root):
        return [f"the git tag {tag} does not exist yet: nothing is official before the freeze"]
    problems = sigma_problems(root) if check_sigma else []
    d = _git("diff", "--quiet", tag, "--", *CODE_PATHS, root=root)
    if d.returncode == 1:
        problems.append(f"{', '.join(CODE_PATHS)} differ from {tag}: the code is not the frozen code")
    elif d.returncode != 0:
        problems.append(f"git diff against {tag} failed: {d.stderr.strip()[:120]}")
    s = _git("status", "--porcelain", "--untracked-files=all", "--", *CODE_PATHS, root=root)
    if s.returncode != 0:
        problems.append(f"git status failed: {s.stderr.strip()[:120]}")
    elif s.stdout.strip():
        problems.append(f"uncommitted or untracked files under {', '.join(CODE_PATHS)}")
    return problems


def code_state(root: str = ROOT) -> dict:
    """{commit, tag, frozen}: written into every official output, so a result names the code it came from."""
    head = _git("rev-parse", "HEAD", root=root)
    return {"commit": head.stdout.strip() if head.returncode == 0 else None, "tag": FREEZE_TAG,
            "frozen": not code_problems(root=root)}
