"""Where downloaded tools and reference data live (night-tools and night-explain labs; read-only).

Two helper styles, merged on the night branch (both builders wrote this file):
- roots()/folder()/target(): night-tools, <project>/downloads/night/<tool>, ANALYSTLAB_NIGHT_DOWNLOADS overrides.
- root()/find(): night-explain, nearest `downloads/<sub>` up the folder tree, ANALYSTLAB_DOWNLOADS overrides.
Downloads are never committed (.gitignore: downloads/).
"""
import os

from engine.labs._files import CODE_ROOT

ENV = "ANALYSTLAB_NIGHT_DOWNLOADS"


def roots(recordings=None):
    if os.environ.get(ENV):
        return [os.environ[ENV]]
    out = []
    if recordings:
        out.append(os.path.join(os.path.dirname(os.path.abspath(recordings)), "downloads", "night"))
    out.append(os.path.join(CODE_ROOT, "downloads", "night"))
    # a worktree (.claude/worktrees/<name>) also looks in the main checkout's downloads
    parts = os.path.abspath(CODE_ROOT).split(os.sep)
    if ".claude" in parts:
        out.append(os.path.join(os.sep.join(parts[:parts.index(".claude")]), "downloads", "night"))
    # any other worktree (wt\dash, wt\night): the nearest downloads/night up the folder tree (merge fix)
    up = find("night")
    if up:
        out.append(up)
    seen, res = set(), []
    for r in out:
        if r.lower() not in seen:
            seen.add(r.lower())
            res.append(r)
    return res


def folder(tool, recordings=None):
    """The first existing downloads/night/<tool> folder, or None."""
    for r in roots(recordings):
        p = os.path.join(r, tool)
        if os.path.isdir(p):
            return p
    return None


def target(tool, recordings=None):
    """Where a fetch puts <tool> (the first root)."""
    return os.path.join(roots(recordings)[0], tool)


# --- night-explain helpers ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def root(start=None):
    """The nearest existing `downloads` folder (ANALYSTLAB_DOWNLOADS when set), or None."""
    override = os.environ.get("ANALYSTLAB_DOWNLOADS")
    if override:
        return override if os.path.isdir(override) else None
    here = os.path.abspath(start or PROJECT_ROOT)
    for _ in range(6):
        p = os.path.join(here, "downloads")
        if os.path.isdir(p):
            return p
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return None


def find(sub, start=None):
    """The first existing `<dir>/downloads/<sub>` from `start` (default: the project) upwards, or None."""
    override = os.environ.get("ANALYSTLAB_DOWNLOADS")
    if override:
        p = os.path.join(override, *sub.split("/"))
        return p if os.path.exists(p) else None
    here = os.path.abspath(start or PROJECT_ROOT)
    for _ in range(6):
        p = os.path.join(here, "downloads", *sub.split("/"))
        if os.path.exists(p):
            return p
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return None
