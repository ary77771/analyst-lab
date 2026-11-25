"""Every rule file's id, title, level, log category and tags (night-explain labs; read-only, cached).

"What our rules can see" must count only the rules the engine really loads: engine/detect.load_rules keeps
a rule only when its log source is `product: windows` in a category we record (detect.CATEGORY_EVENT_ID,
or a declared-only category such as ps_script). The same filter is applied here, on the YAML alone (no SQL
conversion, so it takes seconds, not minutes). A rule whose conversion would fail is still counted here:
the page says these are the rules "for the events we record", not "rules proven to run".
"""

import functools
import glob
import os

import yaml

from engine import detect

from . import _sigma_explain as sx

try:
    _Loader = yaml.CSafeLoader
except AttributeError:                                       # no libyaml: the pure-Python loader
    _Loader = yaml.SafeLoader


def _ours(logsource):
    logsource = logsource or {}
    cat = logsource.get("category")
    return logsource.get("product") == "windows" and (cat in detect.CATEGORY_EVENT_ID or cat in detect.DECLARED_CATEGORY_EVENT_ID)


@functools.lru_cache(maxsize=4)
def index(folders=None):
    """{rule id: {id, title, level, tags, category, ours, path, source}} over every rule file in `folders`
    (default: the engine's own folders). Correlation rules count as ours when all their base rules are."""
    folders = tuple(folders or sx.rule_folders())
    out = {}
    for folder in folders:
        own = os.path.abspath(folder) == os.path.abspath(detect.OWN_RULES)
        for path in sorted(glob.glob(os.path.join(folder, "**", "*.yml"), recursive=True)):
            try:
                with open(path, encoding="utf-8") as f:
                    docs = [d for d in yaml.load_all(f, Loader=_Loader) if isinstance(d, dict)]
            except Exception:
                continue
            names = {}
            for d in docs:
                if "detection" in d:
                    names[d.get("name") or d.get("id")] = _ours(d.get("logsource"))
            for d in docs:
                if "correlation" in d:
                    refs = (d.get("correlation") or {}).get("rules") or []
                    ours = bool(refs) and all(names.get(r, False) for r in refs)
                    category = "correlation"
                elif "detection" in d:
                    ours = _ours(d.get("logsource"))
                    category = (d.get("logsource") or {}).get("category")
                else:
                    continue
                rid = f"analystlab.{d['name']}" if own and d.get("name") else (str(d.get("id")) if d.get("id") else None)
                if not rid or rid in out:
                    continue
                out[rid] = {"id": rid, "title": d.get("title"), "level": str(d.get("level") or "informational").lower(),
                            "tags": [str(t) for t in (d.get("tags") or [])], "category": category, "ours": ours,
                            "status": d.get("status"), "path": path, "source": "analystlab" if own else "sigma"}
    return out
