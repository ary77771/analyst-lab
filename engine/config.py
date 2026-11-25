"""The one place every chosen number is read from: config/frozen.yaml (fair-test rule 2;
docs/plans/freeze-prep.md). Engine code asks this module instead of keeping hidden defaults, so
what the freeze locks is what really runs.
"""

import os
from datetime import timedelta
from typing import NamedTuple

import yaml

FROZEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "frozen.yaml")


def load(path: str = FROZEN) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def min_level(path: str = FROZEN) -> str:
    """The lowest Sigma level that raises an alert (Yousif 2026-10-23: medium)."""
    value = (load(path).get("sigma") or {}).get("min_level")
    if value is None:
        raise ValueError("config/frozen.yaml sigma.min_level is not chosen yet")
    return value


def hub_rule(path: str = FROZEN):
    """graph.hub_rule (package G), or None while it is not chosen. Its learning settings must be
    there: engine/hubs.py learns with exactly these, no defaults of its own."""
    from .hubs import METHOD
    rule = (load(path).get("graph") or {}).get("hub_rule")
    if not rule:
        return None
    missing = [k for k in ("method", "top_share", "min_children", "file") if rule.get(k) is None]
    if missing:
        raise ValueError(f"config/frozen.yaml graph.hub_rule lacks {missing}")
    if rule["method"] != METHOD:
        raise ValueError(f"graph.hub_rule.method {rule['method']!r} is not implemented (only {METHOD!r})")
    return rule


def hubs(path: str = FROZEN, allow_missing: bool = False):
    """The frozen hub list (package G) as a frozenset of normalized program paths, or None while
    the rule is not chosen. The file must exist (allow_missing=True: None instead, for a machine
    that never has it, e.g. a friend's), carry the frozen SHA256 (any case) and have been learned
    with the frozen settings; anything else is refused, never silently skipped."""
    import hashlib
    from .hubs import load as load_hubs, read
    rule = hub_rule(path)
    if rule is None:
        return None
    if not rule.get("sha256"):
        raise ValueError("config/frozen.yaml graph.hub_rule.sha256 is not set")
    file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(path))), rule["file"])
    if not os.path.exists(file):
        if allow_missing:
            return None
        raise FileNotFoundError(f"hub list {rule['file']} is missing on this machine")
    with open(file, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != str(rule["sha256"]).strip().lower():
        raise ValueError(f"{rule['file']} changed since it was frozen (sha256 {digest[:12]}...)")
    doc = read(file)
    if (doc.get("method"), doc.get("top_share"), doc.get("min_children")) != \
            (rule["method"], rule["top_share"], rule["min_children"]):
        raise ValueError(f"{rule['file']} was learned with other settings than graph.hub_rule")
    found = load_hubs(file)
    if not found:
        raise ValueError(f"{rule['file']} lists no hub: an empty list would switch suppression off unnoticed")
    return found


def declared_registry(path: str = FROZEN) -> bool:
    """declared_registry.reg_command (v4 F7): offer the registry rules the registry writes declared
    on reg.exe command lines (engine/regcmd.py, engine/detect.py). Must be chosen: true or false."""
    value = (load(path).get("declared_registry") or {}).get("reg_command")
    if not isinstance(value, bool):
        raise ValueError("config/frozen.yaml declared_registry.reg_command must be true or false")
    return value


def declared_script(path: str = FROZEN) -> bool:
    """declared_script.powershell_command (v4 F8): offer the PowerShell script rules (Sigma ps_script)
    the code declared on powershell.exe command lines (engine/pscmd.py). Must be chosen: true or false."""
    value = (load(path).get("declared_script") or {}).get("powershell_command")
    if not isinstance(value, bool):
        raise ValueError("config/frozen.yaml declared_script.powershell_command must be true or false")
    return value


def declared_kinds(path: str = FROZEN) -> frozenset:
    """Which declared rows the rules are offered (engine/detect.py): {"registry", "script"} or a part."""
    return frozenset(k for k, on in (("registry", declared_registry(path)), ("script", declared_script(path))) if on)


def own_rule_params(path: str = FROZEN) -> dict:
    """{rule_id: {argument: value}} for engine/own_rules.run_all."""
    block = load(path).get("own_rules") or {}
    return {f"analystlab.{name}": dict(args or {}) for name, args in block.items()}


class GraphView(NamedTuple):
    window: timedelta          # +- this around the alert
    max_depth: int             # steps from the seed
    max_nodes: int             # nodes in one view


def graph_view(path: str = FROZEN) -> GraphView:
    """graph.window_minutes / max_depth / max_nodes: the bounds of every view (report, dashboard,
    graph checker). Refuses a missing or null value, or one that is not a positive number."""
    block = load(path).get("graph") or {}
    values = {}
    for key in ("window_minutes", "max_depth", "max_nodes"):
        v = block.get(key)
        if v is None:
            raise ValueError(f"config/frozen.yaml graph.{key} is not chosen yet (null or missing)")
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            raise ValueError(f"config/frozen.yaml graph.{key} must be a positive number, got {v!r}")
        if key != "window_minutes" and int(v) != v:
            raise ValueError(f"config/frozen.yaml graph.{key} must be a whole number, got {v!r}")
        values[key] = v
    return GraphView(timedelta(minutes=values["window_minutes"]), int(values["max_depth"]), int(values["max_nodes"]))


# -- official runs ---------------------------------------------------------------------------------
OFFICIAL_ENV = "ANALYSTLAB_OFFICIAL"


def is_official() -> bool:
    """True inside an official evaluation run (tools/run_series.py --label official sets
    ANALYSTLAB_OFFICIAL=1): then every frozen value and file must be in place (verify_official)."""
    return os.environ.get(OFFICIAL_ENV) == "1"


def _root(path: str) -> str:
    """The project root of a frozen file at <root>/config/frozen.yaml (paths in it are relative to it)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(path)))


def _sha256_of(file: str) -> str:
    import hashlib
    with open(file, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def default_pool(path: str = FROZEN) -> str:
    """Where the frozen pool of normal rates lives (engine.confidence --build-pool --out ...)."""
    return os.path.join(_root(path), "recordings", "confidence", "pool.json")


def verify_official(path: str = FROZEN, pool: str = None) -> list:
    """Everything an official run needs, checked BEFORE it runs: a list of problems in plain words
    (empty = OK). Nothing is skipped silently:
      - the confidence block loads in official mode (burst_factor and pool_sha256 chosen);
      - the pool file (default <root>/recordings/confidence/pool.json) has that SHA256 and was
        built with the same confidence settings;
      - every `baselines:` entry {file, sha256, learned_from} exists with that SHA256 (any case);
      - the hub rule and its list load (config.hubs());
      - sigma.min_level and the graph view bounds are chosen."""
    from . import confidence as C
    problems = []
    try:
        doc = load(path)
    except (OSError, ValueError) as e:
        return [f"config/frozen.yaml cannot be read: {e}"]
    cfg = None
    try:
        cfg = C.load_config(path, official=True)
    except (OSError, ValueError, TypeError) as e:
        problems.append(f"confidence: {e}")
    pool = pool or default_pool(path)
    if cfg is not None:
        if not os.path.exists(pool):
            problems.append(f"pool of normal rates missing: {pool}")
        else:
            try:
                C.Pool.load(pool, expect_sha256=cfg.pool_sha256, cfg=cfg)
            except (OSError, ValueError, KeyError) as e:
                problems.append(f"pool {os.path.basename(pool)}: {e}")
    entries = doc.get("baselines")
    if not entries:
        problems.append("baselines: no learned-normal file is listed")
    for i, entry in enumerate(entries or []):
        if not isinstance(entry, dict) or not entry.get("file") or not entry.get("sha256") or not entry.get("learned_from"):
            problems.append(f"baselines entry {i + 1}: needs file, sha256 and learned_from")
            continue
        file = os.path.join(_root(path), entry["file"])
        if not os.path.exists(file):
            problems.append(f"baseline {entry['file']} is missing on this machine")
        elif _sha256_of(file) != str(entry["sha256"]).strip().lower():
            problems.append(f"baseline {entry['file']} changed since it was frozen (sha256 differs)")
    try:
        if hubs(path) is None:
            problems.append("graph.hub_rule is not chosen")
    except (OSError, ValueError, KeyError, TypeError) as e:
        problems.append(f"hub list: {e}")
    for check in (min_level, graph_view):
        try:
            check(path)
        except (ValueError, TypeError) as e:
            problems.append(str(e))
    return problems
