"""Lab: YARA scan. "Does any published pattern rule recognise this file?"

YARA is the standard pattern language for recognising files (VirusTotal's). The engine here is YARA-X
(`pip install yara-x`, VirusTotal's official successor to YARA; yara-python has no Python 3.14 build). The
rules are public sets downloaded into downloads/night/yara/<set>/ (e.g. YARA-Forge "core"), never committed;
each rule keeps its own author, description and licence in its `meta`, and the page shows them.

Scans stay on this laptop: the file is read locally, nothing is uploaded or looked up. The file is
addressed by the same ids as the File inspector (engine/labs/_files.py), never by a path from the browser.

A match means "this rule's pattern is in the file": it is the rule author's claim about what the pattern
indicates, not a verdict of this lab, and no match means only that none of these rules fit.
"""

import glob
import json
import os
import re
import threading
import time
from typing import Optional

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _downloads, _files

router = APIRouter(prefix="/api/labs/yara")

MAX_SCAN_BYTES = 200 * 1024 * 1024
SCAN_TIMEOUT_S = 60
MAX_SCAN_ALL = 60                         # "scan everything" stops after this many files
RULE_EXT = (".yar", ".yara")

WORDS = {
    "title": "YARA scan",
    "jargon": {
        "YARA": "pattern rules for files: each rule describes text or bytes that a known tool or family carries",
        "YARA-X": "the current program that runs YARA rules (by VirusTotal, who made YARA)",
        "YARA-Forge": "a public collection of YARA rules from many authors, checked and packaged",
    },
    "intro": ("Checks a file against published YARA rules: patterns that security researchers wrote to recognise "
              "known tools and families. Runs here; nothing is uploaded."),
    "match_note": ("A match is the rule author's claim about what the pattern indicates (read its description). "
                   "No match means none of these rules fit, not that the file is harmless."),
    "no_engine": "The YARA-X engine is not installed in this Python (pip install yara-x).",
    "no_rules": "No rule set has been downloaded yet (python -m engine.labs._fetch yara).",
    "skipped": "rules could not be compiled by YARA-X and were left out",
    "scan_one": "Scan this file", "scan_all": "Scan every file of the recording we have a copy of",
    "none_matched": "No rule of these sets matched.",
    "rebuild": ("A rebuild of the same test program, not the exact file that ran (the fingerprints differ): this scan "
                "is not evidence about the recording."),
}

_lock = threading.Lock()
_cache = {"key": None, "rules": None, "info": None}


# --- the engine (a seam, so the tests can use a stand-in) ---------------------------------------------------
class YaraX:
    """Thin wrapper over the yara_x module: compile sources, scan bytes, return plain dicts."""

    def __init__(self, mod):
        self.mod = mod
        self.version = getattr(mod, "__version__", None)

    def compiler(self):
        try:
            return self.mod.Compiler(relaxed_re_syntax=True)
        except TypeError:
            return self.mod.Compiler()

    def add(self, compiler, source, origin):
        """Add one source; raise ValueError with the compiler's reason when it does not compile."""
        try:
            try:
                compiler.add_source(source, origin=origin)
            except TypeError:            # an older yara_x without `origin`
                compiler.add_source(source)
        except Exception as e:           # yara_x.CompileError (a subclass of Exception)
            raise ValueError(str(e).splitlines()[0] if str(e) else type(e).__name__) from None

    def build(self, compiler):
        return compiler.build()

    def scan(self, rules, data):
        scanner = self.mod.Scanner(rules)
        if hasattr(scanner, "set_timeout"):
            scanner.set_timeout(SCAN_TIMEOUT_S)
        res = scanner.scan(data)
        out = []
        for r in res.matching_rules:
            meta = {}
            for k, v in (r.metadata or ()):
                meta.setdefault(k, v)
            pats = []
            for p in r.patterns:
                ms = list(p.matches)
                if ms:
                    pats.append({"id": p.identifier, "hits": len(ms),
                                 "offsets": [m.offset for m in ms[:5]],
                                 "preview": _preview(data, ms[0].offset, ms[0].length)})
            out.append({"rule": r.identifier, "namespace": r.namespace, "tags": list(r.tags or ()), "meta": meta,
                        "patterns": pats})
        return out


def _preview(data, offset, length):
    chunk = data[offset:offset + min(length, 48)]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return text if sum(c != "." for c in text) >= len(text) * 0.6 else chunk.hex(" ")


def engine():
    """The YARA-X engine, or None when yara_x is not installed (the lab still loads and says so)."""
    try:
        import yara_x
    except ImportError:
        return None
    return YaraX(yara_x)


# --- the rule sets -------------------------------------------------------------------------------------------
_RULE_START = re.compile(r"^(?:(?:private|global)\s+)*rule\s+\w+", re.M)
_IMPORT = re.compile(r"^\s*import\s+\"[^\"]+\"\s*$", re.M)


def split_rules(source):
    """(imports header, [rule texts]) of a .yar file, cut at each top-level `rule` line. Used only when a whole
    file does not compile, so one rule the engine rejects does not take its whole set out."""
    header = "\n".join(_IMPORT.findall(source))
    starts = [m.start() for m in _RULE_START.finditer(source)]
    rules = [source[a:b] for a, b in zip(starts, starts[1:] + [len(source)])]
    return header, rules


def rule_sets(root):
    """[(set name, [rule files])] under downloads/night/yara/: each sub-folder is a set."""
    if not root or not os.path.isdir(root):
        return []
    out = []
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            files = sorted(f for f in glob.glob(os.path.join(p, "**", "*"), recursive=True) if f.lower().endswith(RULE_EXT))
            if files:
                out.append((d, files))
    return out


def _source_info(set_dir):
    """What was recorded about a set when it was downloaded: SOURCE.txt (our fetch script) or the downloads
    folder's manifest.json (an entry whose file is `<set folder>.zip`): url, version, sha256, licence."""
    p = os.path.join(set_dir, "SOURCE.txt")
    info = {}
    if os.path.isfile(p):
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip().lower()] = v.strip()
        return info
    name = os.path.basename(set_dir.rstrip("\\/"))
    d = os.path.dirname(set_dir.rstrip("\\/"))
    for _ in range(3):
        m = os.path.join(d, "manifest.json")
        if os.path.isfile(m):
            try:
                with open(m, encoding="utf-8-sig") as f:
                    entries = json.load(f)
            except (OSError, ValueError):
                return info
            for e in entries if isinstance(entries, list) else []:
                if os.path.splitext(e.get("file") or "")[0] == name:
                    ver = re.search(r"/download/([^/]+)/", e.get("url") or "")
                    return {"url": e.get("url"), "version": ver.group(1) if ver else None, "sha256": e.get("sha256"),
                            "license": e.get("licence") or e.get("license"), "bytes": e.get("size")}
            return info
        d = os.path.dirname(d)
    return info


def pick_sets(sets, which=None):
    """The sets to use. YARA-Forge's "extended" package contains all of "core", so the two are never loaded
    together: by default core (fewer false alarms), `which` = a set name (or part of it) for another."""
    if which:
        chosen = [s for s in sets if which.lower() in s[0].lower()]
        return chosen or sets
    core = [s for s in sets if "core" in s[0].lower()]
    supersets = [s for s in sets if any(k in s[0].lower() for k in ("extended", "full"))]
    return core + [s for s in sets if s not in core and s not in supersets] if core else sets


def compile_sets(eng, root, which=None):
    """(compiled rules or None, info): every rule file of the chosen sets (one namespace each); a file that fails
    is retried rule by rule."""
    comp = eng.compiler()
    every = rule_sets(root)
    chosen = pick_sets(every, which)
    info = {"sets": [], "rules": 0, "skipped": 0, "skipped_examples": [], "seconds": 0.0,
            "available": [n for n, _ in every], "chosen": [n for n, _ in chosen]}
    t0 = time.time()
    for name, files in chosen:
        if hasattr(comp, "new_namespace"):
            comp.new_namespace(re.sub(r"\W", "_", name))
        s = {"name": name, "files": len(files), "rules": 0, "skipped": 0,
             "source": _source_info(os.path.join(root, name))}
        for path in files:
            with open(path, encoding="utf-8", errors="replace") as f:
                src = f.read()
            n = len(_RULE_START.findall(src))
            try:
                eng.add(comp, src, origin=os.path.relpath(path, root))
                s["rules"] += n
                continue
            except ValueError:
                pass
            header, parts = split_rules(src)
            for part in parts:
                try:
                    eng.add(comp, header + "\n" + part, origin=os.path.relpath(path, root))
                    s["rules"] += 1
                except ValueError as e:
                    s["skipped"] += 1
                    if len(info["skipped_examples"]) < 5:
                        m = _RULE_START.search(part)
                        info["skipped_examples"].append({"rule": m.group(0).split()[-1] if m else "?", "reason": str(e)[:200]})
        info["sets"].append(s)
        info["rules"] += s["rules"]
        info["skipped"] += s["skipped"]
    info["seconds"] = round(time.time() - t0, 1)
    if not info["rules"]:
        return None, info
    return eng.build(comp), info


def rules_root(ctx=None):
    """ANALYSTLAB_YARA_RULES, else downloads/night/yara (our fetch script), else downloads/night/yara-forge."""
    rec = getattr(ctx, "recordings", None)
    return (os.environ.get("ANALYSTLAB_YARA_RULES") or _downloads.folder("yara", rec)
            or _downloads.folder("yara-forge", rec))


def _fingerprint(root):
    """Changes whenever a rule file is added, removed or edited (so the compiled rules are rebuilt)."""
    parts = []
    for name, files in rule_sets(root):
        for f in files:
            st = os.stat(f)
            parts.append((f, st.st_size, st.st_mtime_ns))
    return tuple(parts)


def loaded(ctx=None, eng=None, which=None):
    """(engine, compiled rules, info), compiled once per change of the rule files or of the chosen set."""
    eng = eng or engine()
    root = rules_root(ctx)
    if eng is None:
        return None, None, {"engine": None, "root": bool(root)}
    key = (id(eng.mod), root, which, _fingerprint(root) if root else ())
    with _lock:
        if _cache["key"] != key:
            rules, info = compile_sets(eng, root, which) if root else (None, {"sets": [], "rules": 0, "skipped": 0})
            info.update(engine=f"YARA-X {eng.version}" if eng.version else "YARA-X")
            _cache.update(key=key, rules=rules, info=info)
        return eng, _cache["rules"], _cache["info"]


def scan_path(eng, rules, path):
    """Matches of `rules` in the file at `path` (read here; at most MAX_SCAN_BYTES)."""
    with open(path, "rb") as f:
        data = f.read(MAX_SCAN_BYTES + 1)
    truncated = len(data) > MAX_SCAN_BYTES
    t0 = time.time()
    matches = eng.scan(rules, data[:MAX_SCAN_BYTES])
    for m in matches:
        meta = m["meta"]
        m["description"] = meta.get("description")
        m["author"] = meta.get("author")
        m["reference"] = meta.get("reference")
        m["license"] = meta.get("license")
        m["score"] = meta.get("score")
        m["date"] = meta.get("date")
        m["set"] = (m.get("namespace") or "").split(".")[0] or None
    matches.sort(key=lambda m: -(int(m["score"]) if str(m.get("score") or "").isdigit() else 0))
    return {"matches": matches, "truncated": truncated, "seconds": round(time.time() - t0, 2)}


# --- routes ------------------------------------------------------------------------------------------------
def _brief(item):
    out = {k: item[k] for k in ("id", "name", "host", "sha256", "kinds", "match")}
    out["evidence"] = bool(item.get("evidence"))
    return out


def _status(ctx, which=None):
    eng, rules, info = loaded(ctx, which=which)
    state = "ready" if rules is not None else ("no_engine" if eng is None else "no_rules")
    return eng, rules, {"state": state, **{k: v for k, v in info.items() if k != "root"}}


@router.get("")
def status(set: Optional[str] = None):
    ctx = labs.context()
    _, _, st = _status(ctx, set)
    files = [_brief(i) for i in _files.ctx_catalogue(ctx) if i["inspectable"]]
    return {"words": WORDS, "status": st, "files": files}


@router.get("/scan/{file_id}")
def scan(file_id: str, set: Optional[str] = None):
    ctx = labs.context()
    eng, rules, st = _status(ctx, set)
    if rules is None:
        raise HTTPException(status_code=503, detail=WORDS["no_engine"] if st["state"] == "no_engine" else WORDS["no_rules"])
    item = _files.resolve(_files.ctx_catalogue(ctx), file_id)
    if item is None or not item["inspectable"]:
        raise HTTPException(status_code=404, detail="no file with that id that has a copy here")
    out = {"file": _brief(item), **scan_path(eng, rules, item["local"])}
    if item["match"] == "name":
        out["rebuild"] = WORDS["rebuild"]                 # a same-name rebuild: never the evidence
    return out


@router.get("/scan-all")
def scan_all(only_recorded: bool = True, set: Optional[str] = None):
    """Every file the recording mentions that has a copy here (or also the lab's own files)."""
    ctx = labs.context()
    eng, rules, st = _status(ctx, set)
    if rules is None:
        raise HTTPException(status_code=503, detail=WORDS["no_engine"] if st["state"] == "no_engine" else WORDS["no_rules"])
    # "every file of the recording" = the EVIDENCE only (exact content that ran); rebuilds are never scanned as it
    items = [i for i in _files.ctx_catalogue(ctx) if i["inspectable"] and (i.get("evidence") or (not only_recorded and i["match"] == "lab"))]
    out = []
    for i in items[:MAX_SCAN_ALL]:
        try:
            out.append({"file": _brief(i), **scan_path(eng, rules, i["local"])})
        except OSError as e:
            out.append({"file": _brief(i), "error": f"could not be read ({type(e).__name__})", "matches": []})
    return {"results": out, "scanned": len(out), "left_out": max(0, len(items) - MAX_SCAN_ALL),
            "matched_files": sum(1 for r in out if r["matches"])}
