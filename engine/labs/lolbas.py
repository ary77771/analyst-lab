"""Lab: LOLBAS check. "Which built-in Windows tools ran, and did they run the way attackers are known to use them?"

LOLBAS ("Living Off The Land Binaries, Scripts and Libraries", lolbas-project.github.io, GPL-3.0) is the public
catalogue of Windows' own programs that can be misused: to download, run code, get round application
allow-listing (AWL bypass), copy credentials... Each entry lists documented command lines, each with a
category, a use case and an ATT&CK technique. The data (api/lolbas.json) is downloaded once into
downloads/night/lolbas/ and read here; nothing is sent anywhere.

For every program start (Sysmon event 1) whose file name, or Windows' OriginalFileName (which survives a
rename), is in the catalogue: which misuse categories the catalogue documents for it, whether it ran from a
documented place, and how closely the recorded command line resembles each documented command (the share of
the documented switches that are in it). A resemblance is a pointer for the investigator, not a finding.
"""

import json
import os
import re
import threading

from fastapi import APIRouter, HTTPException

from engine import labs
from engine.labs import _downloads

router = APIRouter(prefix="/api/labs/lolbas")

RESEMBLE_AT = 0.5                 # share of a documented command's switches seen in the command line
MAX_RUNS_PER_TOOL = 25
PAGE = "https://lolbas-project.github.io/lolbas/{type}/{name}/"

WORDS = {
    "title": "Built-in tools check (LOLBAS)",
    "jargon": {
        "LOLBAS": "Windows' own tools that can be misused: intruders 'live off the land' by using what is already installed",
        "ATT&CK": "MITRE's public list of the techniques intruders use, each with an id such as T1105",
    },
    "intro": ("Windows' own programs that the LOLBAS project documents as misusable, as they ran in this recording. "
              "Running one is normal; how it was run is what matters."),
    "resemble": "The command line has {n} of the {of} switches of this documented use",
    "resemble_note": ("Resemblance = share of the documented command's switches found in the recorded command "
                      "line: at least half of them and at least two (or all of them). A pointer for a closer look, "
                      "not a finding."),
    "renamed": "Renamed: Windows says this file's original name is {orig}",
    "odd_place": "Not at one of the places the catalogue documents for it",
    "no_data": "The LOLBAS data has not been downloaded yet (python -m engine.labs._fetch lolbas).",
    "none_seen": "None of the catalogue's programs ran in this recording.",
    "none_seen_alert": "None of the programs in this alert's story is a catalogued Windows tool.",
    "source": "Data: LOLBAS project (lolbas-project.github.io), GPL-3.0",
}

_lock = threading.Lock()
_cache = {"key": None, "data": None}


def data_path(ctx=None):
    if os.environ.get("ANALYSTLAB_LOLBAS_JSON"):
        return os.environ["ANALYSTLAB_LOLBAS_JSON"]
    d = _downloads.folder("lolbas", getattr(ctx, "recordings", None))
    return os.path.join(d, "lolbas.json") if d else None


def load(path):
    """The catalogue as {lower-case file name: entry}, cached by the file's mtime."""
    if not path or not os.path.isfile(path):
        return None
    key = (path, os.path.getmtime(path))
    with _lock:
        if _cache["key"] == key:
            return _cache["data"]
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    data = {}
    for e in raw:
        name = (e.get("Name") or "").strip()
        if name:
            data[name.lower()] = e
    with _lock:
        _cache.update(key=key, data=data)
    return data


_SWITCH = re.compile(r"(?<![\w{])([-/][A-Za-z][\w:-]*)")
_URL_HOLE = re.compile(r"\{REMOTEURL[^}]*\}|https?://", re.I)


def switches(command):
    """The switches of a command line (-urlcache, /i:, -split), lower-case, the program's own path left out
    and placeholders ({PATH} ...) ignored. `/i:http://x` gives `/i:`."""
    text = command or ""
    first = re.match(r'^\s*("[^"]*"|\S+)', text)
    rest = text[first.end():] if first else text
    out = []
    for m in _SWITCH.finditer(rest):
        s = m.group(1).lower()
        if s.startswith("/") and ("\\" in s or s.count("/") > 1):
            continue                      # a path, not a switch
        s = re.split(r"(?<=:)", s)[0] if ":" in s else s
        if s not in out:
            out.append(s)
    return out


def _norm(s):
    return s.lstrip("-/").rstrip(":")


def resemblance(observed, documented):
    """(score 0..1, [documented switches found]) of a recorded command line against a documented command."""
    want = switches(documented)
    have = {_norm(s) for s in switches(observed)}
    needs_url = bool(_URL_HOLE.search(documented or ""))
    total = len(want) + (1 if needs_url else 0)
    if total == 0:
        return 0.0, []
    hit = [s for s in want if _norm(s) in have]
    if needs_url and re.search(r"https?://|\\\\", observed or "", re.I):
        hit.append("(a web address)")
    return round(len(hit) / total, 2), hit


def _basename(p):
    return re.split(r"[\\/]", p or "")[-1]


def _norm_path(p):
    return re.sub(r"\\+", "\\\\", (p or "").lower()).replace("c:\\windows\\syswow64", "c:\\windows\\system32")


# placeholders, and dotted version numbers (the catalogue gives one example version, e.g. ...\\131.0.2903.70\\...)
_HOLE = re.compile(r"<[^>]*>|\{[^}]*\}|\*|\d+(?:\.\d+){1,3}")


def place_pattern(documented):
    """A documented path as a regex: placeholders (<version>, {VERSION}, *) and version numbers stand for any
    text within one folder name; the
    32/64-bit Program Files and System32/SysWOW64 folders count as the same place."""
    s = _norm_path(documented).replace("program files (x86)", "program files")
    parts = _HOLE.split(s)
    rx = "[^\\\\]+".join(re.escape(x) for x in parts)
    return re.compile("^" + rx + "$")


def at_documented_place(image, patterns):
    """True / False, or None when the catalogue documents no place."""
    if not patterns:
        return None
    s = _norm_path(image).replace("program files (x86)", "program files")
    return any(p.match(s) for p in patterns)


def resembles(m):
    """A run resembles a documented use when at least half of its switches are there AND at least two of them
    (or all, for a use with a single switch): one common switch alone is not enough."""
    return bool(m and m["score"] >= RESEMBLE_AT and (len(m["matched"]) >= 2 or m["score"] >= 1.0))


def entry_summary(e):
    cmds = e.get("Commands") or []
    return {"name": e.get("Name"), "description": e.get("Description"), "type": _type_folder(e),
            "categories": sorted({c.get("Category") for c in cmds if c.get("Category")}),
            "mitre": sorted({c.get("MitreID") for c in cmds if c.get("MitreID")}),
            "page": PAGE.format(type=_type_folder(e), name=os.path.splitext(e.get("Name") or "")[0])}


def _type_folder(e):
    p = (e.get("url") or "") or ""
    for t in ("Binaries", "Libraries", "Scripts", "OtherMSBinaries"):
        if f"/{t}/" in p:
            return t
    name = (e.get("Name") or "").lower()
    return "Libraries" if name.endswith(".dll") else "Scripts" if name.endswith((".vbs", ".js", ".ps1", ".wsf", ".cmd", ".bat")) else "Binaries"


def best_match(command, entry):
    best = None
    for c in entry.get("Commands") or []:
        score, hit = resemblance(command, c.get("Command"))
        if best is None or score > best["score"]:
            of = len(switches(c.get("Command"))) + (1 if _URL_HOLE.search(c.get("Command") or "") else 0)
            best = {"score": score, "matched": hit, "of": of, "category": c.get("Category"), "usecase": c.get("Usecase"),
                    "description": c.get("Description"), "command": c.get("Command"), "mitre": c.get("MitreID"),
                    "privileges": c.get("Privileges")}
    return best


def check(con, catalogue, guids=None):
    """[{tool..., runs: [...]}] for the program starts in the store whose name is in the catalogue."""
    tools = {}
    from engine.labs._files import host_clause
    hw, hp = host_clause()                     # VM data only unless the laptop switch is on (night rule 11)
    rows = con.execute("SELECT host, time, Image, OriginalFileName, CommandLine, ParentImage, Hashes, User, ProcessGuid "
                       f"FROM events WHERE event_id = 1 AND Image IS NOT NULL{hw} ORDER BY time", hp)
    for host, t, image, orig, cmd, parent, hashes, user, guid in rows:
        if guids is not None and (guid or "").lower() not in guids:
            continue                                  # with an alert: only the programs of its own story
        name = _basename(image).lower()
        o = (orig or "").lower()
        entry = catalogue.get(name) or catalogue.get(o)
        if entry is None:
            continue
        key = entry["Name"].lower()
        tool = tools.get(key)
        if tool is None:
            tool = tools[key] = {**entry_summary(entry), "runs": [], "times": 0, "resembling": 0, "renamed": 0,
                                 "odd_place": 0, "_paths": [place_pattern(p.get("Path")) for p in entry.get("Full_Path") or []
                                                            if p.get("Path")]}
        renamed = bool(o) and o != name and catalogue.get(o) is entry
        documented = at_documented_place(image, tool["_paths"])
        m = best_match(cmd, entry)
        resembling = resembles(m)
        tool["times"] += 1
        tool["resembling"] += resembling
        tool["renamed"] += renamed
        tool["odd_place"] += documented is False
        sha = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes or "")
        tool["runs"].append({"time": t, "host": host, "image": image, "command_line": cmd, "parent": parent, "user": user,
                             "renamed_from": orig if renamed else None, "documented_place": documented,
                             "sha256": sha.group(1).lower() if sha else None,
                             "match": m if resembling else None, "nearest": None if resembling else m})
    out = []
    for tool in tools.values():
        tool.pop("_paths")
        # the runs that resemble a documented misuse first, then the newest
        tool["runs"].sort(key=lambda r: (r["match"] is None, -(r["match"] or {}).get("score", 0), r["time"] or ""), reverse=False)
        tool["runs"] = tool["runs"][:MAX_RUNS_PER_TOOL]
        out.append(tool)
    out.sort(key=lambda x: (-x["resembling"], -x["renamed"], -x["odd_place"], x["name"].lower()))
    return out


@router.get("")
def lolbas(alert: str = None):
    ctx = labs.context()
    scope = None
    if alert:
        from engine.labs import _files
        try:
            scope = _files.alert_scope(ctx, alert)
        except LookupError as e:
            raise HTTPException(status_code=404, detail=str(e))
    path = data_path(ctx)
    catalogue = load(path)
    if catalogue is None:
        return {"words": WORDS, "state": "no_data", "tools": []}
    try:
        with ctx.reading() as con:
            tools = check(con, catalogue, scope["guids"] if scope else None)
    except (FileNotFoundError, OSError):
        tools = []
    except Exception as e:                       # e.g. a store without the columns: said, not raised
        return {"words": WORDS, "state": "error", "error": f"{type(e).__name__}: {e}", "tools": []}
    return {"words": WORDS, "state": "ready", "catalogue_size": len(catalogue), "tools": tools,
            "alert": scope and scope["alert"],
            "runs": sum(t["times"] for t in tools), "resembling": sum(t["resembling"] for t in tools),
            "resemble_at": RESEMBLE_AT}
