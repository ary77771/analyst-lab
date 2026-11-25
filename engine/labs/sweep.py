"""Indicator sweep (Labs, night-hunt): the analyst pastes a list of indicators (hashes, IP addresses,
domain names, file names or paths, registry keys; one per line, or a STIX 2.1 bundle such as the case
board exports) and gets, for each one, SEEN (when, which machine, which program, how often, a pivot
link) or NOT SEEN, and whether "not seen" can be trusted for that kind of indicator.

    POST /api/labs/sweep/   {"text": "...", "window": "all" | "24h" | ..., "start": ISO, "end": ISO}

"Not seen" is only as good as what the recorder collects. What it collects is read from the Sysmon
config itself (tools/sysmon/sysmon-config.xml): which hash algorithm, which file types and folders
file creations are recorded for, which registry places. An indicator the recorder could not have
seen is answered "can't tell here", never "not seen".

Batch work: each kind is checked in one or two queries for the whole list (IN lists on indexed columns,
or one pass over the window's rows for hashes and file names). Read-only, test machine's data only (the
dashboard's hosts), and NO internet lookups, ever: nothing here leaves the laptop.
"""

import ipaddress
import json
import os
import re
import time
import xml.etree.ElementTree as ET

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import _huntdb as db

router = APIRouter(prefix="/api/labs/sweep", tags=["labs: sweep"])

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG = os.path.join(ROOT, "tools", "sysmon", "sysmon-config.xml")
MAX_INDICATORS = 2000
WHEN_CAP = 50000                    # hit times kept per indicator for counting runs ("where else")
ALERT_INDICATORS = 40               # an alert's own indicators looked for at most
MAX_TEXT = 2_000_000
KINDS = ("sha256", "sha1", "md5", "ip", "domain", "file", "registry")
PIVOT_KIND = {"sha256": "hash", "ip": "ip", "domain": "domain", "file": "file", "registry": "registry"}
WORDS = {
    "seen": "seen",
    "not_seen": "not seen",
    "cant_tell": "can't tell here",
    "intro": "Paste indicators from a report, a feed or a case: one per line (hashes, IP addresses, domain names, "
             "file names or paths, registry keys), or a STIX 2.1 bundle. Each one is looked for in this machine's "
             "recording. Nothing is looked up on the internet.",
    "not_seen_means": "'Not seen' means: not in this recording, for the time chosen. It is not proof that it never "
                      "happened, only that the recorder, which would have seen it, did not.",
}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_REG = re.compile(r"^(HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)(\\|$)", re.I)
_FILE_EXT = re.compile(r"\.[a-z0-9]{1,5}$", re.I)
# one comparison inside a STIX pattern: object-type:path = 'value' (several may be joined by AND / OR)
_STIX_VALUE = re.compile(r"([a-z0-9-]+):([\w.'-]+?)\s*=\s*'((?:[^'\\]|\\.)*)'", re.I)
REG_ROOTS = {"hkey_local_machine": "hklm", "hkey_users": "hku", "hkey_current_user": "hkcu", "hkey_classes_root": "hkcr"}


# -- reading the list --------------------------------------------------------------------------------
def refang(s: str) -> str:
    """Undo the usual 'defanging' of indicators in reports: hxxp, [.], (.), {.}, [:]."""
    s = s.strip().strip("\"'`,;")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://")):
        s = s.replace(a, b)
    return s


def classify(raw: str):
    """(kind, normalised value) or (None, why) for one indicator."""
    s = refang(raw)
    if not s or s.startswith("#"):
        return None, "empty or a comment"
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", s, re.I)            # a URL: its host is the indicator
    if m:
        s = m.group(1)
    if _HEX.match(s) and len(s) in (32, 40, 64):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(s)], s.lower()
    try:
        return "ip", str(ipaddress.ip_address(s.strip("[]")))
    except ValueError:
        pass
    if _REG.match(s):
        head, _, rest = s.partition("\\")
        root = REG_ROOTS.get(head.lower(), head.lower())
        return "registry", (root + ("\\" + rest if rest else "")).lower()
    if "\\" in s or "/" in s or re.match(r"^[a-z]:", s, re.I):
        return "file", s.replace("/", "\\").lower()
    low = s.lower().rstrip(".")
    if _FILE_EXT.search(low) and low.rsplit(".", 1)[-1] in FILE_LIKE_EXT:
        return "file", low
    if _DOMAIN.match(low):
        return "domain", low
    if _FILE_EXT.search(low):
        return "file", low
    return None, "not a kind this sweep knows (hash, IP address, domain name, file, registry key)"


# a name ending in one of these is a file, not a domain (com is both: .com files are rare, .com domains are not)
FILE_LIKE_EXT = {"exe", "dll", "sys", "scr", "msi", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta",
                 "py", "jar", "lnk", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "pdf", "zip", "rar", "7z", "iso",
                 "img", "tmp", "dat", "txt", "bin", "ocx", "cpl", "inf", "reg"}


def from_stix(bundle: dict) -> list:
    """Indicator values from a STIX 2.1 bundle: observables (file hashes and names, addresses, domains,
    registry keys) and the values inside indicator patterns."""
    out = []
    for o in bundle.get("objects") or []:
        t = o.get("type")
        if t == "file":
            out += [v for k, v in (o.get("hashes") or {}).items() if k.upper().replace("-", "") in ("SHA256", "MD5", "SHA1")]
            if o.get("x_analystlab_path") or o.get("name"):          # the case board keeps the full path too
                out.append(o.get("x_analystlab_path") or o["name"])
        elif t in ("ipv4-addr", "ipv6-addr", "domain-name", "url") and o.get("value"):
            out.append(o["value"])
        elif t == "windows-registry-key" and o.get("key"):
            out.append(o["key"])
        elif t == "indicator" and o.get("pattern"):
            out += [m.group(3).replace("\\'", "'").replace("\\\\", "\\") for m in _STIX_VALUE.finditer(o["pattern"])]
    return out


def read_list(text: str):
    """[{raw, kind, value}] (duplicates folded) and [{raw, why}] for lines that are not indicators."""
    text = (text or "").strip()
    raws = []
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and doc.get("type") == "bundle":
            raws = from_stix(doc)
    if not raws:
        raws = [r for line in text.splitlines() for r in re.split(r"[\t,;]+|\s{2,}", line) if r.strip()]
    items, skipped, seen = [], [], set()
    for raw in raws:
        kind, value = classify(raw)
        if kind is None:
            if value != "empty or a comment":
                skipped.append({"raw": raw[:200], "why": value})
            continue
        if (kind, value) not in seen:
            seen.add((kind, value))
            items.append({"raw": raw[:300], "kind": kind, "value": value})
    return items, skipped


# -- what the recorder collects (from the Sysmon config) -------------------------------------------------
def coverage(path=CONFIG) -> dict:
    """{hashes: {...}, file_ext: [...], file_contains: [...], registry_rules: n, dns: bool, ok: bool}."""
    out = {"hashes": {"sha256"}, "file_ext": set(), "file_contains": [], "registry": True, "dns": True, "ok": False}
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError):
        return out                                           # unknown config: say "can't tell" for the uncertain kinds
    root = tree.getroot()
    algo = (root.findtext("HashAlgorithms") or "").lower()
    out["hashes"] = {a.strip().replace("-", "") for a in algo.split(",") if a.strip()} or {"sha256"}
    if "*" in algo:
        out["hashes"] = {"sha256", "sha1", "md5"}
    for fc in root.iter("FileCreate"):
        if fc.get("onmatch") == "include":
            for t in fc.findall("TargetFilename"):
                cond, val = (t.get("condition") or "").lower(), (t.text or "").lower()
                if cond == "end with":
                    out["file_ext"].add(val)
                elif cond == "contains":
                    out["file_contains"].append(val)
    dns = [d for d in root.iter("DnsQuery")]
    out["dns"] = any(d.get("onmatch") == "exclude" and not list(d) for d in dns)    # exclude nothing = record all
    out["registry"] = any(r.get("onmatch") == "include" and list(r) for r in root.iter("RegistryEvent"))
    out["ok"] = True
    out["file_ext"] = sorted(out["file_ext"])
    return out


def trust(kind, value, cov, con):
    """None when "not seen" can be trusted for this indicator, else the plain reason it can't."""
    if kind in ("md5", "sha1") and kind not in cov["hashes"]:
        return f"The recorder fingerprints files with {', '.join(sorted(cov['hashes'])).upper()} only, so a {kind.upper()} cannot be matched."
    if kind == "domain" and (not cov["dns"] or not db.has(con, "QueryName")):
        return "Name lookups (DNS) are not recorded here, so a domain can only be seen when a connection names it."
    if kind == "registry":
        if not db.has(con, "TargetObject") or not cov["registry"]:
            return "This recording has no registry events."
        if db.autostart_kind(value) == "Other autostart place":
            return "Only autostart places of the registry (Run keys, services, Winlogon...) are recorded; this key is not one."
    if kind == "file":
        name = db.basename(value)
        ext_ok = any(name.endswith(e) for e in cov["file_ext"])
        folder_ok = any(c in value for c in cov["file_contains"])
        if not (ext_ok or folder_ok):
            return ("File creations are recorded only for program and script types and a few folders; this one would "
                    "be seen only if it ran as a program.")
    if not cov["ok"]:
        return "The recorder's settings could not be read, so 'not seen' is uncertain."
    return None


# -- looking --------------------------------------------------------------------------------------------
def _add(hits, key, r, image=None, full=None):
    """Count one matching row. `full` = the value as recorded (a full path or HKU\\<SID>\\... key), so the
    pivot link can name exactly what the recording holds, not the bare name the analyst pasted."""
    h = hits.setdefault(key, {"count": 0, "first": None, "last": None, "hosts": set(), "programs": {}, "full": None, "when": []})
    if full and not h["full"]:
        h["full"] = full
    if len(h["when"]) < WHEN_CAP:                       # (host, time) of each hit: "where else" counts runs from it
        h["when"].append((r["host"], r["time"]))
    h["count"] += 1
    t = r["time"]
    h["first"] = t if h["first"] is None or (t and t < h["first"]) else h["first"]
    h["last"] = t if h["last"] is None or (t and t > h["last"]) else h["last"]
    if r["host"]:
        h["hosts"].add(r["host"])
    img = image if image is not None else r["Image"]
    if img:
        h["programs"][img] = h["programs"].get(img, 0) + 1


def _in(con, w, col, values, extra="1=1", cols="time, host, Image"):
    """Rows whose `col` (lower-cased) is one of `values`, in chunks (IN lists use the column's index)."""
    tw, tp = w.sql()
    hw, hp = db.host_filter(None)
    hw += " AND " + db.own_filter(con)                   # never the lab's own test machinery (_shared_defs)
    values = sorted(values)
    for i in range(0, len(values), 400):
        chunk = values[i:i + 400]
        yield from con.execute(f"SELECT {col} AS v, {cols} FROM events WHERE {col} IN ({','.join('?' * len(chunk))}) "
                               f"AND {extra}{tw}{hw}", chunk + tp + hp)


def look(con, items, w) -> dict:
    """{(kind, value): hit} for every indicator seen, in batch queries per kind."""
    hits = {}
    by = {k: {i["value"] for i in items if i["kind"] == k} for k in KINDS}
    cols = db.columns(con)
    tw, tp = w.sql()
    hw, hp = db.host_filter(None)
    hw += " AND " + db.own_filter(con)                   # never the lab's own test machinery (_shared_defs)
    frm = db.events_from(con, w)
    # hashes: the agent's fingerprints (sha256 column) + Sysmon's Hashes field ("SHA256=...,MD5=...")
    hashes = by["sha256"] | by["md5"] | by["sha1"]
    if hashes:
        if "sha256" in cols and by["sha256"]:
            for r in con.execute(f"SELECT lower(sha256) AS v, time, host, TargetFilename AS Image FROM {frm} "
                                 f"WHERE type = 'FILE_HASH' AND sha256 IS NOT NULL{tw}{hw}", tp + hp):
                if r["v"] in by["sha256"]:
                    _add(hits, ("sha256", r["v"]), r)
        if "hashes" in cols:
            # Sysmon writes Hashes on process starts, driver/image loads, streams and deletions only
            for r in con.execute(f"SELECT Hashes, time, host, Image FROM {frm} WHERE event_id IN (1, 6, 7, 15, 23, 24, 25, 26) "
                                 f"AND Hashes IS NOT NULL{tw}{hw}", tp + hp):
                for part in (r["Hashes"] or "").split(","):
                    algo, _, val = part.partition("=")
                    kind, val = algo.strip().lower().replace("-", ""), val.strip().lower()
                    if kind in ("sha256", "md5", "sha1") and val in by[kind]:
                        _add(hits, (kind, val), r)
    if by["ip"]:
        # the other side of a connection: DestinationIp of outgoing ones (indexed); SourceIp only of incoming
        # ones (Initiated = false), where it is the remote side. LocalIp is this machine's own address.
        if "destinationip" in cols:
            for r in _in(con, w, "DestinationIp", by["ip"]):
                _add(hits, ("ip", r["v"]), r)
        if "sourceip" in cols:
            for r in _in(con, w, "SourceIp", by["ip"], "event_id = 3 AND Initiated = 'false'"):
                _add(hits, ("ip", r["v"]), r)
    if by["domain"]:
        if "queryname" in cols:
            for r in _in(con, w, "lower(QueryName)", by["domain"], "event_id = 22"):
                _add(hits, ("domain", r["v"]), r)
        if "destinationhostname" in cols:
            for r in _in(con, w, "lower(DestinationHostname)", by["domain"], "event_id = 3"):
                _add(hits, ("domain", r["v"]), r)
    if by["file"]:
        paths = {v for v in by["file"] if "\\" in v}
        names = {v for v in by["file"] if "\\" not in v}
        fcols = [c for c in ("Image", "TargetFilename", "final_path") if c.lower() in cols]
        sel = ", ".join(f"{c}" for c in fcols)
        where = " OR ".join(f"{c} IS NOT NULL" for c in fcols)
        # the events that name a file: starts (the program's own file), file created / deleted / stream, the
        # agent's fingerprints. Network and registry events repeat a program already seen starting.
        kinds = "(event_id IN (1, 11, 15, 23, 26) OR type = 'FILE_HASH')"
        for r in con.execute(f"SELECT {sel}, time, host, Image AS prog FROM {frm} WHERE {kinds} AND ({where}){tw}{hw}", tp + hp):
            done = set()
            for c in fcols:
                orig = r[c]
                if not orig:
                    continue
                v = orig.lower()
                for key in ((v in paths) and v, (db.basename(v) in names) and db.basename(v)):
                    if key and key not in done:
                        done.add(key)
                        _add(hits, ("file", key), r, image=r["prog"], full=orig)
    if by["registry"] and "targetobject" in cols:
        regs = sorted(by["registry"])
        for r in con.execute(f"SELECT TargetObject AS orig, time, host, Image FROM {frm} "
                             f"WHERE event_id IN (12, 13, 14) AND TargetObject IS NOT NULL{tw}{hw}", tp + hp):
            v = r["orig"].lower()
            # Sysmon writes a user's keys as HKU\<SID>\...: they also answer an indicator given as HKCU\...
            as_hkcu = re.sub(r"^hku\\[^\\]+\\", "hkcu\\\\", v)
            for k in regs:                                   # a key matches itself and every value under it
                if any(x == k or x.startswith(k + "\\") for x in (v, as_hkcu)):
                    _add(hits, ("registry", k), r, full=r["orig"])
    return hits


def sweep(con, text, w) -> dict:
    t0 = time.perf_counter()
    items, skipped = read_list(text)
    truncated = len(items) > MAX_INDICATORS
    items = items[:MAX_INDICATORS]
    cov = coverage()
    hits = look(con, items, w)
    rows = []
    for it in items:
        h = hits.get((it["kind"], it["value"]))
        why = None if h else trust(it["kind"], it["value"], cov, con)
        verdict = "seen" if h else ("cant_tell" if why else "not_seen")
        progs = sorted((h or {}).get("programs", {}).items(), key=lambda kv: -kv[1])[:3]
        rows.append({**it, "verdict": verdict, "verdict_word": WORDS[verdict], "count": h["count"] if h else 0,
                     "first": h["first"] if h else None, "last": h["last"] if h else None,
                     "hosts": sorted(h["hosts"]) if h else [], "programs": [{"program": p, "count": n} for p, n in progs],
                     "why_uncertain": why,
                     "pivot": {"kind": PIVOT_KIND[it["kind"]], "value": (h or {}).get("full") or it["value"]}
                     if PIVOT_KIND.get(it["kind"]) else None})
    order = {"seen": 0, "cant_tell": 1, "not_seen": 2}
    rows.sort(key=lambda r: (order[r["verdict"]], r["first"] or ""))
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in order}
    return {"rows": rows, "counts": counts, "skipped": skipped[:200], "skipped_total": len(skipped),
            "truncated": truncated, "coverage": {"hashes": sorted(cov["hashes"]), "dns": cov["dns"],
                                                 "file_types": cov["file_ext"], "config_read": cov["ok"]},
            "words": WORDS, "ms": round((time.perf_counter() - t0) * 1000)}


# -- "where else does this appear?" (analyst critique gap 2: scope) ------------------------------------------
ROLES = {"fingerprint": "the program's fingerprint", "program": "the program file", "parent": "its parent program",
         "address": "an address it contacted", "wrote": "a file it wrote", "wrote_fp": "the fingerprint of a file it wrote"}


def _chunks(items, n=400):
    items = list(items)
    for i in range(0, len(items), n):
        yield items[i:i + n]


def alert_indicators(con, scope) -> list:
    """The alert's own indicators: [{raw, kind, value, role}], from its evidence processes and the programs they
    started (one step), inside its run: their fingerprints and files, their parent program, the addresses they
    contacted, the files they wrote. The test machinery (_shared_defs.is_harness) is never an indicator."""
    from . import _shared_defs as sd                       # noqa: PLC0415
    w = scope["window"]
    tw, tp = w.sql()
    hw, hp = db.host_filter(scope["host"])
    cols = db.columns(con)
    evidence = set(scope["guids"])
    procs = set(evidence)
    for chunk in _chunks(evidence):                       # one step down: what the alert's processes started
        procs.update(g for (g,) in con.execute(
            f"SELECT ProcessGuid FROM events WHERE event_id = 1 AND ParentProcessGuid IN ({','.join('?' * len(chunk))}){tw}{hw}",
            chunk + tp + hp) if g)
    out, seen = [], set()

    def add(raw, role, of=None):
        kind, value = classify(str(raw or ""))
        if kind and (kind, value) not in seen and len(out) < ALERT_INDICATORS:
            seen.add((kind, value))
            out.append({"raw": str(raw), "kind": kind, "value": value, "role": ROLES[role], "of": of})

    for chunk in _chunks(procs):
        q = ",".join("?" * len(chunk))
        starts = [dict(r) for r in con.execute(
            f"SELECT ProcessGuid, ParentProcessGuid, Image, Hashes, ParentImage, CommandLine, origin FROM events "
            f"WHERE event_id = 1 AND ProcessGuid IN ({q}){hw}", chunk + hp)]
        # a parent is judged by its OWN start record (a generic powershell.exe is the launcher only by its command line)
        pg = [s["ParentProcessGuid"] for s in starts if s["ProcessGuid"] in evidence and s["ParentProcessGuid"]]
        parent_rows = {}
        for pchunk in _chunks(set(pg)):
            for r in con.execute(f"SELECT ProcessGuid, Image, CommandLine, origin FROM events WHERE event_id = 1 "
                                 f"AND ProcessGuid IN ({','.join('?' * len(pchunk))}){hw}", pchunk + hp):
                parent_rows[r["ProcessGuid"]] = dict(r)
        for r in starts:
            if sd.is_harness(r):
                continue
            m = re.search(r"SHA256=([0-9A-Fa-f]{64})", r["Hashes"] or "")
            if m:
                add(m.group(1), "fingerprint", of=db.basename(r["Image"]))
            add(r["Image"], "program")
            parent = parent_rows.get(r["ParentProcessGuid"]) or {"Image": r["ParentImage"]}
            if r["ProcessGuid"] in evidence and r["ParentImage"] and not sd.is_harness(parent):
                add(r["ParentImage"], "parent")
        for r in con.execute(f"SELECT Image, DestinationIp, DestinationPort, origin FROM events WHERE event_id = 3 "
                             f"AND ProcessGuid IN ({q}){tw}{hw}", chunk + tp + hp):
            if r["DestinationIp"] and not sd.is_harness(dict(r)):
                add(r["DestinationIp"], "address")
        if "targetfilename" in cols:
            for r in con.execute(f"SELECT TargetFilename FROM events WHERE event_id = 11 AND ProcessGuid IN ({q}){tw}{hw}",
                                 chunk + tp + hp):
                add(r["TargetFilename"], "wrote")
        if "sha256" in cols:
            for r in con.execute(f"SELECT sha256 FROM events WHERE type = 'FILE_HASH' AND sha256 IS NOT NULL "
                                 f"AND ProcessGuid IN ({q}){tw}{hw}", chunk + tp + hp):
                add(r["sha256"], "wrote_fp")
    return out


def _boots(con):
    """{host: sorted start times}: each machine start (Sysmon event 4 State=Started) begins a new run."""
    out = {}
    hw, hp = db.host_filter(None)
    if not db.has(con, "State"):
        return out
    for h, t in con.execute(f"SELECT host, time FROM events WHERE event_id = 4 AND State = 'Started'{hw} ORDER BY time", hp):
        out.setdefault(h, []).append(t)
    return out


def where_else(con, scope) -> dict:
    """The alert's own indicators, looked for in the whole recording (the machines this dashboard shows), each
    counted by runs: how often in the alert's own run, in how many OTHER runs, first/last elsewhere."""
    import bisect
    t0 = time.perf_counter()
    items = alert_indicators(con, scope)
    hits = look(con, items, db.Window(None, None, "all", bounded=False)) if items else {}
    boots = _boots(con)
    run_of = lambda h, t: (h, bisect.bisect_right(boots.get(h, []), t or ""))   # noqa: E731
    mine = run_of(scope["host"], scope["window"].since)
    cov = coverage()
    rows = []
    for it in items:
        h = hits.get((it["kind"], it["value"]))
        whens = (h or {}).get("when", [])
        runs = {run_of(host, t) for host, t in whens}
        in_run = sum(1 for host, t in whens if run_of(host, t) == mine)
        away = sorted(t for host, t in whens if run_of(host, t) != mine)
        why = None if h else trust(it["kind"], it["value"], cov, con)
        rows.append({**it, "verdict": "seen" if h else ("cant_tell" if why else "not_seen"), "times": (h or {}).get("count", 0),
                     "in_this_run": in_run, "other_runs": len(runs - {mine}), "elsewhere": len(away),
                     "elsewhere_first": away[0] if away else None, "elsewhere_last": away[-1] if away else None,
                     "hosts": sorted((h or {}).get("hosts", ())), "why_uncertain": why,
                     "pivot": {"kind": PIVOT_KIND[it["kind"]], "value": (h or {}).get("full") or it["value"]}
                     if PIVOT_KIND.get(it["kind"]) else None})
    runs_total = sum(len(v) for v in boots.values())
    # a thing in at least half of all runs (conhost.exe, the test server's address...) says nothing about THIS
    # alert's reach: marked "common" and put last, so the distinctive things lead
    for r in rows:
        r["common"] = bool(runs_total >= 4 and r["other_runs"] + 1 >= runs_total / 2)
    order = [ROLES[k] for k in ("fingerprint", "program", "wrote_fp", "wrote", "address", "parent")]
    rows.sort(key=lambda r: (r["common"], r["verdict"] != "seen", -r["other_runs"], order.index(r["role"]), -r["elsewhere"]))
    notes = [f"A run is one start of a machine to its next start; this recording holds {runs_total} start(s) of the machines shown.",
             "Only the machines this dashboard shows are searched (the test machine, unless it was started with "
             "--labs-all-hosts)."]
    if any(r["common"] for r in rows):
        notes.append("'Common on this machine' = seen in at least half of all runs (Windows' own helpers, the test "
                     "server's address): listed last, they say little about where THIS alert's activity reached.")
    return {"rows": rows, "spread": sum(1 for r in rows if r["other_runs"] and not r["common"]), "runs_total": runs_total,
            "notes": notes,
            "text": "\n".join(r["raw"] for r in rows), "ms": round((time.perf_counter() - t0) * 1000)}


@router.get("/alert/{alert_id}")
def alert_sweep(alert_id: str):
    """Where else does this alert's own stuff appear? (?alert= on the sweep page)."""
    try:
        con = db.connect(db.events_path())
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        scope = db.alert_scope(con, alert_id)
        if scope.get("missing"):
            return {"alert": {"id": alert_id, "missing": True}, "rows": [], "text": "", "notes": []}
        return {**where_else(con, scope), "alert": db.alert_public(scope, True), **db.result_meta(con, scope["window"], scope["host"])}
    finally:
        con.close()


class SweepIn(BaseModel):
    text: str
    window: str = "all"
    start: str | None = None
    end: str | None = None


@router.get("/")
def about():
    return {"words": WORDS, "windows": list(db.WINDOWS), "max": MAX_INDICATORS}


@router.post("/")
def run(body: SweepIn):
    if len(body.text) > MAX_TEXT:
        raise HTTPException(status_code=413, detail="the list is too long (2 MB at most)")
    try:
        con = db.connect(db.events_path())
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        try:
            w = db.window(con, body.window, body.start, body.end)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {**sweep(con, body.text, w), **db.result_meta(con, w)}
    finally:
        con.close()
