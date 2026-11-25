"""MITRE ATT&CK (Enterprise) for the night-explain labs: tactics, techniques, mitigations, read from the
downloaded STIX bundle (engine/labs/_fetch_attack.py; downloads/night/attack/, never committed).

Nothing here is invented: every name, description and mitigation is MITRE's text from the bundle, with its
ATT&CK id and URL. Sigma rules name techniques in their tags (`attack.t1059.001`); a tag naming a technique
MITRE has since revoked is followed to its replacement (MITRE's own `revoked-by` relationship) and said so.
ATT&CK © The MITRE Corporation (terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

import functools
import json
import os
import re

from . import _downloads

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
LEGAL = "ATT&CK® © The MITRE Corporation. Used under MITRE's ATT&CK terms of use."


def data_folder():
    return _downloads.find("night/attack")


def bundle_path(folder=None):
    """The bundle the manifest names (or the newest enterprise-attack-*.json), or None."""
    folder = folder or data_folder()
    if not folder or not os.path.isdir(folder):
        return None
    try:
        with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
            p = os.path.join(folder, json.load(f)["file"])
            if os.path.exists(p):
                return p
    except (OSError, ValueError, KeyError):
        pass
    files = sorted(f for f in os.listdir(folder) if f.startswith("enterprise-attack") and f.endswith(".json"))
    return os.path.join(folder, files[-1]) if files else None


def plain(text, first_paragraph=False):
    """MITRE's markdown description without its citation markers ("(Citation: ...)"); links keep their words."""
    t = CITATION.sub("", text or "")
    t = LINK.sub(r"\1", t)
    t = t.replace("<code>", "").replace("</code>", "").strip()
    if first_paragraph:
        t = t.split("\n\n")[0].strip()
    return t


def _ext(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"], r.get("url")
    return None, None


class Attack:
    """The parts of one ATT&CK Enterprise release the labs use."""

    def __init__(self, bundle, path=None):
        objs = bundle.get("objects", [])
        self.path = path
        by_id = {o["id"]: o for o in objs}
        self.version = None
        coll = next((o for o in objs if o.get("type") == "x-mitre-collection"), None)
        if coll:
            self.version = coll.get("x_mitre_version")
        matrix = next((o for o in objs if o.get("type") == "x-mitre-matrix"), None)
        tactic_objs = [by_id[t] for t in (matrix or {}).get("tactic_refs", []) if t in by_id]
        if not tactic_objs:
            tactic_objs = [o for o in objs if o.get("type") == "x-mitre-tactic"]
        self.tactics = []
        for o in tactic_objs:
            tid, url = _ext(o)
            self.tactics.append({"id": tid, "shortname": o.get("x_mitre_shortname"), "name": o.get("name"), "url": url})
        self.tactic_by_short = {t["shortname"]: t for t in self.tactics}
        self.tactic_by_id = {t["id"]: t for t in self.tactics}

        self.techniques, stix_tid, self.retired = {}, {}, {}
        for o in objs:
            if o.get("type") != "attack-pattern":
                continue
            tid, url = _ext(o)
            if not tid:
                continue
            stix_tid[o["id"]] = tid
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                self.retired[tid] = {"id": tid, "name": o.get("name"), "revoked": bool(o.get("revoked")),
                                     "deprecated": bool(o.get("x_mitre_deprecated")), "replaced_by": None}
                continue
            self.techniques[tid] = {
                "id": tid, "name": o.get("name"), "url": url, "sub": bool(o.get("x_mitre_is_subtechnique")),
                "parent": tid.split(".")[0] if "." in tid else None,
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
                "platforms": o.get("x_mitre_platforms", []), "description": o.get("description") or ""}
        self.mitigations, self.mitigates = {}, {}
        coa = {}
        for o in objs:
            if o.get("type") == "course-of-action" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
                mid, url = _ext(o)
                if mid:
                    coa[o["id"]] = mid
                    self.mitigations[mid] = {"id": mid, "name": o.get("name"), "url": url,
                                             "description": o.get("description") or ""}
        for o in objs:
            if o.get("type") != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            kind, src, dst = o.get("relationship_type"), o.get("source_ref"), o.get("target_ref")
            if kind == "revoked-by" and src in stix_tid and dst in stix_tid:
                old = stix_tid[src]
                if old in self.retired:
                    self.retired[old]["replaced_by"] = stix_tid[dst]
            elif kind == "mitigates" and src in coa and dst in stix_tid:
                self.mitigates.setdefault(stix_tid[dst], []).append(
                    {"mitigation": coa[src], "how": o.get("description") or ""})

    def resolve(self, tid):
        """(the current technique id or None, a note): follows MITRE's revoked-by chain."""
        tid = tid.upper()
        seen, note = set(), None
        while tid not in self.techniques and tid in self.retired and tid not in seen:
            seen.add(tid)
            r = self.retired[tid]
            if not r["replaced_by"]:
                return None, "deprecated" if r["deprecated"] else "revoked"
            note = f"revoked: now {r['replaced_by']}"
            tid = r["replaced_by"]
        return (tid, note) if tid in self.techniques else (None, "unknown")

    def name(self, tid):
        t = self.techniques.get(tid)
        return t["name"] if t else None

    def full_name(self, tid):
        """'Parent: Sub' for a sub-technique, as MITRE writes it."""
        t = self.techniques.get(tid)
        if not t:
            return None
        if t["parent"] and t["parent"] in self.techniques:
            return f"{self.techniques[t['parent']]['name']}: {t['name']}"
        return t["name"]


@functools.lru_cache(maxsize=2)
def _load(path, mtime):
    with open(path, encoding="utf-8") as f:
        return Attack(json.load(f), path)


def load(path=None):
    """The downloaded ATT&CK release, or None when it is not on this laptop."""
    path = path or bundle_path()
    if not path or not os.path.exists(path):
        return None
    return _load(path, os.path.getmtime(path))


def rule_techniques(attack, tags, unknown=None):
    """The current technique ids for a rule's tags (revoked ones followed to their replacement).
    unknown: a dict that collects {tag id: note} for tags this release does not know or has replaced."""
    out = []
    for t in technique_tags(tags):
        cur, note = attack.resolve(t)
        if cur is None:
            if unknown is not None:
                unknown[t] = note
            continue
        if note and unknown is not None:
            unknown[t] = note
        if cur not in out:
            out.append(cur)
    return out


def technique_tags(tags):
    """The technique ids named in Sigma tags, upper-case, in order, once each."""
    out = []
    for t in tags or []:
        m = TECHNIQUE_TAG.match(str(t).strip())
        if m and m.group(1).upper() not in out:
            out.append(m.group(1).upper())
    return out
