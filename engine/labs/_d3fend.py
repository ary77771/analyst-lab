"""MITRE D3FEND for the "What to do next" lab: defensive techniques mapped to ATT&CK techniques, read from
the downloaded release (engine/labs/_fetch_d3fend.py; downloads/night/d3fend/, never committed).

The mapping is D3FEND's own (d3fend-full-mappings.csv, the inferred mappings its website shows): a
defensive technique and an ATT&CK technique are linked through a "digital artifact" both touch, e.g.
"File Hashing analyzes File" and "T1036.003 modifies File". Every row here keeps that link, so the page can
say WHY a defence is listed. Nothing is added or ranked by this project.
D3FEND © The MITRE Corporation (terms of use: https://d3fend.mitre.org/tou).
"""

import csv
import functools
import json
import os

from . import _downloads

LEGAL = "D3FEND™ © The MITRE Corporation. Used under D3FEND's terms of use."
# D3FEND's tactics; the page shows the ones that act on an incident first (eviction, isolation, restoring),
# then finding more (detection), then the ones that make a repeat harder.
TACTIC_ORDER = ["Evict", "Isolate", "Restore", "Detect", "Harden", "Deceive", "Model"]


def data_folder():
    return _downloads.find("night/d3fend")


class D3fend:
    def __init__(self, folder):
        self.folder = folder
        self.version = None
        try:
            with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as f:
                self.version = json.load(f).get("version")
        except (OSError, ValueError):
            pass
        self.techniques = {}                       # name -> {id, name, tactic, definition}
        with open(os.path.join(folder, "d3fend.csv"), encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                name = r.get("D3FEND Technique") or r.get("D3FEND Technique Level 0") or r.get("D3FEND Technique Level 1")
                if name:
                    self.techniques[name] = {"id": r["ID"], "name": name, "tactic": r.get("D3FEND Tactic"),
                                             "definition": (r.get("Definition") or "").strip()}
        self.by_attack = {}                        # T-id -> {defence name: {tactic, links set}}
        with open(os.path.join(folder, "d3fend-full-mappings.csv"), encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                tid = (r.get("off_tech_id") or "").strip().upper()
                # def_tech_label, not query_def_tech_label: checked 2026-11-23 against D3FEND's own API for
                # T1036.003, def_tech_label gives exactly its 16 defences; the query column adds 25 broader
                # parents/siblings whose link sentence would name another technique.
                name = r.get("def_tech_label")
                if not tid or not name:
                    continue
                d = self.by_attack.setdefault(tid, {}).setdefault(name, {"tactic": r.get("def_tactic_label"), "links": set()})
                d["links"].add((r.get("def_tech_label"), r.get("def_artifact_rel_label"), r.get("def_artifact_label"),
                                r.get("off_artifact_rel_label"), r.get("off_artifact_label")))

    def for_technique(self, tid, max_links=3):
        """D3FEND's defences for an ATT&CK technique, grouped by D3FEND tactic in TACTIC_ORDER. Uses the
        technique's own mappings; a sub-technique without any falls back to its parent (said in `via`)."""
        tid = tid.upper()
        via = tid
        rows = self.by_attack.get(tid)
        if not rows and "." in tid:
            via = tid.split(".")[0]
            rows = self.by_attack.get(via)
        groups = {}
        for name, d in (rows or {}).items():
            t = self.techniques.get(name, {})
            links = sorted(d["links"])[:max_links]
            groups.setdefault(d["tactic"] or "?", []).append({
                "id": t.get("id"), "name": name, "definition": t.get("definition", ""),
                "links": [{"defence": a, "defence_rel": b, "artifact": c, "attack_rel": e_rel, "attack_artifact": e}
                          for a, b, c, e_rel, e in links],
                "more_links": max(0, len(d["links"]) - max_links)})
        order = TACTIC_ORDER + sorted(set(groups) - set(TACTIC_ORDER))
        return {"via": via, "count": sum(len(v) for v in groups.values()),
                "tactics": [{"tactic": k, "techniques": sorted(groups[k], key=lambda x: x["name"])} for k in order if k in groups],
                "url": f"https://d3fend.mitre.org/offensive-technique/attack/{via}/"}


@functools.lru_cache(maxsize=2)
def _load(folder, mtime):
    return D3fend(folder)


def load(folder=None):
    folder = folder or data_folder()
    if not folder or not os.path.exists(os.path.join(folder, "d3fend-full-mappings.csv")) \
            or not os.path.exists(os.path.join(folder, "d3fend.csv")):
        return None
    return _load(folder, os.path.getmtime(os.path.join(folder, "d3fend-full-mappings.csv")))
