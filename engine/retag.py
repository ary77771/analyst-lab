"""Re-apply today's origin rules while loading laptop recordings (decided 2026-10-17).

The agent tags each event "project" (our own dev work) or "normal" (real use) when it records
it, with the rules of that day. On day 1 the rules were still being fixed, so some dev work was
tagged "normal". Loading re-tags laptop ("host") records with the current rules
(agent.enrich.OriginTagger, the same code the agent runs), in recording order, so old and new
data are judged the same way; the recorded tag is kept as `origin_recorded`.

- Sysmon events: re-tagged exactly as the agent would tag them today. The tagger also follows
  process trees across agent restarts, which the agent itself can't.
- FILE_HASH: takes the new tag of the event 11 it belongs to (by record number and time).
- Port records: unchanged (their rule, "the program is inside the project folder", hasn't changed).
- The VM ("vm", since 2026-10-23): re-tagged STRICTLY (security review): "our own tools" =
  programs that live in C:\\LabTools and their children; a command line merely mentioning the
  folder no longer hides a program. The VM agent tags the same way from its next snapshot on.
- Other labels: unchanged.
"""

import os

from agent.enrich import OriginTagger

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIRTUALBOX_DIR = r"C:\Program Files\Oracle\VirtualBox"     # same as agent.main
VM_TOOLS = r"C:\LabTools"                                  # the VM agent's project folder
LABELS = ("host", "vm")


class Retagger:
    def __init__(self, labels=LABELS):
        self.labels = set(labels)
        self.taggers = {}                 # one per computer: process trees don't cross machines
        self.created = {}                 # (host, record_id, time) of event 11 -> new tag
        self.changed = 0

    def __call__(self, r: dict) -> dict:
        if r.get("label") not in self.labels:
            return r
        host = r.get("host")
        tagger = self.taggers.get(host)
        if tagger is None:
            if r.get("label") == "vm":
                tagger = OriginTagger(VM_TOOLS, dev_tools=False, strict=True)
            else:
                tagger = OriginTagger(PROJECT_ROOT, extra_prefixes=[VIRTUALBOX_DIR])
            self.taggers[host] = tagger
        old = r.get("origin")
        if r.get("source") == "sysmon" and r.get("event_id") is not None:
            new = tagger.tag({"event_id": r["event_id"], "data": r.get("data") or {}})
            if r["event_id"] == 11:
                self.created[(host, r.get("record_id"), r.get("time"))] = new
        elif r.get("type") == "FILE_HASH":
            d = r.get("data") or {}
            new = self.created.get((host, d.get("ref_record_id"), d.get("ref_time")), old)
        else:
            return r
        out = dict(r)
        out["origin_recorded"], out["origin"] = old, new
        if new != old:
            self.changed += 1
        return out
