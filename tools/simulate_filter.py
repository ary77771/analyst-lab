"""Simulate a Sysmon config change on real recordings before applying it.

Applies the v0.2 file-event rule in Python (the same logic as the XML config) to recorded
events and reports how many events per hour would remain, overall and for normal use.
Prints only counts. Used to decide config v0.2 (VERIFICATION_PLAN stage 2, A7).

    python tools/simulate_filter.py --since 2026-10-16T13:56:00Z
"""

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from noise_report import load, norm  # noqa: E402
from agent.enrich import OriginTagger  # noqa: E402
from agent.main import PROJECT_ROOT, VIRTUALBOX_DIR  # noqa: E402
from agent.filetypes import is_recorded  # noqa: E402  (the same rule as sysmon-config.xml v0.2)


def kept(event_id: int, data: dict) -> bool:
    if event_id not in (11, 26):
        return True
    return is_recorded(data.get("TargetFilename"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True)
    a = ap.parse_args()
    tagger = OriginTagger(PROJECT_ROOT, extra_prefixes=[VIRTUALBOX_DIR])
    since = norm(a.since)
    before = collections.Counter()
    after = collections.Counter()
    minutes = set()
    for r in load("host"):
        tag = tagger.tag({"event_id": r["event_id"], "data": r["data"]})
        if norm(r["time"]) < since:
            continue
        key = (tag, r["event_id"])
        before[key] += 1
        if kept(r["event_id"], r["data"]):
            after[key] += 1
        if tag == "normal":
            minutes.add(r["time"][:16])
    hours = max(len(minutes) / 60, 1 / 60)

    def total(c, tag=None):
        return sum(n for (t, _), n in c.items() if tag in (None, t))

    print(f"active hours: {hours:.2f}")
    print(f"{'':28}{'before':>10}{'after':>10}{'per hour after':>16}")
    for tag in ("normal", "project", None):
        b, k = total(before, tag), total(after, tag)
        print(f"{(tag or 'all'):28}{b:>10}{k:>10}{k / hours:>16,.0f}")
    print("\nnormal use, by event type (before -> after):")
    for eid in sorted({e for (_, e) in before}):
        b, k = before[("normal", eid)], after[("normal", eid)]
        if b:
            print(f"  event {eid:>3}: {b:>7} -> {k:>7}")


if __name__ == "__main__":
    main()
