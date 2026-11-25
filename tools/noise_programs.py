"""Which programs produce the most *normal-use* Sysmon noise? (input for config tuning)

Privacy-minimal by design (CLAUDE.md rule 7): the console shows program file names and counts
only. Folder patterns for file events (user name masked) go only to a git-ignored file in
recordings/, never to the console. Never prints file names, command lines, domains or IPs.
Uses the same full-history re-tagging as noise_report.py.

    python tools/noise_programs.py --since 2026-10-16T13:56:00Z
"""

import argparse
import collections
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from noise_report import NAMES, base, load, norm  # noqa: E402
from agent.enrich import OriginTagger  # noqa: E402
from agent.main import PROJECT_ROOT, VIRTUALBOX_DIR  # noqa: E402


def folder_pattern(path: str, depth: int = 4) -> str:
    p = re.sub(r"(?i)^c:\\users\\[^\\]+", r"C:\\Users\\<user>", path or "")
    parts = p.split("\\")[:-1][:depth]
    return "\\".join(parts) or "(none)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True)
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    tagger = OriginTagger(PROJECT_ROOT, extra_prefixes=[VIRTUALBOX_DIR])
    since = norm(a.since)
    normal = collections.defaultdict(list)
    for r in load("host"):
        tag = tagger.tag({"event_id": r["event_id"], "data": r["data"]})
        if norm(r["time"]) >= since and tag == "normal":
            normal[r["event_id"]].append(r)

    total = sum(len(v) for v in normal.values()) or 1
    private = []
    print(f"normal events since {a.since}: {total}")
    for eid in sorted(normal, key=lambda k: -len(normal[k])):
        events = normal[eid]
        print(f"\n== {eid} {NAMES.get(eid, '')}: {len(events)} ({len(events) / total:.0%} of all) ==")
        for name, n in collections.Counter(base(r["data"].get("Image")) for r in events).most_common(a.top):
            print(f"  {n:6}  {n / len(events):4.0%}  {name}")
        if eid in (11, 26):
            private.append(f"== {eid} top folders ==")
            for f, n in collections.Counter(folder_pattern(r["data"].get("TargetFilename")) for r in events).most_common(6):
                private.append(f"  {n:6}  {n / len(events):4.0%}  {f}")
    if private:
        path = os.path.join(PROJECT_ROOT, "recordings", f"noise_report_folders_{datetime.now():%Y%m%d-%H%M}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(private) + "\n")
        print(f"\n(folder patterns saved privately to {os.path.basename(path)} in recordings/, not printed)")


if __name__ == "__main__":
    main()
