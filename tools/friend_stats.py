"""Read the statistics files friends send (DESIGN 9.1-9.2) and say, in plain words, whether each
laptop records properly, then combine all friends' numbers.

    python tools/friend_stats.py                       # every file under recordings/friends/
    python tools/friend_stats.py path\\to\\file.txt ...  # just these files

Keep each friend's files in their own folder: recordings/friends/<name>/AnalystLab-statistics-*.txt
(recordings/ is never committed). A friend sends a day-1 file (health check) and a day-7 file
(the real numbers); the combined table uses each friend's NEWEST file ("Made on" date).

Every file goes through stats.read_export, which refuses anything that isn't exactly our own
numbers-only LAYOUT (a foreign file or extra fields can't slip in). It can't tell whether a number
inside that layout was changed by hand: the numbers are trusted as the friend's own (review
2026-10-20).
Exit code: 0 all fine · 1 at least one laptop has a problem or a file was refused.
"""

import argparse
import glob
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from statusapp.stats import NotNumbersOnly, read_export  # noqa: E402

OK, NOTE, PROBLEM = "OK", "NOTE", "PROBLEM"
TOTAL_HOURS_TARGET = 75          # DESIGN 9: ~7 days on 3 laptops, 75+ active hours in total
MISSING_SHARE_PROBLEM = 0.001    # more than 0.1 % of Sysmon's records missing: something lost data
SESSIONS_PER_DAY_NOTE = 10       # every boot or recorder restart is a session; far more means crashes


def made_on(text):
    m = re.search(r"^Made on: (\d{4}-\d{2}-\d{2})\s*$", text, re.M)
    return m.group(1) if m else "?"


def newness(date, s):
    """Sort key for "newest": an unknown date counts as oldest (review 2026-10-20: "?" sorted
    after every date), and on the same day the file with more recording wins."""
    return (date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else "", s["days_recorded"], s["active_hours"])


def health(s):
    """[(level, message, what to tell the friend)] for one summary; empty = all good."""
    out = []
    h, st = s["health"], s["self_test"]
    if h["sysmon_records"] == 0:
        out.append((PROBLEM, "nothing was recorded at all",
                    "Restart the laptop, open Analyst Lab, run the self-test and send me a screenshot."))
    if st["last_passed"] is False:
        out.append((PROBLEM, "the last self-test FAILED",
                    "Restart, run the self-test again; if it still fails, send the screenshot and "
                    r"C:\ProgramData\AnalystLab\setup-log.txt."))
    elif st["last_passed"] is None:
        out.append((NOTE, "no self-test result in the file",
                    "Click 'Run self-test' once, then export again."))
    missing = h["sysmon_records_missing"]
    if missing and missing > MISSING_SHARE_PROBLEM * max(h["sysmon_records"], 1):
        out.append((PROBLEM, f"{missing:,} of Sysmon's records are missing (events were lost)",
                    "Nothing to do for you; I'll look into it (the recorder may have been stopped)."))
    elif missing:
        out.append((NOTE, f"{missing:,} Sysmon record(s) missing (tiny share, usually a restart)", ""))
    if h["damaged_lines"] or h["damaged_files"]:
        out.append((NOTE, f"{h['damaged_lines']} damaged line(s), {h['damaged_files']} damaged file(s) skipped", ""))
    per_hour = s["events_per_active_hour"]
    if h["sysmon_records"] and not per_hour.get("process starts"):
        out.append((PROBLEM, "no program starts recorded (is it really our Sysmon setup?)",
                    "Send me C:\\ProgramData\\AnalystLab\\setup-log.txt."))
    if s["active_hours"] < 1:
        out.append((NOTE, f"only {s['active_hours']} active hour(s) so far", ""))
    days = max(s["days_recorded"], 1)
    if h["recorder_sessions"] > SESSIONS_PER_DAY_NOTE * days:
        out.append((NOTE, f"{h['recorder_sessions']} recorder starts in {days} day(s): it may be crashing", ""))
    return out


def verdict(issues):
    levels = {lvl for lvl, _, _ in issues}
    return PROBLEM if PROBLEM in levels else NOTE if NOTE in levels else OK


def friend_of(path, root, given=None):
    """Whose file is it: --friend if given, else the friend folder under root, else the file's own
    folder. Never the file name: every export is called AnalystLab-statistics-<date>.txt, so two
    friends' files would merge (review 2026-10-20)."""
    if given:
        return given
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root)) if root else ".."
    except ValueError:                       # another drive
        rel = ".."
    parts = rel.split(os.sep)
    if not rel.startswith("..") and len(parts) > 1:
        return parts[0]
    return os.path.basename(os.path.dirname(os.path.abspath(path))) or "?"


def collect(paths, root, given=None):
    """[(friend, date, path, summary or None, error)]."""
    out = []
    for p in paths:
        friend = friend_of(p, root, given)
        try:
            with open(p, encoding="utf-8") as f:
                text = f.read()
            out.append((friend, made_on(text), p, read_export(text), None))
        except (OSError, ValueError, NotNumbersOnly) as e:
            out.append((friend, "?", p, None, f"{type(e).__name__}: the file is not an untouched Analyst Lab export"))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check and combine friends' Analyst Lab statistics files")
    ap.add_argument("files", nargs="*")
    ap.add_argument("--root", default=os.path.join(PROJECT_ROOT, "recordings", "friends"))
    ap.add_argument("--friend", help="whose files these are (when passing files from outside the friend folders)")
    a = ap.parse_args(argv)
    paths = a.files or sorted(glob.glob(os.path.join(a.root, "*", "*.txt")))
    if not paths:
        print(f"No files. Put each friend's files in {a.root}\\<name>\\ (or pass file paths).")
        return 1
    rows = collect(paths, a.root, a.friend)
    bad = False
    print("== Each file ==")
    for friend, date, path, s, err in rows:
        if s is None:
            bad = True
            print(f"\n[REFUSED] {friend} · {os.path.basename(path)}\n   {err}")
            continue
        issues = health(s)
        v = verdict(issues)
        bad |= v == PROBLEM
        print(f"\n[{v}] {friend} · made on {date} · day {min(s['days_recorded'], s['target_days'])} of "
              f"{s['target_days']} · {s['active_hours']:.1f} active hours · paused {s['paused_minutes']} min")
        if not issues:
            print("   This laptop records properly.")
        for lvl, msg, tell in issues:
            print(f"   {lvl}: {msg}")
            if tell:
                print(f"         tell them: {tell}")

    newest = {}
    for friend, date, path, s, err in rows:
        if s is not None and (friend not in newest or newness(date, s) >= newness(*newest[friend])):
            newest[friend] = (date, s)
    if newest:
        print("\n== All friends together (each friend's newest file) ==")
        hours = sum(s["active_hours"] for _, s in newest.values())
        kinds = ["process starts", "network connections", "DNS lookups", "files created (watched kinds)"]
        print(f"{'friend':<14}{'days':>6}{'hours':>8}" + "".join(f"{k.split(' (')[0][:15]:>17}" for k in kinds) + "   (per active hour)")
        for friend, (date, s) in sorted(newest.items()):
            print(f"{friend[:13]:<14}{s['days_recorded']:>6}{s['active_hours']:>8.1f}"
                  + "".join(f"{s['events_per_active_hour'].get(k, 0):>17,.1f}" for k in kinds))
        # hours-weighted average of each laptop's own rate (the file's hours are rounded, its
        # rates are not: dividing summed counts by summed rounded hours would drift)
        pooled = {k: (sum(s["events_per_active_hour"].get(k, 0) * s["active_hours"] for _, s in newest.values()) / hours
                      if hours else 0) for k in kinds}
        print(f"{'together':<14}{'':>6}{hours:>8.1f}" + "".join(f"{pooled[k]:>17,.1f}" for k in kinds))
        print(f"\nActive hours so far: {hours:.1f} of the {TOTAL_HOURS_TARGET} planned "
              f"({min(100, 100 * hours / TOTAL_HOURS_TARGET):.0f} %).")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
