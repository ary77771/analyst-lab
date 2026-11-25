"""v3 1.4 follow-up (review 2026-11-14): how much of each rule's raw material the development data
holds, counted through the rules' OWN filters (Sysmon channel, not our tools, not paused), step by
step. Is a zero cost a real zero or an empty test? Counts only.

    python docs/plans/v3/v3_exposure.py <wt\\v3 root> <db> [<db> ...]
"""
import sqlite3
import sys
from dataclasses import replace

root = sys.argv[1]
sys.path.insert(0, root)
from engine import beacon as B  # noqa: E402
from engine import own_rules as O  # noqa: E402
from engine.config import own_rule_params  # noqa: E402
from engine.graph import norm_path  # noqa: E402

cfg = replace(B.load_config(), short_min=None, short_cutoffs=None)
EXE = ("%.exe", "%.scr", "%.com")
LIKE = " OR ".join("lower(TargetFilename) LIKE ?" for _ in EXE)
listed = [r for r in own_rule_params()["analystlab.embedded_system_name"]["extra_references"] if len(r) >= 6]

for path in sys.argv[2:]:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    rows = lambda sql, p=(): con.execute(sql, p).fetchall()  # noqa: E731
    writes = {}
    for h, p, u, t in rows(f"SELECT host, TargetFilename, UtcTime, time FROM events WHERE event_id = 11 AND {O.NORMAL} AND ({LIKE})", EXE):
        tt = O._when(u, t)
        if tt and p:
            writes.setdefault((h, norm_path(p)), []).append(tt)
    deletes = {}
    for h, p, u, t in rows(f"SELECT host, TargetFilename, UtcTime, time FROM events WHERE event_id = 26 AND {O.NORMAL} AND ({LIKE})", EXE):
        tt = O._when(u, t)
        if tt and p:
            deletes.setdefault((h, norm_path(p)), []).append(tt)
    started = deleted = connected = 0
    for h, img, guid, u, t in rows(f"SELECT host, Image, ProcessGuid, UtcTime, time FROM events WHERE event_id = 1 AND {O.NORMAL}"):
        p, ts = norm_path(img) if img else None, O._when(u, t)
        if not p or not ts or (h, p) not in writes:
            continue
        if not any(0 <= (ts - w).total_seconds() <= 300 for w in writes[(h, p)]):
            continue
        started += 1
        if not any(0 < (d - ts).total_seconds() <= 900 for d in deletes.get((h, p), [])):
            continue
        deleted += 1
        if O._first_connection(con, h, guid, ts, ts + O.timedelta(seconds=900)) is not None:
            connected += 1
    windows, outside = O._windows_refs_and_outside(con, "c:\\windows\\")
    containing = sum(1 for (h, p) in outside if any(r in O._stem(p) and r != O._stem(p) for r in listed))
    series = B.series_from_store(con, None, cfg.unicast_only)
    segs, fresh, fresh4 = {}, 0, 0
    for (h, image, ip, port), conns in series.items():
        if h not in segs:
            segs[h] = B.host_segments(con, h, cfg.sleep_gap_seconds, cfg.split_at_boot, cfg.window_cap_seconds)
        for seg, chunk in B.split_by_segment(conns, segs[h]):
            if B.fresh_drop(con, h, image, min(c[0] for c in chunk), cfg) is not None:
                fresh += 1
                fresh4 += len(B.checkin_times([c[0] for c in chunk], cfg.time_resolution_seconds)) >= 4
    print(f"{path.rsplit(chr(92), 1)[-1]}:")
    print(f"  1.2 executables written {sum(map(len, writes.values()))} -> started within 300 s {started} -> "
          f"deleted within 900 s {deleted} -> connected out (ordinary address) {connected}")
    print(f"  1.1 program files started outside Windows {len(outside)}; listed names >= 6 letters {len(listed)}; "
          f"outside files whose name contains one {containing}")
    print(f"  1.3 series of freshly dropped programs {fresh} (with >= 4 check-ins: {fresh4})")
    con.close()
