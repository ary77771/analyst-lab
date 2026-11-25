"""Hand-made stores for the report's plain-words tests (report-next, debate 10 plan v2), built on a
REAL layer-2 graph with the frozen confidence config (burst factor 2.5, T2/T3 leads only), so every
field the report words come from is what engine/graph.py really stores.

One "rich" story around an alert at t=1400 s (all layer-2 links inside the 15-minute view):
  PP tool.exe   connects at 1000 and 1300; creates a.exe and b.exe in the same second (1001.0 and
                1001.4: a tie on band, p and time) and starts child.exe at 1002 (T3, a lead only);
                its rate is its own activity (within-life); N = 2 causes
  QQ q.exe      connects at 1100 to 10.0.0.3:80, creates m.exe at 1101 and marks it as downloaded
                from http://10.0.0.3/m.exe: T1 raised to high by the download marker; its timing p
                is SMALLER than RR's (so ranking by p would put it first)
  RR r.exe      its program's own pool rate (pool:program); connects at 1500; creates
                r_out.exe at 1498.8, 1.2 s BEFORE the linked connection (a negative gap); high
  SS s.exe      lives 600-3000 s (lifetime band 60-3600): the band pool rate (pool:lifetime ...)
  UU u.exe      lives 8 s: not assessable by timing
  MM maker.exe  creates run.exe (fingerprint failed); BB runs it 10 s later: an R1 row (no timing)
  VV srv.exe    accepts a connection from 10.0.0.8 on port 8080 at 1250 and starts helper.exe at
                1251: T2 (a lead only)
  XX x.exe      25 connections to 10.0.0.9 (1000-1480 s), creates x_out.exe at 1481: N = 25 makes a
                T1 LOW graded by the formula (p above the T3 lead's, which must not outrank it)
explorer.exe (ROOT) starts every program inside the window, so one view holds them all.
"""

from dataclasses import replace

from engine import confidence as C
from engine.alerts import Alert
from engine.graph import Layer2, build_graph
from engine.store import EventStore
from test_graph import ROOT, ZERO_GUID, at, ev, file_hash, start
from test_graph_layer2 import BANDS, filler, marker, out

CFG = replace(C.load_config(), pool_sha256=None)       # the frozen config (hand-made pool: no hash)
EXPLORER = r"C:\Windows\explorer.exe"
PP, CC, QQ, RR = ("{A1000000-0000-0000-0000-000000000000}", "{A2000000-0000-0000-0000-000000000000}",
                  "{A3000000-0000-0000-0000-000000000000}", "{A4000000-0000-0000-0000-000000000000}")
SS, UU, MM, BB = ("{A5000000-0000-0000-0000-000000000000}", "{A6000000-0000-0000-0000-000000000000}",
                  "{A7000000-0000-0000-0000-000000000000}", "{A8000000-0000-0000-0000-000000000000}")
VV, WW = "{A9000000-0000-0000-0000-000000000000}", "{AA000000-0000-0000-0000-000000000000}"
XX, XS = "{AB000000-0000-0000-0000-000000000000}", r"C:\x.exe"
TOOL, Q, RX, SX, UX = r"C:\tool.exe", r"C:\q.exe", r"C:\r.exe", r"C:\s.exe", r"C:\u.exe"
H = "AB" * 32
ALERT_AT = 1400


def rich_pool():
    """file: band rates 0.0001 / 0.001 / 0.0001 per second; r.exe's own file rate 0.0002 (enough
    events to count); child starts 0 (within-life wins)."""
    band_rates = {"file": {"<60": 0.0001, "60-3600": 0.001, ">=3600": 0.0001}}
    per_band = {k: {b: (band_rates.get(k, {}).get(b, 0.0) * 1e6, 1e6) for b in BANDS} for k in C.KINDS}
    per_program = {k: {} for k in C.KINDS}
    per_program["file"]["r.exe"] = (200, 1e6)
    return C.Pool(per_program, per_band, C.pool_settings(CFG))


def made(rid, s, path, guid, image, pid):
    return ev(rid, 11, s, ProcessGuid=guid, ProcessId=pid, Image=image, TargetFilename=path)


def proc(rid, s, guid, pid, image, end=7200, parent=ROOT, parent_image=EXPLORER, sha="A1"):
    recs = [start(rid, s, guid, pid, image, parent, 100, parent_image, sha=sha)]
    if end is not None:
        recs.append(ev(rid + 1, 5, end, ProcessGuid=guid, ProcessId=pid, Image=image))
    return recs


def rich_records():
    a, b = made(20, 1001.0, r"C:\dl\a.exe", PP, TOOL, 9), made(21, 1001.4, r"C:\dl\b.exe", PP, TOOL, 9)
    m = made(30, 1101, r"C:\dl\m.exe", QQ, Q, 77)
    r = made(40, 1498.8, r"C:\dl\r_out.exe", RR, RX, 88)
    s = made(50, 1203, r"C:\dl\s_out.exe", SS, SX, 66)
    u = made(60, 1603, r"C:\dl\u_out.exe", UU, UX, 44)
    run = made(70, 1350, r"C:\dl\run.exe", MM, r"C:\maker.exe", 33)
    x = made(130, 1481, r"C:\dl\x_out.exe", XX, XS, 13)
    return [
        start(1, 0, ROOT, 100, EXPLORER, ZERO_GUID, parent_image="-"), *filler(hi=7200),
        *proc(2, 600, PP, 9, TOOL), out(10, 1000, guid=PP), out(11, 1300, guid=PP, ip="10.0.0.2"),
        a, file_hash(1, 1002, a, "ok", "C1" * 32), b, file_hash(2, 1002.5, b, "ok", "C2" * 32),
        start(12, 1002, CC, 55, r"C:\child.exe", PP, 9, TOOL, sha="CD" * 32),
        ev(13, 5, 1900, ProcessGuid=CC, ProcessId=55, Image=r"C:\child.exe"),
        *proc(4, 601, QQ, 77, Q), out(31, 1100, guid=QQ, image=Q, pid=77, ip="10.0.0.3", port=80),
        m, file_hash(3, 1102, m, "ok", H), marker(32, 1103, path=r"C:\dl\m.exe", guid=QQ, image=Q,
                                                 url="http://10.0.0.3/m.exe"),
        *proc(6, 602, RR, 88, RX), out(41, 1500, guid=RR, image=RX, pid=88, ip="10.0.0.4"), r, file_hash(4, 1500, r, "ok", "C4" * 32),
        *proc(8, 603, SS, 66, SX, end=3000), out(51, 1200, guid=SS, image=SX, pid=66, ip="10.0.0.6"),
        s, file_hash(5, 1204, s, "ok", "C5" * 32),
        *proc(14, 1600, UU, 44, UX, end=1608), out(61, 1602, guid=UU, image=UX, pid=44, ip="10.0.0.7"),
        u, file_hash(6, 1604, u, "ok", "C6" * 32),
        *proc(16, 604, MM, 33, r"C:\maker.exe"), run, file_hash(7, 1351, run, "failed"),
        *proc(18, 1360, BB, 22, r"C:\dl\run.exe", end=1390, sha="BC" * 32),
        *proc(80, 605, VV, 11, r"C:\srv.exe"),
        ev(82, 3, 1250, ProcessGuid=VV, ProcessId=11, Image=r"C:\srv.exe", Protocol="tcp", Initiated="false",
           SourceIp="10.0.0.8", SourcePort=40000, DestinationIp="10.0.2.15", DestinationPort=8080),
        start(83, 1251, WW, 12, r"C:\helper.exe", VV, 11, r"C:\srv.exe", sha="CE" * 32),
        ev(84, 5, 1900, ProcessGuid=WW, ProcessId=12, Image=r"C:\helper.exe"),
        *proc(90, 606, XX, 13, XS),
        *[out(100 + i, 1000 + 20 * i, guid=XX, image=XS, pid=13, ip="10.0.0.9") for i in range(25)],
        x, file_hash(8, 1482, x, "ok", "C8" * 32),
    ]


def rich(tmp_path):
    """(store connection, alert, full graph): the alert cites PP's connection at 1000, the creation
    of a.exe and the start of child.exe."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    recs = rich_records()
    store = EventStore(str(tmp_path / "rich.db"))
    store.insert(recs)
    G = build_graph(store, hypotheses=Layer2(rich_pool(), CFG))
    alert = Alert("analystlab.test", "Connect, write, run", "analystlab", "medium",
                  at(ALERT_AT).replace(" ", "T") + "Z", "PC", "a test alert",
                  tuple(key(store.db, rid) for rid in (10, 20, 12)))
    return store.db, alert, G


KK, LL, D1, D2, O1, O2 = ("{B1000000-0000-0000-0000-000000000000}", "{B2000000-0000-0000-0000-000000000000}",
                          "{B3000000-0000-0000-0000-000000000000}", "{B4000000-0000-0000-0000-000000000000}",
                          "{B5000000-0000-0000-0000-000000000000}", "{B6000000-0000-0000-0000-000000000000}")
KID, LOADER = r"C:\kid.exe", r"C:\loader.exe"


def causal_records():
    """Report v3 (debate 11): Sysmon stamps an EFFECT BEFORE ITS CAUSE, inside the alert's chain.
      explorer.exe (parent all zeros: a parent_unknown gap) starts loader.exe at 100;
      loader starts dup.exe twice (150, 151: a name NOT unique in the view) and other.exe at 160
        (unique in the view; a second other.exe runs at 5000, outside the view);
      loader starts kid.exe at 200.5, but kid's own connection is stamped 200.0 and its first file
        200.2 (both before its start); kid creates nohash.exe at 200.3 (no fingerprint: a
        content_unknown gap at the file), then zzz.exe at 200.6 and aaa.exe at 200.9 (one second,
        sentence order the reverse of time order);
      loader creates early.exe at 120 under record id 99, the HIGHEST id: record-id order and time
        order disagree (v3 review fix 5: the order must come from the times)."""
    o = made(12, 200.2, r"C:\c\out.exe", KK, KID, 30)
    early = made(99, 120, r"C:\c\early.exe", LL, LOADER, 20)
    z, a = made(14, 200.6, r"C:\c\zzz.exe", KK, KID, 30), made(15, 200.9, r"C:\c\aaa.exe", KK, KID, 30)
    return [
        start(1, 0, ROOT, 100, EXPLORER, ZERO_GUID, parent_image="-"),
        start(2, 100, LL, 20, LOADER, ROOT, 100, EXPLORER),
        start(3, 150, D1, 31, r"C:\dup.exe", LL, 20, LOADER), start(4, 151, D2, 32, r"C:\dup.exe", LL, 20, LOADER),
        start(5, 160, O1, 41, r"C:\other.exe", LL, 20, LOADER),
        start(6, 5000, O2, 42, r"C:\other.exe", ROOT, 100, EXPLORER),
        start(10, 200.5, KK, 30, KID, LL, 20, LOADER, sha="K1"),
        out(11, 200.0, guid=KK, image=KID, pid=30, ip="10.0.0.9", port=443),
        o, file_hash(1, 200.4, o, "ok", "D1" * 32),
        made(13, 200.3, r"C:\c\nohash.exe", KK, KID, 30),
        z, file_hash(2, 200.7, z, "ok", "D2" * 32), a, file_hash(3, 201.0, a, "ok", "D3" * 32),
        early, file_hash(4, 120.5, early, "ok", "D4" * 32),
    ]


def causal(tmp_path):
    """(store connection, alert, full graph) for causal_records(); the alert cites kid's start, its
    connection and its first file, so the inverted pair is IN the chain."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = EventStore(str(tmp_path / "causal.db"))
    store.insert(causal_records())
    G = build_graph(store)
    alert = Alert("analystlab.test", "Kid story", "analystlab", "medium", at(201).replace(" ", "T") + "Z", "PC",
                  "a test alert", tuple(key(store.db, rid) for rid in (10, 11, 12)))
    return store.db, alert, G


def key(db, record_id):
    """The dedup key of the Sysmon record with this record id."""
    return db.execute("SELECT dedup_key FROM events WHERE record_id = ?", (record_id,)).fetchone()[0]
