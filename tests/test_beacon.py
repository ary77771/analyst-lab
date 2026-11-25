"""Answer sheet for the check-in rhythm rule (engine/beacon.py), written before the code.

Every expected number here is worked out by hand in the comment next to it (RITA v5.1.2's
method as described in docs/plans/reports/beacon.md; quartiles = numpy's default linear
interpolation).
"""
import math
import random
import sqlite3

import pytest

from engine.alerts import missing_evidence
from engine.beacon import (BeaconConfig, awake_segments, beacon_alerts, bimodal_fit, bin_counts,
                           checkin_times, consistency_score, first_crossing, histogram_score,
                           load_config, score_series, score_store, timestamp_score)
from engine.store import EventStore

CFG = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8)


def rhythm(n, gap, start=0.0):
    return [start + i * gap for i in range(n)]


# -- timestamp score (skew + MAD), by hand ---------------------------------------------------
def test_timestamp_score_tight_gaps_skip_skew():
    # gaps 10,12,14,16,30: Q1=12 Q2=14 Q3=16, IQR=4 < 10 -> skew not computed -> skew score 1
    # median 14; |g-14| = 4,2,0,2,16 -> sorted 0,2,2,4,16 -> MAD 2 -> MAD score 12/14
    s = timestamp_score([10, 12, 14, 16, 30], CFG)
    assert s["skew_score"] == 1.0
    assert s["mad_score"] == pytest.approx(12 / 14)
    assert s["timestamp"] == pytest.approx((1 + 12 / 14) / 2)


def test_timestamp_score_with_skew():
    # gaps 10,20,25,40,100: Q1=20 Q2=25 Q3=40 (IQR 20 >= 10, Q2 differs from both)
    # Bowley = (40+20-50)/20 = 0.5 -> skew score 0.5
    # median 25; |g-25| = 15,5,0,15,75 -> sorted 0,5,15,15,75 -> MAD 15 -> MAD score 10/25
    s = timestamp_score([10, 20, 25, 40, 100], CFG)
    assert s["skew_score"] == pytest.approx(0.5)
    assert s["mad_score"] == pytest.approx(0.4)
    assert s["timestamp"] == pytest.approx(0.45)


def test_skew_guard_boundary():
    # gaps 10,20,22,30,100: Q1=20 Q2=22 Q3=30, IQR exactly 10 -> skew IS computed:
    # Bowley = (30+20-44)/10 = 0.6 -> skew score 0.4
    assert timestamp_score([10, 20, 22, 30, 100], CFG)["skew_score"] == pytest.approx(0.4)
    # IQR 9.9: just under the guard -> skew counts as 0 -> skew score 1
    assert timestamp_score([10, 20, 22, 29.9, 100], CFG)["skew_score"] == 1.0
    # Q2 equal to Q1: guard -> skew 0 even with a wide IQR (gaps 10,20,20,40,100)
    assert timestamp_score([10, 20, 20, 40, 100], CFG)["skew_score"] == 1.0


def test_timestamp_score_order_does_not_matter():
    assert timestamp_score([100, 10, 40, 25, 20], CFG) == timestamp_score([10, 20, 25, 40, 100], CFG)


def test_sub_second_median_gap_gets_no_mad_score():
    # all gaps 0.5 s: median < 1 -> MAD score 0; IQR 0 -> skew score 1; timestamp = 0.5
    s = timestamp_score([0.5] * 8, CFG)
    assert s["mad_score"] == 0.0 and s["skew_score"] == 1.0 and s["timestamp"] == 0.5


def test_exact_rhythm_scores_one():
    assert timestamp_score([30.0] * 9, CFG)["timestamp"] == 1.0


# -- bins, duration, histogram, by hand ------------------------------------------------------
def test_bin_counts_scale_with_the_rhythm():
    # window 2400 s, median gap 20 -> bins = min(24, floor(2400 / (5*20))) = 24 bins of 100 s.
    # timestamps every 20 s from 0 to 1180 -> bins 0..11 hold 5 each, bins 12..23 are empty.
    counts, width = bin_counts(rhythm(60, 20), (0.0, 2400.0), median_gap=20, cfg=CFG)
    assert width == 100 and len(counts) == 24
    assert counts == [5] * 12 + [0] * 12


def test_bins_never_thinner_than_five_beats():
    # window 300 s, median gap 30 -> floor(300/150) = 2 bins of 150 s (not 24 bins of 12.5 s)
    counts, width = bin_counts(rhythm(10, 30), (0.0, 300.0), median_gap=30, cfg=CFG)
    assert len(counts) == 2 and width == 150 and counts == [5, 5]


def test_consistency_needs_six_busy_bins():
    busy = [1] * 8 + [0] * 16                      # longest run 8 of 24 -> 8 / 12
    assert consistency_score(busy, CFG) == pytest.approx(8 / 12)
    assert consistency_score([1] * 5 + [0] * 19, CFG) is None       # 5 busy bins: not computed
    assert consistency_score([1] * 24, CFG) == 1.0                   # capped


def test_histogram_cv_and_bimodal_by_hand():
    # 12 busy bins of 5, 12 empty: mean 2.5, population sd 2.5 -> CV 1 -> CV score 0;
    # bimodal: bucket size ceil(5*0.05)=1, all 12 busy in one bucket -> 12 / 11 -> capped 1
    assert bimodal_fit([5] * 12 + [0] * 12) == 1.0
    assert histogram_score([5] * 12 + [0] * 12, CFG) == 1.0
    # busy counts 10,10,10,1,1,2,3,4,5,6,7,8 (+12 empty): CV > 1 -> 0;
    # buckets of size 1: count 10 -> 3 bins, count 1 -> 2 bins, others 1 -> top two = 5 / 11
    counts = [10, 10, 10, 1, 1, 2, 3, 4, 5, 6, 7, 8] + [0] * 12
    assert bimodal_fit(counts) == pytest.approx(5 / 11)
    assert histogram_score(counts, CFG) == pytest.approx(5 / 11)
    assert histogram_score([5] * 10 + [0] * 14, CFG) is None         # 10 busy bins: not computed


# -- whole series ---------------------------------------------------------------------------
def test_perfect_long_beacon_scores_one():
    # 120 connections every 60 s filling a 2 h window: timestamp 1, coverage 7140/7200,
    # consistency 24/12 -> 1, histogram 1 (all bins 5) -> final 1
    s = score_series(rhythm(120, 60), (0.0, 7200.0), CFG)
    assert s.timestamp == 1.0 and s.duration == 1.0 and s.histogram == 1.0 and s.final == 1.0
    assert s.n_bins == 24 and s.busy_bins == 24


def test_short_series_is_judged_on_rhythm_and_coverage_only():
    # S2-like: 10 connections 30 s apart inside a 15-minute window. Timestamp 1;
    # coverage 270/900 = 0.3; 6 bins of 150 s, 2 busy: no consistency, no histogram -> final (1+0.3)/2
    s = score_series(rhythm(10, 30), (0.0, 900.0), CFG)
    assert s.timestamp == 1.0 and s.histogram is None and s.consistency is None
    assert s.coverage == pytest.approx(0.3) and s.final == pytest.approx(0.65)


def test_jitter_scores_lower_than_exact_but_higher_than_random():
    rnd = random.Random(7)
    t, jit = 0.0, [0.0]
    for _ in range(9):
        t += rnd.uniform(18, 42)                    # 30 s +-40 %, as scenario S2J
        jit.append(t)
    t, poisson = 0.0, [0.0]
    for _ in range(59):
        t += rnd.expovariate(1 / 30)                # random arrivals, mean 30 s
        poisson.append(t)
    exact = score_series(rhythm(10, 30), (0.0, 3600.0), CFG).timestamp
    jitter = score_series(jit, (0.0, 3600.0), CFG).timestamp
    rand = score_series(poisson, (0.0, 3600.0), CFG).timestamp
    assert exact == 1.0 and 0.6 < jitter < exact and rand < jitter and rand < 0.7


def test_too_few_timestamps():
    assert score_series(rhythm(5, 30), (0.0, 900.0), CFG) is None
    assert score_series(rhythm(6, 30), (0.0, 900.0), CFG) is not None


def test_unsorted_and_duplicate_timestamps():
    base = rhythm(10, 30)
    shuffled = base[::-1]
    assert score_series(shuffled, (0.0, 900.0), CFG) == score_series(base, (0.0, 900.0), CFG)
    burst = base + [base[3]] * 50                   # 50 copies of one timestamp: zero gaps dropped
    s = score_series(burst, (0.0, 900.0), CFG)
    assert s.distinct == 10 and s.n == 60 and s.timestamp == 1.0
    assert score_series([100.0] * 50, (0.0, 900.0), CFG) is None       # a burst alone is not a rhythm


def test_awake_segments_split_at_sleep_gaps():
    times = [0, 10, 20, 400, 410, 420]              # 380 s silence > 300
    assert awake_segments(times, 300) == [(0, 20), (400, 420)]
    assert awake_segments([20, 0, 10], 300) == [(0, 20)]
    assert awake_segments([0, 10, 20, 320, 330], 300) == [(0, 330)]    # 300 exactly: not a sleep
    assert awake_segments([], 300) == []


# -- alerts from a store --------------------------------------------------------------------
SYSMON = "Microsoft-Windows-Sysmon/Operational"
BASE = 1_800_000_000                                # some epoch second; only differences matter


def net(host, rid, t, image, ip, port="443", initiated="true", origin="normal", guid="{G1}",
        utc=None, channel=SYSMON, paused=None):
    """A Sysmon network event. `t` is the record time (ISO); `utc` the Sysmon UtcTime text
    (defaults to the same instant)."""
    rec = {"host": host, "channel": channel, "record_id": rid, "time": t, "event_id": 3,
           "origin": origin, "data": {"Image": image, "ProcessGuid": guid, "DestinationIp": ip,
                                      "DestinationPort": port, "Initiated": initiated, "Protocol": "tcp",
                                      "UtcTime": utc if utc is not None else utctime(iso_seconds(t))}}
    if paused is not None:
        rec["paused"] = paused
    return rec


def iso(seconds):
    whole = int(seconds)
    frac = seconds - whole
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(BASE + whole, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(round(frac * 1e7)):07d}Z"


def utctime(seconds):
    """Sysmon's UtcTime spelling: 'YYYY-MM-DD HH:MM:SS.fff' (milliseconds)."""
    whole = int(seconds)
    frac = seconds - whole
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(BASE + whole, timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f".{int(round(frac * 1e3)):03d}"


def iso_seconds(text):
    from datetime import datetime
    return datetime.fromisoformat(text).timestamp() - BASE


def alert_time(seconds):
    """The alert spelling: ISO-8601 UTC with milliseconds (same as engine/detect.py)."""
    return iso(seconds)[:23] + "Z"


def make_store(tmp_path, records):
    st = EventStore(str(tmp_path / "e.db"))
    st.insert(records)
    st.close()
    return sqlite3.connect(f"file:{tmp_path / 'e.db'}?mode=ro", uri=True)


def test_alerts_from_store(tmp_path):
    recs = []
    rid = 0
    for t in rhythm(10, 30):                        # the rhythm
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\beacon.exe", "10.0.0.9"))
    for t in rhythm(10, 30, start=5):               # another program, same destination
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\other.exe", "10.0.0.9"))
    for t in rhythm(10, 30, start=7):               # our own tools: ignored
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\ours.exe", "10.0.0.9", origin="project"))
    for t in rhythm(10, 30, start=9):               # incoming: ignored
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\server.exe", "10.0.0.9", initiated="false"))
    for t in rhythm(10, 30, start=11):              # multicast destination: ignored
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\mdns.exe", "224.0.0.251", port="5353"))
    for t in (0, 17, 40, 41, 99, 100, 160, 200, 201, 270):     # irregular: scored, but no alert at 0.8
        rid += 1; recs.append(net("h", rid, iso(float(t)), r"C:\x\random.exe", "10.0.0.9"))
    for t in (3, 200, 280):                         # other events: keep the host awake for 280 s
        rid += 1; recs.append({"host": "h", "channel": SYSMON, "record_id": rid, "time": iso(t), "event_id": 1})
    db = make_store(tmp_path, recs)
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8)
    alerts = beacon_alerts(db, cfg)
    images = sorted(a.details["image"] for a in alerts)
    assert images == [r"C:\x\beacon.exe", r"C:\x\other.exe"]       # separate series; ours, incoming, multicast, irregular: no
    assert any(k[1].endswith("random.exe") for k, _, _, _ in score_store(db, cfg))    # irregular was scored, just low
    assert not any(k[1].endswith("mdns.exe") for k, _, _, _ in score_store(db, cfg))  # multicast never scored
    a = next(x for x in alerts if x.details["image"].endswith("beacon.exe"))
    assert a.source == "beacon" and a.rule_id == "beacon" and a.host == "h" and a.level == "medium"
    # the alert is stamped where the rhythm first reached the gate: after 6 check-ins (the minimum)
    assert len(a.evidence) == 6 and missing_evidence(a, db) == []
    assert a.time == alert_time(150) and a.details["n"] == 10 and a.details["detected_after_checkins"] == 6
    assert "10 times" in a.reason and "30.0 s" in a.reason and f"{a.details['final']:.2f}" in a.reason
    assert a.details["timestamp"] == 1.0 and a.details["histogram"] is None
    # window = the host's awake segment (0..281 s: the ignored multicast series still proves the
    # host was awake until 281), not the series' own span
    assert a.details["window_seconds"] == pytest.approx(281)
    assert a.details["coverage"] == pytest.approx(270 / 281)
    # running twice gives the same ids
    assert [x.alert_id for x in beacon_alerts(db, cfg)] == [x.alert_id for x in alerts]
    # threshold respected: at 0 the irregular program alerts too (the multicast one never does)
    assert len(beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0))) == 3


def test_series_split_across_a_sleep_gap(tmp_path):
    recs = []
    rid = 0
    for t in rhythm(6, 30) + rhythm(6, 30, start=1000):      # 850 s of silence in the middle
        rid += 1; recs.append(net("h", rid, iso(t), r"C:\x\beacon.exe", "10.0.0.9"))
    db = make_store(tmp_path, recs)
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0)
    alerts = beacon_alerts(db, cfg)
    assert len(alerts) == 2 and all(len(a.evidence) == 6 for a in alerts)
    assert all(a.details["timestamp"] == 1.0 for a in alerts)
    # a pause shorter than the sleep gap does not split. One skipped beat among ten regular
    # gaps does not move the median or the MAD, so the timestamp score stays 1 (RITA's
    # statistics are robust on purpose); the pause shows up in the bins instead.
    recs2 = []
    for i, t in enumerate(rhythm(6, 30) + rhythm(6, 30, start=400)):  # 250 s pause < 300
        recs2.append(net("h", i + 1, iso(t), r"C:\x\beacon.exe", "10.0.0.9"))
    (tmp_path / "b").mkdir()
    alerts2 = beacon_alerts(make_store(tmp_path / "b", recs2), cfg)
    assert len(alerts2) == 1 and alerts2[0].details["n"] == 12 and len(alerts2[0].evidence) == 6
    assert alerts2[0].details["timestamp"] == 1.0 and alerts2[0].details["busy_bins"] < alerts2[0].details["n_bins"]


def test_boot_splits_the_window(tmp_path):
    # the same program keeps its rhythm across a quick reboot (60 s of silence < sleep gap):
    # Sysmon's "service started" event at the new boot's first second still splits the window
    recs = [net("h", i + 1, iso(t), r"C:\x\beacon.exe", "10.0.0.9")
            for i, t in enumerate(rhythm(8, 30) + rhythm(8, 30, start=300))]
    recs.append({"host": "h", "channel": SYSMON, "record_id": 99, "time": iso(300), "event_id": 4,
                 "data": {"State": "Started", "UtcTime": utctime(300)}})
    db = make_store(tmp_path, recs)
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0)
    alerts = beacon_alerts(db, cfg)
    assert sorted(a.details["window_start"] for a in alerts) == [pytest.approx(0 + BASE), pytest.approx(300 + BASE)]
    assert all(a.details["n"] == 8 for a in alerts)
    # the split can be switched off (then it is one series of 16)
    off = beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0, split_at_boot=False))
    assert len(off) == 1 and off[0].details["n"] == 16


def test_awake_segments_with_boots():
    assert awake_segments([0, 10, 20, 30, 40], 300, boots=[20]) == [(0, 10), (20, 40)]
    assert awake_segments([0, 10, 20], 300, boots=[0]) == [(0, 20)]          # a boot at the very start: no empty segment


def test_is_unicast():
    from engine.beacon import is_unicast
    assert is_unicast("10.0.2.2") and is_unicast("8.8.8.8") and is_unicast("2001:db8::1")
    for bad in ("224.0.0.251", "239.255.255.250", "255.255.255.255", "192.168.1.255", "169.254.1.1",
                "127.0.0.1", "::1", "ff02::fb", "fe80::1", "0.0.0.0", "", None, "not-an-ip"):
        assert not is_unicast(bad), bad


def test_too_few_connections_give_no_alert(tmp_path):
    recs = [net("h", i + 1, iso(t), r"C:\x\beacon.exe", "10.0.0.9") for i, t in enumerate(rhythm(5, 30))]
    db = make_store(tmp_path, recs)
    assert beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0)) == []


# -- frozen config ---------------------------------------------------------------------------
def test_null_config_refuses(tmp_path):
    p = tmp_path / "frozen.yaml"
    p.write_text("beacon:\n  min_timestamps: 6\n  sleep_gap_seconds: 300\n  rhythm_threshold: null\n")
    with pytest.raises(ValueError, match="rhythm_threshold"):
        load_config(str(p))
    p.write_text("beacon:\n  min_timestamps: 6\n  sleep_gap_seconds: 300\n  rhythm_threshold: 0.8\n"
                 "  beats_per_bin: 5\n  short_series_rule: text\n  level: medium\n")
    cfg = load_config(str(p))
    assert cfg.rhythm_threshold == 0.8 and cfg.beats_per_bin == 5


def test_repo_config_has_the_proposed_values():
    cfg = load_config()
    assert (cfg.min_timestamps, cfg.sleep_gap_seconds, cfg.rhythm_threshold) == (10, 300, 0.9)
    assert cfg.unicast_only and cfg.split_at_boot and cfg.beats_per_bin == 5


# -- review fixes (2026-10-22): real timestamps, double taps, guards, cap, crossing --------------
def test_missed_beats_with_millisecond_noise_keep_the_score():
    # a 30 s beacon that misses several beats, on real epoch timestamps with +-1 ms noise.
    # Q1 and Q2 are 30.000x and 30.000y: compared at RITA's 1 s resolution they are equal, so
    # the "Q2 differs from Q1" guard fires, skew counts as 0 and the score stays 1.
    rnd = random.Random(3)
    gaps = [30] * 5 + [90, 120, 150, 30, 30, 200]
    t = 1_800_000_000.3
    times = [t]
    for g in gaps:
        t += g + rnd.uniform(-0.001, 0.001)
        times.append(t)
    s = score_series(times, (times[0], times[-1]), CFG)
    assert s.skew_score == 1.0 and s.timestamp == pytest.approx(1.0, abs=1e-3)
    # KNOWN LIMIT (RITA's whole-second guard): noise of +-1 s can put Q1 and Q2 in different
    # seconds (29 vs 30); the guard stays off, Bowley is ~1 and the score drops to ~0.5;
    # whether it does depends on the draw. Over 200 draws, some but not all must fail
    # (measured share in docs/plans/reports/beacon.md 6.3).
    low = 0
    for seed in range(200):
        rnd = random.Random(seed)
        t = 1_800_000_000.3
        noisy = [t]
        for g in gaps:
            t += g + rnd.uniform(-1.0, 1.0)
            noisy.append(t)
        low += score_series(noisy, (noisy[0], noisy[-1]), CFG).timestamp < 0.6
    assert 0 < low < 200
    # a genuinely wide low end is not "equal": gaps 10,20,25,40,100 still compute the skew
    assert timestamp_score([10, 20, 25, 40, 100], CFG)["skew_score"] == pytest.approx(0.5)


def test_double_tap_is_one_checkin():
    # two connections 0.3 s apart at every 60 s check-in: folded into one check-in each
    times = []
    for i in range(10):
        times += [i * 60.0, i * 60.0 + 0.3]
    s = score_series(times, (0.0, 600.0), CFG)
    assert s.n == 20 and s.distinct == 10 and s.timestamp == 1.0
    assert first_crossing(times, CFG) == 300.3          # the last connection of the 6th check-in


def test_fold_is_chained_so_a_fast_loop_is_one_checkin():
    # 60 connections 0.5 s apart: each is < 1 s after the previous one -> ONE check-in, never
    # scored (an unchained fold would keep every second one and see a perfect 1 s rhythm)
    loop = [i * 0.5 for i in range(60)]
    assert checkin_times(loop, 1.0) == [0.0]
    assert score_series(loop, (0.0, 30.0), CFG) is None
    # gaps of exactly 1.0 s are kept (>= the resolution)
    assert checkin_times([float(i) for i in range(10)], 1.0) == list(range(10))
    fast = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8, min_median_gap_seconds=0)
    assert score_series([float(i) for i in range(10)], (0.0, 9.0), fast).distinct == 10


def test_rhythms_faster_than_ritas_skew_scale_are_not_judged():
    # a perfect 5 s rhythm lives entirely below RITA's 10 s IQR scale (no skew information,
    # MAD term alone): not judged, unless the rule is switched off
    assert score_series(rhythm(20, 5), (0.0, 100.0), CFG) is None
    assert first_crossing(rhythm(20, 5), CFG) is None
    off = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8, min_median_gap_seconds=0)
    assert score_series(rhythm(20, 5), (0.0, 100.0), off).timestamp == 1.0
    assert score_series(rhythm(20, 10), (0.0, 200.0), CFG).timestamp == 1.0        # exactly 10 s: judged
    # a random sub-second burst (60 connections, mean gap 0.3 s) folds into a handful of
    # check-ins: below the frozen minimum, so it is never judged
    rnd = random.Random(11)
    t, burst = 0.0, [0.0]
    for _ in range(59):
        t += rnd.expovariate(1 / 0.3)
        burst.append(t)
    assert score_series(burst, (0.0, burst[-1]), load_config()) is None


def test_quartiles_between_sample_points():
    # 4 gaps 10,20,30,100 (linear interpolation): Q1 = 17.5, Q2 = 25, Q3 = 47.5; IQR 30 >= 10;
    # Bowley = (47.5 + 17.5 - 50) / 30 = 0.5 -> skew score 0.5;
    # |g - 25| = 15,5,5,75 -> sorted 5,5,15,75 -> MAD 10 -> MAD score 15/25 = 0.6 -> 0.55
    s = timestamp_score([10, 20, 30, 100], CFG)
    assert s["skew_score"] == pytest.approx(0.5) and s["mad_score"] == pytest.approx(0.6)
    assert s["timestamp"] == pytest.approx(0.55)


def test_negative_bowley_skew():
    # gaps 10,40,55,60,100: Q1=40 Q2=55 Q3=60 -> Bowley = (60+40-110)/20 = -0.5 -> skew score 0.5
    assert timestamp_score([10, 40, 55, 60, 100], CFG)["skew_score"] == pytest.approx(0.5)


def test_mad_never_exceeds_median_for_positive_gaps():
    # (median - MAD) / median cannot go negative on positive gaps: at least half the gaps lie
    # at or below the median, each at most `median` away from it, so MAD <= median. The clamp
    # to 0 is RITA's rule, kept, but unreachable: checked on random gap lists.
    rnd = random.Random(5)
    for _ in range(300):
        gaps = [rnd.choice([rnd.uniform(1, 5), rnd.uniform(1, 500), rnd.expovariate(0.01) + 1]) for _ in range(rnd.randint(3, 40))]
        assert 0.0 <= timestamp_score(gaps, CFG)["mad_score"] <= 1.0


def test_exactly_six_busy_bins_and_a_window_over_24h():
    assert consistency_score([1] * 6 + [0] * 18, CFG) == pytest.approx(6 / 12)     # exactly the minimum
    # a 48 h window handed in directly: coverage is measured against RITA's 24 h cap
    day = rhythm(1441, 60)                                                            # 24 h of 60 s beats
    s = score_series(day, (0.0, 172800.0), CFG)
    assert s.coverage == 1.0 and s.window == 172800.0


def test_sysmon_clock_is_preferred_over_logging_time(tmp_path):
    # UtcTime is a perfect 30 s rhythm; the log's record time lags it by 0-9 s at random
    rnd = random.Random(8)
    recs = [net("h", i + 1, iso(t + rnd.uniform(0, 9)), r"C:\x\b.exe", "10.0.0.9", utc=utctime(t))
            for i, t in enumerate(rhythm(10, 30))]
    db = make_store(tmp_path, recs)
    alerts = beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.95))
    assert len(alerts) == 1 and alerts[0].details["timestamp"] == 1.0 and alerts[0].details["median_gap"] == 30.0
    assert alerts[0].time == alert_time(150)          # stamped on Sysmon's clock, milliseconds, like every alert


def test_other_channels_and_paused_rows_are_ignored(tmp_path):
    recs = [net("h", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30))]
    recs += [net("h", 20 + i, iso(t), r"C:\x\c.exe", "10.0.0.9", channel="Other") for i, t in enumerate(rhythm(10, 30))]
    recs += [net("h", 40 + i, iso(t), r"C:\x\d.exe", "10.0.0.9", paused=1) for i, t in enumerate(rhythm(10, 30))]
    db = make_store(tmp_path, recs)
    alerts = beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.9))
    assert [a.details["image"] for a in alerts] == [r"C:\x\b.exe"]


def test_mad_guard_boundary():
    assert timestamp_score([1.0] * 8, CFG)["mad_score"] == 1.0         # median exactly 1 s: computed
    assert timestamp_score([0.999] * 8, CFG)["mad_score"] == 0.0       # just under: not computed


def test_q2_equal_q3_guard():
    # gaps 10,20,40,40,100: Q1=20 Q2=40 Q3=40 -> guard -> skew 0 -> skew score 1
    assert timestamp_score([10, 20, 40, 40, 100], CFG)["skew_score"] == 1.0


def test_window_cap_splits_long_stretches():
    hours30 = [i * 600.0 for i in range(181)]            # an event every 10 min for 30 h
    segs = awake_segments(hours30, 900, cap=86400)
    assert len(segs) == 2 and segs[0][1] - segs[0][0] <= 86400 and segs[1][0] > segs[0][1]
    assert bin_counts([5.0], (0.0, 0.0), median_gap=1, cfg=CFG) == ([1], 1.0)     # a window of length 0


def test_first_crossing_gives_a_stable_alert(tmp_path):
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=1.0)   # exactly at the gate
    short = [net("h", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30))]
    grown = short + [net("h", 11 + i, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30, start=300))]
    a = beacon_alerts(make_store(tmp_path, short), cfg)
    (tmp_path / "g").mkdir()
    b = beacon_alerts(make_store(tmp_path / "g", grown), cfg)
    assert len(a) == len(b) == 1 and a[0].alert_id == b[0].alert_id and a[0].time == b[0].time == alert_time(150)
    assert b[0].details["n"] == 20 and len(b[0].evidence) == 6


def test_frozen_values_end_to_end(tmp_path):
    cfg = load_config()                                   # the repo's proposed block
    nine = [net("h", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(9, 30))]
    ten = nine + [net("h", 10, iso(270.0), r"C:\x\b.exe", "10.0.0.9")]
    assert beacon_alerts(make_store(tmp_path, nine), cfg) == []
    (tmp_path / "t").mkdir()
    assert len(beacon_alerts(make_store(tmp_path / "t", ten), cfg)) == 1


def test_unreadable_time_is_skipped(tmp_path):
    recs = [net("h", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30))]
    recs.append(net("h", 99, "not a time", r"C:\x\b.exe", "10.0.0.9", utc="not a time"))
    db = make_store(tmp_path, recs)
    from engine.beacon import series_from_store
    bad = []
    series = series_from_store(db, unreadable=bad)
    assert len(bad) == 1 and sum(len(v) for v in series.values()) == 10
    assert len(beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.9))) == 1


def test_windows_are_per_host(tmp_path):
    # host A's rhythm runs 0..270 s; host B has events until 2000 s. A's window must not be
    # stretched by B's events (coverage would drop), and B gets no series of its own.
    recs = [net("A", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9") for i, t in enumerate(rhythm(10, 30))]
    recs += [{"host": "B", "channel": SYSMON, "record_id": 50 + i, "time": iso(t), "event_id": 1} for i, t in enumerate((0, 1000, 2000))]
    db = make_store(tmp_path, recs)
    alerts = beacon_alerts(db, BeaconConfig(min_timestamps=6, sleep_gap_seconds=3000, rhythm_threshold=0.9))
    assert len(alerts) == 1 and alerts[0].host == "A"
    assert alerts[0].details["window_seconds"] == pytest.approx(270) and alerts[0].details["coverage"] == 1.0


def test_boot_split_needs_a_sysmon_service_start(tmp_path):
    # the same "Started" record on another channel is not a boot marker: one series of 16
    recs = [net("h", i + 1, iso(t), r"C:\x\b.exe", "10.0.0.9")
            for i, t in enumerate(rhythm(8, 30) + rhythm(8, 30, start=300))]
    recs.append({"host": "h", "channel": "Other", "record_id": 99, "time": iso(300), "event_id": 4,
                 "data": {"State": "Started", "UtcTime": utctime(300)}})
    alerts = beacon_alerts(make_store(tmp_path, recs), BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.0))
    assert len(alerts) == 1 and alerts[0].details["n"] == 16


def test_histogram_uses_population_sd():
    # 24 busy bins with counts 4,5,6 repeating: mean 5, population sd sqrt(2/3) = 0.8165 ->
    # CV 0.1633 -> 0.8367 (the sample sd, 0.8341, would give 0.8332); bimodal: buckets of 1,
    # three buckets of 8 -> top two 16/23 = 0.696, so the CV part wins
    counts = [4, 5, 6] * 8
    assert histogram_score(counts, CFG) == pytest.approx(1 - math.sqrt(2 / 3) / 5, abs=1e-9)
    assert bimodal_fit(counts) == pytest.approx(16 / 23)


def test_max_connections_boundary():
    # RITA skips series of 86,400 connections or more; 86,399 at 10 s gaps are scored
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.9, window_cap_seconds=10 ** 7)
    big = rhythm(86_399, 10)
    assert score_series(big, (0.0, big[-1]), cfg) is not None
    assert score_series(big + [big[-1] + 10], (0.0, big[-1] + 10), cfg) is None


def test_bin_counts_survive_a_bad_median():
    # a median gap that is not a finite positive number (nan, inf, 0) falls back to the
    # smallest beat -> 24 bins, never a crash
    for bad in (float("nan"), float("inf"), 0.0):
        counts, _ = bin_counts([5.0], (0.0, 100.0), median_gap=bad, cfg=CFG)
        assert len(counts) == 24 and sum(counts) == 1, bad


def test_config_validation(tmp_path):
    with pytest.raises(ValueError, match="at least 4"):
        BeaconConfig(min_timestamps=2, sleep_gap_seconds=300, rhythm_threshold=0.9)
    p = tmp_path / "frozen.yaml"
    p.write_text("beacon:\n  min_timestamps: 6\n  sleep_gap_seconds: 300\n  rhythm_threshold: 0.9\n  beats_per_bim: 5\n")
    with pytest.raises(ValueError, match="unknown keys beats_per_bim"):
        load_config(str(p))


def test_listed_updater_is_noticed_but_labelled_expected(tmp_path):
    """C1 (2026-10-23): a series on the expected-updaters list is still alerted, at level
    informational and labelled expected; the same rhythm off the list stays medium."""
    recs, rid = [], 0
    for t in rhythm(10, 30):
        rid += 1; recs.append(net("h", rid, iso(t), r"D:\c1\c1_updater.exe", "10.0.0.9"))
    for t in rhythm(10, 30, start=5):
        rid += 1; recs.append(net("h", rid, iso(t), r"D:\s2\s2_checkin.exe", "10.0.0.9"))
    for t in rhythm(10, 30, start=7):                       # listed program, other destination: not expected
        rid += 1; recs.append(net("h", rid, iso(t), r"D:\c1\c1_updater.exe", "10.0.0.8"))
    db = make_store(tmp_path, recs)
    cfg = BeaconConfig(min_timestamps=6, sleep_gap_seconds=300, rhythm_threshold=0.8,
                       expected=(("c1_updater.exe", "10.0.0.9:443", "test listed updater"),))
    got = {(a.details["image"].rsplit("\\", 1)[-1], a.details["destination_ip"]): a for a in beacon_alerts(db, cfg)}
    listed = got[("c1_updater.exe", "10.0.0.9")]
    assert listed.level == "informational" and listed.reason.startswith("Expected (listed updater: test listed updater)")
    assert listed.details["expected"] == "test listed updater"
    assert got[("s2_checkin.exe", "10.0.0.9")].level == "medium" and "expected" not in got[("s2_checkin.exe", "10.0.0.9")].details
    assert got[("c1_updater.exe", "10.0.0.8")].level == "medium"


def test_expected_list_loads_from_the_frozen_file():
    cfg = load_config()
    assert ("c1_updater.exe", "10.0.2.2:18765") in {(p, d) for p, d, _ in cfg.expected}
