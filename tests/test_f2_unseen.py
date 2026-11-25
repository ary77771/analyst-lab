"""v4 F2 (docs/plans/v4-prereg.md section 5): the registered short check-in test also judges series of a
program the machine never saw opening an outgoing connection during its learning period (learned-normal
connector lists, engine/baseline.learn_connectors). Hand-made events only."""
import json
import sqlite3
from dataclasses import replace

import pytest

from engine import baseline as BL
from engine import beacon as B
from engine import score as S
from tests.test_detect import ev, store
from tests.test_v3_rules import beacons, con_of

CD = r"D:\blind\x\bin\telemetry.exe"           # runs from a read-only CD: never "freshly written"
JITTER = [0, 20.3, 42.7, 73.9, 97.9, 123.9, 151.2, 182.4]   # 8 check-ins 18-32 s apart (B15's shape)


def jittered(image=CD, start=100.0, ip="10.0.2.2"):
    return [ev(3, start + t, ProcessGuid="{T}", Image=image, Initiated="true", DestinationIp=ip, DestinationPort=18765)
            for t in JITTER]


def cfg(on=True):
    return replace(B.load_config(), short_unseen=on)


KNOWN = {"h1": {"browser.exe"}}                 # ev() records are on host "h1"


def test_a_never_seen_program_with_jittered_checkins_fires_by_the_short_gate(tmp_path):
    con = con_of(tmp_path, jittered())
    assert B.beacon_alerts(con, cfg(on=False), connectors=KNOWN) == []     # v3: not fresh, 8 < 10: never judged
    (a,) = B.beacon_alerts(con, cfg(), connectors=KNOWN)
    assert a.details["gate"] == "short" and a.details["eligible"] == "never_seen_connecting"
    assert "written_seconds_before_first_checkin" not in a.details
    assert "never saw this program open an outgoing connection" in a.reason and a.level == "medium"
    assert 4 <= a.details["detected_after_checkins"] <= 8


def test_the_frozen_config_has_f2_off():
    """2026-11-17: OFF by the pre-registered blind condition (the innocent B11 turned FALSE ALARM)."""
    assert B.load_config().short_unseen is False


def test_a_learned_program_stays_quiet(tmp_path):
    con = con_of(tmp_path, jittered())
    assert B.beacon_alerts(con, cfg(), connectors={"h1": {"telemetry.exe"}}) == []
    assert B.beacon_alerts(con, cfg(), connectors={"H1": {"telemetry.exe"}} | {"h1": {"TELEMETRY.EXE".lower()}}) == []


@pytest.mark.parametrize("connectors", [None, {}, {"other-pc": set()}])
def test_without_a_learned_list_for_the_machine_nothing_new_fires(tmp_path, connectors):
    """No list is not an empty list: a machine nobody learned must not call every program new."""
    assert B.beacon_alerts(con_of(tmp_path, jittered()), cfg(), connectors=connectors) == []


def test_an_empty_learned_list_does_judge(tmp_path):
    assert len(B.beacon_alerts(con_of(tmp_path, jittered()), cfg(), connectors={"h1": set()})) == 1


def test_uneven_timing_stays_quiet_even_for_a_new_program(tmp_path):
    recs = [ev(3, 100 + t, ProcessGuid="{T}", Image=CD, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765)
            for t in (0, 10, 60, 70, 200, 210, 400, 405)]
    assert B.beacon_alerts(con_of(tmp_path, recs), cfg(), connectors=KNOWN) == []


def test_a_fresh_drop_keeps_its_own_reason(tmp_path):
    drop = r"C:\AnalystLab\work\cache\x.exe"
    recs = [ev(11, 50, ProcessGuid="{W}", TargetFilename=drop)] + jittered(image=drop)
    (a,) = B.beacon_alerts(con_of(tmp_path, recs), cfg(), connectors=KNOWN)
    assert a.details["eligible"] == "fresh_drop" and "freshly dropped" in a.reason


def test_a_listed_updater_stays_informational(tmp_path):
    c = replace(cfg(), expected=(("telemetry.exe", "10.0.2.2:18765", "the lab's listed updater"),))
    (a,) = B.beacon_alerts(con_of(tmp_path, jittered()), c, connectors=KNOWN)
    assert a.level == "informational" and a.details["expected"]


def test_series_the_rita_gate_also_alerts_stay_one_alert(tmp_path):
    recs = beacons(14, gap=20.0, image=CD)
    con = con_of(tmp_path, recs)
    rita = B.beacon_alerts(con, replace(cfg(on=False), short_min=None, short_cutoffs=None))
    both = B.beacon_alerts(con, cfg(), connectors=KNOWN)
    assert len(rita) == 1 and len(both) == 1 and both[0].details["gate"] == "short" and both[0].time < rita[0].time


def test_one_new_program_raises_once(tmp_path):
    """Review 2026-11-17 finding 1: a new program polling for days must not raise one alert per destination
    per awake window. F2 raises ONE alert per (machine, program); later F2 series of it stay visible as
    informational (`details.repeat_of`)."""
    recs = []
    for day, ip in enumerate(["10.0.2.2", "10.0.2.3", "10.0.2.4"]):
        recs += jittered(start=100.0 + day * 3600, ip=ip)          # 3 destinations, windows an hour apart (asleep)
    alerts = B.beacon_alerts(con_of(tmp_path, recs), cfg(), connectors=KNOWN)
    raised = [a for a in alerts if a.level == "medium"]
    assert len(alerts) == 3 and len(raised) == 1
    first = raised[0]
    assert first.time == min(a.time for a in alerts)
    for a in alerts:
        if a is not first:
            assert a.level == "informational" and a.details["repeat_of"] == first.alert_id
            assert a.reason.startswith("Already alerted for this program on this machine")


def test_a_fresh_drop_is_never_capped(tmp_path):
    drop = r"C:\AnalystLab\work\cache\x.exe"
    recs = [ev(11, 50, ProcessGuid="{W}", TargetFilename=drop)]
    for k, ip in enumerate(["10.0.2.2", "10.0.2.3"]):
        recs += jittered(image=drop, start=100.0 + k * 3600, ip=ip)
    alerts = B.beacon_alerts(con_of(tmp_path, recs), cfg(), connectors=KNOWN)
    assert [a.level for a in alerts] == ["medium", "medium"]                # v3 behaviour unchanged


def test_a_learned_shell_is_labelled_honestly(tmp_path):
    """Finding 2: a shell ON the learned list is still judged (never-normal), but not called 'never seen'."""
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    (a,) = B.beacon_alerts(con_of(tmp_path, jittered(image=ps)), cfg(), connectors={"h1": {"powershell.exe"}})
    assert a.details["eligible"] == "never_normal_program"
    assert "never treated as learned" in a.reason and "never saw" not in a.reason
    (b,) = B.beacon_alerts(con_of(tmp_path, jittered(image=ps)), cfg(), connectors=KNOWN)
    assert b.details["eligible"] == "never_seen_connecting"


def test_never_seen_connecting():
    assert B.never_seen_connecting({"h1": {"a.exe"}}, "H1", r"C:\x\B.EXE")
    assert not B.never_seen_connecting({"h1": {"b.exe"}}, "h1", r"C:\x\B.EXE")
    assert not B.never_seen_connecting({"h1": {"a.exe"}}, "h2", r"C:\x\b.exe")
    assert not B.never_seen_connecting(None, "h1", r"C:\x\b.exe")
    assert not B.never_seen_connecting({"h1": set()}, "h1", "")
    assert B.never_seen_connecting({"h1": {"powershell.exe", "cmd.exe"}}, "h1", r"C:\W\powershell.exe")   # never learned
    assert B.never_seen_connecting({"h1": {"?"}}, "h1", "?")
    assert not B.never_seen_connecting(None, "h1", r"C:\W\powershell.exe")       # still: no list, no rule


# -- learning and loading ---------------------------------------------------------------------------
def test_learn_connectors_mirrors_the_beacon_series(tmp_path):
    recs = [ev(3, 1, Image=r"C:\a\Out.exe", Initiated="true", DestinationIp="10.0.2.2"),
            ev(3, 2, Image=r"C:\a\inbound.exe", Initiated="false", DestinationIp="10.0.2.2"),
            ev(3, 3, Image=r"C:\a\bcast.exe", Initiated="true", DestinationIp="255.255.255.255"),
            ev(3, 4, Image=r"C:\a\ours.exe", Initiated="true", DestinationIp="10.0.2.2", origin="project"),
            ev(3, 5, Image=r"C:\a\paused.exe", Initiated="true", DestinationIp="10.0.2.2", paused=1),
            ev(3, 9000, Image=r"C:\a\late.exe", Initiated="true", DestinationIp="10.0.2.2")]
    con = sqlite3.connect(store(tmp_path, recs))
    got = BL.learn_connectors(con, until="2026-10-22T11:00:00Z")
    assert got["h1"]["connectors"] == ["out.exe"] and got["h1"]["shell_pairs"] == [] and got["h1"]["listeners"] == []
    assert BL.learn_connectors(con)["h1"]["connectors"] == ["late.exe", "out.exe"]


def test_learn_connectors_filters_and_host_case(tmp_path):
    recs = [ev(3, 1, Image=r"C:\a\One.exe", Initiated="true", DestinationIp="10.0.2.2", host="PC-A"),
            ev(3, 2, Image=r"C:\a\two.exe", Initiated="true", DestinationIp="10.0.2.2", host="pc-b"),
            ev(3, 3, Image=r"C:\a\late.exe", Initiated="true", DestinationIp="10.0.2.2", host="PC-A", happened=1)]
    recs[2]["time"] = "2026-10-22T13:00:00Z"                 # LOGGED after the cut, HAPPENED before it (finding 6)
    con = sqlite3.connect(store(tmp_path, recs))
    got = BL.learn_connectors(con, until="2026-10-22T12:00:00Z")
    assert got["pc-a"]["connectors"] == ["late.exe", "one.exe"] and got["pc-b"]["connectors"] == ["two.exe"]
    assert set(BL.learn_connectors(con, host="pc-a")) == {"pc-a"}
    assert BL.learn_connectors(con, sessions=[]).get("pc-a", {}).get("connectors", []) == []
    bcast = [ev(3, 1, Image=r"C:\a\b.exe", Initiated="true", DestinationIp="255.255.255.255")]
    con2 = sqlite3.connect(store(tmp_path, bcast))
    assert BL.learn_connectors(con2)["h1"]["connectors"] == []
    assert BL.learn_connectors(con2, unicast_only=False)["h1"]["connectors"] == ["b.exe"]   # finding 7


def test_load_merges_lists_and_null_is_no_list(tmp_path):
    a, b, c = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"
    BL.save({"h1": {"shell_pairs": [], "listeners": [], "connectors": ["x.exe"], "events": 1}}, str(a), "t")
    BL.save({"h1": {"shell_pairs": [], "listeners": [], "connectors": ["y.exe"], "events": 1}}, str(b), "t")
    BL.save({"h1": {"shell_pairs": [], "listeners": [], "connectors": None, "events": 1}}, str(c), "t")
    assert BL.load([str(a), str(b)])["h1"]["connectors"] == {"x.exe", "y.exe"}
    assert BL.load([str(c)])["h1"]["connectors"] is None                       # finding 5: null = no list


def test_a_host_only_in_other_baseline_files_gets_no_f2(tmp_path):
    from engine import detect
    a = tmp_path / "pairs.json"
    BL.save({"h1": {"shell_pairs": [["x.exe", "cmd.exe"]], "listeners": [], "events": 1}}, str(a), "t")
    con = detect.open_store(store(tmp_path, jittered()))
    try:
        assert [x for x in S.score(con, [], BL.load([str(a)]), beacon_cfg=cfg()) if x.rule_id == B.RULE_ID] == []
    finally:
        con.close()


def test_load_keeps_no_list_apart_from_an_empty_list(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    BL.save({"h1": {"shell_pairs": [], "listeners": ["x.exe"], "events": 1}}, str(a), "t")
    BL.save({"h1": {"shell_pairs": [], "listeners": [], "connectors": [], "events": 1},
             "h2": {"shell_pairs": [], "listeners": [], "connectors": ["y.exe"], "events": 1}}, str(b), "t")
    only_a = BL.load([str(a)])
    assert only_a["h1"]["connectors"] is None and S.connectors_of(only_a) == {}
    both = BL.load([str(a), str(b)])
    assert both["h1"]["connectors"] == set() and both["h1"]["listeners"] == {"x.exe"}
    assert S.connectors_of(both) == {"h1": set(), "h2": {"y.exe"}}
    assert S.connectors_of(None) is None


def test_score_passes_the_learned_lists_to_the_beacon_rule(tmp_path):
    from engine import detect
    con = detect.open_store(store(tmp_path, jittered()))
    try:
        learned = {"h1": {"shell_pairs": set(), "listeners": set(), "wipers": set(), "connectors": {"browser.exe"}}}
        got = [a for a in S.score(con, [], learned, beacon_cfg=cfg()) if a.rule_id == B.RULE_ID]
        assert len(got) == 1 and got[0].details["eligible"] == "never_seen_connecting"
        assert [a for a in S.score(con, [], learned) if a.rule_id == B.RULE_ID] == []      # frozen config: F2 off
        learned["h1"]["connectors"] = None
        assert [a for a in S.score(con, [], learned, beacon_cfg=cfg()) if a.rule_id == B.RULE_ID] == []
    finally:
        con.close()


def test_the_budget_counts_f2_alerts(tmp_path):
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    import v3_budget as V
    con = sqlite3.connect(store(tmp_path, jittered()))
    with pytest.raises(ValueError, match="connector lists"):
        V.budget(con, cfg())                                     # finding 3: F2 on and no lists = refused
    assert V.budget(con, cfg(on=False), alerts=[])["short"]["extra"] == 0
    doc = V.budget(con, cfg(), connectors=KNOWN, alerts=[])
    assert doc["short"]["extra"] == 1 and doc["short"]["hosts_with_list"] == 1 and doc["short"]["hosts_without_list"] == 0
    doc = V.budget(con, cfg(), connectors={"other": set()}, alerts=[])
    assert doc["short"]["hosts_without_list"] == 1


def test_the_budget_main_uses_the_frozen_lists(monkeypatch):
    """Finding 3: main()'s wiring. The helper main() calls must return the frozen lists, and refuse a
    judged machine without one while F2 is on."""
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    import inspect
    import v3_budget as V
    assert "official_connectors(" in inspect.getsource(V.main)
    monkeypatch.setattr(S, "load_baseline", lambda files=None: {"h1": {"connectors": {"a.exe"}}, "h2": {"connectors": None}})
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE events (host TEXT)")
    con.executemany("INSERT INTO events VALUES (?)", [("h1",), ("H1",)])
    assert V.official_connectors(con, cfg()) == {"h1": {"a.exe"}}
    con.execute("INSERT INTO events VALUES ('h2')")
    with pytest.raises(ValueError, match="no learned connector list"):
        V.official_connectors(con, cfg())
    assert V.official_connectors(con, cfg(on=False)) is None
