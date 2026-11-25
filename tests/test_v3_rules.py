"""Version 3 rules (docs/plans/v3-prereg.md section 1): embedded_system_name, drop_run_delete and the short
check-in test for freshly dropped programs. Hand-made events only."""

import sqlite3
from dataclasses import replace

import pytest

from engine import beacon as B
from engine import own_rules
from tests.test_detect import ev, store

SVCHOST = r"C:\Windows\System32\svchost.exe"
DROP = r"C:\AnalystLab\work\cache\WinSvcHost.exe"
CUTOFFS = {5: 0.2533, 6: 0.2068, 7: 0.1766, 8: 0.155, 9: 0.1385}


def con_of(tmp_path, records):
    return sqlite3.connect(store(tmp_path, records))


# -- 1.1 embedded_system_name (v3 1.8: the published list only) ----------------------------------
LISTED = ["svchost", "dllhost", "lsass", "services", "conhost"]


def emb(con, **kw):
    return own_rules.embedded_system_name(con, **{"extra_references": LISTED, **kw})


def test_a_name_hiding_a_listed_name_fires_once(tmp_path):
    recs = [ev(1, 5, Image=DROP, ProcessGuid="{B}"), ev(1, 9, Image=DROP, ProcessGuid="{C}")]   # no real svchost needed
    alerts = emb(con_of(tmp_path, recs))
    assert len(alerts) == 1 and alerts[0].details == {"program": "winsvchost.exe", "contains": "svchost"}   # paths ignore case
    assert alerts[0].rule_id == "analystlab.embedded_system_name" and alerts[0].level == "medium"


@pytest.mark.parametrize("image", [
    r"C:\Windows\System32\winsvchost.exe",       # inside the Windows folder: not this rule's case
    r"C:\Users\u\svchost.exe",                   # the exact name: SigmaHQ's masquerading rules
    r"C:\Users\u\netsetup.exe",                  # not on the list
    r"C:\Program Files\Notepad++\notepad++.exe", # contains a Windows program (notepad) that is NOT on the list
    r"C:\Program Files\Vendor\nvcontrolpanel.exe",
])
def test_near_misses(tmp_path, image):
    recs = [ev(1, 0, Image=r"C:\Windows\notepad.exe", ProcessGuid="{N}"), ev(1, 0, Image=r"C:\Windows\System32\control.exe", ProcessGuid="{K}"),
            ev(1, 5, Image=image, ProcessGuid="{X}")]
    assert emb(con_of(tmp_path, recs)) == []


def test_an_exact_listed_name_containing_another_is_left_to_sigma(tmp_path):
    """taskhostw contains taskhost; the exact listed name outside Windows is SigmaHQ e4a6b256's case (no double alert)."""
    con = con_of(tmp_path, [ev(1, 5, Image=r"C:\Users\u\taskhostw.exe", ProcessGuid="{X}")])
    assert emb(con, extra_references=["taskhost", "taskhostw"]) == []


def test_the_rule_refuses_to_run_without_its_list(tmp_path):
    with pytest.raises(ValueError, match="reference names"):
        own_rules.embedded_system_name(con_of(tmp_path, [ev(1, 5, Image=DROP, ProcessGuid="{X}")]))


def test_a_subnet_broadcast_is_not_connecting_out(tmp_path):
    assert own_rules.drop_run_delete(con_of(tmp_path, story(ip="10.0.2.255"))) == []     # as beacon.is_unicast


def test_running_windows_programs_are_not_references_by_default(tmp_path):
    """v3 1.8: notepad++ contains notepad, which runs from the Windows folder: no alert unless use_running."""
    recs = [ev(1, 0, Image=r"C:\Windows\notepad.exe", ProcessGuid="{N}"),
            ev(1, 5, Image=r"C:\Program Files\Notepad++\notepad++.exe", ProcessGuid="{X}")]
    con = con_of(tmp_path, recs)
    assert emb(con) == [] and len(emb(con, use_running=True)) == 1


def test_lookalike_also_takes_the_listed_names(tmp_path):
    """v3 1.7: a short run window may hold no start of svchost.exe (B5 run 174202 had none)."""
    con = con_of(tmp_path, [ev(1, 6, Image=r"C:\Users\u\scvhost.exe", ProcessGuid="{C}")])
    assert own_rules.lookalike_name(con) == []
    assert [a.details["looks_like"] for a in own_rules.lookalike_name(con, extra_references=["SVCHOST"])] == ["svchost"]


def test_the_frozen_config_carries_the_listed_names():
    from engine.config import own_rule_params
    p = own_rule_params()
    for rule in ("analystlab.lookalike_name", "analystlab.embedded_system_name"):
        refs = p[rule]["extra_references"]
        assert len(refs) == 55 and "svchost" in refs and "lsass" in refs


def test_the_reference_length_is_a_parameter(tmp_path):
    recs = [ev(1, 5, Image=r"C:\Users\u\mydllhost2.exe", ProcessGuid="{B}")]
    assert len(emb(con_of(tmp_path, recs), min_ref_length=7)) == 1          # dllhost: 7 letters
    assert emb(con_of(tmp_path, recs), min_ref_length=8) == []

# -- 1.2 drop_run_delete ------------------------------------------------------------------------
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def story(t_write=0, t_start=10, t_conn=15, t_del=100, writer=PS, ip="10.0.2.2", deleted=DROP):
    return [ev(11, t_write, ProcessGuid="{W}", Image=writer, TargetFilename=DROP),
            ev(1, t_start, ProcessGuid="{D}", ParentProcessGuid="{W}", Image=DROP),
            ev(3, t_conn, ProcessGuid="{D}", Image=DROP, Initiated="true", DestinationIp=ip, DestinationPort=18765),
            ev(26, t_del, ProcessGuid="{W}", Image=writer, TargetFilename=deleted)]


def test_the_whole_chain_fires_once_with_four_events(tmp_path):
    recs = story()
    alerts = own_rules.drop_run_delete(con_of(tmp_path, recs))
    assert len(alerts) == 1 and len(alerts[0].evidence) == 4 and alerts[0].time == "2026-10-22T10:01:40.000Z"


@pytest.mark.parametrize("case", [
    dict(t_start=400),                         # started more than 300 s after the write
    dict(t_del=1000),                          # deleted more than 900 s after the start
    dict(t_conn=950),                          # connected only after start + 900 s
    dict(ip="127.0.0.1"),                      # talked only to itself
    dict(deleted=r"C:\AnalystLab\work\cache\other.exe"),   # another file deleted
    dict(t_del=5),                             # deleted before it started
])
def test_each_missing_link_breaks_the_chain(tmp_path, case):
    assert own_rules.drop_run_delete(con_of(tmp_path, story(**case))) == []


def test_a_connection_after_the_deletion_completes_the_chain(tmp_path):
    """v3 1.8: a program may delete its own file while running and connect afterwards."""
    alerts = own_rules.drop_run_delete(con_of(tmp_path, story(t_conn=120, t_del=100)))
    assert len(alerts) == 1 and alerts[0].time == "2026-10-22T10:02:00.000Z"     # stamped when the chain was complete


@pytest.mark.parametrize("ip", ["169.254.1.1", "fe80::1", "224.0.0.252", "255.255.255.255"])
def test_link_local_multicast_and_broadcast_are_not_connecting_out(tmp_path, ip):
    assert own_rules.drop_run_delete(con_of(tmp_path, story(ip=ip))) == []


def test_variant_b_needs_a_shell_writer(tmp_path):
    recs = story(writer=r"C:\Program Files\Some\installer.exe")
    assert len(own_rules.drop_run_delete(con_of(tmp_path, recs), writers="any")) == 1
    assert own_rules.drop_run_delete(con_of(tmp_path, recs), writers="shells") == []
    assert len(own_rules.drop_run_delete(con_of(tmp_path, story()), writers="shells")) == 1


# -- 1.3 short check-ins for freshly dropped programs ---------------------------------------------
def beacons(n, gap=10.0, start=100.0, image=DROP, ip="10.0.2.2"):
    return [ev(3, start + i * gap, ProcessGuid="{D}", Image=image, Initiated="true", DestinationIp=ip, DestinationPort=18765)
            for i in range(n)]


def short_cfg(m=5):
    return replace(B.load_config(), short_min=m, short_cutoffs=dict((k, v) for k, v in CUTOFFS.items() if k >= m))


def test_six_even_check_ins_of_a_fresh_drop_fire_by_the_short_gate(tmp_path):
    recs = [ev(11, 50, ProcessGuid="{W}", TargetFilename=DROP)] + beacons(6)
    con = con_of(tmp_path, recs)
    assert B.beacon_alerts(con, replace(B.load_config(), short_min=None)) == []   # v2: 6 < 10, never judged
    alerts = B.beacon_alerts(con, short_cfg())
    assert len(alerts) == 1 and alerts[0].details["gate"] == "short" and alerts[0].details["detected_after_checkins"] == 5
    assert alerts[0].details["written_seconds_before_first_checkin"] == 50.0


@pytest.mark.parametrize("case", ["no write", "old write", "program files", "windows", "uneven"])
def test_the_short_gate_needs_a_fresh_drop_and_even_gaps(tmp_path, case):
    image = {"program files": r"C:\Program Files\App\app.exe", "windows": r"C:\Windows\System32\app.exe"}.get(case, DROP)
    recs = beacons(6, image=image) if case != "uneven" else \
        [ev(3, 100 + t, ProcessGuid="{D}", Image=DROP, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765)
         for t in (0, 10, 60, 70, 200, 210)]
    if case != "no write":
        recs.append(ev(11, -90000 if case == "old write" else 50, ProcessGuid="{W}", TargetFilename=image))
    assert B.beacon_alerts(con_of(tmp_path, recs), short_cfg()) == []


def test_a_series_the_rita_gate_also_alerts_stays_one_alert_stamped_at_the_earlier_gate(tmp_path):
    recs = [ev(11, 50, ProcessGuid="{W}", TargetFilename=DROP)] + beacons(14)
    con = con_of(tmp_path, recs)
    rita = B.beacon_alerts(con, replace(B.load_config(), short_min=None))
    both = B.beacon_alerts(con, short_cfg())
    assert len(rita) == 1 and rita[0].details["gate"] == "rita"
    assert len(both) == 1 and both[0].details["gate"] == "short" and both[0].time < rita[0].time


def test_the_frozen_short_gate_is_b2s_m4_test_and_fires_at_four_check_ins(tmp_path):
    """The config's cut-offs are b2_crit.json's m = 4 values (rounded to 6 places), and the frozen config
    alerts a fresh drop's 4 perfectly even check-ins."""
    import json
    import os
    crit = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                       "docs", "plans", "b2", "b2_crit.json"), encoding="utf-8"))["4"]["c"]
    cfg = B.load_config()
    assert cfg.short_min == 4 and set(cfg.short_cutoffs) == {4, 5, 6, 7, 8, 9}
    assert all(abs(cfg.short_cutoffs[int(k)] - v) < 1e-6 for k, v in crit.items())
    recs = [ev(11, 50, ProcessGuid="{W}", TargetFilename=DROP)] + beacons(4)
    alerts = B.beacon_alerts(con_of(tmp_path, recs), cfg)
    assert len(alerts) == 1 and alerts[0].details["detected_after_checkins"] == 4


def test_short_settings_are_checked():
    with pytest.raises(ValueError):
        replace(B.load_config(), short_min=3, short_cutoffs={})
    with pytest.raises(ValueError):
        replace(B.load_config(), short_min=5, short_cutoffs={5: 0.25})        # cut-offs missing for 6 ... 9


def test_greenwood_by_hand():
    assert B.greenwood([10, 10, 10, 10]) == pytest.approx(0.25)
    assert B.greenwood([1, 3]) == pytest.approx(10 / 16)
