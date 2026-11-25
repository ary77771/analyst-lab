"""v4 F6: our Sigma filter documents (rules/filters/) on SigmaHQ's ASEP rules: Windows' own default
MIDI driver writes are quiet, every near miss still alerts, and without the filter they all fire."""
import os

import pytest

from engine import detect
from engine.store import EventStore
from tests.test_detect import ev, store

ASEP = [os.path.join(detect.COMMUNITY_RULES, "registry", "registry_set", n) for n in
        ("registry_set_asep_reg_keys_modification_currentversion_nt.yml",
         "registry_set_asep_reg_keys_modification_wow6432node_currentversion.yml")]
SVCHOST = r"C:\Windows\System32\svchost.exe"
NT = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32"
WOW = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32"


def reg(s, key, value, data, image=SVCHOST):
    return ev(13, s, EventType="SetValue", Image=image, TargetObject=f"{key}\\{value}", Details=data)


def fired(tmp_path, records, filters=None):
    if not all(os.path.exists(p) for p in ASEP):
        pytest.skip("SigmaHQ checkout not present")
    rules, _, failures = detect.load_rules(ASEP, "sigma", filters=filters)
    assert not failures and len(rules) == 2
    con = detect.open_store(store(tmp_path, records))
    try:
        hits = detect.detect(con, rules)
    finally:
        con.close()
    by_key = {EventStore.dedup_key(r): r for r in records}
    return sorted({(by_key[k]["data"]["TargetObject"].rsplit("\\", 1)[-1], by_key[k]["data"]["Details"],
                    by_key[k]["data"]["Image"].rsplit("\\", 1)[-1]) for a in hits for k in a.evidence})


DEFAULTS = [reg(0, NT, "midi", "wdmaud.drv"), reg(1, NT, "midi1", "wdmaud2.drv"),
            reg(2, WOW, "midi", "wdmaud.drv"), reg(3, WOW, "midi1", "wdmaud2.drv")]
NEAR = [reg(4, NT, "midi", "evil.dll"),                                   # a hijacked driver
        reg(5, NT, "midi1", "wdmaud.drv"),                                # values swapped
        reg(6, NT, "midi2", "wdmaud.drv"),                                # another value name
        reg(7, WOW, "midi", "wdmaud.drv", image=r"C:\Users\u\AppData\Local\Temp\svchost.exe"),   # not System32's
        reg(8, NT, "msacm.evil", "wdmaud.drv"),
        reg(9, WOW, "midi", "wdmaud2.drv")]                               # the other default driver, wrong value


def test_windows_default_midi_writes_are_filtered_near_misses_alert(tmp_path):
    got = fired(tmp_path, DEFAULTS + NEAR)
    assert got == sorted({("midi", "evil.dll", "svchost.exe"), ("midi1", "wdmaud.drv", "svchost.exe"),
                          ("midi2", "wdmaud.drv", "svchost.exe"), ("midi", "wdmaud.drv", "svchost.exe"),
                          ("msacm.evil", "wdmaud.drv", "svchost.exe"), ("midi", "wdmaud2.drv", "svchost.exe")})
    assert ("midi1", "wdmaud2.drv", "svchost.exe") not in got     # the defaults never appear


def test_without_the_filter_the_defaults_fire(tmp_path):
    got = fired(tmp_path, DEFAULTS, filters=[])
    assert {(v, d) for v, d, _ in got} == {("midi", "wdmaud.drv"), ("midi1", "wdmaud2.drv")}


def test_a_filter_naming_a_missing_rule_is_reported(tmp_path):
    (tmp_path / "f.yml").write_text(open(os.path.join(detect.FILTER_RULES, os.listdir(detect.FILTER_RULES)[0]),
                                         encoding="utf-8").read().replace("cbf93e5d-ca6c-4722-8bea-e9119007c248",
                                                                          "00000000-0000-0000-0000-00000000dead"),
                                    encoding="utf-8")
    filters = detect.load_filters(str(tmp_path))
    assert detect._unmatched_filters(filters, {"480421f9-417f-4d3b-9552-fd2728443ec8"}) == \
        [(filters[0].title, ["00000000-0000-0000-0000-00000000dead"])]
    assert detect._unmatched_filters(detect.load_filters(), {"cbf93e5d-ca6c-4722-8bea-e9119007c248",
                                                             "480421f9-417f-4d3b-9552-fd2728443ec8"}) == []


@pytest.mark.parametrize("text", ["title: not a filter\nlogsource: {product: windows}\ndetection: {s: {a: b}, condition: s}\n",
                                  "filter: [this is: not valid"])
def test_a_broken_filter_file_fails_loudly(tmp_path, text):
    (tmp_path / "bad.yml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="bad.yml"):
        detect.load_filters(str(tmp_path))


def test_an_empty_details_value_still_alerts(tmp_path):
    got = fired(tmp_path, [reg(0, NT, "midi", "")])
    assert [(v, i) for v, _, i in got] == [("midi", "svchost.exe")]
