"""v4 F7 in the rule engine (engine/detect.py): registry rules also see the registry writes DECLARED on
reg.exe command lines; the alert cites the reg.exe start and says so. Plus a round-trip check against
the real reg.exe registry events SigmaHQ ships as samples for its rules: the reg.exe command line
that would perform each sampled event (built here, with Python's own Windows quoting; the samples
hold no command line) must make the SAME rule fire as the real event. It grounds the field shapes
the samples contain (DWORD, text, no Details; HKLM, the per-user hive, _Classes, (Default)), nothing more."""
import glob
import json
import os
import re
import sqlite3
import subprocess

import pytest

from engine import detect
from engine.store import EventStore
from tests.test_detect import ev, rules_from, store

REG = r"C:\Windows\System32\reg.exe"
RULE = r"""
title: Contoso Switch Turned Off
id: 11111111-2222-3333-4444-555555555555
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|endswith: '\Contoso\App\Protect'
    Details: 'DWORD (0x00000000)'
  condition: sel
level: high
"""
DELETE_RULE = r"""
title: Contoso Key Removed
id: 11111111-2222-3333-4444-666666666666
logsource: {product: windows, category: registry_delete}
detection:
  sel:
    EventType: DeleteKey
    TargetObject|endswith: '\Contoso\App'
  condition: sel
level: medium
"""
PROC_RULE = r"""
title: Reg Add Seen
id: 11111111-2222-3333-4444-777777777777
logsource: {product: windows, category: process_creation}
detection:
  sel:
    CommandLine|contains: 'Contoso'
  condition: sel
level: medium
"""
OFF = r'reg add "HKLM\SOFTWARE\Contoso\App" /v Protect /t REG_DWORD /d 0 /f'


def start(s, command_line, image=REG, guid="{g-1}", **more):
    return ev(1, s, Image=image, CommandLine=command_line, ProcessGuid=guid, User=r"PC\u",
              OriginalFileName=more.pop("original", "reg.exe"), **more)


def run(tmp_path, records, text=RULE, **kw):
    rules = rules_from(tmp_path, text)
    con = detect.open_store(store(tmp_path, records))
    try:
        timings = {}
        alerts = detect.detect(con, rules, timings=timings, **kw)
        assert not timings.get("_errors"), timings["_errors"]
        return alerts
    finally:
        con.close()


def test_a_declared_write_fires_the_registry_rule_and_cites_the_reg_start(tmp_path):
    rec = start(0, OFF)
    (a,) = run(tmp_path, [rec])
    assert a.evidence == (EventStore.dedup_key(rec),) and a.level == "high" and a.host == "h1"
    assert a.details["derived_from"] == "command_line" and a.details["event_id"] == 1
    assert a.details["declared"] == {"event_id": 13, "EventType": "SetValue", "Details": "DWORD (0x00000000)",
                                     "TargetObject": r"HKLM\SOFTWARE\Contoso\App\Protect"}
    assert "declared, not recorded" in a.reason and "may have failed" in a.reason


def test_switched_off_there_is_no_alert(tmp_path):
    assert run(tmp_path, [start(0, OFF)], declared=False) == []


@pytest.mark.parametrize("record", [
    start(0, OFF.replace("/d 0", "/d 1")),                                     # another value
    start(0, OFF.replace("Protect", "Protec")),                                # another name
    start(0, OFF.replace(" add ", " query ").replace(" /t REG_DWORD /d 0 /f", "")),
    start(0, OFF + " /zz"),                                                    # reg.exe would refuse it
    start(0, "cmd.exe /c " + OFF, image=r"C:\Windows\System32\cmd.exe", original="Cmd.Exe"),   # only reg.exe's own start counts
    start(0, OFF, image=r"C:\Users\u\reg.exe", original="other.exe"),          # a program merely called reg.exe
    start(0, OFF, origin="project"),                                           # our own tools
    start(0, OFF, paused=1),
    ev(1, 0, channel="Security", Image=REG, CommandLine=OFF, ProcessGuid="{g-1}", OriginalFileName="reg.exe"),
])
def test_near_misses_do_not_alert(tmp_path, record):
    assert run(tmp_path, [record]) == []


def test_matching_ignores_case_like_sigma(tmp_path):
    (a,) = run(tmp_path, [start(0, r"REG ADD hklm\software\CONTOSO\app /V PROTECT /T reg_dword /D 0x0 /F")])
    assert a.details["derived_from"] == "command_line"


def test_a_renamed_copy_of_reg_exe_counts(tmp_path):
    assert len(run(tmp_path, [start(0, OFF.replace("reg add", "r.exe add"), image=r"C:\Users\u\r.exe")])) == 1


def test_a_recorded_registry_event_of_the_same_process_wins(tmp_path):
    """Sysmon was watching that key: one alert, citing the real event, not a second one for the start."""
    real = ev(13, 1, EventType="SetValue", Image=REG, ProcessGuid="{g-1}",
              TargetObject=r"HKLM\SOFTWARE\Contoso\App\Protect", Details="DWORD (0x00000000)")
    other = start(2, OFF, guid="{g-2}")                                        # another reg.exe run, not recorded
    alerts = run(tmp_path, [start(0, OFF), real, other])
    assert sorted((a.evidence, a.details.get("derived_from")) for a in alerts) == sorted(
        [((EventStore.dedup_key(real),), None), ((EventStore.dedup_key(other),), "command_line")])


def test_two_candidate_spellings_give_one_alert(tmp_path):
    rule = RULE.replace(r"'\Contoso\App\Protect'", r"'\thing\shell\Protect'")
    (a,) = run(tmp_path, [start(0, r"reg add HKCR\thing\shell /v Protect /t REG_DWORD /d 0 /f")], text=rule)
    assert a.details["declared"]["TargetObject"] in (r"HKLM\SOFTWARE\Classes\thing\shell\Protect", r"HKCR\thing\shell\Protect")


def test_reg_delete_fires_a_delete_rule(tmp_path):
    (a,) = run(tmp_path, [start(0, r"reg delete HKLM\SOFTWARE\Contoso\App /f")], text=DELETE_RULE)
    assert a.details["declared"]["EventType"] == "DeleteKey" and a.details["declared"]["Details"] is None
    assert run(tmp_path, [start(0, r"reg delete HKLM\SOFTWARE\Contoso\App /v x /f")], text=DELETE_RULE) == []


def test_process_rules_are_untouched_and_the_normal_view_is_back(tmp_path):
    rules = rules_from(tmp_path, RULE, name="a.yml") + rules_from(tmp_path, PROC_RULE, name="b.yml")
    rec = start(0, OFF)
    con = detect.open_store(store(tmp_path, [rec]))
    try:
        alerts = detect.detect(con, rules)
        assert sorted((a.rule_id[-12:], a.details.get("derived_from"), a.details["event_id"]) for a in alerts) == \
            [("555555555555", "command_line", 1), ("777777777777", None, 1)]
        assert all(a.evidence == (EventStore.dedup_key(rec),) for a in alerts)
        assert con.execute("SELECT event_id FROM logs").fetchall() == [(1,)]      # `logs` is the real view again
        assert con.execute("SELECT COUNT(*) FROM events").fetchone() == (1,)       # nothing was stored
    finally:
        con.close()


def test_new_events_are_picked_up_once_and_after_id_holds(tmp_path):
    """The live loop: the same connection scores again after more events arrived."""
    path = store(tmp_path, [start(0, OFF)])
    rules = rules_from(tmp_path, RULE)
    con = detect.open_store(path)
    try:
        assert len(detect.detect(con, rules)) == 1
        st = EventStore(path)
        st.insert([start(5, OFF, guid="{g-2}"), start(6, OFF.replace("/d 0", "/d 7"), guid="{g-3}")])
        st.close()
        assert len(detect.detect(con, rules)) == 2                                # both, each once
        first = con.execute("SELECT MIN(id) FROM events").fetchone()[0]
        (late,) = detect.detect(con, rules, after_id=first)
        assert "|" in late.evidence[0] and len(detect.detect(con, rules, after_id=10 ** 9)) == 0
        assert con.execute("SELECT COUNT(*) FROM temp.declared_events").fetchone() == (3,)   # no duplicates
    finally:
        con.close()


def test_correlation_rules_never_see_declared_rows(tmp_path):
    text = RULE.replace("level: high", "level: high\nname: contoso_switch") + r"""---
title: Many Contoso Switches
id: 11111111-2222-3333-4444-888888888888
correlation:
  type: event_count
  rules: [contoso_switch]
  generate: true
  group-by: [Image]
  timespan: 1m
  condition: {gte: 2}
level: high
"""
    rules = rules_from(tmp_path, text)
    assert sorted((r.rule_id[-12:], r.correlation, r.registry) for r in rules) == \
        [("555555555555", False, True), ("888888888888", True, False)]           # both loaded; only the simple one is offered
    alerts = run(tmp_path, [start(0, OFF), start(1, OFF, guid="{g-2}"), start(2, OFF, guid="{g-3}")], text=text)
    assert sorted(a.rule_id[-12:] for a in alerts) == ["555555555555"] * 3
    real = [ev(13, i, EventType="SetValue", Image=REG, ProcessGuid=f"{{r-{i}}}",
               TargetObject=r"HKLM\SOFTWARE\Contoso\App\Protect", Details="DWORD (0x00000000)") for i in range(3)]
    assert sorted({a.rule_id[-12:] for a in run(tmp_path, real, text=text)}) == ["555555555555", "888888888888"]   # recorded ones do count


def rule(**sel):
    lines = "\n".join(f"    {k}: {v}" for k, v in sel.items())
    return ("title: T\nid: 11111111-2222-3333-4444-999999999999\nlogsource: {product: windows, category: registry_set}\n"
            f"detection:\n  sel:\n{lines}\n  condition: sel\nlevel: medium\n")


def test_exact_matches_ignore_case_on_declared_rows(tmp_path):
    """Sigma's `=` is case-blind; SQLite's is not unless the declared view collates NOCASE."""
    text = rule(TargetObject=r"'HKLM\SOFTWARE\Contoso\App\Mode'", Details="'ENABLED'")
    assert len(run(tmp_path, [start(0, r"reg add hklm\software\contoso\app /v mode /d enabled /f")], text=text)) == 1
    assert run(tmp_path, [start(0, r"reg add hklm\software\contoso\app /v mode /d enable /f")], text=text) == []


def test_a_number_in_a_rule_matches_declared_text_like_recorded_text(tmp_path):
    text = rule(TargetObject=r"'HKLM\SOFTWARE\Contoso\App\Mode'", Details="1")       # an unquoted number in the rule
    recorded = ev(13, 0, EventType="SetValue", Image=REG, ProcessGuid="{r}", TargetObject=r"HKLM\SOFTWARE\Contoso\App\Mode", Details="1")
    assert len(run(tmp_path, [recorded], text=text)) == 1
    assert len(run(tmp_path, [start(0, r"reg add HKLM\SOFTWARE\Contoso\App /v Mode /d 1 /f")], text=text)) == 1


def test_a_declared_row_has_the_fields_of_a_registry_event_and_no_others(tmp_path):
    s = start(0, OFF, RuleName="proc-rule", ParentImage=r"C:\Windows\System32\cmd.exe")
    target = r"TargetObject|endswith: '\Contoso\App\Protect'"
    fires = lambda **more: len(run(tmp_path, [s], text=rule(**{target.split(": ")[0]: target.split(": ")[1], **more})))
    assert fires() == 1
    assert fires(**{"Image|endswith": r"'\reg.exe'"}) == 1 and fires(**{"Image|endswith": r"'\cmd.exe'"}) == 0
    assert fires(**{"User|endswith": r"'\u'"}) == 1 and fires(**{"User|endswith": r"'\admin'"}) == 0
    assert fires(EventType="SetValue") == 1 and fires(EventType="DeleteValue") == 0
    assert fires(**{"CommandLine|contains": "'Contoso'"}) == 0      # a registry event has no command line
    assert fires(**{"ParentImage|endswith": r"'\cmd.exe'"}) == 0
    assert fires(RuleName="'proc-rule'") == 0                       # the process rule's name is not the registry event's


def test_the_shadow_is_per_computer_and_needs_a_visible_event(tmp_path):
    target = r"HKLM\SOFTWARE\Contoso\App\Protect"
    elsewhere = ev(13, 1, host="h2", EventType="SetValue", Image=REG, ProcessGuid="{g-1}", TargetObject=target + "x", Details="1")
    ours = ev(13, 1, origin="project", EventType="SetValue", Image=REG, ProcessGuid="{g-1}", TargetObject=target + "x", Details="1")
    security = ev(13, 1, channel="Security", EventType="SetValue", Image=REG, ProcessGuid="{g-1}", TargetObject=target + "x", Details="1")
    for other in (elsewhere, ours, security):                       # none of these is "Sysmon recorded this process's write"
        (a,) = run(tmp_path, [start(0, OFF), other])
        assert a.details["derived_from"] == "command_line"
    same = ev(13, 1, EventType="SetValue", Image=REG, ProcessGuid="{g-1}", TargetObject=target + "x", Details="1")
    assert run(tmp_path, [start(0, OFF), same]) == []               # it was recorded (and does not match): nothing declared


def test_a_store_from_before_the_registry_fields_still_works(tmp_path):
    path = store(tmp_path, [start(0, OFF.upper().replace("REG ADD", "reg add").replace("REG_DWORD", "REG_DWORD"))])
    con = sqlite3.connect(path)
    for column in ("EventType", "TargetObject", "Details", "NewName"):
        con.execute(f'ALTER TABLE events DROP COLUMN "{column}"')
    con.commit()
    con.close()
    con = detect.open_store(path)
    try:
        (a,) = detect.detect(con, rules_from(tmp_path, RULE))
        assert a.details["declared"]["TargetObject"].lower() == r"hklm\software\contoso\app\protect"
        exact = rule(TargetObject=r"'hklm\software\contoso\app\protect'", EventType="setvalue")
        assert len(detect.detect(con, rules_from(tmp_path, exact, name="x.yml"))) == 1   # `=` is case-blind there too
    finally:
        con.close()


def test_an_unreadable_command_line_is_skipped_and_reported_once(tmp_path, monkeypatch):
    real = detect.regcmd.declared
    monkeypatch.setattr(detect.regcmd, "declared",
                        lambda line, image=None: (_ for _ in ()).throw(ValueError("boom")) if "POISON" in line else real(line, image))
    path = store(tmp_path, [start(0, OFF + " POISON", guid="{g-0}"), start(1, OFF)])
    rules = rules_from(tmp_path, RULE)
    con = detect.open_store(path)
    try:
        timings = {}
        assert len(detect.detect(con, rules, timings=timings)) == 1              # the good row still alerts
        (who, message), = timings["_errors"]
        assert who == "declared" and "1 command line" in message and "boom" in message
        timings = {}
        assert len(detect.detect(con, rules, timings=timings)) == 1 and "_errors" not in timings   # not again
    finally:
        con.close()


def test_a_huge_number_is_refused_without_stopping_the_pass(tmp_path):
    poison = OFF.replace("/d 0", "/d " + "9" * 5000)
    alerts = run(tmp_path, [start(0, poison, guid="{g-0}"), start(1, OFF)])     # run() asserts no errors
    assert len(alerts) == 1


def test_a_failing_rule_is_reported_once_and_the_real_view_comes_back(tmp_path, monkeypatch):
    bad = detect.Rule("bad", "Bad", "medium", "sigma", "bad.yml", ["SELECT * FROM logs WHERE no_such_column = 1"],
                      categories=("registry_set",))
    con = detect.open_store(store(tmp_path, [start(0, OFF)]))
    try:
        timings = {}
        assert len(detect.detect(con, [bad] + rules_from(tmp_path, RULE), timings=timings)) == 1
        assert [who for who, _ in timings["_errors"]] == ["bad"]
        calls = []

        def interrupted(con_, rule_, untimed=None, declared=False):
            calls.append(declared)
            if declared:
                raise KeyboardInterrupt
            return []
        monkeypatch.setattr(detect, "_simple_alerts", interrupted)
        with pytest.raises(KeyboardInterrupt):
            detect.detect(con, rules_from(tmp_path, RULE))
        assert calls == [False, True]
        assert con.execute("SELECT event_id FROM logs").fetchall() == [(1,)]     # not left on the declared view
    finally:
        con.close()


def test_a_recorded_event_cannot_pose_as_declared(tmp_path):
    """Whether a row is declared is the engine's knowledge, never a field of the row."""
    forged = ev(13, 0, EventType="SetValue", Image=REG, ProcessGuid="{r}", derived_from="command_line",
                TargetObject=r"HKLM\SOFTWARE\Contoso\App\Protect", Details="DWORD (0x00000000)")
    alerts = run(tmp_path, [forged, start(1, OFF, guid="{g-2}")])
    assert sorted((a.details["event_id"], a.details.get("derived_from"), "declared" in a.reason) for a in alerts) == \
        [(1, "command_line", True), (13, None, False)]


def test_the_callers_open_transaction_is_not_committed(tmp_path):
    path = store(tmp_path, [start(0, OFF)])
    con = sqlite3.connect(path)
    try:
        con.execute("UPDATE events SET label = 'pending'")
        assert con.in_transaction
        assert len(detect.detect(con, rules_from(tmp_path, RULE))) == 1
        assert con.in_transaction
        con.rollback()
        assert con.execute("SELECT label FROM events").fetchone() == (None,)
    finally:
        con.close()


def test_a_fresh_connection_reads_only_what_it_is_asked_about(tmp_path):
    """The live loop opens a new connection per tick with after_id: old events are not re-read; a
    later, wider question on the same connection fills the gap, each event once."""
    path = store(tmp_path, [start(i, OFF, guid=f"{{g-{i}}}") for i in range(4)])
    rules = rules_from(tmp_path, RULE)
    con = detect.open_store(path)
    try:
        ids = [i for (i,) in con.execute("SELECT id FROM events ORDER BY id")]
        assert len(detect.detect(con, rules, after_id=ids[1])) == 2
        assert con.execute("SELECT COUNT(*) FROM temp.declared_events").fetchone() == (2,)
        assert len(detect.detect(con, rules)) == 4
        assert len(detect.detect(con, rules, after_id=ids[0])) == 3
        assert con.execute("SELECT COUNT(*), COUNT(DISTINCT id) FROM temp.declared_events").fetchone() == (4, 4)
    finally:
        con.close()


def test_a_hand_made_store_without_the_columns_is_left_alone(tmp_path):
    path = str(tmp_path / "bare.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, dedup_key TEXT, host TEXT, channel TEXT, time TEXT, "
                "event_id INTEGER, origin TEXT, paused INTEGER, UtcTime TEXT)")
    con.commit()
    assert detect.prepare_declared(con) == 0
    detect.prepare(con)
    timings = {}
    assert detect.detect(con, rules_from(tmp_path, RULE), timings=timings) == [] and not timings.get("_errors")
    con.close()


def test_rules_know_their_category(tmp_path):
    (r,) = rules_from(tmp_path, RULE, name="a.yml")
    (p,) = rules_from(tmp_path, PROC_RULE, name="b.yml")
    assert r.categories == ("registry_set",) and r.registry and p.categories == ("process_creation",) and not p.registry


# -- the oracle: SigmaHQ's own samples of real reg.exe registry events -----------------------------------
SAMPLES = os.path.join(detect.PROJECT_ROOT, "downloads", "sigma", "regression_data", "rules", "windows", "registry")
_SID = re.compile(r"^HKU\\S-1-5-21-[\d-]+")


def _docs(path):
    text, i, dec, out = open(path, encoding="utf-8-sig").read().strip(), 0, json.JSONDecoder(), []
    while i < len(text):
        doc, i = dec.raw_decode(text, i)
        out.append(doc)
        while i < len(text) and text[i].isspace():
            i += 1
    return out


def _command(data):
    """The reg.exe command line that performs the sampled event (written with Python's own Windows
    quoting, subprocess.list2cmdline), or None for a shape reg.exe cannot be told to write."""
    target, details, kind = data["TargetObject"], data.get("Details"), data.get("EventType")
    if _SID.match(target):
        rest = _SID.sub("", target)
        target = "HKCU\\Software\\Classes" + rest[len("_Classes"):] if rest.startswith("_Classes") else "HKCU" + rest
    if kind == "DeleteKey":
        return subprocess.list2cmdline(["reg", "delete", target, "/f"])
    key, _, name = target.rpartition("\\")
    value = ["/ve"] if name == "(Default)" else ["/v", name]
    if kind == "DeleteValue":
        return subprocess.list2cmdline(["reg", "delete", key, *value, "/f"])
    if kind != "SetValue" or details is None:
        return None
    m = re.fullmatch(r"DWORD \((0x[0-9a-fA-F]{8})\)", details)
    if m:
        data_args = ["/t", "REG_DWORD", "/d", m.group(1)]
    elif details == "Binary Data":
        data_args = ["/t", "REG_BINARY", "/d", "00"]
    elif details == "(Empty)":
        data_args = ["/t", "REG_SZ", "/d", ""]
    else:
        data_args = ["/t", "REG_SZ", "/d", details]
    return subprocess.list2cmdline(["reg", "add", key, *value, *data_args, "/f"])


def _reg_samples():
    out = []
    for path in sorted(glob.glob(os.path.join(SAMPLES, "**", "*.json"), recursive=True)):
        rule_id = os.path.splitext(os.path.basename(path))[0]
        for doc in _docs(path):
            data = (doc.get("Event") or {}).get("EventData") or {}
            if str(data.get("Image", "")).lower().endswith("\\reg.exe") and data.get("TargetObject"):
                out.append(pytest.param(rule_id, data, id=f"{rule_id[:8]}-{data.get('EventType')}"))
    return out


_RULE_FILES = {}


def _rule_file(rule_id):
    if not _RULE_FILES:
        for path in glob.glob(os.path.join(detect.COMMUNITY_RULES, "registry", "**", "*.yml"), recursive=True):
            m = re.search(r"(?m)^id:\s*([0-9a-fA-F-]{36})", open(path, encoding="utf-8").read())
            if m:
                _RULE_FILES[m.group(1).lower()] = path
    return _RULE_FILES.get(rule_id.lower())


@pytest.mark.parametrize("rule_id, data", _reg_samples() or [pytest.param(None, None, marks=pytest.mark.skip("no SigmaHQ samples"))])
def test_the_equivalent_command_line_fires_the_same_sigmahq_rule_as_the_real_event(tmp_path, rule_id, data):
    path = _rule_file(rule_id)
    assert path, f"rule {rule_id} not in the pinned checkout"
    rules, _, failures = detect.load_rules([path], "sigma", filters=[])
    assert not failures and rules
    real = ev(13 if data["EventType"] == "SetValue" else 12, 0, ProcessGuid="{real}",
              **{k: data[k] for k in ("EventType", "Image", "TargetObject", "Details", "User") if data.get(k) is not None})
    con = detect.open_store(store(tmp_path, [real]))
    try:
        on_real = [a for a in detect.detect(con, rules, declared=False) if a.rule_id == rule_id]
    finally:
        con.close()
    if not on_real:
        pytest.skip("the sample alone does not fire its rule in our engine")
    command = _command(data)
    assert command, data
    rec = ev(1, 0, Image=data["Image"], CommandLine=command, ProcessGuid="{cmd}", OriginalFileName="reg.exe",
             User=data.get("User"))
    con = detect.open_store(store(tmp_path, [rec]))
    try:
        got = [a for a in detect.detect(con, rules) if a.rule_id == rule_id]
    finally:
        con.close()
    assert len(got) == 1 and got[0].details["derived_from"] == "command_line", command
    assert got[0].evidence == (EventStore.dedup_key(rec),)
