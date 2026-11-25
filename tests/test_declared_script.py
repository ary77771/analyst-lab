"""v4 F8 in the rule engine (engine/detect.py): PowerShell script rules (Sigma ps_script, event 4104)
run ONLY over the code DECLARED on powershell.exe command lines; the alert cites the powershell.exe
start and says so. Plus a round trip with the real script block events SigmaHQ ships as samples for
its rules: the command line that would run each sampled script block (built here: -EncodedCommand
and -Command forms; the samples hold no command line) must make the SAME rule fire. It grounds that
the declared row has the field the rules read, nothing more."""
import base64
import glob
import json
import os
import subprocess

import pytest
import yaml

from engine import detect
from engine.store import EventStore
from tests.test_detect import ev, rules_from, store

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RULE = r"""
title: Contoso Download Cradle
id: 22222222-2222-3333-4444-555555555555
logsource: {product: windows, category: ps_script}
detection:
  sel:
    ScriptBlockText|contains|all: ['Contoso.Fetch', 'Invoke-Thing']
  condition: sel
level: high
"""
PATH_RULE = r"""
title: Contoso Web Request
id: 22222222-2222-3333-4444-666666666666
logsource: {product: windows, category: ps_script}
detection:
  sel:
    ScriptBlockText|contains: 'Contoso.Fetch'
  filter:
    Path|startswith: 'C:\Packages\'
  condition: sel and not filter
level: medium
"""
REG_RULE = r"""
title: Contoso Switch Turned Off
id: 22222222-2222-3333-4444-777777777777
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|endswith: '\Contoso\App\Protect'
  condition: sel
level: high
"""
CODE = "Contoso.Fetch; Invoke-Thing -Now"
LINE = f'"{PS}" -NoProfile -Command {CODE}'


def start(s, command_line, image=PS, guid="{p-1}", **more):
    return ev(1, s, Image=image, CommandLine=command_line, ProcessGuid=guid, User=r"PC\u",
              OriginalFileName=more.pop("original", "PowerShell.EXE"), **more)


def enc(code):
    return base64.b64encode(code.encode("utf-16-le")).decode()


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


def test_declared_code_fires_the_script_rule_and_cites_the_powershell_start(tmp_path):
    rec = start(0, LINE)
    (a,) = run(tmp_path, [rec])
    assert a.evidence == (EventStore.dedup_key(rec),) and a.level == "high" and a.host == "h1"
    assert a.details["derived_from"] == "command_line" and a.details["event_id"] == 1
    assert a.details["declared"] == {"event_id": 4104, "ScriptBlockText": CODE, "length": len(CODE)}
    assert "PowerShell code" in a.reason and "declared, not recorded" in a.reason and "may not have run" in a.reason


def test_encoded_code_is_decoded(tmp_path):
    (a,) = run(tmp_path, [start(0, f'"{PS}" -nop -w hidden -enc {enc(CODE)}')])
    assert a.details["declared"]["ScriptBlockText"] == CODE


def test_the_harness_form_fires(tmp_path):
    """ART's executor: `"powershell.exe" & {<code>}` (a bare first word starts the code)."""
    (a,) = run(tmp_path, [start(0, '"powershell.exe" & {' + CODE + "}")])
    assert a.details["declared"]["ScriptBlockText"] == "& {" + CODE + "}"


@pytest.mark.parametrize("declared, fires", [(None, True), (True, True), (False, False), ({"script"}, True),
                                             ({"registry"}, False), (frozenset(), False)])
def test_the_switch(tmp_path, declared, fires):
    assert len(run(tmp_path, [start(0, LINE)], declared=declared)) == (1 if fires else 0)


def test_an_unknown_kind_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown declared"):
        run(tmp_path, [start(0, LINE)], declared={"scripts"})


def test_the_config_switch_is_read(tmp_path, monkeypatch):
    from engine import config
    monkeypatch.setattr(config, "declared_kinds", lambda *a: frozenset({"registry"}))
    assert run(tmp_path, [start(0, LINE)]) == []


@pytest.mark.parametrize("text, expected", [
    ("declared_registry: {reg_command: true}\ndeclared_script: {powershell_command: true}\n", {"registry", "script"}),
    ("declared_registry: {reg_command: false}\ndeclared_script: {powershell_command: true}\n", {"script"}),
    ("declared_registry: {reg_command: true}\ndeclared_script: {powershell_command: false}\n", {"registry"}),
])
def test_config_kinds(tmp_path, text, expected):
    from engine import config
    p = tmp_path / "f.yaml"
    p.write_text(text, encoding="utf-8")
    assert config.declared_kinds(str(p)) == expected


@pytest.mark.parametrize("value", ["", "{powershell_command: yes-ish}", "{powershell_command: 1}", "{}"])
def test_config_must_choose(tmp_path, value):
    from engine import config
    p = tmp_path / "f.yaml"
    p.write_text(f"declared_registry: {{reg_command: true}}\ndeclared_script: {value}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="powershell_command must be true or false"):
        config.declared_script(str(p))


def test_the_frozen_config_switches_f8_on():
    from engine import config
    assert config.declared_script() is True and config.declared_kinds() == {"registry", "script"}


def test_script_rules_never_run_over_the_store(tmp_path):
    """The store has no ScriptBlockText column; running a ps_script rule there would be an SQL error.
    With nothing declared there is neither an error (run() asserts none) nor an alert."""
    assert run(tmp_path, [start(0, f'"{PS}" -File x.ps1'), ev(4104, 1, ScriptBlockText=CODE)]) == []


def test_an_inline_command_has_an_empty_path_so_not_filter_works(tmp_path):
    """Real 4104 events of -Command code carry Path = '' (not NULL): `sel and not filter` must fire."""
    assert len(run(tmp_path, [start(0, LINE)], text=PATH_RULE)) == 1


@pytest.mark.parametrize("record", [
    start(0, LINE.replace("Invoke-Thing", "Invoke-Thin")),                                  # the rule needs both
    start(0, f'"{PS}" -NoProfile -File {CODE}'),                                             # a script file
    start(0, f'"{PS}" -NoProfile -Command -'),                                               # standard input
    start(0, f'"{PS}" -psconsolefile x {CODE}'),                                             # 5.1's own parameter we do not read
    start(0, LINE, image=r"C:\Program Files\PowerShell\7\pwsh.exe", original="pwsh.dll"),    # PowerShell 7
    start(0, "cmd.exe /c " + LINE, image=r"C:\Windows\System32\cmd.exe", original="Cmd.Exe"),  # only PS's own start
    start(0, LINE, image=r"C:\Users\u\powershell.exe", original="other.exe"),               # merely called so
    start(0, LINE, origin="project"),                                                        # our own tools
    start(0, LINE, paused=1),
    ev(1, 0, channel="Security", Image=PS, CommandLine=LINE, ProcessGuid="{p-1}", OriginalFileName="PowerShell.EXE"),
])
def test_near_misses_do_not_alert(tmp_path, record):
    assert run(tmp_path, [record]) == []


def test_matching_ignores_case_like_sigma(tmp_path):
    (a,) = run(tmp_path, [start(0, f'"{PS}" -NOP -C contoso.fetch; INVOKE-THING')])
    assert a.details["declared"]["ScriptBlockText"] == "contoso.fetch; INVOKE-THING"


def test_a_renamed_copy_counts(tmp_path):
    assert len(run(tmp_path, [start(0, LINE.replace("powershell.exe", "p.exe"), image=r"C:\Users\u\p.exe")])) == 1


def test_one_alert_per_start_per_rule(tmp_path):
    alerts = run(tmp_path, [start(0, LINE, guid="{p-1}"), start(1, LINE, guid="{p-2}")])
    assert len(alerts) == 2 and len({a.evidence for a in alerts}) == 2


def test_a_recorded_registry_event_does_not_hide_the_script(tmp_path):
    """F7's shadow (a recorded registry event wins over a declared one) is for registry rows only."""
    real = ev(13, 1, EventType="SetValue", Image=PS, ProcessGuid="{p-1}",
              TargetObject=r"HKLM\SOFTWARE\Contoso\App\Protect", Details="DWORD (0x00000000)")
    assert len(run(tmp_path, [start(0, LINE), real])) == 1


def test_registry_and_script_rows_do_not_cross(tmp_path):
    """A registry rule never matches a script row and the other way round (event ids differ)."""
    reg_like = start(0, f'"{PS}" -c HKLM\\SOFTWARE\\Contoso\\App\\Protect')
    assert run(tmp_path, [reg_like], text=REG_RULE) == []
    reg = ev(1, 1, Image=r"C:\Windows\System32\reg.exe", OriginalFileName="reg.exe", ProcessGuid="{r-1}",
             CommandLine=r"reg add HKLM\SOFTWARE\Contoso.Fetch /v Invoke-Thing /d x /f")
    assert run(tmp_path, [reg]) == []


def test_both_kinds_in_one_store(tmp_path):
    reg = ev(1, 1, Image=r"C:\Windows\System32\reg.exe", OriginalFileName="reg.exe", ProcessGuid="{r-1}",
             CommandLine=r"reg add HKLM\SOFTWARE\Contoso\App /v Protect /t REG_DWORD /d 0 /f")
    rules = rules_from(tmp_path, RULE, name="a.yml") + rules_from(tmp_path, REG_RULE, name="b.yml")
    con = detect.open_store(store(tmp_path, [start(0, LINE), reg]))
    try:
        got = sorted((a.title, a.details["declared"]["event_id"]) for a in detect.detect(con, rules))
    finally:
        con.close()
    assert got == [("Contoso Download Cradle", 4104), ("Contoso Switch Turned Off", 13)]


def test_the_shown_text_is_capped_but_its_length_kept(tmp_path):
    long_code = CODE + "; " + "x" * 5000
    (a,) = run(tmp_path, [start(0, f'"{PS}" -c {long_code}')])
    shown = a.details["declared"]
    assert len(shown["ScriptBlockText"]) == detect.DECLARED_TEXT_SHOWN and shown["length"] == len(long_code)


def test_a_correlation_over_script_rules_is_refused(tmp_path):
    corr = RULE + r"""---
title: Many Cradles
correlation:
  type: event_count
  rules: [22222222-2222-3333-4444-555555555555]
  group-by: [Computer]
  timespan: 1m
  condition: {gte: 2}
level: high
"""
    d = tmp_path / "corr"
    d.mkdir()
    (d / "c.yml").write_text(corr, encoding="utf-8")
    rules, _, failures = detect.load_rules([str(d)])
    assert any("declared rows are never correlated" in msg for _, msg in failures)
    assert rules == []                     # its base rule is only part of the correlation (as for any rule)
    (alone,) = rules_from(tmp_path, RULE, name="alone.yml")
    assert alone.declared_only and alone.script and not alone.registry and alone.categories == ("ps_script",)


def test_the_live_loop_path_and_repeated_calls(tmp_path):
    """after_id (the live loop opens a fresh connection per tick and looks only after the last row) and a
    second detect() on the same connection: no lost and no duplicate declared script rows."""
    path = store(tmp_path, [start(0, LINE, guid="{p-1}"), start(1, LINE, guid="{p-2}")])
    rules = rules_from(tmp_path, RULE)
    con = detect.open_store(path)
    try:
        first_id = con.execute("SELECT MIN(id) FROM events").fetchone()[0]
        assert len(detect.detect(con, rules, after_id=first_id)) == 1         # only the row after it
        assert len(detect.detect(con, rules)) == 2                            # the gap below is filled
        assert len(detect.detect(con, rules)) == 2                            # and nothing doubles
        assert con.execute("SELECT COUNT(*) FROM temp.declared_events WHERE event_id = 4104").fetchone()[0] == 2
    finally:
        con.close()


def test_printed_alerts_say_declared(tmp_path):
    from engine.alerts import declared_note
    (a,) = run(tmp_path, [start(0, LINE)])
    assert declared_note(a) == " (declared on a command line, not recorded)"
    import dataclasses
    assert declared_note(dataclasses.replace(a, details={})) == "" and declared_note(dataclasses.replace(a, details=None)) == ""


def test_rule_kinds():
    from engine.detect import Rule
    assert Rule("a", "t", "high", "sigma", "p", [], categories=("ps_script",)).declared_only
    assert not Rule("a", "t", "high", "sigma", "p", [], categories=("process_creation",)).declared_only
    assert not Rule("a", "t", "high", "sigma", "p", [], correlation=True, categories=("ps_script",)).script


def test_an_unreadable_powershell_line_is_skipped_and_reported_once(tmp_path, monkeypatch):
    real = detect.pscmd.script_text
    monkeypatch.setattr(detect.pscmd, "script_text",
                        lambda line: (_ for _ in ()).throw(ValueError("boom")) if "POISON" in line else real(line))
    path = store(tmp_path, [start(0, LINE + " POISON", guid="{p-0}"), start(1, LINE)])
    rules = rules_from(tmp_path, RULE)
    con = detect.open_store(path)
    try:
        timings = {}
        assert len(detect.detect(con, rules, timings=timings)) == 1
        (who, message), = timings["_errors"]
        assert who == "declared" and "1 command line" in message and "boom" in message
    finally:
        con.close()


# -- round trip with SigmaHQ's real 4104 samples --------------------------------------------------------
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "downloads", "sigma",
                       "regression_data", "rules", "windows", "powershell", "powershell_script")
RULES_DIR = os.path.join(detect.COMMUNITY_RULES, "powershell", "powershell_script")


def _samples():
    out = []
    for info in sorted(glob.glob(os.path.join(SAMPLES, "*", "info.yml"))):
        with open(info, encoding="utf-8") as f:
            meta = yaml.safe_load(f)
        rid = meta["rule_metadata"][0]["id"]
        for js in sorted(glob.glob(os.path.join(os.path.dirname(info), "*.json"))):
            dec, text = json.JSONDecoder(), open(js, encoding="utf-8").read()
            i = 0
            while i < len(text):
                while i < len(text) and text[i].isspace():
                    i += 1
                if i >= len(text):
                    break
                obj, i = dec.raw_decode(text, i)
                e = obj.get("Event", {})
                data = e.get("EventData", {})
                if e.get("System", {}).get("EventID") == 4104 and data.get("ScriptBlockText"):
                    out.append((rid, os.path.basename(os.path.dirname(info)), data["ScriptBlockText"], data.get("Path") or ""))
    return out


SAMPLE_LIST = _samples() if os.path.isdir(SAMPLES) else []


@pytest.fixture(scope="module")
def script_rules():
    if not os.path.isdir(RULES_DIR):
        pytest.skip("SigmaHQ rules not downloaded")
    rules, _, failures = detect.load_rules([RULES_DIR])
    assert not failures, failures[:3]
    return {r.rule_id: r for r in rules}


@pytest.mark.skipif(not SAMPLE_LIST, reason="SigmaHQ regression data not downloaded")
def test_the_samples_are_there():
    assert len({s[1] for s in SAMPLE_LIST}) >= 60      # 65 sample folders at the pinned commit


@pytest.mark.parametrize("form", ["encoded", "command"])
@pytest.mark.parametrize("sample", SAMPLE_LIST, ids=lambda s: s[1] if isinstance(s, tuple) else str(s))
def test_round_trip_with_sigmahq_samples(tmp_path, script_rules, sample, form):
    rid, folder, code, path = sample
    rule = script_rules.get(rid)
    if rule is None:
        pytest.skip(f"rule {rid} not in the pinned set")
    if path:
        pytest.skip("sample is a script FILE's block (Path set): a command line cannot reproduce its Path")
    if form == "encoded":
        line = f'"{PS}" -NoProfile -EncodedCommand {enc(code)}'
    else:                          # Python's own Windows quoting (C runtime rules): one argument = the code
        line = subprocess.list2cmdline([PS, "-NoProfile", "-Command", code])
    if len(line) > 32767:
        pytest.skip("longer than a Windows command line")
    con = detect.open_store(store(tmp_path, [start(0, line)]))
    try:
        timings = {}
        alerts = detect.detect(con, [rule], timings=timings)
        assert not timings.get("_errors"), timings["_errors"]
    finally:
        con.close()
    assert [a.rule_id for a in alerts] == [rid], f"{folder}: the sampled code did not fire its own rule"
    assert alerts[0].details["derived_from"] == "command_line"
