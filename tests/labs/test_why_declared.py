"""The Why lab on DECLARED alerts (v4 F7/F8: a registry write or PowerShell code read from a typed command,
never recorded): run by the real engine, explained against the declared row, and said to be declared."""

import base64

from engine import detect
from engine.alerts import Alert
from engine.labs import why
from engine.store import EventStore
from tests.labs.test_why import FakeCtx
from tests.test_detect import ev, store

REG_RULE = r"""
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
PS_RULE = r"""
title: Contoso Fetch In Script
id: 11111111-2222-3333-4444-888888888888
logsource: {product: windows, category: ps_script}
detection:
  sel:
    ScriptBlockText|contains|all: ['Contoso.Fetch', 'Invoke-Thing']
  condition: sel
level: high
"""
REG = r"C:\Windows\System32\reg.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def engine_alerts(tmp_path, rule_text, records, name):
    d = tmp_path / f"rules_{name}"
    d.mkdir()
    (d / f"{name}.yml").write_text(rule_text, encoding="utf-8")
    rules, _, failures = detect.load_rules([str(d)], "sigma", filters=[])
    assert not failures
    path = store(tmp_path, records)
    con = detect.open_store(path)
    alerts = detect.detect(con, rules, declared=True)
    con.close()
    return path, str(d), alerts


def test_declared_registry_write_is_explained_against_the_declared_row(tmp_path):
    rec = ev(1, 0, Image=REG, CommandLine=r'reg add "HKLM\SOFTWARE\Contoso\App" /v Protect /t REG_DWORD /d 0 /f',
             ProcessGuid="{g-1}", User=r"PC\u", OriginalFileName="reg.exe")
    db, rules_dir, alerts = engine_alerts(tmp_path, REG_RULE, [rec], "reg")
    (a,) = alerts
    assert a.details["derived_from"] == "command_line"
    out = why.explain(FakeCtx(db), a, folders=[rules_dir])
    assert out["alert"]["declared"] and out["check"] == "reproduced"
    e = out["events"][0]
    assert e["kind"] == "declared" and set(e["matched_fields"]) == {"TargetObject", "Details"}
    f = dict(e["fields"])
    assert f["TargetObject"].endswith(r"\Contoso\App\Protect") and "CommandLine" not in f     # the declared row, not the reg.exe start
    assert [f["TargetObject"][s:t] for s, t in e["highlights"]["TargetObject"]] == [r"\Contoso\App\Protect"]


def test_declared_powershell_code_is_explained_and_a_truncated_miss_is_not_checked(tmp_path):
    code = "Contoso.Fetch -Uri x; Invoke-Thing"
    line = f"powershell.exe -NoProfile -EncodedCommand {base64.b64encode(code.encode('utf-16-le')).decode()}"
    rec = ev(1, 0, Image=PS, CommandLine=line, ProcessGuid="{p-1}", User=r"PC\u", OriginalFileName="PowerShell.EXE")
    db, rules_dir, alerts = engine_alerts(tmp_path, PS_RULE, [rec], "ps")
    (a,) = alerts
    out = why.explain(FakeCtx(db), a, folders=[rules_dir])
    assert out["check"] == "reproduced" and out["events"][0]["kind"] == "declared"
    assert out["events"][0]["highlights"]["ScriptBlockText"]
    # the alert keeps only the start of long code: when the kept part lacks a needed word, say "not checked", not red
    cut = dict(a.details, declared={"event_id": 4104, "ScriptBlockText": "Contoso.Fetch -Uri x; ", "length": 5000})
    short = Alert(a.rule_id, a.title, a.source, a.level, a.time, a.host, a.reason, a.evidence, cut)
    out2 = why.explain(FakeCtx(db), short, folders=[rules_dir])
    assert out2["check"] == "not_checked" and out2["events"][0]["matched"] is None
