"""tools/v3_budget.py: the v3 rules' pass/fail budgets on a hand-made store."""
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import v3_budget as V  # noqa: E402
from engine.alerts import Alert  # noqa: E402
from tests.test_detect import ev, rules_from, store  # noqa: E402

DROP = r"C:\AnalystLab\work\cache\WinSvcHost.exe"


def busy_hours(n):
    """Events every 60 s for n hours (awake time)."""
    return [ev(5, 60.0 * i, ProcessGuid="{K}", Image=r"C:\Windows\System32\svchost.exe") for i in range(int(n * 60))]


def test_a_quiet_week_passes():
    import tempfile
    con = sqlite3.connect(store(__import__("pathlib").Path(tempfile.mkdtemp()), busy_hours(2)))
    doc = V.budget(con, connectors={}, alerts=[])
    assert 1.9 < doc["awake_hours"] < 2.1
    assert all(r["alerts"] == 0 and r["pass"] for r in doc["rules"].values())
    assert doc["short"]["extra"] == 0 and doc["short"]["pass"]
    assert doc["declared"]["alerts"] == 0 and doc["declared"]["pass"]
    assert "PASS" in V.markdown(doc) and "FAIL" not in V.markdown(doc)


def test_too_many_new_rule_alerts_fail(tmp_path):
    recs = busy_hours(2) + [ev(1, 30 + i, Image=rf"C:\Users\u\x{i}\winsvchost.exe", ProcessGuid=f"{{X{i}}}") for i in range(3)]
    doc = V.budget(sqlite3.connect(store(tmp_path, recs)), connectors={}, alerts=[])
    r = doc["rules"]["analystlab.embedded_system_name"]
    assert r["alerts"] == 3 and abs(r["per_hour"] - 1.5) < 0.1 and r["pass"] is False      # 1.5 per hour > 0.1
    assert "| analystlab.embedded_system_name | 3 |" in V.markdown(doc) and "FAIL" in V.markdown(doc)


def test_extra_short_gate_series_fail_when_rita_has_none(tmp_path):
    recs = busy_hours(1) + [ev(11, 50, ProcessGuid="{W}", TargetFilename=DROP)] + \
        [ev(3, 100 + 10 * i, ProcessGuid="{D}", Image=DROP, Initiated="true", DestinationIp="10.0.2.2", DestinationPort=18765)
         for i in range(6)]
    s = V.budget(sqlite3.connect(store(tmp_path, recs)), connectors={}, alerts=[])["short"]
    assert s["rita_series"] == 0 and s["extra"] == 1 and s["share"] is None and s["pass"] is False


def test_it_refuses_without_official_mode(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ANALYSTLAB_OFFICIAL", raising=False)
    assert V.main(["--label", "official", "--recordings", str(tmp_path)]) == 2
    assert "Refusing" in capsys.readouterr().out


# -- v4 pre-registration 3c: the declared-alert brake ------------------------------------------------

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RULE = r"""
title: Contoso Download Cradle
id: 22222222-2222-3333-4444-888888888888
logsource: {product: windows, category: ps_script}
detection:
  sel:
    ScriptBlockText|contains|all: ['Contoso.Fetch', 'Invoke-Thing']
  condition: sel
level: high
"""


def declared(i, level="high", kind=4104):
    return Alert(f"r{i}", "t", "sigma", level, "2026-11-01T00:00:00Z", "h1", "x", (f"k{i}",),
                 {"event_id": 1, "derived_from": "command_line", "declared": {"event_id": kind}})


def recorded(i, level="high"):
    return Alert(f"q{i}", "t", "sigma", level, "2026-11-01T00:00:00Z", "h1", "x", (f"j{i}",), {"event_id": 1})


def test_declared_alerts_are_counted_together_and_split(tmp_path):
    con = sqlite3.connect(store(tmp_path, busy_hours(10)))
    alerts = [declared(0), declared(1, kind=12), recorded(2)]
    doc = V.budget(con, connectors={}, alerts=alerts)
    d = doc["declared"]
    assert d["alerts"] == 2 and d["script"] == 1 and d["registry"] == 1
    assert abs(d["per_hour"] - 0.2) < 0.02 and d["pass"] is False          # 0.2 per awake hour > 0.1
    tail = V.markdown(doc).split("Declared alerts")[1]
    assert "F7 registry 1 + F8 PowerShell 1" in tail and "**FAIL**" in tail


def test_one_declared_alert_in_eleven_hours_passes(tmp_path):
    d = V.budget(sqlite3.connect(store(tmp_path, busy_hours(11))), connectors={}, alerts=[declared(0)])["declared"]
    assert d["alerts"] == 1 and d["pass"] is True                           # ~0.09 per awake hour: within budget


def test_declared_alerts_below_the_floor_do_not_count(tmp_path):
    d = V.budget(sqlite3.connect(store(tmp_path, busy_hours(2))), connectors={},
                 alerts=[declared(i, level="low") for i in range(5)])["declared"]
    assert d["alerts"] == 0 and d["pass"] is True


def test_no_awake_time_cannot_pass():
    assert V.declared_budget([declared(0)], 0)["pass"] is False


def test_it_refuses_without_alerts_while_a_declared_feature_is_on(tmp_path):
    con = sqlite3.connect(store(tmp_path, busy_hours(1)))
    with pytest.raises(ValueError, match="declared features on"):
        V.budget(con, connectors={}, kinds=frozenset({"script"}))
    assert "declared" not in V.budget(con, connectors={}, kinds=frozenset())      # all off: nothing to count


def test_the_frozen_config_needs_the_alerts(tmp_path):
    con = sqlite3.connect(store(tmp_path, busy_hours(1)))
    with pytest.raises(ValueError, match="declared features on"):
        V.budget(con, connectors={})                                             # F7/F8 are on in frozen.yaml


def test_score_store_finds_a_declared_alert_end_to_end(tmp_path):
    """The real path main() uses: engine.score over a store with one powershell.exe start whose command
    line declares code a ps_script rule matches (a made-up rule, so no real attack text is needed)."""
    rec = ev(1, 3600, Image=PS, CommandLine=f'"{PS}" -NoProfile -Command Contoso.Fetch; Invoke-Thing -Now',
             ProcessGuid="{p-1}", User=r"PC\u", OriginalFileName="PowerShell.EXE")
    path = store(tmp_path, busy_hours(2) + [rec])
    rules = rules_from(tmp_path, RULE)

    class Lab:
        def rules(self):
            return rules

        def baseline(self):
            return None
    alerts, problem = V.score_store(str(path), Lab())
    assert problem is None
    d = V.declared_budget(alerts, 2.0)
    assert d["alerts"] == 1 and d["script"] == 1 and d["registry"] == 0


def test_a_detector_error_refuses(tmp_path, monkeypatch):
    path = store(tmp_path, busy_hours(1))

    def broken(con, rules, baseline=None, errors=None, **kw):
        errors.append(("own_rules", "boom"))
        return []
    monkeypatch.setattr(V.S, "score", broken)

    class Lab:
        def rules(self):
            return []

        def baseline(self):
            return None
    alerts, problem = V.score_store(str(path), Lab())
    assert alerts is None and "detector error" in problem


def test_main_counts_declared_alerts_end_to_end(tmp_path, monkeypatch, capsys):
    """main()'s wiring: it scores the store and reports the declared section (not only the old budgets)."""
    import experiments as X
    rec = ev(1, 3600, Image=PS, CommandLine=f'"{PS}" -NoProfile -Command Contoso.Fetch; Invoke-Thing -Now',
             ProcessGuid="{p-1}", User=r"PC\u", OriginalFileName="PowerShell.EXE")
    path = store(tmp_path, busy_hours(2) + [rec])
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE snapshot (key TEXT, value TEXT)")
    con.executemany("INSERT INTO snapshot VALUES (?, ?)", [("from_day_utc", "d1"), ("cutoff_day_utc", "d2")])
    con.commit()
    con.close()
    rules = rules_from(tmp_path, RULE)

    class Lab:
        def __init__(self, label, recordings):
            self.out_dir, self.results_dir = str(tmp_path / "out"), str(tmp_path / "res")

        def problems(self):
            return []

        def laptop_db(self):
            return str(path)

        def rules(self):
            return rules

        def baseline(self):
            return None
    monkeypatch.setattr(X, "Lab", Lab)
    assert V.main(["--label", "official"]) == 0
    out = capsys.readouterr().out
    assert "Declared alerts" in out and "F8 PowerShell 1" in out

REG_RULE = r"""
title: Contoso Switch Turned Off
id: 22222222-2222-3333-4444-999999999999
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|endswith: '\Contoso\App\Protect'
  condition: sel
level: high
"""


def test_score_store_finds_both_kinds_end_to_end(tmp_path):
    """Review 11-17 finding 1: F7's path too (a reg.exe start + a registry rule), next to F8's."""
    ps = ev(1, 3600, Image=PS, CommandLine=f'"{PS}" -NoProfile -Command Contoso.Fetch; Invoke-Thing -Now',
            ProcessGuid="{p-1}", User=r"PC\u", OriginalFileName="PowerShell.EXE")
    reg = ev(1, 3700, Image=r"C:\Windows\System32\reg.exe", OriginalFileName="reg.exe", ProcessGuid="{r-1}",
             CommandLine=r"reg add HKLM\SOFTWARE\Contoso\App /v Protect /t REG_DWORD /d 0 /f")
    path = store(tmp_path, busy_hours(2) + [ps, reg])
    rules = rules_from(tmp_path, RULE, name="a.yml") + rules_from(tmp_path, REG_RULE, name="b.yml")

    class Lab:
        def rules(self):
            return rules

        def baseline(self):
            return None
    alerts, problem = V.score_store(str(path), Lab())
    assert problem is None
    d = V.declared_budget(alerts, 2.0)
    assert d["alerts"] == 2 and d["script"] == 1 and d["registry"] == 1


def test_exactly_at_the_budget_passes():
    assert V.declared_budget([declared(0)], 10.0)["pass"] is True                 # 0.1 per awake hour = within
    assert V.declared_budget([declared(0), declared(1)], 10.0)["pass"] is False


def test_an_unknown_declared_kind_refuses():
    with pytest.raises(ValueError, match="unknown kind"):
        V.declared_budget([declared(0, kind=7)], 10.0)


def test_main_refuses_when_scoring_reports_a_problem(tmp_path, monkeypatch, capsys):
    import experiments as X
    path = store(tmp_path, busy_hours(1))
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE snapshot (key TEXT, value TEXT)")
    con.commit()
    con.close()

    class Lab:
        def __init__(self, label, recordings):
            self.out_dir, self.results_dir = str(tmp_path / "out"), str(tmp_path / "res")

        def problems(self):
            return []

        def laptop_db(self):
            return str(path)
    monkeypatch.setattr(X, "Lab", Lab)
    monkeypatch.setattr(V, "score_store", lambda p, lab: (None, "1 detector error(s) while scoring the store"))
    assert V.main(["--label", "official"]) == 2
    assert "Refusing: 1 detector error" in capsys.readouterr().out
    assert not (tmp_path / "res").exists()                                       # nothing written


def test_all_declared_features_off_says_not_applicable(tmp_path):
    con = sqlite3.connect(store(tmp_path, busy_hours(1)))
    assert "not applicable" in V.markdown(V.budget(con, connectors={}, kinds=frozenset()))